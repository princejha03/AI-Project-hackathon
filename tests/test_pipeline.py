"""End-to-end tests against the planted ground truth.

The demo repo defines exactly what must happen:
  * InputCleaner.sanitize / sanitizeNumeric  -> learned as sanitizers
  * LegacyRequest.getParam                   -> learned as source
  * 7 FPs downgraded on re-scan, 1 new critical surfaced
  * false learnings (e.g. a servlet handler as sanitizer) must NOT occur
  * second run learns nothing new (idempotent)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import requests

from truesignal.config import Config
from truesignal.feedback import FeedbackStore
from truesignal.llm_classifier import MockClassifier
from truesignal.override_generator import Ledger
from truesignal.pipeline import diff_results, run_apply, run_learn
from truesignal.summarizer import MockSummarizer, RunHistory, build_run_payload, summarize_run
from truesignal.verifier import APPROVED


def fresh_cfg(tmp_path) -> Config:
    cfg = Config()
    cfg.state_dir = tmp_path / ".truesignal"
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return cfg


def test_learns_planted_ground_truth(tmp_path):
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    learned = {v["qualified_name"]: v for v in out["semantics"]["learned"]}

    assert "InputCleaner.sanitize" in learned
    assert learned["InputCleaner.sanitize"]["role"] == "sanitizer"
    assert learned["InputCleaner.sanitize"]["evidence"]["triage_count"] >= 30

    assert "LegacyRequest.getParam" in learned
    assert learned["LegacyRequest.getParam"]["role"] == "source"


def test_classification_failure_does_not_crash_the_whole_run(tmp_path, monkeypatch):
    """A network blip or malformed response from a live LLM backend for one
    candidate must not take down every other candidate's classification in
    the same run -- it should show up as a rejected/needs-review verdict
    with the failure visible, not an unhandled exception."""
    cfg = fresh_cfg(tmp_path)
    real = MockClassifier()

    class FlakyClassifier:
        def classify(self, candidate):
            if candidate["qualified_name"] == "InputCleaner.sanitize":
                raise requests.exceptions.Timeout("simulated network timeout")
            return real.classify(candidate)

    monkeypatch.setattr("truesignal.pipeline.make_classifier", lambda cfg: FlakyClassifier())

    out = run_learn(cfg, "webshop")
    sem = out["semantics"]
    all_verdicts = {v["qualified_name"]: v for v in sem["learned"] + sem["needs_review"] + sem["rejected"]}

    assert "InputCleaner.sanitize" in all_verdicts, "a failed candidate must still get a verdict, not vanish"
    failed = all_verdicts["InputCleaner.sanitize"]
    assert failed["role"] == "none"
    assert "simulated network timeout" in failed["evidence"]["notes"]

    # the sibling candidate, classified by the same (otherwise-working) run, is unaffected
    assert "LegacyRequest.getParam" in {v["qualified_name"] for v in sem["learned"]}


def test_no_false_learnings(tmp_path):
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    learned_sanitizers = {v["qualified_name"] for v in out["semantics"]["learned"]
                          if v["role"] == "sanitizer"}
    # servlet handlers and DAO methods must never be classified as sanitizers
    forbidden = {"OrderServlet.legacyLookup", "OrderServlet.rawSearch",
                 "OrderDao.query", "LegacyRequest.getParam"}
    assert not (learned_sanitizers & forbidden)

    # void servlet handlers CONSUME input; they must never be learned as sources
    learned_sources = {v["qualified_name"] for v in out["semantics"]["learned"]
                       if v["role"] == "source"}
    handlers = {"OrderServlet.searchByProduct", "OrderServlet.searchByEmail",
                "OrderServlet.searchSanitizedRef", "OrderServlet.rawSearch",
                "OrderServlet.legacyLookup", "ProfileServlet.ordersForUser",
                "ProfileServlet.ordersForAccount", "ProfileServlet.searchHistory",
                "ProfileServlet.contactLookup"}
    assert not (learned_sources & handlers), f"handlers misclassified: {learned_sources & handlers}"


def test_full_loop_matches_ground_truth(tmp_path):
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    run_apply(cfg, "webshop", approved, client=out["client"])

    rescan = out["client"].rescan("webshop")
    diff = diff_results(out["scan"], rescan)

    assert len(diff["downgraded"]) == 7, "exactly the 7 planted FPs must be downgraded"
    assert len(diff["new"]) == 1, "exactly the planted SQLi must surface"
    assert diff["new"][0]["severity"] == "CRITICAL"
    assert "LegacyRequest.getParam" in diff["new"][0]["taintPath"][0]["node"]
    # the honest true positive must remain a live finding
    tp = next(f for f in rescan["results"] if f["id"] == "CX-1008")
    assert tp["state"] != "NOT_EXPLOITABLE"


def test_ledger_applied_overrides_reflects_rollback(tmp_path):
    """applied_overrides() feeds the cross-project pattern library its source
    data, so it must track the same "currently applied" truth as
    already_learned() -- including dropping a function the moment it's
    rolled back, not just when it was never applied."""
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    run_apply(cfg, "webshop", approved, client=out["client"])

    ledger = Ledger(cfg.state_dir)
    applied = ledger.applied_overrides()
    assert "InputCleaner.sanitize" in applied
    assert applied["InputCleaner.sanitize"]["kind"] == "sanitizer"
    assert set(applied) == ledger.already_learned()

    ledger.record("rolled_back", applied["InputCleaner.sanitize"])
    assert "InputCleaner.sanitize" not in ledger.applied_overrides()
    assert "InputCleaner.sanitize" not in ledger.already_learned()


def test_partial_batch_failure_leaves_ledger_accurate(tmp_path):
    """If applying override N of a multi-override batch raises (network blip
    against a live tenant, one bad override), every override that already
    succeeded before it must still have a ledger entry -- otherwise it's
    applied for real against the live tenant but invisible to rollback and
    every ledger-driven screen in this app."""
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    assert len(approved) >= 2, "need >=2 approved overrides to exercise a partial-batch failure"

    real_client = out["client"]
    calls = []

    class FlakyOnSecondCall:
        def apply_query_overrides(self, project_id, overrides):
            calls.append(overrides)
            if len(calls) == 2:
                raise ConnectionError("simulated network failure applying override #2")
            real_client.apply_query_overrides(project_id, overrides)

    with pytest.raises(ConnectionError):
        run_apply(cfg, "webshop", approved, client=FlakyOnSecondCall())

    ledger = Ledger(cfg.state_dir)
    applied = ledger.already_learned()
    assert len(applied) == 1, "only the override applied before the failure should be ledgered"
    assert len(calls) == 2, "the batch must stop at the failure, not skip ahead to later overrides"


def test_idempotent_second_run(tmp_path):
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    run_apply(cfg, "webshop", approved, client=out["client"])

    out2 = run_learn(cfg, "webshop")
    already = {v["qualified_name"] for v in approved}
    relearned = {v["qualified_name"] for v in out2["semantics"]["learned"]}
    assert not (already & relearned), "applied learnings must not be re-proposed"


def test_stability_five_runs(tmp_path):
    """Classification must be deterministic (temperature-0 stand-in)."""
    results = []
    for i in range(5):
        cfg = fresh_cfg(tmp_path / str(i))
        out = run_learn(cfg, "webshop")
        results.append(sorted((v["qualified_name"], v["role"], v["confidence"])
                              for v in out["semantics"]["learned"]))
    assert all(r == results[0] for r in results)


def test_feedback_store_bounds_and_roundtrip(tmp_path):
    store = FeedbackStore(tmp_path)
    assert store.adjustment("sanitizer", ["xss"]) == 0.0  # no history yet -> no-op

    store.record("sanitizer", ["xss"], "approved")
    store.record("sanitizer", ["xss"], "approved")
    assert store.adjustment("sanitizer", ["xss"]) == round(0.02, 4)

    for _ in range(10):
        store.record("sanitizer", ["xss"], "rolled_back")
    assert store.adjustment("sanitizer", ["xss"]) == -0.10  # capped, not unbounded

    summary = store.summary()
    assert summary["sanitizer:xss"]["rolled_back"] == 10
    assert summary["sanitizer:xss"]["adjustment"] == -0.10
    assert "sanitizer:sql_injection" not in summary  # signatures don't cross-contaminate


def test_all_trends_tracks_running_adjustment_chronologically(tmp_path):
    """The calibration trend chart is built from this: the running adjustment
    after each event, in order, not just the final tally."""
    store = FeedbackStore(tmp_path)
    store.record("sanitizer", ["xss"], "approved")
    store.record("sanitizer", ["xss"], "approved")
    store.record("sanitizer", ["xss"], "rolled_back")
    store.record("sink", ["sql_injection"], "rejected")

    trends = store.all_trends()
    assert set(trends) == {"sanitizer:xss", "sink:sql_injection"}

    xss_points = trends["sanitizer:xss"]
    assert [p["outcome"] for p in xss_points] == ["approved", "approved", "rolled_back"]
    assert [p["adjustment"] for p in xss_points] == [0.01, 0.02, -0.04]  # running, not final-only
    assert all("timestamp" in p for p in xss_points)

    sink_points = trends["sink:sql_injection"]
    assert [p["adjustment"] for p in sink_points] == [-0.03]

    # matches summary()'s final tally exactly -- same log, two views of it
    assert xss_points[-1]["adjustment"] == store.summary()["sanitizer:xss"]["adjustment"]


def test_repeated_rollbacks_push_a_learned_sanitizer_to_review(tmp_path):
    """The audit trail should make the gate harder to clear for a signature
    that keeps getting rolled back in production -- without touching the
    classifier or the fixed thresholds themselves."""
    cfg = fresh_cfg(tmp_path)
    feedback = FeedbackStore(cfg.state_dir)
    feedback.record("sanitizer", ["sql_injection"], "rolled_back")
    feedback.record("sanitizer", ["sql_injection"], "rolled_back")

    out = run_learn(cfg, "webshop")
    learned = {v["qualified_name"] for v in out["semantics"]["learned"]}
    review = {v["qualified_name"]: v for v in out["semantics"]["needs_review"]}

    assert "InputCleaner.sanitize" not in learned
    assert "InputCleaner.sanitize" in review
    ev = review["InputCleaner.sanitize"]["evidence"]
    assert ev["feedback_adjustment"] == -0.10
    assert ev["effective_confidence"] == round(review["InputCleaner.sanitize"]["confidence"] - 0.10, 4)

    # the source signature is untouched -- feedback keys are (role, attack_class)
    assert "LegacyRequest.getParam" in learned


def test_approvals_alone_never_bypass_the_evidence_gate(tmp_path):
    """Positive feedback nudges confidence up but can never substitute for the
    hard requirements (triage support, code reasons, indexer confirmation) --
    it only ever affects the confidence term of the same fixed comparison."""
    cfg = fresh_cfg(tmp_path)
    feedback = FeedbackStore(cfg.state_dir)
    for _ in range(20):
        feedback.record("sink", ["sql_injection"], "approved")

    out = run_learn(cfg, "webshop")
    # capped at +0.10 regardless of how much positive history piles up
    assert feedback.adjustment("sink", ["sql_injection"]) == 0.10
    sinks = [v for v in out["semantics"]["learned"] if v["role"] == "sink"]
    for v in sinks:
        assert v["evidence"]["feedback_adjustment"] == 0.10


def test_mock_summarizer_names_specifics_and_no_op_on_empty_run():
    empty_payload = build_run_payload("webshop", [], {"downgraded": [], "new": []})
    assert MockSummarizer().summarize(empty_payload) == "No new semantics were learned or applied this run."

    overrides = [
        {"function": "InputCleaner.sanitize", "kind": "sanitizer",
         "confidence": 0.93, "attackClass": "sql_injection"},
        {"function": "LegacyRequest.getParam", "kind": "source",
         "confidence": 0.97, "attackClass": "sql_injection"},
    ]
    diff = {
        "downgraded": [{"id": "CX-1001",
                         "downgradeReason": "passes through verified sanitizer InputCleaner.sanitize()"}],
        "new": [{"id": "CX-2001", "severity": "CRITICAL",
                 "taintPath": [{"node": "LegacyRequest.getParam"}, {"node": "OrderDao.query"}]}],
    }
    payload = build_run_payload("webshop", overrides, diff, needs_review=[{"qualified_name": "x"}])
    text = MockSummarizer().summarize(payload)

    assert "InputCleaner.sanitize" in text
    assert "LegacyRequest.getParam" in text
    assert "1 finding(s) were downgraded" in text
    assert "passes through verified sanitizer InputCleaner.sanitize()" in text
    assert "pass through passes through" not in text  # no duplicated phrasing
    assert "CX-2001" in text and "CRITICAL" in text
    assert "1 additional item(s)" in text and "manual review" in text


def test_run_history_roundtrip(tmp_path):
    history = RunHistory(tmp_path)
    assert history.recent() == []

    history.record("webshop", "first run summary", {"a": 1})
    history.record("webshop", "second run summary", {"a": 2})
    recent = history.recent()

    assert len(recent) == 2
    assert recent[0]["summary"] == "second run summary"  # most recent first
    assert recent[1]["summary"] == "first run summary"
    assert all("timestamp" in e for e in recent)


def test_summarize_run_persists_to_run_history(tmp_path):
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    overrides = run_apply(cfg, "webshop", approved, client=out["client"])
    rescan = out["client"].rescan("webshop")
    diff = diff_results(out["scan"], rescan)

    summary = summarize_run(cfg, "webshop", overrides, diff, needs_review=out["semantics"]["needs_review"])
    assert "InputCleaner.sanitize" in summary
    assert "LegacyRequest.getParam" in summary  # the hidden SQLi's source, named in the new-finding sentence

    entries = RunHistory(cfg.state_dir).recent()
    assert len(entries) == 1
    assert entries[0]["summary"] == summary
    assert entries[0]["project"] == "webshop"


def test_summarize_run_survives_a_failing_backend(tmp_path, monkeypatch):
    """summarize_run's own docstring promises it never raises, because it runs
    after apply/re-scan/diff are already final -- a flaky summarizer backend
    must degrade to a fallback message, not an exception that makes an
    already-applied, already-ledgered override look like it failed."""
    cfg = fresh_cfg(tmp_path)
    out = run_learn(cfg, "webshop")
    approved = [v for v in out["semantics"]["learned"] if v["verdict"] == APPROVED]
    overrides = run_apply(cfg, "webshop", approved, client=out["client"])
    rescan = out["client"].rescan("webshop")
    diff = diff_results(out["scan"], rescan)

    class FailingSummarizer:
        def summarize(self, payload):
            raise requests.exceptions.ConnectionError("simulated backend outage")

    monkeypatch.setattr("truesignal.summarizer.make_summarizer", lambda cfg: FailingSummarizer())

    summary = summarize_run(cfg, "webshop", overrides, diff, needs_review=out["semantics"]["needs_review"])
    assert "simulated backend outage" in summary
    assert "succeeded" in summary  # must not read as if the apply itself failed

    entries = RunHistory(cfg.state_dir).recent()
    assert len(entries) == 1  # the fallback message is still ledgered, not dropped
    assert entries[0]["summary"] == summary
