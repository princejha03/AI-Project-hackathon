"""The agent loop: fetch -> classify -> verify -> generate -> apply -> re-scan."""
from __future__ import annotations

import logging
from typing import Any

import requests

from .candidate_selector import select_candidates
from .checkmarx_client import make_client
from .code_indexer import index_repo
from .feedback import FeedbackStore
from .jsonstore import write_json
from .llm_classifier import make_classifier
from .override_generator import Ledger, generate_overrides
from .verifier import APPROVED, NEEDS_REVIEW, verify

logger = logging.getLogger(__name__)


def run_ingest(cfg, project: str, client=None) -> dict[str, Any]:
    client = client or make_client(cfg)
    methods = index_repo(cfg.repo_path)
    scan = client.get_scan_results(project)
    triage = client.get_triage_history(project)
    candidates = select_candidates(methods, scan, triage)
    bundle = {
        "project": project,
        "methods_indexed": len(methods),
        "baseline_findings": len(scan["results"]),
        "triage_decisions": len(triage["decisions"]),
        "candidates": [
            {"qualified_name": c["qualified_name"], "hypothesis": c["hypothesis"],
             "findings": c["findings"], "dismissal_count": len(c["dismissals"])}
            for c in candidates
        ],
    }
    write_json(cfg.state_dir / "ingest_bundle.json", bundle)
    return {"bundle": bundle, "candidates": candidates, "scan": scan, "client": client}


def run_learn(cfg, project: str, client=None) -> dict[str, Any]:
    ingest = run_ingest(cfg, project, client=client)
    classifier = make_classifier(cfg)
    ledger = Ledger(cfg.state_dir)
    feedback = FeedbackStore(cfg.state_dir)
    already = ledger.already_learned()

    verdicts = []
    for cand in ingest["candidates"]:
        if cand["qualified_name"] in already:
            continue  # idempotent: skip what's already applied
        try:
            classification = classifier.classify(cand)
        except (requests.exceptions.RequestException, ValueError, KeyError, IndexError) as e:
            # A network blip, rate limit, or one malformed response from a live
            # LLM backend must not take down every other candidate's classification
            # in the same run -- fall through to role "none" so verify() routes it
            # to REJECTED/NEEDS_REVIEW like any other low-evidence result, with the
            # actual failure visible in the evidence bundle instead of a crash.
            logger.warning("classification failed for %s: %s", cand["qualified_name"], e)
            classification = {
                "role": "none", "confidence": 0.0, "attack_classes": [],
                "code_reasons": [], "notes": f"classification failed: {e}",
            }
        verdicts.append(verify(cand, classification, cfg, feedback=feedback))

    semantics = {
        "project": project,
        "learned": [v for v in verdicts if v["verdict"] == APPROVED],
        "needs_review": [v for v in verdicts if v["verdict"] == NEEDS_REVIEW],
        "rejected": [v for v in verdicts if v["verdict"] not in (APPROVED, NEEDS_REVIEW)],
    }
    write_json(cfg.state_dir / "semantics.json", semantics)
    return {**ingest, "semantics": semantics}


def run_apply(cfg, project: str, approved: list[dict[str, Any]], client=None) -> list[dict]:
    """Apply and ledger one override at a time -- not apply-the-whole-batch,
    then-ledger-the-whole-batch. If the live client raises partway through a
    multi-override batch (network blip, one bad override), any override that
    already succeeded against the real Checkmarx tenant would otherwise have
    *no* ledger entry: applied for real, but unrollbackable and invisible to
    every screen that reads from the ledger. Interleaving means the ledger is
    always an accurate record of exactly what actually got applied, even when
    this raises partway through."""
    client = client or make_client(cfg)
    ledger = Ledger(cfg.state_dir)
    overrides = generate_overrides(approved)
    for ov in overrides:
        client.apply_query_overrides(project, [ov])
        ledger.record("applied", ov)
    return overrides


def diff_results(baseline: dict, rescan: dict) -> dict[str, Any]:
    base_by_id = {f["id"]: f for f in baseline["results"]}
    downgraded, new = [], []
    for f in rescan["results"]:
        old = base_by_id.get(f["id"])
        if old and old.get("state") != "NOT_EXPLOITABLE" and f.get("state") == "NOT_EXPLOITABLE":
            downgraded.append(f)
        if f.get("new") or f["id"] not in base_by_id:
            new.append(f)
    return {"downgraded": downgraded, "new": new}
