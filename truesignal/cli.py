"""TrueSignal CLI.

  truesignal ingest   --project webshop     # build the evidence bundle
  truesignal learn    --project webshop     # + classify & verify (dry run)
  truesignal analyze  --project webshop     # full loop: learn -> review -> apply -> rescan -> diff
  truesignal analyze  --project webshop --yes        # non-interactive (CI)
  truesignal analyze  --project webshop --dry-run    # never applies anything
  truesignal ledger                          # show the audit trail
  truesignal feedback                        # show the confidence calibration learned from past audits
  truesignal history                         # show past runs' AI-authored summaries
  truesignal export-training-data            # write admin-approved corrections as a fine-tune JSONL
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import load_config
from .feedback import FeedbackStore
from .override_generator import Ledger
from .pipeline import diff_results, run_apply, run_ingest, run_learn
from .summarizer import RunHistory, summarize_run
from .training_store import TrainingStore

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

GREEN, RED, YELLOW, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def _fmt_learned(v: dict) -> str:
    role_pad = {"sanitizer": "sanitizer  ", "source": "taint source", "sink": "sink       "}
    extra = ""
    if v["role"] == "sanitizer":
        extra = f"(confidence {v['confidence']:.2f}, {v['evidence']['triage_count']} dismissals support this)"
    elif v["role"] == "source":
        extra = (f"({v['evidence']['notes'].rstrip('.')})" if v["evidence"]["notes"]
                 else f"(confidence {v['confidence']:.2f})")
    else:
        extra = f"(confidence {v['confidence']:.2f})"
    return f"{GREEN}Learned: {v['qualified_name']}()  -> {role_pad.get(v['role'], v['role'])} {extra}{RESET}"


def cmd_ingest(args) -> int:
    cfg = load_config()
    out = run_ingest(cfg, args.project)
    b = out["bundle"]
    print(f"Indexed {b['methods_indexed']} methods | "
          f"{b['baseline_findings']} baseline findings | "
          f"{b['triage_decisions']} triage decisions")
    for c in b["candidates"]:
        print(f"  candidate: {c['qualified_name']:40s} hypothesis={c['hypothesis']:9s} "
              f"dismissals={c['dismissal_count']}")
    print(f"{DIM}bundle saved to {cfg.state_dir / 'ingest_bundle.json'}{RESET}")
    return 0


def cmd_learn(args) -> int:
    cfg = load_config()
    out = run_learn(cfg, args.project)
    sem = out["semantics"]
    for v in sem["learned"]:
        print(_fmt_learned(v))
    for v in sem["needs_review"]:
        print(f"{YELLOW}Needs review: {v['qualified_name']} -> {v['role']} "
              f"({v['verdict_reason']}){RESET}")
    for v in sem["rejected"]:
        print(f"{DIM}Rejected: {v['qualified_name']} ({v['verdict_reason']}){RESET}")
    print(f"{DIM}semantics saved to {cfg.state_dir / 'semantics.json'}{RESET}")
    return 0


def _review(items: list[dict], auto_yes: bool, feedback: FeedbackStore | None = None) -> list[dict]:
    approved = []
    for v in items:
        print(f"\n{BOLD}{v['qualified_name']}{RESET} -> {v['role']} "
              f"(confidence {v['confidence']:.2f})")
        print(f"  file: {v['file']}:{v['line']}")
        for r in v["evidence"]["code_reasons"]:
            print(f"  code evidence: {r}")
        print(f"  triage support: {v['evidence']['triage_count']} decisions "
              f"{v['evidence']['triage_support'][:5]}{'...' if v['evidence']['triage_count'] > 5 else ''}")
        adj = v["evidence"].get("feedback_adjustment", 0.0)
        if adj:
            print(f"  {DIM}learned calibration: {adj:+.2f} from past audits of this signature "
                  f"(effective confidence {v['evidence']['effective_confidence']:.2f}){RESET}")
        if auto_yes:
            print("  -> auto-approved (--yes)")
            approved.append(v)
            if feedback is not None:
                feedback.record(v["role"], v["attack_classes"], "approved")
            continue
        ans = input("  approve override? [y/N] ").strip().lower()
        if ans == "y":
            approved.append(v)
            if feedback is not None:
                feedback.record(v["role"], v["attack_classes"], "approved")
        elif feedback is not None:
            feedback.record(v["role"], v["attack_classes"], "rejected")
    return approved


def cmd_analyze(args) -> int:
    cfg = load_config()
    print(f"> truesignal analyze --project {args.project}"
          + (" --dry-run" if args.dry_run else ""))
    out = run_learn(cfg, args.project)
    sem, scan, client = out["semantics"], out["scan"], out["client"]

    if not sem["learned"] and not sem["needs_review"]:
        print("Nothing new to learn — engine already knows this codebase's semantics.")
        return 0

    for v in sem["learned"]:
        print(_fmt_learned(v))
    for v in sem["needs_review"]:
        print(f"{YELLOW}Needs review: {v['qualified_name']} -> {v['role']} "
              f"({v['verdict_reason']}){RESET}")

    if args.dry_run:
        print(f"{DIM}dry run: no overrides applied.{RESET}")
        return 0

    to_review = sem["learned"] + (sem["needs_review"] if args.include_review else [])
    feedback = FeedbackStore(cfg.state_dir)
    approved = _review(to_review, args.yes, feedback=feedback)
    if not approved:
        print("No overrides approved — nothing applied.")
        return 0

    overrides = run_apply(cfg, args.project, approved, client=client)

    print("\nRe-scan results:")
    rescan = client.rescan(args.project)
    diff = diff_results(scan, rescan)
    if diff["downgraded"]:
        print(f"  - {len(diff['downgraded'])} findings downgraded: pass through verified "
              f"sanitizer (line refs attached)")
        for f in diff["downgraded"]:
            print(f"{DIM}      {f['id']}  {f['sourceFile']}:{f['sourceLine']}  "
                  f"[{f.get('downgradeReason', '')}]{RESET}")
    for f in diff["new"]:
        path = " -> ".join(step["node"] for step in f["taintPath"])
        print(f"  {RED}- 1 NEW {f['severity'].lower()}: SQLi via {path}  [was invisible]{RESET}")

    print(f"\nSaved {len(overrides)} query overrides to project config. "
          f"Future scans apply them automatically.")

    summary = summarize_run(cfg, args.project, overrides, diff, needs_review=sem["needs_review"])
    print(f"\n{BOLD}Summary:{RESET} {DIM}{summary}{RESET}")
    return 0


def cmd_ledger(args) -> int:
    cfg = load_config()
    ledger = Ledger(cfg.state_dir)
    entries = ledger._read()
    if not entries:
        print("ledger is empty.")
        return 0
    for e in entries:
        ov = e["override"]
        print(f"{e['timestamp']}  {e['event']:8s} {ov['kind']:9s} {ov['function']} "
              f"(confidence {ov['confidence']:.2f}, "
              f"{ov['evidence']['triage_count']} triage decisions)")
    return 0


def cmd_feedback(args) -> int:
    cfg = load_config()
    summary = FeedbackStore(cfg.state_dir).summary()
    if not summary:
        print("no audit feedback recorded yet — every classification is still using "
              "its raw confidence, unadjusted.")
        return 0
    print(f"{'signature':30s} {'approved':>9s} {'rejected':>9s} {'rolled back':>12s} {'adjustment':>11s}")
    for key, s in sorted(summary.items()):
        print(f"{key:30s} {s['approved']:9d} {s['rejected']:9d} {s['rolled_back']:12d} "
              f"{s['adjustment']:+11.3f}")
    print(f"\n{DIM}adjustment is added to raw confidence before the verification gate's "
          f"threshold checks; capped at +-0.10; zero for any signature with no history yet.{RESET}")
    return 0


def cmd_history(args) -> int:
    cfg = load_config()
    entries = RunHistory(cfg.state_dir).recent(limit=args.limit)
    if not entries:
        print("no analysis runs recorded yet.")
        return 0
    for e in entries:
        print(f"{DIM}{e['timestamp']}  [{e['project']}]{RESET}")
        print(f"  {e['summary']}\n")
    return 0


def cmd_export_training_data(args) -> int:
    dataset = TrainingStore().export_dataset()
    if not dataset:
        print("no approved training examples yet — curate some at /training in the web UI, "
              "or with TrainingStore.add_manual().")
        return 0
    with open(args.out, "w", encoding="utf-8") as f:
        for record in dataset:
            f.write(json.dumps(record) + "\n")
    print(f"wrote {len(dataset)} approved example(s) to {args.out}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="truesignal", description="Self-tuning SAST agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, fn in (("ingest", cmd_ingest), ("learn", cmd_learn)):
        sp = sub.add_parser(name)
        sp.add_argument("--project", required=True)
        sp.set_defaults(fn=fn)

    sp = sub.add_parser("analyze")
    sp.add_argument("--project", required=True)
    sp.add_argument("--yes", action="store_true", help="auto-approve (CI)")
    sp.add_argument("--dry-run", action="store_true", help="never apply overrides")
    sp.add_argument("--include-review", action="store_true",
                    help="also present NEEDS_REVIEW items for approval")
    sp.set_defaults(fn=cmd_analyze)

    sp = sub.add_parser("ledger")
    sp.set_defaults(fn=cmd_ledger)

    sp = sub.add_parser("feedback", help="show the confidence calibration learned from past audits")
    sp.set_defaults(fn=cmd_feedback)

    sp = sub.add_parser("history", help="show past runs' AI-authored summaries")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_history)

    sp = sub.add_parser("export-training-data", help="write admin-approved corrections as a fine-tune JSONL")
    sp.add_argument("--out", default="training_data.jsonl")
    sp.set_defaults(fn=cmd_export_training_data)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
