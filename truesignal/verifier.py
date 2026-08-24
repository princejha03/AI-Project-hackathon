"""Verification gate — nothing persists on the LLM's word alone.

Rules (a wrong sanitizer creates real false negatives, so sanitizers get
the strictest treatment):

  sanitizer -> AUTO-APPROVE only if confidence >= threshold AND
               triage support >= min_triage AND code_reasons present.
               Code-evidence-only sanitizers go to NEEDS_REVIEW.
  source    -> AUTO-APPROVE if confidence >= threshold AND the indexer
               independently confirms it wraps a known source.
  sink      -> AUTO-APPROVE if confidence >= threshold AND the indexer
               confirms it touches a known sink.
  anything below threshold, or role "none" -> REJECT / NEEDS_REVIEW.

If a `feedback` store (feedback.py) is passed in, its bounded, audit-history
-derived adjustment for this (role, attack_class) signature is added to the
raw confidence *before* the threshold checks above -- e.g. a sanitizer
signature that keeps getting rolled back needs a bit more headroom to clear
the bar next time; one that keeps getting approved cleanly needs a bit less.
The adjustment is capped at +-0.10 and is zero with no history, so an
unreviewed project (or `feedback=None`) behaves exactly as before. The raw
confidence, the adjustment, and the effective confidence actually compared
against the threshold are all carried forward in the evidence bundle so
nothing about the calibration is hidden from the human review step or the
ledger.

Every verdict carries the full evidence bundle for the human review step
and the audit ledger.
"""
from __future__ import annotations

from typing import Any

APPROVED = "APPROVED"
NEEDS_REVIEW = "NEEDS_REVIEW"
REJECTED = "REJECTED"


def verify(candidate: dict[str, Any], classification: dict[str, Any], cfg, feedback=None) -> dict[str, Any]:
    m = candidate["method"]
    role = classification.get("role", "none")
    conf = float(classification.get("confidence", 0.0))
    attack_classes = classification.get("attack_classes", [])
    n_triage = len(candidate["dismissals"])
    reasons = classification.get("code_reasons") or []

    adjustment = feedback.adjustment(role, attack_classes) if feedback is not None else 0.0
    eff_conf = max(0.0, min(1.0, conf + adjustment))

    verdict, why = REJECTED, "role none or evidence absent"

    if role == "sanitizer":
        if eff_conf >= cfg.min_confidence_auto and n_triage >= cfg.min_triage_support and reasons:
            verdict, why = APPROVED, f"code evidence + {n_triage} supporting dismissals"
        elif eff_conf >= cfg.min_confidence_auto and reasons:
            verdict, why = NEEDS_REVIEW, "code evidence only — no triage support"
        elif reasons:
            verdict, why = NEEDS_REVIEW, f"confidence {eff_conf:.2f} below threshold"
    elif role == "source":
        if eff_conf >= cfg.min_confidence_auto and m.wraps_known_source:
            verdict, why = APPROVED, "wraps a known source (independently confirmed by indexer)"
        elif eff_conf >= cfg.min_confidence_auto:
            verdict, why = NEEDS_REVIEW, "indexer could not confirm known-source wrapping"
    elif role == "sink":
        if eff_conf >= cfg.min_confidence_auto and m.touches_known_sink:
            verdict, why = APPROVED, "touches a known sink (independently confirmed by indexer)"
        elif eff_conf >= cfg.min_confidence_auto:
            verdict, why = NEEDS_REVIEW, "indexer could not confirm sink behavior"

    return {
        "qualified_name": m.qualified_name,
        "file": m.file,
        "line": m.line,
        "role": role,
        "confidence": conf,
        "attack_classes": attack_classes,
        "verdict": verdict,
        "verdict_reason": why,
        "evidence": {
            "code_reasons": reasons,
            "triage_support": [d["findingId"] for d in candidate["dismissals"]],
            "triage_count": n_triage,
            "notes": classification.get("notes", ""),
            "feedback_adjustment": round(adjustment, 4),
            "effective_confidence": round(eff_conf, 4),
        },
    }
