"""Feedback-calibrated confidence — the audit trail teaches the gate.

Every time a human reviews a proposed classification (approves it, declines
it) or later rolls back something that was applied, that decision is
evidence about whether *that kind* of classification (role + attack class,
e.g. "sanitizer:xss") tends to be trustworthy. FeedbackStore turns that
history into a small, bounded confidence adjustment that verifier.py applies
before comparing against the fixed thresholds — so the same threshold gets
a little easier or harder to clear as real audit history accumulates for a
given signature, entirely from data this project already collects.

Deliberately NOT deep reinforcement learning: no reward model, no policy
weights, no training loop, no gradient anything. Just bounded counters, so
every adjustment stays fully explainable (each verdict's evidence shows the
raw confidence, the adjustment, and the effective confidence used) and fully
reversible — delete <state_dir>/feedback.json and the gate goes back to
untouched defaults. This keeps the project's core guarantee intact: nothing
is ever approved on the LLM's word (or the calibration's word) alone, only
after the same fixed threshold + evidence checks in verifier.py.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .jsonstore import read_json, write_json

# Bounded per-occurrence nudge, by outcome. Rollbacks are weighted heaviest
# because an approved-then-rolled-back sanitizer already manufactured a real
# false negative in production -- the worst outcome this project is designed
# to avoid (see verifier.py).
_STEP = {"approved": 0.01, "rejected": -0.03, "rolled_back": -0.06}
_MAX_ADJUSTMENT = 0.10

OUTCOMES = tuple(_STEP)


def signature(role: str, attack_classes: list[str] | None) -> str:
    """'sanitizer', ['xss'] -> 'sanitizer:xss' -- the calibration bucket key."""
    attack_class = next(iter(attack_classes or []), "unknown")
    return f"{role}:{attack_class}"


def _adjustment_from_counts(counts: dict[str, int]) -> float:
    raw = sum(_STEP[outcome] * counts.get(outcome, 0) for outcome in OUTCOMES)
    return max(-_MAX_ADJUSTMENT, min(_MAX_ADJUSTMENT, raw))


class FeedbackStore:
    """Append-only log of audit outcomes, persisted next to the ledger at
    state_dir/feedback.json. Each entry is one human decision -- approve,
    decline, or roll back -- tagged with the (role, attack_class) signature
    it applies to and a timestamp, so both the current calibration (fold the
    whole log) and its trend over time (fold it incrementally) come from the
    same append-only source of truth, the same shape as Ledger/RunHistory."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "feedback.json"

    def _read(self) -> list[dict]:
        return read_json(self.path, default=[])

    def _write(self, entries: list[dict]) -> None:
        write_json(self.path, entries)

    def record(self, role: str, attack_classes: list[str] | None, outcome: str) -> None:
        if outcome not in _STEP:
            raise ValueError(f"unknown feedback outcome {outcome!r}, expected one of {OUTCOMES}")
        entries = self._read()
        entries.append({
            "signature": signature(role, attack_classes),
            "role": role,
            "attack_class": next(iter(attack_classes or []), "unknown"),
            "outcome": outcome,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._write(entries)

    def _counts_by_signature(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for e in self._read():
            counts.setdefault(e["signature"], {o: 0 for o in OUTCOMES})[e["outcome"]] += 1
        return counts

    def adjustment(self, role: str, attack_classes: list[str] | None) -> float:
        """Bounded confidence delta learned from this signature's audit history.
        Zero with no history -- an untouched project behaves exactly as before."""
        counts = self._counts_by_signature().get(signature(role, attack_classes))
        return _adjustment_from_counts(counts) if counts else 0.0

    def summary(self) -> dict[str, dict[str, Any]]:
        """signature -> counts + current adjustment, for `truesignal feedback`
        and any UI that wants to show what's been learned so far."""
        return {key: {**counts, "adjustment": round(_adjustment_from_counts(counts), 4)}
                for key, counts in self._counts_by_signature().items()}

    def all_trends(self) -> dict[str, list[dict[str, Any]]]:
        """signature -> chronological list of {timestamp, outcome, adjustment},
        where `adjustment` is the running value after that event -- the data
        behind the web UI's calibration trend chart. Walking the same
        append-only log incrementally instead of just folding it once is what
        turns "current calibration" into "calibration over time"."""
        running: dict[str, dict[str, int]] = {}
        trends: dict[str, list[dict[str, Any]]] = {}
        for e in self._read():
            key = e["signature"]
            counts = running.setdefault(key, {o: 0 for o in OUTCOMES})
            counts[e["outcome"]] += 1
            trends.setdefault(key, []).append({
                "timestamp": e["timestamp"],
                "outcome": e["outcome"],
                "adjustment": round(_adjustment_from_counts(counts), 4),
            })
        return trends
