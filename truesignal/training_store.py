"""Curated training examples for fine-tuning the local (Ollama) classifier
model on its own verified mistakes.

Two-gate design, mirroring the trust model the rest of this project already
uses (nothing persists on the LLM's word alone -- see verifier.py):

  1. A human who reviews the model's proposed classifications (rejecting a
     proposed role, rolling back an applied override, or confirming a
     finding that a "sanitizer" override claimed was safe) generates a
     *candidate* correction, recorded here as status="pending". This is the
     "verified by whoever reviews the change" half of the gate.
  2. An admin reviews pending candidates -- approving (optionally editing
     the correction first), discarding, or hand-authoring a new example
     outright -- before anything reaches the exported training set. Only
     status=="approved" rows are ever exported. This is the second gate:
     no unverified or low-quality example trains the model just because a
     single reviewer clicked something.

Same append-only JSON persistence as Ledger/FeedbackStore/RunHistory. Lives
at a project-wide (not per-project) location, since the fine-tuned model is
shared across every project's classifier.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .jsonstore import read_json, write_json
from .llm_classifier import SYSTEM_PROMPT

PENDING = "pending"
APPROVED = "approved"
DISCARDED = "discarded"

DEFAULT_ROOT = PROJECT_ROOT / ".truesignal"


class TrainingStore:
    def __init__(self, root: Path | None = None):
        root = root if root is not None else DEFAULT_ROOT
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "training_examples.json"

    def _read(self) -> list[dict]:
        return read_json(self.path, default=[])

    def _write(self, entries: list[dict]) -> None:
        write_json(self.path, entries)

    def record_candidate(self, *, qualified_name: str, prompt: str, model_output: dict[str, Any] | None,
                          corrected_role: str, corrected_attack_classes: list[str],
                          source_event: str, verified_by: str, verified_role: str) -> str:
        entries = self._read()
        example_id = uuid.uuid4().hex[:12]
        entries.append({
            "id": example_id,
            "status": PENDING,
            "qualified_name": qualified_name,
            "prompt": prompt,
            "model_output": model_output,
            "corrected_role": corrected_role,
            "corrected_attack_classes": corrected_attack_classes,
            "source_event": source_event,
            "verified_by": verified_by,
            "verified_role": verified_role,
            "created": datetime.now(timezone.utc).isoformat(),
            "reviewed_by": None,
            "reviewed_at": None,
        })
        self._write(entries)
        return example_id

    def add_manual(self, *, qualified_name: str, prompt: str, corrected_role: str,
                    corrected_attack_classes: list[str], admin: str) -> str:
        """Admin hand-authors an example with no reviewer trigger. Recorded
        approved immediately -- an admin curating the training set directly
        is itself the verification step."""
        entries = self._read()
        example_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        entries.append({
            "id": example_id,
            "status": APPROVED,
            "qualified_name": qualified_name,
            "prompt": prompt,
            "model_output": None,
            "corrected_role": corrected_role,
            "corrected_attack_classes": corrected_attack_classes,
            "source_event": "manual",
            "verified_by": admin,
            "verified_role": "admin",
            "created": now,
            "reviewed_by": admin,
            "reviewed_at": now,
        })
        self._write(entries)
        return example_id

    def list(self, status: str | None = None) -> list[dict]:
        entries = self._read()
        return [e for e in entries if status is None or e["status"] == status]

    def set_status(self, example_id: str, status: str, *, admin: str,
                   corrected_role: str | None = None,
                   corrected_attack_classes: list[str] | None = None) -> None:
        if status not in (APPROVED, DISCARDED):
            raise ValueError(f"unknown status {status!r}, expected {APPROVED!r} or {DISCARDED!r}")
        entries = self._read()
        for e in entries:
            if e["id"] != example_id:
                continue
            if corrected_role is not None:
                e["corrected_role"] = corrected_role
            if corrected_attack_classes is not None:
                e["corrected_attack_classes"] = corrected_attack_classes
            e["status"] = status
            e["reviewed_by"] = admin
            e["reviewed_at"] = datetime.now(timezone.utc).isoformat()
            self._write(entries)
            return
        raise ValueError(f"no training example {example_id!r}")

    def export_dataset(self) -> list[dict[str, Any]]:
        """Only status=='approved'. Chat-SFT records ready for a fine-tune
        run: same system prompt and user-message shape the live classifier
        actually sees, paired with the human-verified correct answer."""
        records = []
        for e in self.list(status=APPROVED):
            completion = {
                "role": e["corrected_role"],
                "confidence": 1.0,
                "attack_classes": e["corrected_attack_classes"],
                "code_reasons": (e["model_output"] or {}).get("code_reasons", []),
                "notes": f"corrected by {e['verified_by']} ({e['source_event']})",
            }
            records.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": e["prompt"]},
                    {"role": "assistant", "content": json.dumps(completion)},
                ]
            })
        return records
