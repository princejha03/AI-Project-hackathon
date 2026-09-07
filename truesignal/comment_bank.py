"""Admin-curated bank of predefined audit comments.

Reviewers auditing a finding today only get one prefilled comment option: the
heuristic "AI suggestion" from triage_advisor.py. This store lets an admin
hand-author accurate, reusable comments (per attack class and resolution)
that a reviewer can pick *instead of* that auto-generated text -- see the
picker on the audit page (webapp/templates/audit.html).

Same trust model as training_store.py's `add_manual`: an admin authoring a
comment directly *is* the verification step, so there's no separate
pending/approve gate here. Project-wide (not per-project) JSON file, since the
attack-class taxonomy and the comments themselves are reusable across every
project, not specific to one codebase.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import PROJECT_ROOT
from .jsonstore import read_json, write_json

ATTACK_CLASSES = [
    "csrf",
    "insufficiently_protected_credentials",
    "missing_hsts_header",
    "privacy_violation",
    "log_forging",
    "trust_boundary_violation",
    "heap_inspection",
    "client_jquery_deprecated_symbols",
    "xss",
    "open_redirect",
    "missing_csp_header",
    "unsafe_target_blank",
    "client_dangerous_file_inclusion",
    "path_traversal",
    "xxe",
    "risky_cryptographic_algorithm",
]
RESOLUTIONS = ["CONFIRMED", "NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE", "TO_VERIFY"]
LANGUAGES = ["JAVA", "PYTHON", "JAVASCRIPT", "TYPESCRIPT", "CSHARP", "GO", "OTHER"]

DEFAULT_ROOT = PROJECT_ROOT / ".truesignal"


class CommentBank:
    def __init__(self, root: Path | None = None):
        root = root if root is not None else DEFAULT_ROOT
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "comment_bank.json"

    def _read(self) -> list[dict]:
        return read_json(self.path, default=[])

    def _write(self, entries: list[dict]) -> None:
        write_json(self.path, entries)

    def add(self, *, attack_class: str, resolution: str, language: str, label: str, text: str,
             admin: str) -> str:
        if attack_class not in ATTACK_CLASSES:
            raise ValueError(f"unknown attack class {attack_class!r}, expected one of {ATTACK_CLASSES}")
        if resolution not in RESOLUTIONS:
            raise ValueError(f"unknown resolution {resolution!r}, expected one of {RESOLUTIONS}")
        if language not in LANGUAGES:
            raise ValueError(f"unknown language {language!r}, expected one of {LANGUAGES}")
        entries = self._read()
        comment_id = uuid.uuid4().hex[:12]
        entries.append({
            "id": comment_id,
            "attack_class": attack_class,
            "resolution": resolution,
            "language": language,
            "label": label,
            "text": text,
            "created_by": admin,
            "created": datetime.now(timezone.utc).isoformat(),
        })
        self._write(entries)
        return comment_id

    def list(self, attack_class: str | None = None, language: str | None = None) -> list[dict]:
        entries = self._read()
        if attack_class is not None:
            entries = [e for e in entries if e["attack_class"] == attack_class]
        if language is not None:
            entries = [e for e in entries if e.get("language") == language]
        return sorted(entries, key=lambda e: (e["attack_class"], e["label"]))

    def delete(self, comment_id: str) -> None:
        entries = self._read()
        remaining = [e for e in entries if e["id"] != comment_id]
        if len(remaining) == len(entries):
            raise ValueError(f"no comment {comment_id!r}")
        self._write(remaining)
