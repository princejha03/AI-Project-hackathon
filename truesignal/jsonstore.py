"""Shared JSON persistence for every state file this project writes --
ledger, feedback, triage, training examples, run history, applied overrides.

Every one of those was previously written with a plain `path.write_text(...)`.
If the process is killed or the disk fills up mid-write, that leaves a
truncated file on disk, and the *next* read explodes with a raw
json.JSONDecodeError -- there's no recovery path, and for files like
ledger.json that's this project's entire audit trail. write_json writes to a
temp file in the same directory and atomically renames it over the real path
(os.replace, atomic on both POSIX and Windows) so a reader only ever sees the
previous complete file or the new complete file, never a partial one.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
