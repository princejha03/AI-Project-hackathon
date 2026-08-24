"""Atomic JSON persistence: a reader must never see a partially-written file."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from truesignal.jsonstore import read_json, write_json


def test_read_json_missing_file_returns_default(tmp_path):
    assert read_json(tmp_path / "missing.json", default=[]) == []
    assert read_json(tmp_path / "missing.json", default={"a": 1}) == {"a": 1}


def test_write_then_read_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    write_json(path, {"decisions": [1, 2, 3]})
    assert read_json(path, default=None) == {"decisions": [1, 2, 3]}


def test_write_creates_parent_directories(tmp_path):
    path = tmp_path / "nested" / "deeper" / "state.json"
    write_json(path, {"x": 1})
    assert read_json(path, default=None) == {"x": 1}


def test_write_leaves_no_temp_file_behind(tmp_path):
    path = tmp_path / "state.json"
    write_json(path, [1, 2, 3])
    leftovers = list(tmp_path.glob(".*.tmp"))
    assert leftovers == []


def test_overwrite_replaces_old_content_atomically(tmp_path):
    path = tmp_path / "state.json"
    write_json(path, {"version": 1})
    write_json(path, {"version": 2})
    assert read_json(path, default=None) == {"version": 2}
    # exactly one file on disk -- no leftover temp/old copy
    assert list(tmp_path.iterdir()) == [path]


def test_failed_write_does_not_corrupt_existing_file(tmp_path, monkeypatch):
    """If json.dump blows up partway through (e.g. an unserializable value
    slipped in), the file that was already there must survive untouched --
    that's the entire point of writing to a temp file first."""
    path = tmp_path / "state.json"
    write_json(path, {"safe": "original"})

    class Unserializable:
        pass

    with pytest.raises(TypeError):
        write_json(path, {"bad": Unserializable()})

    assert read_json(path, default=None) == {"safe": "original"}
    # the failed attempt's temp file must be cleaned up, not left behind
    assert list(tmp_path.glob(".*.tmp")) == []
