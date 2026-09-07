"""webapp/store.py -- ProjectStore's upload handling, zip-safety checks, and
the audit/rollback/settings persistence behind the web UI.

Every test gets its own PROJECTS_ROOT (monkeypatched to tmp_path) and its own
project-wide training/comment-bank roots, so nothing here ever touches this
checkout's real .truesignal_ui or .truesignal state.
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from truesignal import comment_bank, training_store
from truesignal.webapp import store as store_module
from truesignal.webapp.store import ProjectStore


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "PROJECTS_ROOT", tmp_path / "projects")
    monkeypatch.setattr(training_store, "DEFAULT_ROOT", tmp_path / "training")
    monkeypatch.setattr(comment_bank, "DEFAULT_ROOT", tmp_path / "comments")
    return ProjectStore()


SIMPLE_JAVA = b"""
public class Widget {
    public String handle(HttpServletRequest req) {
        String q = req.getParameter("id");
        return q;
    }
}
"""


def test_builtin_demos_are_seeded_on_construction(isolated_store):
    ids = {p["id"] for p in isolated_store.list_projects()}
    assert {"storefront-demo", "accountvault-demo", "docexchange-demo"} <= ids


def test_create_from_zip_indexes_and_scans(isolated_store):
    pid = isolated_store.create_from_zip("My Project", _zip_bytes({"src/Widget.java": SIMPLE_JAVA}))
    assert isolated_store.exists(pid)
    meta = isolated_store.meta(pid)
    assert meta["name"] == "My Project"
    assert meta["seeded"] is False
    # a real upload never gets synthetic triage history
    assert isolated_store.get_triage(pid)["decisions"] == []


def test_create_from_zip_rejects_path_traversal(isolated_store):
    evil = _zip_bytes({"../../evil.txt": b"pwned"})
    with pytest.raises(ValueError, match="unsafe path"):
        isolated_store.create_from_zip("evil", evil)


def test_create_from_zip_rejects_oversized_uncompressed_archive(isolated_store, monkeypatch):
    monkeypatch.setattr(ProjectStore, "_MAX_UNCOMPRESSED_BYTES", 10)
    payload = _zip_bytes({"Big.java": b"x" * 100})
    with pytest.raises(ValueError, match="more than"):
        isolated_store.create_from_zip("big", payload)


def test_slugify_produces_unique_ids_for_the_same_name(isolated_store):
    pid1 = isolated_store.create_from_zip("dup", _zip_bytes({"A.java": SIMPLE_JAVA}))
    pid2 = isolated_store.create_from_zip("dup", _zip_bytes({"A.java": SIMPLE_JAVA}))
    assert pid1 != pid2


def test_add_audit_and_latest_audit_roundtrip(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    assert isolated_store.latest_audit(pid, "CX-1") is None
    isolated_store.add_audit(pid, "CX-1", "DISMISS", "NOT_EXPLOITABLE", "safe", "alice")
    isolated_store.add_audit(pid, "CX-1", "CONFIRM", "CONFIRMED", "actually not", "bob")
    latest = isolated_store.latest_audit(pid, "CX-1")
    assert latest["user"] == "bob"
    assert latest["resolution"] == "CONFIRMED"


def test_settings_roundtrip_and_reset(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    assert isolated_store.get_settings(pid) == {}
    isolated_store.save_settings(pid, 0.75, 2)
    assert isolated_store.get_settings(pid) == {"min_confidence_auto": 0.75, "min_triage_support": 2}
    cfg = isolated_store.config_for(pid)
    assert cfg.min_confidence_auto == 0.75
    assert cfg.min_triage_support == 2

    isolated_store.save_settings(pid, None, None)
    assert isolated_store.get_settings(pid) == {}


def test_delete_project_protects_builtin_demos(isolated_store):
    with pytest.raises(ValueError, match="can't be deleted"):
        isolated_store.delete_project("storefront-demo")


def test_delete_project_removes_uploaded_project(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    isolated_store.delete_project(pid)
    assert not isolated_store.exists(pid)


def test_rollback_override_removes_it_and_ledgers_the_rollback(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    client = isolated_store.client_for(pid)
    override = {"name": "truesignal_sanitizer_Widget_clean", "kind": "sanitizer",
                "function": "Widget.clean", "confidence": 0.9, "attackClass": "sql_injection"}
    client.apply_query_overrides(pid, [override])

    isolated_store.rollback_override(pid, override["name"], rolled_back_by="admin")

    from truesignal.override_generator import Ledger
    ledger = Ledger(isolated_store.config_for(pid).state_dir)
    events = [e["event"] for e in ledger._read()]
    assert events == ["rolled_back"]
    assert "Widget.clean" not in ledger.already_learned()

    # a rolled-back override is the strongest possible negative signal --
    # it must produce a pending training correction.
    pending = training_store.TrainingStore().list(status=training_store.PENDING)
    assert any(e["qualified_name"] == "Widget.clean" and e["source_event"] == "rollback" for e in pending)


def test_rollback_override_unknown_name_raises(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    with pytest.raises(ValueError, match="not currently applied"):
        isolated_store.rollback_override(pid, "no-such-override")


def test_check_confirmed_bypasses_sanitizer(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    client = isolated_store.client_for(pid)
    override = {"name": "ov1", "kind": "sanitizer", "function": "Widget.clean",
                "confidence": 0.9, "attackClass": "sql_injection"}
    client.apply_query_overrides(pid, [override])

    finding = {"taintPath": [
        {"node": "Widget.source()", "role": "source"},
        {"node": "Widget.clean()", "role": "passthrough"},
        {"node": "Widget.sink()", "role": "sink"},
    ]}
    assert isolated_store.check_confirmed_bypasses_sanitizer(pid, finding) == override

    clean_finding = {"taintPath": [{"node": "Widget.source()", "role": "source"},
                                    {"node": "Widget.sink()", "role": "sink"}]}
    assert isolated_store.check_confirmed_bypasses_sanitizer(pid, clean_finding) is None


def test_recent_activity_sorted_newest_first_and_limited(isolated_store):
    pid = isolated_store.create_from_zip("p", _zip_bytes({"A.java": SIMPLE_JAVA}))
    isolated_store.add_audit(pid, "CX-1", "DISMISS", "NOT_EXPLOITABLE", "c1", "alice")
    isolated_store.add_audit(pid, "CX-2", "CONFIRM", "CONFIRMED", "c2", "bob")

    events = isolated_store.recent_activity(limit=1)
    assert len(events) == 1
    assert events[0]["user"] == "bob"  # most recent audit first

    all_events = isolated_store.recent_activity(limit=None)
    assert len(all_events) >= 2
