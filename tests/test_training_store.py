"""TrainingStore: the two-gate curation store behind the fine-tune loop --
a reviewer's correction lands as 'pending'; only an admin's approve/discard
decides what an export ever sees."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from truesignal.training_store import APPROVED, DISCARDED, PENDING, TrainingStore


def _model_output(role="sanitizer", confidence=0.9):
    return {"role": role, "confidence": confidence, "attack_classes": ["sql_injection"],
            "code_reasons": ["allow-list"], "notes": "n"}


def test_record_candidate_starts_pending(tmp_path):
    store = TrainingStore(tmp_path)
    eid = store.record_candidate(
        qualified_name="Foo.bar", prompt="PROMPT", model_output=_model_output(),
        corrected_role="none", corrected_attack_classes=[],
        source_event="review_reject", verified_by="appsec", verified_role="AppSec",
    )
    pending = store.list(PENDING)
    assert len(pending) == 1
    assert pending[0]["id"] == eid
    assert pending[0]["reviewed_by"] is None
    assert store.export_dataset() == []  # never exported while pending


def test_set_status_unknown_id_raises(tmp_path):
    store = TrainingStore(tmp_path)
    with pytest.raises(ValueError):
        store.set_status("does-not-exist", APPROVED, admin="admin")


def test_set_status_rejects_bad_status(tmp_path):
    store = TrainingStore(tmp_path)
    eid = store.record_candidate(qualified_name="Foo.bar", prompt="P", model_output=None,
                                  corrected_role="none", corrected_attack_classes=[],
                                  source_event="rollback", verified_by="admin", verified_role="admin")
    with pytest.raises(ValueError):
        store.set_status(eid, "pending", admin="admin")


def test_admin_approval_gates_export(tmp_path):
    store = TrainingStore(tmp_path)
    eid = store.record_candidate(
        qualified_name="Foo.bar", prompt="PROMPT", model_output=_model_output(),
        corrected_role="none", corrected_attack_classes=[],
        source_event="review_reject", verified_by="appsec", verified_role="AppSec",
    )
    assert store.export_dataset() == []
    store.set_status(eid, APPROVED, admin="admin")
    dataset = store.export_dataset()
    assert len(dataset) == 1
    messages = dataset[0]["messages"]
    assert messages[1]["content"] == "PROMPT"
    completion = json.loads(messages[2]["content"])
    assert completion["role"] == "none"  # the corrected label, not the model's original guess


def test_admin_can_edit_correction_before_approving(tmp_path):
    store = TrainingStore(tmp_path)
    eid = store.record_candidate(
        qualified_name="Foo.bar", prompt="PROMPT", model_output=_model_output(),
        corrected_role="none", corrected_attack_classes=[],
        source_event="review_reject", verified_by="appsec", verified_role="AppSec",
    )
    store.set_status(eid, APPROVED, admin="admin", corrected_role="source",
                      corrected_attack_classes=["xss"])
    completion = json.loads(store.export_dataset()[0]["messages"][2]["content"])
    assert completion["role"] == "source"
    assert completion["attack_classes"] == ["xss"]


def test_discarded_examples_never_export(tmp_path):
    store = TrainingStore(tmp_path)
    eid = store.record_candidate(qualified_name="Foo.bar", prompt="P", model_output=_model_output(),
                                  corrected_role="none", corrected_attack_classes=[],
                                  source_event="rollback", verified_by="admin", verified_role="admin")
    store.set_status(eid, DISCARDED, admin="admin")
    assert store.list(DISCARDED)[0]["id"] == eid
    assert store.export_dataset() == []


def test_add_manual_is_approved_immediately(tmp_path):
    store = TrainingStore(tmp_path)
    store.add_manual(qualified_name="Baz.qux", prompt="P2", corrected_role="sink",
                      corrected_attack_classes=["command_injection"], admin="admin")
    assert store.list(PENDING) == []
    dataset = store.export_dataset()
    assert len(dataset) == 1
    assert json.loads(dataset[0]["messages"][2]["content"])["role"] == "sink"


def test_no_unverified_input_reaches_export(tmp_path):
    """The core guarantee the user asked for: a raw reviewer correction is
    never enough on its own -- only an explicit admin approval flips it into
    the exported set."""
    store = TrainingStore(tmp_path)
    for i in range(5):
        store.record_candidate(qualified_name=f"F{i}.m", prompt=f"P{i}", model_output=_model_output(),
                                corrected_role="none", corrected_attack_classes=[],
                                source_event="review_reject", verified_by="appsec", verified_role="AppSec")
    assert len(store.list(PENDING)) == 5
    assert store.export_dataset() == []
