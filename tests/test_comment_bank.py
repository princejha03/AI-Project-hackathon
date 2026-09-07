"""CommentBank: admin-curated predefined comments for the audit picker --
authoring is single-gated (an admin writing one directly *is* the
verification step), unlike training_store.py's reviewer/admin two-gate flow."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from truesignal.comment_bank import CommentBank


def test_add_then_list_returns_the_comment(tmp_path):
    bank = CommentBank(tmp_path)
    cid = bank.add(attack_class="csrf", resolution="NOT_EXPLOITABLE", language="JAVA",
                    label="Sanitized via allow-list",
                    text="Goes through the numeric allow-list sanitizer before reaching the query.",
                    admin="admin")
    comments = bank.list()
    assert len(comments) == 1
    assert comments[0]["id"] == cid
    assert comments[0]["attack_class"] == "csrf"
    assert comments[0]["resolution"] == "NOT_EXPLOITABLE"
    assert comments[0]["created_by"] == "admin"


def test_add_rejects_unknown_attack_class(tmp_path):
    bank = CommentBank(tmp_path)
    with pytest.raises(ValueError):
        bank.add(attack_class="not_a_real_class", resolution="CONFIRMED", language="JAVA",
                  label="x", text="x", admin="admin")


def test_add_rejects_unknown_resolution(tmp_path):
    bank = CommentBank(tmp_path)
    with pytest.raises(ValueError):
        bank.add(attack_class="xss", resolution="NOT_A_REAL_RESOLUTION", language="JAVA",
                  label="x", text="x", admin="admin")


def test_add_rejects_unknown_language(tmp_path):
    bank = CommentBank(tmp_path)
    with pytest.raises(ValueError):
        bank.add(attack_class="xss", resolution="CONFIRMED", language="COBOL",
                  label="x", text="x", admin="admin")


def test_list_filters_by_attack_class(tmp_path):
    bank = CommentBank(tmp_path)
    bank.add(attack_class="csrf", resolution="CONFIRMED", language="JAVA", label="a", text="a", admin="admin")
    bank.add(attack_class="xss", resolution="CONFIRMED", language="PYTHON", label="b", text="b", admin="admin")
    assert [c["label"] for c in bank.list(attack_class="xss")] == ["b"]
    assert [c["label"] for c in bank.list(language="PYTHON")] == ["b"]
    assert len(bank.list()) == 2


def test_delete_removes_the_comment(tmp_path):
    bank = CommentBank(tmp_path)
    cid = bank.add(attack_class="xxe", resolution="TO_VERIFY", language="JAVA", label="a", text="a", admin="admin")
    bank.delete(cid)
    assert bank.list() == []


def test_delete_unknown_id_raises(tmp_path):
    bank = CommentBank(tmp_path)
    with pytest.raises(ValueError):
        bank.delete("does-not-exist")
