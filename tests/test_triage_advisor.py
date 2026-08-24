"""Unit tests for the advisory triage suggester.

This module never decides anything -- it only pre-fills the audit form -- so
these tests check the three verdicts it's allowed to reach and, just as
importantly, when it must stay conservative (TO_VERIFY) instead of guessing.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from truesignal.triage_advisor import CONFIRMED, NOT_EXPLOITABLE, TO_VERIFY, suggest_verdict


def _step(role: str, resolved_source: str | None = None, qname: str = "Some.method") -> dict:
    step = {"node": qname + "()", "role": role}
    if resolved_source is not None:
        step["resolved"] = {"qualified_name": qname, "file": "x.java", "line": 1, "source": resolved_source}
    else:
        step["resolved"] = None
    return step


def test_no_passthrough_suggests_confirmed():
    """Source flows straight into the sink -- nothing could have sanitized it."""
    path = [_step("source"), _step("sink")]
    result = suggest_verdict(path)
    assert result["verdict"] == CONFIRMED
    assert result["confidence"] > 0.5
    assert "nothing had the chance to sanitize" in result["reason"]


def test_recognized_sanitizer_shape_suggests_not_exploitable():
    path = [
        _step("source"),
        _step("passthrough", resolved_source='if (isLetterOrDigit(c)) { out.append(c); }',
              qname="InputCleaner.sanitize"),
        _step("sink"),
    ]
    result = suggest_verdict(path)
    assert result["verdict"] == NOT_EXPLOITABLE
    assert "InputCleaner.sanitize" in result["reason"]
    assert "sql_injection" in result["reason"]


def test_unrecognized_passthrough_suggests_to_verify_not_confirmed():
    """A passthrough function that isn't a known sanitizer shape must NOT be
    treated as confirmed-exploitable -- it might be a custom sanitizer this
    tool hasn't learned yet. Staying conservative here is the whole point."""
    path = [
        _step("source"),
        _step("passthrough", resolved_source="return raw.trim();", qname="Helper.trim"),
        _step("sink"),
    ]
    result = suggest_verdict(path)
    assert result["verdict"] == TO_VERIFY
    assert result["confidence"] < 0.5


def test_unresolvable_passthrough_step_does_not_crash():
    """A passthrough step the indexer couldn't resolve (framework/JDK call)
    has resolved=None -- must degrade to TO_VERIFY, not raise."""
    path = [_step("source"), _step("passthrough", resolved_source=None), _step("sink")]
    result = suggest_verdict(path)
    assert result["verdict"] == TO_VERIFY


def test_checks_every_passthrough_step_not_just_the_first():
    path = [
        _step("source"),
        _step("passthrough", resolved_source="return raw.trim();", qname="Helper.trim"),
        _step("passthrough", resolved_source='out.append("&lt;")', qname="HtmlEncoder.encode"),
        _step("sink"),
    ]
    result = suggest_verdict(path)
    assert result["verdict"] == NOT_EXPLOITABLE
    assert "HtmlEncoder.encode" in result["reason"]
    assert "xss" in result["reason"]
