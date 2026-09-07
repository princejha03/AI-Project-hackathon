"""webapp/scanner.py -- the naive stand-in scanner behind the web UI's
"upload an arbitrary Java project" flow. No fixtures here: JavaMethod objects
are built by hand so each test isolates exactly the source/passthrough/sink
shape it's checking.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from truesignal.code_indexer import JavaMethod
from truesignal.webapp.scanner import _bare, scan_methods


def _method(qname, calls, file="Demo.java", line=10):
    class_name, method_name = qname.split(".")
    return JavaMethod(
        qualified_name=qname, class_name=class_name, method_name=method_name,
        file=file, line=line, source=f"// {qname}", calls=calls,
    )


def test_bare_strips_receiver():
    assert _bare("req.getParameter") == "getParameter"
    assert _bare("getParameter") == "getParameter"


def test_finds_sql_injection_source_to_sink():
    methods = {"Servlet.handle": _method("Servlet.handle", ["req.getParameter", "stmt.executeQuery"])}
    findings = scan_methods(methods)
    assert "Servlet.handle" in findings
    f = findings["Servlet.handle"]
    assert f["attackClass"] == "sql_injection"
    assert f["queryName"] == "SQL_Injection"
    roles = [step["role"] for step in f["taintPath"]]
    assert roles == ["source", "sink"]


def test_passthrough_steps_are_recorded_in_order():
    methods = {"Servlet.handle": _method(
        "Servlet.handle", ["req.getParameter", "helper.clean", "helper.trim", "stmt.executeQuery"])}
    f = scan_methods(methods)["Servlet.handle"]
    roles = [step["role"] for step in f["taintPath"]]
    assert roles == ["source", "passthrough", "passthrough", "sink"]
    assert f["taintPath"][1]["node"] == "helper.clean()"
    assert f["taintPath"][2]["node"] == "helper.trim()"


def test_no_finding_without_a_sink():
    methods = {"Servlet.handle": _method("Servlet.handle", ["req.getParameter", "helper.clean"])}
    assert scan_methods(methods) == {}


def test_no_finding_without_a_source():
    methods = {"Dao.query": _method("Dao.query", ["stmt.executeQuery"])}
    assert scan_methods(methods) == {}


def test_learned_source_surfaces_a_previously_invisible_finding():
    methods = {"Servlet.legacyLookup": _method(
        "Servlet.legacyLookup", ["legacy.getParam", "stmt.executeQuery"])}
    assert scan_methods(methods) == {}  # "getParam" isn't a known source on its own

    findings = scan_methods(methods, learned_sources={"getParam": "LegacyRequest.getParam"})
    assert "Servlet.legacyLookup" in findings
    assert findings["Servlet.legacyLookup"]["taintPath"][0]["node"] == "LegacyRequest.getParam()"


def test_recognizes_other_attack_classes():
    methods = {
        "Handler.cmd": _method("Handler.cmd", ["req.getParameter", "runtime.exec"]),
        "Handler.file": _method("Handler.file", ["req.getHeader", "files.readAllBytes"]),
        "Handler.ssrf": _method("Handler.ssrf", ["req.getParameter", "rest.getForObject"]),
        "Handler.ldap": _method("Handler.ldap", ["req.getParameter", "ctx.searchDirectory"]),
    }
    findings = scan_methods(methods)
    assert findings["Handler.cmd"]["attackClass"] == "command_injection"
    assert findings["Handler.file"]["attackClass"] == "path_traversal"
    assert findings["Handler.ssrf"]["attackClass"] == "ssrf"
    assert findings["Handler.ldap"]["attackClass"] == "ldap_injection"


def test_only_traces_within_a_single_methods_own_calls():
    """The source and the sink must both appear in the SAME method's call
    list -- scan_methods never chases a source across a call into another
    method (that's the whole reason LegacyRequest.getParam stays invisible
    until it's explicitly taught as a learned source)."""
    methods = {
        "Servlet.a": _method("Servlet.a", ["req.getParameter"]),
        "Dao.b": _method("Dao.b", ["stmt.executeQuery"]),
    }
    assert scan_methods(methods) == {}


def test_single_letter_calls_from_comment_noise_are_ignored():
    """code_indexer's call regex doesn't strip comments, so a stray line
    comment can produce a spurious single-letter "call" -- scanner must
    filter those out rather than let them break source/sink detection."""
    methods = {"Servlet.handle": _method(
        "Servlet.handle", ["req.getParameter", "x", "stmt.executeQuery"])}
    f = scan_methods(methods)["Servlet.handle"]
    roles = [step["role"] for step in f["taintPath"]]
    assert roles == ["source", "sink"], "the noise call must not appear as a passthrough step"
