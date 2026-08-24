"""Built-in stand-in scanner used only by the web UI.

Real TrueSignal deployments get findings from Checkmarx One (live mode) or
from bundled fixtures (the CLI demo's MockCheckmarxClient). The web UI lets
you upload an arbitrary Java project with no SAST engine behind it, so it
needs *some* way to produce initial findings and to react to newly learned
sources/sanitizers. This is that stand-in: it traces, within each indexed
method's own call sequence, a known-source call followed later by a call
that resolves to a known sink, generalizing the exact source/passthrough/
sink shape the CLI demo hardcodes for its one fixed repo.

It deliberately only looks at a method's OWN call list (never crosses into
a second method to keep chasing a source) — that is what keeps a wrapper
class like LegacyRequest.getParam() invisible until its bare name is added
to learned_sources, mirroring why real engines miss it too.

Recognizes more than one vulnerability class: SQL Injection (the CLI demo's
class) and Command Injection, each with its own literal sink names and
CxQL-style query name, so the same trace logic below is shared across
classes instead of being SQL-specific.
"""
from __future__ import annotations

from typing import Any

from ..code_indexer import KNOWN_SINKS, KNOWN_SOURCES, JavaMethod

# bare call name -> (attack_class, CxQL-style query name). KNOWN_SINKS come
# from the shared indexer (SQL); the rest are additions scoped to this
# module only, so the CLI's own detection is untouched. Sink names are
# deliberately distinctive (never generic JDK names like write/print/get)
# so a real uploaded project's unrelated code can't spuriously trip them.
_SINK_CLASSES: dict[str, tuple[str, str]] = {
    **{s: ("sql_injection", "SQL_Injection") for s in KNOWN_SINKS},
    # Spring JdbcTemplate / JPA raw-SQL equivalents of the plain-JDBC sinks
    # above -- same vulnerability class, just the calling convention real
    # Spring apps actually use instead of java.sql.Statement directly.
    "createNativeQuery": ("sql_injection", "SQL_Injection"),
    "queryForObject": ("sql_injection", "SQL_Injection"),
    "queryForList": ("sql_injection", "SQL_Injection"),
    "queryForMap": ("sql_injection", "SQL_Injection"),
    "batchUpdate": ("sql_injection", "SQL_Injection"),
    "exec": ("command_injection", "Command_Injection"),
    "readAllBytes": ("path_traversal", "Path_Traversal"),
    # java.nio.file.Files equivalents of readAllBytes.
    "readAllLines": ("path_traversal", "Path_Traversal"),
    "readString": ("path_traversal", "Path_Traversal"),
    "newInputStream": ("path_traversal", "Path_Traversal"),
    "renderUnescaped": ("xss", "XSS_Reflected"),
    "fetchRemote": ("ssrf", "SSRF"),
    # RestTemplate / java.net.URL equivalents of fetchRemote.
    "getForObject": ("ssrf", "SSRF"),
    "getForEntity": ("ssrf", "SSRF"),
    "postForObject": ("ssrf", "SSRF"),
    "postForEntity": ("ssrf", "SSRF"),
    "openConnection": ("ssrf", "SSRF"),
    "searchDirectory": ("ldap_injection", "LDAP_Injection"),
}


def _bare(call: str) -> str:
    return call.rsplit(".", 1)[-1]


def _resolve_sink(bare: str, methods: dict[str, JavaMethod]) -> tuple[str, str, str] | None:
    """Returns (node_repr, attack_class, query_name) or None."""
    if bare in _SINK_CLASSES:
        attack_class, query_name = _SINK_CLASSES[bare]
        return bare, attack_class, query_name
    for qname, m in methods.items():
        if m.method_name == bare and m.touches_known_sink:
            return qname, "sql_injection", "SQL_Injection"
    return None


def scan_methods(
    methods: dict[str, JavaMethod],
    learned_sources: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Trace source -> passthrough* -> sink within each method's calls.

    learned_sources maps a bare call name (e.g. "getParam") to the
    qualified wrapper method that TrueSignal has confirmed wraps a real
    accessor (e.g. "LegacyRequest.getParam") -- passing one in is what
    makes a previously-invisible finding appear on the next scan.

    Returns {qualified_name_of_the_method_holding_the_flow: finding_body}
    (no "id" key yet -- the caller assigns stable ids).
    """
    learned_sources = learned_sources or {}
    findings: dict[str, dict[str, Any]] = {}

    for qname, method in methods.items():
        # code_indexer's call regex doesn't strip comments, so a stray
        # "// ... word (" in a // line comment can produce a spurious
        # single-letter call; those never carry real signal, drop them.
        calls = [c for c in method.calls if len(_bare(c)) > 1]
        source_idx = None
        source_repr = None
        for i, c in enumerate(calls):
            bare = _bare(c)
            if bare in KNOWN_SOURCES:
                source_idx, source_repr = i, bare
                break
            if bare in learned_sources:
                source_idx, source_repr = i, learned_sources[bare]
                break
        if source_idx is None:
            continue

        sink_idx, sink_target, attack_class, query_name = None, None, None, None
        for j in range(source_idx + 1, len(calls)):
            resolved = _resolve_sink(_bare(calls[j]), methods)
            if resolved:
                sink_idx, (sink_target, attack_class, query_name) = j, resolved
                break
        if sink_idx is None:
            continue

        passthrough = calls[source_idx + 1:sink_idx]
        taint_path = [{"node": f"{source_repr}()", "file": method.file,
                        "line": method.line, "role": "source"}]
        for p in passthrough:
            taint_path.append({"node": f"{p}()", "file": method.file,
                                "line": method.line, "role": "passthrough"})
        taint_path.append({"node": f"{sink_target}()", "file": method.file,
                            "line": method.line, "role": "sink"})

        findings[qname] = {
            "queryName": query_name,
            "attackClass": attack_class,
            "severity": "HIGH",
            "state": "TO_VERIFY",
            "sourceFile": method.file,
            "sourceLine": method.line,
            "sinkFile": method.file,
            "sinkLine": method.line,
            "taintPath": taint_path,
        }
    return findings
