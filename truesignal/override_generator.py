"""Persistence layer: learned semantics -> CxQL query overrides.

Template-based on purpose — the LLM classifies, but rule generation is
deterministic. One template per role (sanitizer/source/sink), parameterized
by attack class so a Path Traversal sanitizer doesn't generate a
`base.SqlInjection()` override just because that was the first vulnerability
class this ever supported.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .jsonstore import read_json, write_json

SANITIZER_TEMPLATE = """// TrueSignal override — add custom sanitizer: {qname}
// Evidence: {evidence}
result = base.{base_query}();
CxList customSanitizer = All.FindByMemberAccess("{qname}");
result = result - result.InfluencedBy(customSanitizer.DataInfluencedBy(result));
"""

SOURCE_TEMPLATE = """// TrueSignal override — add custom taint source: {qname}
// Evidence: {evidence}
CxList customSource = All.FindByMemberAccess("{qname}");
CxList db = Find_DB_In();
result = customSource.InfluencingOnAndNotSanitized(db, Find_Sanitize());
result = base.{base_query}() + result;
"""

SINK_TEMPLATE = """// TrueSignal override — add custom sink: {qname}
// Evidence: {evidence}
CxList customSink = All.FindByMemberAccess("{qname}");
result = base.{base_query}() +
    Find_Interactive_Inputs().InfluencingOnAndNotSanitized(customSink, Find_Sanitize());
"""

_TEMPLATES = {"sanitizer": SANITIZER_TEMPLATE, "source": SOURCE_TEMPLATE, "sink": SINK_TEMPLATE}

# attack_class (as returned by the classifier) -> (display queryName, CxQL base query).
# Unrecognized/missing attack classes fall back to sql_injection, matching this
# project's original single-class behavior.
_ATTACK_CLASS_META = {
    "sql_injection": ("SQL_Injection", "SqlInjection"),
    "command_injection": ("Command_Injection", "Cmd_Execution"),
    "path_traversal": ("Path_Traversal", "Path_Traversal"),
    "xss": ("XSS_Reflected", "Reflected_XSS"),
    "ssrf": ("SSRF", "Server_Side_Request_Forgery"),
    "ldap_injection": ("LDAP_Injection", "LDAP_Injection"),
}


def generate_overrides(verified: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn APPROVED (or human-approved) verdicts into override records."""
    overrides = []
    for v in verified:
        if v["role"] not in _TEMPLATES:
            continue
        attack_class = next(iter(v.get("attack_classes") or []), "sql_injection")
        query_name, base_query = _ATTACK_CLASS_META.get(attack_class, _ATTACK_CLASS_META["sql_injection"])
        evidence = (f"{v['evidence']['triage_count']} dismissals, "
                    f"confidence {v['confidence']:.2f}")
        overrides.append({
            "name": f"truesignal_{v['role']}_{v['qualified_name'].replace('.', '_')}",
            "kind": v["role"],
            "function": v["qualified_name"],
            "queryName": query_name,
            "attackClass": attack_class,
            "language": "Java",
            "group": "Java_Custom",
            "cxql": _TEMPLATES[v["role"]].format(
                qname=v["qualified_name"], evidence=evidence, base_query=base_query),
            "confidence": v["confidence"],
            "evidence": v["evidence"],
        })
    return overrides


class Ledger:
    """Append-only audit trail of everything learned and applied."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "ledger.json"

    def _read(self) -> list[dict]:
        return read_json(self.path, default=[])

    def already_learned(self) -> set[str]:
        # Latest event per function wins, so a "rolled_back" entry after an
        # "applied" one makes that function eligible to be relearned.
        latest: dict[str, str] = {}
        for e in self._read():
            latest[e["override"]["function"]] = e["event"]
        return {fn for fn, event in latest.items() if event == "applied"}

    def applied_overrides(self) -> dict[str, dict[str, Any]]:
        """function -> its override record, for whatever is *currently* applied
        (latest event per function is "applied", same rule as already_learned()).
        Used to turn ledger history back into reusable pattern data."""
        latest: dict[str, dict[str, Any]] = {}
        for e in self._read():
            if e["event"] == "applied":
                latest[e["override"]["function"]] = e["override"]
            else:
                latest.pop(e["override"]["function"], None)
        return latest

    def record(self, event: str, override: dict[str, Any]) -> None:
        entries = self._read()
        entries.append({
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "override": override,
        })
        write_json(self.path, entries)
