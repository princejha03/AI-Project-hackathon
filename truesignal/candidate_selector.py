"""Select candidate functions for LLM classification.

Never send the whole codebase to the model. Candidates are:
  * sanitizer candidates — functions that appear on the taint paths of
    repeatedly-dismissed findings (they're what the humans keep pointing at)
  * source candidates    — functions that wrap known sources
    (call getParameter/getHeader/...) but aren't recognized sources themselves
  * sink candidates      — functions that touch known sinks

Each candidate carries its evidence bundle: code, call info, the findings
it appears on, and the triage decisions attached to those findings.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .code_indexer import JavaMethod


def _norm(node: str) -> str:
    """'InputCleaner.sanitize()' -> 'InputCleaner.sanitize'"""
    return node.split("(")[0].strip()


def select_candidates(
    methods: dict[str, JavaMethod],
    scan: dict[str, Any],
    triage: dict[str, Any],
) -> list[dict[str, Any]]:
    dismiss_by_finding: dict[str, list[dict]] = defaultdict(list)
    for d in triage["decisions"]:
        if d["action"] == "DISMISS":
            dismiss_by_finding[d["findingId"]].append(d)

    # map qualified function name -> findings whose taint path contains it
    on_path: dict[str, list[dict]] = defaultdict(list)
    for f in scan["results"]:
        for step in f["taintPath"]:
            on_path[_norm(step["node"])].append(f)

    candidates: dict[str, dict] = {}

    # --- sanitizer candidates: on paths of dismissed findings -------------
    for qname, findings in on_path.items():
        method = methods.get(qname)
        if method is None:
            continue
        dismissals = [d for f in findings for d in dismiss_by_finding.get(f["id"], [])]
        if not dismissals:
            continue
        # skip functions that ARE the source or sink endpoints of those paths
        roles = {step["role"] for f in findings for step in f["taintPath"]
                 if _norm(step["node"]) == qname}
        if roles == {"source"} or roles == {"sink"}:
            continue
        candidates[qname] = {
            "qualified_name": qname,
            "hypothesis": "sanitizer",
            "method": method,
            "findings": [f["id"] for f in findings],
            "dismissals": dismissals,
        }

    # --- source candidates: wrap known sources, not endpoints themselves --
    for qname, method in methods.items():
        if method.wraps_known_source and qname not in candidates:
            candidates[qname] = {
                "qualified_name": qname,
                "hypothesis": "source",
                "method": method,
                "findings": [f["id"] for f in on_path.get(qname, [])],
                "dismissals": [],
            }

    # --- sink candidates: touch known sinks with query building -----------
    for qname, method in methods.items():
        if method.touches_known_sink and qname not in candidates:
            candidates[qname] = {
                "qualified_name": qname,
                "hypothesis": "sink",
                "method": method,
                "findings": [f["id"] for f in on_path.get(qname, [])],
                "dismissals": [],
            }

    return list(candidates.values())
