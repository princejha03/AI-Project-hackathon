"""Advisory triage suggestions -- speeds up manual audit, decides nothing.

Given one finding's taint path (already resolved to source code by the code
indexer, the same way audit.html displays it), suggest a likely verdict and
a short reason to pre-fill the audit form. This sits entirely outside the
learn -> verify -> apply pipeline: nothing here is ever ledgered, nothing
here is ever auto-applied, and a wrong suggestion costs a human one extra
click to override -- unlike a wrongly-learned sanitizer, which would
manufacture a real false negative (see verifier.py). That asymmetry is why
this module gets a much lighter evidence bar than the verification gate, and
why it stays honest about its limits rather than guessing: it only ever
claims NOT_EXPLOITABLE when it names a concrete, recognized sanitizer
shape, and only ever claims CONFIRMED when there is *nothing* between
source and sink that could have sanitized the value. Everything else is
TO_VERIFY -- "I don't recognize what's happening here, a human should look."
"""
from __future__ import annotations

from typing import Any

NOT_EXPLOITABLE = "not_exploitable"
CONFIRMED = "confirmed"
TO_VERIFY = "to_verify"

# The same code-shape signatures llm_classifier.py's MockClassifier recognizes
# per attack class. Kept separate (not imported) on purpose: this module
# reasons about a whole taint *path* for triage, not a single function's
# *role* for override generation, and the two are free to diverge as each
# grows its own signals.
_SANITIZER_SHAPES: list[tuple[str, Any, str]] = [
    ("sql_injection", lambda s: "isLetterOrDigit" in s or 'replaceAll("[^' in s,
     "a strict allow-list character filter"),
    ("path_traversal", lambda s: '".."' in s or 'replace("..' in s,
     "a filter that strips \"..\" path-traversal sequences"),
    ("xss", lambda s: "&lt;" in s,
     "an HTML encoder for markup metacharacters"),
    ("ssrf", lambda s: "ALLOWED_HOSTS" in s,
     "a fixed host allow-list check"),
    ("ldap_injection", lambda s: r"\\2a" in s or r"\\28" in s,
     "an RFC 4515 LDAP metacharacter escaper"),
]


def _detect_sanitizer_shape(source: str) -> dict[str, str] | None:
    for attack_class, matches, description in _SANITIZER_SHAPES:
        if matches(source):
            return {"attack_class": attack_class, "description": description}
    return None


def suggest_verdict(path: list[dict[str, Any]]) -> dict[str, Any]:
    """path: a finding's taint path, each step carrying a `role`
    ("source" | "passthrough" | "sink") and optionally a `resolved` dict with
    the step's indexed source code (the same shape audit.html already
    renders). Returns {"verdict", "confidence", "reason"}."""
    passthrough = [s for s in path if s.get("role") == "passthrough"]

    if not passthrough:
        return {
            "verdict": CONFIRMED,
            "confidence": 0.75,
            "reason": "No function sits between the source and the sink on this "
                      "path -- nothing had the chance to sanitize the value.",
        }

    for step in passthrough:
        resolved = step.get("resolved")
        source = resolved["source"] if resolved else ""
        shape = _detect_sanitizer_shape(source)
        if shape:
            qname = resolved["qualified_name"]
            return {
                "verdict": NOT_EXPLOITABLE,
                "confidence": 0.70,
                "reason": f"{qname}() looks like {shape['description']} for "
                          f"{shape['attack_class']} -- worth confirming it actually "
                          "runs on this path before dismissing.",
            }

    return {
        "verdict": TO_VERIFY,
        "confidence": 0.40,
        "reason": "This path passes through a function that isn't a recognized "
                  "sanitizer shape -- it could be a custom one this tool hasn't "
                  "learned yet, or it could do nothing. Worth a closer look.",
    }
