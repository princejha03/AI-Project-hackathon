"""Lightweight Java code indexer (stdlib only — no external parser needed
for the POC; swap in tree-sitter for production multi-language support).

Extracts per file: class name, method signatures, method bodies, and the
method calls each body makes. Good enough to (a) hand function source to
the LLM and (b) know which functions wrap known sources/sinks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

KNOWN_SOURCES = {
    "getParameter", "getHeader", "getQueryString", "getCookies",
    "getInputStream", "getReader", "getParameterMap",
}
KNOWN_SINKS = {"executeQuery", "executeUpdate", "execute", "addBatch"}

_METHOD_RE = re.compile(
    r"(?:public|protected|private|static|final|\s)+"
    r"[\w<>\[\], ?]+\s+"          # return type
    r"(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*"
    r"(?:throws\s+[\w, .]+)?\s*\{",
)
_CALL_RE = re.compile(r"(?P<recv>\w+)?\.?(?P<meth>\w+)\s*\(")
_CLASS_RE = re.compile(r"(?:class|interface)\s+(?P<name>\w+)")


@dataclass
class JavaMethod:
    qualified_name: str          # e.g. InputCleaner.sanitize
    class_name: str
    method_name: str
    file: str
    line: int
    source: str
    calls: list[str] = field(default_factory=list)
    wraps_known_source: bool = False
    touches_known_sink: bool = False


def _method_body(text: str, brace_start: int) -> str:
    """Return the balanced-brace body starting at brace_start ('{')."""
    depth = 0
    for i in range(brace_start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start:i + 1]
    return text[brace_start:]


def index_repo(repo_path: Path) -> dict[str, JavaMethod]:
    """Index all .java files under repo_path. Returns {qualified_name: JavaMethod}."""
    methods: dict[str, JavaMethod] = {}
    for path in sorted(repo_path.rglob("*.java")):
        text = path.read_text(errors="replace")
        m_class = _CLASS_RE.search(text)
        class_name = m_class.group("name") if m_class else path.stem

        for m in _METHOD_RE.finditer(text):
            name = m.group("name")
            if name == class_name:      # constructor — skip for role classification
                continue
            body = _method_body(text, m.end() - 1)
            line = text[:m.start()].count("\n") + 1
            sig_and_body = text[m.start():m.end() - 1].strip() + " " + body

            calls = []
            for c in _CALL_RE.finditer(body):
                meth = c.group("meth")
                if meth in ("if", "for", "while", "switch", "catch", "return", "new"):
                    continue
                recv = c.group("recv")
                calls.append(f"{recv}.{meth}" if recv and recv[0].isupper() else meth)

            qm = JavaMethod(
                qualified_name=f"{class_name}.{name}",
                class_name=class_name,
                method_name=name,
                file=str(path.relative_to(repo_path)),
                line=line,
                source=sig_and_body,
                calls=calls,
                wraps_known_source=any(c.split(".")[-1] in KNOWN_SOURCES for c in calls),
                touches_known_sink=any(c.split(".")[-1] in KNOWN_SINKS for c in calls),
            )
            methods[qm.qualified_name] = qm
    return methods
