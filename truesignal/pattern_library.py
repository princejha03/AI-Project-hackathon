"""Cross-project pattern library — advisory only, never auto-applied.

Once a function is proven and applied as a sanitizer/source/sink override in
one project, its code shape is a reusable pattern: other projects often carry
a structurally similar (sometimes literally copy-pasted) helper that hasn't
been classified yet. This module flags those matches so a reviewer starts
from "these two functions look alike" instead of re-deriving the same
classification from scratch in every project TrueSignal ever sees.

Deterministic string similarity (difflib's SequenceMatcher), not embeddings
or another LLM call — a reviewer can see exactly why two functions matched
by reading the same two snippets themselves. And it is purely advisory: this
module never changes a verdict, a threshold, or an override. verifier.py is
still the only thing allowed to do that.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from .code_indexer import JavaMethod

MIN_SIMILARITY = 0.4
_WS_RE = re.compile(r"\s+")


@dataclass
class LearnedPattern:
    """A function some project has already applied a real override for."""
    project_id: str
    project_name: str
    qualified_name: str
    kind: str  # sanitizer | source | sink
    attack_class: str
    confidence: float
    source: str


@dataclass
class PatternMatch:
    candidate: str  # candidate's qualified_name
    pattern: LearnedPattern
    similarity: float
    name_similarity: float
    body_similarity: float


def _normalize(source: str) -> str:
    return _WS_RE.sub(" ", source).strip()


def score(method: JavaMethod, pattern: LearnedPattern) -> tuple[float, float, float]:
    """(combined, name_similarity, body_similarity) -- body weighted higher
    than name, since two unrelated helpers can share a common name like
    "clean" or "escape" but two independently-written functions that also
    read alike are the stronger, more explainable signal."""
    name_sim = SequenceMatcher(None, method.method_name.lower(),
                                pattern.qualified_name.split(".")[-1].lower()).ratio()
    body_sim = SequenceMatcher(None, _normalize(method.source), _normalize(pattern.source)).ratio()
    return 0.35 * name_sim + 0.65 * body_sim, name_sim, body_sim


def find_matches(
    candidates: list[JavaMethod],
    patterns: list[LearnedPattern],
    *,
    exclude_project: str | None = None,
    min_similarity: float = MIN_SIMILARITY,
    limit_per_candidate: int = 1,
) -> list[PatternMatch]:
    """For each candidate method, the best learned pattern(s) from *other*
    projects whose name+body shape clears min_similarity, most similar first."""
    matches = []
    for method in candidates:
        scored = []
        for pattern in patterns:
            if exclude_project is not None and pattern.project_id == exclude_project:
                continue
            combined, name_sim, body_sim = score(method, pattern)
            if combined >= min_similarity:
                scored.append(PatternMatch(method.qualified_name, pattern, combined, name_sim, body_sim))
        scored.sort(key=lambda m: m.similarity, reverse=True)
        matches.extend(scored[:limit_per_candidate])
    matches.sort(key=lambda m: m.similarity, reverse=True)
    return matches
