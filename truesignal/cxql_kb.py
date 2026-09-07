"""Lightweight retrieval over the bundled Checkmarx CxQL API Guide.

No embeddings / vector DB -- the guide is small enough (~300 pages) that a
plain keyword-overlap score over per-method sections is good enough, and it
keeps this dependency-free like the rest of the project's static heuristics
(see pattern_library.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_GUIDE_PATH = Path(__file__).resolve().parent / "data" / "cxql_api_guide.txt"

_PAGE_MARKER = re.compile(r"^--- PAGE (\d+) ---$")
_HEADING = re.compile(r"^\d+(?:\.\d+){1,3}\s+\S")
_WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{1,}")

# Fragments shorter than this are mostly stray table-of-contents leader lines
# (e.g. "5.1.3 CallingMethodOfAny Method (CxList) ..... 22") which also match
# the heading pattern but carry no real content -- fold them into whatever
# chunk precedes them instead of letting them become their own near-empty entry.
_MIN_CHUNK_CHARS = 40


@dataclass
class Chunk:
    heading: str
    page: int
    text: str


def _iter_lines_with_pages(raw: str):
    page = 1
    for line in raw.splitlines():
        m = _PAGE_MARKER.match(line.strip())
        if m:
            page = int(m.group(1))
            continue
        yield line, page


def load_guide(path: Path | None = None) -> list[Chunk]:
    """Parse the guide text into one chunk per numbered section header (e.g.
    "5.1.103 InfluencingOnAndNotSanitized Methods"), each tagged with the page
    it starts on."""
    raw = (path or DEFAULT_GUIDE_PATH).read_text(encoding="utf-8")
    chunks: list[Chunk] = []
    heading, page, body = "Preface", 1, []

    def _flush():
        text = "\n".join(body).strip()
        if text:
            chunks.append(Chunk(heading=heading, page=page, text=text))

    for line, line_page in _iter_lines_with_pages(raw):
        stripped = line.strip()
        if _HEADING.match(stripped):
            pending = "\n".join(body).strip()
            if chunks and len(pending) < _MIN_CHUNK_CHARS:
                chunks[-1].text = (chunks[-1].text + "\n" + pending).strip()
            else:
                _flush()
            heading, page, body = stripped, line_page, []
            continue
        body.append(line)
    _flush()
    return chunks


@lru_cache(maxsize=1)
def get_chunks() -> tuple[Chunk, ...]:
    """Parsed once per process -- the bundled guide file never changes at runtime."""
    return tuple(load_guide())


def _tokens(text: str) -> list[str]:
    return [w.lower() for w in _WORD.findall(text)]


def search(chunks, query: str, top_k: int = 4) -> list[tuple[Chunk, float]]:
    """Score each chunk by token overlap with the query. A heading match counts
    for more than a body match, so a question naming a method
    (e.g. "FindByName") surfaces that method's own section first."""
    q_tokens = set(_tokens(query))
    if not q_tokens:
        return []
    scored = []
    for chunk in chunks:
        heading_hits = q_tokens & set(_tokens(chunk.heading))
        body_hits = q_tokens & set(_tokens(chunk.text))
        score = 3 * len(heading_hits) + len(body_hits)
        if score > 0:
            scored.append((chunk, float(score)))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[:top_k]
