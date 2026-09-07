"""Retrieval over the bundled CxQL API Guide: chunking + keyword search."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from truesignal.cxql_kb import load_guide, search

SAMPLE_GUIDE = """--- PAGE 2 ---
Table of Contents
5.1.36 FindByName Methods  .......................................................... 82
5.1.19 Filter Method (Func<DOMProperties, bool>)  ................................ 51
--- PAGE 82 ---
Methods Documentation
5.1.36 FindByName Methods
5.1.36.1 FindByName Method (string, int, int)
Returns a CxList which is a subset of the instance whose elements have a name
matching the given parameter (optionally with wildcards).
Example
CxQL
1 result = All.FindByName("*Me*", 3, 7);
--- PAGE 51 ---
Methods Documentation
5.1.19 Filter Method (Func<DOMProperties, bool>)
Filters the CxList using a predicate over DOMProperties.
Example
CxQL
1 result = All.Filter(p => p.FileName == "Foo.java");
"""


def _write_sample(tmp_path) -> Path:
    p = tmp_path / "guide.txt"
    p.write_text(SAMPLE_GUIDE, encoding="utf-8")
    return p


def test_load_guide_folds_short_toc_fragments_into_prior_chunk(tmp_path):
    chunks = load_guide(_write_sample(tmp_path))
    headings = [c.heading for c in chunks]
    # The dotted-leader ToC lines match the heading pattern too, but carry no
    # real body text -- they should not survive as their own chunks.
    toc_heading = "5.1.36 FindByName Methods  .......................................................... 82"
    assert toc_heading not in headings
    assert any("FindByName Method (string, int, int)" in h for h in headings)
    assert any("Filter Method" in h for h in headings)


def test_load_guide_tags_each_chunk_with_its_starting_page(tmp_path):
    chunks = load_guide(_write_sample(tmp_path))
    find_by_name = next(c for c in chunks if "FindByName Method (string, int, int)" in c.heading)
    filter_method = next(c for c in chunks if "Filter Method" in c.heading)
    assert find_by_name.page == 82
    assert filter_method.page == 51
    assert 'All.FindByName("*Me*"' in find_by_name.text


def test_search_ranks_the_named_method_first(tmp_path):
    chunks = load_guide(_write_sample(tmp_path))
    results = search(chunks, "how do I use FindByName to match objects by name", top_k=2)
    assert results, "expected at least one match"
    top_chunk, _score = results[0]
    assert "FindByName" in top_chunk.heading


def test_search_returns_nothing_for_unrelated_query(tmp_path):
    chunks = load_guide(_write_sample(tmp_path))
    assert search(chunks, "xyz nonsense zzzqqq", top_k=2) == []
