"""CxQL Assistant: mock-mode (fully offline) answers grounded in the bundled guide."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from truesignal.config import Config
from truesignal.cxql_assistant import answer_question

CFG = Config()  # defaults to mock mode/mock LLM with no env vars set


def test_answer_question_grounds_reply_in_the_guide_and_suggests_a_query():
    result = answer_question(CFG, "How do I use FindByName to search for objects by name?")
    assert "FindByName" in result["reply"]
    assert result["sources"], "expected at least one cited guide section"
    assert all(isinstance(s["page"], int) and s["page"] > 0 for s in result["sources"])
    assert result["cxql_snippets"], "mock mode should surface the guide's own worked example"
    assert any("FindByName" in snippet for snippet in result["cxql_snippets"])


def test_answer_question_with_no_guide_match_says_so_instead_of_inventing_syntax():
    result = answer_question(CFG, "zzzqqq nonsense unrelated gibberish")
    assert result["sources"] == []
    assert "couldn't find" in result["reply"].lower()


def test_answer_question_greets_back_instead_of_a_guide_miss():
    result = answer_question(CFG, "hi")
    assert "couldn't find" not in result["reply"].lower()
    assert "cxql assistant" in result["reply"].lower()
    assert result["sources"] == []


def test_answer_question_answers_a_capability_question_without_hitting_the_guide():
    result = answer_question(CFG, "what can you do?")
    assert "findbyname" in result["reply"].lower() or "cxlist" in result["reply"].lower()
    assert result["sources"] == []


def test_answer_question_uses_real_taint_path_functions_from_context():
    context = {
        "query_name": "SQL_Injection",
        "severity": "HIGH",
        "taint_functions": ["com.example.orders.OrderService.buildQuery",
                             "com.example.orders.SqlSanitizer.sanitizeQuery"],
    }
    result = answer_question(CFG, "Suggest a CxQL query for this finding's taint path.", context=context)
    assert any("sanitizeQuery" in snippet for snippet in result["cxql_snippets"]), (
        "context-aware mock reply should reference the finding's real qualified name, "
        "not a generic placeholder"
    )
