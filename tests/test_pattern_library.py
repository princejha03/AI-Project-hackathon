"""Cross-project pattern library: deterministic similarity, advisory only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from truesignal.code_indexer import JavaMethod
from truesignal.pattern_library import MIN_SIMILARITY, LearnedPattern, find_matches, score

SQL_SANITIZE_SRC = """public String sanitize(String input) {
    if (input == null) return "";
    return input.replaceAll("['\\";]", "");
}"""

# Same shape, different project/class -- this is the "copy-pasted helper" case
# the pattern library exists to catch.
SQL_SANITIZE_CLONE_SRC = """public String clean(String value) {
    if (value == null) return "";
    return value.replaceAll("['\\";]", "");
}"""

UNRELATED_SRC = """public ResultSet query(String customerRef) throws SQLException {
    String sql = "SELECT * FROM orders WHERE customer_ref = '" + customerRef + "'";
    Statement stmt = connection.createStatement();
    return stmt.executeQuery(sql);
}"""


def _method(name: str, source: str, qname: str | None = None) -> JavaMethod:
    qualified = qname or f"Helper.{name}"
    return JavaMethod(qualified_name=qualified, class_name=qualified.split(".")[0],
                       method_name=name, file="Helper.java", line=1, source=source)


def _pattern(project_id: str, qname: str, source: str, kind: str = "sanitizer") -> LearnedPattern:
    return LearnedPattern(project_id=project_id, project_name=project_id.title(),
                           qualified_name=qname, kind=kind, attack_class="sql_injection",
                           confidence=0.9, source=source)


def test_structurally_similar_functions_score_high():
    combined, name_sim, body_sim = score(
        _method("clean", SQL_SANITIZE_CLONE_SRC),
        _pattern("webshop", "InputCleaner.sanitize", SQL_SANITIZE_SRC),
    )
    assert combined >= MIN_SIMILARITY
    assert body_sim > 0.8  # nearly identical bodies modulo the variable/method names


def test_unrelated_functions_score_low():
    combined, _, _ = score(
        _method("query", UNRELATED_SRC),
        _pattern("webshop", "InputCleaner.sanitize", SQL_SANITIZE_SRC),
    )
    assert combined < MIN_SIMILARITY


def test_find_matches_excludes_same_project():
    candidate = _method("clean", SQL_SANITIZE_CLONE_SRC, qname="ReportServlet.clean")
    same_project_pattern = _pattern("reportservlet", "InputCleaner.sanitize", SQL_SANITIZE_SRC)
    matches = find_matches([candidate], [same_project_pattern], exclude_project="reportservlet")
    assert matches == []


def test_find_matches_ranks_by_similarity_and_respects_limit():
    candidate = _method("clean", SQL_SANITIZE_CLONE_SRC, qname="Toolbox.clean")
    close_pattern = _pattern("webshop", "InputCleaner.sanitize", SQL_SANITIZE_SRC)
    far_pattern = _pattern("cmdi-demo", "FormatValidator.clean", UNRELATED_SRC)
    matches = find_matches([candidate], [far_pattern, close_pattern],
                            exclude_project="toolbox", limit_per_candidate=1)
    assert len(matches) == 1
    assert matches[0].pattern.qualified_name == "InputCleaner.sanitize"
    assert matches[0].candidate == "Toolbox.clean"


def test_find_matches_returns_nothing_below_threshold():
    candidate = _method("query", UNRELATED_SRC, qname="Toolbox.query")
    pattern = _pattern("webshop", "InputCleaner.sanitize", SQL_SANITIZE_SRC)
    assert find_matches([candidate], [pattern], exclude_project="toolbox") == []


def test_finds_real_cross_project_pattern_in_demo_repos():
    """Regression guard for the actual demo scenario: webshop's InputCleaner.sanitize
    (already a proven, applied sanitizer) has a genuinely similar, independently-written
    "keep only allowed chars" helper in both other demo repos. If this stops matching,
    either the indexer or the scoring weights changed underneath the live UI feature."""
    from truesignal.code_indexer import index_repo

    demos_root = Path(__file__).resolve().parent.parent / "demos"
    webshop = index_repo(demos_root / "demo-repo")
    cmdi = index_repo(demos_root / "demo-repo-cmdi")
    toolbox = index_repo(demos_root / "demo-repo-toolbox")

    pattern = _pattern("webshop", "InputCleaner.sanitize", webshop["InputCleaner.sanitize"].source)

    cmdi_matches = find_matches(list(cmdi.values()), [pattern], exclude_project="cmdi-demo")
    assert any(m.candidate == "FormatValidator.clean" for m in cmdi_matches)

    toolbox_matches = find_matches(list(toolbox.values()), [pattern], exclude_project="toolbox-demo")
    assert any(m.candidate == "Validators.sanitizePath" for m in toolbox_matches)
