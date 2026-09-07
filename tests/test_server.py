"""webapp/server.py -- Flask route smoke tests: auth gating, CSRF
enforcement, and the core project/audit/admin flows.

The module-level `store` and CxQL-assistant config the app was built with
point at this checkout's real .truesignal_ui / .truesignal directories; every
test here swaps `server.store` for a fresh ProjectStore rooted under
tmp_path (via the isolated_store fixture, same trick as test_store.py) so
nothing touches real state, and restores the original store afterwards.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from truesignal import comment_bank, training_store
from truesignal.webapp import server
from truesignal.webapp import store as store_module
from truesignal.webapp.store import ProjectStore


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "PROJECTS_ROOT", tmp_path / "projects")
    monkeypatch.setattr(training_store, "DEFAULT_ROOT", tmp_path / "training")
    monkeypatch.setattr(comment_bank, "DEFAULT_ROOT", tmp_path / "comments")
    fresh_store = ProjectStore()
    monkeypatch.setattr(server, "store", fresh_store)

    server.app.testing = True
    with server.app.test_client() as c:
        yield c


def _csrf_token(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html)
    assert m, "no csrf_token field found on the page"
    return m.group(1)


def _login(client, username="admin", password="checkmarx"):
    html = client.get("/login").get_data(as_text=True)
    token = _csrf_token(html)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


# --- auth gating ------------------------------------------------------
def test_dashboard_requires_login(client):
    r = client.get("/app")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_login_with_bad_credentials_shows_error(client):
    html = client.get("/login").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": token})
    assert r.status_code == 200
    assert "Invalid username or password" in r.get_data(as_text=True)


def test_login_success_redirects_to_dashboard(client):
    r = _login(client)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/app")
    assert client.get("/app").status_code == 200


def test_login_rate_limited_after_repeated_failures(client, monkeypatch):
    monkeypatch.setattr(server, "_LOGIN_ATTEMPT_LIMIT", 3)
    for _ in range(3):
        html = client.get("/login").get_data(as_text=True)
        token = _csrf_token(html)
        client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": token})
    html = client.get("/login").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post("/login", data={"username": "admin", "password": "checkmarx", "csrf_token": token})
    assert "Too many attempts" in r.get_data(as_text=True)


def test_logout_clears_session(client):
    _login(client)
    html = client.get("/app").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post("/logout", data={"csrf_token": token})
    assert r.status_code == 302
    assert client.get("/app").status_code == 302


# --- CSRF ---------------------------------------------------------------
def test_post_without_csrf_token_is_rejected(client):
    _login(client)
    r = client.post(f"/projects/{store_module.DEMO_PROJECT_ID}/settings", data={
        "min_confidence_auto": "0.9", "min_triage_support": "2",
    })
    assert r.status_code == 400


def test_post_with_valid_csrf_token_succeeds(client):
    _login(client)
    html = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/settings").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post(f"/projects/{store_module.DEMO_PROJECT_ID}/settings", data={
        "min_confidence_auto": "0.90", "min_triage_support": "2", "csrf_token": token,
    })
    assert r.status_code == 302


# --- admin gating --------------------------------------------------------
def test_non_admin_cannot_reach_admin_only_routes(client):
    _login(client, "appsec", "checkmarx")
    assert client.get("/admin/comments").status_code == 403
    assert client.get("/training").status_code == 403
    assert client.get("/activity").status_code == 403


def test_non_admin_settings_write_is_forbidden(client):
    _login(client, "appsec", "checkmarx")
    html = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/settings").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post(f"/projects/{store_module.DEMO_PROJECT_ID}/settings", data={
        "min_confidence_auto": "0.90", "min_triage_support": "2", "csrf_token": token,
    })
    assert r.status_code == 403


def test_admin_can_write_settings(client):
    _login(client, "admin", "checkmarx")
    html = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/settings").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post(f"/projects/{store_module.DEMO_PROJECT_ID}/settings", data={
        "min_confidence_auto": "0.90", "min_triage_support": "2", "csrf_token": token,
    })
    assert r.status_code == 302


# --- core project flows ---------------------------------------------------
def test_dashboard_lists_builtin_demo_projects(client):
    _login(client)
    html = client.get("/app").get_data(as_text=True)
    assert "storefront-demo" in html.lower() or "StoreFront" in html


def test_project_overview_404s_for_unknown_project(client):
    _login(client)
    assert client.get("/projects/does-not-exist").status_code == 404


def test_findings_page_renders(client):
    _login(client)
    r = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/findings")
    assert r.status_code == 200


def test_audit_get_then_post_records_a_decision(client):
    _login(client)
    findings_html = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/findings").get_data(as_text=True)
    m = re.search(r"findings/(CX-\d+)/audit", findings_html)
    assert m, "expected at least one finding on the seeded demo project"
    fid = m.group(1)
    audit_url = f"/projects/{store_module.DEMO_PROJECT_ID}/findings/{fid}/audit"

    audit_html = client.get(audit_url).get_data(as_text=True)
    token = _csrf_token(audit_html)
    r = client.post(audit_url, data={
        "decision": "to_verify", "comment": "looking into it", "user": "tester", "csrf_token": token,
    })
    assert r.status_code == 302

    history = server.store.get_triage(store_module.DEMO_PROJECT_ID)["decisions"]
    assert any(d["findingId"] == fid and d["user"] == "tester" for d in history)


def test_audit_rejects_unknown_decision(client):
    _login(client)
    findings_html = client.get(f"/projects/{store_module.DEMO_PROJECT_ID}/findings").get_data(as_text=True)
    fid = re.search(r"findings/(CX-\d+)/audit", findings_html).group(1)
    audit_url = f"/projects/{store_module.DEMO_PROJECT_ID}/findings/{fid}/audit"
    audit_html = client.get(audit_url).get_data(as_text=True)
    token = _csrf_token(audit_html)
    r = client.post(audit_url, data={"decision": "not-a-real-decision", "csrf_token": token})
    assert r.status_code == 400


# --- upload validation -----------------------------------------------------
def test_new_project_rejects_non_zip_upload(client):
    _login(client)
    html = client.get("/projects/new").get_data(as_text=True)
    token = _csrf_token(html)
    from io import BytesIO
    r = client.post("/projects/new", data={
        "name": "not-a-zip", "archive": (BytesIO(b"hello"), "notes.txt"), "csrf_token": token,
    }, content_type="multipart/form-data")
    assert r.status_code == 302
    flashed = client.get("/projects/new").get_data(as_text=True)
    assert "Only .zip archives" in flashed


# --- analytics: Attack Surface Radar ---------------------------------------
def test_org_wide_analytics_shape():
    from truesignal import comment_bank as cb_module
    data = server._org_wide_analytics()
    assert set(data) == {"severity_chart", "state_chart", "radar_chart"}
    radar = data["radar_chart"]
    categories = {c["key"] for c in radar["categories"]}
    assert categories == set(cb_module.ATTACK_CLASSES)
    assert {s["label"] for s in radar["series"]} == {"Open exposure", "Learned coverage"}
    for s in radar["series"]:
        assert set(s["values"]) == categories
        assert all(0.0 <= v <= 1.0 for v in s["values"].values())


def test_analytics_page_renders_radar_chart(client):
    _login(client)
    html = client.get("/analytics").get_data(as_text=True)
    assert "chart-risk-radar" in html
    assert "Attack Surface Radar" in html
    assert "Csrf" in html  # attack class label, title-cased server-side


# --- read-only JSON API ----------------------------------------------------
def test_api_projects_requires_login(client):
    assert client.get("/api/projects").status_code == 302


def test_api_projects_lists_seeded_demos(client):
    _login(client)
    data = client.get("/api/projects").get_json()
    assert {"storefront-demo", "accountvault-demo", "docexchange-demo"} <= {p["id"] for p in data}


def test_api_project_statistics(client):
    _login(client)
    data = client.get(f"/api/projects/{store_module.DEMO_PROJECT_ID}/statistics").get_json()
    assert data["project_id"] == store_module.DEMO_PROJECT_ID
    assert data["total_findings"] >= 1
    assert "severity_breakdown" in data


def test_api_export_findings_csv(client):
    _login(client)
    r = client.get(f"/api/projects/{store_module.DEMO_PROJECT_ID}/findings/export?format=csv")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/csv")
    body = r.get_data(as_text=True)
    assert body.splitlines()[0] == "id,queryName,severity,state,sourceFile,sourceLine,audit_count"


def test_api_search_findings_short_query_returns_empty(client):
    _login(client)
    assert client.get("/api/search/findings?q=a").get_json() == {"results": []}


def test_bulk_operations_endpoint_was_removed(client):
    """Dead code cleanup: /api/projects/<pid>/bulk-operations had zero UI
    callers and duplicated /findings/bulk-audit -- it should no longer exist."""
    _login(client)
    html = client.get("/app").get_data(as_text=True)
    token = _csrf_token(html)
    r = client.post(f"/api/projects/{store_module.DEMO_PROJECT_ID}/bulk-operations", json={},
                     headers={"X-CSRFToken": token})
    assert r.status_code == 404
