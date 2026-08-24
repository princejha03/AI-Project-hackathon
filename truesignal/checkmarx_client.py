"""Checkmarx One API client.

Two implementations behind one interface:
  * CheckmarxClient      — real REST calls (live mode)
  * MockCheckmarxClient  — reads bundled fixtures and simulates the effect
                           of query overrides on a re-scan (mock mode)

The mock is faithful to the demo's ground truth: applying a sanitizer
override downgrades the 7 planted FPs; applying the source override
surfaces the planted SQLi through LegacyRequest.getParam().
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Any

import requests

from .jsonstore import read_json, write_json

# Retried: connection-level failures and 429/5xx (transient -- a network blip
# or an overloaded tenant, not a real problem with the request). Anything
# else (401, 404, 400...) fails fast, since retrying won't fix a bad token or
# a bad request and just wastes time before surfacing the real error.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 2


def _request_with_retry(method: str, url: str, **kwargs) -> requests.Response:
    last_exc: BaseException | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            resp = requests.request(method, url, **kwargs)
        except requests.exceptions.ConnectionError as e:
            last_exc = e
        else:
            if resp.status_code not in _RETRYABLE_STATUS:
                return resp
            last_exc = requests.exceptions.HTTPError(
                f"{resp.status_code} {resp.reason} for url: {url}", response=resp)
        if attempt < _MAX_ATTEMPTS - 1:
            time.sleep(_BACKOFF_BASE_SECONDS * (2 ** attempt))
    raise last_exc


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------
class BaseCheckmarxClient:
    def get_scan_results(self, project_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def get_triage_history(self, project_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def apply_query_overrides(self, project_id: str, overrides: list[dict]) -> None:
        raise NotImplementedError

    def rescan(self, project_id: str) -> dict[str, Any]:
        raise NotImplementedError


# --------------------------------------------------------------------------
# Live client (Checkmarx One REST API)
# --------------------------------------------------------------------------
class CheckmarxClient(BaseCheckmarxClient):
    """Thin wrapper over the Checkmarx One REST API.

    Endpoints follow the public API surface (results, predicates, queries).
    Adjust paths to your tenant if your region differs.
    """

    def __init__(self, base_url: str, tenant: str, api_key: str, cache_dir: Path | None = None):
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.api_key = api_key
        self.cache_dir = cache_dir
        self._token: str | None = None
        self._token_exp: float = 0.0

    # -- auth ---------------------------------------------------------------
    def _auth_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        url = f"{self.base_url}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        resp = _request_with_retry("POST", url, data={
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.api_key,
        }, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_exp = time.time() + int(data.get("expires_in", 1800))
        return self._token

    def _get(self, path: str, **params) -> dict:
        resp = _request_with_retry(
            "GET", f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._auth_token()}"},
            params=params, timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: Any) -> dict:
        resp = _request_with_retry(
            "POST", f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._auth_token()}",
                     "Content-Type": "application/json"},
            json=payload, timeout=60,
        )
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    # -- API surface ----------------------------------------------------------
    def _latest_scan_id(self, project_id: str) -> str:
        scans = self._get("/api/scans", **{"project-id": project_id, "limit": 1,
                                           "sort": "-created_at", "statuses": "Completed"})
        items = scans.get("scans") or []
        if not items:
            raise RuntimeError(f"no completed scans for project {project_id}")
        return items[0]["id"]

    def get_scan_results(self, project_id: str) -> dict[str, Any]:
        scan_id = self._latest_scan_id(project_id)
        raw = self._get("/api/sast-results", **{"scan-id": scan_id, "limit": 500,
                                                "include-nodes": "true"})
        results = []
        for r in raw.get("results", []):
            results.append({
                "id": r.get("similarityId") or r.get("id"),
                "queryName": r.get("queryName"),
                "severity": r.get("severity"),
                "state": r.get("state"),
                "sourceFile": (r.get("nodes") or [{}])[0].get("fileName", ""),
                "sourceLine": (r.get("nodes") or [{}])[0].get("line", 0),
                "sinkFile": (r.get("nodes") or [{}])[-1].get("fileName", ""),
                "taintPath": [
                    {"node": n.get("fullName") or n.get("name", ""),
                     "file": n.get("fileName", ""), "line": n.get("line", 0),
                     "role": "source" if i == 0 else
                             ("sink" if i == len(r.get("nodes", [])) - 1 else "passthrough")}
                    for i, n in enumerate(r.get("nodes", []))
                ],
            })
        return {"projectId": project_id, "scanId": scan_id, "results": results}

    def get_triage_history(self, project_id: str) -> dict[str, Any]:
        raw = self._get("/api/sast-results-predicates/predicates",
                        **{"project-ids": project_id, "limit": 1000})
        decisions = []
        for p in raw.get("predicateHistoryPerProject", []):
            for pred in p.get("predicates", []):
                decisions.append({
                    "findingId": pred.get("similarityId"),
                    "scanId": pred.get("scanId", ""),
                    "action": "DISMISS" if pred.get("state") == "NOT_EXPLOITABLE" else "CONFIRM"
                              if pred.get("state") == "CONFIRMED" else pred.get("state", ""),
                    "resolution": pred.get("state", ""),
                    "comment": pred.get("comment", ""),
                    "user": pred.get("createdBy", ""),
                    "sanitizerOnPath": None,   # enriched later by joining with taint paths
                    "date": pred.get("createdAt", ""),
                })
        return {"projectId": project_id, "decisions": decisions}

    def apply_query_overrides(self, project_id: str, overrides: list[dict]) -> None:
        """Upload project-level query overrides (CxQL) via the queries editor API."""
        for ov in overrides:
            self._post("/api/cx-audit/queries", {
                "name": ov["queryName"],
                "language": ov.get("language", "Java"),
                "group": ov.get("group", "Java_Custom"),
                "level": "project",
                "projectId": project_id,
                "source": ov["cxql"],
            })

    def rescan(self, project_id: str) -> dict[str, Any]:
        self._post("/api/scans", {
            "project": {"id": project_id},
            "type": "upload",
            "config": [{"type": "sast", "value": {"incremental": "false"}}],
        })
        # Poll until complete, then return fresh results
        for _ in range(240):
            time.sleep(15)
            try:
                return self.get_scan_results(project_id)
            except RuntimeError:
                continue
        raise TimeoutError("re-scan did not complete in time")


# --------------------------------------------------------------------------
# Mock client (fixtures)
# --------------------------------------------------------------------------
class MockCheckmarxClient(BaseCheckmarxClient):
    """Simulates Checkmarx One from bundled fixtures.

    Re-scan semantics:
      * sanitizer override for InputCleaner.*  -> the 7 findings whose taint
        path passes through it become state=NOT_EXPLOITABLE (downgraded).
      * source override for LegacyRequest.getParam -> a NEW critical SQLi
        finding appears with its full taint path.
    """

    def __init__(self, fixtures_path: Path, state_dir: Path):
        self.fixtures = fixtures_path
        self.state_dir = state_dir
        self._overrides_file = state_dir / "applied_overrides.json"

    def _load(self, name: str) -> dict:
        return json.loads((self.fixtures / name).read_text())

    def get_scan_results(self, project_id: str) -> dict[str, Any]:
        return self._load("baseline_scan.json")

    def get_triage_history(self, project_id: str) -> dict[str, Any]:
        return self._load("triage_history.json")

    def apply_query_overrides(self, project_id: str, overrides: list[dict]) -> None:
        existing = read_json(self._overrides_file, default=[])
        names = {o["name"] for o in existing}
        for ov in overrides:
            if ov["name"] not in names:
                existing.append(ov)
        write_json(self._overrides_file, existing)

    def rescan(self, project_id: str) -> dict[str, Any]:
        baseline = copy.deepcopy(self._load("baseline_scan.json"))
        applied = read_json(self._overrides_file, default=[])

        sanitizers = {o["function"] for o in applied if o["kind"] == "sanitizer"}
        sources = {o["function"] for o in applied if o["kind"] == "source"}

        results = []
        for f in baseline["results"]:
            on_path = {step["node"].split("(")[0] for step in f["taintPath"]}
            if any(s.split("(")[0] in on_path or any(s.startswith(n.rsplit(".", 1)[0]) for n in on_path)
                   for s in sanitizers) and any(
                    step["node"].split("(")[0] in {s.split("(")[0] for s in sanitizers}
                    for step in f["taintPath"]):
                f = dict(f)
                f["state"] = "NOT_EXPLOITABLE"
                f["downgradeReason"] = (
                    "passes through verified sanitizer "
                    + next(step["node"] for step in f["taintPath"]
                           if step["node"].split("(")[0] in {s.split("(")[0] for s in sanitizers})
                )
            results.append(f)

        if any(s.startswith("LegacyRequest.getParam") for s in sources):
            results.append({
                "id": "CX-2001",
                "queryName": "SQL_Injection",
                "severity": "CRITICAL",
                "state": "TO_VERIFY",
                "new": True,
                "sourceFile": "src/main/java/com/webshop/web/OrderServlet.java",
                "sourceLine": 52,
                "sinkFile": "src/main/java/com/webshop/dao/OrderDao.java",
                "taintPath": [
                    {"node": "LegacyRequest.getParam(\"customerRef\")",
                     "file": "src/main/java/com/webshop/legacy/LegacyRequest.java",
                     "line": 24, "role": "source"},
                    {"node": "OrderServlet.legacyLookup()",
                     "file": "src/main/java/com/webshop/web/OrderServlet.java",
                     "line": 52, "role": "passthrough"},
                    {"node": "OrderDao.query()",
                     "file": "src/main/java/com/webshop/dao/OrderDao.java",
                     "line": 26, "role": "sink"},
                ],
            })

        return {"projectId": project_id, "scanId": "scan-rescan-002", "results": results}


def make_client(cfg) -> BaseCheckmarxClient:
    if cfg.live:
        return CheckmarxClient(cfg.cx_base_url, cfg.cx_tenant, cfg.cx_api_key)
    return MockCheckmarxClient(cfg.fixtures_path, cfg.state_dir)
