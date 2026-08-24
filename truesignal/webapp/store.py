"""Per-project storage for the web UI: upload handling, the built-in
webshop demo seed, and UiCheckmarxClient -- the BaseCheckmarxClient
implementation that backs everything the UI does with the naive scanner
instead of a real Checkmarx scan.
"""
from __future__ import annotations

import io
import re
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..checkmarx_client import BaseCheckmarxClient
from ..code_indexer import index_repo
from ..config import PROJECT_ROOT, Config
from ..feedback import FeedbackStore
from ..jsonstore import read_json as _read_json
from ..jsonstore import write_json as _write_json
from ..llm_classifier import build_user_prompt
from ..override_generator import Ledger
from ..summarizer import RunHistory
from ..training_store import TrainingStore
from .scanner import _bare, scan_methods

UI_ROOT = PROJECT_ROOT / ".truesignal_ui"
PROJECTS_ROOT = UI_ROOT / "projects"

WEBSHOP_ID = "webshop"

# (project_id, display name, repo path relative to the project root)
BUILTIN_DEMOS = [
    (WEBSHOP_ID, "WebShop (built-in demo — SQL Injection)", "demos/demo-repo"),
    ("cmdi-demo", "ReportServlet (built-in demo — Command Injection)", "demos/demo-repo-cmdi"),
    ("toolbox-demo", "SecureApp (built-in demo — Path Traversal, XSS, SSRF, LDAP Injection)",
     "demos/demo-repo-toolbox"),
]

# Distinctive code signatures that mark a passthrough node as a genuine
# sanitizer worth pre-seeding realistic dismissal history for -- one per
# demo sanitizer, matching the heuristics MockClassifier looks for.
_SANITIZER_HINTS = (
    'isLetterOrDigit', 'replaceAll("[^',                  # SQL / Command Injection
    '".."', '&lt;', 'ALLOWED_HOSTS', r'\\2a', r'\\28',     # path traversal / xss / ssrf / ldap
)

# Seeded demo reviewers -- real-looking names/emails rather than alice/bob/carol.
SEED_REVIEWERS = ("prince@checkmarx.com", "abhishek@checkmarx.com",
                   "vishak@checkmarx.com", "apurva@checkmarx.com")

# Absolute repo_path for the built-in demos, re-derived from the current
# PROJECT_ROOT rather than trusted from meta.json -- meta.json is only
# written once, at first seed, so if the whole project directory is ever
# moved or renamed afterwards, a persisted absolute path would go stale.
_BUILTIN_REPO_PATHS = {pid: str(PROJECT_ROOT / repo_rel) for pid, _name, repo_rel in BUILTIN_DEMOS}


def _slugify(name: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip()).strip("-").lower() or "project"
    return f"{base}-{uuid.uuid4().hex[:6]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectStore:
    def __init__(self):
        PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
        for project_id, name, repo_rel in BUILTIN_DEMOS:
            if not self.exists(project_id):
                self._finish_project(project_id, name, PROJECT_ROOT / repo_rel, seed_triage=True)

    # -- project directory / metadata ---------------------------------
    def project_dir(self, project_id: str) -> Path:
        return PROJECTS_ROOT / project_id

    def exists(self, project_id: str) -> bool:
        return (self.project_dir(project_id) / "meta.json").exists()

    def meta(self, project_id: str) -> dict:
        data = _read_json(self.project_dir(project_id) / "meta.json", {})
        if project_id in _BUILTIN_REPO_PATHS:
            data["repo_path"] = _BUILTIN_REPO_PATHS[project_id]
        return data

    def list_projects(self) -> list[dict]:
        projects = []
        for d in sorted(PROJECTS_ROOT.iterdir()) if PROJECTS_ROOT.exists() else []:
            if not (d / "meta.json").exists():
                continue
            meta = self.meta(d.name)
            scan = self.get_scan(d.name)
            triage = self.get_triage(d.name)
            projects.append({
                **meta,
                "finding_count": len(scan.get("results", [])),
                "dismiss_count": sum(1 for x in triage.get("decisions", []) if x["action"] == "DISMISS"),
            })
        return projects

    # -- creation --------------------------------------------------------
    def create_from_zip(self, name: str, zip_bytes: bytes) -> str:
        project_id = _slugify(name)
        pdir = self.project_dir(project_id)
        source_dir = pdir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        self._extract_zip_safe(zip_bytes, source_dir)
        self._finish_project(project_id, name, source_dir, seed_triage=False)
        return project_id

    def _finish_project(self, project_id: str, name: str, repo_path: Path, seed_triage: bool) -> None:
        pdir = self.project_dir(project_id)
        pdir.mkdir(parents=True, exist_ok=True)
        methods = index_repo(repo_path)
        findings_by_qname = scan_methods(methods, {})
        ids = self._assign_ids(project_id, set(findings_by_qname))

        results = []
        for qname, body in findings_by_qname.items():
            results.append({"id": ids[qname], **body})
        scan = {"projectId": project_id, "scanId": "scan-baseline", "results": results}
        _write_json(pdir / "scan_baseline.json", scan)

        decisions = self._synthetic_triage(results, methods, ids) if seed_triage else []
        _write_json(pdir / "triage.json", {"projectId": project_id, "decisions": decisions})
        _write_json(pdir / "applied_overrides.json", [])
        _write_json(pdir / "meta.json", {
            "id": project_id, "name": name, "created": _now(),
            "repo_path": str(repo_path), "seeded": seed_triage,
        })

    # Uncompressed-size cap independent of Flask's MAX_CONTENT_LENGTH, which only
    # bounds the *compressed* upload -- a small archive can still decompress to
    # many times that on disk.
    _MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024

    @classmethod
    def _extract_zip_safe(cls, data: bytes, dest: Path) -> None:
        dest = dest.resolve()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            total_uncompressed = 0
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if target != dest and dest not in target.parents:
                    raise ValueError(f"unsafe path in zip: {member.filename}")
                total_uncompressed += member.file_size
                if total_uncompressed > cls._MAX_UNCOMPRESSED_BYTES:
                    max_mb = cls._MAX_UNCOMPRESSED_BYTES // (1024 * 1024)
                    raise ValueError(f"archive expands to more than {max_mb} MB uncompressed")
            zf.extractall(dest)

    # -- synthetic triage for the built-in demo only ---------------------
    def _synthetic_triage(self, results: list[dict], methods, ids: dict[str, str]) -> list[dict]:
        """Seed realistic-looking triage history for findings whose taint path
        already runs through what looks like an allow-list filter, so the
        webshop demo has audit evidence to learn from the moment it's opened.
        Never used for a project a user actually uploads.
        """
        decisions = []
        for f in results:
            passthrough_nodes = [
                s["node"].split("(")[0] for s in f["taintPath"] if s["role"] == "passthrough"
            ]
            sanitizer_qname = None
            for n in passthrough_nodes:
                m = methods.get(n) or methods.get(_bare(n))
                if m and any(h in m.source for h in _SANITIZER_HINTS):
                    sanitizer_qname = n
                    break
            if not sanitizer_qname:
                continue
            # One dismissal per reviewer, a few days apart -- several independent
            # people is exactly the default min_triage_support; repeating the same
            # names on the same finding wouldn't be independent evidence of anything.
            for i, user in enumerate(SEED_REVIEWERS):
                seeded_at = datetime.now(timezone.utc) - timedelta(days=(len(SEED_REVIEWERS) - i) * 2)
                decisions.append({
                    "findingId": f["id"], "scanId": "scan-seed", "action": "DISMISS",
                    "resolution": "NOT_EXPLOITABLE",
                    "comment": f"goes through {sanitizer_qname}, safe",
                    "user": user,
                    "date": seeded_at.isoformat(),
                })
        return decisions

    def _assign_ids(self, project_id: str, qnames: set[str]) -> dict[str, str]:
        path = self.project_dir(project_id) / "finding_ids.json"
        state = _read_json(path, {"next": 1001, "map": {}})
        changed = False
        for q in sorted(qnames):
            if q not in state["map"]:
                state["map"][q] = f"CX-{state['next']}"
                state["next"] += 1
                changed = True
        if changed:
            _write_json(path, state)
        return state["map"]

    # -- data access -------------------------------------------------------
    def get_scan(self, project_id: str) -> dict:
        return _read_json(self.project_dir(project_id) / "scan_baseline.json", {"results": []})

    def get_triage(self, project_id: str) -> dict:
        return _read_json(self.project_dir(project_id) / "triage.json", {"decisions": []})

    def add_audit(self, project_id: str, finding_id: str, action: str, resolution: str,
                   comment: str, user: str) -> None:
        path = self.project_dir(project_id) / "triage.json"
        triage = _read_json(path, {"projectId": project_id, "decisions": []})
        triage["decisions"].append({
            "findingId": finding_id, "scanId": "scan-ui-audit", "action": action,
            "resolution": resolution, "comment": comment or "", "user": user or "anonymous",
            "date": _now(),
        })
        _write_json(path, triage)

    def latest_audit(self, project_id: str, finding_id: str) -> dict | None:
        decisions = [d for d in self.get_triage(project_id)["decisions"] if d["findingId"] == finding_id]
        return decisions[-1] if decisions else None

    def config_for(self, project_id: str) -> Config:
        meta = self.meta(project_id)
        pdir = self.project_dir(project_id)
        kwargs: dict[str, Any] = {"repo_path": Path(meta["repo_path"]), "state_dir": pdir / ".truesignal"}
        settings = self.get_settings(project_id)
        if "min_confidence_auto" in settings:
            kwargs["min_confidence_auto"] = settings["min_confidence_auto"]
        if "min_triage_support" in settings:
            kwargs["min_triage_support"] = settings["min_triage_support"]
        return Config(**kwargs)

    # -- per-project gate settings ----------------------------------------
    def get_settings(self, project_id: str) -> dict:
        return _read_json(self.project_dir(project_id) / "settings.json", {})

    def save_settings(self, project_id: str, min_confidence_auto: float | None,
                       min_triage_support: int | None) -> None:
        settings: dict[str, Any] = {}
        if min_confidence_auto is not None:
            settings["min_confidence_auto"] = min_confidence_auto
        if min_triage_support is not None:
            settings["min_triage_support"] = min_triage_support
        _write_json(self.project_dir(project_id) / "settings.json", settings)

    def feedback_calibration(self, project_id: str) -> list[dict]:
        """Per-signature confidence-calibration trend + current counts, for
        the settings page's chart. One entry per (role, attack_class)
        signature with any audit history; empty list if none yet."""
        fb = FeedbackStore(self.config_for(project_id).state_dir)
        summary = fb.summary()
        return [{"signature": key, "points": points, **summary.get(key, {})}
                for key, points in sorted(fb.all_trends().items())]

    # -- cross-project aggregation: activity feed, search, trend ---------
    def recent_activity(self, limit: int | None = 60) -> list[dict]:
        events: list[dict] = []
        for p in self.list_projects():
            pid, pname = p["id"], p["name"]
            for d in self.get_triage(pid)["decisions"]:
                events.append({
                    "type": "audit", "timestamp": d["date"], "project_id": pid, "project_name": pname,
                    "user": d.get("user") or "anonymous", "action": d["action"],
                    "resolution": d["resolution"], "finding_id": d["findingId"],
                    "comment": d.get("comment", ""),
                })
            cfg = self.config_for(pid)
            for e in Ledger(cfg.state_dir)._read():
                ov = e["override"]
                events.append({
                    "type": "ledger", "timestamp": e["timestamp"], "project_id": pid, "project_name": pname,
                    "event": e["event"], "function": ov["function"], "kind": ov["kind"],
                    "confidence": ov["confidence"],
                })
            for e in RunHistory(cfg.state_dir)._read():
                events.append({
                    "type": "summary", "timestamp": e["timestamp"], "project_id": pid, "project_name": pname,
                    "summary": e["summary"],
                })
        events.sort(key=lambda e: e["timestamp"], reverse=True)
        return events[:limit] if limit is not None else events

    def search_index(self) -> list[dict]:
        items: list[dict] = []
        for p in self.list_projects():
            pid, pname = p["id"], p["name"]
            items.append({"type": "project", "label": pname, "sub": "Project", "url": f"/projects/{pid}"})
            for f in self.get_scan(pid)["results"]:
                items.append({
                    "type": "finding", "label": f["id"], "sub": f"{f['queryName']} · {pname}",
                    "url": f"/projects/{pid}/findings/{f['id']}/audit",
                })
            cfg = self.config_for(pid)
            seen: set[str] = set()
            for e in Ledger(cfg.state_dir)._read():
                fn = e["override"]["function"]
                if fn in seen:
                    continue
                seen.add(fn)
                items.append({
                    "type": "override", "label": fn, "sub": f"{e['override']['kind']} · {pname}",
                    "url": f"/projects/{pid}/ledger",
                })
        return items

    def ledger_trend(self, days: int = 14) -> list[dict]:
        counts: dict[str, int] = defaultdict(int)
        for p in self.list_projects():
            cfg = self.config_for(p["id"])
            for e in Ledger(cfg.state_dir)._read():
                if e["event"] != "applied":
                    continue
                counts[e["timestamp"][:10]] += 1
        today = datetime.now(timezone.utc).date()
        return [{"date": (today - timedelta(days=i)).isoformat(),
                  "value": counts.get((today - timedelta(days=i)).isoformat(), 0)}
                for i in range(days - 1, -1, -1)]

    def client_for(self, project_id: str) -> UiCheckmarxClient:
        return UiCheckmarxClient(self, project_id)

    def delete_project(self, project_id: str) -> None:
        import shutil
        if project_id in {p[0] for p in BUILTIN_DEMOS}:
            raise ValueError("built-in demo projects can't be deleted")
        try:
            shutil.rmtree(self.project_dir(project_id))
        except OSError as e:
            raise ValueError(f"could not fully delete project files: {e}") from e

    def rollback_override(self, project_id: str, override_name: str, rolled_back_by: str = "unknown") -> None:
        """Undo one applied override: remove it from the applied set (so the
        next rescan no longer downgrades/adds findings through it) and record
        the rollback in the ledger. Nothing else needs to change -- rescan()
        always re-derives everything from the current applied set.
        """
        path = self.project_dir(project_id) / "applied_overrides.json"
        existing = _read_json(path, [])
        match = next((o for o in existing if o["name"] == override_name), None)
        if match is None:
            raise ValueError(f"override '{override_name}' is not currently applied")
        _write_json(path, [o for o in existing if o["name"] != override_name])
        state_dir = self.config_for(project_id).state_dir
        Ledger(state_dir).record("rolled_back", match)
        attack_classes = [match["attackClass"]] if match.get("attackClass") else []
        FeedbackStore(state_dir).record(match["kind"], attack_classes, "rolled_back")

        # A rolled-back override was proven wrong in production -- the
        # strongest possible signal, and a candidate training correction.
        methods = index_repo(Path(self.meta(project_id)["repo_path"]))
        method = methods.get(match["function"])
        prompt = (build_user_prompt({"hypothesis": match["kind"], "method": method,
                                      "findings": [], "dismissals": []})
                  if method is not None
                  else f"(source unavailable for rolled-back function {match['function']})")
        TrainingStore().record_candidate(
            qualified_name=match["function"], prompt=prompt,
            model_output={"role": match["kind"], "confidence": match["confidence"],
                          "attack_classes": attack_classes, "code_reasons": [],
                          "notes": "override rolled back after being applied"},
            corrected_role="none", corrected_attack_classes=[],
            source_event="rollback", verified_by=rolled_back_by, verified_role="admin",
        )

    def check_confirmed_bypasses_sanitizer(self, project_id: str, finding: dict) -> dict | None:
        """If `finding`'s taint path passes through a function currently
        applied as a sanitizer override, confirming this finding exploitable
        proves that override wrong -- the same passthrough-matching logic
        UiCheckmarxClient.rescan() uses to downgrade findings, run in reverse."""
        applied = _read_json(self.project_dir(project_id) / "applied_overrides.json", [])
        for step in finding.get("taintPath", []):
            if step["role"] != "passthrough":
                continue
            node = step["node"].split("(")[0]
            for ov in applied:
                if ov["kind"] != "sanitizer":
                    continue
                if node == ov["function"] or _bare(node) == _bare(ov["function"]):
                    return ov
        return None


class UiCheckmarxClient(BaseCheckmarxClient):
    """Backs the web UI with the naive scanner instead of a real Checkmarx
    scan, so `truesignal.pipeline` (candidate_selector, classify, verify,
    apply, diff_results) runs completely unmodified against it.
    """

    def __init__(self, store: ProjectStore, project_id: str):
        self.store = store
        self.project_id = project_id

    def get_scan_results(self, project_id: str) -> dict[str, Any]:
        return self.store.get_scan(project_id)

    def get_triage_history(self, project_id: str) -> dict[str, Any]:
        return self.store.get_triage(project_id)

    def apply_query_overrides(self, project_id: str, overrides: list[dict]) -> None:
        path = self.store.project_dir(project_id) / "applied_overrides.json"
        existing = _read_json(path, [])
        names = {o["name"] for o in existing}
        for ov in overrides:
            if ov["name"] not in names:
                existing.append(ov)
        _write_json(path, existing)

    def rescan(self, project_id: str) -> dict[str, Any]:
        meta = self.store.meta(project_id)
        applied = _read_json(self.store.project_dir(project_id) / "applied_overrides.json", [])
        learned_sources = {_bare(ov["function"]): ov["function"] for ov in applied if ov["kind"] == "source"}
        sanitizer_names = {ov["function"] for ov in applied if ov["kind"] == "sanitizer"}
        sanitizer_bare = {_bare(n) for n in sanitizer_names}

        methods = index_repo(Path(meta["repo_path"]))
        findings_by_qname = scan_methods(methods, learned_sources)
        ids = self.store._assign_ids(project_id, set(findings_by_qname))
        baseline_ids = {f["id"] for f in self.store.get_scan(project_id)["results"]}

        results = []
        for qname, body in findings_by_qname.items():
            f = {"id": ids[qname], **body}
            for step in f["taintPath"]:
                if step["role"] != "passthrough":
                    continue
                node = step["node"].split("(")[0]
                if node in sanitizer_names or node in sanitizer_bare or _bare(node) in sanitizer_bare:
                    f["state"] = "NOT_EXPLOITABLE"
                    f["downgradeReason"] = f"passes through verified sanitizer {step['node']}"
                    break
            if f["id"] not in baseline_ids:
                f["new"] = True
            results.append(f)

        return {"projectId": project_id, "scanId": f"scan-rescan-{int(time.time())}", "results": results}
