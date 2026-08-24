"""TrueSignal web UI: Flask routes.

Screens: dashboard -> upload a project -> findings grid (like a SAST
results view) -> per-finding audit/triage -> run analysis (learn + review
+ apply) -> the false-positive/false-negative diff. Every mutating step
(audit, apply) is a POST; nothing is ever applied without landing on the
review screen first.

Run with `python -m truesignal.webapp.server` (see run_ui.bat).
"""
from __future__ import annotations

import logging
import os
import secrets
import webbrowser
from datetime import datetime
from functools import wraps
from pathlib import Path
from threading import Timer

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from ..code_indexer import index_repo
from ..config import default_thresholds
from ..feedback import FeedbackStore
from ..llm_classifier import build_user_prompt
from ..override_generator import Ledger
from ..pattern_library import LearnedPattern, find_matches
from ..pipeline import diff_results, run_apply, run_learn
from ..summarizer import summarize_run
from ..training_store import APPROVED, DISCARDED, PENDING, TrainingStore
from ..triage_advisor import suggest_verdict
from .store import ProjectStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("TRUESIGNAL_SECRET_KEY") or secrets.token_hex(16)
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    session_secure = os.environ.get("TRUESIGNAL_SESSION_SECURE", "false").lower() in ("1", "true", "yes")
    app.config["SESSION_COOKIE_SECURE"] = session_secure
    # Uploaded project archives are Java source trees, not multi-GB monorepos --
    # cap the request body so an oversized (or malicious) upload can't exhaust
    # server memory before create_from_zip even gets a chance to validate it.
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("TRUESIGNAL_MAX_UPLOAD_MB", "50")) * 1024 * 1024

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        logger.warning(f"404 error: {request.path}")
        return render_template("error.html", code=404, message="Page not found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"500 error: {str(error)}", exc_info=True)
        return render_template("error.html", code=500, message="Internal server error"), 500

    @app.errorhandler(403)
    def forbidden(error):
        logger.warning(f"403 error: {request.path}")
        return render_template("error.html", code=403, message="Access forbidden"), 403

    @app.errorhandler(413)
    def too_large(error):
        logger.warning(f"413 error: {request.path}")
        max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_template("error.html", code=413,
                                message=f"That file is too large (limit {max_mb} MB)"), 413

    return app

app = create_app()
store = ProjectStore()

# --- auth: two demo accounts gate the app; override via env for anything real ---
DEMO_ACCOUNTS = [
    {
        "username": os.environ.get("TRUESIGNAL_ADMIN_USER", "admin"),
        "password": os.environ.get("TRUESIGNAL_ADMIN_PASSWORD", "checkmarx"),
        "label": "Admin",
        "desc": "Full access — upload projects, apply overrides, roll back the ledger.",
    },
    {
        "username": os.environ.get("TRUESIGNAL_APPSEC_USER", "appsec"),
        "password": os.environ.get("TRUESIGNAL_APPSEC_PASSWORD", "checkmarx"),
        "label": "AppSec",
        "desc": "Triage and audit findings — read-only on settings and rollback.",
    },
]
ACCOUNTS = {a["username"]: generate_password_hash(a["password"]) for a in DEMO_ACCOUNTS}
ACCOUNT_LABELS = {a["username"]: a["label"] for a in DEMO_ACCOUNTS}


@app.context_processor
def inject_current_user():
    username = session.get("user")
    return {"current_user": username, "current_user_label": ACCOUNT_LABELS.get(username, username)}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Gates the training-data curation screen -- only the admin account can
    decide what actually reaches the fine-tune dataset. Reviewers (any
    logged-in user) can only generate *pending* candidates; only an admin
    can approve, edit, or discard them."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user") != os.environ.get("TRUESIGNAL_ADMIN_USER", "admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def _safe_next(target: str | None) -> str:
    """Only ever redirect to a same-app relative path -- never an open redirect."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


def _methods_for(project_id: str) -> dict:
    meta = store.meta(project_id)
    return index_repo(Path(meta["repo_path"]))


def _learned_patterns() -> list[LearnedPattern]:
    """Every currently-applied override across every project, turned back into
    reusable pattern data (project, role, attack class, confidence, source) for
    the cross-project pattern library. Advisory only -- see pattern_library.py."""
    patterns = []
    for p in store.list_projects():
        cfg = store.config_for(p["id"])
        applied = Ledger(cfg.state_dir).applied_overrides()
        if not applied:
            continue
        methods = _methods_for(p["id"])
        for function, override in applied.items():
            method = methods.get(function)
            if method is None:
                continue
            patterns.append(LearnedPattern(
                project_id=p["id"], project_name=p["name"], qualified_name=function,
                kind=override["kind"], attack_class=override.get("attackClass", ""),
                confidence=override.get("confidence", 0.0), source=method.source,
            ))
    return patterns


def _cross_project_matches(pid: str, limit: int = 5) -> list[dict]:
    """Indexed methods in `pid` that aren't already learned here but structurally
    resemble something already proven and applied in another project. Returns
    plain dicts (not PatternMatch/JavaMethod) since this is purely for display --
    a reviewer still has to go add it as a training example for anything to change."""
    already_here = Ledger(store.config_for(pid).state_dir).already_learned()
    methods = {qn: m for qn, m in _methods_for(pid).items() if qn not in already_here}
    patterns = [p for p in _learned_patterns() if p.project_id != pid]
    if not methods or not patterns:
        return []
    matches = find_matches(list(methods.values()), patterns, exclude_project=pid)[:limit]
    return [{
        "candidate": m.candidate,
        "candidate_file": methods[m.candidate].file,
        "candidate_line": methods[m.candidate].line,
        "similarity_pct": round(m.similarity * 100),
        "pattern": m.pattern,
    } for m in matches]


def _capture_confirmed_bypass(pid: str, finding: dict, user: str) -> None:
    """A reviewer just confirmed a finding is genuinely exploitable. If its
    taint path passes through a function currently trusted as a sanitizer
    override, that override just manufactured a real false negative --
    capture it as a pending training correction (best-effort/heuristic, like
    the rest of this project's static matching)."""
    override = store.check_confirmed_bypasses_sanitizer(pid, finding)
    if override is None:
        return
    methods = _methods_for(pid)
    method = methods.get(override["function"])
    prompt = (build_user_prompt({"hypothesis": "sanitizer", "method": method,
                                  "findings": [finding["id"]], "dismissals": []})
              if method is not None
              else f"(source unavailable for {override['function']})")
    TrainingStore().record_candidate(
        qualified_name=override["function"], prompt=prompt,
        model_output={"role": "sanitizer", "confidence": override["confidence"],
                      "attack_classes": [override.get("attackClass")] if override.get("attackClass") else [],
                      "code_reasons": [], "notes": "confirmed exploitable despite this sanitizer override"},
        corrected_role="none", corrected_attack_classes=[],
        source_event="confirmed_despite_sanitizer", verified_by=user,
        verified_role=ACCOUNT_LABELS.get(user, user),
    )


TRAINING_ROLE_CHOICES = ["sanitizer", "source", "sink", "none"]
TRAINING_ATTACK_CLASSES = [
    "sql_injection", "command_injection", "path_traversal", "xss", "ssrf", "ldap_injection",
]

DECISION_MAP = {
    "not_exploitable": ("DISMISS", "NOT_EXPLOITABLE"),
    "confirmed": ("CONFIRM", "CONFIRMED"),
    "proposed_not_exploitable": ("DISMISS", "PROPOSED_NOT_EXPLOITABLE"),
    "to_verify": ("TO_VERIFY", "TO_VERIFY"),
}

STATE_CHART_LABELS = {
    "TO_VERIFY": ("To verify", "warning"), "NOT_EXPLOITABLE": ("Not exploitable", "success"),
}
RESOLUTION_CHART_LABELS = {
    "NOT_EXPLOITABLE": ("Not exploitable", "success"),
    "PROPOSED_NOT_EXPLOITABLE": ("Proposed N/E", "low"),
    "CONFIRMED": ("Confirmed", "danger"),
    "TO_VERIFY": ("To verify", "warning"),
}
KIND_CHART_LABELS = {
    "sanitizer": ("Sanitizer", "info"), "source": ("Source", "danger"), "sink": ("Sink", "warning"),
}


def _chart_segments(counts: dict, labels: dict) -> list[dict]:
    return [{"label": labels.get(k, (k, "faint"))[0], "value": v, "colorKey": labels.get(k, (k, "faint"))[1]}
            for k, v in sorted(counts.items())]


def _resolve_node(node: str, methods: dict) -> dict | None:
    qname = node.split("(")[0]
    m = methods.get(qname)
    if m is None:
        bare = qname.rsplit(".", 1)[-1]
        m = next((v for v in methods.values() if v.method_name == bare), None)
    if m is None:
        return None
    return {"qualified_name": m.qualified_name, "file": m.file, "line": m.line, "source": m.source}


def _project_impact(pid: str) -> dict:
    """Real, re-derived-on-the-fly numbers for the pitch: how many findings
    this project has, how many were audited, and -- only if overrides are
    actually applied -- how many turned out to be false positives (now
    downgraded) versus previously-invisible findings that surfaced.
    """
    cfg = store.config_for(pid)
    client = store.client_for(pid)
    baseline = client.get_scan_results(pid)
    results = baseline.get("results", [])
    ledger = Ledger(cfg.state_dir)
    applied = len(ledger.already_learned())
    downgraded, surfaced, surfaced_critical = [], [], 0
    current_results = results
    if applied:
        rescan = client.rescan(pid)
        diff = diff_results(baseline, rescan)
        downgraded, surfaced = diff["downgraded"], diff["new"]
        surfaced_critical = sum(1 for f in surfaced if f["severity"] in ("CRITICAL", "HIGH"))
        current_results = rescan.get("results", [])
    triage = store.get_triage(pid)
    audited_ids = {d["findingId"] for d in triage["decisions"]} & {f["id"] for f in results}
    return {
        # "total" tracks current_results (post-rescan when an override is applied), not the
        # frozen baseline -- otherwise a project with a surfaced finding shows a smaller
        # "total" than its own state/severity breakdowns, which are built from current_results.
        "total": len(current_results), "audited": len(audited_ids), "overrides_applied": applied,
        "downgraded": len(downgraded), "surfaced": len(surfaced), "surfaced_critical": surfaced_critical,
        "current_results": current_results,
    }


@app.route("/")
def landing():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    next_url = request.values.get("next", "")
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        stored_hash = ACCOUNTS.get(username)
        if stored_hash and check_password_hash(stored_hash, password):
            session["user"] = username
            return redirect(_safe_next(request.form.get("next")))
        error = "Invalid username or password."
    return render_template("login.html", error=error, next=next_url, demo_accounts=DEMO_ACCOUNTS)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    flash("Signed out.", "info")
    return redirect(url_for("landing"))


@app.route("/app")
@login_required
def dashboard():
    projects = store.list_projects()
    raw_impacts = {p["id"]: _project_impact(p["id"]) for p in projects}
    state_counts: dict[str, int] = {}
    for impact in raw_impacts.values():
        for f in impact["current_results"]:
            state_counts[f["state"]] = state_counts.get(f["state"], 0) + 1
    impacts = {pid: {k: v for k, v in impact.items() if k != "current_results"}
               for pid, impact in raw_impacts.items()}
    totals = {
        "projects": len(projects),
        "findings": sum(i["total"] for i in impacts.values()),
        "audited": sum(i["audited"] for i in impacts.values()),
        "overrides": sum(i["overrides_applied"] for i in impacts.values()),
        "downgraded": sum(i["downgraded"] for i in impacts.values()),
        "surfaced": sum(i["surfaced"] for i in impacts.values()),
        "surfaced_critical": sum(i["surfaced_critical"] for i in impacts.values()),
    }
    totals["noise_pct"] = round(100 * totals["downgraded"] / totals["findings"]) if totals["findings"] else 0
    state_chart = _chart_segments(state_counts, STATE_CHART_LABELS)
    project_bars = {
        "groups": [
            {"label": p["name"].split(" (")[0], "total": impacts[p["id"]]["total"],
             "downgraded": impacts[p["id"]]["downgraded"], "surfaced": impacts[p["id"]]["surfaced"]}
            for p in projects
        ],
        "keys": [{"key": "total", "colorKey": "faint"}, {"key": "downgraded", "colorKey": "success"},
                 {"key": "surfaced", "colorKey": "danger"}],
    }
    trend_chart = {"points": store.ledger_trend(days=14)}
    return render_template("dashboard.html", projects=projects, impacts=impacts, totals=totals,
                            state_chart=state_chart, project_bars=project_bars, trend_chart=trend_chart)


@app.route("/projects/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_project():
    if request.method == "GET":
        return render_template("upload.html")
    name = request.form.get("name", "").strip()
    file = request.files.get("archive")
    if not name or not file or not file.filename:
        flash("A project name and a .zip file are both required.", "error")
        return redirect(url_for("new_project"))
    if not file.filename.lower().endswith(".zip"):
        flash("Only .zip archives are accepted.", "error")
        return redirect(url_for("new_project"))
    try:
        pid = store.create_from_zip(name, file.read())
    except ValueError as e:
        flash(f"Could not import that archive: {e}", "error")
        return redirect(url_for("new_project"))
    flash(f"Imported '{name}' and ran the initial scan.", "success")
    return redirect(url_for("project_overview", pid=pid))


@app.route("/projects/<pid>")
@login_required
def project_overview(pid):
    if not store.exists(pid):
        abort(404)
    meta = store.meta(pid)
    impact = _project_impact(pid)
    current_results = impact.pop("current_results")
    stats = {**impact, "critical": sum(1 for f in current_results if f["severity"] == "CRITICAL")}
    stats["noise_pct"] = round(100 * stats["downgraded"] / stats["total"]) if stats["total"] else 0

    state_counts: dict[str, int] = {}
    for f in current_results:
        state_counts[f["state"]] = state_counts.get(f["state"], 0) + 1

    latest_by_finding: dict[str, dict] = {}
    for d in store.get_triage(pid)["decisions"]:
        latest_by_finding[d["findingId"]] = d
    resolution_counts: dict[str, int] = {}
    for d in latest_by_finding.values():
        resolution_counts[d["resolution"]] = resolution_counts.get(d["resolution"], 0) + 1

    cfg = store.config_for(pid)
    ledger = Ledger(cfg.state_dir)
    currently_applied = ledger.already_learned()
    kind_by_function: dict[str, str] = {}
    for e in ledger._read():
        if e["event"] == "applied" and e["override"]["function"] in currently_applied:
            kind_by_function[e["override"]["function"]] = e["override"]["kind"]
    kind_counts: dict[str, int] = {}
    for kind in kind_by_function.values():
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

    return render_template("project.html", meta=meta, stats=stats, pid=pid,
                            state_chart=_chart_segments(state_counts, STATE_CHART_LABELS),
                            resolution_chart=_chart_segments(resolution_counts, RESOLUTION_CHART_LABELS),
                            kind_chart=_chart_segments(kind_counts, KIND_CHART_LABELS),
                            pattern_matches=_cross_project_matches(pid))


@app.route("/projects/<pid>/delete", methods=["POST"])
@login_required
@admin_required
def delete_project(pid):
    try:
        store.delete_project(pid)
        flash("Project deleted.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/projects/<pid>/findings")
@login_required
def findings(pid):
    if not store.exists(pid):
        abort(404)
    # current_results, not the frozen baseline -- otherwise a finding surfaced by a
    # learned override is reported in the project's impact numbers but can never
    # actually be found or audited here (see also audit() below).
    current_results = _project_impact(pid)["current_results"]
    triage = store.get_triage(pid)
    by_finding: dict[str, list[dict]] = {}
    for d in triage["decisions"]:
        by_finding.setdefault(d["findingId"], []).append(d)
    rows = []
    for f in current_results:
        decisions = by_finding.get(f["id"], [])
        rows.append({"f": f, "audit_count": len(decisions), "latest": decisions[-1] if decisions else None})
    rows.sort(key=lambda r: (r["f"]["severity"] != "CRITICAL", r["f"]["id"]))
    return render_template("findings.html", pid=pid, meta=store.meta(pid), rows=rows)


@app.route("/projects/<pid>/findings/bulk-audit", methods=["POST"])
@login_required
def bulk_audit(pid):
    if not store.exists(pid):
        abort(404)
    finding_ids = request.form.getlist("finding_ids")
    decision = request.form.get("decision", "")
    comment = request.form.get("comment", "")
    user = request.form.get("user", "anonymous").strip() or "anonymous"
    session["last_user"] = user
    if not finding_ids:
        flash("Select at least one finding first.", "error")
        return redirect(url_for("findings", pid=pid))
    if decision not in DECISION_MAP:
        abort(400)
    action, resolution = DECISION_MAP[decision]
    current_results = _project_impact(pid)["current_results"] if resolution == "CONFIRMED" else []
    findings_by_id = {f["id"]: f for f in current_results}
    for fid in finding_ids:
        store.add_audit(pid, fid, action, resolution, comment, user)
        if resolution == "CONFIRMED" and fid in findings_by_id:
            _capture_confirmed_bypass(pid, findings_by_id[fid], user)
    flash(f"Recorded '{resolution}' for {len(finding_ids)} finding(s).", "success")
    return redirect(url_for("findings", pid=pid))


@app.route("/projects/<pid>/findings/<fid>/audit", methods=["GET", "POST"])
@login_required
def audit(pid, fid):
    if not store.exists(pid):
        abort(404)
    current_results = _project_impact(pid)["current_results"]
    finding = next((f for f in current_results if f["id"] == fid), None)
    if finding is None:
        abort(404)

    if request.method == "POST":
        decision = request.form.get("decision", "")
        comment = request.form.get("comment", "")
        user = request.form.get("user", "anonymous").strip() or "anonymous"
        session["last_user"] = user
        if decision not in DECISION_MAP:
            abort(400)
        action, resolution = DECISION_MAP[decision]
        store.add_audit(pid, fid, action, resolution, comment, user)
        if resolution == "CONFIRMED":
            _capture_confirmed_bypass(pid, finding, user)
        flash(f"Recorded audit for {fid}.", "success")
        return redirect(url_for("findings", pid=pid))

    methods = _methods_for(pid)
    path = [{**step, "resolved": _resolve_node(step["node"], methods)} for step in finding["taintPath"]]
    triage = store.get_triage(pid)
    history = [d for d in triage["decisions"] if d["findingId"] == fid]
    return render_template("audit.html", pid=pid, finding=finding, path=path, history=history,
                            default_user=session.get("last_user", ""), suggestion=suggest_verdict(path))


@app.route("/projects/<pid>/analyze", methods=["GET", "POST"])
@login_required
@admin_required
def analyze(pid):
    if not store.exists(pid):
        abort(404)
    cfg = store.config_for(pid)
    client = store.client_for(pid)
    out = run_learn(cfg, pid, client=client)
    sem = out["semantics"]
    if request.method == "GET" or "confirm" not in request.form:
        if not sem["learned"] and not sem["needs_review"]:
            flash("Nothing new to learn — TrueSignal already knows this codebase's semantics.", "info")
            return redirect(url_for("project_overview", pid=pid))
        return render_template(
            "learn.html", pid=pid, learned=sem["learned"], needs_review=sem["needs_review"]
        )

    selected = set(request.form.getlist("approve"))
    reviewed = sem["learned"] + sem["needs_review"]
    approved = [v for v in reviewed if v["qualified_name"] in selected]

    feedback = FeedbackStore(cfg.state_dir)
    training_store = TrainingStore()
    reviewer = session.get("user", "anonymous")
    reviewer_role = ACCOUNT_LABELS.get(reviewer, reviewer)
    candidates_by_qname = {c["qualified_name"]: c for c in out["candidates"]}
    for v in reviewed:
        is_approved = v in approved
        feedback.record(v["role"], v["attack_classes"], "approved" if is_approved else "rejected")
        cand = candidates_by_qname.get(v["qualified_name"])
        if cand is not None:
            training_store.record_candidate(
                qualified_name=v["qualified_name"],
                prompt=build_user_prompt(cand),
                model_output={"role": v["role"], "confidence": v["confidence"],
                              "attack_classes": v["attack_classes"],
                              "code_reasons": v["evidence"]["code_reasons"],
                              "notes": v["evidence"]["notes"]},
                corrected_role=v["role"] if is_approved else "none",
                corrected_attack_classes=v["attack_classes"] if is_approved else [],
                source_event="review_approve" if is_approved else "review_reject",
                verified_by=reviewer, verified_role=reviewer_role,
            )

    if not approved:
        flash("Nothing selected — no overrides applied.", "info")
        return redirect(url_for("project_overview", pid=pid))

    overrides = run_apply(cfg, pid, approved, client=client)
    baseline = client.get_scan_results(pid)
    rescan = client.rescan(pid)
    diff = diff_results(baseline, rescan)
    needs_review_unselected = [v for v in sem["needs_review"] if v not in approved]
    summary = summarize_run(cfg, pid, overrides, diff, needs_review=needs_review_unselected)
    return render_template("results.html", pid=pid, approved=approved,
                            downgraded=diff["downgraded"], new=diff["new"], summary=summary)


@app.route("/projects/<pid>/ledger")
@login_required
def ledger_view(pid):
    if not store.exists(pid):
        abort(404)
    cfg = store.config_for(pid)
    entries = Ledger(cfg.state_dir)._read()
    currently_applied = Ledger(cfg.state_dir).already_learned()
    rows = [{**e, "can_rollback": e["event"] == "applied" and e["override"]["function"] in currently_applied}
            for e in reversed(entries)]
    return render_template("ledger.html", pid=pid, meta=store.meta(pid), rows=rows)


@app.route("/projects/<pid>/export/findings.json")
@login_required
def export_findings(pid):
    if not store.exists(pid):
        abort(404)
    return jsonify(store.get_scan(pid))


@app.route("/projects/<pid>/export/ledger.json")
@login_required
def export_ledger(pid):
    if not store.exists(pid):
        abort(404)
    cfg = store.config_for(pid)
    return jsonify(Ledger(cfg.state_dir)._read())


@app.route("/api/projects")
@login_required
def api_projects():
    """Small read-only JSON API over the same data the dashboard shows."""
    return jsonify(store.list_projects())


def _triage_leaderboard(events: list[dict]) -> list[dict]:
    """Who has recorded the most triage decisions, most first. Counted from
    the same (optionally filtered) event set the activity feed shows, so the
    leaderboard, the charts, and the feed always agree on what's in scope."""
    counts: dict[str, int] = {}
    for e in events:
        if e["type"] != "audit":
            continue
        counts[e["user"]] = counts.get(e["user"], 0) + 1
    return sorted(
        ({"user": u, "count": c} for u, c in counts.items()),
        key=lambda row: (-row["count"], row["user"]),
    )


@app.route("/activity")
@login_required
@admin_required
def activity():
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    user_filter = request.args.get("user", "").strip()
    min_count_raw = request.args.get("min_count", "").strip()
    min_count = int(min_count_raw) if min_count_raw.isdigit() else 0
    filters_active = bool(date_from or date_to or user_filter or min_count)

    # Unbounded fetch whenever any filter is active -- filtering the
    # already-capped last-80 events would silently hide older matches.
    all_events = store.recent_activity(limit=None)
    all_users = sorted({e["user"] for e in all_events if e["type"] == "audit"})

    events = all_events if filters_active else all_events[:80]
    if date_from:
        events = [e for e in events if e["timestamp"][:10] >= date_from]
    if date_to:
        events = [e for e in events if e["timestamp"][:10] <= date_to]
    if user_filter:
        # Ledger/summary events aren't attributed to a human reviewer in this
        # data model, so a user filter narrows the whole feed to that
        # reviewer's own audit decisions rather than showing unrelated events.
        events = [e for e in events if e["type"] == "audit" and e["user"] == user_filter]
    if min_count:
        # A reviewer-level threshold has to apply everywhere on the page --
        # KPIs, charts, and the timeline -- not just hide rows in the
        # leaderboard table while every other tile keeps counting everyone.
        qualifying = {row["user"] for row in _triage_leaderboard(events) if row["count"] >= min_count}
        events = [e for e in events if e["type"] != "audit" or e["user"] in qualifying]

    leaderboard = _triage_leaderboard(events)

    audit_events = [e for e in events if e["type"] == "audit"]
    resolution_counts: dict[str, int] = {}
    day_counts: dict[str, int] = {}
    for e in audit_events:
        resolution_counts[e["resolution"]] = resolution_counts.get(e["resolution"], 0) + 1
        day = e["timestamp"][:10]
        day_counts[day] = day_counts.get(day, 0) + 1

    kpis = {
        "total_decisions": len(audit_events),
        "unique_reviewers": len({e["user"] for e in audit_events}),
        "top_reviewer": leaderboard[0]["user"] if leaderboard else "—",
        "top_reviewer_count": leaderboard[0]["count"] if leaderboard else 0,
    }
    # Short label (the bars/axis-label SVG has no room for a full email address
    # without overlapping neighbors); the leaderboard table right below still
    # shows the full reviewer identity.
    reviewer_bars = {"series": [{"label": row["user"].split("@")[0], "value": row["count"],
                                  "colorKey": "accent"} for row in leaderboard]}
    trend_chart = {"points": [{"date": d, "value": c} for d, c in sorted(day_counts.items())]}

    return render_template(
        "activity.html", events=events[:80], leaderboard=leaderboard,
        date_from=date_from, date_to=date_to, user_filter=user_filter,
        min_count=min_count_raw, all_users=all_users, kpis=kpis,
        resolution_chart=_chart_segments(resolution_counts, RESOLUTION_CHART_LABELS),
        reviewer_bars=reviewer_bars, trend_chart=trend_chart,
    )


@app.route("/analytics")
@login_required
def analytics():
    """Advanced analytics and reporting view."""
    return render_template("analytics.html")


@app.route("/help")
def help():
    """Help and documentation page."""
    return render_template("help.html")


@app.route("/api/search-index")
@login_required
def api_search_index():
    """Backs the Ctrl/Cmd+K command palette: projects, findings, and applied
    overrides across every project, fetched once client-side and filtered
    locally rather than round-tripping on every keystroke."""
    return jsonify(store.search_index())


@app.route("/projects/<pid>/settings", methods=["GET", "POST"])
@login_required
def project_settings(pid):
    if not store.exists(pid):
        abort(404)
    meta = store.meta(pid)

    if request.method == "POST":
        # GET stays open so AppSec's documented "read-only on settings" access is
        # real, not just a hidden save button -- only the write path is admin-only.
        if session.get("user") != os.environ.get("TRUESIGNAL_ADMIN_USER", "admin"):
            abort(403)
        if request.form.get("reset") == "1":
            store.save_settings(pid, None, None)
            flash("Settings reset to the environment defaults.", "success")
            return redirect(url_for("project_settings", pid=pid))
        try:
            min_conf = float(request.form.get("min_confidence_auto", ""))
            min_triage = int(request.form.get("min_triage_support", ""))
        except ValueError:
            flash("Confidence must be a number and triage support a whole number.", "error")
            return redirect(url_for("project_settings", pid=pid))
        if not (0.0 <= min_conf <= 1.0) or min_triage < 0:
            flash("Confidence must be between 0 and 1; triage support must be 0 or more.", "error")
            return redirect(url_for("project_settings", pid=pid))
        store.save_settings(pid, min_conf, min_triage)
        flash("Settings saved — they apply the next time you run an analysis.", "success")
        return redirect(url_for("project_settings", pid=pid))

    saved = store.get_settings(pid)
    effective = store.config_for(pid)
    return render_template("settings.html", pid=pid, meta=meta, saved=saved,
                            min_confidence_auto=effective.min_confidence_auto,
                            min_triage_support=effective.min_triage_support,
                            defaults=default_thresholds(),
                            calibration=store.feedback_calibration(pid))


@app.route("/projects/<pid>/ledger/rollback", methods=["POST"])
@login_required
@admin_required
def rollback(pid):
    if not store.exists(pid):
        abort(404)
    name = request.form.get("name", "")
    try:
        store.rollback_override(pid, name, rolled_back_by=session.get("user", "unknown"))
        flash(f"Rolled back '{name}'. Findings it affected are back to their pre-override state.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("ledger_view", pid=pid))


@app.route("/training", methods=["GET", "POST"])
@login_required
@admin_required
def training():
    """Admin-only curation of candidate corrections captured whenever a
    reviewer rejects a proposed classification, rolls back an applied
    override, or confirms a finding that a sanitizer override claimed was
    safe. Nothing here reaches the exported fine-tune dataset until an admin
    explicitly approves it (optionally editing the correction first)."""
    ts = TrainingStore()
    admin = session.get("user", "admin")

    if request.method == "POST":
        action = request.form.get("action", "")
        if action in ("approve", "discard"):
            example_id = request.form.get("example_id", "")
            corrected_role = request.form.get("corrected_role") or None
            attack_class = request.form.get("corrected_attack_class") or None
            try:
                ts.set_status(
                    example_id, APPROVED if action == "approve" else DISCARDED, admin=admin,
                    corrected_role=corrected_role,
                    corrected_attack_classes=[attack_class] if attack_class else None,
                )
                flash(f"Example {'approved' if action == 'approve' else 'discarded'}.", "success")
            except ValueError as e:
                flash(str(e), "error")
        elif action == "add_manual":
            pid = request.form.get("project_id", "")
            qname = request.form.get("qualified_name", "").strip()
            corrected_role = request.form.get("corrected_role", "none")
            attack_class = request.form.get("corrected_attack_class") or None
            if not pid or not qname or not store.exists(pid):
                flash("A project and a qualified function name are both required.", "error")
                return redirect(url_for("training"))
            method = _methods_for(pid).get(qname)
            if method is None:
                flash(f"'{qname}' was not found among {pid}'s indexed methods.", "error")
                return redirect(url_for("training"))
            prompt = build_user_prompt({
                "hypothesis": corrected_role if corrected_role != "none" else "sanitizer",
                "method": method, "findings": [], "dismissals": [],
            })
            ts.add_manual(qualified_name=qname, prompt=prompt, corrected_role=corrected_role,
                           corrected_attack_classes=[attack_class] if attack_class else [], admin=admin)
            flash(f"Added manual training example for '{qname}'.", "success")
        else:
            abort(400)
        return redirect(url_for("training"))

    # Prefill the manual-add form when linked here from a cross-project pattern
    # match ("suggest this as a sanitizer") -- still just prefilled text in a
    # form the admin has to submit, same as every other suggestion in this app.
    prefill = {
        "project_id": request.args.get("project_id", ""),
        "qualified_name": request.args.get("qualified_name", ""),
        "corrected_role": request.args.get("role", "sanitizer"),
        "corrected_attack_class": request.args.get("attack_class", ""),
    }

    return render_template(
        "training.html",
        pending=ts.list(status=PENDING),
        approved=ts.list(status=APPROVED),
        discarded=ts.list(status=DISCARDED),
        projects=store.list_projects(),
        role_choices=TRAINING_ROLE_CHOICES,
        attack_classes=TRAINING_ATTACK_CLASSES,
        prefill=prefill,
    )


# ===== NEW FEATURES =====

@app.route("/api/projects/<pid>/statistics")
@login_required
def api_project_statistics(pid):
    """Get detailed statistics for a project."""
    if not store.exists(pid):
        abort(404)
    
    try:
        meta = store.meta(pid)
        impact = _project_impact(pid)
        current_results = impact.pop("current_results")
        
        # Severity breakdown
        severity_counts = {}
        for f in current_results:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # State breakdown
        state_counts = {}
        for f in current_results:
            state = f.get("state", "TO_VERIFY")
            state_counts[state] = state_counts.get(state, 0) + 1
        
        # Query breakdown
        query_counts = {}
        for f in current_results:
            query = f.get("queryName", "Unknown")
            query_counts[query] = query_counts.get(query, 0) + 1
        
        cfg = store.config_for(pid)
        ledger = Ledger(cfg.state_dir)
        currently_applied = ledger.already_learned()
        
        return jsonify({
            "project_id": pid,
            "project_name": meta.get("name", pid),
            "total_findings": len(current_results),
            "severity_breakdown": severity_counts,
            "state_breakdown": state_counts,
            "query_breakdown": query_counts,
            "impact": impact,
            "overrides_applied": len(currently_applied),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting statistics for {pid}: {str(e)}")
        abort(500)


@app.route("/api/projects/<pid>/findings/export")
@login_required
def api_export_findings_advanced(pid):
    """Export findings with advanced filtering options."""
    if not store.exists(pid):
        abort(404)
    
    try:
        # Get query parameters for filtering
        raw_severity = request.args.get("severity")
        severity_filter = raw_severity.split(",") if raw_severity else None
        raw_state = request.args.get("state")
        state_filter = raw_state.split(",") if raw_state else None

        results = _project_impact(pid)["current_results"]
        
        # Apply filters
        if severity_filter:
            results = [f for f in results if f.get("severity") in severity_filter]
        if state_filter:
            results = [f for f in results if f.get("state") in state_filter]
        
        # Get triage info
        triage = store.get_triage(pid)
        by_finding = {}
        for d in triage["decisions"]:
            by_finding.setdefault(d["findingId"], []).append(d)
        
        # Enrich results with triage info
        for f in results:
            f["audit_history"] = by_finding.get(f["id"], [])
        
        export_format = request.args.get("format", "json").lower()
        
        if export_format == "csv":
            import csv
            from io import StringIO
            
            output = StringIO()
            if results:
                writer = csv.DictWriter(output, fieldnames=[
                    "id", "queryName", "severity", "state", "lines", "audit_count"
                ])
                writer.writeheader()
                for f in results:
                    writer.writerow({
                        "id": f.get("id", ""),
                        "queryName": f.get("queryName", ""),
                        "severity": f.get("severity", ""),
                        "state": f.get("state", ""),
                        "lines": ",".join(str(line) for line in f.get("lines", [])),
                        "audit_count": len(f.get("audit_history", []))
                    })
            return output.getvalue(), 200, {
                "Content-Disposition": f"attachment; filename=findings-{pid}.csv",
                "Content-Type": "text/csv"
            }
        else:  # JSON
            return jsonify({
                "project_id": pid,
                "export_timestamp": datetime.now().isoformat(),
                "count": len(results),
                "findings": results
            })
    except Exception as e:
        logger.error(f"Error exporting findings for {pid}: {str(e)}")
        abort(500)


@app.route("/api/search/findings")
@login_required
def api_search_findings():
    """Advanced search across all projects' findings."""
    query = request.args.get("q", "").lower()
    if not query or len(query) < 2:
        return jsonify({"results": []})
    
    try:
        results = []
        for project in store.list_projects():
            pid = project["id"]
            scan = store.get_scan(pid)
            for finding in scan.get("results", []):
                if (query in finding.get("queryName", "").lower() or
                    query in finding.get("id", "").lower() or
                    query in str(finding.get("severity", "")).lower()):
                    results.append({
                        "project_id": pid,
                        "project_name": project.get("name"),
                        "finding_id": finding.get("id"),
                        "query": finding.get("queryName"),
                        "severity": finding.get("severity"),
                        "state": finding.get("state")
                    })
                    if len(results) >= 50:  # Limit results
                        break
            if len(results) >= 50:
                break
        return jsonify({"results": results})
    except Exception as e:
        logger.error(f"Error searching findings: {str(e)}")
        return jsonify({"results": [], "error": "Search failed"}), 500


# DECISION_MAP is keyed by the form's decision name; the JSON API instead takes the
# target state directly, so invert it once: resolution -> (action, resolution).
STATE_TO_DECISION = {resolution: (action, resolution) for action, resolution in DECISION_MAP.values()}


@app.route("/api/projects/<pid>/bulk-operations", methods=["POST"])
@login_required
def api_bulk_operations(pid):
    """Handle bulk operations on findings. Shares its persistence path with the
    form-based /findings/bulk-audit route so both actually record the audit
    (and, for CONFIRMED, the same sanitizer-bypass training capture) instead
    of just reporting a count back."""
    if not store.exists(pid):
        abort(404)

    try:
        data = request.get_json()
        operation = data.get("operation")
        finding_ids = data.get("finding_ids", [])

        if not finding_ids:
            return jsonify({"success": False, "message": "No findings selected"}), 400

        if operation == "change_state":
            state = data.get("new_state")
            if state not in STATE_TO_DECISION:
                return jsonify({"success": False, "message": "Invalid state"}), 400

            action, resolution = STATE_TO_DECISION[state]
            comment = data.get("comment", "")
            user = session.get("last_user") or session.get("user", "anonymous")
            findings_by_id = {f["id"]: f for f in _project_impact(pid)["current_results"]}
            updated = 0
            for fid in finding_ids:
                if fid not in findings_by_id:
                    continue
                store.add_audit(pid, fid, action, resolution, comment, user)
                if resolution == "CONFIRMED":
                    _capture_confirmed_bypass(pid, findings_by_id[fid], user)
                updated += 1

            return jsonify({
                "success": True,
                "message": f"Updated {updated} finding(s)",
                "count": updated,
            })

        return jsonify({"success": False, "message": "Unknown operation"}), 400
    except Exception as e:
        logger.error(f"Error in bulk operations: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/projects/compare")
@login_required
def api_compare_projects():
    """Compare statistics across multiple projects."""
    try:
        projects = store.list_projects()
        comparison = []
        
        for project in projects:
            pid = project["id"]
            impact = _project_impact(pid)
            current_results = impact.get("current_results", [])
            
            severity_counts = {}
            for f in current_results:
                sev = f.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            comparison.append({
                "project_id": pid,
                "project_name": project.get("name"),
                "total_findings": impact.get("total", 0),
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "overrides_applied": impact.get("overrides_applied", 0),
                "downgraded": impact.get("downgraded", 0),
                "surfaced": impact.get("surfaced", 0)
            })
        
        return jsonify({"projects": comparison})
    except Exception as e:
        logger.error(f"Error comparing projects: {str(e)}")
        return jsonify({"error": str(e)}), 500


def main() -> None:
    port = int(os.environ.get("TRUESIGNAL_PORT", "5000"))
    print("Demo logins:")
    for a in DEMO_ACCOUNTS:
        print(f"  {a['label']}: {a['username']} / {a['password']}")
    Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
