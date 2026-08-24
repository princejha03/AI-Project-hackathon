"""AI-authored plain-English summaries of an `analyze` run.

Everything upstream of this module (learn -> verify -> apply -> re-scan ->
diff) is the deterministic, evidence-gated pipeline the rest of this project
is built around. This module is deliberately outside that trust boundary: it
never decides anything and is never consulted by the verifier -- it only
narrates a run that has *already* happened, for a human skimming a PR
comment or the cross-project Activity feed instead of reading a results
table. If the model hallucinates a detail in the prose, nothing downstream
changes; the CxQL overrides, the ledger, and the ledgered evidence are
already final by the time this runs.

Same four-backend shape as llm_classifier.py:
  * AnthropicSummarizer / OpenAISummarizer / OllamaSummarizer -- real API
    calls (live)
  * MockSummarizer -- deterministic template, offline
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .jsonstore import read_json, write_json

SYSTEM_PROMPT = """You summarize one already-completed TrueSignal analysis run for a \
security engineer skimming an audit trail or pull-request comment. Write 2-4 plain \
English sentences: no markdown, no bullet points, no code fences. Name the specific \
functions and attack classes learned, state how many findings were downgraded and why, \
name any new critical findings that surfaced, and mention if anything still needs manual \
review. Be factual and concise -- you are summarizing verified results, not evaluating \
or second-guessing them."""


def build_run_payload(project: str, overrides: list[dict[str, Any]], diff: dict[str, Any],
                       needs_review: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "project": project,
        "overrides_applied": [
            {"function": o["function"], "role": o["kind"], "confidence": o["confidence"],
             "attack_class": o.get("attackClass")}
            for o in overrides
        ],
        "findings_downgraded": len(diff.get("downgraded", [])),
        "downgrade_reasons": sorted({
            f["downgradeReason"] for f in diff.get("downgraded", []) if f.get("downgradeReason")
        }),
        "new_findings": [
            {"id": f["id"], "severity": f.get("severity"),
             "taint_path": " -> ".join(step["node"] for step in f.get("taintPath", []))}
            for f in diff.get("new", [])
        ],
        "needs_review_count": len(needs_review or []),
    }


def _parse_text(text: str) -> str:
    return text.strip().strip("`").strip()


class AnthropicSummarizer:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def summarize(self, payload: dict[str, Any]) -> str:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 300, "temperature": 0,
                  "system": SYSTEM_PROMPT,
                  "messages": [{"role": "user", "content": json.dumps(payload, indent=2)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_text(resp.json()["content"][0]["text"])


class OpenAISummarizer:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def summarize(self, payload: dict[str, Any]) -> str:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "temperature": 0,
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": json.dumps(payload, indent=2)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_text(resp.json()["choices"][0]["message"]["content"])


class OllamaSummarizer:
    def __init__(self, base_url: str, model: str):
        self.base_url, self.model = base_url.rstrip("/"), model

    def summarize(self, payload: dict[str, Any]) -> str:
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={"model": self.model, "stream": False,
                  "options": {"temperature": 0},
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": json.dumps(payload, indent=2)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_text(resp.json()["message"]["content"])


class MockSummarizer:
    """Deterministic template stand-in so the whole pipeline runs offline --
    mirrors what a well-prompted model would say about the same payload."""

    def summarize(self, payload: dict[str, Any]) -> str:
        sentences = []

        overrides = payload["overrides_applied"]
        if overrides:
            by_role: dict[str, list[str]] = {}
            for o in overrides:
                by_role.setdefault(o["role"], []).append(o["function"])
            parts = [f"{len(fns)} {role}{'s' if len(fns) != 1 else ''} ({', '.join(fns)})"
                     for role, fns in by_role.items()]
            classes = sorted({o["attack_class"] for o in overrides if o.get("attack_class")})
            class_note = f" for {', '.join(classes)}" if classes else ""
            sentences.append(f"This run learned and applied {' and '.join(parts)}{class_note}.")
        else:
            sentences.append("No new semantics were learned or applied this run.")

        if payload["findings_downgraded"]:
            reasons = ("; ".join(payload["downgrade_reasons"]) if payload["downgrade_reasons"]
                       else "the newly-applied overrides")
            sentences.append(f"{payload['findings_downgraded']} finding(s) were downgraded to "
                              f"NOT_EXPLOITABLE: {reasons}.")

        if payload["new_findings"]:
            for f in payload["new_findings"]:
                sentences.append(f"A previously-hidden {f['severity']} finding ({f['id']}) surfaced "
                                  f"via {f['taint_path']}.")

        if payload["needs_review_count"]:
            sentences.append(f"{payload['needs_review_count']} additional item(s) fell below the "
                              f"auto-approval bar and still need manual review.")

        return " ".join(sentences)


def make_summarizer(cfg):
    if cfg.llm_provider == "anthropic" and cfg.anthropic_api_key:
        return AnthropicSummarizer(cfg.anthropic_api_key, cfg.anthropic_model)
    if cfg.llm_provider == "openai" and cfg.openai_api_key:
        return OpenAISummarizer(cfg.openai_api_key, cfg.openai_model)
    if cfg.llm_provider == "ollama":
        return OllamaSummarizer(cfg.ollama_base_url, cfg.ollama_model)
    return MockSummarizer()


class RunHistory:
    """Append-only log of AI-authored run summaries, persisted alongside the
    ledger at state_dir/run_history.json."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "run_history.json"

    def _read(self) -> list[dict]:
        return read_json(self.path, default=[])

    def record(self, project: str, summary: str, stats: dict[str, Any]) -> dict:
        entries = self._read()
        entry = {
            "project": project,
            "summary": summary,
            "stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        entries.append(entry)
        write_json(self.path, entries)
        return entry

    def recent(self, limit: int = 20) -> list[dict]:
        return list(reversed(self._read()))[:limit]


def summarize_run(cfg, project: str, overrides: list[dict[str, Any]], diff: dict[str, Any],
                   needs_review: list[dict[str, Any]] | None = None) -> str:
    """Build the payload, call whichever backend `cfg` selects, and ledger the
    result in RunHistory. Never raises -- this runs strictly after apply/
    re-scan/diff are already final, so a flaky summarizer backend must not
    surface as an error page implying the (already-succeeded, already-
    ledgered) apply itself failed."""
    payload = build_run_payload(project, overrides, diff, needs_review)
    try:
        summary = make_summarizer(cfg).summarize(payload)
    except (requests.exceptions.RequestException, ValueError, KeyError, IndexError) as e:
        summary = (
            "AI summary unavailable (the run itself succeeded — see the ledger and "
            f"diff for what actually changed): {e}"
        )
    RunHistory(cfg.state_dir).record(project, summary, payload)
    return summary
