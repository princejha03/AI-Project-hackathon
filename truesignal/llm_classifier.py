"""Function-role classification.

One prompt, four backends:
  * AnthropicClassifier — Claude via the Messages API (live)
  * OpenAIClassifier    — GPT via chat completions (live)
  * OllamaClassifier    — a locally-hosted model via Ollama's chat API (live,
                          no API key)
  * MockClassifier      — deterministic heuristics that emulate the model's
                          JSON output so the whole pipeline runs offline

All three return the same strict JSON schema per candidate:
{
  "role": "sanitizer" | "source" | "sink" | "none",
  "confidence": 0.0-1.0,
  "attack_classes": ["sql_injection", ...],
  "code_reasons": ["..."],
  "notes": "..."
}
Temperature 0 in live mode — classification must be reproducible.
"""
from __future__ import annotations

import json
import re
from typing import Any

import requests

SYSTEM_PROMPT = """You are a static-analysis security expert. You classify the role a \
Java function plays in taint analysis. Respond ONLY with a JSON object, no markdown, \
no prose, matching exactly:
{"role": "sanitizer"|"source"|"sink"|"none",
 "confidence": <float 0..1>,
 "attack_classes": [<strings, e.g. "sql_injection">],
 "code_reasons": [<short strings citing concrete code behavior>],
 "notes": <string>}

Definitions:
- sanitizer: neutralizes attacker-controlled data for a specific attack class \
(allow-listing, encoding, escaping, strict parsing). Weak/bypassable filtering is NOT \
a sanitizer — role "none" with a note.
- source: returns or exposes external/attacker-controlled input (e.g. wraps \
HttpServletRequest accessors).
- sink: executes/interprets data dangerously (SQL execution, command exec, etc.).
Be conservative: when in doubt, lower the confidence. A wrong "sanitizer" creates \
false negatives, which is the worst outcome."""


def build_user_prompt(candidate: dict[str, Any]) -> str:
    m = candidate["method"]
    dismiss_comments = [d["comment"] for d in candidate["dismissals"]][:10]
    return json.dumps({
        "hypothesis_from_static_signals": candidate["hypothesis"],
        "function": {
            "qualified_name": m.qualified_name,
            "file": m.file,
            "line": m.line,
            "source_code": m.source,
            "calls": m.calls,
        },
        "appears_on_findings": candidate["findings"],
        "past_triage_dismissal_count": len(candidate["dismissals"]),
        "sample_dismissal_comments": dismiss_comments,
    }, indent=2)


def _parse_json(text: str) -> dict:
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    return json.loads(text)


# --------------------------------------------------------------------------
class AnthropicClassifier:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def classify(self, candidate: dict[str, Any]) -> dict:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 1024, "temperature": 0,
                  "system": SYSTEM_PROMPT,
                  "messages": [{"role": "user", "content": build_user_prompt(candidate)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_json(resp.json()["content"][0]["text"])


class OpenAIClassifier:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def classify(self, candidate: dict[str, Any]) -> dict:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "temperature": 0,
                  "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": build_user_prompt(candidate)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_json(resp.json()["choices"][0]["message"]["content"])


class OllamaClassifier:
    def __init__(self, base_url: str, model: str):
        self.base_url, self.model = base_url.rstrip("/"), model

    def classify(self, candidate: dict[str, Any]) -> dict:
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={"model": self.model, "stream": False, "format": "json",
                  "options": {"temperature": 0},
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": build_user_prompt(candidate)}]},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse_json(resp.json()["message"]["content"])


# --------------------------------------------------------------------------
class MockClassifier:
    """Deterministic stand-in for the LLM so the POC runs offline.

    Emulates what a well-prompted model concludes from the same evidence:
    allow-list loops => sanitizer; wrappers over request accessors => source;
    executeQuery on concatenated SQL => sink.
    """

    def classify(self, candidate: dict[str, Any]) -> dict:
        m = candidate["method"]
        src = m.source
        n_dismiss = len(candidate["dismissals"])

        # sanitizer heuristics: allow-list char loop / strip regex, returns String
        allowlist = ("isLetterOrDigit" in src or "replaceAll(\"[^" in src)
        if allowlist and candidate["hypothesis"] == "sanitizer":
            # confidence grows with corroborating triage decisions, capped at 0.94
            conf = round(min(0.86 + 0.002 * n_dismiss, 0.94), 2)
            return {
                "role": "sanitizer",
                "confidence": conf,
                "attack_classes": ["sql_injection"],
                "code_reasons": [
                    "strict allow-list: characters outside a safe set are dropped",
                    "single quotes and SQL metacharacters cannot pass through",
                    "output length capped; result trimmed",
                ],
                "notes": f"{n_dismiss} past dismissals reference this function as the reason.",
            }
        if allowlist and candidate["hypothesis"] != "sanitizer":
            return {"role": "sanitizer", "confidence": 0.86,
                    "attack_classes": ["sql_injection"],
                    "code_reasons": ["numeric allow-list keeps digits only"],
                    "notes": "no triage support; code evidence only."}

        # sanitizer heuristics for the other attack classes: one distinctive
        # code signature per class, same confidence-grows-with-triage formula
        # as the SQL allow-list case above.
        conf = round(min(0.86 + 0.002 * n_dismiss, 0.94), 2)
        if '".."' in src or "replace(\"..\"" in src:
            return {
                "role": "sanitizer", "confidence": conf,
                "attack_classes": ["path_traversal"],
                "code_reasons": [
                    "rejects/strips \"..\" path-traversal sequences",
                    "restricts the result to a safe filename character set",
                ],
                "notes": f"{n_dismiss} past dismissals reference this function as the reason.",
            }
        if "&lt;" in src:
            return {
                "role": "sanitizer", "confidence": conf,
                "attack_classes": ["xss"],
                "code_reasons": [
                    "HTML-encodes <, >, &, and quote characters",
                    "encoded output cannot break out of the surrounding markup",
                ],
                "notes": f"{n_dismiss} past dismissals reference this function as the reason.",
            }
        if "ALLOWED_HOSTS" in src:
            return {
                "role": "sanitizer", "confidence": conf,
                "attack_classes": ["ssrf"],
                "code_reasons": [
                    "checks the target host against a fixed allow-list",
                    "requests to hosts outside the allow-list are rejected",
                ],
                "notes": f"{n_dismiss} past dismissals reference this function as the reason.",
            }
        if r"\\2a" in src or r"\\28" in src:
            return {
                "role": "sanitizer", "confidence": conf,
                "attack_classes": ["ldap_injection"],
                "code_reasons": [
                    "escapes LDAP special characters per RFC 4515",
                    "escaped metacharacters cannot alter the search filter",
                ],
                "notes": f"{n_dismiss} past dismissals reference this function as the reason.",
            }

        # source heuristics: wraps request accessors AND RETURNS their value.
        # A void handler that merely CONSUMES getParameter() is not a source.
        signature = src.split("{", 1)[0]
        returns_string = " void " not in f" {signature} "
        returns_taint = returns_string and "return" in src
        if m.wraps_known_source and returns_taint and any(
                k in src for k in ("getParameter", "getHeader")):
            return {
                "role": "source",
                "confidence": 0.97,
                "attack_classes": ["sql_injection", "xss"],
                "code_reasons": [
                    "directly returns HttpServletRequest accessor values",
                    "no validation or transformation on the returned data",
                ],
                "notes": "wrapper class — engine sees only the wrapper, not the inner accessor.",
            }

        # sink heuristics: string-concatenated SQL into executeQuery
        if m.touches_known_sink and ('+ ' in src or '+"' in src) and "SELECT" in src.upper():
            return {
                "role": "sink",
                "confidence": 0.95,
                "attack_classes": ["sql_injection"],
                "code_reasons": ["builds SQL via string concatenation",
                                 "passes result to Statement.executeQuery"],
                "notes": "already a known sink pattern; confirms engine coverage.",
            }

        return {"role": "none", "confidence": 0.4, "attack_classes": [],
                "code_reasons": [], "notes": "no clear taint role."}


def make_classifier(cfg):
    if cfg.llm_provider == "anthropic" and cfg.anthropic_api_key:
        return AnthropicClassifier(cfg.anthropic_api_key, cfg.anthropic_model)
    if cfg.llm_provider == "openai" and cfg.openai_api_key:
        return OpenAIClassifier(cfg.openai_api_key, cfg.openai_model)
    if cfg.llm_provider == "ollama":
        return OllamaClassifier(cfg.ollama_base_url, cfg.ollama_model)
    return MockClassifier()
