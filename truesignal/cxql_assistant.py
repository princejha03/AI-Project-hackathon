"""Chat backend for the CxQL Assistant floating widget.

Same shape as llm_classifier.py: one shared retrieval-augmented prompt, four
backends (Anthropic/OpenAI/Ollama live, Mock fully offline). Grounded only in
the bundled CxQL API Guide (see cxql_kb.py) plus, optionally, the qualified
function names from whichever finding's taint path the user currently has
open -- it never invents CxQL syntax that isn't in the guide.
"""
from __future__ import annotations

import re
from typing import Any

import requests

from .cxql_kb import Chunk, get_chunks, search

SYSTEM_PROMPT = """You are a Checkmarx CxQL expert assistant embedded in TrueSignal. For \
greetings, thanks, or questions about what you can do, reply briefly and naturally -- don't \
treat those as guide lookups. For any actual CxQL/security question, answer ONLY using the \
CxQL API Guide excerpts provided in the user message -- if the excerpts don't cover it, say \
so rather than inventing CxQL syntax. When a CxQL query would help, propose one in a fenced \
```cxql code block, adapted to any "current finding" context you're given (use its real \
qualified function names instead of placeholders). Cite the guide page number(s) you drew \
on. Be concise."""

_CODE_BLOCK = re.compile(r"```(?:cxql)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_GUIDE_EXAMPLE = re.compile(r"CxQL\n((?:\d+\s.*(?:\n|$))+)")
_MAX_HISTORY_TURNS = 8

# Small talk never matches anything in the guide, so without this every "hi" or
# "thanks" would fall through the retrieval step and come back as a confusing
# "couldn't find anything in the guide" -- handled uniformly here (mock *and*
# live backends) instead of relying on each live model to infer it from
# SYSTEM_PROMPT alone.
_GREETING_RE = re.compile(
    r"^(hi|hello|hey|hiya|yo|howdy|good (morning|afternoon|evening))[!.\s]*$", re.IGNORECASE
)
_THANKS_RE = re.compile(r"^(thanks|thank you|thx|ty|appreciate it|cheers)[!.\s]*$", re.IGNORECASE)
_FAREWELL_RE = re.compile(r"^(bye|goodbye|good bye|see ya|see you|cya|later)[!.\s]*$", re.IGNORECASE)
_CAPABILITY_RE = re.compile(
    r"^(who are you|what are you|what can you do|what do you do|help|"
    r"what is this|how does this work)[?!.\s]*$",
    re.IGNORECASE,
)
_CAPABILITY_REPLY = (
    "I'm the CxQL Assistant, grounded in the Checkmarx CxQL API Guide. I can:\n"
    "- Explain any CxQL / CxList method from the guide\n"
    "- Suggest a ready-to-use CxQL query, with a working example\n"
    "- Tailor a query to the real functions in a finding you're auditing\n\n"
    "Try asking about a method (e.g. \"What does FindByName do?\") or describe what you're trying to query."
)


def _small_talk_reply(question: str) -> str | None:
    q = question.strip()
    if _GREETING_RE.match(q):
        return ("Hi! I'm the CxQL Assistant, grounded in the Checkmarx CxQL API Guide. Ask me about a "
                "CxQL/CxList method, or describe the query you need and I'll suggest one.")
    if _THANKS_RE.match(q):
        return "You're welcome! Let me know if you need another CxQL query or method explained."
    if _FAREWELL_RE.match(q):
        return "Goodbye! Come back any time you need help with CxQL."
    if _CAPABILITY_RE.match(q):
        return _CAPABILITY_REPLY
    return None


def _format_context(context: dict[str, Any] | None) -> str:
    if not context:
        return ""
    lines = ["Current finding context (tailor any suggested query to this):"]
    if context.get("query_name"):
        lines.append(f"- Query: {context['query_name']} (severity: {context.get('severity', 'unknown')})")
    taint_functions = context.get("taint_functions") or []
    if taint_functions:
        lines.append(f"- Taint path functions: {', '.join(taint_functions)}")
    if len(lines) == 1:
        return ""
    return "\n".join(lines) + "\n\n"


def build_user_prompt(question: str, chunks: list[Chunk], context: dict[str, Any] | None) -> str:
    excerpts = "\n\n".join(f"[Guide p.{c.page} -- {c.heading}]\n{c.text}" for c in chunks)
    if not excerpts:
        excerpts = "(no matching guide sections found)"
    return (
        f"{_format_context(context)}"
        f"CxQL API Guide excerpts:\n{excerpts}\n\n"
        f"Question: {question}"
    )


def _extract_snippets(reply: str) -> list[str]:
    return [block.strip() for block in _CODE_BLOCK.findall(reply)]


def _summarize(text: str, limit: int = 500) -> str:
    head = text.split("\nExample")[0].split("\nCxQL\n")[0]
    head = re.sub(r"\s+", " ", head).strip()
    return (head[:limit] + "...") if len(head) > limit else head


def _first_example(text: str) -> str | None:
    m = _GUIDE_EXAMPLE.search(text)
    if not m:
        return None
    lines = [re.sub(r"^\d+\s+", "", ln) for ln in m.group(1).splitlines() if ln.strip()]
    return "\n".join(lines) if lines else None


# --------------------------------------------------------------------------
class AnthropicAssistant:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def reply(self, question: str, chunks: list[Chunk], context: dict | None, history: list[dict]) -> str:
        user_prompt = build_user_prompt(question, chunks, context)
        messages = [*history[-_MAX_HISTORY_TURNS:], {"role": "user", "content": user_prompt}]
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 1024, "temperature": 0,
                  "system": SYSTEM_PROMPT, "messages": messages},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


class OpenAIAssistant:
    def __init__(self, api_key: str, model: str):
        self.api_key, self.model = api_key, model

    def reply(self, question: str, chunks: list[Chunk], context: dict | None, history: list[dict]) -> str:
        user_prompt = build_user_prompt(question, chunks, context)
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    *history[-_MAX_HISTORY_TURNS:],
                    {"role": "user", "content": user_prompt}]
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "temperature": 0, "messages": messages},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


class OllamaAssistant:
    def __init__(self, base_url: str, model: str):
        self.base_url, self.model = base_url.rstrip("/"), model

    def reply(self, question: str, chunks: list[Chunk], context: dict | None, history: list[dict]) -> str:
        user_prompt = build_user_prompt(question, chunks, context)
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    *history[-_MAX_HISTORY_TURNS:],
                    {"role": "user", "content": user_prompt}]
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={"model": self.model, "stream": False, "options": {"temperature": 0},
                  "messages": messages},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


# --------------------------------------------------------------------------
class MockAssistant:
    """Deterministic offline fallback -- formats an answer straight from the
    top-matched guide section instead of calling a model, the same "runs
    offline by default" contract as MockClassifier in llm_classifier.py."""

    def reply(self, question: str, chunks: list[Chunk], context: dict | None, history: list[dict]) -> str:
        if not chunks:
            return ("I couldn't find anything in the CxQL API Guide matching that. Try naming a "
                     "CxList method (e.g. \"FindByName\", \"DataInfluencedBy\") or an attack class.")
        top = chunks[0]
        lines = [f"From the CxQL API Guide, page {top.page} ({top.heading}):", "", _summarize(top.text)]

        taint_functions = (context or {}).get("taint_functions") or []
        example = _first_example(top.text)
        if taint_functions:
            target = taint_functions[-1].rsplit(".", 1)[-1]
            lines += ["", "Suggested query for the current finding's taint path:",
                      "```cxql", f'result = All.FindByName("*{target}*");', "```"]
        elif example:
            lines += ["", "Example from the guide:", "```cxql", example, "```"]

        if len(chunks) > 1:
            others = ", ".join(f"p.{c.page} {c.heading}" for c in chunks[1:])
            lines += ["", f"Related sections: {others}"]
        return "\n".join(lines)


def make_assistant(cfg):
    if cfg.llm_provider == "anthropic" and cfg.anthropic_api_key:
        return AnthropicAssistant(cfg.anthropic_api_key, cfg.anthropic_model)
    if cfg.llm_provider == "openai" and cfg.openai_api_key:
        return OpenAIAssistant(cfg.openai_api_key, cfg.openai_model)
    if cfg.llm_provider == "ollama":
        return OllamaAssistant(cfg.ollama_base_url, cfg.ollama_model)
    return MockAssistant()


def answer_question(cfg, question: str, history: list[dict] | None = None,
                     context: dict[str, Any] | None = None) -> dict:
    small_talk = _small_talk_reply(question)
    if small_talk is not None:
        return {"reply": small_talk, "cxql_snippets": [], "sources": []}
    chunks = [c for c, _score in search(get_chunks(), question, top_k=4)]
    assistant = make_assistant(cfg)
    reply = assistant.reply(question, chunks, context, history or [])
    return {
        "reply": reply,
        "cxql_snippets": _extract_snippets(reply),
        "sources": [{"heading": c.heading, "page": c.page} for c in chunks],
    }
