"""Environment-driven configuration.

Mock mode (default) needs no credentials and runs entirely from fixtures.
Live mode activates when TRUESIGNAL_MODE=live and the required keys exist.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    # mock | live
    mode: str = os.getenv("TRUESIGNAL_MODE", "mock")

    # --- Checkmarx One (live mode) ---
    cx_base_url: str = os.getenv("CX_BASE_URL", "https://ast.checkmarx.net")
    cx_tenant: str = os.getenv("CX_TENANT", "")
    cx_api_key: str = os.getenv("CX_API_KEY", "")

    # --- LLM (live mode) ---
    # provider: anthropic | openai | ollama | mock
    llm_provider: str = os.getenv("TRUESIGNAL_LLM", "mock")
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1")

    # --- Paths ---
    repo_path: Path = field(
        default_factory=lambda: Path(os.getenv("TRUESIGNAL_REPO", PROJECT_ROOT / "demos" / "demo-repo"))
    )
    fixtures_path: Path = field(default_factory=lambda: PROJECT_ROOT / "fixtures")
    state_dir: Path = field(
        default_factory=lambda: Path(os.getenv("TRUESIGNAL_STATE", PROJECT_ROOT / ".truesignal"))
    )

    # --- Verification gate thresholds ---
    min_confidence_auto: float = float(os.getenv("TRUESIGNAL_MIN_CONF", "0.85"))
    min_triage_support: int = int(os.getenv("TRUESIGNAL_MIN_TRIAGE", "3"))

    def __post_init__(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)

    @property
    def live(self) -> bool:
        return self.mode == "live"


def load_config() -> Config:
    return Config()


def default_thresholds() -> dict:
    """The env-driven gate defaults, exposed without instantiating a Config
    (which creates its state_dir as a side effect) -- used by the web UI's
    per-project settings screen to show what a project would use absent an
    override."""
    return {
        "min_confidence_auto": float(os.getenv("TRUESIGNAL_MIN_CONF", "0.85")),
        "min_triage_support": int(os.getenv("TRUESIGNAL_MIN_TRIAGE", "3")),
    }
