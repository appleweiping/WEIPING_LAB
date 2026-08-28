"""Lab configuration: model roles, thresholds, workspace, and provider env sources."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from lab.runtime import is_configured_value, project_root

load_dotenv()


LAB_ENV_PREFIX = "WEIPING_LAB"
LEGACY_LAB_ENV_PREFIX = "VIPIN_LAB"


def _env(name: str, default: str = "", legacy_name: str = "") -> str:
    value = os.environ.get(name, "")
    if is_configured_value(value):
        return value.strip()
    if legacy_name:
        legacy_value = os.environ.get(legacy_name, "")
        if is_configured_value(legacy_value):
            return legacy_value.strip()
    return default.strip()


def _lab_env(suffix: str, default: str = "") -> str:
    return _env(
        f"{LAB_ENV_PREFIX}_{suffix}",
        default,
        legacy_name=f"{LEGACY_LAB_ENV_PREFIX}_{suffix}",
    )


@dataclass
class ModelProfile:
    id: str
    name: str
    role: str
    provider: str = "anthropic"  # anthropic | openai | openrouter | deepseek
    base_url: str = ""
    api_key_env: str = "ANTHROPIC_API_KEY"
    context_k: int = 200
    cost_per_1m_in: float = 0.0
    cost_per_1m_out: float = 0.0

    @property
    def api_key(self) -> str:
        value = _env(self.api_key_env)
        return value if is_configured_value(value) else ""

    @property
    def api_key_configured(self) -> bool:
        return bool(self.api_key)


def _anthropic_base() -> str:
    return _env("ANTHROPIC_BASE_URL")


@dataclass
class LabConfig:
    """Runtime config for the research workbench.

    Defaults are public-safe. Private endpoints and keys must be supplied through
    environment variables or `.env`, never by editing tracked source.
    """

    models: list[ModelProfile] = field(
        default_factory=lambda: [
            ModelProfile(
                id=_lab_env("ARCHITECT_MODEL", "claude-opus-4-7"),
                name="Opus",
                role="architect",
                provider="anthropic",
                base_url=_anthropic_base(),
                api_key_env="ANTHROPIC_API_KEY",
                context_k=1000,
                cost_per_1m_in=15.0,
                cost_per_1m_out=75.0,
            ),
            ModelProfile(
                id=_lab_env("EXECUTOR_MODEL", "claude-sonnet-4-6"),
                name="Sonnet",
                role="executor",
                provider="anthropic",
                base_url=_anthropic_base(),
                api_key_env="ANTHROPIC_API_KEY",
                context_k=1000,
                cost_per_1m_in=3.0,
                cost_per_1m_out=15.0,
            ),
            ModelProfile(
                id=_lab_env("AUDITOR_MODEL", "claude-sonnet-4-6"),
                name="Auditor",
                role="auditor",
                provider="anthropic",
                base_url=_anthropic_base(),
                api_key_env="ANTHROPIC_API_KEY",
                context_k=1000,
                cost_per_1m_in=3.0,
                cost_per_1m_out=15.0,
            ),
            ModelProfile(
                id=_lab_env("SCREENER_MODEL", "deepseek-chat"),
                name="DeepSeek",
                role="screener",
                provider="deepseek",
                base_url=_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
                api_key_env="DEEPSEEK_API_KEY",
                context_k=64,
                cost_per_1m_in=0.14,
                cost_per_1m_out=0.28,
            ),
        ]
    )

    min_novelty_score: float = 6.0
    min_feasibility_score: float = 6.0
    min_experiment_audit_score: float = 6.0
    min_review_score: float = 7.0
    min_baselines: int = 8
    min_seeds_paper: int = 20
    min_seeds_diagnostic: int = 3
    min_citations: int = 30

    phenomenon_severity_threshold: float = 0.5
    max_phenomena_per_session: int = 10
    min_analogy_confidence: float = 0.6
    max_analogies_per_idea: int = 5

    max_kill_iterations: int = 3
    max_review_iterations: int = 3
    workspace_root: str = field(
        default_factory=lambda: _lab_env("WORKSPACE_ROOT", str(project_root() / "workspace"))
    )
    agentmemory_url: str = field(
        default_factory=lambda: _env("AGENTMEMORY_URL", "http://localhost:3111")
    )

    @property
    def anthropic_key(self) -> str:
        value = _env("ANTHROPIC_API_KEY")
        return value if is_configured_value(value) else ""

    @property
    def openai_key(self) -> str:
        value = _env("OPENAI_API_KEY")
        return value if is_configured_value(value) else ""

    @property
    def semantic_scholar_key(self) -> str:
        value = _env("SEMANTIC_SCHOLAR_API_KEY")
        return value if is_configured_value(value) else ""

    def workspace_path(self) -> Path:
        return Path(self.workspace_root).expanduser().resolve()

    def get_model(self, role: str) -> ModelProfile:
        for model in self.models:
            if model.role == role:
                return model
        return self.models[0]

    def architect(self) -> ModelProfile:
        return self.get_model("architect")

    def executor(self) -> ModelProfile:
        return self.get_model("executor")

    def auditor(self) -> ModelProfile:
        return self.get_model("auditor")

    def screener(self) -> ModelProfile:
        return self.get_model("screener")
