"""Honest runtime diagnostics for CLI, API, and release tests."""

from __future__ import annotations

from pathlib import Path

from lab.core.config import LabConfig, ModelProfile
from lab.runtime import VERSION, endpoint_host, env_flag, safe_error


def _diagnostic_text(value: object) -> str:
    """Keep useful dynamic labels while applying the public error redaction policy."""
    return safe_error(value, limit=160)


def build_diagnostics(config: LabConfig | None = None) -> dict:
    cfg = config or LabConfig()
    workspace = cfg.workspace_path()
    workspace_available = workspace.exists() or workspace.parent.exists()
    workspace_configured = env_flag("WEIPING_LAB_WORKSPACE_ROOT") or env_flag(
        "VIPIN_LAB_WORKSPACE_ROOT"
    )
    checks = [
        {
            "name": "workspace",
            "level": "ok" if workspace_available else "warn",
            "message": "available" if workspace_available else "unavailable",
        },
        {
            "name": "anthropic_api_key",
            "level": "ok" if env_flag("ANTHROPIC_API_KEY") else "error",
            "message": "configured" if env_flag("ANTHROPIC_API_KEY") else "missing",
        },
        {
            "name": "legacy_agent_hub",
            "level": "ok",
            "message": "disabled",
        },
    ]
    return {
        "ok": not any(item["level"] == "error" for item in checks),
        "version": VERSION,
        "workspace": {
            "configured": workspace_configured,
            "available": workspace_available,
        },
        "agentmemory": {
            "url_configured": bool(cfg.agentmemory_url),
            "endpoint": endpoint_host(cfg.agentmemory_url),
            "legacy_markdown_fallback": False,
            "legacy_agent_hub_mailbox": False,
        },
        "models": [_model_diagnostics(model) for model in cfg.models],
        "quality_gates": {
            "min_novelty_score": cfg.min_novelty_score,
            "min_feasibility_score": cfg.min_feasibility_score,
            "min_baselines": cfg.min_baselines,
            "min_seeds_paper": cfg.min_seeds_paper,
            "min_review_score": cfg.min_review_score,
        },
        "checks": checks,
    }


def _model_diagnostics(model: ModelProfile) -> dict:
    return {
        "role": _diagnostic_text(model.role),
        "name": _diagnostic_text(model.name),
        "provider": _diagnostic_text(model.provider),
        "model": _diagnostic_text(model.id),
        "api_key": "configured" if model.api_key_configured else "missing",
        "api_key_env": _diagnostic_text(model.api_key_env),
        "endpoint_host": endpoint_host(model.base_url),
        "context_k": model.context_k,
    }


def count_sessions(workspace_root: str | Path) -> int:
    root = Path(workspace_root)
    if not root.exists():
        return 0
    return len(list(root.glob("*/session.json")))
