"""Project-context and handoff contract checks."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_docs_catalog_handoff_artifacts():
    readme = _read("README.md")
    agents = _read("AGENTS.md")
    skill = _read(".codex/skills/weiping-lab/SKILL.md")
    combined = "\n".join([readme, agents, skill])

    for artifact in [
        "workspace/*/session.json",
        "workspace/ideas/<idea_id>/idea.json",
        "plan.json",
        "paper.json",
        "EXPERIMENT_PLAN.md",
        "EXPERIMENT_TRACKER.md",
        "experiments/results/*.json",
        "agentmemory-outbox.jsonl",
    ]:
        assert artifact in combined


def test_optional_context_inputs_are_documented_and_not_required(monkeypatch, tmp_path):
    for name in [
        "WEIPING_LAB_CONTEXT_FILE",
        "WEIPING_LAB_RULES_FILE",
        "WEIPING_WIKI_ROOT",
        "VIPIN_LAB_CONTEXT_FILE",
        "VIPIN_LAB_RULES_FILE",
        "VIPIN_WIKI_ROOT",
    ]:
        monkeypatch.delenv(name, raising=False)

    from lab.context.project_scanner import load_project_context

    empty = load_project_context()
    assert empty.projects == []
    assert empty.rules == []

    context_file = tmp_path / "workbench.md"
    context_file.write_text(
        "| 1 | **Pony** | sequential recommendation | Phase 1 active |\n",
        encoding="utf-8",
    )
    rules_file = tmp_path / "rules.md"
    rules_file.write_text("- Evidence labels control paper claims.\n", encoding="utf-8")

    monkeypatch.setenv("WEIPING_LAB_CONTEXT_FILE", str(context_file))
    monkeypatch.setenv("WEIPING_LAB_RULES_FILE", str(rules_file))

    context = load_project_context()
    assert context.projects[0].name == "Pony"
    assert context.rules == ["Evidence labels control paper claims."]
