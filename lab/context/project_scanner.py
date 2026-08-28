"""Optional project context scanner for maintained wiki/context files.

Weiping Lab no longer reads retired Agent Hub mailboxes or repo-local markdown
memory trees by default. Set `WEIPING_LAB_CONTEXT_FILE` or `WEIPING_WIKI_ROOT`
when you want the lab to inject public-safe maintained project context. Legacy
`VIPIN_LAB_CONTEXT_FILE`, `VIPIN_LAB_RULES_FILE`, and `VIPIN_WIKI_ROOT` names are
still accepted for existing workspaces.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from lab.runtime import is_configured_value


@dataclass
class ActiveProject:
    name: str
    direction: str
    status: str
    phase: str
    priority: int


@dataclass
class ProjectContext:
    projects: list[ActiveProject] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    raw_summary: str = ""

    def as_prompt_block(self) -> str:
        if not self.projects and not self.rules:
            return ""
        lines = ["=== Active Research Projects ==="]
        for project in self.projects:
            lines.append(
                f"[P{project.priority}] {project.name}: {project.direction} | "
                f"Status: {project.status}"
            )
        if self.rules:
            lines.append("\n=== Key Rules ===")
            lines.extend(f"- {rule}" for rule in self.rules[:5])
        return "\n".join(lines)

    def find_project(self, query: str) -> ActiveProject | None:
        q = query.lower()
        for project in self.projects:
            if project.name.lower() in q or any(word in q for word in project.name.lower().split()):
                return project
        return None


def load_project_context() -> ProjectContext:
    ctx = ProjectContext()
    for path in _candidate_context_files():
        _load_projects(ctx, path)
        if ctx.projects:
            break
    _load_rules(ctx)
    return ctx


def read_mailbox(agent: str) -> list[dict]:
    """Compatibility shim: Agent Hub mailboxes are retired and intentionally unused."""
    return []


def mark_messages_read(agent: str) -> None:
    """Compatibility shim: no-op because Agent Hub mailboxes are retired."""
    return None


def _candidate_context_files() -> list[Path]:
    files = []
    explicit = _env_alias("WEIPING_LAB_CONTEXT_FILE", "VIPIN_LAB_CONTEXT_FILE")
    if explicit:
        files.append(Path(explicit))
    wiki_root = _env_alias("WEIPING_WIKI_ROOT", "VIPIN_WIKI_ROOT")
    if wiki_root:
        root = Path(wiki_root)
        files.extend(
            [
                root / "wiki" / "concepts" / "research-project-workbench.md",
            ]
        )
    return files


def _load_projects(ctx: ProjectContext, path: Path) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    ctx.raw_summary = text[:2000]
    for match in re.finditer(
        r"\|\s*(\d+)\s*\|\s*\*\*([^*]+)\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|",
        text,
    ):
        priority = int(match.group(1))
        name = match.group(2).strip()
        direction = match.group(3).strip()
        status_raw = match.group(4).strip()
        phase_match = re.search(
            r"(Phase \d+|experiment-\w+|research-\w+|paper-\w+|Gate \w+)",
            status_raw,
        )
        ctx.projects.append(
            ActiveProject(
                name=name,
                direction=direction,
                status=status_raw[:80],
                phase=phase_match.group(1) if phase_match else status_raw[:40],
                priority=priority,
            )
        )


def _load_rules(ctx: ProjectContext) -> None:
    explicit = _env_alias("WEIPING_LAB_RULES_FILE", "VIPIN_LAB_RULES_FILE")
    if not explicit:
        return
    path = Path(explicit)
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for match in re.finditer(r"^[-*]\s+(.+)$", text, re.MULTILINE):
        rule = match.group(1).strip()
        if len(rule) > 20:
            ctx.rules.append(rule)
        if len(ctx.rules) >= 8:
            break


def _env_alias(primary: str, legacy: str) -> str:
    value = os.environ.get(primary, "")
    if is_configured_value(value):
        return value.strip()
    legacy_value = os.environ.get(legacy, "")
    return legacy_value.strip() if is_configured_value(legacy_value) else ""
