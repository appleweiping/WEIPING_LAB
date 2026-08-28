"""
Workspace Manager — lifecycle management for idea workspaces.

Creates, loads, validates, and archives idea workspaces.
Handles pipeline checkpointing and resumption.
"""

from __future__ import annotations
import hashlib
import json
import math
import re
from pathlib import Path
from ..core.models import (
    Idea,
    IdeaStatus,
    IdeaOrigin,
    KillArgument,
    ExperimentPlan,
    ExperimentBlock,
    ExperimentStatus,
    EvidenceLabel,
    Paper,
    Claim,
)
from ..core.config import LabConfig
from ..memory.store import _redact_jsonish
from ..storage import atomic_write_json


MAX_CHECKPOINT_BYTES = 5 * 1024 * 1024
MAX_READY_RESULT_FILES = 256


class WorkspaceManager:
    def __init__(self, config: LabConfig):
        self.root = Path(config.workspace_root)
        self.ideas_dir = self.root / "ideas"
        self.sessions_dir = self.root / "sessions"

    def setup(self):
        """Create workspace directories."""
        for d in [
            self.root,
            self.ideas_dir,
            self.sessions_dir,
            self.root / "phenomena",
            self.root / "papers",
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def create_idea_workspace(self, idea: Idea) -> Path:
        """Create workspace directory for an idea and return the path."""
        workspace = self.ideas_dir / idea.id
        for subdir in [
            "",
            "experiments/configs",
            "experiments/src/method",
            "experiments/src/utils",
            "experiments/scripts",
            "experiments/results",
            "papers",
        ]:
            (workspace / subdir).mkdir(parents=True, exist_ok=True)
        idea.workspace_dir = str(workspace)
        self.save_idea(idea)
        return workspace

    def save_idea(self, idea: Idea):
        """Persist idea state to workspace."""
        if not idea.workspace_dir:
            return
        path = Path(idea.workspace_dir) / "idea.json"
        atomic_write_json(path, _redact_jsonish(self._idea_to_dict(idea)))

    def load_idea(self, idea_id: str) -> Idea | None:
        """Load idea from workspace by ID."""
        if not _safe_prefix_id(idea_id):
            return None
        # Search by exact ID or prefix match
        candidates = [path for path in self.ideas_dir.glob(f"{idea_id}*") if path.is_dir()]
        exact = self.ideas_dir / idea_id
        if exact in candidates:
            workspace = exact
        elif len(candidates) == 1:
            workspace = candidates[0]
        else:
            return None
        idea_file = workspace / "idea.json"
        if not idea_file.exists():
            return None
        try:
            data = _load_json_object(idea_file)
            if data.get("id") != workspace.name or not _safe_prefix_id(str(data.get("id", ""))):
                return None
            return self._dict_to_idea(data, str(workspace))
        except (OSError, TypeError, ValueError, KeyError, RecursionError):
            return None

    def save_plan(self, idea: Idea, plan: ExperimentPlan):
        """Persist experiment plan to workspace."""
        if not idea.workspace_dir:
            return
        path = Path(idea.workspace_dir) / "plan.json"
        atomic_write_json(path, _redact_jsonish(self._plan_to_dict(plan)))

    def load_plan(self, idea: Idea) -> ExperimentPlan | None:
        """Load experiment plan from workspace."""
        if not idea.workspace_dir:
            return None
        path = Path(idea.workspace_dir) / "plan.json"
        if not path.exists():
            return None
        try:
            data = _load_json_object(path)
            if data.get("idea_id") != idea.id:
                return None
            return self._dict_to_plan(data)
        except (OSError, TypeError, ValueError, KeyError, RecursionError):
            return None

    def save_paper(self, idea: Idea, paper: Paper):
        """Persist paper to workspace."""
        if not idea.workspace_dir:
            return
        path = Path(idea.workspace_dir) / "paper.json"
        atomic_write_json(
            path,
            _redact_jsonish(
                {
                    "idea_id": paper.idea_id,
                    "title": paper.title,
                    "abstract": paper.abstract,
                    "sections": paper.sections,
                    "claims": [
                        {
                            "text": claim.text,
                            "claim_type": claim.claim_type,
                            "evidence_ids": claim.evidence_ids,
                            "evidence_label": claim.evidence_label.value,
                            "verified": claim.verified,
                        }
                        for claim in paper.claims
                    ],
                    "citations": paper.citations,
                    "figures": paper.figures,
                    "latex_path": paper.latex_path,
                    "review_scores": paper.review_scores,
                    "claim_audit_passed": paper.claim_audit_passed,
                    "created_at": paper.created_at,
                }
            ),
        )

    def load_paper(self, idea: Idea) -> Paper | None:
        """Load paper from workspace."""
        if not idea.workspace_dir:
            return None
        path = Path(idea.workspace_dir) / "paper.json"
        if not path.exists():
            return None
        try:
            data = _load_json_object(path)
            if data.get("idea_id") != idea.id:
                return None
            if not isinstance(data.get("title"), str):
                return None
            if not isinstance(data.get("abstract", ""), str):
                return None
            sections = data.get("sections", {})
            if not isinstance(sections, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in sections.items()
            ):
                return None
            p = Paper(idea_id=data["idea_id"], title=data["title"])
            p.abstract = data.get("abstract", "")
            p.sections = sections
            raw_claims = data.get("claims", [])
            if not isinstance(raw_claims, list):
                return None
            p.claims = (
                [self._dict_to_claim(item) for item in raw_claims]
                if isinstance(raw_claims, list)
                else []
            )
            citations = data.get("citations", [])
            figures = data.get("figures", [])
            if not isinstance(citations, list) or any(
                not isinstance(item, str) for item in citations
            ):
                return None
            if not isinstance(figures, list) or any(not isinstance(item, str) for item in figures):
                return None
            p.citations = citations
            p.figures = figures
            p.latex_path = data.get("latex_path", "")
            raw_review_scores = data.get("review_scores", {})
            p.review_scores = (
                {
                    str(key): _finite_score(value)
                    for key, value in raw_review_scores.items()
                    if isinstance(key, str)
                }
                if isinstance(raw_review_scores, dict)
                else {}
            )
            p.claim_audit_passed = data.get("claim_audit_passed") is True
            p.created_at = data.get("created_at", "")
            return p
        except (OSError, TypeError, ValueError, KeyError, RecursionError):
            return None

    def ready_artifact_manifest(self, idea: Idea) -> dict[str, str]:
        """Hash the exact plan, paper, and result bytes backing a READY checkpoint.

        An empty manifest is returned for missing, oversized, linked-outside, or
        otherwise unreadable artifacts so callers fail closed without crashing.
        """

        if not idea.workspace_dir:
            return {}
        workspace = Path(idea.workspace_dir)
        try:
            root = workspace.resolve(strict=True)
            paths = [root / "plan.json", root / "paper.json"]
            results_dir = root / "experiments" / "results"
            result_paths = sorted(results_dir.glob("*.json"), key=lambda path: path.name.lower())
            if not 1 <= len(result_paths) <= MAX_READY_RESULT_FILES:
                return {}
            paths.extend(result_paths)
            if len(paths) <= 2:
                return {}

            manifest: dict[str, str] = {}
            for path in paths:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    return {}
                raw = resolved.read_bytes()
                if len(raw) > MAX_CHECKPOINT_BYTES:
                    return {}
                relative = path.relative_to(root).as_posix()
                manifest[relative] = "sha256:" + hashlib.sha256(raw).hexdigest()
            return manifest
        except (OSError, RuntimeError, ValueError):
            return {}

    def get_pipeline_stage(self, idea: Idea) -> str:
        """Determine what stage the pipeline is at for this idea."""
        if not idea.workspace_dir:
            return "not_started"
        ws = Path(idea.workspace_dir)
        if (ws / "paper.json").exists() and idea.status == IdeaStatus.READY:
            return "complete"
        if (ws / "paper.json").exists():
            return "paper_written"
        if (ws / "experiments" / "results").exists() and any(
            (ws / "experiments" / "results").glob("*.json")
        ):
            return "experiments_done"
        if (ws / "experiments" / "src" / "method" / "model.py").exists():
            return "bridge_done"
        if (ws / "plan.json").exists():
            return "plan_done"
        if (ws / "RESEARCH_QUESTION.md").exists():
            return "refine_done"
        if (ws / "idea.json").exists():
            return "kill_tested"
        return "not_started"

    def list_ideas(self, status_filter: str | None = None) -> list[dict]:
        """List all ideas in workspace."""
        ideas = []
        if not self.ideas_dir.exists():
            return ideas
        for workspace in sorted(self.ideas_dir.iterdir(), reverse=True):
            idea_file = workspace / "idea.json"
            if not idea_file.exists():
                continue
            try:
                data = json.loads(idea_file.read_text(encoding="utf-8"))
                if status_filter and data.get("status") != status_filter:
                    continue
                ideas.append(
                    {
                        "id": data.get("id", workspace.name),
                        "title": data.get("title", "?"),
                        "domain": data.get("domain", "?"),
                        "status": data.get("status", "?"),
                        "origin": data.get("origin", "?"),
                        "novelty_score": data.get("novelty_score", 0),
                        "feasibility_score": data.get("feasibility_score", 0),
                        "workspace": str(workspace),
                        "stage": self._get_stage_from_workspace(workspace),
                    }
                )
            except Exception:
                pass
        return ideas

    def _get_stage_from_workspace(self, workspace: Path) -> str:
        if (workspace / "paper.json").exists():
            return "paper_written"
        # Check for actual JSON result files, not just directory existence
        results_dir = workspace / "experiments" / "results"
        if results_dir.exists() and any(results_dir.glob("*.json")):
            return "experiments_done"
        if (workspace / "experiments" / "src" / "method" / "model.py").exists():
            return "bridge_done"
        if (workspace / "plan.json").exists():
            return "plan_done"
        if (workspace / "RESEARCH_QUESTION.md").exists():
            return "refine_done"
        return "kill_tested"

    # ── Serialization ─────────────────────────────────────────────────────────

    def _idea_to_dict(self, idea: Idea) -> dict:
        return {
            "id": idea.id,
            "title": idea.title,
            "domain": idea.domain,
            "origin": idea.origin.value,
            "phenomenon": idea.phenomenon,
            "hypothesis": idea.hypothesis,
            "proposed_method": idea.proposed_method,
            "expected_contribution": idea.expected_contribution,
            "novelty_score": idea.novelty_score,
            "feasibility_score": idea.feasibility_score,
            "status": idea.status.value,
            "created_at": idea.created_at,
            "workspace_dir": idea.workspace_dir,
            "metadata": idea.metadata,
            "kill_argument": {
                "argument": idea.kill_argument.argument,
                "closest_prior_work": idea.kill_argument.closest_prior_work,
                "rebuttal": idea.kill_argument.rebuttal,
                "survived": idea.kill_argument.survived,
                "reviewer_model": idea.kill_argument.reviewer_model,
            }
            if idea.kill_argument
            else None,
        }

    def _dict_to_idea(self, data: dict, workspace_dir: str) -> Idea:
        for key in (
            "id",
            "title",
            "domain",
            "phenomenon",
            "hypothesis",
            "proposed_method",
            "expected_contribution",
            "created_at",
        ):
            if key in data and not isinstance(data[key], str):
                raise ValueError(f"idea field {key} must be a string")
        kill = None
        if data.get("kill_argument"):
            k = data["kill_argument"]
            if not isinstance(k, dict):
                raise ValueError("kill_argument must be an object")
            for key in ("argument", "rebuttal", "reviewer_model"):
                if not isinstance(k.get(key, ""), str):
                    raise ValueError(f"kill_argument field {key} must be a string")
            closest_prior_work = k.get("closest_prior_work", [])
            if not isinstance(closest_prior_work, list) or any(
                not isinstance(item, str) for item in closest_prior_work
            ):
                raise ValueError("kill_argument closest_prior_work must be an array of strings")
            kill = KillArgument(
                argument=k.get("argument", ""),
                closest_prior_work=closest_prior_work,
                rebuttal=k.get("rebuttal", ""),
                survived=k.get("survived") is True,
                reviewer_model=k.get("reviewer_model", ""),
            )
        try:
            origin = IdeaOrigin(data.get("origin", "phenomenon"))
        except ValueError:
            origin = IdeaOrigin.PHENOMENON
        try:
            status = IdeaStatus(data.get("status", "generated"))
        except ValueError:
            status = IdeaStatus.GENERATED
        return Idea(
            id=data["id"],
            title=data["title"],
            domain=data.get("domain", ""),
            origin=origin,
            phenomenon=data.get("phenomenon", ""),
            hypothesis=data.get("hypothesis", ""),
            proposed_method=data.get("proposed_method", ""),
            expected_contribution=data.get("expected_contribution", ""),
            novelty_score=_finite_score(data.get("novelty_score", 0.0)),
            feasibility_score=_finite_score(data.get("feasibility_score", 0.0)),
            status=status,
            created_at=data.get("created_at", ""),
            workspace_dir=workspace_dir,
            metadata=data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {},
            kill_argument=kill,
        )

    def _plan_to_dict(self, plan: ExperimentPlan) -> dict:
        return {
            "idea_id": plan.idea_id,
            "compute_estimate_hours": plan.compute_estimate_hours,
            "seed_strategy": plan.seed_strategy,
            "fairness_constraints": plan.fairness_constraints,
            "milestone_gates": plan.milestone_gates,
            "approved": plan.approved,
            "audit_scores": plan.audit_scores,
            "blocks": [
                {
                    "id": b.id,
                    "name": b.name,
                    "hypothesis": b.hypothesis,
                    "primary_metrics": b.primary_metrics,
                    "secondary_metrics": b.secondary_metrics,
                    "baselines": b.baselines,
                    "seeds": b.seeds,
                    "expected_outcome": b.expected_outcome,
                    "failure_mode": b.failure_mode,
                    "kill_condition": b.kill_condition,
                    "status": b.status.value,
                    "results": b.results,
                    "evidence_label": b.evidence_label.value,
                }
                for b in plan.blocks
            ],
        }

    def _dict_to_plan(self, data: dict) -> ExperimentPlan:
        blocks = []
        raw_blocks = data.get("blocks", [])
        if not isinstance(raw_blocks, list) or not raw_blocks:
            raise ValueError("plan blocks must be a non-empty array")
        used_ids: set[int] = set()
        for b in raw_blocks:
            if not isinstance(b, dict) or "id" not in b or "name" not in b or "hypothesis" not in b:
                raise ValueError("plan contains a malformed block")
            block_id = b["id"]
            if (
                isinstance(block_id, bool)
                or not isinstance(block_id, int)
                or not 0 <= block_id < 10_000
                or block_id in used_ids
            ):
                raise ValueError("plan block IDs must be unique integers from 0 to 9999")
            used_ids.add(block_id)
            if not isinstance(b["name"], str) or not isinstance(b["hypothesis"], str):
                raise ValueError(f"plan block {block_id} names and hypotheses must be strings")
            for key in ("primary_metrics", "secondary_metrics", "baselines"):
                values = b.get(key, [])
                if not isinstance(values, list) or any(
                    not isinstance(item, str) for item in values
                ):
                    raise ValueError(f"plan block {block_id} field {key} must be an array")
            for key in ("expected_outcome", "failure_mode", "kill_condition"):
                if not isinstance(b.get(key, ""), str):
                    raise ValueError(f"plan block {block_id} field {key} must be a string")
            seeds = b.get("seeds", 20)
            if isinstance(seeds, bool) or not isinstance(seeds, int) or not 0 <= seeds <= 1_000_000:
                raise ValueError(f"plan block {block_id} seeds must be a non-negative integer")
            if not isinstance(b.get("results", {}), dict):
                raise ValueError(f"plan block {block_id} results must be an object")
            try:
                status = ExperimentStatus(b.get("status", "planned"))
            except ValueError:
                status = ExperimentStatus.PLANNED
            block = ExperimentBlock(
                id=block_id,
                name=b["name"],
                hypothesis=b["hypothesis"],
                primary_metrics=b.get("primary_metrics", []),
                secondary_metrics=b.get("secondary_metrics", []),
                baselines=b.get("baselines", []),
                seeds=seeds,
                expected_outcome=b.get("expected_outcome", ""),
                failure_mode=b.get("failure_mode", ""),
                kill_condition=b.get("kill_condition", ""),
                status=status,
                results=dict(b.get("results", {})),
            )
            try:
                block.evidence_label = EvidenceLabel(b.get("evidence_label", "pilot"))
            except ValueError:
                block.evidence_label = EvidenceLabel.PILOT
            blocks.append(block)

        compute_estimate = _finite_nonnegative(data.get("compute_estimate_hours", 100))
        seed_strategy = data.get("seed_strategy", "")
        fairness_constraints = data.get("fairness_constraints", [])
        milestone_gates = data.get("milestone_gates", [])
        if not isinstance(seed_strategy, str):
            raise ValueError("seed_strategy must be a string")
        for name, values in (
            ("fairness_constraints", fairness_constraints),
            ("milestone_gates", milestone_gates),
        ):
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise ValueError(f"{name} must be an array of strings")

        plan = ExperimentPlan(
            idea_id=data["idea_id"],
            blocks=blocks,
            compute_estimate_hours=compute_estimate,
            seed_strategy=seed_strategy,
            fairness_constraints=fairness_constraints,
            milestone_gates=milestone_gates,
        )
        plan.approved = data.get("approved") is True
        raw_scores = data.get("audit_scores", {})
        plan.audit_scores = (
            {
                str(key): _finite_score(value)
                for key, value in raw_scores.items()
                if isinstance(key, str)
            }
            if isinstance(raw_scores, dict)
            else {}
        )
        return plan

    def _dict_to_claim(self, data: object) -> Claim:
        if not isinstance(data, dict):
            return Claim(
                text="",
                claim_type="empirical",
                evidence_ids=[],
                evidence_label=EvidenceLabel.PILOT,
            )
        try:
            label = EvidenceLabel(data.get("evidence_label", "pilot"))
        except ValueError:
            label = EvidenceLabel.PILOT
        evidence_ids = data.get("evidence_ids", [])
        if not isinstance(evidence_ids, list):
            evidence_ids = []
        return Claim(
            text=str(data.get("text", "")),
            claim_type=str(data.get("claim_type", "empirical")),
            evidence_ids=[str(item) for item in evidence_ids],
            evidence_label=label,
            verified=data.get("verified") is True and label == EvidenceLabel.PAPER_RESULT,
        )


def _safe_prefix_id(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value or ""))


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _load_json_object(path: Path) -> dict:
    if path.stat().st_size > MAX_CHECKPOINT_BYTES:
        raise ValueError(f"checkpoint exceeds {MAX_CHECKPOINT_BYTES} bytes")
    raw = path.read_bytes()
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise ValueError(f"checkpoint exceeds {MAX_CHECKPOINT_BYTES} bytes")
    data = json.loads(raw.decode("utf-8"), parse_constant=_reject_nonfinite_json)
    if not isinstance(data, dict):
        raise ValueError("checkpoint root must be a JSON object")
    return data


def _finite_score(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _finite_nonnegative(value: object) -> float:
    if isinstance(value, bool):
        raise ValueError("value must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("value must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError("value must be non-negative")
    return number
