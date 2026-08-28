"""
Phase 3: Experiment Plan

Designs rigorous experiments before writing any code.
5-7 blocks, each with a falsifiable hypothesis.
8+ baselines. 20+ seeds. Concrete kill conditions.
Cross-model audit: all dimensions must score ≥6.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from ..core.models import Idea, ExperimentBlock, ExperimentPlan, ExperimentStatus
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..storage import atomic_write_public_text


EXPERIMENT_PLAN_PROMPT = """You are designing a rigorous experiment plan for a research paper.
Design this like a hostile reviewer would — every experiment must be necessary and sufficient.

Idea:
Title: {title}
Phenomenon: {phenomenon}
Hypothesis: {hypothesis}
Proposed method: {proposed_method}
Expected contribution: {expected_contribution}
Available baselines: {baselines}
Available datasets: {datasets}

Design 5-7 experiment blocks. Each block answers ONE sub-question.

Block types (use all that apply):
B1: Phenomenon validation — does the claimed phenomenon actually exist?
B2: Method comparison — head-to-head vs all baselines
B3: Ablation — is our method responsible, not confounders?
B4: Mechanism analysis — why does it work?
B5: Robustness — does it hold across domains/scales/settings?
B6: Downstream impact — does proxy metric improvement translate to real value?
B7: Extended/realistic — real-world simulation

For each block:
{{
  "id": N,
  "name": "Block N: [type] — [what it tests]",
  "hypothesis": "the falsifiable claim this block tests",
  "primary_metrics": ["metric 1", "metric 2"],
  "secondary_metrics": ["metric 3"],
  "baselines": ["baseline 1", ..., "baseline 8+"],
  "seeds": 20,
  "expected_outcome": "what we expect to see if hypothesis is true",
  "failure_mode": "what would disprove the hypothesis",
  "kill_condition": "concrete threshold: if X < Y → STOP or PIVOT"
}}

Also provide:
- milestone_gates: ["M0: Block 1 with 3 seeds must show effect > X", "M1: ...", "M2: ..."]
- fairness_constraints: ["same data splits as baselines", "same preprocessing", ...]
- compute_estimate_hours: N
- seed_strategy: "20 seeds for paper_result blocks, 3-5 for diagnostic blocks"

Output JSON:
{{
  "blocks": [...],
  "milestone_gates": [...],
  "fairness_constraints": [...],
  "compute_estimate_hours": N,
  "seed_strategy": "..."
}}
"""


class ExperimentPlanner:
    def __init__(self, config: LabConfig, llm: LLMProvider):
        self.config = config
        self.llm = llm

    async def run(self, idea: Idea) -> tuple[ExperimentPlan | None, bool]:
        """Design experiment plan. Returns (plan, approved)."""
        baselines = idea.metadata.get("baselines", [])
        datasets = idea.metadata.get("data_sources", [])

        response = await self.llm.complete(
            self.config.executor(),
            [
                {
                    "role": "user",
                    "content": EXPERIMENT_PLAN_PROMPT.format(
                        title=idea.title,
                        phenomenon=idea.phenomenon,
                        hypothesis=idea.hypothesis,
                        proposed_method=idea.proposed_method,
                        expected_contribution=idea.expected_contribution,
                        baselines=", ".join(baselines) if baselines else "to be determined",
                        datasets=", ".join(datasets) if datasets else "standard benchmarks",
                    ),
                }
            ],
            temperature=0.4,
            max_tokens=4096,
        )
        data = self._parse_json(response)
        if not data:
            return None, False

        blocks = []
        raw_blocks = data.get("blocks")
        if not isinstance(raw_blocks, list) or not 5 <= len(raw_blocks) <= 7:
            return None, False
        used_ids: set[int] = set()
        fallback_baselines = self._string_list(baselines)
        for raw_block in raw_blocks:
            if not isinstance(raw_block, dict):
                return None, False
            block_baselines = self._string_list(raw_block.get("baselines")) or fallback_baselines
            # Enforce minimum baselines
            if len(block_baselines) < self.config.min_baselines:
                block_baselines = block_baselines + fallback_baselines
                block_baselines = list(dict.fromkeys(block_baselines))  # deduplicate

            block_id = self._nonnegative_int(raw_block.get("id"))
            if block_id is None or block_id >= 10_000 or block_id in used_ids:
                return None, False
            used_ids.add(block_id)
            seeds = self._nonnegative_int(raw_block.get("seeds")) or 0

            blocks.append(
                ExperimentBlock(
                    id=block_id,
                    name=str(raw_block.get("name", f"Block {block_id}")),
                    hypothesis=str(raw_block.get("hypothesis", "")),
                    primary_metrics=self._string_list(raw_block.get("primary_metrics")),
                    secondary_metrics=self._string_list(raw_block.get("secondary_metrics")),
                    baselines=block_baselines,
                    seeds=max(seeds, self.config.min_seeds_paper),
                    expected_outcome=str(raw_block.get("expected_outcome", "")),
                    failure_mode=str(raw_block.get("failure_mode", "")),
                    kill_condition=str(raw_block.get("kill_condition", "")),
                    status=ExperimentStatus.PLANNED,
                )
            )

        if not 5 <= len(blocks) <= 7:
            return None, False

        plan = ExperimentPlan(
            idea_id=idea.id,
            blocks=blocks,
            compute_estimate_hours=self._nonnegative_float(
                data.get("compute_estimate_hours"), default=100.0
            ),
            seed_strategy=str(data.get("seed_strategy", "")),
            fairness_constraints=self._string_list(data.get("fairness_constraints")),
            milestone_gates=self._string_list(data.get("milestone_gates")),
        )

        # Write plan to workspace
        workspace = Path(idea.workspace_dir) if idea.workspace_dir else None
        if workspace:
            self._write_plan(plan, idea, workspace)

        return plan, True

    def _write_plan(self, plan: ExperimentPlan, idea: Idea, workspace: Path):
        lines = [
            f"# Experiment Plan: {idea.title}\n",
            f"**Idea ID**: {idea.id}",
            f"**Compute estimate**: {plan.compute_estimate_hours:.0f} GPU hours",
            f"**Seed strategy**: {plan.seed_strategy}\n",
            "## Milestone Gates\n",
        ]
        for gate in plan.milestone_gates:
            lines.append(f"- {gate}")
        lines.append("\n## Fairness Constraints\n")
        for fc in plan.fairness_constraints:
            lines.append(f"- {fc}")
        lines.append("\n## Experiment Blocks\n")
        for b in plan.blocks:
            lines.extend(
                [
                    f"### Block {b.id}: {b.name}",
                    f"**Hypothesis**: {b.hypothesis}",
                    f"**Primary metrics**: {', '.join(b.primary_metrics)}",
                    f"**Baselines** ({len(b.baselines)}): {', '.join(b.baselines[:5])}{'...' if len(b.baselines) > 5 else ''}",
                    f"**Seeds**: {b.seeds}",
                    f"**Expected outcome**: {b.expected_outcome}",
                    f"**Kill condition**: {b.kill_condition}\n",
                ]
            )

        atomic_write_public_text(workspace / "EXPERIMENT_PLAN.md", "\n".join(lines))

        # Tracker
        tracker_lines = [
            "# Experiment Tracker\n",
            "| Block | Status | Evidence Label | Notes |",
            "|-------|--------|----------------|-------|",
        ]
        for b in plan.blocks:
            tracker_lines.append(f"| {b.id}: {b.name} | {b.status.value} | pending | |")
        atomic_write_public_text(workspace / "EXPERIMENT_TRACKER.md", "\n".join(tracker_lines))

    def _parse_json(self, text: str) -> dict:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass
        try:
            parsed = json.loads(text.strip())
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _string_list(value: object) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    @staticmethod
    def _nonnegative_int(value: object) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, float) and value.is_integer() and value >= 0:
            return int(value)
        return None

    @staticmethod
    def _nonnegative_float(value: object, *, default: float) -> float:
        if isinstance(value, bool):
            return default
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        return number if 0.0 <= number < float("inf") else default
