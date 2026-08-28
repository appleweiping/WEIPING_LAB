"""
Evidence Gate Engine.

Enforces ARIS evidence discipline throughout the pipeline.
Every result gets labeled. Only paper_result evidence goes in the paper.

Evidence labels (from ARIS):
- paper_result: 20+ seeds, statistically valid, fair comparison → main paper
- official: full seeds, needs one more check → almost
- diagnostic: partial seeds / preliminary → supplementary only
- pilot: quick test → never in paper

This engine:
1. Validates experiment results against evidence criteria
2. Labels each result with the appropriate evidence level
3. Blocks paper claims that lack paper_result evidence
4. Generates the claim-evidence map
"""

from __future__ import annotations
import json
import math
import re
from ..core.models import ExperimentBlock, ExperimentPlan, Claim, EvidenceLabel, Paper
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..results.loader import evidence_prompt_view


EVIDENCE_AUDIT_PROMPT = """You are auditing experiment results for evidence quality.
This is a strict audit — you are a different agent from the one who ran the experiments.

Experiment block: {block_name}
Hypothesis: {hypothesis}
Results: {results}
Seeds used: {seeds}
Baselines compared: {baselines}
Metrics reported: {metrics}

Evidence criteria:
- paper_result: ≥20 seeds, paired t-test p<0.05, effect size reported, ≥8 baselines, same data splits
- official: ≥20 seeds, statistically valid, but needs one more verification
- diagnostic: 3-19 seeds OR missing statistical test OR <8 baselines
- pilot: <3 seeds OR no statistical test OR single baseline

Fairness check:
- Same data splits as baselines? (required for paper_result)
- Same preprocessing? (required for paper_result)
- Same compute budget? (required for paper_result)
- Hyperparameter tuning fair? (required for paper_result)

Output JSON:
{{
  "evidence_label": "paper_result|official|diagnostic|pilot",
  "seeds_count": N,
  "statistical_test": "t-test|none|other",
  "p_value": X or null,
  "effect_size": X or null,
  "baselines_count": N,
  "fairness_issues": ["issue 1"] or [],
  "reasoning": "why this label",
  "can_use_in_paper": true/false
}}
"""

CLAIM_EXTRACTION_PROMPT = """Extract all claims from this paper section and map them to evidence.

Section: {section_name}
Content: {content}

Available experiment evidence (the only allowed empirical evidence IDs):
{evidence_catalog}

For each claim, identify:
1. The exact claim text
2. What type: empirical (numbers), novelty (first/new), theoretical (proof)
3. What evidence is needed to support it
4. Which exact experiment block IDs support it. Use an empty list when none do.

Output JSON array:
[{{
  "claim_text": "...",
  "claim_type": "empirical|novelty|theoretical",
  "evidence_needed": "what experiment/result supports this",
  "evidence_ids": ["1", "2"] or [],
  "overclaim_risk": "high|medium|low",
  "overclaim_reason": "why it might be overclaiming" or null
}}]
"""


class EvidenceGate:
    def __init__(self, config: LabConfig, llm: LLMProvider):
        self.config = config
        self.llm = llm

    async def audit_block(self, block: ExperimentBlock) -> ExperimentBlock:
        """LLM-audit a block without allowing the model to promote its label."""
        if not block.results:
            block.evidence_label = EvidenceLabel.PILOT
            return block

        audit_response = await self.llm.complete(
            self.config.auditor(),
            [
                {
                    "role": "user",
                    "content": EVIDENCE_AUDIT_PROMPT.format(
                        block_name=block.name,
                        hypothesis=block.hypothesis,
                        results=json.dumps(
                            evidence_prompt_view(block.results),
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )[:2000],
                        seeds=block.seeds,
                        baselines=", ".join(block.baselines),
                        metrics=", ".join(block.primary_metrics),
                    ),
                }
            ],
            temperature=0.1,
            max_tokens=1024,
        )
        audit = self._parse_json(audit_response)
        if not audit:
            block.evidence_label = EvidenceLabel.PILOT
            return block

        label_str = audit.get("evidence_label", "pilot")
        try:
            suggested_label = EvidenceLabel(label_str)
        except ValueError:
            suggested_label = EvidenceLabel.PILOT

        rank = {
            EvidenceLabel.PILOT: 0,
            EvidenceLabel.DIAGNOSTIC: 1,
            EvidenceLabel.OFFICIAL: 2,
            EvidenceLabel.PAPER_RESULT: 3,
        }
        if rank[suggested_label] < rank[block.evidence_label]:
            block.evidence_label = suggested_label

        # Store audit results in block metadata
        block.results["_evidence_audit"] = audit
        return block

    async def audit_plan(self, plan: ExperimentPlan) -> dict[str, float]:
        """
        Audit the full experiment plan before running.
        Returns scores: Evidence, Rigor, Gates, Feasibility, Paper-potential.
        All must be ≥6 to proceed (ARIS rule).
        """
        plan_text = self._format_plan(plan)

        audit_prompt = f"""You are auditing an experiment plan before execution.
Score each dimension 0-10. All must be ≥6 to proceed.

Experiment plan:
{plan_text}

Scoring criteria:
- Evidence (0-10): Are the evidence requirements clear? Will results be paper_result quality?
- Rigor (0-10): Are there ≥8 baselines? ≥20 seeds planned? Statistical tests specified?
- Gates (0-10): Are there concrete kill conditions? Clear pass/fail thresholds?
- Feasibility (0-10): Can this be done in the estimated time with standard resources?
- Paper-potential (0-10): If results are positive, is this publishable at a top venue?

Output JSON:
{{
  "Evidence": X,
  "Rigor": X,
  "Gates": X,
  "Feasibility": X,
  "Paper-potential": X,
  "blocking_issues": ["issue 1"] or [],
  "verdict": "approved|needs_revision|rejected"
}}"""

        response = await self.llm.complete(
            self.config.auditor(),
            [{"role": "user", "content": audit_prompt}],
            temperature=0.2,
            max_tokens=1024,
        )
        scores = self._parse_json(response)
        # Default to failing scores if parse fails — never approve on empty response
        _DIMS = ("Evidence", "Rigor", "Gates", "Feasibility", "Paper-potential")
        if not scores:
            plan.audit_scores = {d: 0.0 for d in _DIMS}
            plan.approved = False
            return plan.audit_scores

        plan.audit_scores = {dimension: self._score(scores.get(dimension)) for dimension in _DIMS}
        # Require BOTH LLM verdict AND all scores ≥ threshold
        llm_approved = scores.get("verdict") == "approved"
        scores_pass = all(
            plan.audit_scores[dimension] >= self.config.min_experiment_audit_score
            for dimension in _DIMS
        )
        plan.approved = llm_approved and scores_pass
        return plan.audit_scores

    async def extract_claims(self, paper: Paper, plan: ExperimentPlan | None = None) -> list[Claim]:
        """Extract claims and link them to validated experiment block IDs.

        The model identifies candidate links, but the evidence label and verified
        flag are derived locally from the loaded plan.
        """

        claims = []
        block_by_id = {str(block.id): block for block in plan.blocks} if plan else {}
        evidence_catalog = self._format_evidence_catalog(plan)
        claim_sources = [("abstract", paper.abstract), *paper.sections.items()]
        for section_name, content in claim_sources:
            if not content:
                continue
            response = await self.llm.complete(
                self.config.auditor(),
                [
                    {
                        "role": "user",
                        "content": CLAIM_EXTRACTION_PROMPT.format(
                            section_name=section_name,
                            content=content[:3000],
                            evidence_catalog=evidence_catalog,
                        ),
                    }
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            raw_claims = self._parse_json_array(response)
            for rc in raw_claims:
                if not isinstance(rc, dict):
                    continue
                evidence_ids = self._validated_evidence_ids(rc.get("evidence_ids"), block_by_id)
                linked_labels = [block_by_id[item].evidence_label for item in evidence_ids]
                label = self._weakest_label(linked_labels)
                claim_text = str(rc.get("claim_text", "")).strip()
                claim_type = str(rc.get("claim_type", "empirical")).strip().lower()
                if claim_type not in {"empirical", "novelty", "theoretical"}:
                    claim_type = "empirical"
                if section_name.lower() in {"abstract", "experiments", "results", "analysis"}:
                    if self._looks_empirical(claim_text):
                        claim_type = "empirical"
                verified = bool(evidence_ids) and all(
                    item == EvidenceLabel.PAPER_RESULT for item in linked_labels
                )

                claims.append(
                    Claim(
                        text=claim_text,
                        claim_type=claim_type,
                        evidence_ids=evidence_ids,
                        evidence_label=label,
                        verified=verified,
                    )
                )
        paper.claims = claims
        return claims

    def check_paper_ready(
        self, paper: Paper, plan: ExperimentPlan | None = None
    ) -> tuple[bool, list[str]]:
        """Check that empirical claims bind to the current validated plan.

        Persisted claim labels and ``verified`` flags are presentation state, not
        authority. When a plan is supplied, both are recomputed from exact block
        IDs so checkpoint edits or stale results cannot preserve readiness.
        """
        issues = []
        if not paper.claims:
            return False, ["No claims were extracted; deterministic claim audit cannot pass"]
        if plan is None:
            return False, ["A current validated experiment plan is required for claim binding"]
        block_by_id = {str(block.id): block for block in plan.blocks} if plan else {}
        if plan and len(block_by_id) != len(plan.blocks):
            block_by_id = {}

        empirical_claims = []
        for claim in paper.claims:
            claim.claim_type = str(claim.claim_type).strip().lower()
            if claim.claim_type not in {"empirical", "novelty", "theoretical"}:
                claim.claim_type = "empirical"
            if self._looks_empirical(claim.text):
                claim.claim_type = "empirical"
            if claim.claim_type != "empirical":
                continue

            if plan is not None:
                evidence_ids = self._validated_evidence_ids(claim.evidence_ids, block_by_id)
                linked_blocks = [block_by_id[item] for item in evidence_ids]
                linked_labels = [block.evidence_label for block in linked_blocks]
                claim.evidence_ids = evidence_ids
                claim.evidence_label = self._weakest_label(linked_labels)
                claim.verified = bool(linked_blocks) and all(
                    block.results and block.evidence_label == EvidenceLabel.PAPER_RESULT
                    for block in linked_blocks
                )
            empirical_claims.append(claim)

        if not empirical_claims:
            issues.append("No empirical claims were extracted from an experimental paper")
        for claim in empirical_claims:
            if (
                not claim.verified
                or not claim.evidence_ids
                or claim.evidence_label != EvidenceLabel.PAPER_RESULT
            ):
                issues.append(
                    f"Empirical claim lacks linked paper_result evidence: {claim.text[:80]}"
                )
        return len(issues) == 0, issues

    def _format_evidence_catalog(self, plan: ExperimentPlan | None) -> str:
        if not plan:
            return "No validated experiment plan is available."
        lines = []
        for block in plan.blocks:
            public_results = evidence_prompt_view(block.results)
            lines.append(
                f"Block {block.id} [{block.evidence_label.value}] {block.name}: "
                f"{json.dumps(public_results, ensure_ascii=False, default=str)[:800]}"
            )
        return "\n".join(lines) or "No validated experiment results are available."

    @staticmethod
    def _validated_evidence_ids(value: object, blocks: dict[str, ExperimentBlock]) -> list[str]:
        if not isinstance(value, list):
            return []
        validated: list[str] = []
        for raw in value:
            if isinstance(raw, bool) or not isinstance(raw, (int, str)):
                continue
            match = re.fullmatch(r"(?:block[_\s-]*)?(0|[1-9]\d{0,3})", str(raw).strip(), re.I)
            if not match:
                continue
            candidate = str(int(match.group(1)))
            if candidate in blocks and candidate not in validated:
                validated.append(candidate)
        return validated

    @staticmethod
    def _looks_empirical(text: str) -> bool:
        return bool(
            re.search(
                r"(?:\d|%|p\s*[<=>]|confidence interval|effect size|accuracy|"
                r"f1\b|latency|baseline|seed|result|outperform|improv|increase|decrease)",
                str(text),
                re.I,
            )
        )

    @staticmethod
    def _weakest_label(labels: list[EvidenceLabel]) -> EvidenceLabel:
        if not labels:
            return EvidenceLabel.PILOT
        rank = {
            EvidenceLabel.PILOT: 0,
            EvidenceLabel.DIAGNOSTIC: 1,
            EvidenceLabel.OFFICIAL: 2,
            EvidenceLabel.PAPER_RESULT: 3,
        }
        return min(labels, key=rank.__getitem__)

    @staticmethod
    def _score(value: object) -> float:
        if isinstance(value, bool):
            return 0.0
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        return score if math.isfinite(score) and 0.0 <= score <= 10.0 else 0.0

    def _format_plan(self, plan: ExperimentPlan) -> str:
        lines = [f"Idea: {plan.idea_id}", f"Blocks: {len(plan.blocks)}"]
        for b in plan.blocks:
            lines.append(
                f"\nBlock {b.id}: {b.name}\n"
                f"  Hypothesis: {b.hypothesis}\n"
                f"  Baselines: {len(b.baselines)} ({', '.join(b.baselines[:3])}...)\n"
                f"  Seeds: {b.seeds}\n"
                f"  Kill condition: {b.kill_condition}"
            )
        lines.append(f"\nMilestone gates: {'; '.join(plan.milestone_gates)}")
        lines.append(f"Fairness constraints: {'; '.join(plan.fairness_constraints)}")
        return "\n".join(lines)

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

    def _parse_json_array(self, text: str) -> list[dict]:
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                pass
        try:
            result = json.loads(text.strip())
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            return []
