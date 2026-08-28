"""
Phase 5: Paper Write

Evidence-backed narrative. Every claim must have paper_result evidence.
Writes full paper sections to workspace/papers/.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from ..core.models import Idea, ExperimentPlan, Paper, EvidenceLabel
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..providers.literature import LiteratureProvider
from ..results.loader import evidence_prompt_view
from ..storage import atomic_write_public_text


ABSTRACT_PROMPT = """Write a paper abstract for this research.

Title: {title}
Phenomenon: {phenomenon}
Hypothesis: {hypothesis}
Method: {proposed_method}
Key results: {key_results}
Contribution: {expected_contribution}

Write a 150-200 word abstract following this structure:
1. Motivation (the phenomenon/problem)
2. Gap (what existing methods miss)
3. Our approach (the method)
4. Key results (with numbers from paper_result evidence)
5. Significance (why this matters)

Be specific. Include actual numbers. No vague claims.
"""

SECTION_PROMPT = """Write the {section} section of a research paper.

Title: {title}
Phenomenon: {phenomenon}
Method: {proposed_method}
Contribution: {expected_contribution}
Evidence available: {evidence_summary}
Related work context: {related_work}

Section-specific instructions:
{section_instructions}

Requirements:
- Every empirical claim must be backed by evidence labeled paper_result
- No overclaiming ("significantly better" without numbers)
- No vague statements ("our method is effective")
- Cite specific papers where relevant
- Write in academic style, past tense for experiments

Write the section content (LaTeX-compatible, no \\begin/\\end document wrapper).
"""

SECTION_INSTRUCTIONS = {
    "introduction": """
- Start with the phenomenon (the observed anomaly)
- Explain why existing methods fail to address it
- State the hypothesis clearly
- Summarize contributions as a bulleted list
- End with paper organization
""",
    "related_work": """
- Organize by sub-topic, not chronologically
- Be fair to prior work — acknowledge their strengths
- Clearly explain what makes our work different
- Cite at least 15 papers
- Do not strawman prior work
""",
    "method": """
- Start with the problem formulation (notation, definitions)
- Explain the key insight (why this works)
- Describe the method step by step
- Include complexity analysis if relevant
- Explain how it addresses the phenomenon
""",
    "experiments": """
- Describe datasets, baselines, evaluation protocol
- Explain fairness constraints (same splits, same preprocessing)
- Report all metrics (not cherry-picked)
- Include statistical significance tests
- Describe hyperparameter tuning procedure
""",
    "results": """
- Present main results table first
- Discuss each result in relation to the hypothesis
- Explain surprising results
- Include ablation results
- Reference figures and tables
""",
    "analysis": """
- Mechanism analysis: why does it work?
- Failure cases: when does it not work?
- Robustness analysis
- Qualitative examples if applicable
""",
    "conclusion": """
- Summarize the phenomenon, method, and key findings
- State limitations honestly
- Suggest future work
- End with the broader impact
""",
}


class PaperWriter:
    def __init__(self, config: LabConfig, llm: LLMProvider, lit: LiteratureProvider):
        self.config = config
        self.llm = llm
        self.lit = lit

    async def run(self, idea: Idea, plan: ExperimentPlan) -> Paper:
        """Write the full paper. Returns Paper object."""
        workspace = Path(idea.workspace_dir) if idea.workspace_dir else None
        papers_dir = (workspace / "papers") if workspace else None
        if papers_dir:
            papers_dir.mkdir(parents=True, exist_ok=True)

        # Gather evidence summary from completed blocks
        evidence_summary = self._summarize_evidence(plan)
        if not evidence_summary:
            raise RuntimeError("Paper writing requires at least one paper_result evidence block")

        # Get related work
        related_papers = await self.lit.search_multi(
            [
                f"{idea.domain} {idea.hypothesis[:60]}",
                f"{idea.proposed_method[:50]} related work",
            ],
            limit_each=15,
        )
        related_text = self.lit.format_for_prompt(related_papers, max_papers=15)

        paper = Paper(idea_id=idea.id, title=idea.title)

        # Write abstract first
        abstract_response = await self.llm.complete(
            self.config.executor(),
            [
                {
                    "role": "user",
                    "content": ABSTRACT_PROMPT.format(
                        title=idea.title,
                        phenomenon=idea.phenomenon,
                        hypothesis=idea.hypothesis,
                        proposed_method=idea.proposed_method,
                        key_results=evidence_summary[:500],
                        expected_contribution=idea.expected_contribution,
                    ),
                }
            ],
            temperature=0.4,
            max_tokens=512,
        )
        paper.abstract = abstract_response.strip()

        # Write each section
        sections_to_write = [
            "introduction",
            "related_work",
            "method",
            "experiments",
            "results",
            "analysis",
            "conclusion",
        ]

        for section in sections_to_write:
            response = await self.llm.complete(
                self.config.executor(),
                [
                    {
                        "role": "user",
                        "content": SECTION_PROMPT.format(
                            section=section,
                            title=idea.title,
                            phenomenon=idea.phenomenon,
                            proposed_method=idea.proposed_method,
                            expected_contribution=idea.expected_contribution,
                            evidence_summary=evidence_summary,
                            related_work=related_text
                            if section in ("related_work", "introduction")
                            else "",
                            section_instructions=SECTION_INSTRUCTIONS.get(section, ""),
                        ),
                    }
                ],
                temperature=0.5,
                max_tokens=3000,
            )
            paper.sections[section] = response.strip()

        paper.citations = [p.paper_id for p in related_papers[:30]]

        # Write to files
        if papers_dir:
            self._write_paper_files(paper, idea, papers_dir)

        return paper

    def _summarize_evidence(self, plan: ExperimentPlan) -> str:
        lines = []
        for b in plan.blocks:
            if b.results and b.evidence_label == EvidenceLabel.PAPER_RESULT:
                lines.append(f"Block {b.id} ({b.name}): {b.evidence_label.value}")
                safe_results = evidence_prompt_view(b.results)
                lines.append(
                    "  observed: "
                    + json.dumps(safe_results, ensure_ascii=False, separators=(",", ":"))[:2000]
                )
        return "\n".join(lines)[:12_000]

    def write_artifacts(self, paper: Paper, idea: Idea) -> None:
        """Refresh human-readable paper and claim-map artifacts."""

        if not idea.workspace_dir:
            return
        papers_dir = Path(idea.workspace_dir) / "papers"
        papers_dir.mkdir(parents=True, exist_ok=True)
        self._write_paper_files(paper, idea, papers_dir)

    def _write_paper_files(self, paper: Paper, idea: Idea, papers_dir: Path):
        # Full paper as markdown
        md_lines = [f"# {paper.title}\n", f"## Abstract\n\n{paper.abstract}\n"]
        for section, content in paper.sections.items():
            md_lines.append(f"## {section.replace('_', ' ').title()}\n\n{content}\n")
        atomic_write_public_text(papers_dir / "paper.md", "\n".join(md_lines))

        # Claim map
        claim_lines = [
            "# Claim-Evidence Map\n",
            "| Claim | Type | Evidence IDs | Evidence Label | Verified |",
            "|-------|------|--------------|----------------|----------|",
        ]
        for c in paper.claims:
            claim_text = c.text.replace("|", "\\|").replace("\n", " ")[:120]
            claim_lines.append(
                f"| {claim_text} | {c.claim_type} | {', '.join(c.evidence_ids) or 'none'} | "
                f"{c.evidence_label.value} | {'✓' if c.verified else '✗'} |"
            )
        atomic_write_public_text(papers_dir / "CLAIM_MAP.md", "\n".join(claim_lines))

    def _parse_json(self, text: str) -> dict:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return {}
