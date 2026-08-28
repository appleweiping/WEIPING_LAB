"""
Phase 7: Citation Audit
Phase 8: Paper Claim Audit

Two final gates before the paper is marked ready.
Both done by a different agent than the paper writer.
"""

from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from ..core.models import Idea, Paper
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..providers.literature import LiteratureProvider
from ..runtime import safe_error
from ..storage import atomic_write_public_text


CITATION_AUDIT_PROMPT = """You are auditing the citations in a research paper.

Paper title: {title}
Domain: {domain}
Citations listed: {citations}
Related work section: {related_work}

Check:
1. Completeness: Are seminal papers cited? Recent papers through {current_year}?
2. Fairness: Are the 3 closest competitors cited? Are their strengths acknowledged?
3. Breadth: Are papers from different sub-areas cited?
4. Technical accuracy: Are papers cited for the right claims?

Minimum for top venue: {min_citations} citations.

Output JSON:
{{
  "citation_count": N,
  "missing_seminal": ["paper 1", "paper 2"],
  "missing_recent": ["paper 3"],
  "missing_competitors": ["paper 4"],
  "fairness_issues": ["issue 1"],
  "verdict": "pass|needs_additions|fail",
  "additions_required": ["add paper X for claim Y"]
}}
"""

CLAIM_AUDIT_PROMPT = """You are auditing all claims in a research paper.
This is the final gate before submission. Be thorough and strict.

Paper title: {title}
Abstract: {abstract}
All sections: {sections_summary}
Evidence available: {evidence_summary}

For each type of claim, check:

EMPIRICAL CLAIMS (numbers, comparisons):
- Does the number match the experiment results?
- Is the comparison fair (same data, preprocessing, compute)?
- Is statistical significance reported?
- Are seeds ≥20?

NOVELTY CLAIMS ("first", "new", "novel", "state-of-the-art"):
- Is there literature evidence that no prior work does exactly this?
- Is "state-of-the-art" backed by comparison to all recent methods?

THEORETICAL CLAIMS (proofs, guarantees):
- Is the proof complete?
- Are assumptions stated?
- Are edge cases addressed?

OVERCLAIM DETECTION:
- "significantly better" without numbers → flag
- "state-of-the-art" without comparison → flag
- "first ever" without literature search → flag
- "always works" without robustness analysis → flag

Output JSON:
{{
  "empirical_issues": ["issue 1"],
  "novelty_issues": ["issue 2"],
  "theoretical_issues": ["issue 3"],
  "overclaims": ["overclaim 1"],
  "consistency_issues": ["abstract says X but results show Y"],
  "verdict": "ready|needs_revision|not_ready",
  "blocking_issues": ["issue that must be fixed before submission"]
}}
"""


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [safe_error(item, limit=1_000) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [safe_error(value, limit=1_000)]
    return []


class CitationAudit:
    def __init__(self, config: LabConfig, llm: LLMProvider, lit: LiteratureProvider):
        self.config = config
        self.llm = llm
        self.lit = lit

    async def run(self, idea: Idea, paper: Paper) -> tuple[bool, list[str]]:
        """Audit citations. Returns (passed, issues)."""
        response = await self.llm.complete(
            self.config.auditor(),
            [
                {
                    "role": "user",
                    "content": CITATION_AUDIT_PROMPT.format(
                        title=paper.title,
                        domain=idea.domain,
                        citations=", ".join(paper.citations[:30]),
                        related_work=paper.sections.get("related_work", "")[:2000],
                        min_citations=self.config.min_citations,
                        current_year=datetime.now(timezone.utc).year,
                    ),
                }
            ],
            temperature=0.2,
            max_tokens=1024,
        )
        result = self._parse_json(response)
        raw_verdict = result.get("verdict", "fail")
        valid_verdict = isinstance(raw_verdict, str) and raw_verdict in {
            "pass",
            "needs_additions",
            "fail",
        }
        verdict = raw_verdict if valid_verdict else "fail"
        required_lists = (
            "missing_seminal",
            "missing_recent",
            "missing_competitors",
            "fairness_issues",
            "additions_required",
        )
        issues = (
            _string_list(result.get("missing_seminal"))
            + _string_list(result.get("missing_recent"))
            + _string_list(result.get("missing_competitors"))
            + _string_list(result.get("fairness_issues"))
            + _string_list(result.get("additions_required"))
        )
        if not valid_verdict or any(
            not isinstance(result.get(field), list) for field in required_lists
        ):
            issues.append("Model citation audit response was incomplete or malformed")
        actual_citations = len({str(item).strip() for item in paper.citations if str(item).strip()})
        if actual_citations < self.config.min_citations:
            issues.append(
                f"Only {actual_citations} unique citation IDs are persisted; "
                f"minimum is {self.config.min_citations}"
            )
        issues = list(dict.fromkeys(str(item) for item in issues if str(item).strip()))
        passed = verdict == "pass" and not issues

        workspace = Path(idea.workspace_dir) if idea.workspace_dir else None
        if workspace:
            papers_dir = workspace / "papers"
            papers_dir.mkdir(exist_ok=True)
            atomic_write_public_text(
                papers_dir / "CITATION_AUDIT.md",
                f"# Citation Audit\n\n**Model verdict**: {verdict}\n\n"
                f"**Effective verdict**: {'pass' if passed else 'fail'}\n\n"
                f"**Persisted unique count**: {actual_citations}\n\n"
                f"## Issues\n" + "\n".join(f"- {i}" for i in issues) + "\n\n"
                "## Additions Required\n"
                + "\n".join(f"- {a}" for a in _string_list(result.get("additions_required"))),
                encoding="utf-8",
            )

        return passed, issues

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


class PaperClaimAudit:
    def __init__(self, config: LabConfig, llm: LLMProvider):
        self.config = config
        self.llm = llm

    async def run(
        self,
        idea: Idea,
        paper: Paper,
        deterministic_issues: list[str] | None = None,
    ) -> tuple[bool, list[str]]:
        """Final claim audit. Returns (passed, blocking_issues)."""
        sections_summary = "\n\n".join(f"[{k}]: {v[:500]}" for k, v in paper.sections.items())
        evidence_summary = "\n".join(
            f"- {c.text[:80]}: {c.evidence_label.value} ({'verified' if c.verified else 'unverified'})"
            for c in paper.claims[:20]
        )

        response = await self.llm.complete(
            self.config.auditor(),
            [
                {
                    "role": "user",
                    "content": CLAIM_AUDIT_PROMPT.format(
                        title=paper.title,
                        abstract=paper.abstract[:500],
                        sections_summary=sections_summary[:3000],
                        evidence_summary=evidence_summary or "No claims extracted yet",
                    ),
                }
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        result = self._parse_json(response)
        raw_verdict = result.get("verdict", "not_ready")
        valid_verdict = isinstance(raw_verdict, str) and raw_verdict in {
            "ready",
            "needs_revision",
            "not_ready",
        }
        verdict = raw_verdict if valid_verdict else "not_ready"
        required_lists = (
            "blocking_issues",
            "empirical_issues",
            "novelty_issues",
            "theoretical_issues",
            "overclaims",
            "consistency_issues",
        )
        model_issues = (
            _string_list(result.get("blocking_issues"))
            + _string_list(result.get("empirical_issues"))
            + _string_list(result.get("novelty_issues"))
            + _string_list(result.get("theoretical_issues"))
            + _string_list(result.get("overclaims"))
            + _string_list(result.get("consistency_issues"))
        )
        if not valid_verdict or any(
            not isinstance(result.get(field), list) for field in required_lists
        ):
            model_issues.append("Model claim audit response was incomplete or malformed")
        blocking = _string_list(deterministic_issues or []) + model_issues
        blocking = list(dict.fromkeys(str(item) for item in blocking if str(item).strip()))
        passed = verdict == "ready" and not blocking

        workspace = Path(idea.workspace_dir) if idea.workspace_dir else None
        if workspace:
            papers_dir = workspace / "papers"
            papers_dir.mkdir(exist_ok=True)
            atomic_write_public_text(
                papers_dir / "CLAIM_AUDIT.md",
                f"# Claim Audit\n\n**Model verdict**: {verdict}\n\n"
                f"**Effective verdict**: {'ready' if passed else 'not_ready'}\n\n"
                f"## Blocking Issues\n" + "\n".join(f"- {i}" for i in blocking) + "\n\n"
                "## Empirical Issues\n"
                + "\n".join(f"- {i}" for i in _string_list(result.get("empirical_issues")))
                + "\n\n"
                "## Overclaims\n"
                + "\n".join(f"- {i}" for i in _string_list(result.get("overclaims")))
                + "\n\n"
                "## Consistency Issues\n"
                + "\n".join(f"- {i}" for i in _string_list(result.get("consistency_issues"))),
                encoding="utf-8",
            )

        paper.claim_audit_passed = passed
        return passed, blocking

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
