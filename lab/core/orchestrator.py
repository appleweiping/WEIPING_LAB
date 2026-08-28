"""
Weiping Lab Orchestrator v2.

Wires all modules together. Handles pipeline resumption.
Integrates: workspace manager, memory, novelty checker, beam search, anti-toy.
"""

from __future__ import annotations
import uuid
from pathlib import Path
from ..core.models import Idea, IdeaStatus, LabSession, Paper
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..providers.literature import LiteratureProvider
from ..engines.phenomenon import PhenomenonObservatory
from ..engines.analogy import AnalogicalBridge
from ..engines.kill_first import KillFirstEngine
from ..engines.evidence import EvidenceGate
from ..engines.anti_toy import AntiToyEngine
from ..phases.p1_ideation import IdeaGenerator
from ..phases.p2_refine import ResearchRefine
from ..phases.p3_experiment_plan import ExperimentPlanner
from ..phases.p4_bridge import ExperimentBridge
from ..phases.p5_paper_write import PaperWriter
from ..phases.p6_review import AutoReviewLoop, REVIEW_DIMENSIONS
from ..phases.p7_p8_audit import CitationAudit, PaperClaimAudit
from ..workspace.manager import WorkspaceManager
from ..memory.store import LabMemory, IdeaRecord, _redact_jsonish
from ..novelty.checker import NoveltyChecker
from ..results.loader import ResultLoader
from ..search.beam_search import IdeaBeamSearch
from ..storage import atomic_write_json
from ..core.progress import get_reporter
from ..runtime import safe_error


class LabOrchestrator:
    def __init__(self, config: LabConfig):
        self.config = config
        self.llm = LLMProvider(config)
        self.lit = LiteratureProvider(config.semantic_scholar_key)

        # Engines
        self.observatory = PhenomenonObservatory(config, self.llm, self.lit)
        self.bridge = AnalogicalBridge(config, self.llm, self.lit)
        self.kill_first = KillFirstEngine(config, self.llm, self.lit)
        self.evidence_gate = EvidenceGate(config, self.llm)
        self.novelty_checker = NoveltyChecker(self.lit)
        self.beam_search = IdeaBeamSearch(config, self.llm, self.lit)
        self.anti_toy = AntiToyEngine(config, self.llm)

        # Phases
        self.ideator = IdeaGenerator(config, self.llm, self.lit)
        self.refiner = ResearchRefine(config, self.llm, self.lit)
        self.planner = ExperimentPlanner(config, self.llm)
        self.exp_bridge = ExperimentBridge(config, self.llm)
        self.writer = PaperWriter(config, self.llm, self.lit)
        self.reviewer = AutoReviewLoop(config, self.llm)
        self.citation_auditor = CitationAudit(config, self.llm, self.lit)
        self.claim_auditor = PaperClaimAudit(config, self.llm)

        # Infrastructure
        self.workspace = WorkspaceManager(config)
        self.workspace.setup()
        self.memory = LabMemory(str(Path(config.workspace_root) / ".memory"))

    # ── Discovery modes ───────────────────────────────────────────────────────

    async def discover(self, domain: str, use_beam: bool = True) -> LabSession:
        """
        Full discovery pipeline with beam search.
        1. Scan for phenomena
        2. Beam search over hypothesis space per phenomenon
        3. Novelty check
        4. Kill-first evaluation
        """
        session = self._new_session("discover", domain, domain)
        memory_context = self.memory.format_context_for_prompt(domain)
        reporter = get_reporter()

        # Step 1: Phenomenon scan
        reporter.phase("phenomenon_scan", domain)
        session.log("phenomenon_scan", domain=domain)
        phenomena = await self.observatory.scan(domain)
        session.phenomena = phenomena
        session.log("phenomena_found", count=len(phenomena))
        reporter.done(f"{len(phenomena)} phenomena found")

        # Step 2: Generate ideas (beam search or single-pass)
        import asyncio

        reporter.phase("ideation", "beam search" if use_beam else "single pass")
        ideas = []
        for phenomenon in phenomena[:3]:
            if use_beam:
                beam_ideas = await self.beam_search.search(domain, phenomenon, memory_context)
                ideas.extend(beam_ideas)
            else:
                idea = await self.ideator.from_phenomenon(domain, phenomenon)
                if idea:
                    ideas.append(idea)

        # Assign workspaces
        for idea in ideas:
            self.workspace.create_idea_workspace(idea)

        session.log("ideas_generated", count=len(ideas))
        reporter.done(f"{len(ideas)} candidate ideas generated")

        # Step 3: Novelty check (parallel)
        reporter.phase("novelty_check", f"{len(ideas)} candidates")
        novelty_results = await asyncio.gather(
            *[self.novelty_checker.check(idea) for idea in ideas]
        )
        novel_ideas = []
        for idea, (is_novel, blocking, sim) in zip(ideas, novelty_results):
            if not is_novel:
                idea.status = IdeaStatus.KILLED
                idea.metadata["killed_reason"] = safe_error(
                    f"Duplicate detected (sim={sim:.0%}): {blocking[0] if blocking else ''}",
                    limit=1_000,
                )
            else:
                novel_ideas.append(idea)

        session.log(
            "novelty_check", novel=len(novel_ideas), duplicates=len(ideas) - len(novel_ideas)
        )
        reporter.done(f"{len(novel_ideas)} novel candidates")

        # Step 4: Kill-first (parallel)
        reporter.phase("kill_first", f"{len(novel_ideas)} candidates")
        kill_results = await asyncio.gather(
            *[self.kill_first.evaluate(idea) for idea in novel_ideas]
        )
        # Mark surviving ideas as KILL_TESTED, killed ones as KILLED
        # Record killed ideas in anti-toy engine to prevent death loops
        for idea, survived in kill_results:
            if survived:
                idea.status = IdeaStatus.KILL_TESTED
            else:
                idea.status = IdeaStatus.KILLED
                kill_reason = idea.kill_argument.argument[:200] if idea.kill_argument else ""
                prior_work = idea.kill_argument.closest_prior_work if idea.kill_argument else []
                self.anti_toy.record_killed_idea(idea, kill_reason, prior_work)

        # Step 5: Surface-variation check — reject ideas too similar to killed ones
        final_ideas = []
        for idea, survived in kill_results:
            if not survived:
                final_ideas.append(idea)
                continue
            is_variation, reason = self.anti_toy.is_surface_variation(idea)
            if is_variation:
                idea.status = IdeaStatus.KILLED
                idea.metadata["killed_reason"] = safe_error(
                    f"Surface variation: {reason}", limit=1_000
                )
                final_ideas.append(idea)
            else:
                final_ideas.append(idea)

        session.ideas = final_ideas
        surviving = sum(1 for i in final_ideas if i.status == IdeaStatus.KILL_TESTED)
        session.log("kill_first_complete", surviving=surviving, killed=len(novel_ideas) - surviving)
        reporter.done(f"{surviving} candidates survived")

        # Save to memory
        for idea in session.ideas:
            self.workspace.save_idea(idea)
            self._record_to_memory(idea)

        await self._persist_session(session)
        return session

    async def extend(
        self,
        domain: str,
        current_method: str,
        current_results: str,
        limitations: str,
        n: int = 3,
    ) -> LabSession:
        """Generate follow-up ideas from an existing project."""
        session = self._new_session("extend", domain, current_method[:50])

        ideas = await self.ideator.from_extension(
            domain, current_method, current_results, limitations, n
        )
        for idea in ideas:
            self.workspace.create_idea_workspace(idea)

        # Novelty check + kill-first
        import asyncio

        novelty_results = await asyncio.gather(
            *[self.novelty_checker.check(idea) for idea in ideas]
        )
        novel_ideas = [idea for idea, (is_novel, _, _) in zip(ideas, novelty_results) if is_novel]

        kill_results = await asyncio.gather(
            *[self.kill_first.evaluate(idea) for idea in novel_ideas]
        )
        session.ideas = [idea for idea, _ in kill_results]
        session.log(
            "extension_ideas", total=len(ideas), surviving=sum(1 for _, s in kill_results if s)
        )

        for idea in session.ideas:
            self.workspace.save_idea(idea)
            self._record_to_memory(idea)

        await self._persist_session(session)
        return session

    async def transfer(self, source_domain: str, target_domain: str) -> LabSession:
        """Find cross-domain analogies and generate transfer ideas."""
        session = self._new_session("transfer", target_domain, f"{source_domain} → {target_domain}")

        analogies = await self.bridge.scan_transfers(source_domain, target_domain)
        session.analogies = analogies
        session.log("analogies_found", count=len(analogies))

        import asyncio

        ideas = []
        for analogy in analogies[:3]:
            idea = await self.ideator.from_analogy(analogy)
            if idea:
                self.workspace.create_idea_workspace(idea)
                ideas.append(idea)

        kill_results = await asyncio.gather(*[self.kill_first.evaluate(idea) for idea in ideas])
        session.ideas = [idea for idea, _ in kill_results]
        session.log(
            "transfer_ideas", total=len(ideas), surviving=sum(1 for _, s in kill_results if s)
        )

        for idea in session.ideas:
            self.workspace.save_idea(idea)
            self._record_to_memory(idea)

        await self._persist_session(session)
        return session

    # ── Full pipeline ─────────────────────────────────────────────────────────

    async def run_pipeline(self, idea: Idea) -> tuple[Idea, Paper | None]:
        """
        Run the full ARIS pipeline on a surviving idea.
        Checkpoints at each phase. Can be resumed.
        """
        # Ensure workspace exists
        if not idea.workspace_dir:
            self.workspace.create_idea_workspace(idea)

        stage = self.workspace.get_pipeline_stage(idea)
        if stage == "complete":
            completed_plan = self.workspace.load_plan(idea)
            completed_paper = self.workspace.load_paper(idea)
            if completed_plan and completed_paper:
                expected_manifest = idea.metadata.get("ready_artifacts")
                current_manifest = self.workspace.ready_artifact_manifest(idea)
                manifest_ready = (
                    isinstance(expected_manifest, dict)
                    and bool(expected_manifest)
                    and expected_manifest == current_manifest
                )
                loader = ResultLoader(idea.workspace_dir, self.config)
                results_ready, _ = loader.load_into_plan(completed_plan)
                claims_ready, claim_issues = self.evidence_gate.check_paper_ready(
                    completed_paper, completed_plan
                )
                review_ready = completed_paper.claim_audit_passed and all(
                    completed_paper.review_scores.get(dimension, 0) >= self.config.min_review_score
                    for dimension in REVIEW_DIMENSIONS
                )
                citation_ready = (
                    len(
                        {
                            citation.strip()
                            for citation in completed_paper.citations
                            if citation.strip()
                        }
                    )
                    >= self.config.min_citations
                )
                if not review_ready:
                    claim_issues.append(
                        "READY checkpoint lacks a passing persisted review and claim audit"
                    )
                if not citation_ready:
                    claim_issues.append(
                        "READY checkpoint no longer contains the minimum unique citations"
                    )
                if not manifest_ready:
                    claim_issues = [
                        "READY artifact manifest is missing or changed; plan, paper, and results "
                        "must be reviewed again",
                        *claim_issues,
                    ]
                idea.metadata["result_ingestion"] = (
                    loader.last_report.to_dict() if loader.last_report else {}
                )
                if (
                    results_ready
                    and claims_ready
                    and review_ready
                    and citation_ready
                    and manifest_ready
                ):
                    self.workspace.save_plan(idea, completed_plan)
                    self.workspace.save_idea(idea)
                    return idea, completed_paper
                completed_paper.claim_audit_passed = False
                idea.metadata["integrity_regression"] = claim_issues
                idea.metadata.pop("ready_artifacts", None)
                idea.status = IdeaStatus.REVIEWED if results_ready else IdeaStatus.RUNNING
                self.workspace.save_plan(idea, completed_plan)
                self.workspace.save_paper(idea, completed_paper)
                self.workspace.save_idea(idea)
                return idea, completed_paper
            idea.status = IdeaStatus.REVIEWED
            idea.metadata["integrity_regression"] = [
                "A READY checkpoint is missing plan.json or paper.json"
            ]
            self.workspace.save_idea(idea)
            return idea, completed_paper

        # Phase 2: Research refine
        if stage in ("kill_tested", "not_started"):
            idea, passed = await self.refiner.run(idea)
            self.workspace.save_idea(idea)
            if not passed:
                self._record_to_memory(idea, killed_at="research_refine")
                return idea, None
            stage = "refine_done"

        # Phase 3: Experiment plan
        plan = self.workspace.load_plan(idea)
        if stage == "refine_done" or plan is None:
            plan, _ = await self.planner.run(idea)
            if not plan:
                idea.status = IdeaStatus.KILLED
                self.workspace.save_idea(idea)
                return idea, None

            # Anti-toy: static check first (fast, no LLM)
            is_toy_static, toy_violations_static = self.anti_toy.check_plan_for_toys(plan)
            if is_toy_static:
                idea.status = IdeaStatus.KILLED
                idea.metadata["killed_reason"] = safe_error(
                    f"Toy violations: {'; '.join(toy_violations_static[:3])}", limit=1_000
                )
                self.workspace.save_idea(idea)
                self._record_to_memory(idea, killed_at="anti_toy_static")
                return idea, None

            # Anti-toy: LLM audit
            is_toy_llm, toy_violations_llm = await self.anti_toy.audit_plan_for_toys(plan)
            if is_toy_llm:
                idea.status = IdeaStatus.KILLED
                idea.metadata["killed_reason"] = safe_error(
                    f"Toy (LLM audit): {'; '.join(toy_violations_llm[:3])}", limit=1_000
                )
                self.workspace.save_idea(idea)
                self._record_to_memory(idea, killed_at="anti_toy_llm")
                return idea, None

            # Enforce minimum standards (hard floor)
            try:
                plan = self.anti_toy.enforce_minimum_standards(plan)
            except ValueError as e:
                idea.status = IdeaStatus.KILLED
                idea.metadata["killed_reason"] = safe_error(e)
                self.workspace.save_idea(idea)
                return idea, None

            # Evidence gate audit — all dimensions must be ≥6
            await self.evidence_gate.audit_plan(plan)
            self.workspace.save_plan(idea, plan)
            self.workspace.save_idea(idea)

            if not plan.approved:
                idea.status = IdeaStatus.KILLED
                self.workspace.save_idea(idea)
                self._record_to_memory(idea, killed_at="experiment_plan_audit")
                return idea, None

            idea.status = IdeaStatus.PLANNED
            self.workspace.save_idea(idea)
            stage = "plan_done"

        # Phase 4: Experiment bridge
        if stage == "plan_done":
            bridge_ready = await self.exp_bridge.run(idea, plan)
            if not bridge_ready:
                idea.metadata["bridge_error"] = (
                    "Generated scaffold failed structural validation; inspect "
                    "experiments/BRIDGE_STATUS.json and retry"
                )
                self.workspace.save_idea(idea)
                return idea, None
            idea.metadata.pop("bridge_error", None)
            idea.status = IdeaStatus.RUNNING
            self.workspace.save_idea(idea)
            stage = "bridge_done"

        # ── PAUSE POINT: user runs experiments ────────────────────────────────
        # Pipeline resumes when results are available in workspace/experiments/results/
        if stage in ("bridge_done", "experiments_done", "paper_written"):
            # Result files remain the source of truth. Revalidate them on every
            # resume so a stray or self-labeled JSON file cannot unlock writing.
            loader = ResultLoader(idea.workspace_dir, self.config)
            ready_for_writing, _ = loader.load_into_plan(plan)
            report = loader.last_report
            idea.metadata["result_ingestion"] = report.to_dict() if report else {}
            self.workspace.save_plan(idea, plan)
            self.workspace.save_idea(idea)
            if not ready_for_writing:
                idea.status = IdeaStatus.RUNNING
                self.workspace.save_idea(idea)
                existing_paper = (
                    self.workspace.load_paper(idea) if stage == "paper_written" else None
                )
                return idea, existing_paper
            stage = "experiments_done"

        # Phase 5: Paper write
        paper = self.workspace.load_paper(idea)
        if stage == "experiments_done" or paper is None:
            # Reload plan with results
            plan = self.workspace.load_plan(idea) or plan
            paper = await self.writer.run(idea, plan)
            await self.evidence_gate.extract_claims(paper, plan)
            self.writer.write_artifacts(paper, idea)
            self.workspace.save_paper(idea, paper)
            idea.status = IdeaStatus.WRITING
            self.workspace.save_idea(idea)
            stage = "paper_written"

        # Phase 6: Auto review loop
        paper, review_passed = await self.reviewer.run(idea, paper)
        self.workspace.save_paper(idea, paper)
        if not review_passed:
            return idea, paper

        idea.status = IdeaStatus.REVIEWED
        self.workspace.save_idea(idea)

        # Phase 7: Citation audit
        citation_passed, _ = await self.citation_auditor.run(idea, paper)

        # Phase 8: Claim audit
        _, deterministic_claim_issues = self.evidence_gate.check_paper_ready(paper, plan)
        claim_passed, _ = await self.claim_auditor.run(
            idea,
            paper,
            deterministic_issues=deterministic_claim_issues,
        )
        self.workspace.save_paper(idea, paper)

        if citation_passed and claim_passed:
            ready_artifacts = self.workspace.ready_artifact_manifest(idea)
            if ready_artifacts:
                idea.metadata["ready_artifacts"] = ready_artifacts
                idea.metadata.pop("integrity_regression", None)
                idea.status = IdeaStatus.READY
                self.workspace.save_idea(idea)
                self.memory.add_lesson(
                    idea.domain,
                    f"Idea '{idea.title}' reached paper-ready status via {idea.origin.value} origin",
                    idea.id,
                    confidence=0.8,
                )
            else:
                idea.metadata["integrity_regression"] = [
                    "Could not bind READY status to readable plan, paper, and result artifacts"
                ]
                idea.status = IdeaStatus.REVIEWED
                self.workspace.save_idea(idea)

        return idea, paper

    async def resume_pipeline(self, idea_id: str) -> tuple[Idea | None, Paper | None]:
        """Resume pipeline for an existing idea by ID."""
        idea = self.workspace.load_idea(idea_id)
        if not idea:
            return None, None
        return await self.run_pipeline(idea)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _new_session(self, mode: str, domain: str, seed_input: str) -> LabSession:
        session_id = str(uuid.uuid4())[:8]
        workspace = str(Path(self.config.workspace_root) / session_id)
        Path(workspace).mkdir(parents=True, exist_ok=True)
        return LabSession(
            id=session_id,
            mode=mode,
            domain=domain,
            seed_input=seed_input,
            workspace_dir=workspace,
        )

    def _save_session(self, session: LabSession):
        path = Path(session.workspace_dir) / "session.json"
        data = {
            "id": session.id,
            "mode": session.mode,
            "domain": session.domain,
            "seed_input": session.seed_input,
            "created_at": session.created_at,
            "ideas": [
                {
                    "id": i.id,
                    "title": i.title,
                    "origin": i.origin.value,
                    "status": i.status.value,
                    "novelty_score": i.novelty_score,
                    "feasibility_score": i.feasibility_score,
                    "phenomenon": i.phenomenon[:300],
                    "hypothesis": i.hypothesis[:300],
                    "proposed_method": i.proposed_method[:400],
                    "expected_contribution": i.expected_contribution[:300],
                    "kill_survived": i.kill_argument.survived if i.kill_argument else None,
                    "kill_argument": i.kill_argument.argument[:400] if i.kill_argument else None,
                    "kill_rebuttal": i.kill_argument.rebuttal[:400] if i.kill_argument else None,
                    "workspace": i.workspace_dir,
                    "id_full": i.id,
                }
                for i in session.ideas
            ],
            "phenomena": [
                {
                    "id": p.id,
                    "description": p.description,
                    "severity": p.severity,
                    "evidence": p.evidence[:3],
                    "unexplained_by": p.unexplained_by[:3],
                    "potential_causes": p.potential_causes[:3],
                }
                for p in session.phenomena
            ],
            "analogies": [
                {
                    "source_domain": a.source_domain,
                    "target_domain": a.target_domain,
                    "source_problem": a.source_problem,
                    "target_problem": a.target_problem,
                    "structural_similarity": a.structural_similarity,
                    "transfer_method": a.transfer_method,
                    "adaptation_required": a.adaptation_required,
                    "confidence": a.confidence,
                }
                for a in session.analogies
            ],
            "audit_trail": session.audit_trail,
        }
        safe_data = _redact_jsonish(data)
        atomic_write_json(path, safe_data)
        return safe_data

    async def _persist_session(self, session: LabSession) -> None:
        """Persist locally, then route the same session summary to active agentmemory."""
        import asyncio

        summary = self._save_session(session)
        try:
            await asyncio.to_thread(self.memory.save_to_agentmemory, summary)
        except Exception:
            # Local session persistence is authoritative; the memory adapter owns
            # its redacted outbox fallback and must never break the research run.
            return

    def _record_to_memory(self, idea: Idea, killed_at: str = ""):
        kill_reason = ""
        if idea.kill_argument and not idea.kill_argument.survived:
            kill_reason = idea.kill_argument.argument[:200]
        elif idea.metadata.get("killed_reason"):
            kill_reason = idea.metadata["killed_reason"]

        self.memory.record_idea(
            IdeaRecord(
                idea_id=idea.id,
                title=idea.title,
                domain=idea.domain,
                origin=idea.origin.value,
                phenomenon=idea.phenomenon[:200],
                hypothesis=idea.hypothesis[:200],
                novelty_score=idea.novelty_score,
                feasibility_score=idea.feasibility_score,
                final_status=idea.status.value,
                killed_at_phase=killed_at
                or ("kill_first" if idea.status == IdeaStatus.KILLED else ""),
                kill_reason=kill_reason,
            )
        )
