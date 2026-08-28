"""
Weiping Lab API — FastAPI backend for the Web UI.

Endpoints:
  POST /api/discover          → SSE stream of discovery progress + results
  POST /api/extend            → SSE stream
  POST /api/transfer          → SSE stream
  POST /api/pipeline/{id}     → SSE stream of pipeline progress
  POST /api/resume/{id}       → SSE stream
  GET  /api/ideas             → list all ideas
  GET  /api/sessions          → list recent sessions
  GET  /api/sessions/{id}     → get session detail
  GET  /api/ideas/{id}        → get idea detail
  GET  /api/health            → health check
"""

from __future__ import annotations
import asyncio
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent))

from lab.core.config import LabConfig
from lab.core.orchestrator import LabOrchestrator
from lab.core.progress import ProgressEvent, ProgressReporter, reporter_context
from lab.diagnostics import build_diagnostics, count_sessions
from lab.results.loader import ResultLoader
from lab.runtime import VERSION, is_sensitive_key, redact_public_text, safe_error

app = FastAPI(title="Weiping Lab API", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://127.0.0.1:5174"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_config = LabConfig()
_orchestrator: LabOrchestrator | None = None


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    _request: Request, error: RequestValidationError
) -> JSONResponse:
    """Return only structural validation metadata; never echo rejected input or context."""
    details = []
    for item in error.errors()[:32]:
        location = [
            component
            for component in item.get("loc", ())
            if isinstance(component, int)
            or (isinstance(component, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", component))
        ]
        error_type = item.get("type")
        if not isinstance(error_type, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", error_type):
            error_type = "validation_error"
        details.append(
            {
                "loc": location,
                "type": error_type,
                "msg": "Invalid request value",
            }
        )
    return JSONResponse(status_code=422, content={"detail": details})


def get_orchestrator() -> LabOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = LabOrchestrator(_config)
    return _orchestrator


# ── SSE helpers ───────────────────────────────────────────────────────────────


def sse(event: str, data: object) -> str:
    """Format a Server-Sent Event."""
    public_event = (
        re.sub(r"[^a-z0-9_-]", "", event.casefold()) or "message"
        if isinstance(event, str)
        else "message"
    )
    public_data = _public_payload(data)
    return (
        f"event: {public_event}\n"
        f"data: {json.dumps(public_data, ensure_ascii=False, allow_nan=False)}\n\n"
    )


def sse_progress(phase: str, step: str, detail: str = "") -> str:
    return sse(
        "progress",
        {
            "phase": phase,
            "step": step,
            "detail": detail,
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    )


def sse_error(msg: str) -> str:
    return sse("error", {"message": safe_error(msg)})


def sse_done(data: dict) -> str:
    return sse("done", data)


def _session_to_dict(session) -> dict:
    """Serialize a LabSession to JSON-safe dict."""
    payload = {
        "id": session.id,
        "mode": session.mode,
        "domain": session.domain,
        "created_at": session.created_at,
        "phenomena": [
            {
                "id": p.id,
                "description": p.description,
                "severity": p.severity,
                "evidence": p.evidence[:3],
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
                "confidence": a.confidence,
            }
            for a in session.analogies
        ],
        "ideas": [
            {
                "id": i.id,
                "title": i.title,
                "domain": i.domain,
                "origin": i.origin.value,
                "status": i.status.value,
                "phenomenon": i.phenomenon,
                "hypothesis": i.hypothesis,
                "proposed_method": i.proposed_method,
                "expected_contribution": i.expected_contribution,
                "novelty_score": i.novelty_score,
                "feasibility_score": i.feasibility_score,
                "workspace_ref": f"ideas/{i.id}" if i.workspace_dir else "",
                "kill_survived": i.kill_argument.survived if i.kill_argument else None,
                "kill_argument": i.kill_argument.argument[:300] if i.kill_argument else None,
                "kill_rebuttal": i.kill_argument.rebuttal[:300] if i.kill_argument else None,
            }
            for i in session.ideas
        ],
        "audit_trail": session.audit_trail,
    }
    return _public_payload(payload)


_PRIVATE_API_FIELDS = {"workspace", "workspace_dir", "workspace_root", "project_root"}
_DIAGNOSTIC_API_FIELDS = {
    "audit_trail",
    "bridge_error",
    "diagnostic",
    "diagnostics",
    "error",
    "errors",
    "exception",
    "model_call_traces",
    "provider_error",
    "provider_health",
    "traceback",
    "warning",
    "warnings",
}
_PUBLIC_MASK = "...redacted"
_SESSION_PHENOMENON_FIELDS = {
    "id",
    "description",
    "severity",
    "evidence",
    "potential_causes",
}
_SESSION_ANALOGY_FIELDS = {
    "source_domain",
    "target_domain",
    "source_problem",
    "target_problem",
    "structural_similarity",
    "confidence",
}
_SESSION_IDEA_FIELDS = {
    "id",
    "title",
    "domain",
    "origin",
    "status",
    "phenomenon",
    "hypothesis",
    "proposed_method",
    "expected_contribution",
    "novelty_score",
    "feasibility_score",
    "kill_survived",
    "kill_argument",
    "kill_rebuttal",
}


def _public_payload(
    value,
    *,
    _diagnostic: bool = False,
    _seen: set[int] | None = None,
    _depth: int = 0,
):
    """Project persisted state to an HTTP-safe representation without private runtime data."""
    if _depth > 64:
        return _PUBLIC_MASK
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return safe_error(value, limit=2_000) if _diagnostic else redact_public_text(value)

    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        return _PUBLIC_MASK
    if type(value) is dict:
        seen.add(identity)
        try:
            public = {}
            has_private_workspace = False
            for index, (key, item) in enumerate(value.items()):
                if not isinstance(key, str):
                    public[f"masked_field_{index}"] = _PUBLIC_MASK
                    continue
                public_key = key
                folded_key = public_key.casefold()
                if folded_key in _PRIVATE_API_FIELDS:
                    has_private_workspace = has_private_workspace or folded_key in {
                        "workspace",
                        "workspace_dir",
                    }
                    continue
                if (
                    not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", public_key)
                    or redact_public_text(public_key) != public_key
                    or is_sensitive_key(public_key)
                ):
                    masked_key = f"masked_field_{index}"
                    while masked_key in public:
                        masked_key += "_"
                    public[masked_key] = _PUBLIC_MASK
                    continue
                public[public_key] = _public_payload(
                    item,
                    _diagnostic=_diagnostic or folded_key in _DIAGNOSTIC_API_FIELDS,
                    _seen=seen,
                    _depth=_depth + 1,
                )
            if has_private_workspace:
                identifier = value.get("id")
                if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
                    public["workspace_ref"] = f"ideas/{identifier}"
            return public
        except Exception:
            return _PUBLIC_MASK
        finally:
            seen.discard(identity)
    if type(value) is list:
        seen.add(identity)
        try:
            return [
                _public_payload(
                    item,
                    _diagnostic=_diagnostic,
                    _seen=seen,
                    _depth=_depth + 1,
                )
                for item in value
            ]
        except Exception:
            return [_PUBLIC_MASK]
        finally:
            seen.discard(identity)
    return _PUBLIC_MASK


def _public_session_record(value: object) -> dict:
    """Allowlist the persisted session schema before exposing an untrusted JSON file."""
    if not isinstance(value, dict):
        return {}
    projected = {key: value[key] for key in ("id", "mode", "domain", "created_at") if key in value}
    projected["phenomena"] = _project_record_list(
        value.get("phenomena"), _SESSION_PHENOMENON_FIELDS
    )
    projected["analogies"] = _project_record_list(value.get("analogies"), _SESSION_ANALOGY_FIELDS)
    projected_ideas = _project_record_list(value.get("ideas"), _SESSION_IDEA_FIELDS)
    raw_ideas = (
        [item for item in value["ideas"] if isinstance(item, dict)]
        if isinstance(value.get("ideas"), list)
        else []
    )
    for raw, public in zip(raw_ideas, projected_ideas):
        if not isinstance(raw, dict):
            continue
        identifier = public.get("id")
        if (
            isinstance(identifier, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
            and any(raw.get(field) for field in ("workspace", "workspace_dir", "workspace_ref"))
        ):
            public["workspace_ref"] = f"ideas/{identifier}"
    projected["ideas"] = projected_ideas
    projected["audit_trail"] = _public_payload(value.get("audit_trail", []), _diagnostic=True)
    return _public_payload(projected)


def _project_record_list(value: object, fields: set[str]) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [
        {key: item[key] for key in fields if key in item}
        for item in value
        if isinstance(item, dict)
    ]


# ── Request models ────────────────────────────────────────────────────────────


class DiscoverRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=200)
    use_beam: bool = True


class ExtendRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=200)
    method: str = Field(min_length=1, max_length=20_000)
    results: str = Field(default="", max_length=20_000)
    limitations: str = Field(default="", max_length=20_000)
    n: int = Field(default=3, ge=1, le=10)


class TransferRequest(BaseModel):
    source_domain: str = Field(min_length=1, max_length=200)
    target_domain: str = Field(min_length=1, max_length=200)


# ── Streaming endpoints ───────────────────────────────────────────────────────


@app.post("/api/discover")
async def discover(req: DiscoverRequest):
    async def stream() -> AsyncGenerator[str, None]:
        events: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()

        # Per-request reporter — not global, avoids concurrent request interference
        reporter = ProgressReporter(verbose=True)
        reporter._callbacks = [lambda e: events.put_nowait(e)]

        yield sse_progress("start", f"Scanning {req.domain} for phenomena")

        async def run():
            try:
                with reporter_context(reporter):
                    orch = get_orchestrator()
                    session = await orch.discover(req.domain, use_beam=req.use_beam)
                await events.put(None)  # sentinel
                return session
            except Exception as e:
                await events.put(None)
                raise e

        task = asyncio.create_task(run())

        # Stream progress events while task runs
        while True:
            try:
                event = await asyncio.wait_for(events.get(), timeout=0.5)
                if event is None:
                    break
                yield sse_progress(event.phase, event.step, event.detail)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"  # SSE keepalive

        try:
            session = await task
            yield sse_done(_session_to_dict(session))
        except Exception as e:
            yield sse_error(safe_error(e))

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/extend")
async def extend(req: ExtendRequest):
    async def stream() -> AsyncGenerator[str, None]:
        yield sse_progress("start", f"Generating extension ideas for {req.domain}")
        try:
            orch = get_orchestrator()
            session = await orch.extend(req.domain, req.method, req.results, req.limitations, req.n)
            yield sse_done(_session_to_dict(session))
        except Exception as e:
            yield sse_error(safe_error(e))

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"}
    )


@app.post("/api/transfer")
async def transfer(req: TransferRequest):
    async def stream() -> AsyncGenerator[str, None]:
        yield sse_progress("start", f"Finding analogies: {req.source_domain} → {req.target_domain}")
        try:
            orch = get_orchestrator()
            session = await orch.transfer(req.source_domain, req.target_domain)
            yield sse_done(_session_to_dict(session))
        except Exception as e:
            yield sse_error(safe_error(e))

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"}
    )


@app.post("/api/pipeline/{idea_id}")
async def run_pipeline(idea_id: str):
    idea_id = _safe_prefix_id(idea_id)

    async def stream() -> AsyncGenerator[str, None]:
        orch = get_orchestrator()
        idea = orch.workspace.load_idea(idea_id)
        if not idea:
            yield sse_error("Idea not found")
            return

        stage = orch.workspace.get_pipeline_stage(idea)
        yield sse_progress("pipeline", f"Starting from stage: {stage}", f"idea: {idea.title[:60]}")

        if stage == "bridge_done":
            yield sse_error(
                "Waiting for experiments. Place results in experiments/results/ then resume."
            )
            return

        try:
            result_idea, paper = await orch.run_pipeline(idea)
            result = {
                "idea": {
                    "id": result_idea.id,
                    "title": result_idea.title,
                    "status": result_idea.status.value,
                },
                "paper": {
                    "title": paper.title,
                    "abstract": paper.abstract,
                    "review_scores": paper.review_scores,
                    "claim_audit_passed": paper.claim_audit_passed,
                }
                if paper
                else None,
            }
            yield sse_done(result)
        except Exception as e:
            yield sse_error(safe_error(e))

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"}
    )


@app.post("/api/resume/{idea_id}")
async def resume_pipeline(idea_id: str):
    idea_id = _safe_prefix_id(idea_id)

    async def stream() -> AsyncGenerator[str, None]:
        yield sse_progress("resume", f"Resuming pipeline: {idea_id}")
        try:
            orch = get_orchestrator()
            idea, paper = await orch.resume_pipeline(idea_id)
            if idea is None:
                yield sse_error("Idea not found")
                return
            yield sse_done(
                {
                    "idea": {"id": idea.id, "title": idea.title, "status": idea.status.value},
                    "paper": {"title": paper.title, "abstract": paper.abstract} if paper else None,
                }
            )
        except Exception as e:
            yield sse_error(safe_error(e))

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"}
    )


# ── Read endpoints ────────────────────────────────────────────────────────────


@app.get("/api/ideas")
async def list_ideas(domain: str = "", status: str = ""):
    orch = get_orchestrator()
    ideas = orch.workspace.list_ideas(status_filter=status or None)
    if domain:
        ideas = [i for i in ideas if domain.lower() in i.get("domain", "").lower()]
    return [_public_payload(idea) for idea in ideas]


@app.get("/api/ideas/{idea_id}")
async def get_idea(idea_id: str):
    idea_id = _safe_prefix_id(idea_id)
    orch = get_orchestrator()
    idea = orch.workspace.load_idea(idea_id)
    if not idea:
        raise HTTPException(404, "Idea not found")
    plan = orch.workspace.load_plan(idea)
    paper = orch.workspace.load_paper(idea)
    evidence = None
    if plan:
        loader = ResultLoader(idea.workspace_dir, _config)
        loader.load_into_plan(plan)
        evidence = loader.get_summary(plan)
    return _public_payload(
        {
            "id": idea.id,
            "title": idea.title,
            "domain": idea.domain,
            "origin": idea.origin.value,
            "status": idea.status.value,
            "phenomenon": idea.phenomenon,
            "hypothesis": idea.hypothesis,
            "proposed_method": idea.proposed_method,
            "expected_contribution": idea.expected_contribution,
            "novelty_score": idea.novelty_score,
            "feasibility_score": idea.feasibility_score,
            "workspace_ref": f"ideas/{idea.id}" if idea.workspace_dir else "",
            "stage": orch.workspace.get_pipeline_stage(idea),
            "kill_argument": {
                "argument": idea.kill_argument.argument,
                "rebuttal": idea.kill_argument.rebuttal,
                "survived": idea.kill_argument.survived,
                "closest_prior_work": idea.kill_argument.closest_prior_work,
            }
            if idea.kill_argument
            else None,
            "plan": {
                "blocks": len(plan.blocks),
                "approved": plan.approved,
                "audit_scores": plan.audit_scores,
                "milestone_gates": plan.milestone_gates,
            }
            if plan
            else None,
            "evidence": evidence,
            "paper": {
                "title": paper.title,
                "abstract": paper.abstract,
                "review_scores": paper.review_scores,
                "claim_audit_passed": paper.claim_audit_passed,
            }
            if paper
            else None,
        }
    )


@app.get("/api/sessions")
async def list_sessions():
    workspace = Path(_config.workspace_root)
    sessions = []
    for f in sorted(workspace.glob("*/session.json"), reverse=True)[:50]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            ideas = d.get("ideas", [])
            sessions.append(
                {
                    "id": d.get("id"),
                    "mode": d.get("mode"),
                    "domain": d.get("domain"),
                    "created_at": d.get("created_at"),
                    "ideas_count": len(ideas),
                    "surviving": sum(1 for i in ideas if i.get("kill_survived")),
                    # include counts for sidebar display
                    "phenomena_count": len(d.get("phenomena", [])),
                    "analogies_count": len(d.get("analogies", [])),
                }
            )
        except Exception:
            pass
    return _public_payload(sessions)


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    session_id = _safe_prefix_id(session_id)
    workspace = Path(_config.workspace_root)
    matches = list(workspace.glob(f"{session_id}*/session.json"))
    if not matches:
        raise HTTPException(404, "Session not found")
    return _public_session_record(json.loads(matches[0].read_text(encoding="utf-8")))


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": VERSION,
        "anthropic_key": bool(_config.anthropic_key),
        "workspace_available": Path(_config.workspace_root).exists(),
        "sessions": count_sessions(_config.workspace_root),
    }


@app.get("/api/status")
async def status():
    return build_diagnostics(_config)


def _safe_prefix_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise HTTPException(400, "Invalid id")
    return value
