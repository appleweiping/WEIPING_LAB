"""
Memory Layer — cross-session learning and institutional knowledge.

Inspired by AgentLaboratory's AgentRxiv: agents build on prior work.
"""

from __future__ import annotations
import dataclasses
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lab.runtime import endpoint_host, is_sensitive_key, redact, redact_public_text, safe_error
from lab.storage import atomic_write_json


@dataclass
class IdeaRecord:
    idea_id: str
    title: str
    domain: str
    origin: str
    phenomenon: str
    hypothesis: str
    novelty_score: float
    feasibility_score: float
    final_status: str  # killed / refined / planned / ready
    killed_at_phase: str  # which phase killed it
    kill_reason: str  # why it was killed
    paper_title: str = ""  # if it made it to paper
    created_at: str = field(default_factory=lambda: _utc_now())


@dataclass
class PhenomenonRecord:
    phenomenon_id: str
    domain: str
    description: str
    severity: float
    led_to_ideas: list[str]  # idea IDs generated from this phenomenon
    successful_ideas: list[str]  # ideas that made it to paper
    created_at: str = field(default_factory=lambda: _utc_now())


@dataclass
class DomainLesson:
    domain: str
    lesson: str  # what was learned
    evidence: str  # which idea/experiment showed this
    confidence: float  # 0-1
    created_at: str = field(default_factory=lambda: _utc_now())


class LabMemory:
    """Persistent cross-session memory for the lab."""

    def __init__(self, memory_dir: str):
        self.dir = Path(memory_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._ideas_file = self.dir / "ideas.json"
        self._phenomena_file = self.dir / "phenomena.json"
        self._lessons_file = self.dir / "lessons.json"
        self._ideas: list[IdeaRecord] = self._load(self._ideas_file, IdeaRecord)
        self._phenomena: list[PhenomenonRecord] = self._load(self._phenomena_file, PhenomenonRecord)
        self._lessons: list[DomainLesson] = self._load(self._lessons_file, DomainLesson)

    # ── Write ─────────────────────────────────────────────────────────────────

    def record_idea(self, record: IdeaRecord):
        # Update if exists, else append
        for i, r in enumerate(self._ideas):
            if r.idea_id == record.idea_id:
                self._ideas[i] = record
                self._save(self._ideas_file, self._ideas)
                return
        self._ideas.append(record)
        self._save(self._ideas_file, self._ideas)

    def record_phenomenon(self, record: PhenomenonRecord):
        for i, r in enumerate(self._phenomena):
            if r.phenomenon_id == record.phenomenon_id:
                self._phenomena[i] = record
                self._save(self._phenomena_file, self._phenomena)
                return
        self._phenomena.append(record)
        self._save(self._phenomena_file, self._phenomena)

    def add_lesson(self, domain: str, lesson: str, evidence: str, confidence: float = 0.7):
        self._lessons.append(
            DomainLesson(domain=domain, lesson=lesson, evidence=evidence, confidence=confidence)
        )
        self._save(self._lessons_file, self._lessons)

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_domain_lessons(self, domain: str, min_confidence: float = 0.5) -> list[str]:
        """Get lessons relevant to a domain."""
        return [
            lesson.lesson
            for lesson in self._lessons
            if (domain.lower() in lesson.domain.lower() or lesson.domain.lower() in domain.lower())
            and lesson.confidence >= min_confidence
        ]

    def get_kill_patterns(self, domain: str) -> list[str]:
        """What types of ideas consistently get killed in this domain?"""
        killed = [
            r
            for r in self._ideas
            if r.final_status == "killed" and domain.lower() in r.domain.lower()
        ]
        if not killed:
            return []
        reasons = [r.kill_reason for r in killed if r.kill_reason]
        return reasons[:5]

    def get_successful_phenomena(self, domain: str) -> list[str]:
        """Which phenomena led to successful papers in this domain?"""
        successful = []
        for p in self._phenomena:
            if domain.lower() in p.domain.lower() and p.successful_ideas:
                successful.append(p.description)
        return successful[:5]

    def get_prior_ideas(self, domain: str, limit: int = 10) -> list[dict]:
        """Get prior ideas in this domain for context."""
        relevant = [r for r in self._ideas if domain.lower() in r.domain.lower()]
        relevant.sort(key=lambda x: x.novelty_score, reverse=True)
        return [
            {
                "title": r.title,
                "hypothesis": r.hypothesis[:100],
                "status": r.final_status,
                "novelty": r.novelty_score,
            }
            for r in relevant[:limit]
        ]

    def format_context_for_prompt(self, domain: str) -> str:
        """Format memory as context for LLM prompts."""
        lines = []
        lessons = self.get_domain_lessons(domain)
        if lessons:
            lines.append(f"Domain lessons for {domain}:")
            for lesson in lessons[:3]:
                lines.append(f"  - {lesson}")

        kill_patterns = self.get_kill_patterns(domain)
        if kill_patterns:
            lines.append(f"\nIdeas that consistently fail in {domain}:")
            for k in kill_patterns[:3]:
                lines.append(f"  - {k}")

        prior = self.get_prior_ideas(domain, limit=5)
        if prior:
            lines.append(f"\nPrior ideas explored in {domain}:")
            for p in prior:
                lines.append(f"  - [{p['status']}] {p['title']}: {p['hypothesis']}")

        return "\n".join(lines) if lines else ""

    def stats(self) -> dict:
        return {
            "total_ideas": len(self._ideas),
            "survived_kill": sum(1 for r in self._ideas if r.final_status != "killed"),
            "reached_paper": sum(1 for r in self._ideas if r.final_status == "ready"),
            "total_phenomena": len(self._phenomena),
            "total_lessons": len(self._lessons),
            "domains": list({r.domain for r in self._ideas}),
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self, path: Path, record_type):
        if not path.exists():
            return []
        try:
            raw = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=_reject_nonfinite_json,
            )
            records = []
            for item in raw if isinstance(raw, list) else []:
                if dataclasses.is_dataclass(item):
                    records.append(item)
                elif isinstance(item, dict):
                    try:
                        record = record_type(**item)
                        if _safe_memory_record(record):
                            records.append(record)
                    except TypeError:
                        continue
            return records
        except (json.JSONDecodeError, OSError, RecursionError, ValueError):
            return []

    def _save(self, path: Path, data: list):
        records = [dataclasses.asdict(d) if dataclasses.is_dataclass(d) else d for d in data]
        atomic_write_json(
            path,
            _redact_jsonish(records),
        )

    def save_to_agentmemory(self, session_summary: dict) -> bool:
        """Post a session summary to active agentmemory, with a local outbox fallback."""
        import asyncio
        import os

        import httpx

        agentmemory_url = os.environ.get("AGENTMEMORY_URL", "http://localhost:3111")
        safe_summary = _redact_jsonish(session_summary)
        try:

            async def _post():
                async with httpx.AsyncClient(timeout=5.0) as c:
                    r = await c.post(
                        f"{agentmemory_url}/observations",
                        json={
                            "content": json.dumps(safe_summary, ensure_ascii=False, default=str),
                            "type": "vlab_session",
                        },
                    )
                    return r.status_code

            status_code = asyncio.run(_post())
            if status_code < 300:
                return True
            error = f"agentmemory HTTP {status_code}"
        except Exception as exc:
            error = safe_error(exc)

        return self._write_agentmemory_outbox(agentmemory_url, error, safe_summary)

    def _write_agentmemory_outbox(
        self, agentmemory_url: str, error: str, safe_summary: object
    ) -> bool:
        try:
            outbox = self.dir / "agentmemory-outbox.jsonl"
            payload = {
                "type": "vlab_session",
                "agentmemory_endpoint": endpoint_host(agentmemory_url),
                "agentmemory_error": safe_error(error),
                "content": _redact_jsonish(safe_summary),
                "created_at": _utc_now(),
            }
            with outbox.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
            return True
        except Exception:
            return False


_SAFE_MASK = "...redacted"
_MAX_SAFE_DEPTH = 64
_DIAGNOSTIC_MEMORY_KEYS = {
    "bridgeerror",
    "diagnostic",
    "diagnostics",
    "error",
    "errors",
    "exception",
    "modelcalltraces",
    "providererror",
    "providerhealth",
    "traceback",
    "warning",
    "warnings",
}


def _redact_jsonish(
    value,
    *,
    _seen: set[int] | None = None,
    _depth: int = 0,
    _diagnostic: bool = False,
):
    """Recursively make JSON-like, potentially cyclic input safe to persist.

    Values below a sensitive mapping key are replaced without inspecting or
    stringifying them. Unknown object types also fail closed instead of relying
    on a potentially secret-bearing ``repr`` or ``__str__`` implementation.
    """
    if _depth > _MAX_SAFE_DEPTH:
        return _SAFE_MASK
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return safe_error(value, limit=2_000) if _diagnostic else redact_public_text(value)
    if isinstance(value, Path):
        return redact(str(value))
    if isinstance(value, datetime):
        return value.isoformat()

    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        return _SAFE_MASK

    if isinstance(value, Mapping):
        seen.add(identity)
        try:
            safe: dict[str, object] = {}
            for index, (raw_key, item) in enumerate(value.items()):
                key, key_is_sensitive = _safe_jsonish_key(raw_key, index)
                folded_key = (
                    "".join(character for character in raw_key.casefold() if character.isalnum())
                    if isinstance(raw_key, str)
                    else ""
                )
                safe[key] = (
                    _SAFE_MASK
                    if key_is_sensitive
                    else _redact_jsonish(
                        item,
                        _seen=seen,
                        _depth=_depth + 1,
                        _diagnostic=_diagnostic or folded_key in _DIAGNOSTIC_MEMORY_KEYS,
                    )
                )
            return safe
        except Exception:
            return _SAFE_MASK
        finally:
            seen.discard(identity)

    if isinstance(value, (list, tuple)):
        seen.add(identity)
        try:
            return [
                _redact_jsonish(
                    item,
                    _seen=seen,
                    _depth=_depth + 1,
                    _diagnostic=_diagnostic,
                )
                for item in value
            ]
        except Exception:
            return [_SAFE_MASK]
        finally:
            seen.discard(identity)

    return _SAFE_MASK


def _safe_jsonish_key(value: object, index: int) -> tuple[str, bool]:
    if isinstance(value, str):
        text = value
    elif value is None or isinstance(value, (bool, int, float)):
        text = str(value)
    else:
        return f"field_{index}", True
    sensitive = is_sensitive_key(text)
    public = redact_public_text(text)
    if public != text or not all(character.isalnum() or character in "_.-" for character in text):
        return f"field_{index}", sensitive
    return public, sensitive


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _safe_memory_record(record: object) -> bool:
    if isinstance(record, IdeaRecord):
        strings = (
            record.idea_id,
            record.title,
            record.domain,
            record.origin,
            record.phenomenon,
            record.hypothesis,
            record.final_status,
            record.killed_at_phase,
            record.kill_reason,
            record.paper_title,
            record.created_at,
        )
        numbers = (record.novelty_score, record.feasibility_score)
        return all(isinstance(item, str) for item in strings) and all(
            isinstance(item, (int, float)) and not isinstance(item, bool) and math.isfinite(item)
            for item in numbers
        )
    if isinstance(record, PhenomenonRecord):
        return (
            all(
                isinstance(item, str)
                for item in (
                    record.phenomenon_id,
                    record.domain,
                    record.description,
                    record.created_at,
                )
            )
            and isinstance(record.severity, (int, float))
            and not isinstance(record.severity, bool)
            and math.isfinite(record.severity)
            and all(isinstance(item, str) for item in record.led_to_ideas)
            and all(isinstance(item, str) for item in record.successful_ideas)
        )
    if isinstance(record, DomainLesson):
        return (
            all(
                isinstance(item, str)
                for item in (record.domain, record.lesson, record.evidence, record.created_at)
            )
            and isinstance(record.confidence, (int, float))
            and not isinstance(record.confidence, bool)
            and math.isfinite(record.confidence)
        )
    return False
