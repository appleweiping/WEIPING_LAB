"""Validate experiment outputs before they can enter the writing pipeline.

The loader accepts a versioned envelope as well as the legacy flat JSON format.
Evidence labels are derived from observed metadata; a result file can downgrade
its own label, but it can never promote itself to ``paper_result``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.config import LabConfig
from ..core.models import EvidenceLabel, ExperimentBlock, ExperimentPlan, ExperimentStatus
from ..runtime import redact, safe_error


RESULT_SCHEMA_VERSION = "1.0"
MAX_RESULT_FILE_BYTES = 5 * 1024 * 1024
MAX_RESULT_FILES = 256
MAX_SEED_VALUES = 10_000
_BLOCK_FILE_RE = re.compile(r"(?:^|[_-])(?:block[_-]?)?(\d+)(?:[_-]|$)", re.I)
_LABEL_RANK = {
    EvidenceLabel.PILOT: 0,
    EvidenceLabel.DIAGNOSTIC: 1,
    EvidenceLabel.OFFICIAL: 2,
    EvidenceLabel.PAPER_RESULT: 3,
}
_PROVENANCE_FIELDS = ("code_revision", "dataset_version", "config_digest")
_CONFIG_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}", re.I)
_CODE_REVISION_RE = re.compile(r"(?:(?:git|sha256):)?[0-9a-f]{7,64}", re.I)
_PLACEHOLDER_PROVENANCE = {
    "changeme",
    "current",
    "default",
    "example",
    "latest",
    "n/a",
    "na",
    "none",
    "null",
    "todo",
    "unknown",
    "unset",
}
_OMIT = object()


class _SafeDiagnosticList(list[str]):
    """A list that sanitizes every untrusted diagnostic at insertion time."""

    def append(self, item: object) -> None:
        super().append(safe_error(item, limit=1_000))

    def extend(self, items) -> None:
        for item in items:
            self.append(item)


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


@dataclass(frozen=True)
class _ResultEntry:
    block_id: int
    results: dict[str, Any]
    provenance: dict[str, Any]
    requested_label: str
    schema_version: str
    source: Path
    source_sha256: str


@dataclass
class ResultLoadReport:
    """Machine-readable result-ingestion outcome."""

    expected_blocks: list[int]
    loaded_blocks: list[int] = field(default_factory=list)
    missing_blocks: list[int] = field(default_factory=list)
    invalid_blocks: dict[int, list[str]] = field(default_factory=dict)
    labels: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=_SafeDiagnosticList)

    @property
    def complete(self) -> bool:
        return (
            bool(self.expected_blocks)
            and len(self.loaded_blocks) == len(self.expected_blocks)
            and not self.missing_blocks
            and not self.invalid_blocks
        )

    @property
    def ready_for_writing(self) -> bool:
        return self.complete and EvidenceLabel.PAPER_RESULT.value in self.labels.values()

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "ready_for_writing": self.ready_for_writing,
            "expected_blocks": self.expected_blocks,
            "loaded_blocks": self.loaded_blocks,
            "missing_blocks": self.missing_blocks,
            "invalid_blocks": {
                block_id: [safe_error(issue, limit=1_000) for issue in issues]
                for block_id, issues in self.invalid_blocks.items()
            },
            "labels": self.labels,
            "warnings": [safe_error(warning, limit=1_000) for warning in self.warnings],
        }


class ResultLoader:
    """Load, validate, hash, and classify local result JSON files."""

    def __init__(self, workspace_dir: str, config: LabConfig | None = None):
        self.workspace = Path(workspace_dir)
        self.results_dir = self.workspace / "experiments" / "results"
        self.config = config or LabConfig()
        self.last_report: ResultLoadReport | None = None

    def load_into_plan(self, plan: ExperimentPlan) -> tuple[bool, list[str]]:
        """Load results and return ``(ready_for_writing, warnings)``.

        Writing is allowed only when every planned block has one unambiguous,
        structurally valid result and at least one block independently qualifies
        as ``paper_result`` evidence.
        """

        raw_block_ids = [block.id for block in plan.blocks]
        valid_block_ids = [
            block_id
            for block_id in raw_block_ids
            if not isinstance(block_id, bool)
            and isinstance(block_id, int)
            and 0 <= block_id < 10_000
        ]
        report = ResultLoadReport(expected_blocks=valid_block_ids)
        self.last_report = report
        # A persisted plan may contain stale successful state from an earlier
        # ingestion. Every load is a fresh classification of the source files.
        for block in plan.blocks:
            block.status = ExperimentStatus.PLANNED
            block.results = {}
            block.evidence_label = EvidenceLabel.PILOT
        if not plan.blocks:
            report.warnings.append("Experiment plan is empty; writing is blocked")
            return False, report.warnings
        if len(valid_block_ids) != len(raw_block_ids):
            report.warnings.append("Experiment plan contains invalid block IDs; writing is blocked")
            return False, report.warnings
        if len(set(report.expected_blocks)) != len(report.expected_blocks):
            report.warnings.append(
                "Experiment plan contains duplicate block IDs; writing is blocked"
            )
            return False, report.warnings
        if not self.results_dir.exists():
            report.missing_blocks = report.expected_blocks.copy()
            report.warnings.append(f"Results directory not found: {self.results_dir}")
            return False, report.warnings

        result_files = sorted(self.results_dir.glob("*.json"), key=lambda path: path.name.lower())
        if not result_files:
            report.missing_blocks = report.expected_blocks.copy()
            report.warnings.extend(
                [
                    f"Results directory exists but is empty: {self.results_dir}",
                    "Run experiments first, then place result JSON files here.",
                ]
            )
            return False, report.warnings
        if len(result_files) > MAX_RESULT_FILES:
            report.missing_blocks = report.expected_blocks.copy()
            report.warnings.append(
                f"Too many result files ({len(result_files)}; maximum {MAX_RESULT_FILES})"
            )
            return False, report.warnings

        entries: dict[int, list[_ResultEntry]] = {}
        expected = set(report.expected_blocks)
        for path in result_files:
            parsed_entries, warnings = self._read_file(path, plan)
            report.warnings.extend(warnings)
            for entry in parsed_entries:
                if entry.block_id not in expected:
                    report.warnings.append(
                        f"{path.name}: unknown block id {entry.block_id}; entry ignored"
                    )
                    continue
                entries.setdefault(entry.block_id, []).append(entry)

        for block in plan.blocks:
            matches = entries.get(block.id, [])
            if not matches:
                block.status = ExperimentStatus.PLANNED
                report.missing_blocks.append(block.id)
                report.warnings.append(f"Block {block.id} ({block.name}): no usable result found")
                continue
            if len(matches) > 1:
                block.status = ExperimentStatus.FAILED
                sources = ", ".join(entry.source.name for entry in matches)
                issue = f"ambiguous duplicate results in {sources}"
                report.invalid_blocks[block.id] = [issue]
                report.warnings.append(f"Block {block.id}: {issue}")
                continue

            entry = matches[0]
            results, label, issues, notes = self._validate_entry(block, entry)
            report.warnings.extend(f"Block {block.id}: {note}" for note in notes)
            if issues:
                block.status = ExperimentStatus.FAILED
                block.evidence_label = EvidenceLabel.PILOT
                report.invalid_blocks[block.id] = issues
                report.warnings.extend(f"Block {block.id}: {issue}" for issue in issues)
                continue

            block.results = results
            block.evidence_label = label
            block.status = ExperimentStatus.DONE
            report.loaded_blocks.append(block.id)
            report.labels[block.id] = label.value

        if report.complete and EvidenceLabel.PAPER_RESULT.value not in report.labels.values():
            report.warnings.append(
                "All blocks loaded, but none meets the deterministic paper_result contract"
            )
        return report.ready_for_writing, report.warnings

    def _read_file(self, path: Path, plan: ExperimentPlan) -> tuple[list[_ResultEntry], list[str]]:
        warnings: list[str] = []
        try:
            resolved = path.resolve(strict=True)
            workspace_root = self.workspace.resolve(strict=False)
            if not resolved.is_relative_to(workspace_root):
                return [], [f"{path.name}: result file resolves outside the workspace"]
            if not resolved.is_file():
                return [], [f"{path.name}: result path is not a regular file"]
            size = resolved.stat().st_size
        except (OSError, RuntimeError) as exc:
            return [], [f"{path.name}: cannot stat result file: {redact(str(exc))}"]
        if size > MAX_RESULT_FILE_BYTES:
            return [], [
                f"{path.name}: result file is {size} bytes; maximum is {MAX_RESULT_FILE_BYTES}"
            ]

        try:
            raw = resolved.read_bytes()
            if len(raw) > MAX_RESULT_FILE_BYTES:
                return [], [
                    f"{path.name}: result file changed while reading and exceeds "
                    f"{MAX_RESULT_FILE_BYTES} bytes"
                ]
            data = json.loads(raw.decode("utf-8"), parse_constant=_reject_nonfinite_json)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            return [], [f"{path.name}: invalid UTF-8 JSON: {redact(str(exc))}"]
        if not isinstance(data, dict):
            return [], [f"{path.name}: top-level JSON value must be an object"]

        declared_idea = data.get("idea_id")
        if declared_idea is not None and str(declared_idea) != plan.idea_id:
            return [], [
                f"{path.name}: idea_id {declared_idea!r} does not match plan {plan.idea_id!r}"
            ]

        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        schema_version = str(data.get("schema_version", "legacy"))
        if schema_version not in {"legacy", RESULT_SCHEMA_VERSION}:
            return [], [
                f"{path.name}: unsupported schema_version {schema_version!r}; "
                f"expected {RESULT_SCHEMA_VERSION!r}"
            ]
        if schema_version == "legacy":
            warnings.append(
                f"{path.name}: legacy result format accepted; add schema_version and provenance"
            )

        inherited_provenance = self._as_dict(data.get("provenance"))
        if "blocks" in data:
            raw_blocks = data["blocks"]
            if not isinstance(raw_blocks, list):
                return [], [f"{path.name}: blocks must be an array"]
            entries: list[_ResultEntry] = []
            for index, item in enumerate(raw_blocks):
                if not isinstance(item, dict):
                    warnings.append(f"{path.name}: blocks[{index}] must be an object")
                    continue
                entry, issue = self._entry_from_mapping(
                    item,
                    path,
                    digest,
                    schema_version,
                    inherited_provenance,
                )
                if issue:
                    warnings.append(f"{path.name}: blocks[{index}] {issue}")
                elif entry:
                    entries.append(entry)
            return entries, warnings

        inferred_id = self._coerce_block_id(data.get("block_id", data.get("id")))
        if inferred_id is None:
            inferred_id = self._block_id_from_filename(path)
        if inferred_id is None and len(plan.blocks) == 1:
            inferred_id = plan.blocks[0].id
        if inferred_id is None:
            return [], warnings + [
                f"{path.name}: block_id is required when a plan has multiple blocks"
            ]

        item = dict(data)
        item["block_id"] = inferred_id
        entry, issue = self._entry_from_mapping(
            item,
            path,
            digest,
            schema_version,
            inherited_provenance,
        )
        if issue:
            warnings.append(f"{path.name}: {issue}")
        return ([entry] if entry else []), warnings

    def _entry_from_mapping(
        self,
        item: dict[str, Any],
        path: Path,
        digest: str,
        schema_version: str,
        inherited_provenance: dict[str, Any],
    ) -> tuple[_ResultEntry | None, str]:
        block_id = self._coerce_block_id(item.get("block_id", item.get("id")))
        if block_id is None:
            return None, "has no valid integer block_id"

        if "results" in item:
            results = item["results"]
        else:
            envelope_keys = {
                "schema_version",
                "idea_id",
                "block_id",
                "id",
                "provenance",
                "_evidence_label",
            }
            results = {key: value for key, value in item.items() if key not in envelope_keys}
        if not isinstance(results, dict):
            return None, "results must be an object"

        provenance = dict(inherited_provenance)
        provenance.update(self._as_dict(item.get("provenance")))
        provenance.update(self._as_dict(results.get("_provenance")))
        requested_label = str(item.get("_evidence_label", results.get("_evidence_label", "")) or "")
        return (
            _ResultEntry(
                block_id=block_id,
                results=dict(results),
                provenance=provenance,
                requested_label=requested_label,
                schema_version=schema_version,
                source=path,
                source_sha256=digest,
            ),
            "",
        )

    def _validate_entry(
        self, block: ExperimentBlock, entry: _ResultEntry
    ) -> tuple[dict[str, Any], EvidenceLabel, list[str], list[str]]:
        issues: list[str] = []
        notes: list[str] = []
        results = dict(entry.results)
        public_results = {
            key: value for key, value in results.items() if not str(key).startswith("_")
        }
        if not public_results:
            issues.append(f"{entry.source.name}: results object contains no result values")
            return results, EvidenceLabel.PILOT, issues, notes

        declared_seeds = self._positive_int(results.get("seeds_used", results.get("n_seeds")))
        seed_values = entry.provenance.get("seed_values", results.get("seed_values"))
        unique_seeds = self._unique_seed_count(seed_values)
        if seed_values is not None and unique_seeds is None:
            notes.append("seed_values must be a list of scalar seed identifiers")
        if (
            declared_seeds is not None
            and unique_seeds is not None
            and declared_seeds != unique_seeds
        ):
            notes.append(
                f"declared seeds_used={declared_seeds} but provenance has {unique_seeds} unique seeds"
            )
        if declared_seeds is None:
            effective_seeds = unique_seeds or 0
        elif unique_seeds is None:
            effective_seeds = declared_seeds
        else:
            effective_seeds = min(declared_seeds, unique_seeds)

        actual_baselines = self._observed_names(results.get("baselines"))
        planned_baselines = self._names(block.baselines)
        baseline_coverage = bool(planned_baselines) and planned_baselines.issubset(actual_baselines)

        actual_metrics = self._metric_names(results)
        planned_metrics = self._names(block.primary_metrics)
        metric_coverage = bool(planned_metrics) and planned_metrics.issubset(actual_metrics)

        statistics = self._as_dict(results.get("statistics"))
        p_value = statistics.get("p_value", results.get("p_value"))
        confidence_interval = statistics.get(
            "confidence_interval", results.get("confidence_interval")
        )
        has_valid_p = self._valid_p_value(p_value)
        has_valid_ci = self._valid_confidence_interval(confidence_interval)
        has_statistics = has_valid_p or has_valid_ci
        effect_size = statistics.get("effect_size", results.get("effect_size"))
        has_effect_size = self._finite_number(effect_size)
        fair_comparison = results.get("fair_comparison") is True
        provenance_complete = self._valid_provenance(entry.provenance)
        seed_trace_complete = (
            unique_seeds is not None and unique_seeds >= self.config.min_seeds_paper
        )
        seed_count_match = (
            declared_seeds is not None
            and unique_seeds is not None
            and declared_seeds == unique_seeds
        )

        paper_checks = {
            "schema_version": entry.schema_version == RESULT_SCHEMA_VERSION,
            "seeds": effective_seeds >= self.config.min_seeds_paper,
            "seed_trace": seed_trace_complete,
            "seed_count_match": seed_count_match,
            "statistics": has_statistics,
            "effect_size": has_effect_size,
            "baseline_count": len(actual_baselines) >= self.config.min_baselines,
            "baseline_coverage": baseline_coverage,
            "primary_metric_coverage": metric_coverage,
            "fair_comparison": fair_comparison,
            "provenance": provenance_complete,
        }
        if all(paper_checks.values()):
            computed = EvidenceLabel.PAPER_RESULT
        elif effective_seeds >= self.config.min_seeds_paper and has_statistics:
            computed = EvidenceLabel.OFFICIAL
        elif effective_seeds >= self.config.min_seeds_diagnostic:
            computed = EvidenceLabel.DIAGNOSTIC
        else:
            computed = EvidenceLabel.PILOT

        label = computed
        if entry.requested_label:
            try:
                requested = EvidenceLabel(entry.requested_label)
            except ValueError:
                notes.append(f"unknown requested evidence label {entry.requested_label!r} ignored")
            else:
                if _LABEL_RANK[requested] < _LABEL_RANK[computed]:
                    label = requested
                    notes.append(f"result author downgraded evidence to {requested.value}")
                elif _LABEL_RANK[requested] > _LABEL_RANK[computed]:
                    notes.append(
                        f"requested label {requested.value} cannot override computed {computed.value}"
                    )

        safe_provenance = {
            key: redact(str(value))[:256]
            for key, value in entry.provenance.items()
            if key in {*_PROVENANCE_FIELDS, "command", "generated_at"} and value is not None
        }
        if isinstance(seed_values, list):
            safe_provenance["seed_values"] = [
                value
                if isinstance(value, int) and not isinstance(value, bool)
                else redact(value)[:128]
                for value in seed_values[: self.config.min_seeds_paper * 10]
                if (isinstance(value, int) and not isinstance(value, bool))
                or isinstance(value, str)
            ]
        results["_weiping_validation"] = {
            "schema_version": entry.schema_version,
            "source_file": safe_error(entry.source.name, limit=256),
            "source_sha256": entry.source_sha256,
            "computed_label": computed.value,
            "effective_label": label.value,
            "effective_seeds": effective_seeds,
            "baseline_count": len(actual_baselines),
            "checks": paper_checks,
            "provenance": safe_provenance,
        }
        return results, label, issues, notes

    def get_summary(self, plan: ExperimentPlan) -> dict[str, Any]:
        """Return persisted evidence state, plus the latest ingestion report when available."""

        summary: dict[str, Any] = {
            "total_blocks": len(plan.blocks),
            "blocks_with_results": sum(1 for block in plan.blocks if block.results),
            "paper_result_blocks": sum(
                1 for block in plan.blocks if block.evidence_label == EvidenceLabel.PAPER_RESULT
            ),
            "ready_for_writing": bool(plan.blocks)
            and all(block.results for block in plan.blocks)
            and any(block.evidence_label == EvidenceLabel.PAPER_RESULT for block in plan.blocks),
            "by_label": {},
        }
        for label in EvidenceLabel:
            count = sum(1 for block in plan.blocks if block.evidence_label == label)
            if count:
                summary["by_label"][label.value] = count
        if self.last_report:
            summary["ingestion"] = self.last_report.to_dict()
        return summary

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, dict) else {}

    @staticmethod
    def _coerce_block_id(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and 0 <= value < 10_000:
            return value
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,4}", value):
            return int(value)
        return None

    @staticmethod
    def _block_id_from_filename(path: Path) -> int | None:
        if path.stem.isdigit():
            return ResultLoader._coerce_block_id(path.stem)
        match = _BLOCK_FILE_RE.search(path.stem)
        return ResultLoader._coerce_block_id(match.group(1)) if match else None

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, float) and value.is_integer() and value >= 0:
            return int(value)
        return None

    @staticmethod
    def _unique_seed_count(value: Any) -> int | None:
        if not isinstance(value, list) or len(value) > MAX_SEED_VALUES:
            return None
        normalized: set[str] = set()
        for item in value:
            if isinstance(item, bool):
                return None
            if isinstance(item, int):
                normalized.add(str(item))
                continue
            if isinstance(item, str):
                candidate = item.strip()
                if not candidate or len(candidate) > 128:
                    return None
                normalized.add(candidate)
                continue
            return None
        return len(normalized)

    @staticmethod
    def _valid_provenance(provenance: dict[str, Any]) -> bool:
        revision = provenance.get("code_revision")
        dataset = provenance.get("dataset_version")
        config_digest = provenance.get("config_digest")
        if not all(isinstance(value, str) for value in (revision, dataset, config_digest)):
            return False
        revision = revision.strip()
        dataset = dataset.strip()
        config_digest = config_digest.strip()
        if not revision or not dataset or not config_digest:
            return False
        if any(
            value.lower() in _PLACEHOLDER_PROVENANCE or value.lower().startswith("replace-with-")
            for value in (revision, dataset, config_digest)
        ):
            return False
        return (
            len(dataset) <= 256
            and _CODE_REVISION_RE.fullmatch(revision) is not None
            and _CONFIG_DIGEST_RE.fullmatch(config_digest) is not None
        )

    @staticmethod
    def _normalized_name(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value).lower())

    @classmethod
    def _names(cls, value: Any) -> set[str]:
        if isinstance(value, dict):
            values = value.keys()
        elif isinstance(value, (list, tuple, set)):
            values = value
        else:
            return set()
        return {name for item in values if (name := cls._normalized_name(item))}

    @classmethod
    def _metric_names(cls, results: dict[str, Any]) -> set[str]:
        for key in ("metrics", "primary_metrics"):
            names = cls._observed_names(results.get(key))
            if names:
                return names
        ignored = {
            "baselines",
            "statistics",
            "seeds_used",
            "n_seeds",
            "seed_values",
            "fair_comparison",
        }
        return {
            cls._normalized_name(key)
            for key, value in results.items()
            if key not in ignored and not str(key).startswith("_") and cls._finite_number(value)
        }

    @classmethod
    def _observed_names(cls, value: Any) -> set[str]:
        if not isinstance(value, dict):
            return set()
        return {
            name
            for key, observation in value.items()
            if (name := cls._normalized_name(key)) and cls._contains_finite_number(observation)
        }

    @classmethod
    def _contains_finite_number(cls, value: Any) -> bool:
        pending = [value]
        visited_containers: set[int] = set()
        inspected = 0
        while pending and inspected < 100_000:
            current = pending.pop()
            inspected += 1
            if cls._finite_number(current):
                return True
            if isinstance(current, dict):
                identity = id(current)
                if identity not in visited_containers:
                    visited_containers.add(identity)
                    pending.extend(current.values())
            elif isinstance(current, (list, tuple)):
                identity = id(current)
                if identity not in visited_containers:
                    visited_containers.add(identity)
                    pending.extend(current)
        return False

    @staticmethod
    def _finite_number(value: Any) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            return math.isfinite(value)
        except (OverflowError, TypeError, ValueError):
            return False

    @classmethod
    def _valid_p_value(cls, value: Any) -> bool:
        if not cls._finite_number(value):
            return False
        try:
            return 0.0 <= float(value) <= 1.0
        except (OverflowError, TypeError, ValueError):
            return False

    @classmethod
    def _valid_confidence_interval(cls, value: Any) -> bool:
        return (
            isinstance(value, (list, tuple))
            and len(value) == 2
            and cls._finite_number(value[0])
            and cls._finite_number(value[1])
            and float(value[0]) <= float(value[1])
        )


def evidence_prompt_view(results: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded numeric-only view of untrusted results for LLM prompts."""

    projected: dict[str, Any] = {}
    inspected = [0]
    for key, value in results.items():
        if str(key).startswith("_"):
            continue
        safe_value = _numeric_projection(value, depth=0, inspected=inspected)
        if safe_value is not _OMIT:
            projected[str(key)[:128]] = safe_value
        if inspected[0] >= 2_000 or len(projected) >= 100:
            break
    return projected


def _numeric_projection(value: Any, *, depth: int, inspected: list[int]) -> Any:
    inspected[0] += 1
    if inspected[0] > 2_000 or depth > 6:
        return _OMIT
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        try:
            return value if math.isfinite(value) else _OMIT
        except (OverflowError, TypeError, ValueError):
            return _OMIT
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:100]:
            projected = _numeric_projection(item, depth=depth + 1, inspected=inspected)
            if projected is not _OMIT:
                output[str(key)[:128]] = projected
        return output if output else _OMIT
    if isinstance(value, (list, tuple)):
        output = []
        for item in list(value)[:100]:
            projected = _numeric_projection(item, depth=depth + 1, inspected=inspected)
            if projected is not _OMIT:
                output.append(projected)
        return output if output else _OMIT
    return _OMIT
