# WEIPING_LAB v1.6.0 — Evidence Integrity

This release makes experiment-to-paper handoff fail closed.

## Delivered

- Versioned result envelope with deterministic evidence classification and SHA-256 source
  provenance.
- Completeness, duplicate, identity, size, finite-number, baseline, metric, statistics, exact seed
  trace, immutable revision, and full config-digest checks.
- Persisted claim-to-block links and a deterministic empirical-claim gate that requires a current
  plan and exact canonical block IDs.
- Full-dimension enforcement for experiment-plan and paper-review rubrics.
- Persisted citation count enforcement independent of model output.
- Atomic, bounded, strict workspace and memory JSON checkpoints plus a READY artifact manifest that
  detects later plan, paper, or result mutation and rechecks review/citation state on resume.
- Structurally validated experiment bridge with 5–7 approved uniquely numbered blocks, rejection
  of definition-time Python payloads, block configs, a result template, and explicit
  `BRIDGE_STATUS.json`.
- PowerShell verification that exits non-zero when any Python or UI gate fails.

## Compatibility

Legacy result JSON still loads for diagnostic continuity, but it cannot qualify as
`paper_result`. Existing `VIPIN_LAB_*` environment aliases remain fallbacks. No external tracking
service, DVC repository, council process, or private state is required.

## Verification

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

No real experiment outcome is included or claimed by this release.
