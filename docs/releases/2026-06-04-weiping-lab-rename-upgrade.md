# WEIPING_LAB Rename Upgrade

Date: 2026-06-04

## Naming Migration

The public workbench is now named `WEIPING_LAB`. Human-facing prose may use
`Weiping Lab`; repository, path, and project-relationship examples should use
`WEIPING_LAB`.

The Python package name is `weiping-lab`. The CLI entry points remain `vlab` and
`vlab-api` so existing scripts do not need command rewrites.

Historical `vipin-lab` references are compatibility aliases only. Do not use
them in new docs, examples, or release artifacts unless explicitly documenting
backward compatibility.

## Environment Variables

New primary names:

```text
WEIPING_LAB_WORKSPACE_ROOT
WEIPING_LAB_ARCHITECT_MODEL
WEIPING_LAB_EXECUTOR_MODEL
WEIPING_LAB_AUDITOR_MODEL
WEIPING_LAB_SCREENER_MODEL
WEIPING_LAB_CONTEXT_FILE
WEIPING_LAB_RULES_FILE
WEIPING_WIKI_ROOT
```

Legacy fallback names remain accepted:

```text
VIPIN_LAB_WORKSPACE_ROOT
VIPIN_LAB_ARCHITECT_MODEL
VIPIN_LAB_EXECUTOR_MODEL
VIPIN_LAB_AUDITOR_MODEL
VIPIN_LAB_SCREENER_MODEL
VIPIN_LAB_CONTEXT_FILE
VIPIN_LAB_RULES_FILE
VIPIN_WIKI_ROOT
```

When both a primary and legacy name are set, the `WEIPING_*` value wins.

## Public Repository Boundary

`WEIPING_LAB` is the public research workbench distribution. `WEIPING_COUNCIL`
is the companion review/council layer when workflows need cross-agent critique.
Historical `vipin-council` references should be treated as compatibility aliases
for old notes, remotes, or local paths.

This rename does not change Git remotes, push targets, private credentials,
private endpoints, or local untracked `.env` files.

## Research Evidence Boundary

The rename is a product and packaging migration. It must not create, infer, or
upgrade scientific evidence.

Research claims still require the normal gates: experiment plans, real result
files, evidence labels, auto-review, citation audit, and claim audit. The bridge
phase still pauses until real experiments have run, and weak or missing evidence
must not be written as paper-level claims.
