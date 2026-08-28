# WEIPING_LAB Agent Instructions

`WEIPING_LAB` is an honest research workbench for phenomenon-driven discovery, kill-first ideation, experiment planning, evidence-gated writing, and audit support.

## Source Of Truth

Read `AGENTS.md`, `README.md`, `CLAUDE.md`, `pyproject.toml`, `lab/runtime.py`, `lab/core/config.py`, and `.codex/skills/weiping-lab/SKILL.md` before non-trivial work. The project skill is mandatory for implementation, release, maintenance, monitoring, or upgrade tasks.

## Boundaries

- Do not fabricate experiments, paper results, baselines, or citations.
- Do not treat bridge scaffolds as completed experiments.
- Keep config environment-driven; never add real keys, private endpoints, account names, or secret-shaped placeholders to tracked source.
- Keep `lab/workspace/` source tracked, but generated root `workspace/` content stays local/ignored.
- Use `agentmemory` through `AGENTMEMORY_URL` for active memory; local outbox fallback must be redacted.
- Preserve legacy `VIPIN_LAB_*` compatibility only as explicit fallbacks; new docs and variables should use `WEIPING_LAB_*`.
- Treat `experiments/results/*.json` as untrusted input. Preserve the v1.0 result contract,
  deterministic evidence classification, source digests, and claim-to-block links; an LLM or
  producer-supplied label must never promote evidence.

## WEIPING Constellation

`WEIPING_WIKI` is the public durable route map, not a runtime dependency. `WEIPING_COUNCIL` is the companion deliberation/review layer. Lab may consume council session artifacts, but it must not require council private state, local DBs, caches, `.env`, or active server processes to run its own verification.

Recurring WEIPING maintenance may inspect entry evidence, status commands, docs, and git state. It should not edit lab code, workspace outputs, datasets, experiment results, or generated artifacts unless the user explicitly scopes lab work.

Artifact handoffs are path-and-schema contracts, not shared runtime state. The main handoff files are `workspace/*/session.json`, `workspace/ideas/<idea_id>/idea.json`, `plan.json`, `paper.json`, `EXPERIMENT_PLAN.md`, `EXPERIMENT_TRACKER.md`, `experiments/results/*.json`, and redacted `agentmemory-outbox.jsonl`.
The result schema is documented in `docs/RESULT_CONTRACT.md`; bridge-generated workspaces include
a plan-specific copy and example.

Optional context inputs such as `WEIPING_LAB_CONTEXT_FILE`, `WEIPING_LAB_RULES_FILE`, and `WEIPING_WIKI_ROOT` may enrich prompts with maintained public-safe context. They are not required runtime dependencies.

## Validation

Before commit or release:

```powershell
python -m pytest -q
python scripts/run_ruff.py check lab cli api tests scripts
python scripts/run_ruff.py format --check lab cli api tests scripts
python scripts/release_scan.py
npm --prefix ui run lint
npm --prefix ui run build
npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org
git diff --check
```

On Windows, `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1` is the preferred full local gate.
