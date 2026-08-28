# CLAUDE.md - WEIPING_LAB

Weiping Lab is an autonomous research workbench. Treat it as software that assists research, not as an authority that can invent evidence.

## Session Start

1. Run agentmemory recall for the current task when past context matters.
2. Read the smallest relevant project files for current truth: `AGENTS.md`, `README.md`, `pyproject.toml`, `lab/runtime.py`, `lab/core/config.py`, and the files you will edit.
3. Run `git status --short --branch`.
4. For non-trivial work, follow `.codex/skills/weiping-lab/SKILL.md`. An external shared
   resource may be consulted only through an explicitly configured `AGENT_RESOURCE_ROOT`;
   it is never required for startup, verification, or release.

Do not depend on retired mailbox or old markdown session systems. Stable public-safe knowledge belongs in project docs or the maintained wiki; local runtime observations belong in active agentmemory or the workspace outbox.

## Identity

- Name: `vlab`
- Role: phenomenon-driven research discovery, kill-first ideation, experiment planning, evidence-gated paper writing, and audit support
- Runtime memory: active agentmemory via `AGENTMEMORY_URL`
- Local fallback: redacted `agentmemory-outbox.jsonl` under the configured workspace memory directory
- Workspace: `WEIPING_LAB_WORKSPACE_ROOT` or `./workspace`; legacy `VIPIN_LAB_WORKSPACE_ROOT` remains a fallback

Never store API keys, bearer tokens, account secrets, raw private logs, or private documents in memory or tracked source.

## Quick Start

```bash
cd WEIPING_LAB
python -m pip install -e ".[dev]"
copy .env.example .env

vlab status --json
uvicorn api.server:app --reload --port 8001
npm --prefix ui run dev
```

Common commands:

```bash
vlab discover "LLM4Rec"
vlab extend "LLM4Rec" --method "..." --results "..." --limits "..."
vlab transfer "conformal prediction" "LLM4Rec"
vlab pipeline <idea_id>
vlab resume <idea_id>
vlab ideas
vlab sessions
vlab show <session_id>
python scripts/release_scan.py
```

## Architecture

```text
lab/
  core/
    models.py          data types
    config.py          model roles, thresholds, env sources
    orchestrator.py    discovery modes, pipeline, resume logic
    progress.py        streaming progress reporter
  engines/
    phenomenon.py      literature anomaly scanning
    analogy.py         structural cross-domain transfer
    kill_first.py      adversarial idea evaluation
    evidence.py        evidence labels and audit
    anti_toy.py        minimum rigor enforcement
  phases/
    p1_ideation.py
    p2_refine.py
    p3_experiment_plan.py
    p4_bridge.py
    p5_paper_write.py
    p6_review.py
    p7_p8_audit.py
  providers/
    llm.py             provider routing and redacted errors
    literature.py      Semantic Scholar and arXiv search
  workspace/
    manager.py         tracked source for persistence and resume
  memory/
    store.py           local learning plus agentmemory outbox fallback
  diagnostics.py       CLI/API status report
  runtime.py           version and redaction helpers
```

## Pipeline

```text
discover / extend / transfer
  -> kill-first
  -> research refine
  -> experiment plan
  -> experiment bridge
  <- user or server runs experiments
  -> paper write
  -> auto-review
  -> citation audit
  -> claim audit
```

The bridge phase is a real pause. Do not pretend experiments ran. Put result JSON files in `workspace/ideas/<idea_id>/experiments/results/`, then run `vlab resume <idea_id>`.
Follow `docs/RESULT_CONTRACT.md` or the plan-specific
`experiments/RESULT_CONTRACT.md`. Result labels are recomputed locally; schema-less legacy files
cannot qualify as `paper_result`, and all empirical claims must link to validated block IDs.

## Handoff Contract

Use artifact contracts instead of private runtime coupling. Lab owns `workspace/*/session.json`, `workspace/ideas/<idea_id>/idea.json`, `plan.json`, `paper.json`, `EXPERIMENT_PLAN.md`, `EXPERIMENT_TRACKER.md`, `experiments/results/*.json`, and redacted `agentmemory-outbox.jsonl`.

`WEIPING_COUNCIL` may consume or produce council session artifacts for review, but Lab must not require Council's `.env`, local DBs, caches, active server process, or generated sessions to verify itself. `WEIPING_WIKI` is a public route map and optional context source through `WEIPING_WIKI_ROOT`; it is not a hidden runtime dependency.

## Quality Gates

| Gate | Threshold | Blocks |
| --- | --- | --- |
| Kill-first | novelty >= 6 and feasibility >= 6 | idea proceeds |
| Experiment plan | all plan dimensions >= 6 | bridge generation |
| Auto-review | all review dimensions >= 7 | paper proceeds |
| Claim audit | no blocking issues | paper ready |

Evidence labels:

| Label | Criteria | Use |
| --- | --- | --- |
| `paper_result` | versioned schema, matching distinct seed trace, observed metrics/baselines, statistics, effect size, fairness, immutable code revision, dataset version, and full config SHA-256 | main claims |
| `official` | strong run, one check still needed | near-final |
| `diagnostic` | useful but incomplete | supplementary only |
| `pilot` | too weak for claims | never in paper claims |

## Release Rules

Before commit or push:

```bash
python -m pytest -q
python scripts/run_ruff.py check lab cli api tests scripts
python scripts/run_ruff.py format --check lab cli api tests scripts
python scripts/release_scan.py
npm --prefix ui run lint
npm --prefix ui run build
npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org
```

For stricter local development, install dev dependencies and run:

```bash
make verify
```

On Windows without `make`, use:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

The release scan must pass. If it fails, fix the code or docs rather than bypassing it.
`scripts/run_ruff.py` may use a project-local `.tools/ruff` cache when system `ruff` is unavailable.
`scripts/verify.ps1` must propagate non-zero exit codes from every Python and UI command.
READY checkpoints must be downgraded when their persisted plan, paper, or result artifact hashes
change; a stored claim label or model verdict cannot preserve READY status.

## Safety Rules

- Configuration must remain env-driven and public-safe.
- Do not add tracked private endpoints, fallback keys, or secret-shaped placeholders.
- Do not reintroduce retired collaboration paths.
- Keep `lab/workspace/` tracked as source; only the root `/workspace/` output directory is ignored.
- Redact provider errors and outbox content before persistence.
- Keep `AGENTS.md`, README, this file, and `.codex/skills/weiping-lab/SKILL.md` aligned with actual runtime behavior.
