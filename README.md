<div align="center">

<img src="banner.png" alt="WEIPING_LAB" width="720" />

# ⚗ WEIPING_LAB

### v1.6.0 Evidence-Integrity Research Workbench

[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-orange?style=flat-square)](https://github.com/astral-sh/ruff)

Weiping Lab is an autonomous research workbench for phenomenon-driven discovery, kill-first ideation, experiment planning, evidence-gated writing, and cross-model audit.

It is designed to be useful without pretending to be magic: the lab pauses where real experiments are required, records workspace state on disk, exposes runtime diagnostics, and rejects release builds that drift back toward private config, stale versions, or retired collaboration paths.

Agents maintaining this repository should read `AGENTS.md`, this README, `CLAUDE.md`, and `.codex/skills/weiping-lab/SKILL.md` before non-trivial work.

</div>

---

## What Changed In v1.6

The v1.6 release closes the gap between a result file existing and evidence actually being
eligible for a paper.

- Result JSON is treated as untrusted input: size, encoding, schema version, idea/block identity,
  duplicate blocks, finite numbers, and completeness are checked before writing can start.
- Evidence labels are recomputed locally. A file may downgrade itself, but cannot self-promote to
  `paper_result`; qualifying evidence requires an immutable code revision, full config SHA-256,
  exact seed-count/trace agreement, and records its source SHA-256.
- Every planned block must have one unambiguous result and at least one block must meet the full
  `paper_result` contract before Phase 5 runs.
- Extracted claims persist in `paper.json` and must link by exact canonical ID to the current
  validated experiment plan. The final deterministic gate accepts empirical claims only when
  every linked block is `paper_result`.
- Review and plan rubrics require every dimension; partial or malformed model JSON now fails
  closed. Citation counts come from persisted unique IDs, not a model-reported number.
- Workspace JSON checkpoints and local memory snapshots use atomic replacement, so interrupted
  writes leave the previous checkpoint intact. Restores reject non-finite or structurally invalid
  JSON, and READY state is bound to bounded hashes of its plan, paper, and result artifacts; resume
  also rechecks review, citation, result, and claim gates.
- The experiment bridge validates generated Python/YAML, rejects definition-time Python payloads,
  emits deterministic block configs plus a result template/contract, rejects unapproved or
  malformed (including non-5–7-block) restored plans before generation, and records
  `BRIDGE_STATUS.json` instead of claiming a broken scaffold succeeded.
- `scripts/verify.ps1` now propagates every external command failure, including missing or failing
  UI tools.

---

## Core Workflow

Weiping Lab keeps the research pipeline deliberately gated:

```text
discover / extend / transfer
  -> phenomenon or project context
  -> idea generation
  -> novelty check
  -> kill-first adversarial review
  -> research refine
  -> experiment plan
  -> experiment bridge
  -> human or server runs experiments
  -> results loader
  -> evidence-gated paper write
  -> auto-review
  -> citation audit
  -> claim audit
```

The system should not turn weak evidence into paper claims. Results are labeled as `paper_result`, `official`, `diagnostic`, or `pilot`; only `paper_result` belongs in main claims.

---

## Design Principles

- Phenomenon first: ideas should start from anomalies, contradictions, or unexplained findings, not just "method X plus domain Y".
- Kill before build: every idea should face the strongest rejection argument before code is written.
- No toy defaults: paper-level results require strong baselines, sufficient seeds, fair comparisons, and standard metrics.
- Cross-model audit: the auditor role must remain distinct from the executor role.
- Config is runtime state: API keys, model IDs, endpoints, workspace roots, and agentmemory URL come from environment variables or `.env`.
- Honest pauses: the bridge phase generates experiment scaffolding, then waits for real result files.
- Observable health: runtime readiness should be visible through CLI, API, tests, and release scan.

---

## Project Relationships

- `WEIPING_LAB` is the public research workbench repository.
- `WEIPING_COUNCIL` is the companion review/council layer when a workflow needs cross-agent critique.
- `WEIPING_WIKI` is the public route map and durable operating context, not a runtime dependency.
- `AGENT_RESOURCE` is the shared skill/resource library. Use it for workflow guidance; do not copy its caches or local clones into Lab.
- `AGENTIC_SCIENCE` provides optional audit methods such as UUPF for skill/workflow upgrades. UUPF reports are planning evidence only.
- Historical `vipin-lab` and `vipin-council` names may still appear in old local clones, logs, or remotes. Treat them as compatibility aliases; new docs, variables, and examples should use `WEIPING_LAB` and `WEIPING_COUNCIL`.

These projects should stay tightly routed but loosely coupled. Lab may read public-safe wiki context and council artifacts when explicitly configured, but its verification path must not require another repo's `.env`, local database, cache, active service, or generated report directory.

---

## Quick Start

```bash
git clone https://github.com/appleweiping/WEIPING_LAB
cd WEIPING_LAB
python -m pip install --upgrade "pip>=26.2.1" "setuptools>=84.0.0"
python -m pip install -e ".[dev]"
copy .env.example .env
```

Edit `.env` and set at least:

```bash
ANTHROPIC_API_KEY=<anthropic-api-key>
```

Then verify the runtime:

```bash
vlab status
vlab status --json
python scripts/release_scan.py
```

Start the web app:

```bash
uvicorn api.server:app --reload --port 8001
npm --prefix ui run dev
```

The UI expects the API on `http://localhost:8001` and Vite on `http://localhost:5174`.
Node.js 22.18 or newer is required. The release gate runs `pip check`, `pip-audit`,
and the official npm registry audit in addition to tests, lint, and the production build.
Python uses a library-style, latest-compatible-resolution CI policy: declared minimum ranges
are intentionally not an immutable lock. The UI is reproducibly locked with lockfile v3,
official-registry URLs, and SHA-512 integrity pins.

---

## CLI Reference

```bash
vlab discover "LLM4Rec"
vlab extend "LLM4Rec" --method "..." --results "..." --limits "..."
vlab transfer "conformal prediction" "LLM4Rec"
vlab pipeline <idea_id>
vlab resume <idea_id>
vlab ideas --domain LLM4Rec
vlab sessions
vlab show <session_id>
vlab status --json
```

`vlab pipeline` pauses after the experiment bridge when generated experiments need to be run outside the lab. Put result JSON files in:

```text
workspace/ideas/<idea_id>/experiments/results/
```

Then run:

```bash
vlab resume <idea_id>
```

The bridge writes `experiments/RESULT_CONTRACT.md` and `experiments/result.example.json` for the
specific plan. The repository-level contract and a complete example are in
[`docs/RESULT_CONTRACT.md`](docs/RESULT_CONTRACT.md). Legacy flat JSON remains readable for
diagnostic continuity, but schema-less input cannot qualify as `paper_result`.

---

## Runtime Status

`vlab status --json` and `/api/status` return a machine-readable readiness report:

- version
- whether a workspace was explicitly configured and is available, without returning its path
- model role, provider, model ID, API key env var, and endpoint host
- agentmemory endpoint host
- disabled legacy fallback flags
- quality gate thresholds
- required-key checks

The report intentionally says whether a key or workspace is configured, not its value or local path.
HTTP idea/session responses likewise expose only relative `workspace_ref` identifiers, never operator
filesystem paths; internal ignored checkpoints retain absolute paths only for local resumability.

---

## Handoff Artifacts

Generated research state stays in the configured workspace root, usually ignored `workspace/`. Durable handoffs should reference artifact paths and labels, not copy private runtime state into another repo.

| Artifact | Path pattern | Contract |
| --- | --- | --- |
| Discovery session | `workspace/*/session.json` | Top-level session record for phenomena, analogies, ideas, audit trail, and workspace references. |
| Idea state | `workspace/ideas/<idea_id>/idea.json` | Canonical idea metadata, status, kill-first result, and workspace directory. |
| Experiment plan | `workspace/ideas/<idea_id>/plan.json` and `EXPERIMENT_PLAN.md` | Planned datasets, baselines, metrics, seeds, commands, and anti-toy checks. |
| Experiment tracker | `workspace/ideas/<idea_id>/EXPERIMENT_TRACKER.md` | Human/server execution checklist and result status. |
| Result files | `workspace/ideas/<idea_id>/experiments/results/*.json` | Real outputs consumed by `vlab resume`; labels are recomputed from result contract version 1.0 and source hashes are persisted. |
| Paper draft | `workspace/ideas/<idea_id>/paper.json` | Evidence-gated paper state and claim support metadata. |
| Memory outbox | `workspace/.../agentmemory-outbox.jsonl` | Redacted fallback with endpoint host only when active agentmemory is unavailable; never a public evidence source. |

Optional context inputs are explicit and non-required: `WEIPING_LAB_CONTEXT_FILE`, `WEIPING_LAB_RULES_FILE`, and `WEIPING_WIKI_ROOT` can inject maintained public-safe context. If they are unset or missing, Lab should still run without falling back to retired Agent Hub or markdown memory trees.

---

## Configuration

`.env.example` is deliberately placeholder-only. It avoids values that look like real secrets.

```bash
ANTHROPIC_API_KEY=<anthropic-api-key>
OPENAI_API_KEY=
DEEPSEEK_API_KEY=
OPENROUTER_API_KEY=
SEMANTIC_SCHOLAR_API_KEY=

WEIPING_LAB_WORKSPACE_ROOT=
AGENTMEMORY_URL=http://localhost:3111
WEIPING_LAB_ARCHITECT_MODEL=claude-opus-4-7
WEIPING_LAB_EXECUTOR_MODEL=claude-sonnet-4-6
WEIPING_LAB_AUDITOR_MODEL=claude-sonnet-4-6
WEIPING_LAB_SCREENER_MODEL=deepseek-chat

WEIPING_LAB_CONTEXT_FILE=
WEIPING_LAB_RULES_FILE=
WEIPING_WIKI_ROOT=
```

Legacy `VIPIN_LAB_*` names are still read as fallbacks so existing workspaces keep running. Prefer `WEIPING_LAB_*` in new `.env` files.
`VIPIN_WIKI_ROOT` also remains a fallback for `WEIPING_WIKI_ROOT`.

Default model roles:

| Role | Default model | Provider | Purpose |
| --- | --- | --- | --- |
| architect | Claude Opus | Anthropic | phenomenon analysis, kill arguments, analogical reasoning |
| executor | Claude Sonnet | Anthropic | planning, writing, code scaffold generation |
| auditor | Claude Sonnet | Anthropic | cross-model review and final gates |
| screener | DeepSeek | DeepSeek API | inexpensive triage and screening |

---

## Verification

Use the full local gate before committing:

```bash
python -m pytest -q
python scripts/run_ruff.py check lab cli api tests scripts
python scripts/run_ruff.py format --check lab cli api tests scripts
python scripts/release_scan.py
npm --prefix ui run lint
npm --prefix ui run build
npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org
```

On Windows, run the same gate through PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

`make verify` is also available on systems with `make`. If system `ruff` is missing, `scripts/run_ruff.py` can use the project-local `.tools/ruff` cache:

```bash
make verify
```

The release scan checks the repository for:

- version drift between runtime, package metadata, and README
- retired collaboration references
- secret-shaped placeholders
- private endpoint fragments
- mirror registry lockfile URLs
- workspace manager source hidden by `.gitignore`
- invalid package lock JSON

---

## Project Structure

```text
WEIPING_LAB/
  api/                 FastAPI backend and SSE endpoints
  cli/                 Typer CLI and interactive REPL
  lab/
    core/              config, models, orchestrator, progress
    engines/           phenomenon, analogy, kill-first, evidence, anti-toy
    phases/            refine, plan, bridge, paper write, review, audits
    providers/         LLM and literature providers
    workspace/         tracked source package for idea/session persistence
    memory/            local learning plus agentmemory outbox fallback
    diagnostics.py     CLI/API status report
    runtime.py         version and redaction helpers
  scripts/
    release_scan.py    public-safe release guard
  tests/               Python regression tests
  ui/                  React/Vite workbench
  workspace/           generated sessions and idea workspaces, gitignored
```

---

## Open-Source References Studied

The v1.6 design was informed by concrete upstream source inspection. Patterns were adapted to this
project's small, local-first architecture; no upstream source was copied.

- [SakanaAI/AI-Scientist-v2 journal](https://github.com/SakanaAI/AI-Scientist-v2/blob/main/ai_scientist/treesearch/journal.py): typed execution nodes, explicit buggy/good state, metrics, and serialized experiment history reinforced separating observed execution state from narrative review. Its custom source license was reviewed; no code was copied.
- [SamuelSchmidgall/AgentLaboratory checkpoints](https://github.com/SamuelSchmidgall/AgentLaboratory/blob/main/ai_lab_repo.py): phase checkpoints and resumability informed crash-safe workspace replacement and explicit bridge status.
- [MLflow Tracking](https://github.com/mlflow/mlflow/blob/master/docs/docs/classic-ml/tracking/tracking-api/index.mdx): run metrics, parameters, artifacts, dataset versions, and source commit tags informed the compact code/data/config provenance envelope.
- [DVC](https://github.com/iterative/dvc): reproducible data, parameter, metric, and artifact lineage informed the local result contract and content digest without adding a DVC runtime dependency.
- [TIGER-AI-Lab/OpenResearcher](https://github.com/TIGER-AI-Lab/OpenResearcher): parseable evaluator output and explicit mismatch reporting remain reference points for fail-closed audits.

Weiping Lab deliberately keeps a different center of gravity: phenomenon-first discovery, kill-first review, and ARIS-style evidence discipline.

---

## License

MIT
