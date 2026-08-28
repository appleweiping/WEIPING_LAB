---
name: weiping-lab
description: Plan, design, develop, test, release, maintain, monitor, and iterate Weiping Lab honestly.
---

# Weiping Lab Project Skill

Use this skill for any non-trivial change to Weiping Lab. The goal is an honest research workbench: public-safe config, explicit evidence gates, reproducible workspace state, and no hidden dependency on retired collaboration systems.

## 1. Plan

- Read `AGENTS.md`, `README.md`, `CLAUDE.md`, `pyproject.toml`, `lab/core/config.py`, and `lab/runtime.py`.
- Run `git status --short --branch` and do not disturb unrelated user changes.
- Define one version-sized outcome. Avoid tiny isolated tweaks unless the user explicitly asks for one.
- Identify any relation to `WEIPING_WIKI`, `WEIPING_COUNCIL`, `AGENT_RESOURCE`, `AGENTIC_SCIENCE`, or `deepseek-cli`; use current files as evidence, not memory alone. Treat historical `vipin-*` references as compatibility aliases only.

## 2. Design

- Keep runtime configuration env-driven. Never add tracked private keys, endpoints, account names, or secret-shaped placeholders.
- Keep active memory routed through agentmemory. Local fallback may be an outbox under the configured workspace only; do not restore retired Agent Hub mailboxes or old markdown session dumps.
- Preserve the research gate sequence: phenomenon, kill-first, refine, experiment plan, bridge, results, paper write, review, citation audit, claim audit.
- Preserve `docs/RESULT_CONTRACT.md`: result files are untrusted, evidence labels are computed
  locally, and empirical claims require persisted links to `paper_result` block IDs.
- Make every new check observable through CLI, API, tests, or release scan.
- Keep cross-project links low-coupling: route maps, optional context variables, validation commands, and artifact formats are acceptable; private `.env` files, local DBs, caches, generated reports, and active services are not.

## 3. Develop

- Prefer scoped edits in `lab/`, `api/`, `cli/`, `ui/`, `tests/`, `scripts/`, and docs.
- Use `apply_patch` for manual edits.
- If `lab/workspace/` source files are touched, verify they are not gitignored.
- Redact provider errors and persisted diagnostics before writing logs or outbox records.
- Use atomic replacement for durable JSON checkpoints. Never treat a partial result set, a
  producer-supplied label, or a partial model rubric as a passing gate.
- Bind READY state to the exact plan, paper, and result artifact hashes; any later mutation must
  downgrade the checkpoint and force deterministic evidence validation again.

## 4. Test

Run the strongest practical local gate:

```bash
python -m pytest -q
python -m pip check
python -m pip_audit
python scripts/release_scan.py
npm --prefix ui run lint
npm --prefix ui run build
npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org
```

When dependencies are missing, install only the narrow needed dev dependency into a D-drive project-local environment or clearly report the blocker.

## 5. Release

- Bump `lab/runtime.py` and `pyproject.toml` together.
- Update `README.md`, `CLAUDE.md`, `.env.example`, and the release scan when behavior changes.
- Ensure `python scripts/release_scan.py` rejects stale versions, retired infrastructure, mirror registries, private endpoints, and secret-like placeholders.
- Commit and push only after tests and reviewer gates pass.

## 6. Maintain

- Keep `README.md` honest about implemented behavior.
- Keep `CLAUDE.md` as an operational adapter, not a competing policy document.
- Keep `AGENTS.md` as the top-level operating adapter for this repo and align it with README, CLAUDE, and this skill.
- Maintain the handoff contract for `workspace/*/session.json`, `workspace/ideas/<idea_id>/idea.json`, `plan.json`, `paper.json`, `EXPERIMENT_PLAN.md`, `EXPERIMENT_TRACKER.md`, `experiments/results/*.json`, and redacted `agentmemory-outbox.jsonl`.
- Keep the repository result contract and bridge-generated result template synchronized with the
  loader and its regression tests.
- Remove compatibility shims only when callers are updated; otherwise make shims explicit no-ops.

## 7. Monitor

- `vlab status --json` and `GET /api/status` are the public runtime probes.
- Monitor workspace count, model key source, agentmemory endpoint host, and disabled legacy fallbacks.
- Do not expose raw API keys, bearer tokens, full provider URLs containing credentials, or private filesystem paths beyond configured workspace diagnostics.

## 8. Upgrade Iterate

- Study concrete source files from active open-source research-agent projects before major architecture claims.
- Use reviewer partners after the implementation batch is complete. Require `PASS_10` before release.
- Feed reviewer findings back into code, docs, and tests, then rerun the gates.
