"""
Phase 4: Experiment Bridge

Translates the experiment plan into executable code.
Generates:
- Runner architecture (config-driven, seed-controlled)
- Baseline wrappers
- Our method implementation skeleton
- Launch scripts
- M0 sanity check

Does NOT run experiments. That's the user's job (local or server).
Writes everything to workspace/experiments/.
"""

from __future__ import annotations
import ast
import json
import re
from pathlib import Path
import yaml
from ..core.models import Idea, ExperimentPlan
from ..core.config import LabConfig
from ..providers.llm import LLMProvider
from ..results.loader import RESULT_SCHEMA_VERSION
from ..runtime import safe_error
from ..storage import (
    atomic_write_executable_text,
    atomic_write_json,
    atomic_write_public_text,
    atomic_write_text,
)


RUNNER_ARCH_PROMPT = """Design the runner architecture for these experiments.

Idea: {title}
Domain: {domain}
Experiment blocks: {blocks_summary}
Baselines: {baselines}
Datasets: {datasets}

Design a config-driven, seed-controlled experiment runner.
Requirements:
1. All hyperparameters in YAML configs (not hardcoded)
2. Seed control: set all random seeds (numpy, torch, random, cuda)
3. Results go to results/ directory (gitignored)
4. Checkpoint strategy for crash recovery
5. Launcher script that runs all blocks
6. Result aggregation script

Output the architecture as a file tree with brief descriptions:
experiments/
  configs/
    base.yaml          — shared config
    block_1.yaml       — block-specific overrides
    ...
  src/
    run.py             — main runner
    baselines/
      baseline_1.py    — baseline wrapper
      ...
    method/
      model.py         — our method
    utils/
      seeds.py         — seed control
      metrics.py       — metric computation
      aggregator.py    — result aggregation
  scripts/
    launch_all.sh      — launch all blocks
    m0_sanity.sh       — M0 sanity check (block 1, 3 seeds)
  results/             — gitignored

Then write the content of:
1. configs/base.yaml
2. src/utils/seeds.py
3. scripts/m0_sanity.sh

Output JSON:
{{
  "file_tree": "...",
  "base_yaml": "...",
  "seeds_py": "...",
  "m0_sanity_sh": "..."
}}
"""

METHOD_SKELETON_PROMPT = """Write a Python skeleton for this research method.

Method: {proposed_method}
Domain: {domain}
Key components: {key_components}

Write a clean, well-structured skeleton with:
1. Class definition with __init__ and forward/predict methods
2. Type hints
3. Docstrings explaining what each method does
4. TODO comments where the actual implementation goes
5. Integration with the runner (how it's called from run.py)

This is a skeleton — mark implementation points with TODO.
Output the Python code directly (no JSON wrapper).
"""


class ExperimentBridge:
    def __init__(self, config: LabConfig, llm: LLMProvider):
        self.config = config
        self.llm = llm

    async def run(self, idea: Idea, plan: ExperimentPlan) -> bool:
        """Generate experiment code skeleton. Returns True if successful."""
        workspace = Path(idea.workspace_dir) if idea.workspace_dir else None
        if not workspace:
            return False

        exp_dir = workspace / "experiments"
        exp_dir.mkdir(parents=True, exist_ok=True)

        boundary_issues = self._plan_boundary_issues(plan)
        if boundary_issues:
            atomic_write_json(
                exp_dir / "BRIDGE_STATUS.json",
                {
                    "success": False,
                    "generated": {
                        "base_config": False,
                        "seed_helper": False,
                        "method_skeleton": False,
                    },
                    "issues": boundary_issues,
                },
            )
            return False

        # Generate runner architecture
        blocks_summary = "\n".join(
            f"Block {b.id}: {b.name} — {b.hypothesis[:80]}" for b in plan.blocks
        )
        baselines = list({b for block in plan.blocks for b in block.baselines})[:10]
        datasets = idea.metadata.get("data_sources", ["standard benchmarks"])

        arch_response = await self.llm.complete(
            self.config.executor(),
            [
                {
                    "role": "user",
                    "content": RUNNER_ARCH_PROMPT.format(
                        title=idea.title,
                        domain=idea.domain,
                        blocks_summary=blocks_summary,
                        baselines=", ".join(baselines),
                        datasets=", ".join(datasets),
                    ),
                }
            ],
            temperature=0.3,
            max_tokens=4096,
        )
        arch = self._parse_json(arch_response)
        bridge_issues: list[str] = []
        generated = {"base_config": False, "seed_helper": False, "method_skeleton": False}

        # Write architecture files
        if arch.get("base_yaml"):
            base_yaml = arch["base_yaml"]
            try:
                parsed_yaml = yaml.safe_load(base_yaml) if isinstance(base_yaml, str) else None
            except yaml.YAMLError as exc:
                bridge_issues.append(f"base.yaml is invalid YAML: {safe_error(exc)}")
            else:
                if isinstance(parsed_yaml, dict):
                    configs_dir = exp_dir / "configs"
                    configs_dir.mkdir(exist_ok=True)
                    try:
                        atomic_write_executable_text(configs_dir / "base.yaml", base_yaml)
                    except ValueError:
                        bridge_issues.append("base.yaml was rejected by the public safety policy")
                    else:
                        generated["base_config"] = True
                else:
                    bridge_issues.append("base.yaml must contain a mapping")
        else:
            bridge_issues.append("runner architecture did not include base_yaml")

        if arch.get("seeds_py"):
            seeds_code = self._strip_code_fence(str(arch["seeds_py"]))
            if self._valid_python(seeds_code, required_definition="function"):
                utils_dir = exp_dir / "src" / "utils"
                utils_dir.mkdir(parents=True, exist_ok=True)
                try:
                    atomic_write_executable_text(utils_dir / "seeds.py", seeds_code)
                except ValueError:
                    bridge_issues.append(
                        "generated seeds.py was rejected by the public safety policy"
                    )
                else:
                    generated["seed_helper"] = True
            else:
                bridge_issues.append("generated seeds.py is not valid Python")
        else:
            bridge_issues.append("runner architecture did not include seeds_py")

        if arch.get("m0_sanity_sh"):
            scripts_dir = exp_dir / "scripts"
            scripts_dir.mkdir(exist_ok=True)
            try:
                atomic_write_executable_text(
                    scripts_dir / "m0_sanity.sh", str(arch["m0_sanity_sh"])
                )
            except ValueError:
                bridge_issues.append(
                    "generated m0_sanity.sh was rejected by the public safety policy"
                )

        # Write file tree documentation
        if arch.get("file_tree"):
            atomic_write_public_text(
                exp_dir / "ARCHITECTURE.md",
                f"# Experiment Architecture\n\n```\n{arch['file_tree']}\n```\n",
            )

        # Generate method skeleton
        method_response = await self.llm.complete(
            self.config.executor(),
            [
                {
                    "role": "user",
                    "content": METHOD_SKELETON_PROMPT.format(
                        proposed_method=idea.proposed_method,
                        domain=idea.domain,
                        key_components=idea.metadata.get("key_experiments", []),
                    ),
                }
            ],
            temperature=0.3,
            max_tokens=3000,
        )
        method_code = self._strip_code_fence(method_response)
        if method_code and self._valid_python(method_code, required_definition="class"):
            method_dir = exp_dir / "src" / "method"
            method_dir.mkdir(parents=True, exist_ok=True)
            try:
                atomic_write_executable_text(method_dir / "model.py", method_code)
            except ValueError:
                bridge_issues.append(
                    "generated method skeleton was rejected by the public safety policy"
                )
            else:
                generated["method_skeleton"] = True
        else:
            bridge_issues.append("generated method skeleton is empty or invalid Python")

        # Deterministic block configs and result contract do not depend on LLM output.
        configs_dir = exp_dir / "configs"
        configs_dir.mkdir(exist_ok=True)
        for block in plan.blocks:
            block_yaml = yaml.safe_dump(
                {
                    "block_id": block.id,
                    "name": block.name,
                    "hypothesis": block.hypothesis,
                    "primary_metrics": block.primary_metrics,
                    "secondary_metrics": block.secondary_metrics,
                    "baselines": block.baselines,
                    "seeds": block.seeds,
                    "kill_condition": block.kill_condition,
                },
                sort_keys=False,
                allow_unicode=True,
            )
            try:
                atomic_write_executable_text(configs_dir / f"block_{block.id}.yaml", block_yaml)
            except ValueError:
                bridge_issues.append(
                    f"block {block.id} config was rejected by the public safety policy"
                )
        self._write_result_contract(exp_dir, idea, plan)

        # Write gitignore for results
        atomic_write_text(exp_dir / ".gitignore", "results/\n*.log\n__pycache__/\n*.pyc\n")

        # Write README for experiments
        atomic_write_public_text(
            exp_dir / "README.md",
            f"# Experiments: {idea.title}\n\n"
            f"## Scaffold status\n\n"
            f"This bridge creates reviewed inputs and implementation skeletons; it does not "
            f"claim the experiment has run. Resolve every TODO and inspect generated shell/code "
            f"before execution. If `scripts/m0_sanity.sh` exists, review it before running it.\n\n"
            f"## Blocks\n\n"
            + "\n".join(f"- **Block {b.id}**: {b.name}" for b in plan.blocks)
            + "\n\n"
            f"## M0 Gate\n\n"
            f"Block 1 with 3 seeds must pass before scaling to full experiments.\n"
            f"Kill condition: {plan.blocks[0].kill_condition if plan.blocks else 'TBD'}\n\n"
            f"## Result handoff\n\n"
            f"Read `RESULT_CONTRACT.md`, copy `result.example.json` into `results/`, replace "
            f"every placeholder with observed values, then run `vlab resume {idea.id}`.\n",
        )

        success = all(generated.values()) and not bridge_issues
        atomic_write_json(
            exp_dir / "BRIDGE_STATUS.json",
            {"success": success, "generated": generated, "issues": bridge_issues},
        )
        return success

    def _write_result_contract(self, exp_dir: Path, idea: Idea, plan: ExperimentPlan) -> None:
        contract = (
            "# Result Contract\n\n"
            f"Schema version: `{RESULT_SCHEMA_VERSION}`. Result files are untrusted inputs: "
            "WEIPING_LAB recomputes evidence labels and records a SHA-256 digest.\n\n"
            "A paper-result block needs all planned primary metrics and baselines, at least "
            f"{self.config.min_seeds_paper} distinct seed IDs, a valid p-value or confidence "
            "interval, `fair_comparison: true`, and code/data/config provenance. Every planned "
            "block needs one unambiguous result before writing can start.\n\n"
            "The `_evidence_label` field may downgrade evidence but cannot promote it.\n"
        )
        atomic_write_public_text(exp_dir / "RESULT_CONTRACT.md", contract)
        example = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "idea_id": idea.id,
            "provenance": {
                "code_revision": "replace-with-git-commit",
                "dataset_version": "replace-with-dataset-version",
                "config_digest": "sha256:replace-with-config-digest",
                "command": "replace-with-reviewed-command",
                "seed_values": list(range(self.config.min_seeds_paper)),
            },
            "blocks": [
                {
                    "block_id": block.id,
                    "results": {
                        "metrics": {metric: None for metric in block.primary_metrics},
                        "baselines": {baseline: {} for baseline in block.baselines},
                        "statistics": {
                            "p_value": None,
                            "confidence_interval": [None, None],
                            "effect_size": None,
                        },
                        "seeds_used": self.config.min_seeds_paper,
                        "fair_comparison": False,
                    },
                }
                for block in plan.blocks
            ],
        }
        atomic_write_json(exp_dir / "result.example.json", example)

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        stripped = str(text or "").strip()
        match = re.fullmatch(r"```(?:python|py)?\s*\n?(.*?)\n?```", stripped, re.DOTALL | re.I)
        content = (match.group(1) if match else stripped).strip() if stripped else ""
        return f"{content}\n" if content else ""

    @staticmethod
    def _valid_python(source: str, *, required_definition: str) -> bool:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return False
        if not tree.body:
            return False

        allowed_top_level = (
            ast.Import,
            ast.ImportFrom,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
        )
        for statement in tree.body:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    continue
            if not isinstance(statement, allowed_top_level):
                return False
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not ExperimentBridge._safe_function_definition(statement):
                    return False
            elif isinstance(statement, ast.ClassDef):
                if not ExperimentBridge._safe_class_definition(statement):
                    return False

        if required_definition == "function":
            return any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in tree.body
            )
        if required_definition == "class":
            return any(isinstance(node, ast.ClassDef) for node in tree.body)
        return False

    @staticmethod
    def _safe_function_definition(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Reject expressions that execute while a generated function is defined."""

        if node.decorator_list:
            return False
        eager_values = [*node.args.defaults, *node.args.kw_defaults]
        if any(
            value is not None and not ExperimentBridge._literal_expression(value)
            for value in eager_values
        ):
            return False
        annotation_nodes = [
            node.returns,
            *(argument.annotation for argument in node.args.posonlyargs),
            *(argument.annotation for argument in node.args.args),
            *(argument.annotation for argument in node.args.kwonlyargs),
        ]
        if node.args.vararg:
            annotation_nodes.append(node.args.vararg.annotation)
        if node.args.kwarg:
            annotation_nodes.append(node.args.kwarg.annotation)
        return not any(
            annotation is not None
            and any(
                isinstance(child, (ast.Call, ast.Await, ast.NamedExpr, ast.Lambda))
                for child in ast.walk(annotation)
            )
            for annotation in annotation_nodes
        )

    @staticmethod
    def _safe_class_definition(node: ast.ClassDef) -> bool:
        """Reject decorators, metaclass calls, and eager class-body statements."""

        if node.decorator_list:
            return False
        eager_headers = [*node.bases, *(keyword.value for keyword in node.keywords)]
        if any(
            any(
                isinstance(child, (ast.Call, ast.Await, ast.NamedExpr, ast.Lambda))
                for child in ast.walk(value)
            )
            for value in eager_headers
        ):
            return False
        for statement in node.body:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    continue
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if ExperimentBridge._safe_function_definition(statement):
                    continue
            elif isinstance(statement, ast.ClassDef):
                if ExperimentBridge._safe_class_definition(statement):
                    continue
            elif isinstance(statement, ast.Assign):
                if all(
                    ExperimentBridge._safe_assignment_target(target) for target in statement.targets
                ) and ExperimentBridge._literal_expression(statement.value):
                    continue
            elif isinstance(statement, ast.AnnAssign):
                annotation_is_safe = not any(
                    isinstance(child, (ast.Call, ast.Await, ast.NamedExpr, ast.Lambda))
                    for child in ast.walk(statement.annotation)
                )
                if (
                    isinstance(statement.target, ast.Name)
                    and annotation_is_safe
                    and (
                        statement.value is None
                        or ExperimentBridge._literal_expression(statement.value)
                    )
                ):
                    continue
            return False
        return True

    @staticmethod
    def _literal_expression(node: ast.AST) -> bool:
        try:
            ast.literal_eval(node)
        except (ValueError, TypeError, MemoryError, RecursionError):
            return False
        return True

    @staticmethod
    def _safe_assignment_target(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(ExperimentBridge._safe_assignment_target(item) for item in node.elts)
        return False

    @staticmethod
    def _plan_boundary_issues(plan: ExperimentPlan) -> list[str]:
        """Reject restored/mutated plans before IDs become filenames or prompts."""

        if not 5 <= len(plan.blocks) <= 7:
            return ["experiment plan must contain 5 to 7 blocks"]
        if plan.approved is not True:
            return ["experiment plan has not passed the evidence audit"]
        block_ids = [block.id for block in plan.blocks]
        if any(
            isinstance(block_id, bool)
            or not isinstance(block_id, int)
            or not 0 <= block_id < 10_000
            for block_id in block_ids
        ):
            return ["block IDs must be integers from 0 to 9999"]
        if len(set(block_ids)) != len(block_ids):
            return ["block IDs must be unique"]
        for block in plan.blocks:
            if any(
                not isinstance(value, str)
                for value in (
                    block.name,
                    block.hypothesis,
                    block.expected_outcome,
                    block.failure_mode,
                    block.kill_condition,
                )
            ):
                return ["block narrative fields must be strings"]
            if any(
                not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                for values in (block.primary_metrics, block.secondary_metrics, block.baselines)
            ):
                return ["block metrics and baselines must be string arrays"]
            if (
                isinstance(block.seeds, bool)
                or not isinstance(block.seeds, int)
                or not 0 <= block.seeds <= 1_000_000
            ):
                return ["block seed counts must be integers from 0 to 1000000"]
        return []

    def _parse_json(self, text: str) -> dict:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass
        try:
            parsed = json.loads(text.strip())
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
