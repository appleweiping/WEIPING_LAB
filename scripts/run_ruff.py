"""Run ruff from the active environment or the project-local tool cache."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCAL_RUFF = ROOT / ".tools" / "ruff"

if str(LOCAL_RUFF) not in sys.path and LOCAL_RUFF.exists():
    sys.path.insert(0, str(LOCAL_RUFF))

try:
    runpy.run_module("ruff", run_name="__main__")
except ModuleNotFoundError as exc:
    if exc.name != "ruff":
        raise
    raise SystemExit(
        "ruff is not installed. Run `python -m pip install --target .tools/ruff ruff` "
        "or install the dev extras with `python -m pip install -e .[dev]`."
    ) from None
