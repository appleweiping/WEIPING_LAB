"""Crash-safe persistence helpers for durable workspace artifacts."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from lab.runtime import public_executable_artifact_is_safe, redact_public_artifact


def atomic_write_text(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Replace ``path`` atomically after the complete payload reaches disk.

    Temporary files live beside the destination so ``os.replace`` stays on the
    same filesystem. A failed write leaves the previous checkpoint untouched.
    """

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(path: str | Path, value: Any) -> None:
    """Serialize a JSON checkpoint and replace its destination atomically."""

    atomic_write_text(
        path,
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
    )


def atomic_write_public_text(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Atomically persist prose after applying the public artifact projection."""
    atomic_write_text(path, redact_public_artifact(content), encoding=encoding)


def atomic_write_executable_text(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Persist code/config exactly, rejecting secret-bearing material instead of rewriting it."""
    if not public_executable_artifact_is_safe(content, artifact_path=path):
        raise ValueError("Executable artifact rejected by public safety policy")
    atomic_write_text(path, content, encoding=encoding)
