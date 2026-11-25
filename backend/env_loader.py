"""Lightweight stdlib .env loader so Python entrypoints read root .env without external dependencies."""

from __future__ import annotations

import os
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_project_env(env_path: str | Path | None = None) -> Path | None:
    """Load key=value pairs from .env using setdefault (never overrides already-set env vars)."""
    target = Path(env_path) if env_path is not None else _PROJECT_ROOT / ".env"
    if not target.is_file():
        return None

    try:
        content = target.read_text(encoding="utf-8")
    except OSError:
        return None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue

        key, raw_val = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue

        val = raw_val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in {'"', "'"}:
            quote_char = val[0]
            val = val[1:-1]
            if quote_char == '"':
                val = val.replace('\\"', '"').replace("\\n", "\n")
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()

        os.environ.setdefault(key, val)

    return target
