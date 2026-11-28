"""Settings files in KEY=VALUE format (same format as systemd EnvironmentFile)."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_AI_ENV = Path("/etc/phishlens/ai.env")


def load_env_file(path: str | os.PathLike) -> int:
    """Load KEY=VALUE lines into os.environ without overriding existing variables.

    Returns the number of variables set. Missing file: 0.
    """
    path = Path(path)
    if not path.is_file():
        return 0
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value
            count += 1
    return count


def load_default_env() -> None:
    """AI settings for the web app: PHISHLENS_AI_ENV, else /etc/phishlens/ai.env."""
    load_env_file(os.environ.get("PHISHLENS_AI_ENV") or DEFAULT_AI_ENV)
