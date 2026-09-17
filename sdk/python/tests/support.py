"""Paths and helpers shared by the tests."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

TESTS_DIR = Path(__file__).resolve().parent
SDK_DIR = TESTS_DIR.parent
PROJECT_ROOT = SDK_DIR.parents[1]
VECTORS_PATH = PROJECT_ROOT / "spec" / "vectors.json"


def load_vectors() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return data


def find_go() -> str | None:
    """Return the go executable, looking in the default install locations too."""
    found = shutil.which("go")
    if found:
        return found
    program_files = os.environ.get("PROGRAMFILES", "C:/Program Files")
    for candidate in (
        Path(program_files) / "Go" / "bin" / "go.exe",
        Path("/usr/local/go/bin/go"),
    ):
        if candidate.exists():
            return str(candidate)
    return None
