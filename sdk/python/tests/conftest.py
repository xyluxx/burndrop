from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import load_vectors


@pytest.fixture(scope="session")
def vectors() -> dict[str, Any]:
    return load_vectors()
