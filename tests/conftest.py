import json
from pathlib import Path

import pytest


@pytest.fixture
def synthetic_cases_path() -> Path:
    return Path(__file__).parent / "fixtures" / "synthetic" / "cases.json"


@pytest.fixture
def synthetic_cases(synthetic_cases_path: Path) -> dict:
    with open(synthetic_cases_path, "r", encoding="utf-8") as f:
        return json.load(f)
