from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
C_FIXTURES = REPO_ROOT / "c-library" / "tests" / "data"
GENERATOR_PATH = REPO_ROOT / "scripts" / "generate_call_logs.py"


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_call_logs", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def generator() -> ModuleType:
    return _load_generator()


@pytest.fixture(scope="session")
def c_fixtures() -> Path:
    return C_FIXTURES


@pytest.fixture(scope="session")
def generated_log(tmp_path_factory: pytest.TempPathFactory, generator: ModuleType) -> Path:
    """Default generator output (seed 42, fault on CELL-107)."""
    path = tmp_path_factory.mktemp("generated") / "call_logs.csv"
    rows = generator.generate_rows(generator.GeneratorConfig(seed=42))
    path.write_text(generator.render_csv(rows), encoding="ascii", newline="")
    return path
