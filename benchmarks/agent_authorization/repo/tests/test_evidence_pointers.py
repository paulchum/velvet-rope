from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


def _load_checker() -> Any:
    path = Path("scripts/check_evidence_pointers.py")
    spec = importlib.util.spec_from_file_location("check_evidence_pointers", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_evidence_pointers"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_evidence_pointers_resolve() -> None:
    checker = _load_checker()
    assert checker.check_evidence_pointers(Path(".").resolve()) == []
