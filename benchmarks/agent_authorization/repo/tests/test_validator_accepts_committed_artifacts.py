from __future__ import annotations

from pathlib import Path

from aab.validate_submission import main as validate_main


def test_validator_accepts_committed_artifacts() -> None:
    paths = [
        *sorted(str(path) for path in Path("results").glob("*.json")),
        *sorted(str(path) for path in Path("comparison/results").glob("*.json")),
    ]
    assert paths
    assert validate_main(paths) == 0
