from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import velvet.shadowpath_product as product


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("valid", 0),
        ("missing_post", 4),
        ("missing_pre", 4),
        ("bad_dispatch", 4),
        ("control_failed", 5),
    ],
)
def test_observation_contract_is_conservative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: int,
) -> None:
    project_dir = tmp_path / "project"
    product.init_shadowpath_project(project_dir)
    observed: dict[str, int] = {}
    dispatched: list[str] = []

    def adapter(*args: Any) -> dict[str, Any]:
        request = args[2]
        trial = request["trial_id"]
        operation = request["operation"]
        if operation == "reset":
            return {"ok": True}
        if operation == "observe":
            observed[trial] = observed.get(trial, 0) + 1
            if mode == "missing_pre" or (mode == "missing_post" and observed[trial] == 2):
                return {}
            return {"state": "active", "observation_id": str(len(observed))}
        dispatched.append(trial)
        if mode == "bad_dispatch":
            return {"decision": "deny", "dispatch_attempted": "false"}
        if mode == "control_failed":
            return {"decision": "execute", "dispatch_attempted": True}
        return {"decision": "deny", "dispatch_attempted": False}

    monkeypatch.setattr(product, "_call_adapter", adapter)
    result = product.run_shadowpath_project(project_dir / "shadowpath.json", tmp_path / "out")
    assert result["exit_code"] == expected
    assert not result["generated_at"].startswith("1970")
    assert result["run_id"]
    if mode == "missing_pre":
        assert dispatched == []
    if mode == "valid":
        assert result["summary"]["sut_reconciliation_detection_rate"] is None
        assert result["protected_route"]["post_state"]["observation_id"]
        assert result["config_hash"].startswith("sha256:")


def test_portfolio_propagates_unknown_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = {
        "schema_version": product.PORTFOLIO_SCHEMA_VERSION,
        "name": "review",
        "effects": [{"id": "one", "project": "unused.json", "criticality": "low"}],
    }
    path = tmp_path / "portfolio.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(
        product,
        "run_shadowpath_project",
        lambda *a: {
            "summary": {"overall_verdict": "INDETERMINATE"},
            "exit_code": 6,
        },
    )
    result = product.run_shadowpath_portfolio(path, tmp_path / "out")
    assert result["summary"]["status"] == "ACTION_REQUIRED"
    assert result["exit_code"] != 0
