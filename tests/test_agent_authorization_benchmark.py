from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from velvet.agent_authorization_benchmark import (
    BENCHMARK_VERSION,
    CAPABILITY_KEYS,
    DEFAULT_REPEAT_COUNT,
    SHADOWPATH_CAPABILITY_KEYS,
    SUBMISSION_SCHEMA_VERSION,
    append_submission_to_leaderboard,
    run_agent_authorization_benchmark,
    validate_agent_authorization_submission,
)

JsonObject = dict[str, Any]


def _well_formed_submission() -> JsonObject:
    capability = {
        "status": "pass",
        "value": True,
        "evidence_pointer": "results/example.json#/capability",
        "measurement": "Measured by the example adapter.",
    }
    return {
        "schema_version": SUBMISSION_SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "system": "Example System",
        "system_version": "0.2.1",
        "adapter": {"name": "example", "version": "0.2.1"},
        "commit_hash": "abc123",
        "repeat_count": DEFAULT_REPEAT_COUNT,
        "capabilities": {
            key: (
                {**capability, "pass_k": {"1": 1.0, "10": 1.0}}
                if key == "determinism"
                else {
                    "status": "not_measured",
                    "value": None,
                    "evidence_pointer": "results/example.json#/shadowpath",
                    "measurement": "No ShadowPath adapter was run.",
                    "reason": "not run: no ShadowPath adapter",
                }
                if key in SHADOWPATH_CAPABILITY_KEYS
                else dict(capability)
            )
            for key in CAPABILITY_KEYS
        },
    }


def test_agent_authorization_benchmark_populates_capability_evidence(
    tmp_path: Path,
) -> None:
    payload = run_agent_authorization_benchmark(tmp_path, allow_dirty=True)

    assert payload["schema_version"] == "velvet.agent_authorization.results.v0.3"
    assert payload["repeat_count"] == DEFAULT_REPEAT_COUNT
    assert Path(payload["results_path"]).exists()
    assert Path(payload["markdown_path"]).exists()

    matrix = payload["capability_matrix"]
    assert matrix
    systems = {str(row["system"]) for row in matrix}
    assert "Velvet Certified Max-DE" in systems
    assert "OpenAI Agents SDK guardrails" in systems

    for row in matrix:
        capabilities = row["capabilities"]
        assert set(capabilities) == set(CAPABILITY_KEYS)
        for key in CAPABILITY_KEYS:
            entry = capabilities[key]
            assert entry["status"] in {"pass", "fail", "not_measured"}
            assert entry["evidence_pointer"]
            if entry["status"] == "not_measured":
                assert "not run:" in entry["reason"]

    velvet = next(row for row in matrix if row["system"] == "Velvet Certified Max-DE")
    assert velvet["capabilities"]["certificate_emission"]["status"] == "pass"
    assert velvet["capabilities"]["determinism"]["status"] == "pass"
    assert velvet["capabilities"]["replayability"]["status"] == "pass"
    assert velvet["capabilities"]["independent_verifiability"]["status"] == "pass"
    assert velvet["capabilities"]["tamper_evidence"]["status"] == "pass"
    assert velvet["capabilities"]["determinism"]["pass_k"]["1"] == 1.0
    assert velvet["capabilities"]["determinism"]["pass_k"]["10"] == 1.0
    assert velvet["pass_k_reliability"]["10"] == 1.0
    for verdict_key in (
        "certificate_expiry",
        "fleet_false_lockout_accounting",
        "refusal_as_output",
        "priced_inspection",
    ):
        assert velvet["capabilities"][verdict_key]["status"] == "pass"
        for row in matrix:
            if row["system"] == "Velvet Certified Max-DE":
                continue
            assert row["capabilities"][verdict_key]["status"] == "not_measured", (
                f"non-velvet row {row['system']} must be not_measured "
                f"for {verdict_key}, never fail"
            )

    route_only = next(row for row in matrix if row["system"] == "mcp_allowlist_only")
    assert route_only["capabilities"]["route_authorization"]["status"] == "pass"
    assert route_only["capabilities"]["effect_prevention"]["status"] == "fail"
    assert route_only["capabilities"]["effect_inventory"]["status"] == "fail"
    assert route_only["capabilities"]["effect_reconciliation"]["status"] == "fail"
    assert payload["shadowpath"]["overall_verdict"] == "CONTROL_FALSE_SUCCESS"
    assert payload["shadowpath"]["exit_code"] == 3

    markdown = Path(payload["markdown_path"]).read_text(encoding="utf-8")
    assert "Velvet Non-Win Cases" in markdown
    assert "pass^10" in markdown
    assert "not run" in markdown


def test_validate_submission_accepts_well_formed_and_rejects_malformed(
    tmp_path: Path,
) -> None:
    submission = _well_formed_submission()

    assert validate_agent_authorization_submission(submission) == []
    leaderboard = append_submission_to_leaderboard(
        submission,
        tmp_path / "leaderboard.json",
    )
    assert len(leaderboard["submissions"]) == 1

    malformed = _well_formed_submission()
    del malformed["capabilities"]["tamper_evidence"]
    assert validate_agent_authorization_submission(malformed)
    with pytest.raises(ValueError):
        append_submission_to_leaderboard(malformed, tmp_path / "bad.json")

    bad_pass_k = _well_formed_submission()
    bad_pass_k["capabilities"]["determinism"]["pass_k"] = {"0": 1.2}
    errors = validate_agent_authorization_submission(bad_pass_k)
    assert any("pass_k" in error for error in errors)


def test_agent_authorization_benchmark_dirty_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "velvet.agent_authorization_benchmark._git_dirty",
        lambda: True,
    )

    with pytest.raises(SystemExit):
        run_agent_authorization_benchmark(tmp_path)
