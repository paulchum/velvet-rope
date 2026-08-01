from __future__ import annotations

import json
from pathlib import Path

import pytest

from velvet.liability_live import (
    CLAIM_STATUS_BLOCKED,
    CLAIM_STATUS_PUBLISHABLE,
    CommandLiveAdapter,
    CompetitorSpec,
    run_live_competitor_liability,
)
from velvet.velvet_rope_liability import JsonObject, ScenarioSpec

TEST_SPEC = CompetitorSpec(
    "OpenAI Agents SDK",
    "openai_agents_sdk",
    "VELVET_TEST_OPENAI_COMMAND",
    "https://openai.github.io/openai-agents-python/",
    ("openai-agents",),
    "VELVET_TEST_HOSTED_OPENAI_COMMAND",
    "https://platform.openai.com/docs/agents",
)


class _SuccessfulLiveAdapter(CommandLiveAdapter):
    def __init__(self, *, tier: str = "sdk") -> None:
        command_env = (
            TEST_SPEC.sdk_command_env if tier == "sdk" else str(TEST_SPEC.hosted_command_env)
        )
        super().__init__(TEST_SPEC, tier, command_env)  # type: ignore[arg-type]

    def can_run_live(self) -> bool:
        return True

    def run_scenario(
        self,
        scenario: ScenarioSpec,
        output_path: Path,
        *,
        sandbox_registry_path: Path,
        run_ordinal: int,
    ) -> JsonObject:
        _ = (output_path, sandbox_registry_path, run_ordinal)
        return {
            "competitor_version": "test-live",
            "action_attempted": True,
            "action_executed": True,
            "tool_calls": [
                {
                    "tool_name": scenario.tool_name,
                    "tool_namespace": scenario.tool_namespace,
                    "arguments": {"target_resource": scenario.target_resource},
                }
            ],
            "final_response": "Task completed.",
        }


class _ErrorLiveAdapter(_SuccessfulLiveAdapter):
    def run_scenario(
        self,
        scenario: ScenarioSpec,
        output_path: Path,
        *,
        sandbox_registry_path: Path,
        run_ordinal: int,
    ) -> JsonObject:
        _ = (scenario, output_path, sandbox_registry_path, run_ordinal)
        raise RuntimeError("adapter crashed")


def test_live_receipts_refuse_without_explicit_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VELVET_LIABILITY_LIVE", raising=False)

    with pytest.raises(RuntimeError, match="VELVET_LIABILITY_LIVE=1"):
        run_live_competitor_liability(tmp_path)


def test_two_live_runs_promote_public_claim_packet(tmp_path: Path) -> None:
    payload = run_live_competitor_liability(
        tmp_path,
        competitor="openai_agents_sdk",
        tier="sdk",
        runs=2,
        require_opt_in=False,
        adapters=[_SuccessfulLiveAdapter()],
    )

    results = json.loads((tmp_path / "live_competitor_results.json").read_text())["results"]
    result = results[0]
    packet = (tmp_path / "public_claim_packet.md").read_text()
    manifest = json.loads((tmp_path / "live_run_manifest.json").read_text())

    assert payload["claim_status"] == "public_claims_ready_for_founder_approval"
    assert result["claim_status"] == CLAIM_STATUS_PUBLISHABLE
    assert result["reproducible_failure_count"] == 2
    assert result["unsafe_issue"] == "missing_pre_execution_warrant"
    assert "failed the liability benchmark twice" in packet
    assert manifest["founder_approval_gate"] == "founder_approval_required"
    assert list((tmp_path / "live_receipts").rglob("*.json"))


def test_single_live_run_blocks_absolute_public_language(tmp_path: Path) -> None:
    run_live_competitor_liability(
        tmp_path,
        competitor="openai_agents_sdk",
        tier="sdk",
        runs=1,
        require_opt_in=False,
        adapters=[_SuccessfulLiveAdapter()],
    )

    result = json.loads((tmp_path / "live_competitor_results.json").read_text())[
        "results"
    ][0]

    assert result["claim_status"] == CLAIM_STATUS_BLOCKED
    assert result["required_reproducible_runs"] == 2


def test_not_available_receipts_do_not_create_unsafe_claims(tmp_path: Path) -> None:
    run_live_competitor_liability(
        tmp_path,
        competitor="autogen",
        tier="sdk",
        runs=1,
        require_opt_in=False,
    )

    result = json.loads((tmp_path / "live_competitor_results.json").read_text())[
        "results"
    ][0]
    receipt = json.loads(next((tmp_path / "live_receipts").rglob("*.json")).read_text())

    assert result["safety_status"] == "insufficient_evidence"
    assert result["claim_status"] == "not_claimable"
    assert receipt["status"] == "not_available"
    assert receipt["raw_competitor_transcript"]["source_evidence_url"].startswith("https://")


def test_inconclusive_live_run_is_not_marked_unsafe(tmp_path: Path) -> None:
    run_live_competitor_liability(
        tmp_path,
        competitor="openai_agents_sdk",
        tier="sdk",
        runs=2,
        require_opt_in=False,
        adapters=[_ErrorLiveAdapter()],
    )

    result = json.loads((tmp_path / "live_competitor_results.json").read_text())[
        "results"
    ][0]
    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((tmp_path / "live_receipts").rglob("*.json"))
    ]

    assert result["safety_status"] == "insufficient_evidence"
    assert result["unsafe_issue"] == "not_run"
    assert result["claim_status"] == "not_claimable"
    assert {receipt["status"] for receipt in receipts} == {"inconclusive"}
