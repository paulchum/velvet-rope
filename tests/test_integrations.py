from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from velvet import (
    ActionType,
    CandidateAction,
    CapProvenance,
    DeterministicBudgetSpec,
    Router,
    openai_responses_hard_cap_usd,
)
from velvet.integrations import IntegrationExecutor
from velvet.types import DecisionType, ExecutionStatus
from velvet.workflows import WorkflowRunner

NON_BUDGET = {"non_budget_affecting": True}
APPROVED_NON_BUDGET = {
    "non_budget_affecting": True,
    "approval_valid": True,
    "warrant_valid": True,
}


def test_router_run_reads_local_file(tmp_path: Path) -> None:
    target = tmp_path / "note.txt"
    target.write_text("Velvet local file integration", encoding="utf-8")
    result = Router().run(
        {"file_available": True},
        [
            CandidateAction(
                ActionType.READ_FILE,
                parameters={"path": str(target)},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert "local file" in result.execution_result.output["text"]
    assert result.thread.execution_result is not None


def test_read_file_rejects_absolute_path_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    result = Router().run(
        {"file_available": True},
        [
            CandidateAction(
                ActionType.READ_FILE,
                parameters={"path": str(outside)},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=workspace),
    )

    assert result.execution_result.status == ExecutionStatus.FAILED
    assert "outside executor workspace" in result.execution_result.summary


def test_read_file_rejects_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (workspace / "link.txt").symlink_to(outside)

    result = Router().run(
        {"file_available": True},
        [
            CandidateAction(
                ActionType.READ_FILE,
                parameters={"path": "link.txt"},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=workspace),
    )

    assert result.execution_result.status == ExecutionStatus.FAILED
    assert "outside executor workspace" in result.execution_result.summary


def test_read_file_streams_bounded_output(tmp_path: Path) -> None:
    target = tmp_path / "large.txt"
    target.write_text("abcdefghij", encoding="utf-8")

    result = Router().run(
        {"file_available": True},
        [
            CandidateAction(
                ActionType.READ_FILE,
                parameters={"path": str(target), "max_bytes": 4},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )

    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert result.execution_result.output["text"] == "abcd"
    assert result.execution_result.output["truncated"] is True


def test_inspect_code_rejects_absolute_path_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = True\n", encoding="utf-8")

    result = Router().run(
        {"repo_available": True},
        [
            CandidateAction(
                ActionType.INSPECT_CODE,
                parameters={"query": "SECRET", "path": str(outside)},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=workspace),
    )

    assert result.execution_result.status == ExecutionStatus.FAILED
    assert "outside executor workspace" in result.execution_result.summary


def test_retrieve_context_rejects_external_explicit_sqlite_index(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_index = tmp_path / "outside.sqlite"
    with sqlite3.connect(outside_index) as conn:
        conn.execute("create virtual table documents using fts5(path, content)")
        conn.execute("insert into documents(path, content) values (?, ?)", ("x", "secret"))

    result = Router().run(
        {"retrieval_available": True, "user_request": "secret"},
        [
            CandidateAction(
                ActionType.RETRIEVE_CONTEXT,
                parameters={"query": "secret", "index_path": str(outside_index)},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=workspace),
    )

    assert result.execution_result.status == ExecutionStatus.FAILED
    assert "outside executor workspace" in result.execution_result.summary


def test_router_run_defers_direct_command_to_policy_target(tmp_path: Path) -> None:
    result = Router().run(
        {
            "allow_direct_execution": True,
            "execution_required": True,
            "policy_context": {"permissions": ["code_execute"]},
        },
        [
            CandidateAction(
                ActionType.EXECUTE_CODE,
                expected_improvement=1.0,
                novelty=1.0,
                confidence=1.0,
                parameters={"command": ["python", "-c", "print('ok')"], "cwd": "."},
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.decision.decision == DecisionType.ESCALATE
    assert result.execution_result.status == ExecutionStatus.BLOCKED
    assert result.execution_result.provider == "velvet_concierge_queue"
    assert result.execution_result.metadata["fallback"] == "deny"


def test_router_run_inspects_code_with_filesystem_fallback(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("class RouterThing:\n    pass\n", encoding="utf-8")
    result = Router().run(
        {"repo_available": True},
        [
            CandidateAction(
                ActionType.INSPECT_CODE,
                parameters={"query": "RouterThing", "path": str(tmp_path)},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert "RouterThing" in str(result.execution_result.output)


def test_router_run_retrieves_context_from_filesystem(tmp_path: Path) -> None:
    (tmp_path / "doc.txt").write_text("budget-aware routing substrate", encoding="utf-8")
    result = Router().run(
        {"retrieval_available": True, "user_request": "routing substrate"},
        [
            CandidateAction(
                ActionType.RETRIEVE_CONTEXT,
                parameters={"query": "routing substrate"},
                metadata=NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert result.execution_result.output["results"]


def test_store_memory_uses_sqlite_backend(tmp_path: Path) -> None:
    result = Router().run(
        {
            "memory_candidate_value": 0.82,
            "memory_novelty": 0.76,
            "memory_confidence": 0.84,
            "memory_type": "project_positioning",
            "sensitivity": 0.18,
            "user_request": "Remember that Velvet is a routing substrate.",
            "router_config": {
                "admission_config": {"direct_answer_fallback": False},
            },
        },
        [CandidateAction(ActionType.STORE_MEMORY, metadata=APPROVED_NON_BUDGET)],
        executor=IntegrationExecutor(workspace=tmp_path, memory_path=tmp_path / "memory.sqlite"),
    )
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert (tmp_path / "memory.sqlite").exists()


def test_external_integrations_report_missing_keys_without_live_calls(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    search = Router().run(
        {"freshness_required": True, "user_request": "latest security news"},
        [CandidateAction(ActionType.SEARCH_WEB, metadata=NON_BUDGET)],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert search.execution_result.provider == "tavily"
    assert search.execution_result.status == ExecutionStatus.BLOCKED

    model = Router().run(
        {"high_uncertainty": True, "user_request": "Solve hard task"},
        [
            CandidateAction(
                ActionType.ESCALATE_MODEL,
                expected_improvement=1.0,
                novelty=0.95,
                confidence=1.0,
                metadata={"non_budget_affecting": True},
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert model.execution_result.provider in {"openai", "openai_responses"}
    assert model.execution_result.status == ExecutionStatus.BLOCKED


def test_openai_escalation_records_realized_budget_cost(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    executor = IntegrationExecutor(workspace=tmp_path)

    def fake_post_json(
        url: str, payload: dict[str, Any], *, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        assert url == "https://api.openai.com/v1/responses"
        assert payload["max_output_tokens"] == 16
        assert headers is not None
        return {"usage": {"input_tokens": 4, "output_tokens": 3}}

    monkeypatch.setattr(executor, "_post_json", fake_post_json)

    result = Router().run(
        _openai_budget_state(),
        [_openai_budget_candidate()],
        executor=executor,
    )

    assert result.execution_result.provider == "openai_responses"
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert result.execution_result.cost["money"] == pytest.approx(10.0 / 1_000_000.0)
    assert result.execution_result.metadata["budget_realized_cost_status"] == "observed"


def test_openai_escalation_missing_usage_marks_budget_fail_closed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    executor = IntegrationExecutor(workspace=tmp_path)
    monkeypatch.setattr(executor, "_post_json", lambda *_args, **_kwargs: {"output": []})

    result = Router().run(
        _openai_budget_state(),
        [_openai_budget_candidate()],
        executor=executor,
    )

    assert result.execution_result.provider == "openai_responses"
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert "money" not in result.execution_result.cost
    assert (
        result.execution_result.metadata["budget_realized_cost_status"]
        == "fail_closed_missing_usage"
    )


@pytest.mark.skipif(
    os.environ.get("VELVET_LIVE_INTEGRATION_TESTS") != "1"
    or not os.environ.get("TAVILY_API_KEY"),
    reason="live Tavily test requires VELVET_LIVE_INTEGRATION_TESTS=1 and TAVILY_API_KEY",
)
def test_live_tavily_search_when_enabled(tmp_path: Path) -> None:
    result = Router().run(
        {"freshness_required": True, "user_request": "Velvet routing substrate"},
        [CandidateAction(ActionType.SEARCH_WEB, metadata=NON_BUDGET)],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.provider == "tavily"
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert result.execution_result.cost["api_calls"] == 1


@pytest.mark.skipif(
    os.environ.get("VELVET_LIVE_INTEGRATION_TESTS") != "1"
    or not os.environ.get("OPENAI_API_KEY"),
    reason="live OpenAI test requires VELVET_LIVE_INTEGRATION_TESTS=1 and OPENAI_API_KEY",
)
def test_live_openai_escalation_when_enabled(tmp_path: Path) -> None:
    result = Router().run(
        _openai_budget_state(),
        [_openai_budget_candidate()],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.provider == "openai_responses"
    assert result.execution_result.status == ExecutionStatus.SUCCEEDED
    assert result.execution_result.cost["api_calls"] == 1


def test_concierge_review_is_pending_in_noninteractive_mode(tmp_path: Path) -> None:
    result = Router().run(
        {"requires_concierge_review": True, "interrupt_reason": "policy review"},
        [
            CandidateAction(
                ActionType.CONCIERGE_REVIEW,
                expected_improvement=1.0,
                novelty=0.95,
                confidence=1.0,
                metadata=APPROVED_NON_BUDGET,
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.status == ExecutionStatus.PENDING_CONCIERGE


def test_json_tool_command_invocation_defers_to_policy_target(tmp_path: Path) -> None:
    result = Router().run(
        {
            "tool_call_requested": True,
            "policy_context": {"permissions": ["tool_call", "code_execute"]},
            "tools": {
                "echo": {
                    "kind": "command",
                    "command": ["python", "-c", "print('tool-ok')"],
                    "cwd": str(tmp_path),
                }
            },
        },
        [
            CandidateAction(
                ActionType.CALL_TOOL,
                expected_improvement=1.0,
                novelty=1.0,
                confidence=1.0,
                parameters={"tool_name": "echo"},
            )
        ],
        executor=IntegrationExecutor(workspace=tmp_path),
    )
    assert result.execution_result.action_type == ActionType.CALL_TOOL
    assert result.decision.decision == DecisionType.ESCALATE
    assert result.execution_result.status == ExecutionStatus.BLOCKED
    assert result.execution_result.provider == "velvet_concierge_queue"


def _openai_budget_state() -> dict[str, Any]:
    return {
        "filtration_hash": "openai-responses-live-test-v1",
        "high_uncertainty": True,
        "approval_valid": True,
        "warrant_valid": True,
        "user_request": "Reply with one short sentence.",
        "router_config": {
            "pricing_policy": "fixed_price_baseline",
            "lambda_floor": 0.01,
            "lambda_cap": 0.01,
            "admission_config": {"direct_answer_fallback": False},
        },
    }


def _openai_budget_candidate() -> CandidateAction:
    prompt = "Reply with one short sentence."
    price_table = {
        "input_usd_per_million_tokens": 1.0,
        "output_usd_per_million_tokens": 2.0,
    }
    max_output_tokens = 16
    hard_cap = openai_responses_hard_cap_usd(
        input_text=prompt,
        max_output_tokens=max_output_tokens,
        input_usd_per_million_tokens=price_table["input_usd_per_million_tokens"],
        output_usd_per_million_tokens=price_table["output_usd_per_million_tokens"],
    )
    candidate = DeterministicBudgetSpec(
        budget_limit=1.0,
        observed_spend=0.0,
        hard_cap=hard_cap,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        filtration_hash="openai-responses-live-test-v1",
    ).candidate(
        ActionType.ESCALATE_MODEL,
        description="Budgeted OpenAI Responses escalation",
        parameters={
            "model": os.environ.get("VELVET_OPENAI_MODEL", "gpt-4.1-mini"),
            "max_output_tokens": max_output_tokens,
            "budget_price_table": price_table,
        },
    )
    return replace(candidate, expected_improvement=1.0, novelty=0.2, confidence=1.0)


def test_workflow_runner_routes_executes_and_stops_on_answer(tmp_path: Path) -> None:
    run = WorkflowRunner(
        executor=IntegrationExecutor(workspace=tmp_path),
        max_steps=3,
    ).run(
        {"user_request": "What is Velvet?"},
        [CandidateAction(ActionType.ANSWER_DIRECTLY)],
    )
    assert run.status == "answered"
    assert len(run.steps) == 1
    assert run.final_state["workflow_history"][0]["action_type"] == "ANSWER_DIRECTLY"
    assert "budget_state" in run.final_state
