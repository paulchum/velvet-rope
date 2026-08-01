from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given, settings
from hypothesis import strategies as st

import velvet._native as _native
from velvet import ActionType, CandidateAction, Router
from velvet.integrations import IntegrationExecutor
from velvet.types import BudgetLedger, ExecutionStatus, ThreadRecord


@given(
    st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126),
        min_size=1,
        max_size=80,
    )
)
@settings(deadline=None)
def test_thread_schema_v9_round_trips_through_python_model(query: str) -> None:
    raw = _native.route_thread(
        {"freshness_required": True, "user_request": query},
        [{"action_type": "ANSWER_DIRECTLY"}, {"action_type": "SEARCH_WEB"}],
        thread_id="thread_hypothesis_v9",
        timestamp="2026-05-14T00:00:00+00:00",
    )["thread"]
    parsed = ThreadRecord.from_dict(raw)
    assert parsed.schema_version == "9.0"
    assert parsed.scored_candidates[0].admission_trace is not None
    assert parsed.scored_candidates[0].effect_vector is not None
    assert parsed.to_dict() == raw


@given(
    spent=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    limit=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
)
def test_budget_ledger_cost_observer_shape_round_trips(spent: float, limit: float) -> None:
    ledger = BudgetLedger(limit_usd=limit, spent_usd=spent)
    assert BudgetLedger.from_dict(ledger.to_dict()) == ledger


@given(command_label=st.from_regex(r"[a-z]{1,12}", fullmatch=True))
@settings(deadline=None)
def test_escalation_fallback_serializes_seal_packet(command_label: str) -> None:
    with TemporaryDirectory() as workspace:
        tmp_path = Path(workspace)
        result = Router().run(
            {
                "policy_context": {
                    "permissions": ["code_execute"],
                    "user_id": "hypothesis-user",
                    "prior_thread": [{"thread_id": "prior"}],
                }
            },
            [
                CandidateAction(
                    ActionType.EXECUTE_CODE,
                    expected_improvement=1.0,
                    novelty=0.8,
                    confidence=1.0,
                    parameters={
                        "command": ["python", "-c", f"print('{command_label}')"],
                        "cwd": ".",
                    },
                )
            ],
            executor=IntegrationExecutor(workspace=tmp_path),
        )
    assert result.decision.decision.value == "escalate"
    assert result.execution_result.status == ExecutionStatus.BLOCKED
    assert result.execution_result.output["candidate_action"]["action_type"] == "EXECUTE_CODE"
    assert result.execution_result.output["policy_context"]["user_id"] == "hypothesis-user"
    assert result.execution_result.output["thread_prefix"] == [{"thread_id": "prior"}]
