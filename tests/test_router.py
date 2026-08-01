from __future__ import annotations

import json
from pathlib import Path

from velvet import ActionType, CandidateAction, Router
from velvet.registry import action_registry
from velvet.types import CandidateSource, DecisionType

ROOT = Path(__file__).resolve().parents[1]
NON_BUDGET = {"non_budget_affecting": True}


def load_scenario(name: str) -> dict[str, object]:
    with (ROOT / "scenarios" / name).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict)
    return data


def test_reference_scenarios_route_to_expected_actions() -> None:
    router = Router()
    for scenario_path in sorted((ROOT / "scenarios").glob("*.json")):
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        decision = router.decide(_state(scenario), _candidates(scenario))
        assert decision.action_type == ActionType(str(scenario["state"]["expected_action"]))
        assert decision.seal_id


def test_entry_pricing_benchmarks_route_to_expected_actions() -> None:
    router = Router()
    for scenario_path in sorted((ROOT / "benchmarks" / "entry_pricing").glob("*.json")):
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        decision = router.decide(_state(scenario), _candidates(scenario))
        assert decision.action_type == ActionType(str(scenario["state"]["expected_action"]))


def test_explicit_overrides_are_applied_by_rust_kernel() -> None:
    decision = Router().decide(
        {"freshness_required": True},
        [
            CandidateAction(ActionType.ANSWER_DIRECTLY, metadata=NON_BUDGET),
            CandidateAction(
                ActionType.SEARCH_WEB,
                expected_improvement=0.9,
                novelty=0.9,
                confidence=0.9,
                cost_overrides={"latency": 0.0, "api_calls": 0.0},
                risk_overrides={"source_quality_risk": 0.0},
                metadata=NON_BUDGET,
            ),
        ],
    )
    assert decision.action_type == ActionType.SEARCH_WEB
    assert decision.selected_candidate is not None
    assert decision.selected_candidate.admission_score is None
    assert decision.selected_candidate.admission_trace is not None
    assert decision.selected_candidate.effect_vector is not None
    assert decision.selected_candidate.effect_vector.capability_class.value == "external_read"
    assert (
        decision.selected_candidate.admission_trace.objective_components.objective_bps
        > 0
    )


def test_empty_candidate_set_skips_without_old_fixture_path() -> None:
    decision = Router().decide({}, [])
    assert decision.action_type is None
    assert decision.decision == DecisionType.SKIP


def test_candidate_source_and_parameters_round_trip() -> None:
    decision = Router().decide(
        {"repo_available": True},
        [
            CandidateAction(
                ActionType.INSPECT_CODE,
                source=CandidateSource.SCENARIO,
                parameters={"query": "Router"},
                metadata=NON_BUDGET,
            )
        ],
    )
    assert decision.action_type == ActionType.INSPECT_CODE


def test_registry_is_expanded_and_exposed_from_rust() -> None:
    registry = action_registry()
    assert [item.action_type for item in registry] == [
        ActionType.ANSWER_DIRECTLY,
        ActionType.SEARCH_WEB,
        ActionType.RETRIEVE_CONTEXT,
        ActionType.READ_FILE,
        ActionType.INSPECT_CODE,
        ActionType.EXECUTE_CODE,
        ActionType.CALL_TOOL,
        ActionType.ASK_USER,
        ActionType.STORE_MEMORY,
        ActionType.ESCALATE_MODEL,
        ActionType.CONCIERGE_REVIEW,
    ]
    assert registry[5].requires_user_approval
    assert registry[5].action_family == "local_execution"


def _state(scenario: dict[str, object]) -> dict[str, object]:
    state = scenario["state"]
    assert isinstance(state, dict)
    return state


def _candidates(scenario: dict[str, object]) -> list[dict[str, object]]:
    candidates = scenario["candidates"]
    assert isinstance(candidates, list)
    normalized: list[dict[str, object]] = []
    for candidate in candidates:
        assert isinstance(candidate, dict)
        metadata = candidate.get("metadata", {})
        assert isinstance(metadata, dict)
        normalized.append(
            {
                **candidate,
                "metadata": {**metadata, "non_budget_affecting": True},
            }
        )
    return normalized
