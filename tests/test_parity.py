from __future__ import annotations

import json
from pathlib import Path

import velvet._native as _native
from velvet import ActionType, CandidateAction, MemoryEngine, Router
from velvet.thread_log import redact_secrets

ROOT = Path(__file__).resolve().parents[1]
NON_BUDGET = {"non_budget_affecting": True}


def test_python_and_rust_route_outputs_match_for_scenarios() -> None:
    router = Router()
    for scenario_path in sorted((ROOT / "scenarios").glob("*.json")):
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        actual = router.decide(scenario["state"], scenario["candidates"]).to_dict()
        native = _native.route_decision(scenario["state"], scenario["candidates"])
        assert actual == native


def test_reference_edge_cases_are_trace_backed() -> None:
    router = Router()
    assert router.decide({}, []).decision.value == "skip"
    read_file = router.decide({"available_context": []}, [ActionType.READ_FILE])
    assert read_file.action_type == ActionType.READ_FILE
    assert [entry.policy_name for entry in read_file.candidate_decisions[0].policy_trace] == [
        "pii_guard",
        "prompt_injection_detector",
        "cost_ceiling",
        "rate_limiter",
        "escalation_gate",
    ]
    explicit = router.decide(
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
    assert explicit.action_type == ActionType.SEARCH_WEB
    assert explicit.seal_id
    memory = MemoryEngine()
    assert (
        memory.evaluate_candidate(
            "My API key is secret-test-value.",
            {"project": "Velvet"},
        ).decision.value
        == "ask_approval"
    )
    assert (
        memory.evaluate_candidate(
            "I had toast today.",
            {"memory_candidate_value": 0.10},
        ).decision.value
        == "skip"
    )
    assert (
        redact_secrets({"api_key": "abc", "nested": {"Authorization": "bearer x"}, "safe": "ok"})
        == {"api_key": "[REDACTED]", "nested": {"Authorization": "[REDACTED]"}, "safe": "ok"}
    )


def test_thread_schema_v9_matches_python_model() -> None:
    actual = _native.route_thread(
        {"freshness_required": True, "seal_seed": 99},
        [
            {"action_type": "ANSWER_DIRECTLY", "metadata": NON_BUDGET},
            {"action_type": "SEARCH_WEB", "metadata": NON_BUDGET},
        ],
        thread_id="thread_fixture_v9",
        timestamp="2026-05-14T00:00:00+00:00",
    )["thread"]
    assert actual["schema_version"] == "9.0"
    assert "evaluation_context" in actual
    assert "evaluation_outcomes" in actual
    assert actual["router_version"] == "router_v1"
    assert actual["scorer_version"] == "admission_optimizer_v1"
    assert actual["pricing_policy_name"] == "hybrid_production"
    assert actual["pricing_policy_version"] == "entry_pricing_v2"
    assert actual["policy_chain_name"] == "default"
    assert actual["policy_chain_revision"].startswith("policy_graph_")
    assert actual["selected_action"] == "SEARCH_WEB"
    assert actual["seal_id"].startswith("seal_")
    selected = actual["scored_candidates"][1]
    assert selected["admission_score"] is None
    assert selected["admission_trace_hash"].startswith("sha256:")
    assert selected["admission_trace"]["objective_components"]["objective_bps"] > 0
    assert selected["effect_vector"]["capability_class"] == "external_read"
    assert actual["scored_candidates"][1]["final_action"]["action_type"] == "SEARCH_WEB"
    assert actual["scored_candidates"][1]["policy_trace"][0]["policy_name"] == "pii_guard"
