from __future__ import annotations

from pathlib import Path

from velvet import MemoryEngine, Router
from velvet.thread_log import ThreadLogger, redact_secrets
from velvet.types import DecisionType


def test_memory_stores_durable_low_sensitivity_preference() -> None:
    decision = MemoryEngine().evaluate_candidate(
        "User prefers Velvet framed as a control plane, not a framework.",
        {"project": "Velvet", "memory_type": "project_positioning"},
    )
    assert decision.store
    assert decision.decision == DecisionType.EXECUTE
    assert decision.memory_object is not None


def test_sensitive_memory_requires_approval() -> None:
    decision = MemoryEngine().evaluate_candidate(
        "My API key is secret-test-value.",
        {"project": "Velvet"},
    )
    assert not decision.store
    assert decision.decision == DecisionType.ASK_APPROVAL


def test_trivial_memory_is_rejected() -> None:
    decision = MemoryEngine().evaluate_candidate(
        "I had toast today.",
        {"memory_candidate_value": 0.10},
    )
    assert not decision.store
    assert decision.decision == DecisionType.SKIP


def test_thread_logger_redacts_secret_fields_and_writes_v9(tmp_path: Path) -> None:
    thread_path = tmp_path / "thread.jsonl"
    Router().decide(
        state={
            "user_request": "What is safe to answer?",
            "api_key": "secret-value",
            "expected_action": "ANSWER_DIRECTLY",
        },
        candidates=[
            {
                "action_type": "ANSWER_DIRECTLY",
                "metadata": {"non_budget_affecting": True},
            }
        ],
        thread_logger=ThreadLogger(thread_path),
    )
    records = list(ThreadLogger.read(thread_path))
    assert records[0]["state"]["api_key"] == "[REDACTED]"
    assert records[0]["selected_action"] == "ANSWER_DIRECTLY"
    assert records[0]["schema_version"] == "9.0"
    assert records[0]["evaluation_context"]["expected_action"] == "ANSWER_DIRECTLY"
    assert records[0]["pricing_policy_name"] == "hybrid_production"
    assert (
        records[0]["scored_candidates"][0]["admission_trace"]["selected_decision"]
        == "answer_directly"
    )
    assert records[0]["scored_candidates"][0]["effect_vector"]["capability_class"] == "read_only"
    assert records[0]["seal_id"].startswith("seal_")


def test_redaction_primitive_is_rust_backed() -> None:
    assert redact_secrets(
        {"api_key": "secret", "nested": {"Authorization": "bearer x"}, "safe": "ok"}
    ) == {
        "api_key": "[REDACTED]",
        "nested": {"Authorization": "[REDACTED]"},
        "safe": "ok",
    }
