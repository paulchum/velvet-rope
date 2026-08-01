from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from velvet import (
    ActionType,
    AdmissionDecision,
    CandidateAction,
    DecisionType,
    ToolRiskClass,
    VelvetMCP,
    VelvetRope,
    VelvetToolCall,
    VelvetToolPolicy,
)
from velvet.ledger import seal_thread_decision, validate_thread_file
from velvet.thread_log import ThreadLogger

NON_BUDGET = {"non_budget_affecting": True}


def test_velvet_rope_returns_proof_for_selected_action() -> None:
    decision = VelvetRope().decide(
        {"freshness_required": True, "user_request": "latest agent security news"},
        [
            CandidateAction(ActionType.ANSWER_DIRECTLY, metadata=NON_BUDGET),
            CandidateAction(
                ActionType.SEARCH_WEB,
                expected_improvement=0.95,
                novelty=0.9,
                confidence=0.9,
                cost_overrides={"api_calls": 0.0, "latency": 0.0},
                risk_overrides={"source_quality_risk": 0.0},
                metadata=NON_BUDGET,
            ),
        ],
    )

    assert decision.decision.action_type == ActionType.SEARCH_WEB
    assert decision.selected_warrant is not None
    assert decision.selected_warrant.action_type == ActionType.SEARCH_WEB
    assert decision.selected_warrant.clears_rope
    assert decision.selected_warrant.final_lambda is not None
    assert decision.selected_warrant.scarcity_pressure is not None


def test_velvet_mcp_blocks_unlisted_tool_before_routing() -> None:
    decision = VelvetMCP().authorize(
        VelvetToolCall(server="filesystem", tool="delete_file", arguments={"path": "target-file"})
    )

    assert decision.product_surface == "velvet_mcp"
    assert decision.decision.decision == DecisionType.BLOCK
    assert decision.to_dict()["seal_id"].startswith("seal_velvet_mcp.block_")
    assert decision.selected_warrant is not None
    assert decision.selected_warrant.policy_reasons == ("velvet_mcp.list",)
    denied_tool = decision.selected_warrant.jurisdiction_evidence[0]["details"]["tool"]
    assert denied_tool == "filesystem/delete_file"
    assert decision.selected_warrant.pricing_status == "denied_at_rope"
    assert decision.selected_warrant.risk_class == "unlisted"


def test_velvet_mcp_block_does_not_call_rope() -> None:
    class SpyRope(VelvetRope):
        called: bool

        def __init__(self) -> None:
            self.called = False

        def decide(
            self,
            state: Mapping[str, object],
            candidates: Iterable[CandidateAction | ActionType | str | Mapping[str, object]],
            *,
            thread_logger: ThreadLogger | None = None,
            product_surface: str = "velvet_rope",
        ) -> AdmissionDecision:
            del state, candidates, thread_logger, product_surface
            self.called = True
            raise AssertionError("unlisted MCP tools must not enter routing")

    rope = SpyRope()
    decision = VelvetMCP(rope=rope).authorize(
        VelvetToolCall(server="servicenow", tool="delete_change_request")
    )

    assert decision.decision.decision == DecisionType.BLOCK
    assert not rope.called


def test_velvet_mcp_manual_block_writes_replayable_thread(tmp_path: Any) -> None:
    thread_path = tmp_path / "mcp_thread.jsonl"
    decision = VelvetMCP().authorize(
        VelvetToolCall(server="servicenow", tool="delete_change_request"),
        thread_logger=ThreadLogger(thread_path),
    )

    assert decision.decision.decision == DecisionType.BLOCK
    records = list(ThreadLogger.read(thread_path))
    assert len(records) == 1
    assert records[0]["metadata"]["record_kind"] == "velvet_mcp.manual_block.v1"
    assert records[0]["selected_action"] == "CALL_TOOL"
    assert records[0]["seal_id"] == decision.decision.seal_id
    assert validate_thread_file(thread_path)["status"] == "pass"

    replay = seal_thread_decision(thread_path, str(decision.decision.seal_id))
    assert replay["status"] == "pass"
    assert replay["decision"] == "block"


def test_velvet_mcp_routes_listed_tool_with_jurisdiction_evidence() -> None:
    decision = VelvetMCP(
        policies=(
            VelvetToolPolicy(
                server="linear",
                tool="create_issue",
                risk_class=ToolRiskClass.HIGH,
            ),
        )
    ).authorize(
        VelvetToolCall(
            server="linear",
            tool="create_issue",
            arguments={"title": "Investigate agent routing regression"},
        )
    )

    assert decision.decision.action_type == ActionType.CALL_TOOL
    assert decision.decision.decision == DecisionType.ESCALATE
    assert decision.selected_warrant is not None
    assert "escalation_gate.sensitive_action" in decision.selected_warrant.policy_reasons
    assert decision.selected_warrant.tool_key == "linear/create_issue"
    assert decision.selected_warrant.risk_class == "high"
    assert decision.selected_warrant.entry_price is not None
    assert decision.selected_warrant.final_lambda == decision.selected_warrant.entry_price
    assert decision.selected_warrant.scarcity_pressure is not None
    assert decision.selected_warrant.jurisdiction_evidence
    assert decision.selected_warrant.pricing_status == "admission_optimizer"


def test_velvet_mcp_blocks_drifted_schema_before_routing() -> None:
    decision = VelvetMCP(
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="search_records",
                risk_class=ToolRiskClass.LOW,
                metadata={
                    "approval_tier": "auto_approve",
                    "schema_status": "drifted",
                    "schema_hash": "current-hash",
                    "tool_schema_hash": "current-hash",
                    "approved_schema_hash": "approved-hash",
                    "tool_id": "mcp:servicenow/search_records",
                    "owner": "platform",
                    "environment": "production",
                    "data_class": "operational",
                },
            ),
        )
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="search_records",
            arguments={"query": "state=open"},
        )
    )

    assert decision.decision.decision == DecisionType.BLOCK
    assert decision.selected_warrant is not None
    assert decision.selected_warrant.policy_reasons == ("velvet_mcp.schema_drift",)
    evidence = decision.selected_warrant.jurisdiction_evidence[0]
    assert evidence["details"]["schema_status"] == "drifted"
    assert evidence["details"]["approved_schema_hash"] == "approved-hash"


def test_velvet_mcp_read_only_proof_shape_is_buyer_legible() -> None:
    decision = VelvetMCP(
        rope=VelvetRope(policy_dir="examples/mcp/policies", chain="mcp_demo"),
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="search_change_requests",
                risk_class=ToolRiskClass.LOW,
                expected_improvement=0.9,
                novelty=0.52,
                confidence=0.84,
            ),
        ),
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="search_change_requests",
            arguments={"query": "service=payments state=open"},
        )
    )

    payload: dict[str, Any] = decision.to_dict()
    proof = payload["selected_warrant"]
    assert payload["seal_id"].startswith("seal_")
    assert payload["decision"]["decision"] == "execute"
    assert proof["tool_key"] == "servicenow/search_change_requests"
    assert proof["mcp_server"] == "servicenow"
    assert proof["mcp_tool"] == "search_change_requests"
    assert proof["risk_class"] == "low"
    assert proof["entry_price"] == proof["final_lambda"]
    assert proof["entry_price"] > 0.0
    assert proof["scarcity_pressure"] is not None
    assert proof["policy_reasons"]
    assert proof["jurisdiction_evidence"]
    assert proof["selected"]
