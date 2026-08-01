from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from velvet import ToolRiskClass, VelvetMCP, VelvetRope, VelvetToolCall, VelvetToolPolicy
from velvet.rope import VelvetWarrant

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "velvet_rope" / "warrant.schema.json"


def test_warrant_schema_validates_allow_block_escalate() -> None:
    validator = _validator()
    allow = _selected_warrant(
        VelvetMCP(
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
    )
    block = _selected_warrant(
        VelvetMCP().authorize(
            VelvetToolCall(
                server="filesystem",
                tool="delete_file",
                arguments={"path": "customer-secret.txt"},
            )
        )
    )
    escalate = _selected_warrant(
        VelvetMCP(
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
    )

    for payload in (allow, block, escalate):
        validator.validate(payload)
        assert payload["warrant_id"].startswith("wrnt_")
        assert VelvetWarrant.verify_payload_hash(payload)

    assert allow["decision"] == "execute"
    assert not allow["approval_required"]
    assert block["decision"] == "block"
    assert not block["approval_required"]
    assert escalate["decision"] == "escalate"
    assert escalate["approval_required"]


def test_warrant_id_and_hash_are_stable_for_same_decision() -> None:
    policy = VelvetToolPolicy(
        server="servicenow",
        tool="search_change_requests",
        risk_class=ToolRiskClass.LOW,
        expected_improvement=0.9,
        novelty=0.52,
        confidence=0.84,
    )
    call = VelvetToolCall(
        server="servicenow",
        tool="search_change_requests",
        arguments={"query": "service=payments state=open"},
    )
    one = _selected_warrant(
        VelvetMCP(
            rope=VelvetRope(policy_dir="examples/mcp/policies", chain="mcp_demo"),
            policies=(policy,),
        ).authorize(call)
    )
    two = _selected_warrant(
        VelvetMCP(
            rope=VelvetRope(policy_dir="examples/mcp/policies", chain="mcp_demo"),
            policies=(policy,),
        ).authorize(call)
    )

    assert one["warrant_id"] == two["warrant_id"]
    assert one["warrant_hash"] == two["warrant_hash"]
    assert one["arguments_hash"] == two["arguments_hash"]


def test_warrant_hash_and_signature_fail_after_tamper() -> None:
    decision = VelvetMCP().authorize(
        VelvetToolCall(server="filesystem", tool="delete_file", arguments={"path": "target-file"})
    )
    selected = decision.selected_warrant
    assert selected is not None
    signed = selected.sign("local-demo-secret", signing_key_id="demo-key-1")
    payload = signed.to_dict()

    _validator().validate(payload)
    assert signed.verify_hash()
    assert signed.verify_signature("local-demo-secret")
    assert VelvetWarrant.verify_payload_hash(payload)
    assert VelvetWarrant.verify_payload_signature(payload, "local-demo-secret")

    tampered = dict(payload)
    tampered["reason"] = "tampered reason"
    assert VelvetWarrant.compute_hash_for_payload(tampered) != payload["warrant_hash"]
    assert not VelvetWarrant.verify_payload_hash(tampered)
    assert not VelvetWarrant.verify_payload_signature(tampered, "local-demo-secret")

    extra_field_tampered = dict(payload)
    extra_field_tampered["entry_price"] = 1.0
    assert VelvetWarrant.compute_hash_for_payload(extra_field_tampered) == payload["warrant_hash"]
    assert VelvetWarrant.verify_payload_hash(extra_field_tampered)


def test_warrant_hashes_sensitive_arguments_without_exposing_raw_values() -> None:
    decision = VelvetMCP().authorize(
        VelvetToolCall(
            server="gmail",
            tool="send",
            arguments={
                "to": "customer@example.com",
                "body": "secret-token-123",
            },
        )
    )
    payload = _selected_warrant(decision)
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["arguments_hash"]
    assert "customer@example.com" not in serialized
    assert "secret-token-123" not in serialized


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    return validator


def _selected_warrant(decision: Any) -> dict[str, Any]:
    selected = decision.selected_warrant
    assert selected is not None
    return cast(dict[str, Any], selected.to_dict())
