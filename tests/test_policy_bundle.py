from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from velvet import ActionType, CandidateAction, DecisionType, VelvetRope
from velvet.ledger import read_ledger_records
from velvet.mcp import DirectVelvetMCPAdapter
from velvet.policy_bundle import (
    DEMO_POLICY_BUNDLE_SIGNING_KEY,
    PolicyBundleExpired,
    PolicyBundleInvalid,
    PolicyBundleTampered,
    create_policy_bundle_payload,
    load_policy_bundle,
    sign_policy_bundle,
    verify_policy_bundle,
    write_signed_policy_bundle,
)
from velvet.policy_simulation import simulate_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "examples" / "mcp" / "policies"
MCP_LIST = ROOT / "examples" / "mcp" / "list.json"
SCHEMA_PATH = ROOT / "schemas" / "velvet_rope" / "policy_bundle.v1.schema.json"
DEMO_KEY = DEMO_POLICY_BUNDLE_SIGNING_KEY


def test_policy_bundle_schema_accepts_signed_bundle(tmp_path: Path) -> None:
    bundle_path = tmp_path / "policy_bundle.json"
    write_signed_policy_bundle(
        bundle_path,
        policy_dir=POLICY_DIR,
        chain="mcp_demo",
        signing_key=DEMO_KEY,
    )
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload)
    )

    assert errors == []
    verified = load_policy_bundle(bundle_path, signing_key=DEMO_KEY)
    assert verified.policy_hash == payload["policy_hash"]
    assert verified.policy_version == "mcp_demo.bundle.v1"


def test_policy_bundle_rejects_tampering_and_expiry() -> None:
    payload = sign_policy_bundle(
        create_policy_bundle_payload(
            policy_dir=POLICY_DIR,
            chain="mcp_demo",
            expires_at="2999-01-01T00:00:00Z",
        ),
        signing_key=DEMO_KEY,
    )
    tampered = json.loads(json.dumps(payload))
    tampered["policy_files"][0]["content"] += "\n# tampered\n"

    with pytest.raises(PolicyBundleTampered):
        verify_policy_bundle(tampered, signing_key=DEMO_KEY)

    expired = sign_policy_bundle(
        create_policy_bundle_payload(
            policy_dir=POLICY_DIR,
            chain="mcp_demo",
            expires_at="2000-01-01T00:00:00Z",
        ),
        signing_key=DEMO_KEY,
    )
    with pytest.raises(PolicyBundleExpired):
        verify_policy_bundle(expired, signing_key=DEMO_KEY)
    assert verify_policy_bundle(expired, signing_key=DEMO_KEY, allow_expired=True).expired


def test_policy_bundle_rejects_missing_signing_key(tmp_path: Path) -> None:
    bundle_path = tmp_path / "policy_bundle.json"
    with pytest.raises(PolicyBundleInvalid):
        write_signed_policy_bundle(bundle_path, policy_dir=POLICY_DIR, chain="mcp_demo")
    payload = create_policy_bundle_payload(policy_dir=POLICY_DIR, chain="mcp_demo")
    with pytest.raises(PolicyBundleInvalid):
        sign_policy_bundle(payload)


def test_demo_loads_signed_bundle_and_ledger_records_policy_hash(tmp_path: Path) -> None:
    bundle_path = tmp_path / "policy_bundle.json"
    write_signed_policy_bundle(
        bundle_path,
        policy_dir=POLICY_DIR,
        chain="mcp_demo",
        signing_key=DEMO_KEY,
    )
    bundle = load_policy_bundle(bundle_path, signing_key=DEMO_KEY)
    thread_path = tmp_path / "thread.jsonl"
    ledger_path = tmp_path / "ledger.vledger"
    adapter = DirectVelvetMCPAdapter.from_list_file(
        MCP_LIST,
        policy_bundle=bundle_path,
        policy_bundle_signing_key=DEMO_KEY,
        require_policy_bundle=True,
    )

    output = adapter.authorize(
        {
            "server": "servicenow",
            "tool": "search_change_requests",
            "arguments": {"query": "service=payments state=open"},
        },
        thread_path=thread_path,
        ledger_path=ledger_path,
    )

    warrant = output["admission_decision"]["selected_warrant"]
    expected_policy_hash = f"sha256:{bundle.policy_hash}"
    assert warrant["policy_hash"] == expected_policy_hash
    assert warrant["policy_version"] == bundle.policy_version
    record = next(iter(read_ledger_records(ledger_path)))
    assert record["policy_hash"] == expected_policy_hash
    assert record["policy_version"] == bundle.policy_version


def test_tampered_or_missing_required_bundle_fails_closed(tmp_path: Path) -> None:
    bundle_path = tmp_path / "policy_bundle.json"
    write_signed_policy_bundle(
        bundle_path,
        policy_dir=POLICY_DIR,
        chain="mcp_demo",
        signing_key=DEMO_KEY,
    )
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    payload["policy_files"][0]["content"] += "\n# tampered\n"
    bundle_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    adapter = DirectVelvetMCPAdapter.from_list_file(
        MCP_LIST,
        policy_bundle=bundle_path,
        policy_bundle_signing_key=DEMO_KEY,
        require_policy_bundle=True,
    )
    tampered_output = adapter.authorize(
        {"server": "servicenow", "tool": "search_change_requests", "arguments": {}}
    )
    tampered_warrant = tampered_output["admission_decision"]["selected_warrant"]
    assert tampered_output["admission_decision"]["decision"]["decision"] == "block"
    assert tampered_warrant["policy_hash"].startswith("sha256:")
    assert tampered_warrant["policy_version"] == "unavailable"

    missing_adapter = DirectVelvetMCPAdapter.from_list_file(
        MCP_LIST,
        policy_bundle=tmp_path / "missing.json",
        policy_bundle_signing_key=DEMO_KEY,
        require_policy_bundle=True,
    )
    missing_output = missing_adapter.authorize(
        {"server": "servicenow", "tool": "create_change_request", "arguments": {}}
    )
    assert missing_output["admission_decision"]["decision"]["decision"] == "block"
    assert "Policy bundle unavailable" in missing_output["admission_decision"]["decision"]["reason"]


def test_expired_degraded_mode_blocks_consequential_actions(tmp_path: Path) -> None:
    expired_payload = sign_policy_bundle(
        create_policy_bundle_payload(
            policy_dir=POLICY_DIR,
            chain="mcp_demo",
            expires_at="2000-01-01T00:00:00Z",
        ),
        signing_key=DEMO_KEY,
    )
    bundle_path = tmp_path / "expired_bundle.json"
    bundle_path.write_text(json.dumps(expired_payload, sort_keys=True), encoding="utf-8")
    rope = VelvetRope(
        policy_bundle=bundle_path,
        policy_bundle_signing_key=DEMO_KEY,
        require_policy_bundle=True,
        allow_expired_policy_degraded=True,
    )

    blocked = rope.decide(
        {},
        [CandidateAction(ActionType.EXECUTE_CODE, description="run production migration")],
    )
    assert blocked.decision.decision == DecisionType.BLOCK
    assert blocked.selected_warrant is not None
    assert blocked.selected_warrant.policy_hash == expired_payload["policy_hash"]

    read_only = rope.decide(
        {},
        [
            CandidateAction(
                ActionType.ANSWER_DIRECTLY,
                metadata={"non_budget_affecting": True},
            )
        ],
    )
    assert read_only.decision.decision != DecisionType.BLOCK


def test_policy_replay_compares_ledger_hash_to_simulated_bundle(tmp_path: Path) -> None:
    bundle_path = tmp_path / "policy_bundle.json"
    write_signed_policy_bundle(
        bundle_path,
        policy_dir=POLICY_DIR,
        chain="mcp_demo",
        signing_key=DEMO_KEY,
    )
    thread_path = tmp_path / "thread.jsonl"
    ledger_path = tmp_path / "ledger.vledger"
    adapter = DirectVelvetMCPAdapter.from_list_file(
        MCP_LIST,
        policy_bundle=bundle_path,
        policy_bundle_signing_key=DEMO_KEY,
        require_policy_bundle=True,
    )
    adapter.authorize(
        {
            "server": "servicenow",
            "tool": "search_change_requests",
            "arguments": {"query": "service=payments state=open"},
        },
        thread_path=thread_path,
        ledger_path=ledger_path,
    )

    same = simulate_policy(
        thread_path,
        policy_bundle=bundle_path,
        policy_bundle_signing_key=DEMO_KEY,
        ledger_path=ledger_path,
    )
    assert same.to_dict()["summary"]["policy_hash_changed"] == 0

    changed_path = tmp_path / "changed_policy_bundle.json"
    write_signed_policy_bundle(
        changed_path,
        policy_dir=POLICY_DIR,
        chain="mcp_demo",
        signing_key=DEMO_KEY,
        tool_schema_hashes={"servicenow/search_change_requests": "f" * 64},
    )
    changed = simulate_policy(
        thread_path,
        policy_bundle=changed_path,
        policy_bundle_signing_key=DEMO_KEY,
        ledger_path=ledger_path,
    )
    assert changed.to_dict()["summary"]["policy_hash_changed"] == 1
