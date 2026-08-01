from __future__ import annotations

import json
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from velvet.agent_registry import AgentRegistry, SchemaStatus
from velvet.approval_workbench import create_approval_app
from velvet.approvals import (
    APPROVAL_REQUEST_SCHEMA_VERSION,
    ApprovalReceipt,
    ApprovalRequest,
    ApprovalSnapshot,
    ApprovalStatus,
    ApprovalStore,
    ApprovalValidationError,
    arguments_hash,
    redact_sensitive_value,
    request_hash,
)
from velvet.cli import main
from velvet.contracts import AdmissionContract
from velvet.gateway import CallableDispatcher, InlineGateway, InlineGatewayRequest

ROOT = Path(__file__).resolve().parents[1]


def _schema_inventory(*, changed: bool = False, include_create: bool = True) -> dict[str, object]:
    search_schema: dict[str, object] = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    }
    if changed:
        search_schema["properties"] = {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1},
        }
    tools: list[dict[str, object]] = [
        {
            "server": "servicenow",
            "tool": "search_records",
            "risk_class": "low",
            "approval_tier": "auto_approve",
            "risk_rationale": "Read-only enterprise record lookup.",
            "owner": "platform",
            "environment": "production",
            "data_class": "operational",
            "input_schema": search_schema,
        }
    ]
    if include_create:
        tools.append(
            {
                "server": "servicenow",
                "tool": "create_record",
                "risk_class": "high",
                "approval_tier": "concierge_review",
                "risk_rationale": "Creates external operational records.",
                "owner": "platform",
                "environment": "production",
                "data_class": "operational",
                "inputSchema": {
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"],
                },
            }
        )
    else:
        tools.append(
            {
                "server": "linear",
                "tool": "audit_issue",
                "risk_class": "low",
                "approval_tier": "auto_approve",
                "risk_rationale": "Read-only audit lookup for issue state.",
                "owner": "platform",
                "environment": "production",
                "data_class": "operational",
                "parameters": {
                    "type": "object",
                    "properties": {"issue_id": {"type": "string"}},
                    "required": ["issue_id"],
                },
            }
        )
    return {"version": "velvet.mcp_inventory.test.v1", "tools": tools}


def _approved_schema_registry() -> AgentRegistry:
    registry = AgentRegistry().import_mcp_tools_with_schema(
        _schema_inventory(),
        agent_id="release-agent",
        owner="platform",
        environment="production",
    )
    for tool in registry.tools:
        registry = registry.approve_schema_hash(tool.tool_id, tool.schema_hash)
    return registry


def _approval_fixture(tmp_path: Path) -> tuple[ApprovalStore, ApprovalRequest, dict[str, object]]:
    store = ApprovalStore(tmp_path / "approvals.json")
    original_request: dict[str, object] = {
        "proposed_action": {
            "surface": "mcp",
            "server": "servicenow",
            "tool": "create_change_request",
            "arguments": {
                "service": "payments",
                "summary": "Approve production deploy for routing fix",
            },
            "actor_id": "platform-lead@example.com",
            "agent_id": "release-agent",
            "tenant_id": "tenant-a",
            "environment": "production",
        },
        "payload": {
            "arguments": {
                "service": "payments",
                "summary": "Approve production deploy for routing fix",
            }
        },
    }
    now = datetime.now(tz=UTC)
    approval_request = ApprovalRequest(
        schema_version=APPROVAL_REQUEST_SCHEMA_VERSION,
        approval_request_id=f"apr_{request_hash(original_request)[:16]}",
        tenant_id="tenant-a",
        environment="production",
        subject_id="platform-lead@example.com",
        user_id="platform-lead@example.com",
        agent_id="release-agent",
        tool_key="servicenow/create_change_request",
        request_hash=request_hash(original_request),
        arguments_hash=arguments_hash(
            cast(Mapping[str, object], original_request["payload"])["arguments"]
        ),
        policy_hash=request_hash({"policy": "mcp_demo"}),
        policy_version="mcp_demo",
        tool_schema_hash=request_hash({"schema": "servicenow/create_change_request"}),
        reason="Requires change-manager approval.",
        created_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        decision="escalate",
        risk_class="high",
        requester="velvet",
        action_type="CALL_TOOL",
        original_request=original_request,
        redacted_request=redact_sensitive_value(original_request),
    )
    store.save(ApprovalSnapshot(requests=(approval_request,), receipts=()))
    return store, approval_request, original_request


def _expect_approval_validation_error(
    store: ApprovalStore,
    receipt: ApprovalReceipt,
    approval_request: ApprovalRequest,
    message: str,
    **kwargs: Any,
) -> None:
    with pytest.raises(ApprovalValidationError, match=message):
        store.validate_receipt_for_request(receipt, approval_request, **kwargs)


def _inline_search_request(*, request_id: str = "req-search") -> InlineGatewayRequest:
    return InlineGatewayRequest(
        request_id=request_id,
        proposed_action={
            "surface": "mcp",
            "server": "servicenow",
            "tool": "search_change_requests",
            "arguments": {"query": "service=payments state=open"},
            "actor_id": "platform-lead@example.com",
            "agent_id": "release-agent",
            "tenant_id": "tenant-a",
            "environment": "production",
        },
        context={"tenant_id": "tenant-a", "environment": "production"},
    )


def _inline_shell_request(*, request_id: str = "req-shell") -> InlineGatewayRequest:
    return InlineGatewayRequest(
        request_id=request_id,
        replay_id="shell-code-inline-gateway-test",
        proposed_action={
            "surface": "shell_code",
            "operation": "deploy",
            "command": "python scripts/rotate_service_token.py --service payments --dry-run",
            "cwd": "/srv/velvet/pilot",
            "env": {"VELVET_DEMO_MODE": "dry_run", "SERVICE_TOKEN": "secret-token"},
            "external_party": "production-payments",
            "actor_id": "platform-lead@example.com",
            "agent_id": "release-agent",
            "tenant_id": "tenant-a",
            "environment": "production",
            "boundary_key": "shell:payments:release",
            "target_resource": "shell_code:payments-release",
        },
        context={
            "tenant_id": "tenant-a",
            "environment": "production",
            "user_id": "platform-lead@example.com",
        },
    )


def test_inline_gateway_executes_only_after_canonical_admission(tmp_path: Path) -> None:
    ledger_path = tmp_path / "inline_gateway.jsonl"
    calls: list[str] = []

    def handler(action: Any, _context: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(action.canonical_action_hash)
        return {"observed_hash": action.canonical_action_hash}

    gateway = InlineGateway(
        ledger_path=ledger_path,
        dispatchers={"mcp": CallableDispatcher("fake-mcp", handler)},
    )

    result = gateway.run(_inline_search_request())

    assert result.decision.decision.value == "ADMITTED"
    canonical_hash = result.decision.canonical_action.canonical_action_hash
    assert calls == [canonical_hash]
    assert result.execution_receipt.outcome == "succeeded"
    assert result.execution_receipt.output["metadata"]["canonical_action_hash"] == canonical_hash
    assert result.execution_receipt.permit_id.startswith("vpermit_")
    records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [record["phase"] for record in records] == ["pre_execution", "post_execution"]
    assert {record["canonical_action_hash"] for record in records} == {canonical_hash}


def test_inline_gateway_non_admitted_paths_do_not_dispatch(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(action: Any, _context: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(action.canonical_action_hash)
        return {}

    dispatcher = CallableDispatcher("fake", handler)

    refused = InlineGateway(
        contract=replace(
            AdmissionContract(),
            default_authority_budget=1,
            execute_fallback_on_insufficient_budget=False,
        ),
        dispatchers={"sql": dispatcher},
    ).run(
        InlineGatewayRequest(
            proposed_action={
                "surface": "sql",
                "sql": "DROP TABLE production_accounts",
                "actor_id": "dba@example.com",
                "agent_id": "migration-agent",
            }
        )
    )
    assert refused.decision.decision.value == "REFUSED"
    assert refused.execution_receipt.outcome == "rejected"

    escalated = InlineGateway(dispatchers={"connector": dispatcher}).run(
        InlineGatewayRequest(
            proposed_action={
                "surface": "connector",
                "provider": "gmail",
                "connector": "send_email",
                "operation": "send_email",
                "arguments": {"to": "customer@example.com"},
                "external_party": "customer@example.com",
                "actor_id": "support@example.com",
                "agent_id": "support-agent",
            }
        )
    )
    assert escalated.decision.decision.value == "ESCALATED"
    assert escalated.execution_receipt.outcome == "rejected"

    masked = InlineGateway(dispatchers={"sql": dispatcher}).run(
        InlineGatewayRequest(
            proposed_action={
                "surface": "sql",
                "sql": "DELETE FROM",
                "actor_id": "dba@example.com",
                "agent_id": "migration-agent",
            }
        )
    )
    assert masked.decision.decision.value == "MASKED_ACTION_FAILURE"
    assert masked.execution_receipt.outcome == "rejected"
    assert calls == []


def test_inline_gateway_missing_dispatcher_replay_and_permit_mismatch(tmp_path: Path) -> None:
    missing = InlineGateway().run(_inline_search_request(request_id="req-missing"))
    assert missing.decision.decision.value == "ADMITTED"
    assert missing.execution_receipt.outcome == "rejected"
    assert "no dispatcher" in str(missing.execution_receipt.reason)

    calls: list[str] = []

    def handler(action: Any, _context: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(action.canonical_action_hash)
        return {}

    gateway = InlineGateway(
        dispatchers={"mcp": CallableDispatcher("fake-mcp", handler)},
    )
    decision = gateway.authorize(_inline_search_request(request_id="req-permit"))
    tampered_action = replace(decision.canonical_action, operation="tampered")
    tampered_decision = replace(
        decision,
        admission_outcome=replace(
            decision.admission_outcome,
            canonical_action=tampered_action,
        ),
    )

    mismatch = gateway.dispatch_admitted(tampered_decision)
    assert mismatch.outcome == "rejected"
    assert "decision_artifact_action_mismatch" in str(mismatch.reason)
    assert calls == []

    first = gateway.dispatch_admitted(decision)
    second = gateway.dispatch_admitted(decision)
    assert first.outcome == "succeeded"
    assert second.outcome == "rejected"
    assert "permit_replay" in str(second.reason)
    assert len(calls) == 1


def test_inline_gateway_approved_shell_code_rejects_drift_after_approval(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "inline_gateway.jsonl"
    approvals = ApprovalStore(tmp_path / "approvals.json")
    calls: list[str] = []

    def handler(action: Any, _context: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(action.canonical_action_hash)
        return {"observed_hash": action.canonical_action_hash}

    gateway = InlineGateway(
        ledger_path=ledger_path,
        approval_store=approvals,
        dispatchers={"shell_code": CallableDispatcher("shell-dry-run", handler)},
    )

    exact_decision = gateway.authorize(_inline_shell_request(request_id="req-shell-exact"))
    assert exact_decision.decision.value == "ESCALATED"
    assert exact_decision.approval_request is not None
    original_env = cast(
        Mapping[str, object],
        cast(
            Mapping[str, object],
            exact_decision.approval_request["original_request"],
        )["proposed_action"],
    )["env"]
    redacted_env = cast(
        Mapping[str, object],
        cast(
            Mapping[str, object],
            exact_decision.approval_request["redacted_request"],
        )["proposed_action"],
    )["env"]
    assert cast(Mapping[str, object], original_env)["SERVICE_TOKEN"] == "secret-token"  # noqa: S105
    assert cast(Mapping[str, object], redacted_env)["SERVICE_TOKEN"] == "[REDACTED]"  # noqa: S105
    exact_receipt = approvals.decide(
        str(exact_decision.approval_request["approval_request_id"]),
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )
    exact = gateway.run_approved(exact_decision, exact_receipt.approval_receipt_id)

    assert exact.execution_receipt.outcome == "succeeded"
    assert calls == [exact_decision.canonical_action.canonical_action_hash]

    drift_decision = gateway.authorize(_inline_shell_request(request_id="req-shell-drift"))
    assert drift_decision.decision.value == "ESCALATED"
    assert drift_decision.approval_request is not None
    drift_receipt = approvals.decide(
        str(drift_decision.approval_request["approval_request_id"]),
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )
    drifted_action = dict(drift_decision.request.proposed_action)
    drifted_action["command"] = (
        "python scripts/rotate_service_token.py --service payments --no-dry-run"
    )
    drift = gateway.run_approved(
        drift_decision,
        drift_receipt.approval_receipt_id,
        proposed_action=drifted_action,
    )

    assert drift.execution_receipt.outcome == "rejected"
    assert drift.execution_receipt.reason == "approval canonical action hash mismatch"
    assert calls == [exact_decision.canonical_action.canonical_action_hash]
    snapshot = approvals.load()
    receipt_by_id = {item.approval_receipt_id: item for item in snapshot.receipts}
    assert receipt_by_id[exact_receipt.approval_receipt_id].used_at is not None
    assert receipt_by_id[drift_receipt.approval_receipt_id].used_at is None

    records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [record["phase"] for record in records] == [
        "pre_execution",
        "post_execution",
        "pre_execution",
        "post_execution",
    ]
    assert records[-1]["upstream_execution_status"] == "not_forwarded"


def test_approval_receipt_binds_exact_request_hash(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    assert store.validate_receipt_for_request(receipt, approval_request) == receipt
    with pytest.raises(ApprovalValidationError, match="request_hash"):
        store.validate_receipt_for_request(
            receipt,
            approval_request,
            request_hash_value=request_hash({"modified": True}),
        )


def test_approval_receipt_binds_arguments_hash(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    with pytest.raises(ApprovalValidationError, match="arguments_hash"):
        store.validate_receipt_for_request(
            receipt,
            approval_request,
            arguments_hash_value=arguments_hash({"summary": "changed"}),
        )


def test_approval_receipt_binds_identity_and_tool(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    for kwargs, message in (
        ({"tenant_id": "tenant-b"}, "tenant_id"),
        ({"environment": "staging"}, "environment"),
        ({"subject_id": "other@example.com"}, "subject_id"),
        ({"user_id": "other@example.com"}, "user_id"),
        ({"agent_id": "other-agent"}, "agent_id"),
        ({"tool_key": "servicenow/delete_change_request"}, "tool_key"),
    ):
        _expect_approval_validation_error(
            store,
            receipt,
            approval_request,
            message,
            **kwargs,
        )


def test_approval_receipt_binds_policy_and_schema(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    for kwargs, message in (
        ({"policy_hash": request_hash({"policy": "changed"})}, "policy_hash"),
        ({"policy_version": "changed-version"}, "policy_version"),
        ({"tool_schema_hash": request_hash({"schema": "changed"})}, "tool_schema_hash"),
    ):
        _expect_approval_validation_error(
            store,
            receipt,
            approval_request,
            message,
            **kwargs,
        )


def test_approval_receipt_expiry_fails(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    expired_request = replace(approval_request, expires_at="2020-01-01T00:00:00Z")
    receipt = ApprovalReceipt.from_request(
        expired_request,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    with pytest.raises(ApprovalValidationError, match="expired"):
        store.validate_receipt_for_request(receipt, expired_request)


def test_one_time_approval_receipt_cannot_be_redeemed_twice(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    redeemed = store.redeem_receipt_for_request(receipt, approval_request)
    assert redeemed.used_at is not None
    with pytest.raises(ApprovalValidationError, match="already been used"):
        store.redeem_receipt_for_request(receipt, approval_request)


def test_one_time_approval_receipt_redemption_is_atomic(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )

    def redeem_once() -> str:
        try:
            store.redeem_receipt_for_request(receipt, approval_request)
            return "redeemed"
        except ApprovalValidationError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: redeem_once(), range(2)))

    assert outcomes.count("redeemed") == 1
    assert sum("already been used" in outcome for outcome in outcomes) == 1


def test_modified_arguments_cannot_reuse_approval(tmp_path: Path) -> None:
    store, approval_request, original_request = _approval_fixture(tmp_path)
    receipt = store.decide(
        approval_request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )
    modified_request = dict(original_request)
    modified_payload = dict(cast(dict[str, object], modified_request["payload"]))
    modified_payload["arguments"] = {
        "service": "payments",
        "summary": "Changed after approval",
    }
    modified_request["payload"] = modified_payload

    with pytest.raises(ApprovalValidationError):
        store.validate_receipt_for_request(
            receipt,
            approval_request,
            original_request=modified_request,
        )


def test_approval_workbench_lists_pending_and_approves(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    client = TestClient(create_approval_app(store, allow_unauthenticated_local=True))

    list_response = client.get("/api/approvals")
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert list_payload["summary"]["pending"] == 1
    assert (
        list_payload["requests"][0]["approval_request_id"] == approval_request.approval_request_id
    )

    approve_response = client.post(
        f"/api/approvals/{approval_request.approval_request_id}/approve",
        json={"approver": "change-manager@example.com", "reason": "approved"},
    )
    assert approve_response.status_code == 200
    receipt_payload = approve_response.json()
    assert receipt_payload["approved"] is True
    assert receipt_payload["signature"]
    assert ApprovalReceipt.from_dict(receipt_payload).verify_signature()


def test_approval_workbench_requires_auth_and_csrf(tmp_path: Path) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    with pytest.raises(ValueError, match="requires auth_token"):
        create_approval_app(store)

    client = TestClient(
        create_approval_app(
            store,
            auth_token="operator-token",  # noqa: S106
            csrf_secret="csrf-secret",  # noqa: S106
        )
    )

    assert client.get("/api/approvals").status_code == 401
    authorized = {"Authorization": "Bearer operator-token"}
    assert client.get("/api/approvals", headers=authorized).status_code == 200
    assert (
        client.post(
            f"/api/approvals/{approval_request.approval_request_id}/approve",
            headers=authorized,
            json={"approver": "change-manager@example.com", "reason": "approved"},
        ).status_code
        == 403
    )
    approved = client.post(
        f"/api/approvals/{approval_request.approval_request_id}/approve",
        headers={**authorized, "X-CSRF-Token": "csrf-secret"},
        json={"approver": "change-manager@example.com", "reason": "approved"},
    )
    assert approved.status_code == 200
    assert approved.json()["approved"] is True


def test_cli_approval_approve_and_deny_still_work(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store, approval_request, _ = _approval_fixture(tmp_path)
    approvals_path = store.path

    assert (
        main(
            [
                "approvals",
                "--approvals",
                str(approvals_path),
                "--list",
                "--json",
            ]
        )
        == 0
    )
    list_payload = json.loads(capsys.readouterr().out)
    assert list_payload["summary"]["pending"] == 1

    assert (
        main(
            [
                "approvals",
                "--approvals",
                str(approvals_path),
                "--approve",
                approval_request.approval_request_id,
                "--approver",
                "change-manager@example.com",
                "--reason",
                "approved",
                "--json",
            ]
        )
        == 0
    )
    approve_payload = json.loads(capsys.readouterr().out)
    assert approve_payload["approved"] is True

    deny_store, deny_request, _ = _approval_fixture(tmp_path / "deny")
    assert (
        main(
            [
                "approvals",
                "--approvals",
                str(deny_store.path),
                "--deny",
                deny_request.approval_request_id,
                "--approver",
                "change-manager@example.com",
                "--reason",
                "denied",
                "--json",
            ]
        )
        == 0
    )
    deny_payload = json.loads(capsys.readouterr().out)
    assert deny_payload["approved"] is False


def test_schema_aware_registry_tracks_approval_and_drift() -> None:
    registry = AgentRegistry().import_mcp_tools_with_schema(
        _schema_inventory(),
        agent_id="release-agent",
        owner="platform",
        environment="production",
    )
    search = registry.tool_by_mcp_key("servicenow", "search_records")
    assert search is not None
    assert search.schema_status == SchemaStatus.UNREVIEWED

    approved = registry.approve_schema_hash(search.tool_id, search.schema_hash)
    approved_search = approved.tool_by_mcp_key("servicenow", "search_records")
    assert approved_search is not None
    assert approved_search.schema_status == SchemaStatus.APPROVED
    assert approved_search.approved_schema_hash == approved_search.schema_hash

    changed = approved.import_mcp_tools_with_schema(
        _schema_inventory(changed=True, include_create=False),
        agent_id="release-agent",
        owner="platform",
        environment="production",
    )
    drifted = changed.tool_by_mcp_key("servicenow", "search_records")
    assert drifted is not None
    assert drifted.schema_status == SchemaStatus.DRIFTED
    assert drifted.approved_schema_hash == approved_search.schema_hash

    blocked = changed.block_tool("mcp:servicenow/search_records", reason="Retired API.")
    blocked_search = blocked.tool_by_mcp_key("servicenow", "search_records")
    assert blocked_search is not None
    assert blocked_search.schema_status == SchemaStatus.BLOCKED
    assert blocked_search.approval_tier.value == "blocked"

    fresh_changed = AgentRegistry().import_mcp_tools_with_schema(
        _schema_inventory(changed=True, include_create=False),
        agent_id="release-agent",
        owner="platform",
        environment="production",
    )
    diff = approved.diff_tool_inventory(fresh_changed)
    assert diff["summary"] == {"new_tools": 1, "removed_tools": 1, "schema_drift": 1}
    assert approved.detect_schema_drift(fresh_changed)[0]["tool_id"] == (
        "mcp:servicenow/search_records"
    )


def test_cli_agent_ops_commands(tmp_path: Path, capsys: object) -> None:
    registry_path = tmp_path / "registry.json"
    assert (
        main(
            [
                "registry",
                "--mcp-list",
                str(ROOT / "examples" / "mcp" / "list.json"),
                "--output",
                str(registry_path),
                "--json",
            ]
        )
        == 0
    )
    registry_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert registry_payload["summary"]["tools"] == 4

    request_path = tmp_path / "gateway_request.json"
    request_path.write_text(
        json.dumps(
            {
                "proposed_action": {
                    "surface": "mcp",
                    "server": "servicenow",
                    "tool": "search_change_requests",
                    "arguments": {"query": "service=payments state=open"},
                    "actor_id": "platform-lead@example.com",
                    "agent_id": "agent-1",
                    "tenant_id": "tenant-a",
                    "environment": "production",
                },
                "context": {"tenant_id": "tenant-a", "environment": "production"},
            }
        ),
        encoding="utf-8",
    )
    thread_path = tmp_path / "thread.jsonl"
    ledger_path = tmp_path / "ledger.vledger"
    approvals_path = tmp_path / "approvals.json"
    assert (
        main(
            [
                "gateway",
                "--request",
                str(request_path),
                "--registry",
                str(registry_path),
                "--thread",
                str(thread_path),
                "--ledger",
                str(ledger_path),
                "--approvals",
                str(approvals_path),
                "--policies-dir",
                str(ROOT / "examples" / "mcp" / "policies"),
                "--chain",
                "mcp_demo",
                "--json",
            ]
        )
        == 0
    )
    gateway_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert gateway_payload["decision"] == "ADMITTED"
    assert gateway_payload["canonical_action_hash"]
    assert gateway_payload["canonical_action"]["surface"] == "mcp"
    ledger_records = [
        json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()
    ]
    assert ledger_records[0]["canonical_action_hash"] == gateway_payload["canonical_action_hash"]


def test_cli_shell_code_demo_writes_protocol_agnostic_evidence(
    tmp_path: Path,
    capsys: object,
) -> None:
    output_dir = tmp_path / "shell-code-demo"
    assert (
        main(
            [
                "shell-code-demo",
                "--output-dir",
                str(output_dir),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]

    assert payload["protocol_story"]["surface"] == "shell_code"
    assert payload["protocol_story"]["mcp_required"] is False
    assert payload["summary"]["exact_approved_dispatch"]["outcome"] == "succeeded"
    assert payload["summary"]["drift_after_approval"]["outcome"] in {
        "rejected",
        "failed_before_dispatch",
    }
    assert payload["controls"]["exact_action_binding"]["status"] == "pass"
    assert payload["controls"]["reject_on_drift_after_approval"]["status"] == "pass"
    assert payload["evidence_verification"]["status"] == "pass"

    ledger_path = Path(payload["artifacts"]["ledger_path"])
    approvals_path = Path(payload["artifacts"]["approvals_path"])
    markdown_path = Path(payload["artifacts"]["report_markdown_path"])
    assert ledger_path.exists()
    assert approvals_path.exists()
    assert markdown_path.exists()
    records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert {record["schema_version"] for record in records} == {
        "velvet.inline_gateway.ledger_record.v1"
    }
    assert records[-1]["upstream_execution_status"] == "not_forwarded"
    assert "surface: shell_code" in markdown_path.read_text(encoding="utf-8")


def test_cli_registry_diff_approve_schema_and_report(
    tmp_path: Path,
    capsys: object,
) -> None:
    registry = AgentRegistry().import_mcp_tools_with_schema(
        _schema_inventory(include_create=False),
        agent_id="release-agent",
        owner="platform",
        environment="production",
    )
    tool = registry.tool_by_mcp_key("servicenow", "search_records")
    assert tool is not None
    registry_path = registry.save(tmp_path / "registry.json")

    assert (
        main(
            [
                "registry",
                "approve-schema",
                "--registry",
                str(registry_path),
                "--tool",
                "mcp:servicenow/search_records",
                "--schema-hash",
                tool.schema_hash,
                "--json",
            ]
        )
        == 0
    )
    approved_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    approved_tool = next(
        item
        for item in approved_payload["tools"]
        if item["tool_id"] == "mcp:servicenow/search_records"
    )
    assert approved_tool["schema_status"] == "approved"

    old_path = registry_path
    new_path = (
        AgentRegistry()
        .import_mcp_tools_with_schema(
            _schema_inventory(changed=True, include_create=False),
            agent_id="release-agent",
            owner="platform",
            environment="production",
        )
        .save(tmp_path / "new_registry.json")
    )
    assert main(["registry", "diff", "--old", str(old_path), "--new", str(new_path), "--json"]) == 0
    diff_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert diff_payload["summary"]["schema_drift"] == 1

    output_dir = tmp_path / "registry_report"
    assert (
        main(
            [
                "registry",
                "report",
                "--registry",
                str(old_path),
                "--output-dir",
                str(output_dir),
                "--json",
            ]
        )
        == 0
    )
    report_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert Path(report_payload["artifacts"]["json_path"]).exists()
    assert (output_dir / "policy_bundle.json").exists()
