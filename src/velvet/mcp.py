"""Direct MCP-shaped adapter demo for the launch wedge."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from velvet.approvals import ApprovalRequest, ApprovalStore
from velvet.ledger import VelvetLedger
from velvet.policy_bundle import VerifiedPolicyBundle
from velvet.rope import (
    AdmissionDecision,
    ToolRiskClass,
    VelvetMCP,
    VelvetRope,
    VelvetToolCall,
    VelvetToolPolicy,
)
from velvet.signing import SigningProvider, signer_default_key_id
from velvet.thread_log import ThreadLogger

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class DirectVelvetMCPAdapter:
    """Narrow pre-execution MCP authorization boundary.

    Input is a normalized MCP server/tool/arguments request. Output is the
    Velvet warrant; optional thread and ledger paths persist replayable
    jurisdiction_evidence for demo and pilot review.
    """

    firewall: VelvetMCP
    list_version: str = "velvet.mcp_list.v1"
    signer: SigningProvider | None = None
    signing_key_id: str | None = None
    approval_store: ApprovalStore | None = None

    @classmethod
    def from_list_file(
        cls,
        path: str | Path,
        *,
        policy_dir: str = "examples/mcp/policies",
        chain: str = "mcp_demo",
        policy_bundle: str | Path | VerifiedPolicyBundle | None = None,
        policy_bundle_signing_key: str | None = None,
        require_policy_bundle: bool = False,
        allow_expired_policy_degraded: bool = False,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
        signing_profile: str | None = None,
        dev_ephemeral_key: bool = False,
        approval_store: ApprovalStore | None = None,
    ) -> DirectVelvetMCPAdapter:
        payload = _read_json(path)
        policies = tuple(_policy_from_config(item) for item in _tools(payload))
        return cls(
            firewall=VelvetMCP(
                rope=VelvetRope(
                    policy_dir=policy_dir,
                    chain=chain,
                    policy_bundle=policy_bundle,
                    policy_bundle_signing_key=policy_bundle_signing_key,
                    require_policy_bundle=require_policy_bundle,
                    allow_expired_policy_degraded=allow_expired_policy_degraded,
                    signer=signer,
                    signing_key_id=signing_key_id,
                    signing_profile=signing_profile,
                    dev_ephemeral_key=dev_ephemeral_key,
                ),
                policies=policies,
            ),
            list_version=str(payload.get("version", "velvet.mcp_list.v1")),
            signer=signer,
            signing_key_id=signing_key_id,
            approval_store=approval_store,
        )

    def authorize(
        self,
        request: Mapping[str, Any],
        *,
        thread_path: str | Path | None = None,
        ledger_path: str | Path | None = None,
        approval_store: ApprovalStore | None = None,
        requester: str = "velvet",
    ) -> JsonObject:
        thread_logger = ThreadLogger(thread_path) if thread_path is not None else None
        call = VelvetToolCall(
            server=str(request["server"]),
            tool=str(request["tool"]),
            arguments=cast(Mapping[str, Any], request.get("arguments", {})),
            user_request=str(request.get("user_request", "")),
            untrusted_content=cast(str | None, request.get("untrusted_content")),
        )
        state = cast(Mapping[str, object] | None, request.get("state"))
        decision = self.firewall.authorize(call, state=state, thread_logger=thread_logger)
        active_approval_store = approval_store or self.approval_store
        approval_request = (
            active_approval_store.create_request(
                decision,
                original_request=request,
                requester=requester,
            )
            if active_approval_store is not None
            else None
        )
        ledger_record: JsonObject | None = None
        if ledger_path is not None:
            ledger_signer = self.signer or self.firewall.signer
            if ledger_signer is None:
                raise RuntimeError("Velvet MCP ledger signing provider is not configured")
            ledger_record = VelvetLedger(
                ledger_path,
                signer=ledger_signer,
                signing_key_id=(
                    self.signing_key_id
                    or self.firewall.signing_key_id
                    or signer_default_key_id(ledger_signer)
                ),
            ).write_admission_decision(
                decision,
                request=request,
                thread_path=thread_path,
                label="direct_mcp",
                approval_request=approval_request.to_dict()
                if approval_request is not None
                else None,
            )
        return adapter_payload(
            decision,
            request=request,
            thread_path=thread_path,
            ledger_record=ledger_record,
            approval_request=approval_request,
        )


def adapter_payload(
    decision: AdmissionDecision,
    *,
    request: Mapping[str, Any],
    thread_path: str | Path | None,
    ledger_record: Mapping[str, Any] | None = None,
    approval_request: ApprovalRequest | Mapping[str, Any] | None = None,
) -> JsonObject:
    approval_payload = (
        approval_request.to_dict()
        if isinstance(approval_request, ApprovalRequest)
        else dict(approval_request)
        if isinstance(approval_request, Mapping)
        else None
    )
    return {
        "adapter": "direct_mcp",
        "boundary": "pre_execution_authorization",
        "request": dict(request),
        "tool_key": f"{request['server']}/{request['tool']}",
        "thread_path": str(thread_path) if thread_path is not None else None,
        "admission_decision": decision.to_dict(),
        "approval_request_id": approval_payload.get("approval_request_id")
        if approval_payload
        else None,
        "approval_request": approval_payload,
        "ledger_record_hash": ledger_record.get("record_hash") if ledger_record else None,
        "admission_evidence_hash": ledger_record.get("admission_evidence_hash")
        if ledger_record
        else None,
        "admission_evidence_ref": ledger_record.get("admission_evidence_ref")
        if ledger_record
        else None,
        "admission_evidence": ledger_record.get("admission_evidence") if ledger_record else None,
    }


def load_requests(path: str | Path) -> tuple[JsonObject, ...]:
    payload = _read_json(path)
    if isinstance(payload.get("requests"), list):
        return tuple(cast(JsonObject, item) for item in payload["requests"])
    return (payload,)


def _read_json(path: str | Path) -> JsonObject:
    with Path(path).open("r", encoding="utf-8") as handle:
        return cast(JsonObject, json.load(handle))


def _tools(payload: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    tools = payload.get("tools")
    if not isinstance(tools, list):
        raise ValueError("MCP list must contain a tools array")
    return (cast(Mapping[str, Any], item) for item in tools)


def _policy_from_config(item: Mapping[str, Any]) -> VelvetToolPolicy:
    metadata = dict(cast(Mapping[str, Any], item.get("metadata", {})))
    for key in (
        "approval_tier",
        "rationale",
        "risk_rationale",
        "usd_estimate",
        "input_schema",
        "inputSchema",
        "schema",
        "parameters",
        "schema_hash",
        "tool_schema_hash",
        "approved_schema_hash",
        "schema_status",
        "owner",
        "environment",
        "tenant_id",
        "data_class",
    ):
        if key in item:
            metadata[key] = item[key]
    if "schema_hash" in metadata and "tool_schema_hash" not in metadata:
        metadata["tool_schema_hash"] = metadata["schema_hash"]
    return VelvetToolPolicy(
        server=str(item["server"]),
        tool=str(item["tool"]),
        risk_class=ToolRiskClass(str(item.get("risk_class", ToolRiskClass.MEDIUM.value))),
        expected_improvement=float(item.get("expected_improvement", 0.78)),
        novelty=float(item.get("novelty", 0.60)),
        confidence=float(item.get("confidence", 0.72)),
        metadata=metadata,
    )
