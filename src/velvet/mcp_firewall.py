"""Velvet MCP Firewall pilot workflow backed only by the inline gateway."""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from velvet.admission_evidence import verify_admission_evidence
from velvet.agent_registry import AgentRegistry
from velvet.approvals import ApprovalStore
from velvet.contracts import AdmissionContract
from velvet.evidence import EVIDENCE_PACK_SCHEMA_VERSION
from velvet.gateway import InlineGateway, InlineGatewayDecision, InlineGatewayRequest
from velvet.serialization import canonical_hash_sha256
from velvet.signing import SigningProvider, load_demo_ed25519_signer, signer_default_key_id

JsonObject = dict[str, Any]

MCP_FIREWALL_REQUEST_SCHEMA_VERSION = "velvet.mcp_firewall.request.v1"
MCP_FIREWALL_RESPONSE_SCHEMA_VERSION = "velvet.mcp_firewall.response.v1"
MCP_FIREWALL_PILOT_SCHEMA_VERSION = "velvet.mcp_firewall.pilot.v1"
MCP_FIREWALL_VERIFY_SCHEMA_VERSION = "velvet.mcp_firewall.verify.v1"

DEFAULT_PILOT_REQUESTS: tuple[JsonObject, ...] = (
    {
        "request_id": "fw_allow_read",
        "agent_id": "release-agent",
        "user_id": "platform-lead@example.com",
        "mcp_server": "servicenow",
        "mcp_tool": "search_change_requests",
        "risk_class": "low",
        "requested_at": "2026-05-30T17:00:00Z",
        "arguments": {"query": "service=payments state=open"},
        "user_request": (
            "Find open production payment-service change requests before opening anything new."
        ),
    },
    {
        "request_id": "fw_block_delete",
        "agent_id": "release-agent",
        "user_id": "platform-lead@example.com",
        "mcp_server": "servicenow",
        "mcp_tool": "delete_change_request",
        "risk_class": "destructive",
        "requested_at": "2026-05-30T17:00:10Z",
        "arguments": {"change_id": "CHG0042007"},
        "user_request": "Remove the stale production change request before the release meeting.",
    },
    {
        "request_id": "fw_escalate_write",
        "agent_id": "release-agent",
        "user_id": "platform-lead@example.com",
        "mcp_server": "servicenow",
        "mcp_tool": "create_change_request",
        "risk_class": "high",
        "operation": "external_api_mutation",
        "requested_at": "2026-05-30T17:00:20Z",
        "arguments": {
            "service": "payments",
            "summary": "Approve production deploy for routing fix",
            "window": "2026-05-30T22:00:00-07:00",
        },
        "user_request": "Open a production change request for the routing fix.",
    },
)


@dataclass(frozen=True)
class MCPFirewallRequest:
    agent_id: str
    user_id: str
    mcp_server: str
    mcp_tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    user_request: str = ""
    request_id: str | None = None
    risk_class: str | None = None
    operation: str | None = None
    requested_at: str = field(default_factory=lambda: _now_iso())
    tenant_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_agent_id: str = "release-agent",
    ) -> MCPFirewallRequest:
        return cls(
            agent_id=str(data.get("agent_id", default_agent_id)),
            user_id=str(data.get("user_id", data.get("actor_id", "unknown-user"))),
            mcp_server=_required_string(data, "mcp_server", fallback_key="server"),
            mcp_tool=_required_string(data, "mcp_tool", fallback_key="tool"),
            arguments=dict(cast(Mapping[str, Any], data.get("arguments", {}))),
            user_request=str(data.get("user_request", "")),
            request_id=cast(str | None, data.get("request_id")),
            risk_class=cast(str | None, data.get("risk_class")),
            operation=cast(str | None, data.get("operation")),
            requested_at=str(data.get("requested_at", _now_iso())),
            tenant_id=cast(str | None, data.get("tenant_id")),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    @property
    def tool_key(self) -> str:
        return f"{self.mcp_server}/{self.mcp_tool}"

    def to_inline_gateway_request(self) -> InlineGatewayRequest:
        metadata: JsonObject = dict(self.metadata)
        metadata.update(
            {
                "firewall_schema_version": MCP_FIREWALL_REQUEST_SCHEMA_VERSION,
                "user_id": self.user_id,
                "requested_at": self.requested_at,
            }
        )
        proposed_action: JsonObject = {
            "surface": "mcp",
            "server": self.mcp_server,
            "tool": self.mcp_tool,
            "arguments": dict(self.arguments),
            "agent_id": self.agent_id,
            "actor_id": self.user_id,
            "user_request": self.user_request,
            "metadata": metadata,
        }
        if self.risk_class is not None:
            proposed_action["risk_class"] = self.risk_class
        if self.operation is not None:
            proposed_action["operation"] = self.operation
        if self.tenant_id is not None:
            proposed_action["tenant_id"] = self.tenant_id
        context: JsonObject = {
            "user_id": self.user_id,
            "actor_id": self.user_id,
            "issued_at": self.requested_at,
            "user_request": self.user_request,
        }
        if self.tenant_id is not None:
            context["tenant_id"] = self.tenant_id
        return InlineGatewayRequest(
            proposed_action=proposed_action,
            context=context,
            request_id=self.request_id,
            replay_id=f"mcp_firewall:{self.agent_id}",
            logical_step=1,
        )

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": MCP_FIREWALL_REQUEST_SCHEMA_VERSION,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "tool_key": self.tool_key,
            "arguments": dict(self.arguments),
            "user_request": self.user_request,
            "risk_class": self.risk_class,
            "operation": self.operation,
            "requested_at": self.requested_at,
            "tenant_id": self.tenant_id,
            "metadata": dict(self.metadata),
        }


def load_mcp_firewall_requests(
    path: str | Path,
    *,
    default_agent_id: str = "release-agent",
) -> tuple[MCPFirewallRequest, ...]:
    payload = _read_json(path)
    if isinstance(payload.get("requests"), list):
        return tuple(
            MCPFirewallRequest.from_dict(
                cast(Mapping[str, Any], item),
                default_agent_id=default_agent_id,
            )
            for item in payload["requests"]
        )
    return (MCPFirewallRequest.from_dict(payload, default_agent_id=default_agent_id),)


def mcp_firewall_response(
    decision: InlineGatewayDecision,
    *,
    firewall_request: MCPFirewallRequest,
) -> JsonObject:
    ledger_record = dict(decision.ledger_record or {})
    admission_evidence = dict(decision.admission_evidence or {})
    proof_decision = decision.decision.value
    public_decision = _proof_decision_to_public(proof_decision)
    reason = _inline_reason(decision)
    canonical_action_hash = decision.canonical_action.canonical_action_hash
    approval_request_id = None
    if decision.approval_request is not None:
        approval_request_id = decision.approval_request.get("approval_request_id")
    warrant = _response_warrant(decision, public_decision=public_decision, reason=reason)
    return {
        "schema_version": MCP_FIREWALL_RESPONSE_SCHEMA_VERSION,
        "product": "velvet_mcp_firewall",
        "boundary": "pre_execution_authorization",
        "request": firewall_request.to_dict(),
        "request_id": decision.request.stable_request_id,
        "agent_id": firewall_request.agent_id,
        "user_id": firewall_request.user_id,
        "mcp_server": firewall_request.mcp_server,
        "mcp_tool": firewall_request.mcp_tool,
        "tool_key": firewall_request.tool_key,
        "decision": public_decision,
        "proof_decision": proof_decision,
        "reason": reason,
        "seal_id": decision.admission_outcome.envelope.envelope_id,
        "warrant": warrant,
        "warrant_hash": canonical_hash_sha256(warrant),
        "approval_request_id": approval_request_id,
        "canonical_action_hash": canonical_action_hash,
        "canonical_action": decision.canonical_action.to_dict(),
        "admission_evidence_hash": admission_evidence.get("admission_evidence_hash"),
        "admission_evidence_ref": ledger_record.get("admission_evidence_ref"),
        "admission_evidence": admission_evidence or None,
        "ledger_record_id": ledger_record.get("sequence_number"),
        "ledger_record_hash": ledger_record.get("inline_record_hash"),
        "upstream_execution_status": ledger_record.get("upstream_execution_status")
        or _inline_upstream_status(public_decision),
        "gateway_decision": decision.to_dict(),
    }


def run_mcp_firewall_pilot(
    output_dir: str | Path,
    *,
    list_path: str | Path = "examples/mcp/list.json",
    requests: Sequence[MCPFirewallRequest | Mapping[str, Any]] | None = None,
    policy_dir: str | Path = "examples/mcp/policies",
    chain: str = "mcp_demo",
    owner: str = "platform",
    environment: str = "production",
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> JsonObject:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    firewall_requests = _coerce_requests(requests or DEFAULT_PILOT_REQUESTS)
    agent_ids = {request.agent_id for request in firewall_requests}
    if len(agent_ids) != 1:
        raise ValueError("MCP Firewall pilot expects requests for one agent_id")
    agent_id = next(iter(agent_ids))
    paths = _artifact_paths(destination)
    for value in paths.values():
        path = Path(str(value))
        if path.exists():
            path.unlink()

    active_signer = signer or load_demo_ed25519_signer()
    active_signing_key_id = signing_key_id or signer_default_key_id(active_signer)
    registry = AgentRegistry.from_mcp_list(
        list_path,
        agent_id=agent_id,
        agent_name="Release Agent",
        owner=owner,
        environment=environment,
    )
    registry.save(Path(str(paths["registry_path"])))
    approval_store = ApprovalStore(
        Path(str(paths["approvals_path"])),
        signer=active_signer,
        signing_key_id=active_signing_key_id,
    )
    approval_store.save(approval_store.load())
    Path(str(paths["thread_path"])).write_text("", encoding="utf-8")

    gateway = InlineGateway(
        contract=AdmissionContract(),
        approval_store=approval_store,
        ledger_path=Path(str(paths["ledger_path"])),
        signer=active_signer,
        signing_key_id=active_signing_key_id,
    )
    responses = [
        mcp_firewall_response(
            gateway.authorize(request.to_inline_gateway_request()),
            firewall_request=request,
        )
        for request in firewall_requests
    ]
    Path(str(paths["responses_path"])).write_text(
        json.dumps({"responses": responses}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ledger_report = _inline_ledger_report(Path(str(paths["ledger_path"])), responses)
    Path(str(paths["ledger_report_json_path"])).write_text(
        json.dumps(ledger_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(str(paths["ledger_report_markdown_path"])).write_text(
        _render_inline_ledger_markdown(ledger_report),
        encoding="utf-8",
    )
    evidence_pack = _inline_evidence_pack(ledger_report, responses)
    Path(str(paths["evidence_pack_json_path"])).write_text(
        json.dumps(evidence_pack, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(str(paths["evidence_pack_markdown_path"])).write_text(
        _render_inline_evidence_pack_markdown(evidence_pack),
        encoding="utf-8",
    )
    decision_counts = dict(Counter(str(response["decision"]) for response in responses))
    approvals = approval_store.load().to_dict()
    payload: JsonObject = {
        "schema_version": MCP_FIREWALL_PILOT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "product": "Velvet MCP Firewall",
        "boundary": "pre_execution_authorization",
        "inputs": {
            "list_path": str(list_path),
            "policy_dir": str(policy_dir),
            "chain": chain,
            "agent_id": agent_id,
            "owner": owner,
            "environment": environment,
        },
        "positioning": (
            "Pilot-ready local/offline pre-execution authorization for MCP tool calls: "
            "allow safe reads, block destructive actions, escalate sensitive writes, "
            "and emit signed admission-evidence-bound inline ledger records."
        ),
        "summary": {
            "requests": len(responses),
            "total_requests": len(responses),
            "decision_counts": decision_counts,
            "approval_pending": approvals["summary"]["pending"],
            "pending_approvals": approvals["summary"]["pending"],
            "ledger_verification_status": ledger_report["summary"][
                "ledger_verification_status"
            ],
            "evidence_controls_passing": evidence_pack["summary"]["controls_passing"],
            "artifact_paths": paths,
        },
        "total_requests": len(responses),
        "decision_counts": decision_counts,
        "pending_approvals": approvals["summary"]["pending"],
        "ledger_verification_status": ledger_report["summary"][
            "ledger_verification_status"
        ],
        "evidence_controls_passing": evidence_pack["summary"]["controls_passing"],
        "artifact_paths": paths,
        "artifacts": paths,
        "decisions": responses,
        "replay_report": {
            "status": "pass",
            "mode": "canonical_inline_gateway",
            "records": ledger_report["summary"]["records"],
            "canonical_action_hashes": ledger_report["summary"]["canonical_action_hashes"],
        },
        "velvet_ledger_report": ledger_report,
        "evidence_pack": evidence_pack,
        "approvals": approvals,
    }
    Path(str(paths["pilot_json_path"])).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(str(paths["pilot_markdown_path"])).write_text(
        render_mcp_firewall_pilot_markdown(payload),
        encoding="utf-8",
    )
    return payload


def render_mcp_firewall_pilot_markdown(payload: Mapping[str, Any]) -> str:
    return render_mcp_firewall_report_markdown(payload)


def render_mcp_firewall_report_markdown(payload: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], payload["summary"])
    artifacts = cast(Mapping[str, Any], payload["artifacts"])
    lines = [
        "# Velvet MCP Firewall Pilot",
        "",
        f"Generated: `{payload['generated_at']}`",
        f"Product: `{payload.get('product', 'Velvet MCP Firewall')}`",
        f"Boundary: `{payload.get('boundary', 'pre_execution_authorization')}`",
        "",
        "## Summary",
        "",
        f"- Total requests: `{summary.get('total_requests', summary.get('requests'))}`",
        f"- Decisions: `{json.dumps(summary['decision_counts'], sort_keys=True)}`",
        (
            "- Pending approvals: "
            f"`{summary.get('pending_approvals', summary.get('approval_pending'))}`"
        ),
        f"- Ledger verification: `{summary['ledger_verification_status']}`",
        f"- Evidence controls passing: `{summary['evidence_controls_passing']}`",
        "",
        "## Pilot Decisions",
        "",
        "| Request | Tool | Decision | Canonical hash | Upstream status | Approval |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for response in cast(Sequence[Mapping[str, Any]], payload["decisions"]):
        request = cast(Mapping[str, Any], response["request"])
        lines.append(
            "| "
            f"`{request.get('request_id')}` | "
            f"`{response['tool_key']}` | "
            f"`{response['decision']}` | "
            f"`{response.get('canonical_action_hash')}` | "
            f"`{response.get('upstream_execution_status')}` | "
            f"`{response.get('approval_request_id')}` |"
        )
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Registry: `{artifacts['registry_path']}`",
            f"- Thread: `{artifacts['thread_path']}`",
            f"- Ledger: `{artifacts['ledger_path']}`",
            f"- Responses: `{artifacts['responses_path']}`",
            f"- Evidence pack: `{artifacts['evidence_pack_markdown_path']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def write_mcp_firewall_report(output_dir: str | Path) -> JsonObject:
    destination = Path(output_dir)
    pilot_json_path = destination / "mcp_firewall_pilot.json"
    pilot_markdown_path = destination / "mcp_firewall_pilot.md"
    payload = _read_json(pilot_json_path)
    pilot_markdown_path.write_text(
        render_mcp_firewall_report_markdown(payload),
        encoding="utf-8",
    )
    return {
        "schema_version": "velvet.mcp_firewall.report.v1",
        "status": "pass",
        "output_dir": str(destination),
        "pilot_json_path": str(pilot_json_path),
        "pilot_markdown_path": str(pilot_markdown_path),
    }


def verify_mcp_firewall_pilot(
    output_dir: str | Path,
    *,
    signer: SigningProvider | None = None,
) -> JsonObject:
    _ = signer
    destination = Path(output_dir)
    checks: list[JsonObject] = []
    pilot_json_path = destination / "mcp_firewall_pilot.json"
    pilot: JsonObject | None = None
    try:
        pilot = _read_json(pilot_json_path)
        _add_check(checks, "pilot_json_exists", True, f"Found {pilot_json_path}.")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        _add_check(checks, "pilot_json_exists", False, str(error))

    artifacts = _artifact_paths_for_verification(destination, pilot)
    if pilot is not None:
        _add_check(
            checks,
            "pilot_schema_version",
            pilot.get("schema_version") == MCP_FIREWALL_PILOT_SCHEMA_VERSION,
            f"Expected {MCP_FIREWALL_PILOT_SCHEMA_VERSION}.",
            actual=pilot.get("schema_version"),
        )
        forbidden = _forbidden_investor_terms(json.dumps(pilot, sort_keys=True))
        _add_check(
            checks,
            "pilot_investor_metadata_absent",
            not forbidden,
            "Pilot JSON contains no investor-specific metadata.",
            forbidden_terms=forbidden,
        )

    for key in _required_artifact_keys():
        path = Path(str(artifacts[key]))
        _add_check(checks, f"artifact_{key}_exists", path.exists(), f"Expected {path}.")

    ledger_verification: JsonObject | None = None
    ledger_path = Path(str(artifacts["ledger_path"]))
    if ledger_path.exists():
        try:
            records = _read_inline_ledger_records(ledger_path)
            issues = _inline_ledger_issues(records)
        except (OSError, json.JSONDecodeError) as error:
            records = []
            issues = [{"code": "inline_ledger_read_error", "reason": str(error)}]
        ledger_verification = {
            "schema_version": "velvet.inline_gateway.ledger_verification.v1",
            "status": "pass" if not issues else "fail",
            "records": len(records),
            "issues": issues,
        }
        _add_check(
            checks,
            "inline_ledger_records_verify",
            not issues,
            "Inline gateway record hashes and admission evidence bindings verify.",
            ledger_status=ledger_verification["status"],
            issues=issues,
        )

    evidence_path = Path(str(artifacts["evidence_pack_json_path"]))
    if evidence_path.exists():
        try:
            evidence_pack = _read_json(evidence_path)
            _add_check(
                checks,
                "evidence_pack_schema_version",
                evidence_pack.get("schema_version") == EVIDENCE_PACK_SCHEMA_VERSION,
                f"Expected {EVIDENCE_PACK_SCHEMA_VERSION}.",
                actual=evidence_pack.get("schema_version"),
            )
            controls = cast(Mapping[str, Mapping[str, Any]], evidence_pack.get("controls", {}))
            failing_controls = [
                key for key, control in sorted(controls.items()) if control.get("status") != "pass"
            ]
            _add_check(
                checks,
                "evidence_controls_pass",
                not failing_controls and bool(controls),
                "Evidence controls pass.",
                failing_controls=failing_controls,
            )
        except (OSError, json.JSONDecodeError, ValueError) as error:
            _add_check(checks, "evidence_pack_readable", False, str(error))

    if pilot is not None:
        decisions = tuple(cast(Sequence[Mapping[str, Any]], pilot.get("decisions", ())))
        decision_set = {str(decision.get("decision")) for decision in decisions}
        _add_check(
            checks,
            "decision_coverage",
            bool(decisions) and all(decision_set),
            "Pilot includes gateway decisions.",
            decisions=sorted(decision_set),
        )
        missing_hashes = [
            str(decision.get("request_id"))
            for decision in decisions
            if not decision.get("canonical_action_hash")
        ]
        _add_check(
            checks,
            "canonical_action_hashes_present",
            not missing_hashes and bool(decisions),
            "Every pilot decision carries canonical_action_hash.",
            invalid_request_ids=missing_hashes,
        )
        missing_evidence = [
            str(decision.get("request_id"))
            for decision in decisions
            if not decision.get("admission_evidence_hash")
        ]
        _add_check(
            checks,
            "admission_evidence_present",
            not missing_evidence and bool(decisions),
            "Every pilot decision carries admission evidence.",
            invalid_request_ids=missing_evidence,
        )
        replay_failures = _replay_decisions_for_verification(decisions, artifacts=artifacts)
        _add_check(
            checks,
            "decision_replay_verifies",
            not replay_failures and bool(decisions),
            "Every pilot decision canonical hash matches an inline ledger pre-execution record.",
            failures=replay_failures,
        )

    markdown_path = Path(str(artifacts["pilot_markdown_path"]))
    if markdown_path.exists():
        try:
            forbidden = _forbidden_investor_terms(markdown_path.read_text(encoding="utf-8"))
            _add_check(
                checks,
                "markdown_investor_metadata_absent",
                not forbidden,
                "Pilot Markdown contains no investor-specific metadata.",
                forbidden_terms=forbidden,
            )
        except OSError as error:
            _add_check(checks, "markdown_readable", False, str(error))

    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return {
        "schema_version": MCP_FIREWALL_VERIFY_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "product": "Velvet MCP Firewall",
        "boundary": "pre_execution_authorization",
        "status": status,
        "output_dir": str(destination),
        "checks": checks,
        "ledger_verification": ledger_verification,
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for check in checks if check["status"] == "pass"),
            "failed": sum(1 for check in checks if check["status"] == "fail"),
        },
    }


def _response_warrant(
    decision: InlineGatewayDecision,
    *,
    public_decision: str,
    reason: str,
) -> JsonObject:
    if decision.approval_request is not None:
        warrant = decision.approval_request.get("warrant")
        if isinstance(warrant, Mapping):
            return dict(cast(Mapping[str, Any], warrant))
    return {
        "schema_version": "velvet.inline_gateway.warrant_ref.v1",
        "warrant_id": f"wrnt_{decision.admission_outcome.envelope.envelope_id}",
        "canonical_action_hash": decision.canonical_action.canonical_action_hash,
        "decision": public_decision,
        "reason": reason,
        "tool_key": decision.canonical_action.tool_name,
        "authority_class": decision.canonical_action.authority_class.value,
        "seal_id": decision.admission_outcome.envelope.envelope_id,
    }


def _inline_reason(decision: InlineGatewayDecision) -> str:
    reasons = [str(reason) for reason in decision.admission_outcome.unified_decision.reasons]
    return ", ".join(reasons) or decision.decision.value


def _proof_decision_to_public(decision: str) -> str:
    if decision in {"execute", "ADMITTED"}:
        return "execute"
    if decision in {"escalate", "ask_approval", "delay", "pending_approval", "ESCALATED"}:
        return "escalate"
    return "block"


def _inline_upstream_status(public_decision: str) -> str:
    if public_decision == "execute":
        return "forward_authorized"
    if public_decision == "escalate":
        return "pending_approval"
    return "not_forwarded"


def _inline_ledger_report(
    ledger_path: Path,
    responses: Sequence[Mapping[str, Any]],
) -> JsonObject:
    records = _read_inline_ledger_records(ledger_path) if ledger_path.exists() else []
    issues = _inline_ledger_issues(records)
    response_hashes = {
        str(response.get("canonical_action_hash"))
        for response in responses
        if response.get("canonical_action_hash")
    }
    return {
        "schema_version": "velvet.inline_gateway.ledger_report.v1",
        "ledger_path": str(ledger_path),
        "summary": {
            "records": len(records),
            "responses": len(responses),
            "decision_counts": dict(
                Counter(str(response.get("decision")) for response in responses)
            ),
            "ledger_verification_status": "pass" if not issues else "fail",
            "canonical_action_hashes": len(response_hashes),
            "issues": issues,
        },
        "records": records,
    }


def _render_inline_ledger_markdown(report: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], report["summary"])
    return (
        "# Inline Gateway Ledger Report\n\n"
        f"- Records: `{summary['records']}`\n"
        f"- Verification: `{summary['ledger_verification_status']}`\n"
        f"- Canonical action hashes: `{summary['canonical_action_hashes']}`\n"
    )


def _inline_evidence_pack(
    ledger_report: Mapping[str, Any],
    responses: Sequence[Mapping[str, Any]],
) -> JsonObject:
    summary = cast(Mapping[str, Any], ledger_report["summary"])
    missing_hashes = [
        str(response.get("request_id"))
        for response in responses
        if not response.get("canonical_action_hash")
    ]
    missing_evidence = [
        str(response.get("request_id"))
        for response in responses
        if not response.get("admission_evidence_hash")
    ]
    controls: JsonObject = {
        "canonical_action_binding": {
            "status": "pass" if not missing_hashes else "fail",
            "message": "Every firewall response carries canonical_action_hash.",
            "missing_request_ids": missing_hashes,
        },
        "inline_ledger_records_verify": {
            "status": str(summary.get("ledger_verification_status", "fail")),
            "message": "Inline gateway record hashes and admission evidence bindings verify.",
            "issues": list(cast(Sequence[Any], summary.get("issues", []))),
        },
        "admission_evidence_present": {
            "status": "pass" if not missing_evidence else "fail",
            "message": "Every firewall response carries a signed admission evidence hash.",
            "missing_request_ids": missing_evidence,
        },
    }
    controls_passing = sum(
        1 for control in controls.values() if cast(Mapping[str, Any], control)["status"] == "pass"
    )
    return {
        "schema_version": EVIDENCE_PACK_SCHEMA_VERSION,
        "summary": {
            "controls_passing": controls_passing,
            "controls_attention": len(controls) - controls_passing,
        },
        "controls": controls,
    }


def _render_inline_evidence_pack_markdown(evidence_pack: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], evidence_pack["summary"])
    lines = [
        "# Inline Gateway Evidence Pack",
        "",
        f"- Controls passing: `{summary['controls_passing']}`",
        f"- Controls attention: `{summary['controls_attention']}`",
        "",
        "## Controls",
        "",
    ]
    controls = cast(Mapping[str, Mapping[str, Any]], evidence_pack["controls"])
    for name, control in sorted(controls.items()):
        lines.append(f"- `{name}`: `{control['status']}`")
    return "\n".join(lines) + "\n"


def _artifact_paths(destination: Path) -> JsonObject:
    return {
        "registry_path": str(destination / "mcp_firewall_registry.json"),
        "thread_path": str(destination / "mcp_firewall_thread.jsonl"),
        "ledger_path": str(destination / "mcp_firewall_inline_ledger.jsonl"),
        "approvals_path": str(destination / "mcp_firewall_approvals.json"),
        "responses_path": str(destination / "mcp_firewall_responses.json"),
        "ledger_report_json_path": str(destination / "mcp_firewall_ledger_report.json"),
        "ledger_report_markdown_path": str(destination / "mcp_firewall_ledger_report.md"),
        "evidence_pack_json_path": str(destination / "agent_ops_evidence_pack.json"),
        "evidence_pack_markdown_path": str(destination / "agent_ops_evidence_pack.md"),
        "pilot_json_path": str(destination / "mcp_firewall_pilot.json"),
        "pilot_markdown_path": str(destination / "mcp_firewall_pilot.md"),
    }


def _artifact_paths_for_verification(
    destination: Path,
    pilot: Mapping[str, Any] | None,
) -> JsonObject:
    artifacts = _artifact_paths(destination)
    if pilot is None:
        return artifacts
    raw_artifacts = pilot.get("artifacts")
    if isinstance(raw_artifacts, Mapping):
        artifacts.update({str(key): str(value) for key, value in raw_artifacts.items()})
    return artifacts


def _required_artifact_keys() -> tuple[str, ...]:
    return (
        "pilot_json_path",
        "pilot_markdown_path",
        "responses_path",
        "thread_path",
        "ledger_path",
        "ledger_report_json_path",
        "ledger_report_markdown_path",
        "evidence_pack_json_path",
        "evidence_pack_markdown_path",
        "approvals_path",
        "registry_path",
    )


def _add_check(
    checks: list[JsonObject],
    name: str,
    passed: bool,
    message: str,
    **details: Any,
) -> None:
    check: JsonObject = {
        "name": name,
        "status": "pass" if passed else "fail",
        "message": message,
    }
    if details:
        check["details"] = details
    checks.append(check)


def _read_inline_ledger_records(path: Path) -> list[JsonObject]:
    return [
        cast(JsonObject, json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _inline_record_hash(record: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(
        {str(key): value for key, value in record.items() if key != "inline_record_hash"}
    )


def _inline_ledger_issues(records: Sequence[Mapping[str, Any]]) -> list[JsonObject]:
    issues: list[JsonObject] = []
    expected_previous = f"sha256:{'0' * 64}"
    for index, record in enumerate(records, start=1):
        request_id = record.get("request_id")
        actual_hash = record.get("inline_record_hash")
        expected_hash = _inline_record_hash(record)
        if not record.get("canonical_action_hash"):
            issues.append(
                {
                    "code": "canonical_action_hash_missing",
                    "index": index,
                    "request_id": request_id,
                }
            )
        if actual_hash != expected_hash:
            issues.append(
                {
                    "code": "record_hash_mismatch",
                    "index": index,
                    "request_id": request_id,
                    "expected": expected_hash,
                    "actual": actual_hash,
                }
            )
        previous = record.get("previous_record_hash")
        if previous != expected_previous:
            issues.append(
                {
                    "code": "previous_record_hash_mismatch",
                    "index": index,
                    "request_id": request_id,
                    "expected": expected_previous,
                    "actual": previous,
                }
            )
        evidence = record.get("admission_evidence")
        if isinstance(evidence, Mapping):
            issues.extend(_inline_admission_evidence_issues(record, evidence, index=index))
        elif record.get("admission_evidence_hash") is not None:
            issues.append(
                {
                    "code": "admission_evidence_missing",
                    "index": index,
                    "request_id": request_id,
                }
            )
        expected_previous = expected_hash
    return issues


def _inline_admission_evidence_issues(
    record: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    index: int,
) -> list[JsonObject]:
    issues: list[JsonObject] = []
    request_id = record.get("request_id")
    if record.get("admission_evidence_hash") != evidence.get("admission_evidence_hash"):
        issues.append(
            {
                "code": "admission_evidence_hash_mismatch",
                "index": index,
                "request_id": request_id,
            }
        )
    if not verify_admission_evidence(evidence):
        issues.append(
            {
                "code": "admission_evidence_signature_mismatch",
                "index": index,
                "request_id": request_id,
            }
        )
    for record_field, expected in (
        ("sequence_number", _nested(evidence, ("ledger_state", "sequence_number"))),
        (
            "previous_record_hash",
            _nested(evidence, ("ledger_state", "previous_record_hash")),
        ),
        ("decision", _nested(evidence, ("decision", "decision"))),
    ):
        actual = record.get(record_field)
        comparable_actual = (
            _record_decision_for_evidence(actual) if record_field == "decision" else actual
        )
        if expected is not None and comparable_actual != expected:
            issues.append(
                {
                    "code": "admission_evidence_binding_mismatch",
                    "index": index,
                    "request_id": request_id,
                    "field": record_field,
                    "expected": expected,
                    "actual": comparable_actual,
                }
            )
    return issues


def _record_decision_for_evidence(value: Any) -> str:
    text = str(value)
    if text in {"ADMITTED", "ESCALATED", "FALLBACK_EXECUTED", "REFUSED", "HELD"}:
        return _proof_decision_to_public(text)
    return text


def _nested(value: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _replay_decisions_for_verification(
    decisions: Sequence[Mapping[str, Any]],
    *,
    artifacts: Mapping[str, Any],
) -> list[JsonObject]:
    ledger_path = Path(str(artifacts["ledger_path"]))
    try:
        records = _read_inline_ledger_records(ledger_path)
    except (OSError, json.JSONDecodeError) as error:
        return [{"request_id": None, "reason": str(error)}]
    pre_execution_hashes = {
        str(record.get("request_id")): str(record.get("canonical_action_hash"))
        for record in records
        if record.get("phase") == "pre_execution"
    }
    failures: list[JsonObject] = []
    for decision in decisions:
        request_id = decision.get("request_id")
        expected_hash = decision.get("canonical_action_hash")
        if not isinstance(request_id, str) or not request_id:
            failures.append({"request_id": request_id, "reason": "decision has no request_id"})
            continue
        if not isinstance(expected_hash, str) or not expected_hash:
            failures.append(
                {"request_id": request_id, "reason": "decision has no canonical_action_hash"}
            )
            continue
        actual_hash = pre_execution_hashes.get(request_id)
        if actual_hash != expected_hash:
            failures.append(
                {
                    "request_id": request_id,
                    "reason": "canonical_action_hash mismatch",
                    "expected": expected_hash,
                    "actual": actual_hash,
                }
            )
    return failures


def _coerce_requests(
    requests: Sequence[MCPFirewallRequest | Mapping[str, Any]],
) -> tuple[MCPFirewallRequest, ...]:
    return tuple(
        request
        if isinstance(request, MCPFirewallRequest)
        else MCPFirewallRequest.from_dict(request)
        for request in requests
    )


def _required_string(
    data: Mapping[str, Any],
    key: str,
    *,
    fallback_key: str,
) -> str:
    value = data.get(key, data.get(fallback_key))
    if not isinstance(value, str) or not value:
        raise ValueError(f"MCP Firewall request requires {key!r}")
    return value


def _read_json(path: str | Path) -> JsonObject:
    with Path(path).open("r", encoding="utf-8") as handle:
        return cast(JsonObject, json.load(handle))


def _forbidden_investor_terms(text: str) -> list[str]:
    forbidden = (
        "investor_target",
        "Investor To Reach",
        "Ann Miura-Ko",
        "Floodgate",
        "Sarah Guo",
        "Conviction",
    )
    return [term for term in forbidden if term in text]


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    from velvet.cli import mcp_firewall_main

    return mcp_firewall_main(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
