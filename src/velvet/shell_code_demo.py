"""Launch-grade shell/code proof for the canonical inline gateway."""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from velvet.approvals import ApprovalStatus, ApprovalStore
from velvet.contracts import AdmissionContract
from velvet.gateway import CallableDispatcher, InlineGateway, InlineGatewayRequest
from velvet.serialization import JsonObject, canonical_hash_sha256, stable_json_object
from velvet.storage import LocalFilesystemEvidenceStore, LocalManifestSigner

DEMO_ID = "shell-code-inline-gateway"
DEMO_SCHEMA_VERSION = "velvet.shell_code_inline_gateway_demo.v1"
TENANT_ID = "tenant-a"


def run_shell_code_inline_gateway_demo(output_dir: str | Path) -> JsonObject:
    """Run the protocol-agnostic inline-gateway shell/code approval demo."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    ledger_path = destination / "inline_gateway.jsonl"
    approvals_path = destination / "approvals.json"
    report_json_path = destination / "shell_code_demo.json"
    report_markdown_path = destination / "shell_code_demo.md"
    for path in (ledger_path, approvals_path, report_json_path, report_markdown_path):
        if path.exists():
            path.unlink()
    for path in (destination / "inline_gateway_raw_actions", destination / "evidence_store"):
        if path.exists():
            shutil.rmtree(path)

    dispatch_calls: list[JsonObject] = []

    def dry_run_shell_dispatch(
        action: Any,
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del context
        command = _command_from_action(action.normalized_payload)
        receipt: JsonObject = {
            "mode": "dry_run",
            "would_execute": True,
            "command": command,
            "sandbox_required": bool(action.normalized_payload.get("sandbox_required")),
            "canonical_action_hash": action.canonical_action_hash,
            "surface": action.surface,
        }
        dispatch_calls.append(receipt)
        return receipt

    approvals = ApprovalStore(approvals_path)
    gateway = InlineGateway(
        contract=AdmissionContract(),
        ledger_path=ledger_path,
        approval_store=approvals,
        dispatchers={
            "shell_code": CallableDispatcher("shell-code-dry-run", dry_run_shell_dispatch)
        },
    )

    exact_request = _demo_request("shell-code-exact", _shell_action())
    exact_decision = gateway.authorize(exact_request)
    exact_approval = _approve_pending(approvals, exact_decision.approval_request)
    exact_result = gateway.run_approved(
        exact_decision,
        exact_approval["approval_receipt_id"],
    )

    drift_request = _demo_request("shell-code-drift", _shell_action())
    drift_decision = gateway.authorize(drift_request)
    drift_approval = _approve_pending(approvals, drift_decision.approval_request)
    drifted_action = _shell_action(command_suffix=" --no-dry-run")
    drift_result = gateway.run_approved(
        drift_decision,
        drift_approval["approval_receipt_id"],
        proposed_action=drifted_action,
    )

    ledger_records = _read_jsonl(ledger_path)
    approvals_snapshot = approvals.load().to_dict()
    payload = _build_report(
        destination=destination,
        ledger_path=ledger_path,
        approvals_path=approvals_path,
        exact_decision=exact_decision.to_dict(),
        exact_approval=exact_approval,
        exact_result=exact_result.to_dict(),
        drift_decision=drift_decision.to_dict(),
        drift_approval=drift_approval,
        drifted_action=drifted_action,
        drift_result=drift_result.to_dict(),
        ledger_records=ledger_records,
        approvals_snapshot=approvals_snapshot,
        dispatch_calls=dispatch_calls,
    )
    report_json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_markdown_path.write_text(render_shell_code_demo_markdown(payload), encoding="utf-8")

    store = LocalFilesystemEvidenceStore(destination / "evidence_store")
    artifact_refs = [
        store.put_artifact(
            ledger_path,
            "ledger_segment_binary",
            TENANT_ID,
            {"name": ledger_path.name, "demo": DEMO_ID, "surface": "shell_code"},
        ),
        store.put_artifact(
            approvals_path,
            "approval_receipt_snapshot",
            TENANT_ID,
            {"name": approvals_path.name, "demo": DEMO_ID},
        ),
        store.put_artifact(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            "evidence_pack_json",
            TENANT_ID,
            {
                "name": report_json_path.name,
                "demo": DEMO_ID,
                "note": "stored before evidence_manifest field to avoid circular manifest data",
            },
        ),
        store.put_artifact(
            render_shell_code_demo_markdown(payload).encode("utf-8"),
            "evidence_pack_markdown",
            TENANT_ID,
            {
                "name": report_markdown_path.name,
                "demo": DEMO_ID,
                "note": "stored before evidence_manifest field to avoid circular manifest data",
            },
        ),
    ]
    evidence_manifest = store.write_manifest(
        artifact_refs,
        LocalManifestSigner(tenant_id=TENANT_ID),
    )
    payload["artifacts"]["evidence_store_root"] = str(destination / "evidence_store")
    payload["evidence_manifest"] = evidence_manifest.to_dict()
    payload["evidence_verification"] = store.verify_manifest(evidence_manifest).to_dict()
    payload["summary"]["evidence_verification"] = payload["evidence_verification"]["status"]
    report_json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_markdown_path.write_text(render_shell_code_demo_markdown(payload), encoding="utf-8")
    return payload


def render_shell_code_demo_markdown(payload: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], payload["summary"])
    exact = cast(Mapping[str, Any], summary["exact_approved_dispatch"])
    drift = cast(Mapping[str, Any], summary["drift_after_approval"])
    controls = cast(Mapping[str, Mapping[str, str]], payload["controls"])
    lines = [
        "# Shell/Code Inline Gateway Demo",
        "",
        "This demo uses the canonical inline gateway on `surface: shell_code`, not MCP.",
        "",
        "## Reproduce",
        "",
        "```bash",
        (
            "uv run velvet shell-code-demo --output-dir "
            "reports/launch/shell-code-inline-gateway --json"
        ),
        "```",
        "",
        "## Summary",
        "",
        f"- Exact approved dispatch: `{exact['outcome']}`",
        f"- Drift after approval: `{drift['outcome']}` / `{drift.get('reason')}`",
        f"- Inline ledger records: `{summary['inline_ledger_records']}`",
        f"- Evidence verification: `{summary.get('evidence_verification', 'pending')}`",
        "",
        "## Controls",
        "",
    ]
    for name, control in sorted(controls.items()):
        lines.append(f"- `{name}`: `{control['status']}` - {control['message']}")
    lines.extend(
        [
            "",
            "## Binding",
            "",
            f"- Approved canonical action hash: `{exact['canonical_action_hash']}`",
            f"- Drifted current action hash: `{drift['current_action_hash']}`",
            "- Drift rejection proves the approved receipt cannot be reused for a changed "
            "shell/code command.",
            "",
        ]
    )
    manifest = payload.get("evidence_manifest")
    if isinstance(manifest, Mapping):
        lines.extend(
            [
                "## Evidence Manifest",
                "",
                f"- Manifest: `{manifest['manifest_id']}`",
                f"- Hash: `{manifest['manifest_hash']}`",
            ]
        )
    return "\n".join(lines)


def _build_report(
    *,
    destination: Path,
    ledger_path: Path,
    approvals_path: Path,
    exact_decision: Mapping[str, Any],
    exact_approval: Mapping[str, Any],
    exact_result: Mapping[str, Any],
    drift_decision: Mapping[str, Any],
    drift_approval: Mapping[str, Any],
    drifted_action: Mapping[str, Any],
    drift_result: Mapping[str, Any],
    ledger_records: list[JsonObject],
    approvals_snapshot: Mapping[str, Any],
    dispatch_calls: list[JsonObject],
) -> JsonObject:
    exact_receipt = cast(Mapping[str, Any], exact_result["execution_receipt"])
    drift_receipt = cast(Mapping[str, Any], drift_result["execution_receipt"])
    exact_action_hash = str(exact_decision["canonical_action_hash"])
    drift_admitted_hash = str(drift_decision["canonical_action_hash"])
    drift_current_hash = _current_action_hash_from_receipt(drift_receipt)
    controls = {
        "pre_execution_admission": {
            "status": "pass"
            if exact_decision["decision"] == "ESCALATED"
            and drift_decision["decision"] == "ESCALATED"
            else "fail",
            "message": (
                "Shell/code actions were normalized, priced, and held at approval before dispatch."
            ),
        },
        "exact_action_binding": {
            "status": "pass"
            if exact_receipt["outcome"] == "succeeded"
            and _hashes_match(
                cast(Mapping[str, Any], exact_receipt["output"])["canonical_action_hash"],
                exact_action_hash,
            )
            else "fail",
            "message": "Approved permit dispatched only for the canonical action hash it approved.",
        },
        "reject_on_drift_after_approval": {
            "status": "pass"
            if drift_receipt["outcome"] in {"rejected", "failed_before_dispatch"}
            and not drift_receipt["dispatch_attempted"]
            and (
                cast(Mapping[str, Any], drift_receipt["error"])["code"]
                in {"rejected", "scope_mismatch"}
            )
            else "fail",
            "message": "Changed shell/code command was not dispatched after approval.",
        },
        "protocol_agnostic_surface": {
            "status": "pass" if _surface_set(ledger_records) == {"shell_code"} else "fail",
            "message": (
                "The proof path uses the inline gateway shell/code surface rather than MCP fields."
            ),
        },
    }
    return {
        "schema_version": DEMO_SCHEMA_VERSION,
        "demo_id": DEMO_ID,
        "protocol_story": {
            "surface": "shell_code",
            "protocol_agnostic": True,
            "mcp_required": False,
            "gateway": "velvet_inline_gateway",
        },
        "artifacts": {
            "output_dir": str(destination),
            "ledger_path": str(ledger_path),
            "approvals_path": str(approvals_path),
            "report_json_path": str(destination / "shell_code_demo.json"),
            "report_markdown_path": str(destination / "shell_code_demo.md"),
        },
        "summary": {
            "inline_ledger_records": len(ledger_records),
            "approval_requests": cast(Mapping[str, Any], approvals_snapshot["summary"])["requests"],
            "approval_receipts": cast(Mapping[str, Any], approvals_snapshot["summary"])["receipts"],
            "redeemed_receipts": cast(Mapping[str, Any], approvals_snapshot["summary"])["redeemed"],
            "exact_approved_dispatch": {
                "pre_execution_decision": exact_decision["decision"],
                "approval_status": "approved" if exact_approval["approved"] else "denied",
                "outcome": exact_receipt["outcome"],
                "reason": exact_receipt.get("reason"),
                "canonical_action_hash": exact_action_hash,
            },
            "drift_after_approval": {
                "pre_execution_decision": drift_decision["decision"],
                "approval_status": "approved" if drift_approval["approved"] else "denied",
                "outcome": drift_receipt["outcome"],
                "reason": drift_receipt.get("reason"),
                "approved_canonical_action_hash": drift_admitted_hash,
                "current_action_hash": drift_current_hash,
            },
            "evidence_verification": "pending",
        },
        "controls": controls,
        "steps": [
            {
                "step": "pre_execution_admission",
                "decision": exact_decision["decision"],
                "canonical_action_hash": exact_action_hash,
                "approval_request_id": cast(Mapping[str, Any], exact_decision["approval_request"])[
                    "approval_request_id"
                ],
            },
            {
                "step": "exact_approval_and_dispatch",
                "approval_receipt_id": exact_approval["approval_receipt_id"],
                "execution_outcome": exact_receipt["outcome"],
            },
            {
                "step": "drift_pre_execution_approval",
                "decision": drift_decision["decision"],
                "canonical_action_hash": drift_admitted_hash,
                "approval_receipt_id": drift_approval["approval_receipt_id"],
            },
            {
                "step": "reject_on_drift",
                "drifted_action_hash": drift_current_hash,
                "execution_outcome": drift_receipt["outcome"],
                "reason": drift_receipt.get("reason"),
            },
        ],
        "exact": {
            "decision": stable_json_object(exact_decision),
            "approval_receipt": stable_json_object(exact_approval),
            "result": stable_json_object(exact_result),
        },
        "drift": {
            "decision": stable_json_object(drift_decision),
            "approval_receipt": stable_json_object(drift_approval),
            "drifted_action": stable_json_object(drifted_action),
            "result": stable_json_object(drift_result),
        },
        "approvals": stable_json_object(approvals_snapshot),
        "inline_ledger_records": ledger_records,
        "dispatch_calls": dispatch_calls,
    }


def _demo_request(request_id: str, proposed_action: Mapping[str, Any]) -> InlineGatewayRequest:
    return InlineGatewayRequest(
        request_id=request_id,
        replay_id=DEMO_ID,
        proposed_action=proposed_action,
        context={
            "tenant_id": TENANT_ID,
            "environment": "production",
            "user_id": "platform-lead@example.com",
        },
    )


def _shell_action(*, command_suffix: str = "") -> JsonObject:
    command = "python scripts/rotate_service_token.py --service payments --dry-run"
    return {
        "surface": "shell_code",
        "operation": "deploy",
        "command": command + command_suffix,
        "cwd": "/srv/velvet/pilot",
        "env": {"VELVET_DEMO_MODE": "dry_run"},
        "external_party": "production-payments",
        "actor_id": "platform-lead@example.com",
        "agent_id": "release-agent",
        "tenant_id": TENANT_ID,
        "environment": "production",
        "boundary_key": "shell:payments:release",
        "target_resource": "shell_code:payments-release",
    }


def _approve_pending(
    approvals: ApprovalStore,
    approval_request: Mapping[str, Any] | None,
) -> JsonObject:
    if approval_request is None:
        raise RuntimeError("expected pending shell/code approval request")
    receipt = approvals.decide(
        str(approval_request["approval_request_id"]),
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="Approved exact dry-run shell/code action for launch demo.",
        conditions=("no command or argument drift",),
    )
    return receipt.to_dict()


def _read_jsonl(path: Path) -> list[JsonObject]:
    return [
        cast(JsonObject, json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _surface_set(records: list[JsonObject]) -> set[str]:
    surfaces: set[str] = set()
    for record in records:
        action = record.get("canonical_action")
        if isinstance(action, Mapping):
            surfaces.add(str(action.get("surface")))
    return surfaces


def _hashes_match(left: object, right: object) -> bool:
    """Compare canonical hashes across prefixed and legacy unprefixed surfaces."""

    left_value = str(left).removeprefix("sha256:")
    right_value = str(right).removeprefix("sha256:")
    return len(left_value) == 64 and left_value == right_value


def _command_from_action(normalized_payload: Mapping[str, Any]) -> str | None:
    redacted_args = normalized_payload.get("arguments_redacted")
    if not isinstance(redacted_args, Mapping):
        return None
    command = redacted_args.get("command")
    return command if isinstance(command, str) else None


def _current_action_hash_from_receipt(receipt: Mapping[str, Any]) -> str:
    output = receipt.get("output")
    if isinstance(output, Mapping) and isinstance(output.get("canonical_action_hash"), str):
        return str(output["canonical_action_hash"])
    return canonical_hash_sha256({})


__all__ = ["run_shell_code_inline_gateway_demo", "render_shell_code_demo_markdown"]
