"""Audit and incident evidence packs for the Velvet control plane."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from velvet.agent_registry import AgentRegistry, load_agent_registry
from velvet.approvals import (
    ApprovalSnapshot,
    approval_receipt_findings,
    load_approval_snapshot,
)
from velvet.ledger import build_velvet_ledger_report
from velvet.serialization import canonical_hash
from velvet.signing import (
    DEFAULT_TENANT_ID,
    PURPOSE_EVIDENCE_MANIFEST,
    ArtifactSigner,
    SigningProvider,
    default_artifact_signer,
    signer_default_key_id,
    verify_signature_record,
)

JsonObject = dict[str, Any]

EVIDENCE_PACK_SCHEMA_VERSION = "velvet.evidence_pack.v1"
EVIDENCE_MANIFEST_SCHEMA_VERSION = "velvet.evidence_manifest.v1"


def build_evidence_pack(
    ledger_path: str | Path,
    *,
    thread_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> JsonObject:
    ledger_report = build_velvet_ledger_report(
        ledger_path,
        thread_path=thread_path,
        signer=signer,
    )
    ledger_verification = cast(Mapping[str, Any], ledger_report["ledger_verification"])
    registry = load_agent_registry(registry_path)
    approvals = load_approval_snapshot(approvals_path)
    entries = tuple(cast(Mapping[str, Any], item) for item in ledger_report["entries"])
    approval_findings = approval_receipt_findings(approvals)
    controls = _control_statuses(
        ledger_report,
        ledger_verification,
        registry,
        approvals,
        approval_findings,
    )
    gaps = _gaps(ledger_report, ledger_verification, registry, approvals, approval_findings)
    registry_findings = (
        [finding.to_dict() for finding in registry.scan_findings()] if registry is not None else []
    )
    schema_status_counts = (
        registry.summary()["schema_status_counts"] if registry is not None else {}
    )
    generated_at = datetime.now(tz=UTC).isoformat()
    pack: JsonObject = {
        "schema_version": EVIDENCE_PACK_SCHEMA_VERSION,
        "generated_at": generated_at,
        "ledger_path": str(ledger_path),
        "thread_path": str(thread_path) if thread_path is not None else None,
        "registry_path": str(registry_path) if registry_path is not None else None,
        "approvals_path": str(approvals_path) if approvals_path is not None else None,
        "summary": {
            "records": ledger_report["summary"]["records"],
            "decisions": ledger_report["summary"]["decision_counts"],
            "ledger_verification_status": ledger_verification["status"],
            "tools": dict(sorted(Counter(str(entry.get("tool_key")) for entry in entries).items())),
            "controls_passing": sum(1 for item in controls.values() if item["status"] == "pass"),
            "controls_attention": sum(1 for item in controls.values() if item["status"] != "pass"),
            "gaps": len(gaps),
            "registry_schema_status_counts": schema_status_counts,
            "registry_drift_findings": sum(
                1
                for finding in registry_findings
                if str(finding["finding_id"]).startswith("tool.schema_")
            ),
            "approvals": _approval_summary(approvals, approval_findings),
        },
        "controls": controls,
        "gaps": gaps,
        "registry_findings": registry_findings,
        "approval_findings": approval_findings,
        "registry": registry.to_dict() if registry is not None else None,
        "approvals": approvals.to_dict(),
        "ledger_report": ledger_report,
        "ledger_verification": ledger_verification,
        "incident_timeline": _incident_timeline(entries, approvals),
    }
    pack["manifest"] = _signed_evidence_manifest(
        pack,
        signer=signer,
        signing_key_id=signing_key_id,
    )
    return pack


def verify_evidence_manifest(
    pack: Mapping[str, Any],
    *,
    signer: ArtifactSigner | SigningProvider | None = None,
) -> bool:
    manifest = pack.get("manifest")
    if not isinstance(manifest, Mapping):
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return False
    unsigned_pack = {str(key): value for key, value in pack.items() if key != "manifest"}
    expected_hash = canonical_hash(unsigned_pack)
    if artifacts.get("unsigned_evidence_pack_hash") != expected_hash:
        return False
    if isinstance(signer, ArtifactSigner):
        return signer.verify_payload(manifest, PURPOSE_EVIDENCE_MANIFEST)
    unsigned_manifest = {
        str(key): value for key, value in manifest.items() if key != "signature"
    }
    signature = manifest.get("signature")
    if not isinstance(signature, Mapping):
        return False
    return verify_signature_record(
        signature,
        ArtifactSigner.payload_hash(unsigned_manifest),
        purpose=PURPOSE_EVIDENCE_MANIFEST,
        tenant_id=str(manifest.get("tenant_id", DEFAULT_TENANT_ID)),
        signer=signer,
    )


def render_evidence_pack_markdown(pack: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], pack["summary"])
    controls = cast(Mapping[str, Mapping[str, Any]], pack["controls"])
    lines = [
        "# Velvet Agent Operations Evidence Pack",
        "",
        f"Generated: `{pack['generated_at']}`",
        f"Ledger: `{pack['ledger_path']}`",
        f"Thread file: `{pack.get('thread_path')}`",
        "",
        "## Summary",
        "",
        f"- Records: `{summary['records']}`",
        f"- Decisions: `{json.dumps(summary['decisions'], sort_keys=True)}`",
        f"- Ledger verification: `{summary['ledger_verification_status']}`",
        f"- Controls passing: `{summary['controls_passing']}`",
        f"- Controls needing attention: `{summary['controls_attention']}`",
        f"- Gaps: `{summary['gaps']}`",
        (
            "- Registry schema statuses: "
            f"`{json.dumps(summary.get('registry_schema_status_counts', {}), sort_keys=True)}`"
        ),
        f"- Registry schema findings: `{summary.get('registry_drift_findings', 0)}`",
        f"- Approvals: `{json.dumps(summary.get('approvals', {}), sort_keys=True)}`",
        "",
        "## Controls",
        "",
    ]
    for key, control in sorted(controls.items()):
        lines.append(f"- `{key}`: `{control['status']}` - {control['message']}")
    lines.extend(["", "## Timeline", ""])
    for event in cast(tuple[Mapping[str, Any], ...], tuple(pack["incident_timeline"])):
        lines.extend(
            [
                f"### `{event['seal_id']}`",
                "",
                f"- Decision: `{event['decision']}` / `{event['action_type']}`",
                f"- Tool: `{event.get('tool_key')}`",
                f"- Approval: `{event['approval_status']}`",
                f"- Replayable: `{event['replayable']}`",
                "",
            ]
        )
    gaps = cast(list[Mapping[str, Any]], pack["gaps"])
    if gaps:
        lines.extend(["## Gaps", ""])
        for gap in gaps:
            lines.append(f"- `{gap['gap_id']}`: {gap['message']}")
    approval_findings = cast(list[Mapping[str, Any]], pack.get("approval_findings", []))
    if approval_findings:
        lines.extend(["", "## Approval Findings", ""])
        for finding in approval_findings:
            lines.append(
                f"- `{finding['finding_id']}` `{finding['severity']}` "
                f"`{finding.get('approval_receipt_id')}`: {finding['message']}"
            )
    registry_findings = cast(list[Mapping[str, Any]], pack.get("registry_findings", []))
    if registry_findings:
        lines.extend(["", "## Registry Findings", ""])
        for finding in registry_findings:
            lines.append(
                f"- `{finding['finding_id']}` `{finding['severity']}` "
                f"`{finding['subject']}`: {finding['message']}"
            )
    return "\n".join(lines)


def write_evidence_pack(
    ledger_path: str | Path,
    *,
    thread_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    output_dir: str | Path,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> tuple[Path, Path, JsonObject]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    pack = build_evidence_pack(
        ledger_path,
        thread_path=thread_path,
        registry_path=registry_path,
        approvals_path=approvals_path,
        signer=signer,
        signing_key_id=signing_key_id,
    )
    json_path = destination / "agent_ops_evidence_pack.json"
    markdown_path = destination / "agent_ops_evidence_pack.md"
    json_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_evidence_pack_markdown(pack), encoding="utf-8")
    return json_path, markdown_path, pack


def _approval_summary(
    approvals: ApprovalSnapshot,
    approval_findings: tuple[JsonObject, ...],
) -> JsonObject:
    now = datetime.now(tz=UTC)
    return {
        "pending": sum(1 for request in approvals.requests if request.status.value == "pending"),
        "approved": sum(1 for request in approvals.requests if request.status.value == "approved"),
        "denied": sum(1 for request in approvals.requests if request.status.value == "denied"),
        "expired_requests": sum(1 for request in approvals.requests if request.is_expired(now=now)),
        "receipts": len(approvals.receipts),
        "redeemed": sum(1 for receipt in approvals.receipts if receipt.used_at is not None),
        "invalid_or_attention": len(approval_findings),
    }


def _signed_evidence_manifest(
    pack: Mapping[str, Any],
    *,
    signer: SigningProvider | None,
    signing_key_id: str | None,
) -> JsonObject:
    tenant_id = _evidence_tenant_id(pack)
    unsigned_pack = {str(key): value for key, value in pack.items() if key != "manifest"}
    ledger_report = cast(Mapping[str, Any], pack["ledger_report"])
    approvals = cast(Mapping[str, Any], pack["approvals"])
    manifest: JsonObject = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": str(pack["generated_at"]),
        "artifacts": {
            "unsigned_evidence_pack_hash": canonical_hash(unsigned_pack),
            "ledger_report_hash": canonical_hash(ledger_report),
            "approvals_hash": canonical_hash(approvals),
            "registry_hash": canonical_hash(pack["registry"])
            if pack.get("registry") is not None
            else None,
        },
    }
    active_signer = (
        ArtifactSigner(
            signer,
            tenant_id=tenant_id,
            key_id=signing_key_id or signer_default_key_id(signer),
        )
        if signer is not None
        else default_artifact_signer(tenant_id=tenant_id)
    )
    manifest["signature"] = active_signer.sign_payload(
        manifest,
        PURPOSE_EVIDENCE_MANIFEST,
    ).to_dict()
    return manifest


def _evidence_tenant_id(pack: Mapping[str, Any]) -> str:
    ledger_report = pack.get("ledger_report")
    if isinstance(ledger_report, Mapping):
        entries = ledger_report.get("entries")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                value = entry.get("tenant_id")
                if isinstance(value, str) and value:
                    return value
    return DEFAULT_TENANT_ID


def _control_statuses(
    ledger_report: Mapping[str, Any],
    ledger_verification: Mapping[str, Any],
    registry: AgentRegistry | None,
    approvals: ApprovalSnapshot,
    approval_findings: tuple[JsonObject, ...],
) -> JsonObject:
    summary = cast(Mapping[str, Any], ledger_report["summary"])
    entries = tuple(cast(Mapping[str, Any], item) for item in ledger_report["entries"])
    escalated = tuple(entry for entry in entries if entry["decision"] == "escalate")
    pending_ids = {
        request.approval_request_id
        for request in approvals.requests
        if request.status.value == "pending"
    }
    approved_or_denied = {
        receipt.approval_request_id
        for receipt in approvals.receipts
        if receipt.status.value in {"approved", "denied"}
    }
    approval_coverage = not escalated or len(pending_ids | approved_or_denied) >= len(escalated)
    approval_status = (
        "fail"
        if approval_findings
        else "pass"
        if approval_coverage
        else "attention"
    )
    approval_message = (
        "Approval receipts include invalid, expired, or reused artifacts."
        if approval_findings
        else "Escalated actions have approval queue coverage."
        if approval_coverage
        else "Escalated actions are not covered by approval records."
    )
    ledger_status = str(ledger_verification["status"])
    ledger_integrity_status = (
        "pass" if ledger_status == "pass" else "fail" if ledger_status == "fail" else "attention"
    )
    ledger_integrity_message = (
        "Velvet Ledger hash-chain verification passed."
        if ledger_status == "pass"
        else "Velvet Ledger hash-chain verification failed."
        if ledger_status == "fail"
        else "Ledger records are legacy or otherwise not fully verifiable."
    )
    return {
        "ledger_integrity": {
            "status": ledger_integrity_status,
            "message": ledger_integrity_message,
        },
        "pre_execution_authorization": {
            "status": "pass" if summary["records"] else "attention",
            "message": "Ledger records exist before dispatch."
            if summary["records"]
            else "No ledger records found.",
        },
        "warrant_binding": {
            "status": "pass"
            if all(entry.get("policy_reasons") for entry in entries)
            else "attention",
            "message": "Every entry carries policy reasons."
            if all(entry.get("policy_reasons") for entry in entries)
            else "At least one entry is missing policy reasons.",
        },
        "replayability": {
            "status": "pass" if summary["without_thread"] == 0 else "attention",
            "message": "All ledger records link to schema 9.0 threads."
            if summary["without_thread"] == 0
            else "Some records are pre-routing or thread-free.",
        },
        "registry_ownership": {
            "status": "pass"
            if registry is not None and not registry.scan_findings()
            else "attention",
            "message": "Registry has no ownership or tool findings."
            if registry is not None and not registry.scan_findings()
            else "Registry is missing or has findings.",
        },
        "human_approval": {
            "status": approval_status,
            "message": approval_message,
        },
        "tool_schema_drift": {
            "status": "pass"
            if registry is not None
            and not any(
                finding.finding_id
                in {
                    "tool.schema_unreviewed",
                    "tool.schema_drifted",
                    "tool.schema_blocked",
                }
                for finding in registry.scan_findings()
            )
            else "attention",
            "message": "All registered tool schemas are approved."
            if registry is not None
            and not any(
                finding.finding_id
                in {
                    "tool.schema_unreviewed",
                    "tool.schema_drifted",
                    "tool.schema_blocked",
                }
                for finding in registry.scan_findings()
            )
            else "Registry has unreviewed, drifted, blocked, or missing tool schemas.",
        },
    }


def _gaps(
    ledger_report: Mapping[str, Any],
    ledger_verification: Mapping[str, Any],
    registry: AgentRegistry | None,
    approvals: ApprovalSnapshot,
    approval_findings: tuple[JsonObject, ...],
) -> list[JsonObject]:
    summary = cast(Mapping[str, Any], ledger_report["summary"])
    gaps: list[JsonObject] = []
    ledger_status = str(ledger_verification["status"])
    if ledger_status == "fail":
        gaps.append(
            {
                "gap_id": "ledger.verification_failed",
                "message": "Velvet Ledger hash-chain verification failed.",
                "count": len(cast(list[Mapping[str, Any]], ledger_verification["issues"])),
            }
        )
    elif ledger_status == "attention":
        gaps.append(
            {
                "gap_id": "ledger.legacy_or_unverified",
                "message": "Ledger records render but are not fully verifiable.",
                "count": len(cast(list[Mapping[str, Any]], ledger_verification["issues"])),
            }
        )
    if summary["without_thread"]:
        gaps.append(
            {
                "gap_id": "ledger.thread_free_records",
                "message": "Some ledger records cannot be replayed from a thread file.",
                "count": summary["without_thread"],
            }
        )
    if registry is None:
        gaps.append(
            {
                "gap_id": "registry.missing",
                "message": "No agent registry was attached to this evidence pack.",
            }
        )
    elif registry.scan_findings():
        gaps.append(
            {
                "gap_id": "registry.findings",
                "message": "Agent registry scan found ownership or tool-control issues.",
                "count": len(registry.scan_findings()),
            }
        )
        drift_findings = [
            finding
            for finding in registry.scan_findings()
            if finding.finding_id
            in {"tool.schema_unreviewed", "tool.schema_drifted", "tool.schema_blocked"}
        ]
        if drift_findings:
            gaps.append(
                {
                    "gap_id": "registry.tool_schema_drift",
                    "message": "Registry contains unapproved or drifted tool schemas.",
                    "count": len(drift_findings),
                }
            )
    if any(request.status.value == "pending" for request in approvals.requests):
        gaps.append(
            {
                "gap_id": "approval.pending",
                "message": "One or more escalated actions are still pending human review.",
                "count": sum(
                    1 for request in approvals.requests if request.status.value == "pending"
                ),
            }
        )
    if approval_findings:
        gaps.append(
            {
                "gap_id": "approval.receipt_findings",
                "message": (
                    "One or more approval receipts are invalid, expired, reused, or unbound."
                ),
                "count": len(approval_findings),
            }
        )
    return gaps


def _incident_timeline(
    entries: tuple[Mapping[str, Any], ...],
    approvals: ApprovalSnapshot,
) -> list[JsonObject]:
    approval_by_seal = {
        request.seal_id: request.status.value
        for request in approvals.requests
        if request.seal_id is not None
    }
    request_id_by_seal = {
        request.seal_id: request.approval_request_id
        for request in approvals.requests
        if request.seal_id is not None
    }
    receipt_by_request = {
        receipt.approval_request_id: receipt
        for receipt in approvals.receipts
    }
    timeline: list[JsonObject] = []
    for entry in entries:
        seal_id = cast(str | None, entry.get("seal_id"))
        approval_status = (
            approval_by_seal.get(seal_id, "not_required") if seal_id is not None else "not_required"
        )
        approval_request_id = (
            request_id_by_seal.get(seal_id) if seal_id is not None else None
        )
        receipt = (
            receipt_by_request.get(approval_request_id)
            if approval_request_id is not None
            else None
        )
        timeline.append(
            {
                "seal_id": seal_id,
                "thread_id": entry.get("thread_id"),
                "tool_key": entry.get("tool_key"),
                "decision": entry["decision"],
                "action_type": entry["action_type"],
                "reason": entry["reason"],
                "policy_reasons": entry.get("policy_reasons", []),
                "approval_status": approval_status,
                "approval_request_id": approval_request_id,
                "approval_receipt_id": receipt.approval_receipt_id
                if receipt is not None
                else None,
                "approval_receipt_used_at": receipt.used_at if receipt is not None else None,
                "replayable": bool(entry.get("thread_found")),
                "seal_status": entry.get("seal_status"),
            }
        )
    return timeline
