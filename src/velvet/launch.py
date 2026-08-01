"""Launch-readiness demo artifact generation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from velvet.claims_pack import write_claims_pack
from velvet.ledger import (
    build_velvet_ledger_report,
    read_ledger_records,
    render_velvet_ledger_markdown,
    seal_thread_decision,
)
from velvet.mcp import DirectVelvetMCPAdapter
from velvet.policy_bundle import (
    DEMO_POLICY_BUNDLE_SIGNING_KEY,
    VerifiedPolicyBundle,
    load_policy_bundle,
    write_signed_policy_bundle,
)
from velvet.signing import (
    SigningProvider,
    load_demo_ed25519_signer,
    resolve_ed25519_signing_provider,
    signer_default_key_id,
)
from velvet.storage import LocalFilesystemEvidenceStore, LocalManifestSigner
from velvet.vault.sth import build_signed_tree_head
from velvet.vault.verify import verify_vault_segment

JsonObject = dict[str, Any]

DEMO_REQUESTS: tuple[JsonObject, ...] = (
    {
        "label": "allowed_enterprise_read_only_lookup",
        "server": "servicenow",
        "tool": "search_change_requests",
        "arguments": {"query": "service=payments state=open"},
        "user_request": (
            "Find open production payment-service change requests before opening anything new."
        ),
    },
    {
        "label": "blocked_destructive_enterprise_call",
        "server": "servicenow",
        "tool": "delete_change_request",
        "arguments": {"change_id": "CHG0042007"},
        "user_request": "Remove the stale production change request before the release meeting.",
    },
    {
        "label": "escalated_sensitive_enterprise_write",
        "server": "servicenow",
        "tool": "create_change_request",
        "arguments": {
            "service": "payments",
            "summary": "Approve production deploy for routing fix",
            "window": "2026-05-23T22:00:00-07:00",
        },
        "user_request": "Open a production change request for the routing fix.",
    },
)


def run_launch_demo(
    output_dir: str | Path,
    *,
    list_path: str | Path = "examples/mcp/list.json",
    policy_dir: str | Path = "examples/mcp/policies",
    chain: str = "mcp_demo",
    tenant_id: str = "pilot",
    policy_bundle: str | Path | VerifiedPolicyBundle | None = None,
    policy_bundle_signing_key: str = DEMO_POLICY_BUNDLE_SIGNING_KEY,
    allow_expired_policy_degraded: bool = False,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
    signing_profile: str | None = "demo",
    dev_ephemeral_key: bool = False,
) -> JsonObject:
    """Run the launch workflow and write thread, ledger, and report artifacts."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    thread_path = destination / "mcp_thread.jsonl"
    ledger_path = destination / "velvet_ledger.vledger"
    for path in (thread_path, ledger_path):
        if path.exists():
            path.unlink()

    verified_bundle = _load_or_create_launch_policy_bundle(
        destination,
        policy_bundle=policy_bundle,
        policy_dir=policy_dir,
        chain=chain,
        tenant_id=tenant_id,
        signing_key=policy_bundle_signing_key,
        allow_expired=allow_expired_policy_degraded,
    )
    active_policy_dir = verified_bundle.materialize_policy_dir()
    active_chain = verified_bundle.policy_chain
    active_signer = signer or (
        resolve_ed25519_signing_provider(
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
            key_id=signing_key_id,
        )
        if dev_ephemeral_key or signing_profile != "demo"
        else load_demo_ed25519_signer()
    )
    active_signing_key_id = signing_key_id or signer_default_key_id(active_signer)

    adapter = DirectVelvetMCPAdapter.from_list_file(
        list_path,
        policy_dir=str(active_policy_dir),
        chain=active_chain,
        policy_bundle=verified_bundle,
        policy_bundle_signing_key=policy_bundle_signing_key,
        require_policy_bundle=True,
        allow_expired_policy_degraded=allow_expired_policy_degraded,
        signer=active_signer,
        signing_key_id=active_signing_key_id,
    )
    decisions = [
        adapter.authorize(request, thread_path=thread_path, ledger_path=ledger_path)
        for request in DEMO_REQUESTS
    ]
    report = build_velvet_ledger_report(
        ledger_path,
        thread_path=thread_path,
        signer=active_signer,
    )
    ledger_report_json_path = destination / "velvet_ledger_report.json"
    ledger_report_markdown_path = destination / "velvet_ledger_report.md"
    ledger_report_json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ledger_report_markdown_path.write_text(
        render_velvet_ledger_markdown(report),
        encoding="utf-8",
    )
    replay_report = seal_thread_decision(
        thread_path,
        str(decisions[0]["admission_decision"]["seal_id"]),
        policy_dir=str(active_policy_dir),
        chain=active_chain,
    )
    replay_report_path = destination / "replay_report.json"
    replay_report_path.write_text(
        json.dumps(replay_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    records = tuple(read_ledger_records(ledger_path))
    if not records:
        raise RuntimeError("launch demo produced no ledger records")
    vault_dir = destination / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    sth_path = vault_dir / "signed_tree_head.json"
    public_key_path = vault_dir / "vault_public_key.pem"
    vault_verification_report_path = vault_dir / "vault_verification_report.json"
    record_hashes = [str(record["record_hash"]) for record in records]
    first_sequence = int(records[0]["sequence_number"])
    last_sequence = int(records[-1]["sequence_number"])
    segment_range = f"{first_sequence}-{last_sequence}"
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=first_sequence,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=active_signer,
        key_id=active_signing_key_id,
    )
    _write_json(sth_path, sth)
    public_key_pem = _public_key_pem(active_signer, active_signing_key_id)
    public_key_path.write_text(public_key_pem, encoding="utf-8")
    vault_verification = verify_vault_segment(
        segment_range=segment_range,
        sth_path=sth_path,
        public_key=public_key_pem,
        ledger_path=ledger_path,
    )
    _write_json(vault_verification_report_path, vault_verification)
    if vault_verification.get("status") != "pass":
        raise RuntimeError("launch Vault segment did not verify")

    incident_start, incident_end = _incident_window_for_records(records)
    claims_dir = destination / "claims_pack"
    claims_result_path = destination / "claims_pack.result.json"
    claims_pack = write_claims_pack(
        incident_window_start=incident_start,
        incident_window_end=incident_end,
        ledger_path=ledger_path,
        sth_path=sth_path,
        public_key=public_key_pem,
        output_dir=claims_dir,
        system_name="Velvet launch MCP demo",
        intended_purpose="Pre-execution MCP action admission for investor launch workflow",
        deployer_legal_entity="Velvet Demo Ltd.",
        eu_exposure=True,
        deployment_id_source="velvet-launch-demo/local",
        deployment_salt="velvet-launch-demo-demo-salt",
        signer=active_signer,
        signing_key_id=active_signing_key_id,
        latest_sth_path=sth_path,
        thread_path=thread_path,
        policy_bundle_hash=str(records[-1]["policy_hash"]),
        policy_bundle_signature_status="valid",
        retention_preset="eu_ai_act_minimum",
    )
    claims_result_path.write_text(
        json.dumps(claims_pack, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    payload = {
        "launch_score": 78,
        "thread_path": str(thread_path),
        "ledger_path": str(ledger_path),
        "replay_report_path": str(replay_report_path),
        "policy_bundle_path": verified_bundle.source_path,
        "policy_bundle": verified_bundle.summary,
        "signing_public_key": active_signer.public_verification_material(active_signing_key_id),
        "decisions": decisions,
        "velvet_ledger_report": report,
        "replay_report": replay_report,
        "incident_window": {
            "start": incident_start,
            "end": incident_end,
            "segment": segment_range,
        },
        "vault": {
            "ledger": str(ledger_path),
            "sth": str(sth_path),
            "public_key": str(public_key_path),
            "verification": str(vault_verification_report_path),
            "verification_status": vault_verification["status"],
            "segment": segment_range,
            "record_count": len(records),
        },
        "claims_pack": {
            "output_dir": str(claims_dir),
            "result": str(claims_result_path),
            "attestation_pack_manifest": str(claims_dir / "manifest.json"),
            "attestation_pack_segment": claims_pack["attestation_pack_manifest"]["segment"],
            "assurance_attestations": str(claims_dir / "assurance" / "attestations.jsonl"),
            "assurance_consistency_proofs": str(
                claims_dir / "assurance" / "consistency_proofs.json"
            ),
            "assurance_verification": str(
                claims_dir / "verification" / "assurance_verification_report.json"
            ),
            "assurance_verification_status": claims_pack["assurance_verification"]["status"],
            "replay_verification": str(
                claims_dir / "verification" / "claims_replay_verification_report.json"
            ),
            "replay_verification_status": claims_pack["replay_verification"]["status"],
        },
        "single_thing_not_cut": (
            "Velvet Warrant linked to replayable jurisdiction_evidence for every consequential "
            "agent action before execution."
        ),
    }
    store = LocalFilesystemEvidenceStore(destination / "evidence_store")
    artifact_refs = [
        store.put_artifact(
            ledger_path,
            "ledger_segment_binary",
            tenant_id,
            {"name": "velvet_ledger.vledger", "demo": "launch"},
        ),
        store.put_artifact(
            ledger_report_json_path,
            "ledger_segment_manifest",
            tenant_id,
            {"name": "velvet_ledger_report.json", "demo": "launch"},
        ),
        store.put_artifact(
            ledger_report_markdown_path,
            "evidence_pack_markdown",
            tenant_id,
            {"name": "velvet_ledger_report.md", "demo": "launch"},
        ),
        store.put_artifact(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            "evidence_pack_json",
            tenant_id,
            {
                "name": "launch_demo.json",
                "demo": "launch",
                "note": "stored before evidence_manifest field to avoid circular manifest data",
            },
        ),
        store.put_artifact(
            list_path,
            "tool_inventory_snapshot",
            tenant_id,
            {"name": Path(list_path).name, "demo": "launch"},
        ),
        store.put_artifact(
            _policy_bundle_snapshot_bytes(policy_dir, chain=chain),
            "policy_bundle_snapshot",
            tenant_id,
            {"policy_dir": str(policy_dir), "chain": chain, "demo": "launch"},
        ),
        store.put_artifact(
            json.dumps(verified_bundle.payload, indent=2, sort_keys=True).encode("utf-8"),
            "signed_policy_bundle",
            tenant_id,
            {"bundle_id": verified_bundle.bundle_id, "demo": "launch"},
        ),
        store.put_artifact(
            replay_report_path,
            "replay_report",
            tenant_id,
            {"name": "replay_report.json", "demo": "launch"},
        ),
        store.put_artifact(
            sth_path,
            "vault_signed_tree_head",
            tenant_id,
            {"name": "signed_tree_head.json", "demo": "launch", "segment": segment_range},
        ),
        store.put_artifact(
            public_key_path,
            "vault_public_key",
            tenant_id,
            {"name": "vault_public_key.pem", "demo": "launch"},
        ),
        store.put_artifact(
            vault_verification_report_path,
            "vault_verification_report",
            tenant_id,
            {"name": "vault_verification_report.json", "demo": "launch"},
        ),
        store.put_artifact(
            claims_result_path,
            "claims_pack_result",
            tenant_id,
            {"name": "claims_pack.result.json", "demo": "launch"},
        ),
        store.put_artifact(
            claims_dir / "manifest.json",
            "claims_pack_manifest",
            tenant_id,
            {"name": "claims_pack/manifest.json", "demo": "launch"},
        ),
        store.put_artifact(
            claims_dir / "assurance" / "attestations.jsonl",
            "assurance_attestation_series",
            tenant_id,
            {"name": "claims_pack/assurance/attestations.jsonl", "demo": "launch"},
        ),
        store.put_artifact(
            claims_dir / "assurance" / "consistency_proofs.json",
            "assurance_consistency_proofs",
            tenant_id,
            {"name": "claims_pack/assurance/consistency_proofs.json", "demo": "launch"},
        ),
        store.put_artifact(
            claims_dir / "verification" / "assurance_verification_report.json",
            "assurance_verification_report",
            tenant_id,
            {
                "name": "claims_pack/verification/assurance_verification_report.json",
                "demo": "launch",
            },
        ),
        store.put_artifact(
            claims_dir / "verification" / "claims_replay_verification_report.json",
            "claims_replay_verification_report",
            tenant_id,
            {
                "name": "claims_pack/verification/claims_replay_verification_report.json",
                "demo": "launch",
            },
        ),
    ]
    evidence_manifest = store.write_manifest(artifact_refs, LocalManifestSigner())
    payload["evidence_store_root"] = str(destination / "evidence_store")
    payload["evidence_manifest"] = evidence_manifest.to_dict()
    payload["evidence_verification"] = store.verify_manifest(evidence_manifest).to_dict()
    (destination / "launch_demo.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _public_key_pem(signer: SigningProvider, key_id: str) -> str:
    material = signer.public_verification_material(key_id)
    if not isinstance(material, Mapping):
        raise RuntimeError("launch signer does not expose public verification material")
    public_key_pem = material.get("public_key_pem")
    if not isinstance(public_key_pem, str) or not public_key_pem:
        raise RuntimeError("launch signer public verification material has no PEM key")
    return public_key_pem


def _incident_window_for_records(records: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    timestamps = [_recorded_at(record) for record in records]
    if not timestamps:
        raise RuntimeError("launch records have no recorded_at timestamps")
    return _iso_z(min(timestamps)), _iso_z(max(timestamps) + timedelta(microseconds=1))


def _recorded_at(record: Mapping[str, Any]) -> datetime:
    value = record.get("recorded_at")
    if not isinstance(value, str) or not value:
        raise RuntimeError("launch record is missing recorded_at")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _load_or_create_launch_policy_bundle(
    destination: Path,
    *,
    policy_bundle: str | Path | VerifiedPolicyBundle | None,
    policy_dir: str | Path,
    chain: str,
    tenant_id: str,
    signing_key: str,
    allow_expired: bool,
) -> VerifiedPolicyBundle:
    if isinstance(policy_bundle, VerifiedPolicyBundle):
        return policy_bundle
    if policy_bundle is not None:
        return load_policy_bundle(
            policy_bundle,
            signing_key=signing_key,
            allow_expired=allow_expired,
        )
    generated = destination / "policy_bundle.json"
    write_signed_policy_bundle(
        generated,
        policy_dir=policy_dir,
        chain=chain,
        signing_key=signing_key,
        tenant_id=tenant_id,
        environment="local",
    )
    return load_policy_bundle(generated, signing_key=signing_key)


def _policy_bundle_snapshot_bytes(policy_dir: str | Path, *, chain: str) -> bytes:
    root = Path(policy_dir)
    files: list[JsonObject] = []
    if root.exists():
        paths = sorted(path for path in root.rglob("*") if path.is_file())
    else:
        paths = []
    for path in paths:
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "contents_utf8": data.decode("utf-8"),
            }
        )
    payload = {
        "schema_version": "velvet.policy_bundle_snapshot.v1",
        "policy_dir": str(policy_dir),
        "chain": chain,
        "files": files,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
