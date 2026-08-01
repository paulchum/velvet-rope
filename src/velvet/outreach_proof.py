"""Proof packs for outreach claims about Velvet warrants.

The pack is intentionally narrow: it proves that the local demo emits
Ed25519-signed warrants and ledger records that can be verified with public
material. It does not claim hosted enterprise readiness or broad agent safety.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from velvet.launch import run_launch_demo
from velvet.ledger import ledger_record_hash, read_ledger_records, verify_velvet_ledger
from velvet.rope import VelvetWarrant
from velvet.signing import (
    PURPOSE_LEDGER_RECORD,
    PURPOSE_WARRANT,
    SigningProvider,
    load_demo_ed25519_signer,
    resolve_ed25519_signing_provider,
    signer_default_key_id,
    verify_signature_record,
)

JsonObject = dict[str, Any]

PROOF_VERSION = "velvet-outreach-warrant-proof-v1"


def write_outreach_warrant_proof(
    output_dir: str | Path,
    *,
    signer: SigningProvider | None = None,
    signing_profile: str | None = "demo",
    dev_ephemeral_key: bool = False,
) -> JsonObject:
    """Write a public-key-verifiable warrant proof pack."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    active_signer = signer or (
        resolve_ed25519_signing_provider(
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
        )
        if dev_ephemeral_key or signing_profile != "demo"
        else load_demo_ed25519_signer()
    )
    key_id = signer_default_key_id(active_signer)
    public_material = active_signer.public_verification_material(key_id)
    if active_signer.algorithm != "Ed25519" or not isinstance(public_material, Mapping):
        raise RuntimeError("outreach warrant proof requires public-key-verifiable Ed25519 signing")
    public_key = _public_key_from_material(public_material)

    launch_payload = run_launch_demo(
        destination,
        signer=active_signer,
        signing_key_id=key_id,
        signing_profile=signing_profile,
        dev_ephemeral_key=dev_ephemeral_key,
    )
    warrant_dir = destination / "warrants"
    warrant_dir.mkdir(parents=True, exist_ok=True)
    warrant_reports = _write_and_verify_warrants(
        launch_payload,
        warrant_dir=warrant_dir,
        public_key=public_key,
    )
    ledger_records = list(read_ledger_records(launch_payload["ledger_path"]))
    ledger_report = verify_velvet_ledger(
        launch_payload["ledger_path"],
        enforce_signatures=True,
        public_key=public_key,
    )
    ledger_signature_reports = [
        _verify_ledger_record(record, public_key=public_key)
        for record in ledger_records
    ]
    proof_json = destination / "outreach-warrant-proof.json"
    proof_markdown = destination / "outreach-warrant-proof.md"
    artifact_paths = {
        "launch_demo": str(destination / "launch_demo.json"),
        "ledger": launch_payload["ledger_path"],
        "ledger_report": str(destination / "velvet_ledger_report.json"),
        "replay_report": launch_payload["replay_report_path"],
        "warrant_dir": str(warrant_dir),
        "proof_json": str(proof_json),
        "proof_markdown": str(proof_markdown),
    }
    payload: JsonObject = {
        "proof_version": PROOF_VERSION,
        "claim_boundary": (
            "Local deterministic proof that demoed agent actions produce "
            "Ed25519-signed Velvet Warrants, sealed ledger records, replay "
            "artifacts, and public verification material. This is not a hosted "
            "enterprise governance claim or a guarantee of arbitrary-agent safety."
        ),
        "signing": {
            "algorithm": active_signer.algorithm,
            "provider": active_signer.provider_name,
            "key_id": key_id,
            "public_verification_material": dict(public_material),
        },
        "artifacts": artifact_paths,
        "decisions": _decision_summaries(launch_payload),
        "warrants": warrant_reports,
        "ledger_verification": ledger_report,
        "ledger_signature_reports": ledger_signature_reports,
    }
    payload["artifact_hash"] = _artifact_hash(payload)
    proof_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    proof_markdown.write_text(_render_markdown(payload), encoding="utf-8")
    return payload


def _write_and_verify_warrants(
    launch_payload: Mapping[str, Any],
    *,
    warrant_dir: Path,
    public_key: str,
) -> list[JsonObject]:
    reports: list[JsonObject] = []
    for index, decision in enumerate(launch_payload["decisions"], start=1):
        admission = decision["admission_decision"]
        warrant = admission["selected_warrant"]
        decision_name = str(warrant.get("decision", f"decision-{index}"))
        path = warrant_dir / f"{index:02d}-{decision_name}-warrant.json"
        path.write_text(
            json.dumps(warrant, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        hash_ok = VelvetWarrant.verify_payload_hash(warrant)
        signature = warrant.get("signature")
        signature_ok = isinstance(signature, Mapping) and verify_signature_record(
            signature,
            str(warrant["warrant_hash"]),
            purpose=PURPOSE_WARRANT,
            tenant_id=str(warrant["tenant_id"]),
            key_id=str(signature["key_id"]),
            public_key=public_key,
        )
        reports.append(
            {
                "path": str(path),
                "decision": decision_name,
                "warrant_hash": warrant["warrant_hash"],
                "status": "pass" if hash_ok and signature_ok else "fail",
                "checks": {
                    "warrant_hash": "pass" if hash_ok else "fail",
                    "ed25519_signature": "pass" if signature_ok else "fail",
                },
            }
        )
    return reports


def _verify_ledger_record(record: Mapping[str, Any], *, public_key: str) -> JsonObject:
    expected_hash = ledger_record_hash(record)
    hash_ok = record.get("record_hash") == expected_hash
    signature = record.get("signature")
    signature_ok = isinstance(signature, Mapping) and verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_LEDGER_RECORD,
        tenant_id=str(record["tenant_id"]),
        key_id=str(signature["key_id"]),
        public_key=public_key,
    )
    return {
        "record_id": record.get("record_id"),
        "sequence_number": record.get("sequence_number"),
        "record_hash": record.get("record_hash"),
        "status": "pass" if hash_ok and signature_ok else "fail",
        "checks": {
            "record_hash": "pass" if hash_ok else "fail",
            "ed25519_signature": "pass" if signature_ok else "fail",
        },
    }


def _decision_summaries(launch_payload: Mapping[str, Any]) -> list[JsonObject]:
    summaries = []
    for decision in launch_payload["decisions"]:
        selected = decision["admission_decision"]["selected_warrant"]
        summaries.append(
            {
                "tool_name": selected.get("tool_name"),
                "decision": selected.get("decision"),
                "reason_codes": selected.get("reason_codes"),
                "warrant_hash": selected.get("warrant_hash"),
            }
        )
    return summaries


def _public_key_from_material(material: Mapping[str, Any]) -> str:
    public_key = material.get("public_key_base64") or material.get("public_key_pem")
    if not isinstance(public_key, str) or not public_key:
        raise RuntimeError("Ed25519 signer did not expose public verification material")
    return public_key


def _artifact_hash(payload: Mapping[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _render_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Velvet Outreach Warrant Proof",
        "",
        f"Proof version: `{payload['proof_version']}`",
        "",
        f"Artifact hash: `{payload['artifact_hash']}`",
        "",
        str(payload["claim_boundary"]),
        "",
        "## Warrant Checks",
        "",
        "| Decision | Status | Warrant hash |",
        "|---|---:|---|",
    ]
    for report in payload["warrants"]:
        lines.append(
            f"| {report['decision']} | {report['status']} | `{report['warrant_hash']}` |"
        )
    lines.extend(
        [
            "",
            "## Ledger",
            "",
            f"- Verification status: `{payload['ledger_verification']['status']}`",
            f"- Canonical records: `{payload['ledger_verification']['canonical_records']}`",
            "",
            "## Brag-Safe Summary",
            "",
            "- Demoed MCP actions emit selected warrants before execution.",
            "- Warrant and ledger signatures verify with public Ed25519 material.",
            "- The proof remains local/demo-scoped and does not claim hosted production readiness.",
            "",
        ]
    )
    return "\n".join(lines)
