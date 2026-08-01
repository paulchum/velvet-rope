from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from velvet.binary_ledger import (
    BINARY_LEDGER_GENESIS_HASH,
    BinaryLedgerFrame,
    append_record,
    iter_frames,
)
from velvet.ledger import LEDGER_GENESIS_HASH, ledger_record_hash
from velvet.serialization import JsonObject, canonical_dumps
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_LEDGER_RECORD,
    SigningProvider,
    load_demo_ed25519_signer,
    sign_payload_hash,
    signer_default_key_id,
)
from velvet.vault.sth import build_signed_tree_head
from velvet.vault.verify import verify_vault_segment

BRIDGE_SCHEMA_VERSION = "velvet.live_demo.vault_bridge.v1"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LiveDemoVaultBridgeError(RuntimeError):
    """Raised when live-demo proxy artifacts cannot be safely exported for Vault."""


@dataclass(frozen=True)
class LiveDemoVaultArtifacts:
    ledger_path: Path
    sth_path: Path
    public_key_path: Path
    manifest_path: Path
    verification_report_path: Path
    segment_range: str
    incident_window_start: str
    incident_window_end: str
    record_count: int
    manifest: JsonObject


def export_argument_drift_vault_artifacts(
    *,
    proxy_ledger_path: str | Path,
    output_dir: str | Path,
    policy_hash: str | None = None,
    signer: SigningProvider | None = None,
) -> LiveDemoVaultArtifacts:
    """Export a Rust proxy argument-drift ledger as Vault-verifiable demo evidence."""

    source_ledger = Path(proxy_ledger_path)
    destination = Path(output_dir)
    active_signer = signer or load_demo_ed25519_signer()
    key_id = signer_default_key_id(active_signer)

    frames = tuple(iter_frames(source_ledger))
    if not frames:
        raise LiveDemoVaultBridgeError("source proxy ledger has no records")

    _prepare_output_dir(destination)
    vault_ledger = destination / "argument_drift.vledger"
    sth_path = destination / "signed_tree_head.json"
    public_key_path = destination / "vault_public_key.pem"
    manifest_path = destination / "bridge_manifest.json"
    verification_report_path = destination / "vault_verification_report.json"

    exported_records, record_mappings = _write_exported_ledger(
        frames=frames,
        destination=vault_ledger,
        signer=active_signer,
        key_id=key_id,
    )
    selected_policy_hash = _select_policy_hash(exported_records, explicit=policy_hash)
    record_hashes = [str(record["record_hash"]) for record in exported_records]
    first_sequence = int(exported_records[0]["sequence_number"])
    last_sequence = int(exported_records[-1]["sequence_number"])
    segment_range = f"{first_sequence}-{last_sequence}"
    incident_start, incident_end = incident_window_for_records(exported_records)

    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=first_sequence,
        policy_hash=selected_policy_hash,
        signer=active_signer,
        key_id=key_id,
    )
    _write_json(sth_path, sth)

    public_key = _public_key_pem(active_signer, key_id)
    public_key_path.write_text(public_key, encoding="utf-8")

    verification_report = verify_vault_segment(
        segment_range=segment_range,
        sth_path=sth_path,
        public_key=public_key,
        ledger_path=vault_ledger,
    )
    _write_json(verification_report_path, verification_report)
    if verification_report.get("status") != "pass":
        raise LiveDemoVaultBridgeError("exported Vault segment did not verify")

    manifest: JsonObject = {
        "schema_version": BRIDGE_SCHEMA_VERSION,
        "source": {
            "proxy_ledger": str(source_ledger),
            "sha256": _file_sha256(source_ledger),
            "signature_model": "rust_proxy_local_demo_signature_blocks_preserved_in_source",
        },
        "export": {
            "ledger": str(vault_ledger),
            "ledger_sha256": _file_sha256(vault_ledger),
            "sth": str(sth_path),
            "public_key": str(public_key_path),
            "signature_model": "demo_ed25519_for_vault_offline_verification",
        },
        "segment": {
            "range": segment_range,
            "record_count": len(exported_records),
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "first_record_hash": record_hashes[0],
            "last_record_hash": record_hashes[-1],
        },
        "incident_window": {
            "start": incident_start,
            "end": incident_end,
        },
        "record_mappings": record_mappings,
        "verification_report": str(verification_report_path),
        "boundary": (
            "Derived demo export for Vault and Claims Pack verification; "
            "the original Rust proxy ledger is preserved separately."
        ),
    }
    _write_json(manifest_path, manifest)
    return LiveDemoVaultArtifacts(
        ledger_path=vault_ledger,
        sth_path=sth_path,
        public_key_path=public_key_path,
        manifest_path=manifest_path,
        verification_report_path=verification_report_path,
        segment_range=segment_range,
        incident_window_start=incident_start,
        incident_window_end=incident_end,
        record_count=len(exported_records),
        manifest=manifest,
    )


def incident_window_for_records(records: list[JsonObject]) -> tuple[str, str]:
    timestamps = [_recorded_at(record) for record in records]
    if not timestamps:
        raise LiveDemoVaultBridgeError("exported records have no recorded_at timestamps")
    start = min(timestamps)
    end = max(timestamps) + timedelta(microseconds=1)
    return _iso_z(start), _iso_z(end)


def _write_exported_ledger(
    *,
    frames: tuple[BinaryLedgerFrame, ...],
    destination: Path,
    signer: SigningProvider,
    key_id: str,
) -> tuple[list[JsonObject], list[JsonObject]]:
    expected_sequence = 1
    expected_previous_hash = LEDGER_GENESIS_HASH
    previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    exported_records: list[JsonObject] = []
    record_mappings: list[JsonObject] = []

    for source_frame in frames:
        record = _json_object_copy(source_frame.payload)
        sequence = _positive_int(record.get("sequence_number"), "sequence_number")
        if sequence != expected_sequence:
            raise LiveDemoVaultBridgeError(
                f"source proxy ledger sequence {sequence} did not match {expected_sequence}"
            )
        previous_record_hash = record.get("previous_record_hash")
        if previous_record_hash != expected_previous_hash:
            raise LiveDemoVaultBridgeError("source proxy ledger record hash chain is broken")
        record_hash = _hash_value(record.get("record_hash"), "record_hash")
        recomputed_hash = ledger_record_hash(record)
        if recomputed_hash != record_hash:
            raise LiveDemoVaultBridgeError("source proxy ledger record_hash does not verify")

        tenant_id = _tenant_id(record)
        record["signature"] = sign_payload_hash(
            record_hash,
            purpose=PURPOSE_LEDGER_RECORD,
            tenant_id=tenant_id,
            key_id=key_id,
            signer=signer,
        )
        if ledger_record_hash(record) != record_hash:
            raise LiveDemoVaultBridgeError("exported signature changed the record hash")

        exported_frame = append_record(
            destination,
            record,
            kind=source_frame.kind,
            sequence_number=sequence,
            previous_frame_hash=previous_frame_hash,
            signer=signer,
            tenant_id=tenant_id,
            key_id=key_id,
        )
        exported_records.append(record)
        record_mappings.append(
            {
                "sequence_number": sequence,
                "record_type": record.get("record_type") or record.get("contract"),
                "source_record_hash": record_hash,
                "exported_record_hash": record_hash,
                "source_frame_hash": source_frame.frame_hash,
                "exported_frame_hash": exported_frame.frame_hash,
            }
        )
        expected_sequence += 1
        expected_previous_hash = record_hash
        previous_frame_hash = exported_frame.frame_hash
    return exported_records, record_mappings


def _select_policy_hash(records: list[JsonObject], *, explicit: str | None) -> str:
    record_policy_hash = next(
        (
            value
            for record in reversed(records)
            if isinstance((value := record.get("policy_hash")), str)
            and HASH_RE.fullmatch(value)
        ),
        None,
    )
    if explicit is not None and not HASH_RE.fullmatch(explicit):
        raise LiveDemoVaultBridgeError("explicit policy_hash is not a sha256:<hex> hash")
    if explicit is not None and record_policy_hash is not None and explicit != record_policy_hash:
        raise LiveDemoVaultBridgeError("explicit policy_hash does not match incident records")
    selected = record_policy_hash or explicit
    if selected is None:
        raise LiveDemoVaultBridgeError("no valid policy_hash found in incident records")
    return selected


def _public_key_pem(signer: SigningProvider, key_id: str) -> str:
    material = signer.public_verification_material(key_id)
    if not isinstance(material, Mapping):
        raise LiveDemoVaultBridgeError("signer does not expose public verification material")
    public_key = material.get("public_key_pem")
    if not isinstance(public_key, str) or not public_key:
        raise LiveDemoVaultBridgeError("signer public verification material has no PEM key")
    return public_key


def _prepare_output_dir(destination: Path) -> None:
    if destination.exists():
        for child in destination.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    destination.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_dumps(payload) + "\n", encoding="utf-8")


def _json_object_copy(payload: Mapping[str, Any]) -> JsonObject:
    copied = json.loads(canonical_dumps(payload))
    if not isinstance(copied, dict):
        raise LiveDemoVaultBridgeError("ledger payload is not a JSON object")
    return cast(JsonObject, copied)


def _hash_value(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise LiveDemoVaultBridgeError(f"{field_name} is not a sha256:<hex> hash")
    return value


def _positive_int(value: object, field_name: str) -> int:
    if not isinstance(value, int) or value < 1:
        raise LiveDemoVaultBridgeError(f"{field_name} must be a positive integer")
    return value


def _tenant_id(record: Mapping[str, Any]) -> str:
    value = record.get("tenant_id")
    return value if isinstance(value, str) and value else LOCAL_DEMO_TENANT_ID


def _recorded_at(record: Mapping[str, Any]) -> datetime:
    value = record.get("recorded_at")
    if not isinstance(value, str) or not value:
        raise LiveDemoVaultBridgeError("ledger record missing recorded_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LiveDemoVaultBridgeError(f"invalid recorded_at timestamp: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"
