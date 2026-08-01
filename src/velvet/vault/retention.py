"""Retention controls for sealed Velvet vault ledger segments."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from velvet.binary_ledger import (
    BINARY_LEDGER_GENESIS_HASH,
    RECORD_KIND_CANONICAL,
    append_record,
    scan_tail_state,
)
from velvet.ledger import LEDGER_GENESIS_HASH, ledger_record_hash, read_ledger_records
from velvet.serialization import JsonObject
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_LEDGER_RECORD,
    SigningProvider,
    resolve_ed25519_signing_provider,
    sign_payload_hash,
    signer_default_key_id,
)
from velvet.vault.anchor import anchored_success_for_sth
from velvet.vault.sth import signed_tree_head_hash, sth_ledger_segment, verify_signed_tree_head

RETENTION_POLICY_SCHEMA_VERSION = "velvet.vault.retention_policy.v1"
SEALED_SEGMENT_SCHEMA_VERSION = "velvet.vault.sealed_segment.v1"
VAULT_TOMBSTONE_SCHEMA_VERSION = "velvet.vault.tombstone.v1"
VAULT_TOMBSTONE_CONTRACT = "velvet.vault.tombstone"
VAULT_TOMBSTONE_CONTRACT_REVISION = 1
RETENTION_PRESETS = {"eu_ai_act_minimum": timedelta(days=183)}


class RetentionError(RuntimeError):
    """Raised when retention cannot proceed without violating fail-closed rules."""


@dataclass(frozen=True)
class SealedSegment:
    path: Path
    first_sequence: int
    last_sequence: int
    first_record_hash: str
    last_record_hash: str
    sealed_at: datetime
    schema_version: str = SEALED_SEGMENT_SCHEMA_VERSION

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "path": str(self.path),
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "first_record_hash": self.first_record_hash,
            "last_record_hash": self.last_record_hash,
            "sealed_at": self.sealed_at.isoformat(timespec="microseconds").replace(
                "+00:00",
                "Z",
            ),
        }


def sealed_segment_from_ledger(
    path: str | Path,
    *,
    sealed_at: datetime | None = None,
) -> SealedSegment:
    source = Path(path)
    records = list(read_ledger_records(source))
    if not records:
        raise RetentionError("sealed segment has no ledger records")
    first = records[0]
    last = records[-1]
    timestamp = sealed_at or datetime.fromtimestamp(source.stat().st_mtime, tz=UTC)
    return SealedSegment(
        path=source,
        first_sequence=int(first["sequence_number"]),
        last_sequence=int(last["sequence_number"]),
        first_record_hash=str(first["record_hash"]),
        last_record_hash=str(last["record_hash"]),
        sealed_at=timestamp,
    )


def delete_expired_segments(
    segments: Iterable[SealedSegment],
    *,
    sth: Mapping[str, Any],
    anchor_receipts: Iterable[Mapping[str, Any]],
    live_ledger_path: str | Path,
    signer: SigningProvider | None = None,
    signing_profile: str | None = None,
    public_key: str | bytes | object | None = None,
    preset: str = "eu_ai_act_minimum",
    now: datetime | None = None,
    tenant_id: str = LOCAL_DEMO_TENANT_ID,
    key_id: str | None = None,
) -> JsonObject:
    horizon = RETENTION_PRESETS.get(preset)
    if horizon is None:
        raise RetentionError(f"unknown retention preset: {preset}")
    active_signer = signer or resolve_ed25519_signing_provider(signing_profile=signing_profile)
    resolved_key_id = key_id or signer_default_key_id(active_signer)
    current_time = now or datetime.now(tz=UTC)
    receipts = tuple(anchor_receipts)
    sth_hash = signed_tree_head_hash(sth)
    results: list[JsonObject] = []
    for segment in segments:
        checks = _retention_checks(
            segment,
            sth=sth,
            sth_hash=sth_hash,
            anchor_receipts=receipts,
            public_key=public_key,
            signer=signer,
            now=current_time,
            horizon=horizon,
        )
        if checks:
            results.append(
                {
                    "status": "refused",
                    "segment": segment.to_dict(),
                    "issues": checks,
                }
            )
            continue
        tombstone = append_tombstone_record(
            live_ledger_path,
            segment,
            sth=sth,
            signer=active_signer,
            tenant_id=tenant_id,
            key_id=resolved_key_id,
        )
        segment.path.unlink()
        results.append(
            {
                "status": "deleted",
                "segment": segment.to_dict(),
                "tombstone_record_hash": tombstone["record_hash"],
            }
        )
    return {
        "schema_version": RETENTION_POLICY_SCHEMA_VERSION,
        "preset": preset,
        "horizon_days": horizon.days,
        "status": "pass" if all(item["status"] == "deleted" for item in results) else "refused",
        "results": results,
    }


def append_tombstone_record(
    live_ledger_path: str | Path,
    segment: SealedSegment,
    *,
    sth: Mapping[str, Any],
    signer: SigningProvider,
    tenant_id: str = LOCAL_DEMO_TENANT_ID,
    key_id: str | None = None,
) -> JsonObject:
    path = Path(live_ledger_path)
    state = scan_tail_state(path)
    sequence_number = state.next_sequence_number
    previous_record_hash = (
        state.previous_semantic_record_hash if state.record_count else LEDGER_GENESIS_HASH
    )
    previous_frame_hash = (
        state.previous_frame_hash if state.record_count else BINARY_LEDGER_GENESIS_HASH
    )
    resolved_key_id = key_id or signer_default_key_id(signer)
    tombstone: JsonObject = {
        "schema_version": VAULT_TOMBSTONE_SCHEMA_VERSION,
        "contract": VAULT_TOMBSTONE_CONTRACT,
        "contract_revision": VAULT_TOMBSTONE_CONTRACT_REVISION,
        "record_id": f"vtomb_{uuid.uuid4().hex}",
        "record_type": "vault_retention_tombstone",
        "tenant_id": tenant_id,
        "sequence_number": sequence_number,
        "previous_record_hash": previous_record_hash,
        "recorded_at": _now_iso(),
        "deleted_segment": segment.to_dict(),
        "covering_sth_hash": signed_tree_head_hash(sth),
        "covering_sth": dict(sth),
    }
    tombstone["record_hash"] = ledger_record_hash(tombstone)
    tombstone["signature"] = sign_payload_hash(
        str(tombstone["record_hash"]),
        purpose=PURPOSE_LEDGER_RECORD,
        tenant_id=tenant_id,
        key_id=resolved_key_id,
        signer=signer,
    )
    append_record(
        path,
        tombstone,
        kind=RECORD_KIND_CANONICAL,
        sequence_number=sequence_number,
        previous_frame_hash=previous_frame_hash,
        signer=signer,
        tenant_id=tenant_id,
        key_id=resolved_key_id,
    )
    return tombstone


def is_tombstone_record(record: Mapping[str, Any]) -> bool:
    return (
        record.get("schema_version") == VAULT_TOMBSTONE_SCHEMA_VERSION
        and record.get("contract") == VAULT_TOMBSTONE_CONTRACT
        and record.get("contract_revision") == VAULT_TOMBSTONE_CONTRACT_REVISION
    )


def validate_tombstone_record(record: Mapping[str, Any]) -> list[JsonObject]:
    issues: list[JsonObject] = []
    for field_name in (
        "record_id",
        "record_type",
        "sequence_number",
        "previous_record_hash",
        "record_hash",
        "deleted_segment",
        "covering_sth_hash",
        "covering_sth",
        "signature",
    ):
        if record.get(field_name) is None:
            issues.append(
                {
                    "code": "vault_tombstone_missing_field",
                    "severity": "error",
                    "field": field_name,
                    "message": "Vault tombstone record is missing a required field.",
                }
            )
    segment = record.get("deleted_segment")
    sth = record.get("covering_sth")
    if isinstance(sth, Mapping):
        expected_sth_hash = signed_tree_head_hash(sth)
        if record.get("covering_sth_hash") != expected_sth_hash:
            issues.append(
                {
                    "code": "vault_tombstone_sth_hash_mismatch",
                    "severity": "error",
                    "expected": expected_sth_hash,
                    "actual": record.get("covering_sth_hash"),
                    "message": "Vault tombstone covering_sth_hash does not match covering_sth.",
                }
            )
    if not isinstance(segment, Mapping):
        issues.append(
            {
                "code": "vault_tombstone_segment_invalid",
                "severity": "error",
                "message": "Vault tombstone deleted_segment must be an object.",
            }
        )
    return issues


def _retention_checks(
    segment: SealedSegment,
    *,
    sth: Mapping[str, Any],
    sth_hash: str,
    anchor_receipts: tuple[Mapping[str, Any], ...],
    public_key: str | bytes | object | None,
    signer: SigningProvider | None,
    now: datetime,
    horizon: timedelta,
) -> list[JsonObject]:
    issues: list[JsonObject] = []
    if now - segment.sealed_at < horizon:
        issues.append(
            {
                "code": "segment_within_retention_horizon",
                "severity": "error",
                "message": "Sealed segment is not older than the retention horizon.",
            }
        )
    if not verify_signed_tree_head(sth, public_key=public_key, signer=signer):
        issues.append(
            {
                "code": "covering_sth_signature_invalid",
                "severity": "error",
                "message": "Covering STH is missing or has an invalid signature.",
            }
        )
    if not _sth_exactly_covers_segment(sth, segment):
        issues.append(
            {
                "code": "covering_sth_segment_mismatch",
                "severity": "error",
                "message": "Covering STH does not exactly name the sealed segment range.",
            }
        )
    if not anchored_success_for_sth(sth_hash, anchor_receipts):
        issues.append(
            {
                "code": "covering_sth_not_anchored",
                "severity": "error",
                "message": "Covering STH has no successful external anchor receipt.",
            }
        )
    return issues


def _sth_exactly_covers_segment(sth: Mapping[str, Any], segment: SealedSegment) -> bool:
    try:
        sth_segment = sth_ledger_segment(sth)
    except Exception:  # noqa: BLE001 - malformed STH fails closed.
        return False
    return (
        int(sth_segment.get("first_sequence", -1)) == segment.first_sequence
        and int(sth_segment.get("last_sequence", -1)) == segment.last_sequence
        and sth_segment.get("first_record_hash") == segment.first_record_hash
        and sth_segment.get("last_record_hash") == segment.last_record_hash
    )


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
