"""Signed Tree Head artifacts for Velvet vault Merkle logs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from velvet.serialization import JsonObject, canonical_hash_sha256
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    SigningError,
    SigningProvider,
    resolve_ed25519_signing_provider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.vault.merkle import record_hashes_root

SIGNED_TREE_HEAD_SCHEMA_VERSION = "velvet.vault.sth.v1"
LEDGER_SEGMENT_SCHEMA_VERSION = "velvet.vault.ledger_segment.v1"
PURPOSE_SIGNED_TREE_HEAD = "velvet.vault.sth.v1"


class SignedTreeHeadError(RuntimeError):
    """Raised when STH issuance or verification cannot proceed safely."""


@dataclass(frozen=True)
class STHIssuancePolicy:
    """Cadence rule for issuing STHs."""

    records_interval: int = 1000
    seconds_interval: int = 300

    def should_issue(
        self,
        *,
        current_tree_size: int,
        last_tree_size: int | None,
        now: datetime,
        last_issued_at: datetime | None,
    ) -> bool:
        if current_tree_size <= 0:
            return False
        if last_tree_size is None or last_issued_at is None:
            return True
        if current_tree_size - last_tree_size >= self.records_interval:
            return True
        return (now - last_issued_at).total_seconds() >= self.seconds_interval


@dataclass(frozen=True)
class STHIssuanceResult:
    status: str
    sth: JsonObject | None = None
    degraded_reason: str | None = None


def build_signed_tree_head(
    *,
    record_hashes: Sequence[str],
    first_sequence: int,
    policy_hash: str,
    signer: SigningProvider | None = None,
    signing_profile: str | None = None,
    dev_ephemeral_key: bool = False,
    tenant_id: str = LOCAL_DEMO_TENANT_ID,
    key_id: str | None = None,
    timestamp: str | None = None,
) -> JsonObject:
    """Build and sign an STH over ordered ledger ``record_hash`` values."""

    if not record_hashes:
        raise SignedTreeHeadError("cannot issue an STH for an empty tree")
    if first_sequence < 1:
        raise SignedTreeHeadError("first_sequence must be positive")
    active_signer = signer
    if active_signer is None:
        try:
            active_signer = resolve_ed25519_signing_provider(
                signing_profile=signing_profile,
                dev_ephemeral_key=dev_ephemeral_key,
                key_id=key_id,
            )
        except SigningError as error:
            raise SignedTreeHeadError(str(error)) from error
    resolved_key_id = key_id or signer_default_key_id(active_signer)
    payload = unsigned_tree_head_payload(
        record_hashes=record_hashes,
        first_sequence=first_sequence,
        policy_hash=policy_hash,
        timestamp=timestamp,
    )
    sth_hash = signed_tree_head_hash(payload)
    signed = dict(payload)
    signed["sth_hash"] = sth_hash
    signed["signature"] = sign_payload_hash(
        sth_hash,
        purpose=PURPOSE_SIGNED_TREE_HEAD,
        tenant_id=tenant_id,
        key_id=resolved_key_id,
        signer=active_signer,
    )
    return signed


def try_build_signed_tree_head(**kwargs: Any) -> STHIssuanceResult:
    try:
        return STHIssuanceResult(
            status="ok",
            sth=build_signed_tree_head(**kwargs),
        )
    except SignedTreeHeadError as error:
        return STHIssuanceResult(status="degraded", degraded_reason=str(error))


def unsigned_tree_head_payload(
    *,
    record_hashes: Sequence[str],
    first_sequence: int,
    policy_hash: str,
    timestamp: str | None = None,
) -> JsonObject:
    if not policy_hash.startswith("sha256:"):
        raise SignedTreeHeadError("policy_hash must be a sha256:<hex> hash")
    last_sequence = first_sequence + len(record_hashes) - 1
    return {
        "schema_version": SIGNED_TREE_HEAD_SCHEMA_VERSION,
        "tree_size": len(record_hashes),
        "root_hash": record_hashes_root(record_hashes),
        "ledger_segment": {
            "schema_version": LEDGER_SEGMENT_SCHEMA_VERSION,
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "first_record_hash": record_hashes[0],
            "last_record_hash": record_hashes[-1],
        },
        "timestamp": timestamp or _now_iso(),
        "policy_hash": policy_hash,
    }


def signed_tree_head_hash(sth: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(unsigned_signed_tree_head_payload(sth))


def unsigned_signed_tree_head_payload(sth: Mapping[str, Any]) -> JsonObject:
    return {str(key): value for key, value in sth.items() if key not in {"signature", "sth_hash"}}


def verify_signed_tree_head(
    sth: Mapping[str, Any],
    *,
    public_key: str | bytes | object | None = None,
    signer: SigningProvider | None = None,
    expected_policy_hash: str | None = None,
) -> bool:
    if sth.get("schema_version") != SIGNED_TREE_HEAD_SCHEMA_VERSION:
        return False
    signature = sth.get("signature")
    if not isinstance(signature, Mapping):
        return False
    if expected_policy_hash is not None and sth.get("policy_hash") != expected_policy_hash:
        return False
    expected_hash = signed_tree_head_hash(sth)
    if sth.get("sth_hash") not in {None, expected_hash}:
        return False
    return verify_signature_record(
        cast(Mapping[str, Any], signature),
        expected_hash,
        purpose=PURPOSE_SIGNED_TREE_HEAD,
        signer=signer,
        public_key=public_key,
    )


def sth_ledger_segment(sth: Mapping[str, Any]) -> Mapping[str, Any]:
    segment = sth.get("ledger_segment")
    if not isinstance(segment, Mapping):
        raise SignedTreeHeadError("STH has no ledger_segment object")
    return segment


def parse_sth_timestamp(sth: Mapping[str, Any]) -> datetime:
    value = sth.get("timestamp")
    if not isinstance(value, str):
        raise SignedTreeHeadError("STH timestamp is missing")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
