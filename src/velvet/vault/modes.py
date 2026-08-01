"""Field recording modes for vault evidence artifacts."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any, Protocol

from velvet.serialization import JsonObject, canonical_json_bytes, canonicalize

FIELD_RECORD_SCHEMA_VERSION = "velvet.vault.field_record.v1"


class RecordingMode(StrEnum):
    HASH_ONLY = "hash_only"
    ENCRYPTED_BODY = "encrypted_body"
    PLAINTEXT = "plaintext"


class RecordingModeError(ValueError):
    """Raised when field recording would violate the configured policy."""


class EnvelopeEncryptionProvider(Protocol):
    """External envelope encryption boundary.

    Implementations may wrap AWS KMS, Vault Transit, or another operator-owned
    envelope encryption service. The vault never implements encryption itself.
    """

    @property
    def provider_name(self) -> str:
        """Stable provider name for evidence metadata."""

    @property
    def key_id(self) -> str:
        """Stable envelope key identifier."""

    def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
        """Encrypt plaintext bytes under the provider's envelope key."""


@dataclass(frozen=True)
class FieldRecordingPolicy:
    arguments_mode: RecordingMode = RecordingMode.HASH_ONLY
    results_mode: RecordingMode = RecordingMode.HASH_ONLY
    field_overrides: Mapping[str, RecordingMode] = field(default_factory=dict)
    allow_plaintext_fields: frozenset[str] = frozenset()

    def mode_for(self, field_name: str, *, field_kind: str) -> RecordingMode:
        override = self.field_overrides.get(field_name)
        if override is not None:
            return RecordingMode(override)
        if field_kind == "arguments":
            return self.arguments_mode
        if field_kind == "results":
            return self.results_mode
        raise RecordingModeError(f"unsupported field_kind: {field_kind}")


DEFAULT_FIELD_RECORDING_POLICY = FieldRecordingPolicy()


def record_field(
    value: Any,
    *,
    field_name: str,
    field_kind: str,
    policy: FieldRecordingPolicy = DEFAULT_FIELD_RECORDING_POLICY,
    encryption_provider: EnvelopeEncryptionProvider | None = None,
) -> JsonObject:
    mode = policy.mode_for(field_name, field_kind=field_kind)
    canonical_value = canonicalize(value)
    plaintext = canonical_json_bytes(canonical_value)
    plaintext_hash = f"sha256:{sha256(plaintext).hexdigest()}"
    base: JsonObject = {
        "schema_version": FIELD_RECORD_SCHEMA_VERSION,
        "field_name": field_name,
        "field_kind": field_kind,
        "mode": mode.value,
        "plaintext_hash": plaintext_hash,
        "plaintext_length": len(plaintext),
        "canonicalization": "velvet.canonical_json.v1",
    }
    if mode is RecordingMode.HASH_ONLY:
        return base
    if mode is RecordingMode.PLAINTEXT:
        if field_name not in policy.allow_plaintext_fields:
            raise RecordingModeError(f"plaintext recording is not enabled for {field_name}")
        return {**base, "plaintext": canonical_value}
    if mode is RecordingMode.ENCRYPTED_BODY:
        if encryption_provider is None:
            raise RecordingModeError("encrypted_body recording requires an encryption provider")
        ciphertext = encryption_provider.encrypt(
            plaintext,
            context={
                "field_name": field_name,
                "field_kind": field_kind,
                "plaintext_hash": plaintext_hash,
            },
        )
        return {
            **base,
            "encryption_provider": encryption_provider.provider_name,
            "envelope_key_id": encryption_provider.key_id,
            "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        }
    raise RecordingModeError(f"unsupported recording mode: {mode}")


def record_arguments(
    arguments: Any,
    *,
    policy: FieldRecordingPolicy = DEFAULT_FIELD_RECORDING_POLICY,
    encryption_provider: EnvelopeEncryptionProvider | None = None,
) -> JsonObject:
    return record_field(
        arguments,
        field_name="arguments",
        field_kind="arguments",
        policy=policy,
        encryption_provider=encryption_provider,
    )


def record_results(
    results: Any,
    *,
    policy: FieldRecordingPolicy = DEFAULT_FIELD_RECORDING_POLICY,
    encryption_provider: EnvelopeEncryptionProvider | None = None,
) -> JsonObject:
    return record_field(
        results,
        field_name="results",
        field_kind="results",
        policy=policy,
        encryption_provider=encryption_provider,
    )
