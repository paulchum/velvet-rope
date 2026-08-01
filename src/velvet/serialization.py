"""Deterministic serialization primitives for Velvet admission artifacts."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
from typing import Any, cast

JsonObject = dict[str, Any]
JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]

VELVET_CANONICAL_JSON_V1 = "velvet.canonical_json.v1.sha256"
VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD = (
    "velvet.canonical_json.v1.sha256.unsigned_payload"
)
SAFE_JSON_INTEGER_MIN = -(2**53) + 1
SAFE_JSON_INTEGER_MAX = 2**53 - 1

PROOF_ARTIFACT_TYPES = frozenset(
    {
        "warrant",
        "ledger",
        "policy",
        "tool_schema",
        "approval",
        "admission_evidence",
        "execution_permit",
        "execution_receipt",
        "evidence_manifest",
        "ledger_record",
        "proof_envelope",
    }
)

_UNSIGNED_DROP_FIELDS = {
    "warrant": frozenset({"warrant_hash", "signature"}),
    "ledger": frozenset({"record_hash", "signature"}),
    "policy": frozenset({"policy_hash", "signature"}),
    "tool_schema": frozenset({"tool_schema_hash", "signature"}),
    "approval": frozenset({"receipt_hash", "signature"}),
    "admission_evidence": frozenset({"admission_evidence_hash", "signature"}),
    "execution_permit": frozenset({"permit_hash", "signature"}),
    "execution_receipt": frozenset({"receipt_hash", "signature"}),
    "ledger_record": frozenset({"record_hash", "artifact_hash", "signature"}),
    "proof_envelope": frozenset({"proof_envelope_hash", "signature", "signature_record"}),
}

_WARRANT_FIELDS = (
    "warrant_id",
    "issued_at",
    "tenant_id",
    "environment",
    "request_hash",
    "policy_hash",
    "tool_schema_hash",
    "tool_name",
    "decision",
    "reason",
    "reason_codes",
    "obligations",
    "approval_required",
    "expires_at",
    "issuer",
)

_EVIDENCE_MANIFEST_UNSIGNED_FIELDS = (
    "schema_version",
    "tenant_id",
    "generated_at",
    "artifacts",
)

_TIMESTAMP_FIELD_NAMES = frozenset(
    {
        "timestamp",
        "issued_at",
        "created_at",
        "recorded_at",
        "generated_at",
        "decided_at",
        "expires_at",
        "signed_at",
        "proposal_timestamp",
        "decision_timestamp",
        "execution_timestamp",
    }
)
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,9})?Z$"
)
_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_DECIMAL_FIELD_NAMES = frozenset(
    {
        "admission_price",
        "budget_pressure",
        "clearance_score",
        "confidence",
        "cost_penalty",
        "entry_price",
        "estimated_cost",
        "estimated_risk",
        "expected_upside",
        "final_lambda",
        "hard_ceiling_usd",
        "liability_multiplier",
        "limit_usd",
        "novelty",
        "proposal_score",
        "risk_penalty",
        "scarcity_pressure",
        "soft_ceiling_fraction",
        "spend_amount",
    }
)
_DECIMAL_FIELD_SUFFIXES = (
    "_amount",
    "_ceiling",
    "_cost",
    "_fraction",
    "_lambda",
    "_limit",
    "_penalty",
    "_price",
    "_risk",
    "_score",
    "_usd",
    "_upside",
)


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as Velvet canonical JSON v1."""


def canonicalize(value: Any) -> Any:
    """Convert supported Python values into a stable JSON-compatible form."""

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return canonicalize(dataclasses.asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return quantize_decimal(value)
    if isinstance(value, Mapping):
        return {str(key): canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple):
        return [canonicalize(item) for item in value]
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    if isinstance(value, set | frozenset):
        return [canonicalize(item) for item in sorted(value)]
    return value


def canonical_dumps(value: Any) -> str:
    """Serialize a value as canonical JSON with stable separators and key order."""

    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_dumps(value).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_hash_sha256(value: Any) -> str:
    return f"sha256:{canonical_hash(value)}"


def canonical_hash_prefixed(prefix: str, value: Any) -> str:
    return f"{prefix}_{canonical_hash(value)[:32]}"


def load_canonical_json_v1(data: bytes | str) -> JsonValue:
    """Parse strict UTF-8 JSON for Velvet canonical JSON v1."""

    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise CanonicalizationError("UTF-8 BOM is not allowed")
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CanonicalizationError(f"input is not valid UTF-8: {error}") from error
    else:
        source = data
        if source.startswith("\ufeff"):
            raise CanonicalizationError("UTF-8 BOM is not allowed")

    try:
        value = json.loads(
            source,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_int=_parse_json_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as error:
        raise CanonicalizationError(f"invalid JSON: {error.msg}") from error
    validate_canonical_json_v1(value)
    return cast(JsonValue, value)


def canonical_json_v1_dumps(value: Any) -> str:
    """Serialize a value as Velvet canonical JSON v1."""

    validate_canonical_json_v1(value)
    return _serialize_canonical_json_v1(value)


def canonical_json_v1_bytes(value: Any) -> bytes:
    return canonical_json_v1_dumps(value).encode("utf-8")


def canonical_json_v1_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_v1_bytes(value)).hexdigest()


def canonical_json_v1_hash_sha256(value: Any) -> str:
    return f"sha256:{canonical_json_v1_hash(value)}"


def proof_artifact_unsigned_payload(
    artifact_type: str,
    payload: Mapping[str, Any],
) -> JsonObject:
    """Return the unsigned payload covered by a proof artifact hash."""

    if artifact_type not in PROOF_ARTIFACT_TYPES:
        allowed = "|".join(sorted(PROOF_ARTIFACT_TYPES))
        raise CanonicalizationError(f"unsupported proof artifact type: {artifact_type} ({allowed})")
    if artifact_type == "evidence_manifest":
        return _required_projection(payload, _EVIDENCE_MANIFEST_UNSIGNED_FIELDS)
    if artifact_type == "proof_envelope":
        return _proof_envelope_projection(payload)
    if artifact_type == "warrant" and all(field in payload for field in _WARRANT_FIELDS):
        return _required_projection(payload, _WARRANT_FIELDS)
    drop_fields = _UNSIGNED_DROP_FIELDS.get(artifact_type, frozenset())
    return {str(key): value for key, value in payload.items() if key not in drop_fields}


def _proof_envelope_projection(payload: Mapping[str, Any]) -> JsonObject:
    return {
        "schema_version": str(payload.get("schema_version", "velvet.proof_envelope.compat.v1")),
        "envelope_id": str(payload["envelope_id"]),
        "decision": str(payload["decision"]),
        "proposed_action_hash": canonical_hash_sha256(payload.get("proposed_action", {})),
        "canonical_action_hash": _as_sha256_string(payload.get("canonical_action_hash")),
        "canonical_action_payload_hash": canonical_hash_sha256(payload.get("canonical_action", {})),
        "velvet_fallback_hash": canonical_hash_sha256(payload.get("velvet_fallback", {})),
        "admission_price_units": int(payload.get("admission_price", 0)),
        "appraisal_coverage_hash": canonical_hash_sha256(payload.get("appraisal_coverage", {})),
        "authority_budget_before": int(payload.get("authority_budget_before", 0)),
        "authority_budget_after": int(payload.get("authority_budget_after", 0)),
        "boundary_key": str(payload.get("boundary_key", "")),
        "read_set_hash": _as_sha256_string(payload.get("read_set_hash")),
        "state_hash_before": _as_sha256_string(payload.get("state_hash_before")),
        "state_hash_after": _as_sha256_string(payload.get("state_hash_after")),
        "contract_version": str(payload.get("contract_version", "")),
        "policy_version": str(payload.get("policy_version", "")),
        "estimator_version": str(payload.get("estimator_version", "")),
        "denial_reason_hash": canonical_hash_sha256(payload.get("denial_reason")),
        "escalation_reason_hash": canonical_hash_sha256(payload.get("escalation_reason")),
        "replay_id": str(payload.get("replay_id", "")),
        "logical_step": int(payload.get("logical_step", 0)),
        "deterministic_trace_hash": _as_sha256_string(payload.get("deterministic_trace_hash")),
    }


def _as_sha256_string(value: Any) -> str:
    if isinstance(value, str):
        if value.startswith("sha256:"):
            return value
        if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
            return f"sha256:{value}"
    return canonical_hash_sha256(value)


def proof_artifact_canonical_bytes(artifact_type: str, payload: Mapping[str, Any]) -> bytes:
    unsigned = proof_artifact_unsigned_payload(artifact_type, payload)
    validate_proof_artifact_v1(artifact_type, unsigned)
    return canonical_json_v1_bytes(unsigned)


def proof_artifact_hash(artifact_type: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(proof_artifact_canonical_bytes(artifact_type, payload)).hexdigest()
    return f"sha256:{digest}"


def validate_proof_artifact_v1(artifact_type: str, payload: Mapping[str, Any]) -> None:
    if artifact_type not in PROOF_ARTIFACT_TYPES:
        allowed = "|".join(sorted(PROOF_ARTIFACT_TYPES))
        raise CanonicalizationError(f"unsupported proof artifact type: {artifact_type} ({allowed})")
    canonicalization = payload.get("canonicalization")
    if canonicalization is not None and canonicalization not in {
        VELVET_CANONICAL_JSON_V1,
        VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD,
    }:
        raise CanonicalizationError(f"unsupported canonicalization label: {canonicalization}")
    validate_canonical_json_v1(payload)


def validate_canonical_json_v1(value: Any, *, _path: str = "$", _field: str | None = None) -> None:
    """Validate that a Python value can be emitted as Velvet canonical JSON v1."""

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if _field is not None and _is_decimal_field(_field):
            raise CanonicalizationError(f"{_path}: decimal fields must be canonical strings")
        if not (SAFE_JSON_INTEGER_MIN <= value <= SAFE_JSON_INTEGER_MAX):
            raise CanonicalizationError(f"{_path}: integer is outside the JSON-safe range")
        return
    if isinstance(value, str):
        _validate_json_string(value, _path)
        if _field is not None and _is_timestamp_field(_field):
            _validate_timestamp_string(value, _path)
        if _field is not None and _is_decimal_field(_field):
            _validate_decimal_string(value, _path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_canonical_json_v1(item, _path=f"{_path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{_path}: object keys must be strings")
            _validate_json_string(key, f"{_path}.{key}")
            validate_canonical_json_v1(item, _path=f"{_path}.{key}", _field=key)
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{_path}: non-integer JSON numbers are not supported")
    if isinstance(value, bytes | bytearray | memoryview):
        raise CanonicalizationError(f"{_path}: bytes must be encoded as strings before hashing")
    if isinstance(value, tuple | set | frozenset):
        raise CanonicalizationError(f"{_path}: language-specific sequences are not JSON values")
    if isinstance(value, Decimal):
        raise CanonicalizationError(f"{_path}: decimals must be encoded as canonical strings")
    raise CanonicalizationError(f"{_path}: unsupported JSON value type {type(value).__name__}")


def quantize_decimal(value: Decimal | int | str) -> str:
    decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
    return str(decimal_value.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))


def stable_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if isinstance(value, Decimal):
        return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if isinstance(value, str) and value.strip():
        return int(Decimal(value).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    return default


def stable_json_object(value: Mapping[str, Any] | None = None) -> JsonObject:
    return cast(JsonObject, canonicalize(dict(value or {})))


def stable_sequence(value: Sequence[Any] | None = None) -> tuple[Any, ...]:
    return tuple(canonicalize(item) for item in value or ())


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> JsonObject:
    seen: set[str] = set()
    output: JsonObject = {}
    for key, value in pairs:
        if key in seen:
            raise CanonicalizationError(f"duplicate object key: {key}")
        seen.add(key)
        output[key] = value
    return output


def _parse_json_integer(value: str) -> int:
    parsed = int(value)
    if not (SAFE_JSON_INTEGER_MIN <= parsed <= SAFE_JSON_INTEGER_MAX):
        raise CanonicalizationError("integer is outside the JSON-safe range")
    return parsed


def _reject_json_float(value: str) -> int:
    raise CanonicalizationError(f"non-integer JSON number is not supported: {value}")


def _reject_json_constant(value: str) -> None:
    raise CanonicalizationError(f"unsupported JSON constant: {value}")


def _serialize_canonical_json_v1(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _quote_json_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize_canonical_json_v1(item) for item in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda item: _utf16_sort_key(str(item[0])))
        return (
            "{"
            + ",".join(
                f"{_quote_json_string(str(key))}:{_serialize_canonical_json_v1(item)}"
                for key, item in items
            )
            + "}"
        )
    raise CanonicalizationError(f"unsupported JSON value type {type(value).__name__}")


def _quote_json_string(value: str) -> str:
    output: list[str] = ['"']
    for character in value:
        codepoint = ord(character)
        if character == '"':
            output.append('\\"')
        elif character == "\\":
            output.append("\\\\")
        elif character == "\b":
            output.append("\\b")
        elif character == "\t":
            output.append("\\t")
        elif character == "\n":
            output.append("\\n")
        elif character == "\f":
            output.append("\\f")
        elif character == "\r":
            output.append("\\r")
        elif codepoint < 0x20:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    output.append('"')
    return "".join(output)


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _validate_json_string(value: str, path: str) -> None:
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalizationError(f"{path}: lone surrogate is not valid Unicode")


def _validate_timestamp_string(value: str, path: str) -> None:
    if not _TIMESTAMP_RE.fullmatch(value):
        raise CanonicalizationError(f"{path}: timestamp must be RFC 3339 UTC with Z")


def _validate_decimal_string(value: str, path: str) -> None:
    if not _DECIMAL_RE.fullmatch(value):
        raise CanonicalizationError(f"{path}: decimal string is not canonical")
    if value == "-0" or re.fullmatch(r"-0(?:\.0+)?", value):
        raise CanonicalizationError(f"{path}: negative zero is not canonical")


def _is_timestamp_field(field: str) -> bool:
    return field in _TIMESTAMP_FIELD_NAMES or field.endswith("_at") or field.endswith("_timestamp")


def _is_decimal_field(field: str) -> bool:
    normalized = field.lower()
    return normalized in _DECIMAL_FIELD_NAMES or any(
        normalized.endswith(suffix) for suffix in _DECIMAL_FIELD_SUFFIXES
    )


def _required_projection(payload: Mapping[str, Any], fields: Sequence[str]) -> JsonObject:
    missing = [field for field in fields if field not in payload]
    if missing:
        raise CanonicalizationError(f"missing required unsigned payload field(s): {missing}")
    return {field: payload[field] for field in fields}
