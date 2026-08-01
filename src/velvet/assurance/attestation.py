"""Content-free control-state attestations for insurance and audit review."""

from __future__ import annotations

import hmac
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from velvet.approvals import (
    APPROVAL_RECEIPT_SCHEMA_VERSION,
    ApprovalReceipt,
    load_approval_snapshot,
)
from velvet.ledger import read_ledger_records
from velvet.serialization import JsonObject, canonical_dumps, canonical_hash_sha256
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_APPROVAL_RECEIPT_V1,
    SigningProvider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.vault.sth import verify_signed_tree_head

CONTROL_STATE_ATTESTATION_SCHEMA_VERSION = "velvet.assurance.control_state_attestation.v1"
CONTROL_STATE_ATTESTATION_ENVELOPE_SCHEMA_VERSION = (
    "velvet.assurance.control_state_attestation.envelope.v1"
)
PURPOSE_CONTROL_STATE_ATTESTATION = "velvet.assurance.control_state_attestation.v1"

DECISION_CLASSES = ("admit", "block", "escalate", "defer", "skip")
RISK_CLASSES = (
    "unknown",
    "low",
    "medium",
    "high",
    "unlisted",
    "destructive",
    "bind_external",
    "spend",
    "irreversible",
    "other",
)
RETENTION_PRESETS = (
    "unavailable",
    "eu_ai_act_minimum",
    "minimal",
    "standard",
    "extended",
    "legal_hold",
)
POLICY_SIGNATURE_STATUSES = ("valid", "invalid", "unavailable", "degraded")
SCHEDULED_CADENCES = ("hourly", "daily")
HASH_RE = r"^sha256:[0-9a-f]{64}$"
ISO_Z_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"

_CONTENT_FIELD_DENYLIST = (
    "argument",
    "arguments",
    "body",
    "content",
    "cookie",
    "credential",
    "customer",
    "email",
    "identity",
    "message",
    "name",
    "payload",
    "prompt",
    "raw",
    "record_id",
    "request",
    "response",
    "secret",
    "subject",
    "text",
    "token",
    "tool",
    "user",
)
_SPEND_RISK_CLASSES = {"spend"}
_IRREVERSIBLE_RISK_CLASSES = {"irreversible", "destructive"}


class AssuranceAttestationError(ValueError):
    """Raised when a control-state attestation cannot be built or verified."""


@dataclass(frozen=True)
class PeriodSelection:
    period_start: datetime
    period_end: datetime
    period_records: tuple[Mapping[str, Any], ...]
    records_through_period: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class ScheduledPeriod:
    cadence: str
    period_start: datetime
    period_end: datetime


CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA: JsonObject = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://velvet.local/schemas/assurance/control_state_attestation.v1.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "period",
        "deployment_id",
        "gateway_liveness",
        "policy_state",
        "decision_counts",
        "escalation_integrity",
        "drift_rejections",
        "certificate_coverage",
        "budget_safety",
        "evidence_plane",
        "degraded_flags",
    ],
    "properties": {
        "schema_version": {"const": CONTROL_STATE_ATTESTATION_SCHEMA_VERSION},
        "period": {
            "type": "object",
            "additionalProperties": False,
            "required": ["start", "end"],
            "properties": {
                "start": {"type": "string", "pattern": ISO_Z_RE},
                "end": {"type": "string", "pattern": ISO_Z_RE},
            },
        },
        "deployment_id": {"type": "string", "pattern": HASH_RE},
        "gateway_liveness": {
            "type": "object",
            "additionalProperties": False,
            "required": ["decisions_observed", "max_gap_seconds"],
            "properties": {
                "decisions_observed": {"type": "integer", "minimum": 0},
                "max_gap_seconds": {"type": "integer", "minimum": 0},
            },
        },
        "policy_state": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "active_policy_bundle_hash",
                "bundle_signature_status",
                "last_change_timestamp",
            ],
            "properties": {
                "active_policy_bundle_hash": {
                    "anyOf": [{"type": "string", "pattern": HASH_RE}, {"type": "null"}]
                },
                "bundle_signature_status": {"enum": list(POLICY_SIGNATURE_STATUSES)},
                "last_change_timestamp": {
                    "anyOf": [{"type": "string", "pattern": ISO_Z_RE}, {"type": "null"}]
                },
            },
        },
        "decision_counts": {
            "type": "object",
            "additionalProperties": False,
            "required": list(DECISION_CLASSES),
            "properties": {
                decision: {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(RISK_CLASSES),
                    "properties": {
                        risk_class: {"type": "integer", "minimum": 0} for risk_class in RISK_CLASSES
                    },
                }
                for decision in DECISION_CLASSES
            },
        },
        "escalation_integrity": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "escalations_in_period",
                "valid_approval_receipts",
                "valid_approval_receipt_fraction",
            ],
            "properties": {
                "escalations_in_period": {"type": "integer", "minimum": 0},
                "valid_approval_receipts": {"type": "integer", "minimum": 0},
                "valid_approval_receipt_fraction": {
                    "type": "string",
                    "pattern": r"^(?:0|1)\.[0-9]{6}$",
                },
            },
        },
        "drift_rejections": {
            "type": "object",
            "additionalProperties": False,
            "required": ["canonical_action_mismatch_refusals"],
            "properties": {"canonical_action_mismatch_refusals": {"type": "integer", "minimum": 0}},
        },
        "certificate_coverage": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "spend_class_actions",
                "spend_class_deterministic_budget_certificate_fraction",
                "irreversible_class_actions",
                "irreversible_class_max_de_lockout_inspection_certificate_fraction",
                "irreversible_class_verdict_certificate_fraction",
            ],
            "properties": {
                "spend_class_actions": {"type": "integer", "minimum": 0},
                "spend_class_deterministic_budget_certificate_fraction": {
                    "type": "string",
                    "pattern": r"^(?:0|1)\.[0-9]{6}$",
                },
                "irreversible_class_actions": {"type": "integer", "minimum": 0},
                "irreversible_class_max_de_lockout_inspection_certificate_fraction": {
                    "type": "string",
                    "pattern": r"^(?:0|1)\.[0-9]{6}$",
                },
                "irreversible_class_verdict_certificate_fraction": {
                    "type": "string",
                    "pattern": r"^(?:0|1)\.[0-9]{6}$",
                },
            },
        },
        "budget_safety": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "h1_true_hard_caps_present",
                "h2_single_writer_accounting",
                "max_configured_cap_usd",
                "zero_overshoot_observed",
            ],
            "properties": {
                "h1_true_hard_caps_present": {"type": "boolean"},
                "h2_single_writer_accounting": {"type": "boolean"},
                "max_configured_cap_usd": {"type": "string", "pattern": r"^[0-9]+\.[0-9]{6}$"},
                "zero_overshoot_observed": {"type": "boolean"},
            },
        },
        "evidence_plane": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "latest_sth",
                "last_successful_external_anchor_timestamp",
                "retention_preset",
            ],
            "properties": {
                "latest_sth": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["tree_size", "root_hash"],
                    "properties": {
                        "tree_size": {"type": "integer", "minimum": 0},
                        "root_hash": {"type": "string", "pattern": HASH_RE},
                    },
                },
                "last_successful_external_anchor_timestamp": {
                    "anyOf": [{"type": "string", "pattern": ISO_Z_RE}, {"type": "null"}]
                },
                "retention_preset": {"enum": list(RETENTION_PRESETS)},
            },
        },
        "degraded_flags": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "signing_degraded",
                "anchoring_degraded",
                "fail_open_condition_observed",
            ],
            "properties": {
                "signing_degraded": {"type": "boolean"},
                "anchoring_degraded": {"type": "boolean"},
                "fail_open_condition_observed": {"type": "boolean"},
            },
        },
    },
}


def load_ledger_records(ledger_path: str | Path) -> tuple[JsonObject, ...]:
    """Load semantic ledger records from Velvet's binary audit ledger."""

    return tuple(read_ledger_records(ledger_path))


def deployment_hash(*, deployment_id_source: str, deployment_salt: str) -> str:
    if not deployment_id_source:
        raise AssuranceAttestationError("deployment_id_source is required")
    if not deployment_salt:
        raise AssuranceAttestationError("deployment_salt is required")
    return canonical_hash_sha256(
        {
            "schema_version": "velvet.assurance.deployment_id.v1",
            "deployment_id_source": deployment_id_source,
            "deployment_salt": deployment_salt,
        }
    )


def build_control_state_payload(
    *,
    records: Sequence[Mapping[str, Any]],
    sth: Mapping[str, Any],
    period_start: str | datetime,
    period_end: str | datetime,
    deployment_id_source: str,
    deployment_salt: str,
    approvals_path: str | Path | None = None,
    approval_signer: SigningProvider | None = None,
    policy_bundle_hash: str | None = None,
    policy_bundle_signature_status: str = "unavailable",
    policy_last_change_timestamp: str | datetime | None = None,
    last_successful_anchor_timestamp: str | datetime | None = None,
    retention_preset: str = "unavailable",
    signing_degraded: bool = False,
    anchoring_degraded: bool = False,
    fail_open_condition_observed: bool = False,
) -> JsonObject:
    """Build a deterministic aggregate-only attestation payload."""

    selection = _select_period(records, period_start=period_start, period_end=period_end)
    policy_state = _policy_state(
        selection.records_through_period,
        explicit_policy_hash=policy_bundle_hash,
        explicit_signature_status=policy_bundle_signature_status,
        explicit_change_timestamp=policy_last_change_timestamp,
    )
    approvals = load_approval_snapshot(approvals_path)
    decision_counts = _decision_counts(selection.period_records)
    payload: JsonObject = {
        "schema_version": CONTROL_STATE_ATTESTATION_SCHEMA_VERSION,
        "period": {
            "start": _iso_z(selection.period_start),
            "end": _iso_z(selection.period_end),
        },
        "deployment_id": deployment_hash(
            deployment_id_source=deployment_id_source,
            deployment_salt=deployment_salt,
        ),
        "gateway_liveness": {
            "decisions_observed": len(selection.period_records),
            "max_gap_seconds": _max_gap_seconds(
                selection.period_records,
                period_start=selection.period_start,
                period_end=selection.period_end,
            ),
        },
        "policy_state": policy_state,
        "decision_counts": decision_counts,
        "escalation_integrity": _escalation_integrity(
            selection.period_records,
            approval_receipts=[item.to_dict() for item in approvals.receipts],
            approval_signer=approval_signer,
        ),
        "drift_rejections": {
            "canonical_action_mismatch_refusals": sum(
                1 for record in selection.period_records if _is_drift_rejection(record)
            )
        },
        "certificate_coverage": _certificate_coverage(selection.period_records),
        "budget_safety": _budget_safety(selection.period_records),
        "evidence_plane": {
            "latest_sth": {
                "tree_size": _int_value(sth.get("tree_size")),
                "root_hash": str(sth.get("root_hash")),
            },
            "last_successful_external_anchor_timestamp": _optional_iso_z(
                last_successful_anchor_timestamp
            ),
            "retention_preset": _retention_preset(retention_preset),
        },
        "degraded_flags": {
            "signing_degraded": bool(signing_degraded),
            "anchoring_degraded": bool(anchoring_degraded),
            "fail_open_condition_observed": bool(fail_open_condition_observed),
        },
    }
    validate_control_state_payload(payload)
    return payload


def issue_control_state_attestation(
    *,
    records: Sequence[Mapping[str, Any]],
    sth: Mapping[str, Any],
    period_start: str | datetime,
    period_end: str | datetime,
    deployment_id_source: str,
    deployment_salt: str,
    signer: SigningProvider,
    signing_key_id: str | None = None,
    tenant_id: str = LOCAL_DEMO_TENANT_ID,
    signed_at: str | None = None,
    **payload_kwargs: Any,
) -> JsonObject:
    """Build and sign a control-state attestation envelope."""

    payload = build_control_state_payload(
        records=records,
        sth=sth,
        period_start=period_start,
        period_end=period_end,
        deployment_id_source=deployment_id_source,
        deployment_salt=deployment_salt,
        **payload_kwargs,
    )
    payload_hash = control_state_payload_hash(payload)
    key_id = signing_key_id or signer_default_key_id(signer)
    return {
        "schema_version": CONTROL_STATE_ATTESTATION_ENVELOPE_SCHEMA_VERSION,
        "payload": payload,
        "payload_hash": payload_hash,
        "signature": sign_payload_hash(
            payload_hash,
            purpose=PURPOSE_CONTROL_STATE_ATTESTATION,
            tenant_id=tenant_id,
            key_id=key_id,
            signer=signer,
            signed_at=signed_at,
        ),
    }


def scheduled_attestation_period(
    *,
    cadence: str,
    now: str | datetime | None = None,
) -> ScheduledPeriod:
    """Return the last complete UTC reporting period for a scheduler cadence."""

    normalized = cadence.strip().lower()
    if normalized not in SCHEDULED_CADENCES:
        raise AssuranceAttestationError("cadence must be hourly or daily")
    current = _parse_time(now) if now is not None else datetime.now(tz=UTC)
    current = current.astimezone(UTC)
    if normalized == "hourly":
        end = current.replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(hours=1)
    else:
        end = current.replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=1)
    return ScheduledPeriod(cadence=normalized, period_start=start, period_end=end)


def issue_scheduled_control_state_attestation(
    *,
    cadence: str,
    now: str | datetime | None = None,
    records: Sequence[Mapping[str, Any]],
    sth: Mapping[str, Any],
    deployment_id_source: str,
    deployment_salt: str,
    signer: SigningProvider,
    signing_key_id: str | None = None,
    tenant_id: str = LOCAL_DEMO_TENANT_ID,
    signed_at: str | None = None,
    **payload_kwargs: Any,
) -> JsonObject:
    """Issue an attestation for the last complete scheduler period."""

    period = scheduled_attestation_period(cadence=cadence, now=now)
    return issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start=period.period_start,
        period_end=period.period_end,
        deployment_id_source=deployment_id_source,
        deployment_salt=deployment_salt,
        signer=signer,
        signing_key_id=signing_key_id,
        tenant_id=tenant_id,
        signed_at=signed_at,
        **payload_kwargs,
    )


def control_state_payload_hash(payload: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(payload)


def verify_control_state_attestation(
    envelope: Mapping[str, Any],
    *,
    public_key: str | bytes | object,
) -> bool:
    if envelope.get("schema_version") != CONTROL_STATE_ATTESTATION_ENVELOPE_SCHEMA_VERSION:
        return False
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, Mapping) or not isinstance(signature, Mapping):
        return False
    try:
        validate_control_state_payload(payload)
    except AssuranceAttestationError:
        return False
    payload_hash = control_state_payload_hash(payload)
    if not hmac.compare_digest(str(envelope.get("payload_hash")), payload_hash):
        return False
    return verify_signature_record(
        signature,
        payload_hash,
        purpose=PURPOSE_CONTROL_STATE_ATTESTATION,
        public_key=public_key,
    )


def validate_control_state_payload(payload: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise AssuranceAttestationError(f"invalid control-state payload at {path}: {first.message}")


def validate_payload_schema_content_free(
    schema: Mapping[str, Any] = CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA,
) -> None:
    """Fail if the payload schema admits content fields or free text."""

    violations: list[str] = []
    _walk_schema_fields(schema, path=(), violations=violations)
    if violations:
        joined = ", ".join(sorted(violations))
        raise AssuranceAttestationError(f"attestation payload schema has content fields: {joined}")


def sth_summary(sth: Mapping[str, Any]) -> JsonObject:
    return {"tree_size": _int_value(sth.get("tree_size")), "root_hash": str(sth.get("root_hash"))}


def verify_sth_if_key_available(
    sth: Mapping[str, Any],
    *,
    public_key: str | bytes | object | None,
) -> str:
    if public_key is None:
        return "unavailable"
    return "valid" if verify_signed_tree_head(sth, public_key=public_key) else "invalid"


def _select_period(
    records: Sequence[Mapping[str, Any]],
    *,
    period_start: str | datetime,
    period_end: str | datetime,
) -> PeriodSelection:
    start = _parse_time(period_start)
    end = _parse_time(period_end)
    if end <= start:
        raise AssuranceAttestationError("period_end must be after period_start")
    with_times = [
        (recorded_at, record)
        for record in records
        if (recorded_at := _recorded_at(record)) is not None
    ]
    with_times.sort(key=lambda item: item[0])
    return PeriodSelection(
        period_start=start,
        period_end=end,
        period_records=tuple(
            record for recorded_at, record in with_times if start <= recorded_at < end
        ),
        records_through_period=tuple(
            record for recorded_at, record in with_times if recorded_at < end
        ),
    )


def _decision_counts(records: Sequence[Mapping[str, Any]]) -> JsonObject:
    counts: JsonObject = {
        decision: {risk_class: 0 for risk_class in RISK_CLASSES} for decision in DECISION_CLASSES
    }
    for record in records:
        decision = _normalize_decision(_record_decision(record))
        risk_class = _normalize_risk_class(_record_risk_class(record))
        counts[decision][risk_class] = int(counts[decision][risk_class]) + 1
    return counts


def _escalation_integrity(
    records: Sequence[Mapping[str, Any]],
    *,
    approval_receipts: Sequence[Mapping[str, Any]],
    approval_signer: SigningProvider | None,
) -> JsonObject:
    escalations = [
        record for record in records if _normalize_decision(_record_decision(record)) == "escalate"
    ]
    valid_receipt_requests = {
        str(receipt.get("approval_request_id"))
        for receipt in approval_receipts
        if _approval_receipt_valid(receipt, signer=approval_signer)
    }
    matched = sum(
        1
        for record in escalations
        if (approval_request_id := _approval_request_id(record)) is not None
        and approval_request_id in valid_receipt_requests
    )
    return {
        "escalations_in_period": len(escalations),
        "valid_approval_receipts": matched,
        "valid_approval_receipt_fraction": _fraction(matched, len(escalations)),
    }


def _certificate_coverage(records: Sequence[Mapping[str, Any]]) -> JsonObject:
    executed = [
        record for record in records if _normalize_decision(_record_decision(record)) == "admit"
    ]
    spend = [record for record in executed if _is_spend_class(record)]
    irreversible = [record for record in executed if _is_irreversible_class(record)]
    spend_covered = sum(1 for record in spend if _has_deterministic_budget_certificate(record))
    irreversible_covered = sum(
        1 for record in irreversible if _has_max_de_lockout_or_inspection(record)
    )
    verdict_covered = sum(
        1 for record in irreversible if record.get("verdict_certificate_hash") is not None
    )
    return {
        "spend_class_actions": len(spend),
        "spend_class_deterministic_budget_certificate_fraction": _fraction(
            spend_covered,
            len(spend),
        ),
        "irreversible_class_actions": len(irreversible),
        "irreversible_class_max_de_lockout_inspection_certificate_fraction": _fraction(
            irreversible_covered,
            len(irreversible),
        ),
        "irreversible_class_verdict_certificate_fraction": _fraction(
            verdict_covered,
            len(irreversible),
        ),
    }


def _budget_safety(records: Sequence[Mapping[str, Any]]) -> JsonObject:
    certificates = [
        certificate
        for record in records
        if (certificate := _budget_certificate(record)) is not None
    ]
    caps: list[float] = []
    for certificate in certificates:
        cap = _number(certificate.get("hard_cap_usd"))
        if cap is not None:
            caps.append(cap)
    h1 = bool(certificates) and len(caps) == len(certificates)
    h2 = bool(certificates) and all(
        str(certificate.get("concurrency_model", "")).lower()
        in {"single_writer_atomic", "single-writer-atomic"}
        for certificate in certificates
    )
    zero_overshoot = all(_certificate_has_no_overshoot(certificate) for certificate in certificates)
    max_cap = max(caps) if caps else 0.0
    return {
        "h1_true_hard_caps_present": h1,
        "h2_single_writer_accounting": h2,
        "max_configured_cap_usd": _decimal6(max_cap),
        "zero_overshoot_observed": zero_overshoot,
    }


def _policy_state(
    records: Sequence[Mapping[str, Any]],
    *,
    explicit_policy_hash: str | None,
    explicit_signature_status: str,
    explicit_change_timestamp: str | datetime | None,
) -> JsonObject:
    policy_hash = explicit_policy_hash or _latest_policy_hash(records)
    if policy_hash is not None and not re.fullmatch(HASH_RE, policy_hash):
        raise AssuranceAttestationError("policy_bundle_hash must be a sha256:<hex> hash")
    status = (
        explicit_signature_status
        if explicit_signature_status in POLICY_SIGNATURE_STATUSES
        else "unavailable"
    )
    change_timestamp = (
        explicit_change_timestamp
        if explicit_change_timestamp is not None
        else _policy_change_time(records)
    )
    return {
        "active_policy_bundle_hash": policy_hash,
        "bundle_signature_status": status,
        "last_change_timestamp": _optional_iso_z(change_timestamp),
    }


def _latest_policy_hash(records: Sequence[Mapping[str, Any]]) -> str | None:
    for record in reversed(records):
        value = record.get("policy_hash")
        if isinstance(value, str) and re.fullmatch(HASH_RE, value):
            return value
        selected = _selected_warrant(record)
        value = selected.get("policy_hash") if selected is not None else None
        if isinstance(value, str) and re.fullmatch(HASH_RE, value):
            return value
    return None


def _policy_change_time(records: Sequence[Mapping[str, Any]]) -> datetime | None:
    latest_hash: str | None = None
    latest_change: datetime | None = None
    for record in records:
        policy_hash = cast(str | None, record.get("policy_hash"))
        if policy_hash is None and (selected := _selected_warrant(record)) is not None:
            policy_hash = cast(str | None, selected.get("policy_hash"))
        if policy_hash and policy_hash != latest_hash:
            latest_hash = policy_hash
            latest_change = _recorded_at(record)
    return latest_change


def _max_gap_seconds(
    records: Sequence[Mapping[str, Any]],
    *,
    period_start: datetime,
    period_end: datetime,
) -> int:
    points = [period_start]
    points.extend(
        recorded_at for record in records if (recorded_at := _recorded_at(record)) is not None
    )
    points.append(period_end)
    points.sort()
    gaps = [
        max(0, int(math.ceil((right - left).total_seconds())))
        for left, right in zip(points, points[1:], strict=False)
    ]
    return max(gaps or [0])


def _approval_receipt_valid(
    receipt_payload: Mapping[str, Any],
    *,
    signer: SigningProvider | None,
) -> bool:
    try:
        receipt = ApprovalReceipt.from_dict(receipt_payload)
    except (KeyError, TypeError, ValueError):
        return False
    if receipt.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION:
        return False
    expected_hash = receipt.compute_receipt_hash()
    if not hmac.compare_digest(receipt.receipt_hash, expected_hash):
        return False
    if signer is not None:
        return receipt.verify_signature(signer=signer)
    signature = receipt.signature
    material = (
        signature.get("public_verification_material") if isinstance(signature, Mapping) else None
    )
    public_key = None
    if isinstance(material, Mapping):
        public_key = material.get("public_key_pem") or material.get("public_key_base64")
    return verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_APPROVAL_RECEIPT_V1,
        tenant_id=receipt.tenant_id,
        public_key=cast(str | bytes | object | None, public_key),
    )


def _record_decision(record: Mapping[str, Any]) -> str:
    for value in (
        record.get("decision"),
        _nested(record, ("selected_warrant", "decision")),
        _nested(record, ("admission_evidence", "decision", "decision")),
    ):
        if isinstance(value, str) and value:
            return value
    return "skip"


def _normalize_decision(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"execute", "allow", "allowed", "admitted", "admit", "forwarded"}:
        return "admit"
    if normalized in {"ask_approval", "review", "requires_approval", "escalated"}:
        return "escalate"
    if normalized in {"delay", "delayed", "deferred"}:
        return "defer"
    if normalized in {"skip", "skipped"}:
        return "skip"
    if normalized in {"block", "blocked", "deny", "denied"}:
        return "block"
    upper = value.strip().upper()
    if upper == "ADMITTED":
        return "admit"
    if upper == "ESCALATED":
        return "escalate"
    if upper in {"BLOCKED", "DENIED", "MASKED_ACTION_FAILURE"}:
        return "block"
    return "skip"


def _record_risk_class(record: Mapping[str, Any]) -> str:
    for value in (
        _nested(record, ("selected_warrant", "risk_class")),
        _nested(record, ("admission_evidence", "risk", "risk_class")),
        _nested(record, ("approval_request", "risk_class")),
        record.get("risk_class"),
    ):
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _normalize_risk_class(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized in RISK_CLASSES:
        return normalized
    if normalized in {"bind", "external", "bind_external_action"}:
        return "bind_external"
    if "spend" in normalized or "budget" in normalized or "cost" in normalized:
        return "spend"
    if "destruct" in normalized or "irreversible" in normalized:
        return "irreversible"
    return "other"


def _approval_request_id(record: Mapping[str, Any]) -> str | None:
    for value in (
        _nested(record, ("approval_request", "approval_request_id")),
        _nested(record, ("selected_warrant", "approval_request_id")),
        _nested(record, ("admission_evidence", "decision", "approval_request_id")),
    ):
        if isinstance(value, str) and value:
            return value
    return None


def _is_drift_rejection(record: Mapping[str, Any]) -> bool:
    values = (
        record.get("reason"),
        _nested(record, ("execution_receipt", "reason")),
        _nested(record, ("admission_evidence", "decision", "reason")),
    )
    return any(
        isinstance(value, str) and "canonical action hash mismatch" in value.lower()
        for value in values
    )


def _is_spend_class(record: Mapping[str, Any]) -> bool:
    risk_class = _normalize_risk_class(_record_risk_class(record))
    action_type = str(
        record.get("action_type") or _nested(record, ("selected_warrant", "action_type")) or ""
    )
    return (
        risk_class in _SPEND_RISK_CLASSES
        or "SPEND" in action_type.upper()
        or _budget_certificate(record) is not None
    )


def _is_irreversible_class(record: Mapping[str, Any]) -> bool:
    risk_class = _normalize_risk_class(_record_risk_class(record))
    action_type = str(
        record.get("action_type") or _nested(record, ("selected_warrant", "action_type")) or ""
    )
    return risk_class in _IRREVERSIBLE_RISK_CLASSES or any(
        marker in action_type.upper() for marker in ("DESTROY", "IRREVERSIBLE", "DELETE")
    )


def _has_deterministic_budget_certificate(record: Mapping[str, Any]) -> bool:
    certificate = _budget_certificate(record)
    if certificate is None:
        return False
    return (
        "deterministic" in str(certificate.get("schema_version", "")).lower()
        or str(certificate.get("certificate_kind", "")).lower() == "deterministic_hard_cap"
    )


def _has_max_de_lockout_or_inspection(record: Mapping[str, Any]) -> bool:
    certificate = _max_de_certificate(record)
    if certificate is None:
        return False
    text = canonical_dumps(certificate).lower()
    return "max_de" in text and ("lockout" in text or "inspect" in text or "inspection" in text)


def _budget_certificate(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates = (
        _nested(record, ("selected_warrant", "budget_certificate")),
        _nested(record, ("selected_warrant", "certificate")),
        _nested(record, ("budget_certificate",)),
    )
    for candidate in candidates:
        if isinstance(candidate, Mapping):
            text = canonical_dumps(candidate).lower()
            if "budget" in text or "hard_cap" in text:
                return candidate
    return None


def _max_de_certificate(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates = (
        _nested(record, ("selected_warrant", "certificate")),
        _nested(record, ("selected_warrant", "metadata", "max_de_certificate")),
        _nested(record, ("max_de_certificate",)),
        _nested(record, ("max_de_certificate_envelope",)),
    )
    for candidate in candidates:
        if isinstance(candidate, Mapping) and "max_de" in canonical_dumps(candidate).lower():
            return candidate
    return None


def _certificate_has_no_overshoot(certificate: Mapping[str, Any]) -> bool:
    projected = _number(certificate.get("projected_spend_usd"))
    limit = _number(certificate.get("budget_limit_usd"))
    slack = _number(certificate.get("slack_usd"))
    if projected is not None and limit is not None:
        return projected <= limit + 1e-9
    if slack is not None:
        return slack >= -1e-9
    return True


def _selected_warrant(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    selected = record.get("selected_warrant")
    return selected if isinstance(selected, Mapping) else None


def _recorded_at(record: Mapping[str, Any]) -> datetime | None:
    for key in ("recorded_at", "timestamp", "created_at"):
        value = record.get(key)
        if isinstance(value, str):
            try:
                return _parse_time(value)
            except AssuranceAttestationError:
                return None
    return None


def _parse_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise AssuranceAttestationError(f"invalid timestamp: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _optional_iso_z(value: str | datetime | None) -> str | None:
    if value is None:
        return None
    return _iso_z(_parse_time(value))


def _fraction(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.000000"
    return _decimal6(numerator / denominator)


def _decimal6(value: float) -> str:
    return f"{value:.6f}"


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _int_value(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise AssuranceAttestationError("tree_size must be an integer") from error
    if parsed < 0:
        raise AssuranceAttestationError("tree_size must be non-negative")
    return parsed


def _retention_preset(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    return normalized if normalized in RETENTION_PRESETS else "unavailable"


def _nested(payload: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = payload
    for part in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _walk_schema_fields(
    schema: Mapping[str, Any],
    *,
    path: tuple[str, ...],
    violations: list[str],
) -> None:
    schema_type = schema.get("type")
    if _schema_declares_object(schema_type) and schema.get("additionalProperties") is not False:
        violations.append(".".join((*path, "<open-object>")) or "<root>.<open-object>")
    if _schema_declares_string(schema_type) and not _string_schema_is_constrained(schema):
        violations.append(".".join((*path, "<free-string>")) or "<root>.<free-string>")
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for key, subschema in properties.items():
            key_text = str(key)
            normalized = key_text.lower()
            if any(term in normalized for term in _CONTENT_FIELD_DENYLIST):
                if key_text not in {"deployment_id"}:
                    violations.append(".".join((*path, key_text)))
            if isinstance(subschema, Mapping):
                _walk_schema_fields(subschema, path=(*path, key_text), violations=violations)
    for child_key in ("items", "additionalProperties"):
        child = schema.get(child_key)
        if isinstance(child, Mapping):
            _walk_schema_fields(child, path=path, violations=violations)
    for child_key in ("anyOf", "oneOf", "allOf"):
        children = schema.get(child_key)
        if isinstance(children, Sequence) and not isinstance(children, (str, bytes)):
            for index, child in enumerate(children):
                if isinstance(child, Mapping):
                    _walk_schema_fields(
                        child,
                        path=(*path, f"{child_key}[{index}]"),
                        violations=violations,
                    )


def _schema_declares_object(schema_type: Any) -> bool:
    return schema_type == "object" or (
        isinstance(schema_type, Sequence)
        and not isinstance(schema_type, (str, bytes))
        and "object" in schema_type
    )


def _schema_declares_string(schema_type: Any) -> bool:
    return schema_type == "string" or (
        isinstance(schema_type, Sequence)
        and not isinstance(schema_type, (str, bytes))
        and "string" in schema_type
    )


def _string_schema_is_constrained(schema: Mapping[str, Any]) -> bool:
    return any(key in schema for key in ("const", "enum", "pattern"))
