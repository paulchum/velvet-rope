"""Signed pre-execution admission evidence objects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from urllib.request import url2pathname

from jsonschema import Draft202012Validator

from velvet.approvals import ApprovalRequest, redact_sensitive_value
from velvet.serialization import (
    VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD,
    JsonObject,
    canonical_dumps,
    canonical_hash_sha256,
    proof_artifact_hash,
    quantize_decimal,
    stable_json_object,
)
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_ADMISSION_EVIDENCE,
    SigningProvider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)

ADMISSION_EVIDENCE_SCHEMA_VERSION = "velvet.admission_evidence.v1"
ADMISSION_EVIDENCE_SCHEMA_ARTIFACT = "schemas/velvet_rope/admission_evidence.v1.schema.json"


@dataclass(frozen=True)
class RawActionArtifactRef:
    artifact_id: str
    uri: str
    sha256: str
    size_bytes: int
    content_type: str = "application/json"

    def to_dict(self) -> JsonObject:
        return {
            "artifact_id": self.artifact_id,
            "uri": self.uri,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "content_type": self.content_type,
        }


def build_admission_evidence(
    *,
    request: Mapping[str, Any],
    admission_decision: Mapping[str, Any],
    sequence_number: int,
    previous_record_hash: str,
    previous_frame_hash: str | None = None,
    ledger_path: str | Path | None = None,
    approval_request: ApprovalRequest | Mapping[str, Any] | None = None,
    raw_artifact_dir: str | Path | None = None,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
    tenant_id: str | None = None,
    environment: str | None = None,
) -> JsonObject:
    """Build and sign one replayable pre-execution admission evidence object."""

    request_payload = stable_json_object(request)
    decision_payload = stable_json_object(admission_decision)
    selected_warrant = _mapping(decision_payload.get("selected_warrant"))
    raw_ref = write_raw_action_artifact(
        request_payload,
        _raw_artifact_dir(raw_artifact_dir, ledger_path),
    )
    redacted_request = _proof_safe(redact_sensitive_value(request_payload))
    resolved_tenant_id = (
        tenant_id
        or _string(selected_warrant, "tenant_id")
        or _string(_mapping(request_payload.get("state")), "tenant_id")
        or _string(_mapping(request_payload.get("metadata")), "tenant_id")
        or LOCAL_DEMO_TENANT_ID
    )
    resolved_environment = (
        environment
        or _string(selected_warrant, "environment")
        or _string(_mapping(request_payload.get("state")), "environment")
        or _string(_mapping(request_payload.get("metadata")), "environment")
        or "local"
    )
    approval_payload = _approval_payload(approval_request)
    decision = _mapping(decision_payload.get("decision"))
    tool_key = _tool_key(request_payload, selected_warrant)
    evidence_id = _evidence_id(
        raw_ref.sha256,
        selected_warrant,
        sequence_number=sequence_number,
        previous_record_hash=previous_record_hash,
    )
    evidence: JsonObject = {
        "schema_version": ADMISSION_EVIDENCE_SCHEMA_VERSION,
        "canonicalization": VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD,
        "evidence_id": evidence_id,
        "issued_at": _now_iso(),
        "tenant_id": resolved_tenant_id,
        "environment": resolved_environment,
        "product_surface": str(decision_payload.get("product_surface") or "velvet"),
        "boundary": "pre_execution_authorization",
        "request_id": _request_id(request_payload, selected_warrant),
        "seal_id": _string(decision_payload, "seal_id") or _string(selected_warrant, "seal_id"),
        "thread_id": _string(decision_payload, "thread_id")
        or _string(selected_warrant, "thread_id"),
        "raw_action": {
            "raw_action_hash": raw_ref.sha256,
            "raw_action_ref": raw_ref.to_dict(),
            "redacted_action_hash": canonical_hash_sha256(redacted_request),
            "redacted_action": redacted_request,
        },
        "tool": {
            "tool_key": tool_key,
            "tool_name": _string(selected_warrant, "tool_name") or tool_key or "unknown",
            "mcp_server": _string(selected_warrant, "mcp_server")
            or _string(_mapping(request_payload.get("payload")), "server")
            or _string(request_payload, "server"),
            "mcp_tool": _string(selected_warrant, "mcp_tool")
            or _string(_mapping(request_payload.get("payload")), "tool")
            or _string(request_payload, "tool"),
            "tool_schema_hash": _proof_hash(selected_warrant.get("tool_schema_hash")),
            "arguments_hash": _proof_hash(selected_warrant.get("arguments_hash")),
        },
        "policy": {
            "policy_hash": _proof_hash(selected_warrant.get("policy_hash")),
            "policy_version": _string(selected_warrant, "policy_version") or "unavailable",
            "policy_statuses": _string_list(selected_warrant.get("policy_statuses")),
            "policy_reasons": _string_list(selected_warrant.get("policy_reasons")),
        },
        "decision": {
            "decision": _canonical_decision(str(selected_warrant.get("decision") or "")),
            "reason": str(selected_warrant.get("reason") or decision.get("reason") or ""),
            "action_type": str(
                selected_warrant.get("action_type") or decision.get("action_type") or ""
            ),
            "approval_required": bool(selected_warrant.get("approval_required")),
            "approval_status": _approval_status(approval_payload, selected_warrant),
            "approval_request_id": _string(approval_payload, "approval_request_id"),
            "approval_request_hash": (
                canonical_hash_sha256(approval_payload) if approval_payload else None
            ),
            "approval_receipt_id": None,
            "upstream_execution_status": _upstream_status(
                _canonical_decision(str(selected_warrant.get("decision") or ""))
            ),
            "obligations": _string_list(selected_warrant.get("obligations")),
        },
        "risk": {
            "risk_class": str(selected_warrant.get("risk_class") or "unknown"),
            "pricing_status": str(selected_warrant.get("pricing_status") or "not_priced"),
            "entry_price": _decimal_string(selected_warrant.get("entry_price")),
            "clearance_score": _decimal_string(selected_warrant.get("clearance_score")),
            "risk_penalty": _decimal_string(selected_warrant.get("risk_penalty")),
            "scarcity_pressure": _decimal_string(selected_warrant.get("scarcity_pressure")),
        },
        "authority": _authority_snapshot(request_payload, selected_warrant),
        "identity": _identity_context(request_payload, selected_warrant),
        "ledger_state": {
            "ledger_path": str(ledger_path) if ledger_path is not None else None,
            "sequence_number": int(sequence_number),
            "previous_record_hash": previous_record_hash,
            "previous_frame_hash": previous_frame_hash,
        },
        "bindings": {
            "warrant_hash": _warrant_hash(selected_warrant),
            "selected_warrant_hash": canonical_hash_sha256(selected_warrant),
            "request_hash": _proof_hash(selected_warrant.get("request_hash")),
        },
    }
    evidence["admission_evidence_hash"] = admission_evidence_hash(evidence)
    active_key_id = signing_key_id or (
        signer_default_key_id(signer) if signer is not None else None
    )
    evidence["signature"] = sign_payload_hash(
        str(evidence["admission_evidence_hash"]),
        purpose=PURPOSE_ADMISSION_EVIDENCE,
        tenant_id=resolved_tenant_id,
        key_id=active_key_id or "velvet-local-dev-hmac-demo-key",
        signer=signer,
    )
    validate_admission_evidence(evidence)
    return evidence


def write_raw_action_artifact(
    raw_action: Mapping[str, Any],
    output_dir: str | Path,
) -> RawActionArtifactRef:
    """Write the full raw action to local storage and return a hash-bound ref."""

    data = canonical_dumps(stable_json_object(raw_action)).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"raw_{digest[:32]}"
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f"{artifact_id}.json"
    path.write_bytes(data)
    return RawActionArtifactRef(
        artifact_id=artifact_id,
        uri=path.resolve().as_uri(),
        sha256=f"sha256:{digest}",
        size_bytes=len(data),
    )


def admission_evidence_hash(evidence: Mapping[str, Any]) -> str:
    return proof_artifact_hash("admission_evidence", evidence)


def validate_admission_evidence(evidence: Mapping[str, Any]) -> None:
    schema = json.loads(Path(ADMISSION_EVIDENCE_SCHEMA_ARTIFACT).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(evidence)


def verify_admission_evidence(
    evidence: Mapping[str, Any],
    *,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
    raw_action_payload: Mapping[str, Any] | None = None,
) -> bool:
    try:
        validate_admission_evidence(evidence)
        expected_hash = admission_evidence_hash(evidence)
    except Exception:
        return False
    if evidence.get("admission_evidence_hash") != expected_hash:
        return False
    signature = evidence.get("signature")
    if not isinstance(signature, Mapping):
        return False
    if not verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_ADMISSION_EVIDENCE,
        tenant_id=_string(evidence, "tenant_id"),
        key_id=_string(cast(Mapping[str, Any], signature), "key_id"),
        signer=signer,
        public_key=public_key,
    ):
        return False
    if raw_action_payload is not None:
        return _raw_payload_hash(raw_action_payload) == _raw_action_hash(evidence)
    return verify_raw_action_ref(evidence)


def verify_raw_action_ref(evidence: Mapping[str, Any]) -> bool:
    raw_action = _mapping(evidence.get("raw_action"))
    raw_ref = _mapping(raw_action.get("raw_action_ref"))
    uri = _string(raw_ref, "uri")
    expected_hash = _string(raw_ref, "sha256")
    size = raw_ref.get("size_bytes")
    if uri is None or expected_hash is None or not isinstance(size, int):
        return False
    path = _file_uri_path(uri)
    if path is None or not path.exists():
        return False
    data = path.read_bytes()
    digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
    return (
        digest == expected_hash
        and len(data) == size
        and raw_action.get("raw_action_hash") == digest
    )


def ledger_record_admission_evidence_issues(
    record: Mapping[str, Any],
    *,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
) -> list[JsonObject]:
    evidence = record.get("admission_evidence")
    if evidence is None:
        return []
    if not isinstance(evidence, Mapping):
        return [
            {
                "code": "admission_evidence_invalid",
                "severity": "error",
                "path": "admission_evidence",
                "message": "admission_evidence must be an object.",
            }
        ]
    issues: list[JsonObject] = []
    if not verify_admission_evidence(evidence, signer=signer, public_key=public_key):
        issues.append(
            {
                "code": "admission_evidence_signature_mismatch",
                "severity": "error",
                "path": "admission_evidence",
                "message": "Admission evidence hash, signature, or raw action ref is invalid.",
            }
        )
    if record.get("admission_evidence_hash") != evidence.get("admission_evidence_hash"):
        issues.append(
            {
                "code": "admission_evidence_hash_mismatch",
                "severity": "error",
                "path": "admission_evidence_hash",
                "expected": evidence.get("admission_evidence_hash"),
                "actual": record.get("admission_evidence_hash"),
                "message": "Ledger admission_evidence_hash does not match admission_evidence.",
            }
        )
    for record_field, pointer in (
        ("sequence_number", ("ledger_state", "sequence_number")),
        ("previous_record_hash", ("ledger_state", "previous_record_hash")),
        ("decision", ("decision", "decision")),
        ("tool_schema_hash", ("tool", "tool_schema_hash")),
        ("arguments_hash", ("tool", "arguments_hash")),
        ("policy_hash", ("policy", "policy_hash")),
        ("request_hash", ("bindings", "request_hash")),
        ("warrant_hash", ("bindings", "warrant_hash")),
    ):
        actual = record.get(record_field)
        expected = _nested(evidence, pointer)
        if actual is not None and expected is not None and actual != expected:
            issues.append(
                {
                    "code": "admission_evidence_binding_mismatch",
                    "severity": "error",
                    "path": ".".join(pointer),
                    "field": record_field,
                    "expected": expected,
                    "actual": actual,
                    "message": (
                        f"Ledger {record_field} does not match bound admission evidence."
                    ),
                }
            )
    return issues


def _authority_snapshot(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any],
) -> JsonObject:
    certificate = selected_warrant.get("certificate")
    budget_state = _mapping(request.get("budget_state")) or _mapping(
        _mapping(request.get("state")).get("budget_state")
    )
    pricing_fields = {
        "entry_price": _decimal_string(selected_warrant.get("entry_price")),
        "clearance_score": _decimal_string(selected_warrant.get("clearance_score")),
        "scarcity_pressure": _decimal_string(selected_warrant.get("scarcity_pressure")),
        "risk_penalty": _decimal_string(selected_warrant.get("risk_penalty")),
    }
    if any(
        key in selected_warrant
        for key in (
            "authority_ledger_sequence",
            "authority_budget_before",
            "authority_budget_after",
        )
    ):
        return {
            "mode": "authority_ledger",
            "authority_ledger_sequence": selected_warrant.get("authority_ledger_sequence"),
            "authority_budget_before": selected_warrant.get("authority_budget_before"),
            "authority_budget_after": selected_warrant.get("authority_budget_after"),
            "budget_state_hash": canonical_hash_sha256(_proof_safe(budget_state))
            if budget_state
            else None,
            "budget_certificate_hash": canonical_hash_sha256(_proof_safe(certificate))
            if isinstance(certificate, Mapping)
            else None,
            "pricing": pricing_fields,
        }
    if isinstance(certificate, Mapping):
        return {
            "mode": "deterministic_budget_certificate"
            if "budget" in str(certificate.get("schema_version", "")).lower()
            else "router_pricing_snapshot",
            "budget_state_hash": canonical_hash_sha256(_proof_safe(budget_state))
            if budget_state
            else None,
            "budget_certificate_hash": canonical_hash_sha256(_proof_safe(certificate)),
            "pricing": pricing_fields,
        }
    if any(value is not None for value in pricing_fields.values()):
        return {
            "mode": "router_pricing_snapshot",
            "budget_state_hash": canonical_hash_sha256(_proof_safe(budget_state))
            if budget_state
            else None,
            "budget_certificate_hash": None,
            "pricing": pricing_fields,
        }
    return {
        "mode": "non_budget_affecting",
        "budget_state_hash": canonical_hash_sha256(_proof_safe(budget_state))
        if budget_state
        else None,
        "budget_certificate_hash": None,
        "pricing": pricing_fields,
    }


def _identity_context(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any],
) -> JsonObject:
    state = _mapping(request.get("state"))
    metadata = _mapping(request.get("metadata"))
    return {
        "tenant_id": _string(selected_warrant, "tenant_id") or _string(state, "tenant_id"),
        "environment": _string(selected_warrant, "environment")
        or _string(state, "environment")
        or _string(metadata, "environment"),
        "actor_user_id": _string(selected_warrant, "actor_user_id")
        or _string(state, "actor_user_id")
        or _string(state, "user_id")
        or _string(metadata, "user_id"),
        "subject_id": _string(state, "subject_id") or _string(metadata, "subject_id"),
        "agent_id": _string(selected_warrant, "agent_id")
        or _string(request, "agent_id")
        or _string(state, "agent_id"),
        "session_id": _string(selected_warrant, "session_id") or _string(state, "session_id"),
        "delegation": _proof_safe(
            _mapping(state.get("delegation")) or _mapping(metadata.get("delegation"))
        ),
    }


def _approval_payload(
    approval_request: ApprovalRequest | Mapping[str, Any] | None,
) -> JsonObject:
    if approval_request is None:
        return {}
    if isinstance(approval_request, ApprovalRequest):
        return stable_json_object(approval_request.to_dict())
    return stable_json_object(approval_request)


def _approval_status(
    approval_payload: Mapping[str, Any],
    selected_warrant: Mapping[str, Any],
) -> str:
    if approval_payload:
        return str(approval_payload.get("status", "pending"))
    return "missing" if bool(selected_warrant.get("approval_required")) else "not_required"


def _upstream_status(decision: str) -> str:
    if decision == "execute":
        return "forward_authorized"
    if decision == "escalate":
        return "pending_approval"
    return "not_forwarded"


def _raw_artifact_dir(raw_artifact_dir: str | Path | None, ledger_path: str | Path | None) -> Path:
    if raw_artifact_dir is not None:
        return Path(raw_artifact_dir)
    if ledger_path is not None:
        path = Path(ledger_path)
        return path.parent / f"{path.stem}_raw_actions"
    return Path("admission_evidence_raw_actions")


def _raw_payload_hash(payload: Mapping[str, Any]) -> str:
    data = canonical_dumps(stable_json_object(payload)).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _raw_action_hash(evidence: Mapping[str, Any]) -> str | None:
    return _string(_mapping(evidence.get("raw_action")), "raw_action_hash")


def _file_uri_path(uri: str) -> Path | None:
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        return Path(url2pathname(parsed.path))
    if parsed.scheme == "repo":
        relative = f"{parsed.netloc}{parsed.path}".lstrip("/")
        if relative:
            return Path(relative)
    return None


def _evidence_id(
    raw_action_hash: str,
    selected_warrant: Mapping[str, Any],
    *,
    sequence_number: int,
    previous_record_hash: str,
) -> str:
    return (
        "ae_"
        + canonical_hash_sha256(
            {
                "raw_action_hash": raw_action_hash,
                "warrant_hash": selected_warrant.get("warrant_hash"),
                "sequence_number": sequence_number,
                "previous_record_hash": previous_record_hash,
            }
        ).removeprefix("sha256:")[:32]
    )


def _tool_key(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any],
) -> str | None:
    if _string(selected_warrant, "tool_key"):
        return _string(selected_warrant, "tool_key")
    payload = _mapping(request.get("payload"))
    server = _string(payload, "server") or _string(request, "server")
    tool = _string(payload, "tool") or _string(request, "tool")
    if server and tool:
        return f"{server}/{tool}"
    return _string(request, "tool_key")


def _request_id(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any],
) -> str | None:
    return _string(selected_warrant, "request_id") or _string(request, "request_id")


def _canonical_decision(value: str) -> str:
    if value == "execute":
        return "execute"
    if value in {"escalate", "ask_approval", "delay", "pending_approval"}:
        return "escalate"
    return "block"


def _proof_hash(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith("sha256:"):
        return value
    return None


def _warrant_hash(selected_warrant: Mapping[str, Any]) -> str | None:
    if not selected_warrant:
        return None
    explicit = _proof_hash(selected_warrant.get("warrant_hash"))
    if explicit is not None:
        return explicit
    try:
        return proof_artifact_hash("warrant", selected_warrant)
    except Exception:
        return canonical_hash_sha256(selected_warrant)


def _string(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return []


def _mapping(value: Any) -> JsonObject:
    return dict(cast(Mapping[str, Any], value)) if isinstance(value, Mapping) else {}


def _nested(mapping: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _decimal_string(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return quantize_decimal(str(value))
    except Exception:
        return None


def _proof_safe(value: Any) -> Any:
    if isinstance(value, float):
        return quantize_decimal(str(value))
    if isinstance(value, Mapping):
        return {str(key): _proof_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple | list):
        return [_proof_safe(item) for item in value]
    return value


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
