"""Execution Permit and Receipt artifacts for Velvet execution authority."""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

from velvet.actions import CanonicalAction, ProofDecision
from velvet.contracts import AdmissionContract
from velvet.envelope import ProofEnvelope
from velvet.serialization import (
    JsonObject,
    canonical_hash,
    canonical_hash_sha256,
    proof_artifact_hash,
    stable_json_object,
)
from velvet.signing import (
    DEMO_ED25519_KEY_ID,
    PURPOSE_EXECUTION_PERMIT,
    PURPOSE_EXECUTION_RECEIPT,
    SigningProvider,
    load_demo_ed25519_signer,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)

EXECUTION_PERMIT_SCHEMA_VERSION = "velvet.execution_permit.v1"
EXECUTION_RECEIPT_SCHEMA_VERSION = "velvet.execution_receipt.v1"
EXECUTION_CANONICALIZATION = "velvet.canonical_json.v1.sha256.unsigned_payload"
DEFAULT_PERMIT_TTL_SECONDS = 30
MAX_PERMIT_TTL_SECONDS = 300
LEDGER_RECORD_ARTIFACT_TYPE = "ledger_record"
EXECUTION_METADATA_KEY = "velvet_execution"
LEGACY_ADMISSION_METADATA_KEY = "velvet_admission"

PermitState = Literal["issued", "claimed", "succeeded", "failed_before_dispatch", "indeterminate"]
ReceiptOutcome = Literal["succeeded", "failed_before_dispatch", "rejected", "indeterminate"]


class ExecutionPermitError(ValueError):
    """Raised when execution authority cannot be issued or verified."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def strip_model_controlled_execution_metadata(request: Mapping[str, Any]) -> JsonObject:
    """Remove Velvet-reserved authority metadata from a model-supplied request."""

    sanitized = stable_json_object(request)
    params = sanitized.get("params")
    if not isinstance(params, dict):
        return sanitized
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        if "_meta" in params:
            params.pop("_meta", None)
        return sanitized
    meta.pop(EXECUTION_METADATA_KEY, None)
    meta.pop(LEGACY_ADMISSION_METADATA_KEY, None)
    if not meta:
        params.pop("_meta", None)
    return sanitized


@dataclass(frozen=True)
class ArtifactReference:
    artifact_type: str
    artifact_id: str
    artifact_hash: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ArtifactReference:
        return cls(
            artifact_type=str(data["artifact_type"]),
            artifact_id=str(data["artifact_id"]),
            artifact_hash=str(data["artifact_hash"]),
        )

    def to_dict(self) -> JsonObject:
        return {
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "artifact_hash": _prefixed_hash(self.artifact_hash),
        }


@dataclass(frozen=True)
class SubjectBinding:
    subject_id_hash: str | None = None
    agent_id_hash: str | None = None
    client_id_hash: str | None = None
    session_id_hash: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SubjectBinding:
        return cls(
            subject_id_hash=_optional_string(data.get("subject_id_hash")),
            agent_id_hash=_optional_string(data.get("agent_id_hash")),
            client_id_hash=_optional_string(data.get("client_id_hash")),
            session_id_hash=_optional_string(data.get("session_id_hash")),
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {}
        for key, value in (
            ("subject_id_hash", self.subject_id_hash),
            ("agent_id_hash", self.agent_id_hash),
            ("client_id_hash", self.client_id_hash),
            ("session_id_hash", self.session_id_hash),
        ):
            if value is not None:
                payload[key] = _prefixed_hash(value)
        return payload


@dataclass(frozen=True)
class ResourceScope:
    kind: str
    id_hash: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ResourceScope:
        return cls(kind=str(data["kind"]), id_hash=str(data["id_hash"]))

    def to_dict(self) -> JsonObject:
        return {"kind": self.kind, "id_hash": _prefixed_hash(self.id_hash)}


@dataclass(frozen=True)
class ExecutionPermitScope:
    surface: str
    method: str
    tool_key: str
    operation: str
    request_hash: str
    canonical_action_hash: str
    arguments_hash: str
    tool_schema_hash: str
    read_set_hash: str | None = None
    resource: ResourceScope | None = None
    subgoal_id_hash: str | None = None

    @classmethod
    def from_action(
        cls,
        action: CanonicalAction,
        *,
        actual_request: Mapping[str, Any] | None = None,
        method: str | None = None,
        tool_key: str | None = None,
        arguments_hash: str | None = None,
        tool_schema_hash: str | None = None,
        resource: ResourceScope | None = None,
    ) -> ExecutionPermitScope:
        request_payload = strip_model_controlled_execution_metadata(
            actual_request or action.to_dict()
        )
        return cls(
            surface=action.surface,
            method=method or action.operation or action.canonical_type,
            tool_key=tool_key or action.tool_name,
            operation=action.operation or action.canonical_type,
            request_hash=canonical_hash_sha256(request_payload),
            canonical_action_hash=_prefixed_hash(action.canonical_action_hash),
            arguments_hash=_prefixed_hash(
                arguments_hash or action.arguments_hash or request_payload
            ),
            tool_schema_hash=_prefixed_hash(
                tool_schema_hash
                or action.tool_schema_hash
                or canonical_hash_sha256({"tool_key": tool_key or action.tool_name})
            ),
            read_set_hash=_prefixed_hash(action.read_set_hash) if action.read_set_hash else None,
            resource=resource,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionPermitScope:
        resource = data.get("resource")
        return cls(
            surface=str(data["surface"]),
            method=str(data["method"]),
            tool_key=str(data["tool_key"]),
            operation=str(data["operation"]),
            request_hash=str(data["request_hash"]),
            canonical_action_hash=str(data["canonical_action_hash"]),
            arguments_hash=str(data["arguments_hash"]),
            tool_schema_hash=str(data["tool_schema_hash"]),
            read_set_hash=_optional_string(data.get("read_set_hash")),
            resource=ResourceScope.from_dict(cast(Mapping[str, Any], resource))
            if isinstance(resource, Mapping)
            else None,
            subgoal_id_hash=_optional_string(data.get("subgoal_id_hash")),
        )

    @classmethod
    def from_permit_request(
        cls,
        permit_scope: ExecutionPermitScope,
        *,
        actual_request: Mapping[str, Any],
        operation: str,
        canonical_action_hash: str,
        arguments_hash: str,
        tool_schema_hash: str,
    ) -> ExecutionPermitScope:
        """Rebuild runtime-computed fields without replacing issuer-owned scope.

        Gateways and executors can use different action normalizers. The
        gateway's surface, resource, read-set, and logical bindings therefore
        remain authoritative while request-derived fields are recomputed at
        the executor boundary.
        """
        request_payload = strip_model_controlled_execution_metadata(actual_request)
        return cls(
            surface=permit_scope.surface,
            method=permit_scope.method,
            tool_key=permit_scope.tool_key,
            operation=operation,
            request_hash=canonical_hash_sha256(request_payload),
            canonical_action_hash=_prefixed_hash(canonical_action_hash),
            arguments_hash=_prefixed_hash(arguments_hash),
            tool_schema_hash=_prefixed_hash(tool_schema_hash),
            read_set_hash=permit_scope.read_set_hash,
            resource=permit_scope.resource,
            subgoal_id_hash=permit_scope.subgoal_id_hash,
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "surface": self.surface,
            "method": self.method,
            "tool_key": self.tool_key,
            "operation": self.operation,
            "request_hash": _prefixed_hash(self.request_hash),
            "canonical_action_hash": _prefixed_hash(self.canonical_action_hash),
            "arguments_hash": _prefixed_hash(self.arguments_hash),
            "tool_schema_hash": _prefixed_hash(self.tool_schema_hash),
        }
        if self.read_set_hash is not None:
            payload["read_set_hash"] = _prefixed_hash(self.read_set_hash)
        if self.resource is not None:
            payload["resource"] = self.resource.to_dict()
        if self.subgoal_id_hash is not None:
            payload["subgoal_id_hash"] = _prefixed_hash(self.subgoal_id_hash)
        return payload


@dataclass(frozen=True)
class PermitPolicyBinding:
    policy_hash: str
    policy_version: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PermitPolicyBinding:
        return cls(
            policy_hash=str(data["policy_hash"]),
            policy_version=str(data["policy_version"]),
        )

    def to_dict(self) -> JsonObject:
        return {
            "policy_hash": _prefixed_hash(self.policy_hash),
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class PermitLineage:
    decision_artifact: ArtifactReference
    pre_execution_record: ArtifactReference
    supporting_artifacts: tuple[ArtifactReference, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PermitLineage:
        supporting = data.get("supporting_artifacts", [])
        return cls(
            decision_artifact=ArtifactReference.from_dict(
                cast(Mapping[str, Any], data["decision_artifact"])
            ),
            pre_execution_record=ArtifactReference.from_dict(
                cast(Mapping[str, Any], data["pre_execution_record"])
            ),
            supporting_artifacts=tuple(
                ArtifactReference.from_dict(cast(Mapping[str, Any], item))
                for item in supporting
                if isinstance(item, Mapping)
            ),
        )

    def to_dict(self) -> JsonObject:
        return {
            "decision_artifact": self.decision_artifact.to_dict(),
            "pre_execution_record": self.pre_execution_record.to_dict(),
            "supporting_artifacts": [item.to_dict() for item in self.supporting_artifacts],
        }


@dataclass(frozen=True)
class PermitConstraints:
    single_use: bool = True
    claim_before_dispatch: bool = True
    deny_on_scope_drift: bool = True
    receipt_required: bool = True
    idempotency_key: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PermitConstraints:
        return cls(
            single_use=bool(data.get("single_use", True)),
            claim_before_dispatch=bool(data.get("claim_before_dispatch", True)),
            deny_on_scope_drift=bool(data.get("deny_on_scope_drift", True)),
            receipt_required=bool(data.get("receipt_required", True)),
            idempotency_key=str(data.get("idempotency_key", "")),
        )

    def to_dict(self) -> JsonObject:
        return {
            "single_use": self.single_use,
            "claim_before_dispatch": self.claim_before_dispatch,
            "deny_on_scope_drift": self.deny_on_scope_drift,
            "receipt_required": self.receipt_required,
            "idempotency_key": self.idempotency_key,
        }


@dataclass(frozen=True)
class PermitValidity:
    issued_at: str
    not_before: str
    expires_at: str
    issued_at_logical_step: int | None = None
    expires_at_logical_step: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PermitValidity:
        return cls(
            issued_at=str(data["issued_at"]),
            not_before=str(data["not_before"]),
            expires_at=str(data["expires_at"]),
            issued_at_logical_step=_optional_int(data.get("issued_at_logical_step")),
            expires_at_logical_step=_optional_int(data.get("expires_at_logical_step")),
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
        }
        if self.issued_at_logical_step is not None:
            payload["issued_at_logical_step"] = self.issued_at_logical_step
        if self.expires_at_logical_step is not None:
            payload["expires_at_logical_step"] = self.expires_at_logical_step
        return payload


@dataclass(frozen=True)
class ExecutionPermit:
    permit_id: str
    issuer: str
    tenant_id: str
    environment: str
    audience: str
    subject: SubjectBinding
    scope: ExecutionPermitScope
    policy: PermitPolicyBinding
    lineage: PermitLineage
    constraints: PermitConstraints
    obligations: tuple[str, ...]
    validity: PermitValidity
    signature: JsonObject = field(default_factory=dict)
    permit_hash: str = ""
    schema_version: str = EXECUTION_PERMIT_SCHEMA_VERSION
    canonicalization: str = EXECUTION_CANONICALIZATION

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionPermit:
        return cls(
            schema_version=str(data.get("schema_version", EXECUTION_PERMIT_SCHEMA_VERSION)),
            canonicalization=str(data.get("canonicalization", EXECUTION_CANONICALIZATION)),
            permit_id=str(data["permit_id"]),
            issuer=str(data["issuer"]),
            tenant_id=str(data["tenant_id"]),
            environment=str(data["environment"]),
            audience=str(data["audience"]),
            subject=SubjectBinding.from_dict(cast(Mapping[str, Any], data["subject"])),
            scope=ExecutionPermitScope.from_dict(cast(Mapping[str, Any], data["scope"])),
            policy=PermitPolicyBinding.from_dict(cast(Mapping[str, Any], data["policy"])),
            lineage=PermitLineage.from_dict(cast(Mapping[str, Any], data["lineage"])),
            constraints=PermitConstraints.from_dict(cast(Mapping[str, Any], data["constraints"])),
            obligations=tuple(str(item) for item in data.get("obligations", ())),
            validity=PermitValidity.from_dict(cast(Mapping[str, Any], data["validity"])),
            permit_hash=str(data.get("permit_hash", "")),
            signature=stable_json_object(
                data.get("signature") if isinstance(data.get("signature"), Mapping) else {}
            ),
        )

    def unsigned_payload(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "canonicalization": self.canonicalization,
            "permit_id": self.permit_id,
            "issuer": self.issuer,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "audience": self.audience,
            "subject": self.subject.to_dict(),
            "scope": self.scope.to_dict(),
            "policy": self.policy.to_dict(),
            "lineage": self.lineage.to_dict(),
            "constraints": self.constraints.to_dict(),
            "obligations": list(self.obligations),
            "validity": self.validity.to_dict(),
        }

    def compute_hash(self) -> str:
        return proof_artifact_hash("execution_permit", self.to_dict(include_signature=False))

    def to_dict(self, *, include_signature: bool = True) -> JsonObject:
        payload = self.unsigned_payload()
        payload["permit_hash"] = self.permit_hash or proof_artifact_hash(
            "execution_permit", payload
        )
        if include_signature:
            payload["signature"] = stable_json_object(self.signature)
        return payload

    def with_hash_and_signature(
        self,
        *,
        signer: SigningProvider,
        key_id: str | None = None,
    ) -> ExecutionPermit:
        permit_hash = self.compute_hash()
        signature = sign_payload_hash(
            permit_hash,
            purpose=PURPOSE_EXECUTION_PERMIT,
            tenant_id=self.tenant_id,
            key_id=key_id or signer_default_key_id(signer, DEMO_ED25519_KEY_ID),
            signer=signer,
        )
        return replace(self, permit_hash=permit_hash, signature=signature)


@dataclass(frozen=True)
class DispatchClaim:
    claim_id: str
    permit_id: str
    permit_hash: str
    claimed_at: str
    claimant: str
    pre_execution_record_hash: str
    claim_hash: str = ""

    def to_dict(self) -> JsonObject:
        payload = {
            "claim_id": self.claim_id,
            "permit_id": self.permit_id,
            "permit_hash": _prefixed_hash(self.permit_hash),
            "claimed_at": self.claimed_at,
            "claimant": self.claimant,
            "pre_execution_record_hash": _prefixed_hash(self.pre_execution_record_hash),
        }
        payload["claim_hash"] = self.claim_hash or canonical_hash_sha256(payload)
        return payload


@dataclass(frozen=True)
class ReceiptExecutor:
    executor_id: str
    audience: str
    attestation_level: Literal["gateway_observed", "substrate_attested"] = "gateway_observed"

    def to_dict(self) -> JsonObject:
        return {
            "executor_id": self.executor_id,
            "audience": self.audience,
            "attestation_level": self.attestation_level,
        }


@dataclass(frozen=True)
class ReceiptError:
    code: str
    detail_hash: str

    def to_dict(self) -> JsonObject:
        return {"code": self.code, "detail_hash": _prefixed_hash(self.detail_hash)}


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    permit_id: str
    permit_hash: str
    dispatch_claim_record_hash: str
    pre_execution_record_hash: str
    request_hash: str
    canonical_action_hash: str
    executor: ReceiptExecutor
    outcome: ReceiptOutcome
    dispatch_attempted: bool
    started_at: str
    completed_at: str
    upstream_response_hash: str | None = None
    substrate_receipt_hash: str | None = None
    error: ReceiptError | None = None
    signature: JsonObject = field(default_factory=dict)
    receipt_hash: str = ""
    schema_version: str = EXECUTION_RECEIPT_SCHEMA_VERSION
    canonicalization: str = EXECUTION_CANONICALIZATION
    reason: str | None = None
    output: JsonObject = field(default_factory=dict)

    @classmethod
    def rejected(
        cls,
        *,
        permit: ExecutionPermit | None,
        action: CanonicalAction,
        reason: str,
        now: str | None = None,
    ) -> ExecutionReceipt:
        timestamp = now or _now_iso()
        permit_id = permit.permit_id if permit is not None else "none"
        permit_hash = permit.permit_hash if permit is not None else canonical_hash_sha256({})
        return cls(
            receipt_id=_receipt_id(permit_id, "rejected", timestamp),
            permit_id=permit_id,
            permit_hash=permit_hash,
            dispatch_claim_record_hash=canonical_hash_sha256({"claim": "none"}),
            pre_execution_record_hash=permit.lineage.pre_execution_record.artifact_hash
            if permit is not None
            else canonical_hash_sha256({"pre_execution": "none"}),
            request_hash=canonical_hash_sha256(action.to_dict()),
            canonical_action_hash=_prefixed_hash(action.canonical_action_hash),
            executor=ReceiptExecutor(executor_id="velvet", audience="none"),
            outcome="rejected",
            dispatch_attempted=False,
            started_at=timestamp,
            completed_at=timestamp,
            error=ReceiptError("rejected", canonical_hash_sha256({"reason": reason})),
            reason=reason,
            output={"canonical_action_hash": _prefixed_hash(action.canonical_action_hash)},
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionReceipt:
        error = data.get("error")
        return cls(
            schema_version=str(data.get("schema_version", EXECUTION_RECEIPT_SCHEMA_VERSION)),
            canonicalization=str(data.get("canonicalization", EXECUTION_CANONICALIZATION)),
            receipt_id=str(data["receipt_id"]),
            permit_id=str(data["permit_id"]),
            permit_hash=str(data["permit_hash"]),
            dispatch_claim_record_hash=str(data["dispatch_claim_record_hash"]),
            pre_execution_record_hash=str(data["pre_execution_record_hash"]),
            request_hash=str(data["request_hash"]),
            canonical_action_hash=str(data["canonical_action_hash"]),
            executor=ReceiptExecutor(
                executor_id=str(cast(Mapping[str, Any], data["executor"])["executor_id"]),
                audience=str(cast(Mapping[str, Any], data["executor"])["audience"]),
                attestation_level=cast(
                    Literal["gateway_observed", "substrate_attested"],
                    str(
                        cast(Mapping[str, Any], data["executor"]).get(
                            "attestation_level", "gateway_observed"
                        )
                    ),
                ),
            ),
            outcome=cast(ReceiptOutcome, str(data["outcome"])),
            dispatch_attempted=bool(data["dispatch_attempted"]),
            upstream_response_hash=_optional_string(data.get("upstream_response_hash")),
            substrate_receipt_hash=_optional_string(data.get("substrate_receipt_hash")),
            error=ReceiptError(
                code=str(cast(Mapping[str, Any], error)["code"]),
                detail_hash=str(cast(Mapping[str, Any], error)["detail_hash"]),
            )
            if isinstance(error, Mapping)
            else None,
            started_at=str(data["started_at"]),
            completed_at=str(data["completed_at"]),
            receipt_hash=str(data.get("receipt_hash", "")),
            signature=stable_json_object(
                data.get("signature") if isinstance(data.get("signature"), Mapping) else {}
            ),
            reason=_optional_string(data.get("reason")),
            output=stable_json_object(
                data.get("output") if isinstance(data.get("output"), Mapping) else {}
            ),
        )

    def unsigned_payload(self) -> JsonObject:
        payload: JsonObject = {
            "schema_version": self.schema_version,
            "canonicalization": self.canonicalization,
            "receipt_id": self.receipt_id,
            "permit_id": self.permit_id,
            "permit_hash": _prefixed_hash(self.permit_hash),
            "dispatch_claim_record_hash": _prefixed_hash(self.dispatch_claim_record_hash),
            "pre_execution_record_hash": _prefixed_hash(self.pre_execution_record_hash),
            "request_hash": _prefixed_hash(self.request_hash),
            "canonical_action_hash": _prefixed_hash(self.canonical_action_hash),
            "executor": self.executor.to_dict(),
            "outcome": self.outcome,
            "dispatch_attempted": self.dispatch_attempted,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
        if self.upstream_response_hash is not None:
            payload["upstream_response_hash"] = _prefixed_hash(self.upstream_response_hash)
        if self.substrate_receipt_hash is not None:
            payload["substrate_receipt_hash"] = _prefixed_hash(self.substrate_receipt_hash)
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.output:
            payload["output"] = stable_json_object(self.output)
        return payload

    def compute_hash(self) -> str:
        return proof_artifact_hash("execution_receipt", self.to_dict(include_signature=False))

    def to_dict(self, *, include_signature: bool = True) -> JsonObject:
        payload = self.unsigned_payload()
        payload["receipt_hash"] = self.receipt_hash or proof_artifact_hash(
            "execution_receipt", payload
        )
        if include_signature:
            payload["signature"] = stable_json_object(self.signature)
        return payload

    def with_hash_and_signature(
        self,
        *,
        signer: SigningProvider,
        tenant_id: str,
        key_id: str | None = None,
    ) -> ExecutionReceipt:
        receipt_hash = self.compute_hash()
        signature = sign_payload_hash(
            receipt_hash,
            purpose=PURPOSE_EXECUTION_RECEIPT,
            tenant_id=tenant_id,
            key_id=key_id or signer_default_key_id(signer, DEMO_ED25519_KEY_ID),
            signer=signer,
        )
        return replace(self, receipt_hash=receipt_hash, signature=signature)


@dataclass(frozen=True)
class PermitValidationContext:
    tenant_id: str
    environment: str
    audience: str
    policy_hash: str
    policy_version: str
    tool_schema_hash: str
    scope: ExecutionPermitScope
    subject: SubjectBinding = field(default_factory=SubjectBinding)
    now: str | None = None
    logical_step: int | None = None
    max_ttl_seconds: int = MAX_PERMIT_TTL_SECONDS
    trusted_public_key: str | bytes | object | None = None
    trusted_signer: SigningProvider | None = None
    trusted_key_id: str | None = None


@dataclass(frozen=True)
class PreparedExecution:
    permit: ExecutionPermit
    actual_request: JsonObject
    action: CanonicalAction


@dataclass(frozen=True)
class AuthorizedExecution:
    prepared: PreparedExecution
    claim: DispatchClaim

    @property
    def permit(self) -> ExecutionPermit:
        return self.prepared.permit


class PermitClaimStore:
    """Atomic permit state store for Python execution paths."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._states: dict[tuple[str, str], JsonObject] = {}
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()

    def issue(self, permit: ExecutionPermit) -> None:
        if self.path is None:
            key = (permit.permit_id, "")
            if key in self._states:
                return
            self._states[key] = {
                "state": "issued",
                "permit_hash": permit.permit_hash,
                "tenant_id": permit.tenant_id,
                "environment": permit.environment,
                "receipt_hash": None,
            }
            return
        with sqlite3.connect(self.path, timeout=30.0, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO execution_permit_state(
                    permit_id, permit_hash, tenant_id, environment, state, issued_at
                )
                VALUES (?, ?, ?, ?, 'issued', ?)
                """,
                (
                    permit.permit_id,
                    permit.permit_hash,
                    permit.tenant_id,
                    permit.environment,
                    permit.validity.issued_at,
                ),
            )
            connection.execute("COMMIT")

    def claim(
        self,
        permit: ExecutionPermit,
        *,
        claimant: str,
        claimed_at: str | None = None,
    ) -> DispatchClaim | None:
        timestamp = claimed_at or _now_iso()
        claim = DispatchClaim(
            claim_id=_claim_id(permit.permit_id, permit.permit_hash, claimant),
            permit_id=permit.permit_id,
            permit_hash=permit.permit_hash,
            claimed_at=timestamp,
            claimant=claimant,
            pre_execution_record_hash=permit.lineage.pre_execution_record.artifact_hash,
        )
        claim = replace(claim, claim_hash=canonical_hash_sha256(claim.to_dict()))
        if self.path is None:
            key = (permit.permit_id, "")
            state = self._states.get(key)
            if state is None:
                self.issue(permit)
                state = self._states.get(key)
            if (
                state is None
                or state.get("state") != "issued"
                or state.get("permit_hash") != permit.permit_hash
            ):
                return None
            state.update(
                {
                    "state": "claimed",
                    "claim_id": claim.claim_id,
                    "claim_hash": claim.claim_hash,
                    "claimed_at": timestamp,
                }
            )
            return claim
        with sqlite3.connect(self.path, timeout=30.0, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO execution_permit_state(
                    permit_id, permit_hash, tenant_id, environment, state, issued_at
                )
                VALUES (?, ?, ?, ?, 'issued', ?)
                """,
                (
                    permit.permit_id,
                    permit.permit_hash,
                    permit.tenant_id,
                    permit.environment,
                    permit.validity.issued_at,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE execution_permit_state
                SET state = 'claimed',
                    claim_id = ?,
                    claim_hash = ?,
                    claimed_at = ?
                WHERE permit_id = ?
                  AND permit_hash = ?
                  AND state = 'issued'
                """,
                (claim.claim_id, claim.claim_hash, timestamp, permit.permit_id, permit.permit_hash),
            )
            connection.execute("COMMIT")
            return claim if cursor.rowcount == 1 else None

    def complete(
        self,
        permit: ExecutionPermit,
        *,
        outcome: Literal["succeeded", "failed_before_dispatch", "indeterminate"],
        receipt_hash: str,
        completed_at: str | None = None,
    ) -> bool:
        timestamp = completed_at or _now_iso()
        if self.path is None:
            state = self._states.get((permit.permit_id, ""))
            if (
                state is None
                or state.get("state") != "claimed"
                or state.get("permit_hash") != permit.permit_hash
            ):
                return False
            state.update(
                {
                    "state": outcome,
                    "receipt_hash": receipt_hash,
                    "completed_at": timestamp,
                }
            )
            return True
        with sqlite3.connect(self.path, timeout=30.0, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE execution_permit_state
                SET state = ?, receipt_hash = ?, completed_at = ?
                WHERE permit_id = ?
                  AND permit_hash = ?
                  AND state = 'claimed'
                """,
                (outcome, receipt_hash, timestamp, permit.permit_id, permit.permit_hash),
            )
            connection.execute("COMMIT")
            return cursor.rowcount == 1

    def state(self, permit_id: str, permit_hash: str) -> str | None:
        if self.path is None:
            row = self._states.get((permit_id, ""))
            if row is not None and row.get("permit_hash") != permit_hash:
                return None
            return str(row["state"]) if row is not None else None
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT state FROM execution_permit_state
                WHERE permit_id = ? AND permit_hash = ?
                """,
                (permit_id, permit_hash),
            ).fetchone()
        return str(row[0]) if row is not None else None

    def _initialize(self) -> None:
        if self.path is None:
            return
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_permit_state (
                    permit_id TEXT NOT NULL,
                    permit_hash TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    state TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    claim_id TEXT,
                    claim_hash TEXT,
                    claimed_at TEXT,
                    completed_at TEXT,
                    receipt_hash TEXT,
                    PRIMARY KEY (permit_id),
                    CHECK (
                        state IN (
                            'issued',
                            'claimed',
                            'succeeded',
                            'failed_before_dispatch',
                            'indeterminate'
                        )
                    )
                )
                """
            )


def build_pre_execution_record(
    admission: Any,
    *,
    request: Mapping[str, Any] | None = None,
    tenant_id: str | None = None,
    environment: str | None = None,
    record_id: str | None = None,
) -> JsonObject:
    envelope = cast(ProofEnvelope, admission.envelope)
    action = cast(CanonicalAction, admission.canonical_action)
    payload: JsonObject = {
        "artifact_type": LEDGER_RECORD_ARTIFACT_TYPE,
        "record_type": "pre_execution_decision",
        "record_id": record_id or _pre_execution_record_id(envelope, action),
        "tenant_id": tenant_id or action.tenant_id,
        "environment": environment or action.environment,
        "decision": admission.decision.value,
        "proof_envelope_hash": proof_artifact_hash("proof_envelope", envelope.to_dict()),
        "canonical_action_hash": _prefixed_hash(action.canonical_action_hash),
        "request_hash": canonical_hash_sha256(
            strip_model_controlled_execution_metadata(request or action.to_dict())
        ),
        "policy_hash": canonical_hash_sha256(
            {"policy_version": action.policy_version, "contract_version": action.contract_version}
        ),
        "policy_version": action.policy_version,
        "tool_schema_hash": _prefixed_hash(
            action.tool_schema_hash or canonical_hash_sha256({"tool_key": action.tool_name})
        ),
        "arguments_hash": _prefixed_hash(action.arguments_hash or action.proposed_payload_hash),
    }
    if action.read_set_hash:
        payload["read_set_hash"] = _prefixed_hash(action.read_set_hash)
    payload["artifact_hash"] = canonical_hash_sha256(payload)
    return payload


def prepare_execution(
    admission: Any,
    *,
    actual_request: Mapping[str, Any] | None,
    pre_execution_record: Mapping[str, Any],
    contract: AdmissionContract,
    tenant_id: str | None = None,
    environment: str | None = None,
    audience: str = "velvet.executor",
    product_surface: str = "velvet_python",
    method: str | None = None,
    tool_key: str | None = None,
    tool_schema_hash: str | None = None,
    policy_hash: str | None = None,
    policy_version: str | None = None,
    subject_id: str | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
    approval_receipt_hash: str | None = None,
    issued_at: str | None = None,
    lifetime_seconds: int = DEFAULT_PERMIT_TTL_SECONDS,
    logical_step: int | None = None,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
    claim_store: PermitClaimStore | None = None,
) -> PreparedExecution:
    action = cast(CanonicalAction, admission.canonical_action)
    envelope = cast(ProofEnvelope, admission.envelope)
    approval_permits_execution = (
        admission.decision is ProofDecision.ESCALATED and approval_receipt_hash is not None
    )
    if admission.decision is not ProofDecision.ADMITTED and not approval_permits_execution:
        raise ExecutionPermitError(
            "decision_not_executable",
            "admission decision is not executable",
        )
    if not envelope.verify_signature(contract):
        raise ExecutionPermitError("decision_signature_invalid", "proof envelope signature failed")
    if not hmac.compare_digest(
        _prefixed_hash(envelope.canonical_action_hash),
        _prefixed_hash(action.canonical_action_hash),
    ):
        raise ExecutionPermitError(
            "decision_artifact_action_mismatch",
            "proof envelope does not bind the current canonical action",
        )
    record_hash = str(
        pre_execution_record.get("artifact_hash") or pre_execution_record.get("record_hash")
    )
    if not record_hash:
        raise ExecutionPermitError(
            "pre_execution_record_missing",
            "pre-execution record is missing",
        )
    if pre_execution_record.get("permit_hash") is not None:
        raise ExecutionPermitError(
            "circular_lineage",
            "pre-execution record must not reference permit",
        )
    now = issued_at or _now_iso()
    if lifetime_seconds <= 0 or lifetime_seconds > MAX_PERMIT_TTL_SECONDS:
        raise ExecutionPermitError("permit_ttl_invalid", "permit TTL exceeds configured maximum")
    expires_at = (
        _parse_time(now) + timedelta(seconds=lifetime_seconds)
    ).isoformat().replace("+00:00", "Z")
    scope = ExecutionPermitScope.from_action(
        action,
        actual_request=actual_request,
        method=method,
        tool_key=tool_key,
        arguments_hash=str(pre_execution_record.get("arguments_hash") or action.arguments_hash),
        tool_schema_hash=tool_schema_hash
        or str(pre_execution_record.get("tool_schema_hash") or action.tool_schema_hash or ""),
    )
    policy = PermitPolicyBinding(
        policy_hash=policy_hash
        or str(
            pre_execution_record.get("policy_hash")
            or canonical_hash_sha256(contract.to_dict())
        ),
        policy_version=policy_version or contract.policy_version,
    )
    decision_artifact = ArtifactReference(
        artifact_type="proof_envelope",
        artifact_id=envelope.envelope_id,
        artifact_hash=proof_artifact_hash("proof_envelope", envelope.to_dict()),
    )
    supporting = [
        ArtifactReference(
            artifact_type="canonical_action",
            artifact_id=action.action_id,
            artifact_hash=_prefixed_hash(action.canonical_action_hash),
        )
    ]
    if approval_receipt_hash is not None:
        supporting.append(
            ArtifactReference(
                artifact_type="approval",
                artifact_id="approval_receipt",
                artifact_hash=approval_receipt_hash,
            )
        )
    permit_id = _permit_id(
        tenant_id or action.tenant_id or contract.tenant_id,
        environment or action.environment,
        scope,
        record_hash,
        now,
    )
    constraints = PermitConstraints(
        idempotency_key=_idempotency_key(permit_id, record_hash, scope.request_hash)
    )
    permit = ExecutionPermit(
        permit_id=permit_id,
        issuer="velvet",
        tenant_id=tenant_id or action.tenant_id or contract.tenant_id,
        environment=environment or action.environment,
        audience=audience,
        subject=SubjectBinding(
            subject_id_hash=_hash_identifier(subject_id or action.actor_id),
            agent_id_hash=_hash_identifier(action.agent_id),
            client_id_hash=_hash_identifier(client_id),
            session_id_hash=_hash_identifier(session_id),
        ),
        scope=scope,
        policy=policy,
        lineage=PermitLineage(
            decision_artifact=decision_artifact,
            pre_execution_record=ArtifactReference(
                artifact_type=LEDGER_RECORD_ARTIFACT_TYPE,
                artifact_id=str(pre_execution_record.get("record_id") or "pre_execution_record"),
                artifact_hash=record_hash,
            ),
            supporting_artifacts=tuple(supporting),
        ),
        constraints=constraints,
        obligations=(
            "verify_trusted_signature",
            "verify_scope",
            "verify_lineage",
            "claim_before_dispatch",
            "record_execution_receipt",
        ),
        validity=PermitValidity(
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
            issued_at_logical_step=logical_step,
            expires_at_logical_step=logical_step + 1 if logical_step is not None else None,
        ),
    )
    active_signer = signer or load_demo_ed25519_signer()
    signed = permit.with_hash_and_signature(signer=active_signer, key_id=signing_key_id)
    if claim_store is not None:
        claim_store.issue(signed)
    return PreparedExecution(
        permit=signed,
        actual_request=strip_model_controlled_execution_metadata(
            actual_request or action.to_dict()
        ),
        action=action,
    )


def verify_execution_permit(
    permit: ExecutionPermit | Mapping[str, Any],
    context: PermitValidationContext,
) -> list[JsonObject]:
    artifact = permit if isinstance(permit, ExecutionPermit) else ExecutionPermit.from_dict(permit)
    checks: list[JsonObject] = []
    expected_hash = artifact.compute_hash()
    _append_check(
        checks,
        "canonical_hash",
        hmac.compare_digest(artifact.permit_hash, expected_hash),
        "permit_hash_mismatch",
    )
    signature_ok = False
    if context.trusted_public_key is not None or context.trusted_signer is not None:
        signature_ok = verify_signature_record(
            artifact.signature,
            expected_hash,
            purpose=PURPOSE_EXECUTION_PERMIT,
            tenant_id=artifact.tenant_id,
            key_id=context.trusted_key_id,
            signer=context.trusted_signer,
            public_key=context.trusted_public_key,
        )
    _append_check(checks, "trusted_signature", signature_ok, "trusted_signature_invalid")
    _append_check(checks, "tenant", artifact.tenant_id == context.tenant_id, "tenant_mismatch")
    _append_check(
        checks,
        "environment",
        artifact.environment == context.environment,
        "environment_mismatch",
    )
    _append_check(checks, "audience", artifact.audience == context.audience, "audience_mismatch")
    _append_check(
        checks,
        "scope",
        artifact.scope.to_dict() == context.scope.to_dict(),
        "scope_mismatch",
    )
    _append_check(
        checks,
        "policy",
        artifact.policy.to_dict()
        == PermitPolicyBinding(context.policy_hash, context.policy_version).to_dict(),
        "policy_mismatch",
    )
    _append_check(
        checks,
        "tool_schema",
        artifact.scope.to_dict().get("tool_schema_hash")
        == _prefixed_hash(context.tool_schema_hash),
        "tool_schema_mismatch",
    )
    _append_check(
        checks,
        "subject",
        _subject_matches(artifact.subject, context.subject),
        "subject_mismatch",
    )
    temporal_ok, temporal_code = _validity_ok(
        artifact.validity,
        now=context.now,
        logical_step=context.logical_step,
        max_ttl_seconds=context.max_ttl_seconds,
    )
    _append_check(checks, "temporal_validity", temporal_ok, temporal_code)
    _append_check(
        checks,
        "constraints",
        artifact.constraints.single_use
        and artifact.constraints.claim_before_dispatch
        and artifact.constraints.deny_on_scope_drift
        and artifact.constraints.receipt_required,
        "constraints_invalid",
    )
    return checks


def verify_execution_receipt(
    receipt: ExecutionReceipt | Mapping[str, Any],
    *,
    trusted_public_key: str | bytes | object | None = None,
    trusted_signer: SigningProvider | None = None,
    tenant_id: str | None = None,
    permit: ExecutionPermit | None = None,
) -> list[JsonObject]:
    artifact = (
        receipt if isinstance(receipt, ExecutionReceipt) else ExecutionReceipt.from_dict(receipt)
    )
    checks: list[JsonObject] = []
    expected_hash = artifact.compute_hash()
    _append_check(
        checks,
        "canonical_hash",
        hmac.compare_digest(artifact.receipt_hash, expected_hash),
        "receipt_hash_mismatch",
    )
    signature_ok = False
    if trusted_public_key is not None or trusted_signer is not None:
        signature_ok = verify_signature_record(
            artifact.signature,
            expected_hash,
            purpose=PURPOSE_EXECUTION_RECEIPT,
            tenant_id=tenant_id,
            signer=trusted_signer,
            public_key=trusted_public_key,
        )
    _append_check(checks, "trusted_signature", signature_ok, "trusted_signature_invalid")
    if permit is not None:
        _append_check(
            checks,
            "permit_binding",
            artifact.permit_id == permit.permit_id
            and artifact.permit_hash == permit.permit_hash
            and artifact.pre_execution_record_hash
            == permit.lineage.pre_execution_record.artifact_hash,
            "permit_binding_mismatch",
        )
    return checks


class VelvetExecutor:
    """Execute only with verified and atomically claimed execution authority."""

    def __init__(
        self,
        *,
        claim_store: PermitClaimStore | None = None,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
        executor_id: str = "velvet-python-executor",
    ) -> None:
        self.claim_store = claim_store or PermitClaimStore()
        self.signer = signer or load_demo_ed25519_signer()
        self.signing_key_id = signing_key_id or signer_default_key_id(
            self.signer,
            DEMO_ED25519_KEY_ID,
        )
        self.executor_id = executor_id

    def authorize(
        self,
        prepared: PreparedExecution,
        *,
        context: PermitValidationContext,
        claimant: str = "velvet-python-executor",
    ) -> AuthorizedExecution:
        checks = verify_execution_permit(prepared.permit, context)
        failures = [check for check in checks if check["status"] != "pass"]
        if failures:
            first = failures[0]
            raise ExecutionPermitError(str(first["code"]), str(first["name"]))
        claim = self.claim_store.claim(prepared.permit, claimant=claimant)
        if claim is None:
            raise ExecutionPermitError("permit_replay", "execution permit is already claimed")
        return AuthorizedExecution(prepared=prepared, claim=claim)

    def execute(
        self,
        authorized: AuthorizedExecution,
        *,
        handler: Callable[[CanonicalAction], JsonObject] | None = None,
    ) -> ExecutionReceipt:
        permit = authorized.permit
        action = authorized.prepared.action
        started_at = _now_iso()
        dispatch_attempted = False
        outcome: Literal["succeeded", "failed_before_dispatch", "indeterminate"] = (
            "failed_before_dispatch"
        )
        output: JsonObject = {"canonical_action_hash": _prefixed_hash(action.canonical_action_hash)}
        error: ReceiptError | None = None
        response_hash: str | None = None
        try:
            actual_scope = ExecutionPermitScope.from_action(
                action,
                actual_request=authorized.prepared.actual_request,
                method=permit.scope.method,
                tool_key=permit.scope.tool_key,
                arguments_hash=permit.scope.arguments_hash,
                tool_schema_hash=permit.scope.tool_schema_hash,
            )
            if actual_scope.to_dict() != permit.scope.to_dict():
                raise ExecutionPermitError(
                    "scope_mismatch",
                    "actual request no longer matches permit",
                )
            dispatch_attempted = True
            output = stable_json_object(
                handler(action) if handler is not None else {"admitted_by_velvet": True}
            )
            output.setdefault("canonical_action_hash", _prefixed_hash(action.canonical_action_hash))
            response_hash = canonical_hash_sha256(output)
            outcome = "succeeded"
        except ExecutionPermitError as error_value:
            error = ReceiptError(
                error_value.code,
                canonical_hash_sha256({"detail": str(error_value)}),
            )
            outcome = "failed_before_dispatch"
        except Exception as error_value:  # noqa: BLE001 - executor boundary records conservative evidence.
            error = ReceiptError(
                "handler_exception",
                canonical_hash_sha256({"detail": str(error_value)}),
            )
            outcome = "indeterminate" if dispatch_attempted else "failed_before_dispatch"
        completed_at = _now_iso()
        receipt = ExecutionReceipt(
            receipt_id=_receipt_id(permit.permit_id, authorized.claim.claim_hash, completed_at),
            permit_id=permit.permit_id,
            permit_hash=permit.permit_hash,
            dispatch_claim_record_hash=authorized.claim.claim_hash,
            pre_execution_record_hash=permit.lineage.pre_execution_record.artifact_hash,
            request_hash=permit.scope.request_hash,
            canonical_action_hash=permit.scope.canonical_action_hash,
            executor=ReceiptExecutor(executor_id=self.executor_id, audience=permit.audience),
            outcome=outcome,
            dispatch_attempted=dispatch_attempted,
            upstream_response_hash=response_hash,
            error=error,
            started_at=started_at,
            completed_at=completed_at,
            reason=error.code if error is not None else None,
            output=output,
        ).with_hash_and_signature(
            signer=self.signer,
            tenant_id=permit.tenant_id,
            key_id=self.signing_key_id,
        )
        self.claim_store.complete(
            permit,
            outcome=outcome,
            receipt_hash=receipt.receipt_hash,
            completed_at=completed_at,
        )
        return receipt


def verification_status(checks: Sequence[Mapping[str, Any]]) -> str:
    return "pass" if all(check.get("status") == "pass" for check in checks) else "fail"


def _append_check(checks: list[JsonObject], name: str, ok: bool, code: str) -> None:
    checks.append({"name": name, "status": "pass" if ok else "fail", "code": None if ok else code})


def _subject_matches(permit: SubjectBinding, expected: SubjectBinding) -> bool:
    expected_payload = expected.to_dict()
    if not expected_payload:
        return True
    permit_payload = permit.to_dict()
    return all(permit_payload.get(key) == value for key, value in expected_payload.items())


def _validity_ok(
    validity: PermitValidity,
    *,
    now: str | None,
    logical_step: int | None,
    max_ttl_seconds: int,
) -> tuple[bool, str]:
    try:
        issued = _parse_time(validity.issued_at)
        not_before = _parse_time(validity.not_before)
        expires = _parse_time(validity.expires_at)
        current = _parse_time(now or _now_iso())
    except ValueError:
        return False, "validity_malformed"
    if not (issued <= not_before <= expires):
        return False, "validity_interval_malformed"
    if (expires - not_before).total_seconds() > max_ttl_seconds:
        return False, "validity_ttl_excessive"
    if current < not_before:
        return False, "permit_not_yet_valid"
    if current > expires:
        return False, "permit_expired"
    if (
        logical_step is not None
        and validity.expires_at_logical_step is not None
        and logical_step > validity.expires_at_logical_step
    ):
        return False, "permit_logical_step_expired"
    return True, "temporal_validity_failed"


def _permit_id(
    tenant_id: str,
    environment: str,
    scope: ExecutionPermitScope,
    pre_execution_record_hash: str,
    issued_at: str,
) -> str:
    del issued_at
    return "vpermit_" + canonical_hash(
        {
            "tenant_id": tenant_id,
            "environment": environment,
            "scope": scope.to_dict(),
            "pre_execution_record_hash": _prefixed_hash(pre_execution_record_hash),
        }
    )[:32]


def _pre_execution_record_id(envelope: ProofEnvelope, action: CanonicalAction) -> str:
    return "prexec_" + canonical_hash(
        {
            "envelope_id": envelope.envelope_id,
            "canonical_action_hash": action.canonical_action_hash,
        }
    )[:32]


def _claim_id(permit_id: str, permit_hash: str, claimant: str) -> str:
    return "vclaim_" + canonical_hash(
        {"permit_id": permit_id, "permit_hash": permit_hash, "claimant": claimant}
    )[:32]


def _receipt_id(permit_id: str, claim_hash: str, completed_at: str) -> str:
    return "vreceipt_" + canonical_hash(
        {"permit_id": permit_id, "claim_hash": claim_hash, "completed_at": completed_at}
    )[:32]


def _idempotency_key(permit_id: str, record_hash: str, request_hash: str) -> str:
    return "vdispatch_" + canonical_hash(
        {"permit_id": permit_id, "record_hash": record_hash, "request_hash": request_hash}
    )[:32]


def _prefixed_hash(value: object) -> str:
    if isinstance(value, str):
        if value.startswith("sha256:"):
            return value
        if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
            return f"sha256:{value}"
    return canonical_hash_sha256(value)


def _hash_identifier(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return canonical_hash_sha256({"identifier": value})


def _optional_string(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("logical step must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise TypeError("logical step must be an integer")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
