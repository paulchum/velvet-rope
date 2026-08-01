"""Human approval queue bound to exact Velvet requests."""

from __future__ import annotations

import fcntl
import hmac
import json
import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from velvet.rope import AdmissionDecision
from velvet.serialization import canonical_hash_sha256
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_APPROVAL_RECEIPT_V1,
    SigningProvider,
    sign_payload_hash,
    verify_signature_record,
)
from velvet.types import DecisionType

JsonObject = dict[str, Any]

APPROVAL_SCHEMA_VERSION = "velvet.approvals.v2"
APPROVAL_REQUEST_SCHEMA_VERSION = "velvet.approval_request.v1"
APPROVAL_RECEIPT_SCHEMA_VERSION = "velvet.approval_receipt.v1"
DEFAULT_APPROVAL_TTL_MINUTES = 15

_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "cookie",
    "credential",
    "jwt",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session",
    "token",
)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalValidationError(ValueError):
    """Raised when an approval receipt does not match the requested action."""


@dataclass(frozen=True)
class ApprovalRequest:
    schema_version: str
    approval_request_id: str
    tenant_id: str
    environment: str
    subject_id: str | None
    user_id: str | None
    agent_id: str | None
    tool_key: str
    request_hash: str
    arguments_hash: str
    policy_hash: str
    policy_version: str
    tool_schema_hash: str
    reason: str
    created_at: str
    expires_at: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    decision: str = "escalate"
    risk_class: str | None = None
    requester: str = "velvet"
    approver_groups: tuple[str, ...] = ("velvet-concierge",)
    seal_id: str | None = None
    thread_id: str | None = None
    action_type: str | None = None
    original_request: Mapping[str, Any] = field(default_factory=dict)
    redacted_request: Mapping[str, Any] = field(default_factory=dict)
    warrant: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_admission(
        cls,
        decision: AdmissionDecision,
        *,
        original_request: Mapping[str, Any],
        requester: str = "velvet",
        approver_groups: tuple[str, ...] = ("velvet-concierge",),
    ) -> ApprovalRequest:
        selected = decision.selected_warrant
        warrant = selected.to_dict() if selected is not None else {}
        decision_payload = decision.decision.to_dict()
        original = dict(original_request)
        redacted = redact_sensitive_value(original)
        payload = _request_payload(original)
        state = _mapping(original.get("state"))
        metadata = _mapping(original.get("metadata"))
        tenant_id = (
            _mapping_string(warrant, "tenant_id")
            or _mapping_string(metadata, "tenant_id")
            or _mapping_string(state, "tenant_id")
            or LOCAL_DEMO_TENANT_ID
        )
        environment = (
            _mapping_string(warrant, "environment")
            or _mapping_string(metadata, "environment")
            or _mapping_string(state, "environment")
            or "local"
        )
        user_id = (
            _mapping_string(warrant, "actor_user_id")
            or _mapping_string(metadata, "user_id")
            or _mapping_string(metadata, "actor_id")
            or _mapping_string(state, "user_id")
            or _mapping_string(state, "actor_id")
        )
        subject_id = (
            _mapping_string(metadata, "subject_id")
            or _mapping_string(state, "subject_id")
            or _mapping_string(warrant, "subject_id")
            or user_id
        )
        agent_id = (
            _mapping_string(warrant, "agent_id")
            or _mapping_string(original, "agent_id")
            or requester
        )
        tool_key = (
            _mapping_string(warrant, "tool_key")
            or _tool_key_from_request(original)
            or "unknown/unknown"
        )
        policy_version = _mapping_string(warrant, "policy_version") or "unavailable"
        created_at = _now_iso()
        expires_at = (
            _mapping_string(warrant, "expires_at")
            or _mapping_string(metadata, "expires_at")
            or _expires_after(DEFAULT_APPROVAL_TTL_MINUTES)
        )
        request = cls(
            schema_version=APPROVAL_REQUEST_SCHEMA_VERSION,
            approval_request_id="",
            tenant_id=tenant_id,
            environment=environment,
            subject_id=subject_id,
            user_id=user_id,
            agent_id=agent_id,
            tool_key=tool_key,
            request_hash=_mapping_string(warrant, "request_hash") or request_hash(original),
            arguments_hash=_mapping_string(warrant, "arguments_hash")
            or arguments_hash(payload.get("arguments", {})),
            policy_hash=_mapping_string(warrant, "policy_hash")
            or canonical_hash_sha256(
                {
                    "policy_reasons": list(cast(list[Any], warrant.get("policy_reasons", []))),
                    "policy_statuses": list(cast(list[Any], warrant.get("policy_statuses", []))),
                }
            ),
            policy_version=policy_version,
            tool_schema_hash=_mapping_string(warrant, "tool_schema_hash")
            or canonical_hash_sha256({"tool_key": tool_key}),
            reason=str(decision_payload["reason"]),
            created_at=created_at,
            expires_at=expires_at,
            status=ApprovalStatus.PENDING,
            decision=str(decision_payload["decision"]),
            risk_class=_mapping_string(warrant, "risk_class"),
            requester=requester,
            approver_groups=approver_groups,
            seal_id=decision.decision.seal_id,
            thread_id=decision.decision.thread_id,
            action_type=cast(str | None, decision_payload.get("action_type")),
            original_request=original,
            redacted_request=redacted,
            warrant=warrant,
            metadata={
                "request_payload_hash": request_hash(original),
                "requester": requester,
            },
        )
        return replace(request, approval_request_id=_approval_request_id(request))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalRequest:
        return cls(
            schema_version=str(data.get("schema_version", APPROVAL_REQUEST_SCHEMA_VERSION)),
            approval_request_id=str(data["approval_request_id"]),
            tenant_id=str(data.get("tenant_id", LOCAL_DEMO_TENANT_ID)),
            environment=str(data.get("environment", "local")),
            subject_id=cast(str | None, data.get("subject_id")),
            user_id=cast(str | None, data.get("user_id")),
            agent_id=cast(str | None, data.get("agent_id")),
            tool_key=str(data["tool_key"]),
            request_hash=str(data["request_hash"]),
            arguments_hash=str(data["arguments_hash"]),
            policy_hash=str(data["policy_hash"]),
            policy_version=str(data.get("policy_version", "unavailable")),
            tool_schema_hash=str(data["tool_schema_hash"]),
            reason=str(data["reason"]),
            created_at=str(data["created_at"]),
            expires_at=str(data["expires_at"]),
            status=ApprovalStatus(str(data.get("status", ApprovalStatus.PENDING.value))),
            decision=str(data.get("decision", "escalate")),
            risk_class=cast(str | None, data.get("risk_class")),
            requester=str(data.get("requester", "velvet")),
            approver_groups=tuple(str(item) for item in data.get("approver_groups", ())),
            seal_id=cast(str | None, data.get("seal_id")),
            thread_id=cast(str | None, data.get("thread_id")),
            action_type=cast(str | None, data.get("action_type")),
            original_request=dict(cast(Mapping[str, Any], data.get("original_request", {}))),
            redacted_request=dict(cast(Mapping[str, Any], data.get("redacted_request", {}))),
            warrant=dict(cast(Mapping[str, Any], data.get("warrant", {}))),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    def with_status(self, status: ApprovalStatus) -> ApprovalRequest:
        return replace(self, status=status)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return _parse_time(self.expires_at) <= (now or datetime.now(tz=UTC))

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "approval_request_id": self.approval_request_id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "subject_id": self.subject_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "tool_key": self.tool_key,
            "request_hash": self.request_hash,
            "arguments_hash": self.arguments_hash,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "tool_schema_hash": self.tool_schema_hash,
            "reason": self.reason,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "decision": self.decision,
            "risk_class": self.risk_class,
            "requester": self.requester,
            "approver_groups": list(self.approver_groups),
            "seal_id": self.seal_id,
            "thread_id": self.thread_id,
            "action_type": self.action_type,
            "original_request": dict(self.original_request),
            "redacted_request": dict(self.redacted_request),
            "warrant": dict(self.warrant),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ApprovalReceipt:
    schema_version: str
    approval_receipt_id: str
    approval_request_id: str
    tenant_id: str
    environment: str
    subject_id: str | None
    user_id: str | None
    agent_id: str | None
    approver_id: str
    tool_key: str
    request_hash: str
    arguments_hash: str
    policy_hash: str
    policy_version: str
    tool_schema_hash: str
    approved: bool
    decided_at: str
    expires_at: str
    one_time_use: bool
    nonce: str
    reason: str = ""
    conditions: tuple[str, ...] = ()
    used_at: str | None = None
    receipt_hash: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    signature: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.receipt_hash == "":
            object.__setattr__(self, "receipt_hash", self.compute_receipt_hash())

    @classmethod
    def from_request(
        cls,
        request: ApprovalRequest,
        *,
        status: ApprovalStatus,
        approver: str,
        reason: str,
        conditions: tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
        signer: SigningProvider | None = None,
        tenant_id: str | None = None,
        signing_key_id: str = LOCAL_DEMO_KEY_ID,
        one_time_use: bool = True,
    ) -> ApprovalReceipt:
        if status not in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}:
            raise ValueError("approval receipts must be approved or denied")
        decided_at = _now_iso()
        nonce = secrets.token_urlsafe(24)
        receipt = cls(
            schema_version=APPROVAL_RECEIPT_SCHEMA_VERSION,
            approval_receipt_id=_receipt_id(
                {
                    "approval_request_id": request.approval_request_id,
                    "approved": status == ApprovalStatus.APPROVED,
                    "approver_id": approver,
                    "decided_at": decided_at,
                    "nonce": nonce,
                }
            ),
            approval_request_id=request.approval_request_id,
            tenant_id=request.tenant_id,
            environment=request.environment,
            subject_id=request.subject_id,
            user_id=request.user_id,
            agent_id=request.agent_id,
            approver_id=approver,
            tool_key=request.tool_key,
            request_hash=request.request_hash,
            arguments_hash=request.arguments_hash,
            policy_hash=request.policy_hash,
            policy_version=request.policy_version,
            tool_schema_hash=request.tool_schema_hash,
            approved=status == ApprovalStatus.APPROVED,
            decided_at=decided_at,
            expires_at=request.expires_at,
            one_time_use=one_time_use,
            nonce=nonce,
            reason=reason,
            conditions=conditions,
            metadata=dict(metadata or {}),
        )
        return receipt.sign(
            signer=signer,
            tenant_id=tenant_id or request.tenant_id,
            signing_key_id=signing_key_id,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalReceipt:
        return cls(
            schema_version=str(data.get("schema_version", APPROVAL_RECEIPT_SCHEMA_VERSION)),
            approval_receipt_id=str(data["approval_receipt_id"]),
            approval_request_id=str(data["approval_request_id"]),
            tenant_id=str(data.get("tenant_id", LOCAL_DEMO_TENANT_ID)),
            environment=str(data.get("environment", "local")),
            subject_id=cast(str | None, data.get("subject_id")),
            user_id=cast(str | None, data.get("user_id")),
            agent_id=cast(str | None, data.get("agent_id")),
            approver_id=str(data["approver_id"]),
            tool_key=str(data["tool_key"]),
            request_hash=str(data["request_hash"]),
            arguments_hash=str(data["arguments_hash"]),
            policy_hash=str(data["policy_hash"]),
            policy_version=str(data.get("policy_version", "unavailable")),
            tool_schema_hash=str(data["tool_schema_hash"]),
            approved=bool(data["approved"]),
            decided_at=str(data["decided_at"]),
            expires_at=str(data["expires_at"]),
            one_time_use=bool(data.get("one_time_use", True)),
            nonce=str(data["nonce"]),
            reason=str(data.get("reason", "")),
            conditions=tuple(str(item) for item in data.get("conditions", ())),
            used_at=cast(str | None, data.get("used_at")),
            receipt_hash=str(data.get("receipt_hash", "")),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
            signature=dict(cast(Mapping[str, Any], data.get("signature", {})))
            if isinstance(data.get("signature"), Mapping)
            else {},
        )

    @property
    def status(self) -> ApprovalStatus:
        return ApprovalStatus.APPROVED if self.approved else ApprovalStatus.DENIED

    def receipt_hash_payload(self) -> JsonObject:
        payload = self.to_dict()
        payload.pop("receipt_hash", None)
        payload.pop("signature", None)
        return payload

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "approval_receipt_id": self.approval_receipt_id,
            "approval_request_id": self.approval_request_id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "subject_id": self.subject_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "approver_id": self.approver_id,
            "tool_key": self.tool_key,
            "request_hash": self.request_hash,
            "arguments_hash": self.arguments_hash,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "tool_schema_hash": self.tool_schema_hash,
            "approved": self.approved,
            "decided_at": self.decided_at,
            "expires_at": self.expires_at,
            "one_time_use": self.one_time_use,
            "nonce": self.nonce,
            "reason": self.reason,
            "conditions": list(self.conditions),
            "used_at": self.used_at,
            "receipt_hash": self.receipt_hash,
            "metadata": dict(self.metadata),
            "signature": dict(self.signature),
        }

    def compute_receipt_hash(self) -> str:
        return canonical_hash_sha256(self.receipt_hash_payload())

    def sign(
        self,
        *,
        signer: SigningProvider | None = None,
        tenant_id: str | None = None,
        signing_key_id: str = LOCAL_DEMO_KEY_ID,
    ) -> ApprovalReceipt:
        receipt_hash = self.compute_receipt_hash()
        return replace(
            self,
            receipt_hash=receipt_hash,
            signature=sign_payload_hash(
                receipt_hash,
                purpose=PURPOSE_APPROVAL_RECEIPT_V1,
                tenant_id=tenant_id or self.tenant_id,
                key_id=signing_key_id,
                signer=signer,
            ),
        )

    def verify_signature(self, *, signer: SigningProvider | None = None) -> bool:
        if not self.signature:
            return False
        expected_hash = self.compute_receipt_hash()
        if not hmac.compare_digest(self.receipt_hash, expected_hash):
            return False
        return verify_signature_record(
            self.signature,
            expected_hash,
            purpose=PURPOSE_APPROVAL_RECEIPT_V1,
            tenant_id=self.tenant_id,
            signer=signer,
        )


@dataclass(frozen=True)
class ApprovalSnapshot:
    requests: tuple[ApprovalRequest, ...] = ()
    receipts: tuple[ApprovalReceipt, ...] = ()
    schema_version: str = APPROVAL_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalSnapshot:
        return cls(
            requests=tuple(
                ApprovalRequest.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("requests", ())
            ),
            receipts=tuple(
                ApprovalReceipt.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("receipts", ())
            ),
            schema_version=str(data.get("schema_version", APPROVAL_SCHEMA_VERSION)),
        )

    def to_dict(self) -> JsonObject:
        pending_count = sum(
            1 for item in self.requests if item.status == ApprovalStatus.PENDING
        )
        return {
            "schema_version": self.schema_version,
            "summary": {
                "requests": len(self.requests),
                "pending": pending_count,
                "approved": sum(
                    1 for item in self.requests if item.status == ApprovalStatus.APPROVED
                ),
                "denied": sum(1 for item in self.requests if item.status == ApprovalStatus.DENIED),
                "expired": sum(1 for item in self.requests if item.is_expired()),
                "receipts": len(self.receipts),
                "redeemed": sum(1 for item in self.receipts if item.used_at is not None),
            },
            "requests": [request.to_dict() for request in self.requests],
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }


class ApprovalStore:
    """Small local approval database for escalated Velvet actions."""

    def __init__(
        self,
        path: str | Path,
        *,
        signer: SigningProvider | None = None,
        tenant_id: str | None = None,
        signing_key_id: str = LOCAL_DEMO_KEY_ID,
    ) -> None:
        self.path = Path(path)
        self.signer = signer
        self.tenant_id = tenant_id
        self.signing_key_id = signing_key_id
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> ApprovalSnapshot:
        if not self.path.exists():
            return ApprovalSnapshot()
        with self.path.open("r", encoding="utf-8") as handle:
            return ApprovalSnapshot.from_dict(cast(Mapping[str, Any], json.load(handle)))

    def save(self, snapshot: ApprovalSnapshot) -> None:
        self.path.write_text(
            json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        lock_path = self.path.with_name(f"{self.path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def create_request(
        self,
        decision: AdmissionDecision,
        *,
        original_request: Mapping[str, Any],
        requester: str = "velvet",
        approver_groups: tuple[str, ...] = ("velvet-concierge",),
    ) -> ApprovalRequest | None:
        if decision.decision.decision not in {
            DecisionType.ESCALATE,
            DecisionType.ASK_APPROVAL,
        }:
            return None
        request = ApprovalRequest.from_admission(
            decision,
            original_request=original_request,
            requester=requester,
            approver_groups=approver_groups,
        )
        snapshot = self.load()
        existing = {item.approval_request_id: item for item in snapshot.requests}
        if request.approval_request_id in existing:
            return existing[request.approval_request_id]
        self.save(
            ApprovalSnapshot(
                requests=snapshot.requests + (request,),
                receipts=snapshot.receipts,
            )
        )
        return request

    def decide(
        self,
        approval_request_id: str,
        *,
        status: ApprovalStatus,
        approver: str,
        reason: str,
        conditions: tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ApprovalReceipt:
        snapshot = self.load()
        request = _find_request(snapshot, approval_request_id)
        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"approval request is not pending: {approval_request_id}")
        receipt = ApprovalReceipt.from_request(
            request,
            status=status,
            approver=approver,
            reason=reason,
            conditions=conditions,
            metadata=metadata,
            signer=self.signer,
            tenant_id=self.tenant_id,
            signing_key_id=self.signing_key_id,
        )
        requests = tuple(
            item.with_status(status) if item.approval_request_id == approval_request_id else item
            for item in snapshot.requests
        )
        self.save(
            ApprovalSnapshot(
                requests=requests,
                receipts=snapshot.receipts + (receipt,),
            )
        )
        return receipt

    def validate_receipt_for_request(
        self,
        receipt: ApprovalReceipt | str,
        request: ApprovalRequest | str,
        *,
        original_request: Mapping[str, Any] | None = None,
        tenant_id: str | None = None,
        environment: str | None = None,
        subject_id: str | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        tool_key: str | None = None,
        request_hash_value: str | None = None,
        arguments_hash_value: str | None = None,
        policy_hash: str | None = None,
        policy_version: str | None = None,
        tool_schema_hash: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalReceipt:
        snapshot = self.load()
        return self._validate_receipt_for_snapshot(
            snapshot,
            receipt,
            request,
            original_request=original_request,
            tenant_id=tenant_id,
            environment=environment,
            subject_id=subject_id,
            user_id=user_id,
            agent_id=agent_id,
            tool_key=tool_key,
            request_hash_value=request_hash_value,
            arguments_hash_value=arguments_hash_value,
            policy_hash=policy_hash,
            policy_version=policy_version,
            tool_schema_hash=tool_schema_hash,
            now=now,
        )

    def redeem_receipt_for_request(
        self,
        receipt: ApprovalReceipt | str,
        request: ApprovalRequest | str,
        *,
        original_request: Mapping[str, Any] | None = None,
        tenant_id: str | None = None,
        environment: str | None = None,
        subject_id: str | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        tool_key: str | None = None,
        request_hash_value: str | None = None,
        arguments_hash_value: str | None = None,
        policy_hash: str | None = None,
        policy_version: str | None = None,
        tool_schema_hash: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalReceipt:
        with self._exclusive_lock():
            snapshot = self.load()
            approval_receipt = self._validate_receipt_for_snapshot(
                snapshot,
                receipt,
                request,
                original_request=original_request,
                tenant_id=tenant_id,
                environment=environment,
                subject_id=subject_id,
                user_id=user_id,
                agent_id=agent_id,
                tool_key=tool_key,
                request_hash_value=request_hash_value,
                arguments_hash_value=arguments_hash_value,
                policy_hash=policy_hash,
                policy_version=policy_version,
                tool_schema_hash=tool_schema_hash,
                now=now,
            )
            redeemed = replace(
                approval_receipt,
                used_at=_iso_from_datetime(now or datetime.now(tz=UTC)),
                receipt_hash="",
                signature={},
            ).sign(
                signer=self.signer,
                tenant_id=self.tenant_id or approval_receipt.tenant_id,
                signing_key_id=self.signing_key_id,
            )
            receipts = tuple(
                redeemed if item.approval_receipt_id == redeemed.approval_receipt_id else item
                for item in snapshot.receipts
            )
            if all(item.approval_receipt_id != redeemed.approval_receipt_id for item in receipts):
                receipts = receipts + (redeemed,)
            self.save(ApprovalSnapshot(requests=snapshot.requests, receipts=receipts))
            return redeemed

    def _validate_receipt_for_snapshot(
        self,
        snapshot: ApprovalSnapshot,
        receipt: ApprovalReceipt | str,
        request: ApprovalRequest | str,
        *,
        original_request: Mapping[str, Any] | None = None,
        tenant_id: str | None = None,
        environment: str | None = None,
        subject_id: str | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        tool_key: str | None = None,
        request_hash_value: str | None = None,
        arguments_hash_value: str | None = None,
        policy_hash: str | None = None,
        policy_version: str | None = None,
        tool_schema_hash: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalReceipt:
        approval_request = _coerce_request(snapshot, request)
        approval_receipt = _coerce_receipt(snapshot, receipt)
        stored_receipt = _maybe_find_receipt(snapshot, approval_receipt.approval_receipt_id)
        if stored_receipt is not None:
            approval_receipt = stored_receipt
        expected = _expected_binding(
            approval_request,
            original_request=original_request,
            tenant_id=tenant_id,
            environment=environment,
            subject_id=subject_id,
            user_id=user_id,
            agent_id=agent_id,
            tool_key=tool_key,
            request_hash_value=request_hash_value,
            arguments_hash_value=arguments_hash_value,
            policy_hash=policy_hash,
            policy_version=policy_version,
            tool_schema_hash=tool_schema_hash,
        )
        _validate_receipt(approval_receipt, expected, signer=self.signer, now=now)
        return approval_receipt

    def pending(self) -> tuple[ApprovalRequest, ...]:
        return tuple(
            request
            for request in self.load().requests
            if request.status == ApprovalStatus.PENDING
        )


def load_approval_snapshot(path: str | Path | None) -> ApprovalSnapshot:
    if path is None or not Path(path).exists():
        return ApprovalSnapshot()
    return ApprovalStore(path).load()


def request_hash(request: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(redact_sensitive_value(request))


def arguments_hash(arguments: Any) -> str:
    return canonical_hash_sha256(redact_sensitive_value(arguments))


def redact_sensitive_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: JsonObject = {}
        for key, child in sorted(value.items()):
            key_string = str(key)
            if _is_sensitive_key(key_string):
                redacted[key_string] = "[REDACTED]"
            else:
                redacted[key_string] = redact_sensitive_value(child)
        return redacted
    if isinstance(value, tuple):
        return [redact_sensitive_value(item) for item in value]
    if isinstance(value, list):
        return [redact_sensitive_value(item) for item in value]
    return value


def approval_receipt_findings(
    snapshot: ApprovalSnapshot,
    *,
    signer: SigningProvider | None = None,
    now: datetime | None = None,
) -> tuple[JsonObject, ...]:
    findings: list[JsonObject] = []
    request_by_id = {request.approval_request_id: request for request in snapshot.requests}
    seen: set[str] = set()
    for receipt in snapshot.receipts:
        if receipt.approval_receipt_id in seen:
            findings.append(
                {
                    "finding_id": "approval.receipt_duplicate",
                    "approval_receipt_id": receipt.approval_receipt_id,
                    "severity": "high",
                    "message": "Approval receipt id appears more than once.",
                }
            )
        seen.add(receipt.approval_receipt_id)
        request = request_by_id.get(receipt.approval_request_id)
        if request is None:
            findings.append(
                {
                    "finding_id": "approval.receipt_orphaned",
                    "approval_receipt_id": receipt.approval_receipt_id,
                    "severity": "medium",
                    "message": "Approval receipt has no matching request.",
                }
            )
            continue
        try:
            _validate_receipt(
                receipt,
                _expected_binding(request),
                signer=signer,
                now=now,
                require_approved=False,
                require_unused=False,
            )
        except ApprovalValidationError as error:
            findings.append(
                {
                    "finding_id": _finding_id_for_validation_error(str(error)),
                    "approval_receipt_id": receipt.approval_receipt_id,
                    "approval_request_id": receipt.approval_request_id,
                    "severity": "high",
                    "message": str(error),
                }
            )
    return tuple(findings)


def _validate_receipt(
    receipt: ApprovalReceipt,
    expected: Mapping[str, Any],
    *,
    signer: SigningProvider | None,
    now: datetime | None = None,
    require_approved: bool = True,
    require_unused: bool = True,
) -> None:
    if receipt.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION:
        raise ApprovalValidationError("approval receipt schema is unsupported")
    if not receipt.verify_signature(signer=signer):
        raise ApprovalValidationError("approval receipt signature is invalid")
    if require_approved and not receipt.approved:
        raise ApprovalValidationError("approval receipt is not approved")
    if require_unused and receipt.one_time_use and receipt.used_at is not None:
        raise ApprovalValidationError("approval receipt has already been used")
    if _parse_time(receipt.expires_at) <= (now or datetime.now(tz=UTC)):
        raise ApprovalValidationError("approval receipt is expired")
    _require_equal("approval_request_id", receipt.approval_request_id, expected)
    _require_equal("tenant_id", receipt.tenant_id, expected)
    _require_equal("environment", receipt.environment, expected)
    _require_equal("subject_id", receipt.subject_id, expected)
    _require_equal("user_id", receipt.user_id, expected)
    _require_equal("agent_id", receipt.agent_id, expected)
    _require_equal("tool_key", receipt.tool_key, expected)
    _require_equal("request_hash", receipt.request_hash, expected)
    _require_equal("arguments_hash", receipt.arguments_hash, expected)
    _require_equal("policy_hash", receipt.policy_hash, expected)
    _require_equal("policy_version", receipt.policy_version, expected)
    _require_equal("tool_schema_hash", receipt.tool_schema_hash, expected)


def _expected_binding(
    request: ApprovalRequest,
    *,
    original_request: Mapping[str, Any] | None = None,
    tenant_id: str | None = None,
    environment: str | None = None,
    subject_id: str | None = None,
    user_id: str | None = None,
    agent_id: str | None = None,
    tool_key: str | None = None,
    request_hash_value: str | None = None,
    arguments_hash_value: str | None = None,
    policy_hash: str | None = None,
    policy_version: str | None = None,
    tool_schema_hash: str | None = None,
) -> JsonObject:
    payload = _request_payload(original_request) if original_request is not None else {}
    return {
        "approval_request_id": request.approval_request_id,
        "tenant_id": tenant_id or request.tenant_id,
        "environment": environment or request.environment,
        "subject_id": subject_id if subject_id is not None else request.subject_id,
        "user_id": user_id if user_id is not None else request.user_id,
        "agent_id": agent_id if agent_id is not None else request.agent_id,
        "tool_key": tool_key or request.tool_key,
        "request_hash": request_hash_value
        or (
            request_hash(original_request)
            if original_request is not None
            else request.request_hash
        ),
        "arguments_hash": arguments_hash_value
        or (
            arguments_hash(payload.get("arguments", {}))
            if original_request is not None
            else request.arguments_hash
        ),
        "policy_hash": policy_hash or request.policy_hash,
        "policy_version": policy_version or request.policy_version,
        "tool_schema_hash": tool_schema_hash or request.tool_schema_hash,
    }


def _require_equal(key: str, actual: Any, expected: Mapping[str, Any]) -> None:
    expected_value = expected.get(key)
    if actual != expected_value:
        raise ApprovalValidationError(f"approval receipt {key} does not match")


def _coerce_request(snapshot: ApprovalSnapshot, request: ApprovalRequest | str) -> ApprovalRequest:
    if isinstance(request, ApprovalRequest):
        return request
    return _find_request(snapshot, request)


def _coerce_receipt(snapshot: ApprovalSnapshot, receipt: ApprovalReceipt | str) -> ApprovalReceipt:
    if isinstance(receipt, ApprovalReceipt):
        return receipt
    found = _maybe_find_receipt(snapshot, receipt)
    if found is None:
        raise KeyError(f"unknown approval receipt: {receipt}")
    return found


def _find_request(snapshot: ApprovalSnapshot, approval_request_id: str) -> ApprovalRequest:
    request = next(
        (
            item
            for item in snapshot.requests
            if item.approval_request_id == approval_request_id
        ),
        None,
    )
    if request is None:
        raise KeyError(f"unknown approval request: {approval_request_id}")
    return request


def _maybe_find_receipt(
    snapshot: ApprovalSnapshot,
    approval_receipt_id: str,
) -> ApprovalReceipt | None:
    return next(
        (
            item
            for item in snapshot.receipts
            if item.approval_receipt_id == approval_receipt_id
        ),
        None,
    )


def _approval_request_id(request: ApprovalRequest) -> str:
    return "apr_" + canonical_hash_sha256(
        {
            "tenant_id": request.tenant_id,
            "environment": request.environment,
            "subject_id": request.subject_id,
            "tool_key": request.tool_key,
            "request_hash": request.request_hash,
            "policy_hash": request.policy_hash,
            "policy_version": request.policy_version,
            "tool_schema_hash": request.tool_schema_hash,
        }
    ).removeprefix("sha256:")[:32]


def _receipt_id(payload: Mapping[str, Any]) -> str:
    return "aprct_" + canonical_hash_sha256(payload).removeprefix("sha256:")[:32]


def _request_payload(request: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if request is None:
        return {}
    payload = request.get("payload")
    return _mapping(payload)


def _tool_key_from_request(request: Mapping[str, Any]) -> str | None:
    payload = _request_payload(request)
    server = _mapping_string(payload, "server") or _mapping_string(request, "mcp_server")
    tool = _mapping_string(payload, "tool") or _mapping_string(request, "mcp_tool")
    if server and tool:
        return f"{server}/{tool}"
    return _mapping_string(request, "tool_key")


def _mapping(value: object) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


def _mapping_string(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _parse_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _expires_after(minutes: int) -> str:
    return _iso_from_datetime(datetime.now(tz=UTC) + timedelta(minutes=minutes))


def _now_iso() -> str:
    return _iso_from_datetime(datetime.now(tz=UTC))


def _iso_from_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _finding_id_for_validation_error(message: str) -> str:
    if "already been used" in message:
        return "approval.receipt_reused"
    if "expired" in message:
        return "approval.receipt_expired"
    if "signature" in message or "hash" in message:
        return "approval.receipt_invalid"
    if "not approved" in message:
        return "approval.receipt_denied"
    return "approval.receipt_binding_mismatch"
