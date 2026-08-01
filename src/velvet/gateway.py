"""Canonical inline action gateway.

Proposed actions are normalized first, admitted second, persisted as
pre-execution evidence, and dispatched only after an Execution Permit is
verified and claimed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

from velvet.actions import CanonicalAction, MaskedActionFailure, ProofDecision
from velvet.admission_evidence import build_admission_evidence
from velvet.approvals import (
    APPROVAL_REQUEST_SCHEMA_VERSION,
    ApprovalReceipt,
    ApprovalRequest,
    ApprovalSnapshot,
    ApprovalStatus,
    ApprovalStore,
    ApprovalValidationError,
    redact_sensitive_value,
)
from velvet.contracts import AdmissionContract
from velvet.execution import (
    ExecutionPermitError,
    ExecutionReceipt,
    PermitClaimStore,
    PermitValidationContext,
    SubjectBinding,
    VelvetExecutor,
    build_pre_execution_record,
    prepare_execution,
)
from velvet.executor import AdmissionOutcome, VelvetAdmissionLayer
from velvet.serialization import (
    JsonObject,
    canonical_hash,
    canonical_hash_sha256,
    stable_json_object,
)
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    SigningProvider,
    load_demo_ed25519_signer,
    signer_default_key_id,
)


class InlineDispatcher(Protocol):
    def dispatch(
        self,
        action: CanonicalAction,
        *,
        context: Mapping[str, Any],
    ) -> InlineDispatchReceipt: ...


@dataclass(frozen=True)
class InlineGatewayRequest:
    proposed_action: Mapping[str, Any]
    context: Mapping[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    replay_id: str = "inline_gateway"
    logical_step: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InlineGatewayRequest:
        proposed = data.get("proposed_action")
        if not isinstance(proposed, Mapping):
            raise ValueError("InlineGatewayRequest requires proposed_action object")
        context = data.get("context")
        if context is not None and not isinstance(context, Mapping):
            raise ValueError("InlineGatewayRequest context must be an object")
        return cls(
            proposed_action=dict(proposed),
            context=dict(cast(Mapping[str, Any], context or {})),
            request_id=cast(str | None, data.get("request_id")),
            replay_id=str(data.get("replay_id", "inline_gateway")),
            logical_step=int(data.get("logical_step", 1)),
        )

    @property
    def stable_request_id(self) -> str:
        if self.request_id:
            return self.request_id
        digest = hashlib.blake2b(
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8"),
            digest_size=8,
        ).hexdigest()
        return f"igw_{digest}"

    def to_dict(self) -> JsonObject:
        return {
            "request_id": self.request_id,
            "stable_request_id": self.stable_request_id if self.request_id else None,
            "replay_id": self.replay_id,
            "logical_step": self.logical_step,
            "proposed_action": stable_json_object(self.proposed_action),
            "context": stable_json_object(self.context),
        }


@dataclass(frozen=True)
class InlineGatewayDecision:
    request: InlineGatewayRequest
    admission_outcome: AdmissionOutcome
    approval_request: Mapping[str, Any] | None = None
    admission_evidence: Mapping[str, Any] | None = None
    ledger_record: Mapping[str, Any] | None = None

    @property
    def canonical_action(self) -> CanonicalAction:
        return self.admission_outcome.canonical_action

    @property
    def decision(self) -> ProofDecision:
        return self.admission_outcome.decision

    def to_dict(self) -> JsonObject:
        return {
            "gateway": "velvet_inline_gateway",
            "boundary": "pre_execution_authorization",
            "request": self.request.to_dict(),
            "canonical_action_hash": self.canonical_action.canonical_action_hash,
            "canonical_action": self.canonical_action.to_dict(),
            "decision": self.decision.value,
            "admission_outcome": self.admission_outcome.to_dict(),
            "approval_request": dict(self.approval_request)
            if self.approval_request is not None
            else None,
            "admission_evidence_hash": self.admission_evidence.get("admission_evidence_hash")
            if self.admission_evidence is not None
            else None,
            "admission_evidence_ref": _admission_evidence_ref(self.admission_evidence),
            "admission_evidence": dict(self.admission_evidence)
            if self.admission_evidence is not None
            else None,
            "ledger_record": dict(self.ledger_record) if self.ledger_record is not None else None,
        }


@dataclass(frozen=True)
class InlineDispatchReceipt:
    status: str
    provider: str
    output: Mapping[str, Any] | None = None
    reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "status": self.status,
            "provider": self.provider,
            "output": stable_json_object(self.output or {}),
            "reason": self.reason,
            "metadata": stable_json_object(self.metadata),
        }


@dataclass(frozen=True)
class InlineGatewayResult:
    decision: InlineGatewayDecision
    execution_receipt: ExecutionReceipt

    def to_dict(self) -> JsonObject:
        return {
            "gateway": "velvet_inline_gateway",
            "decision": self.decision.to_dict(),
            "execution_receipt": self.execution_receipt.to_dict(),
        }


class CallableDispatcher:
    def __init__(
        self,
        provider: str,
        handler: Callable[[CanonicalAction, Mapping[str, Any]], Mapping[str, Any]],
    ) -> None:
        self.provider = provider
        self.handler = handler

    def dispatch(
        self,
        action: CanonicalAction,
        *,
        context: Mapping[str, Any],
    ) -> InlineDispatchReceipt:
        return InlineDispatchReceipt(
            status="dispatched",
            provider=self.provider,
            output=self.handler(action, context),
            metadata={"canonical_action_hash": action.canonical_action_hash},
        )


class InlineGateway:
    """Normalize, admit, and dispatch canonical actions inline."""

    def __init__(
        self,
        *,
        contract: AdmissionContract | None = None,
        admission_layer: VelvetAdmissionLayer | None = None,
        dispatchers: Mapping[str, InlineDispatcher] | None = None,
        ledger_path: str | Path | None = None,
        approval_store: ApprovalStore | None = None,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
    ) -> None:
        self.admission_layer = admission_layer or VelvetAdmissionLayer(contract)
        self.dispatchers: MutableMapping[str, InlineDispatcher] = dict(dispatchers or {})
        self.ledger_path = Path(ledger_path) if ledger_path is not None else None
        self.approval_store = approval_store
        self.signer = signer
        self.signing_key_id = signing_key_id or (
            signer_default_key_id(signer) if signer is not None else LOCAL_DEMO_KEY_ID
        )
        self.permit_claim_store = PermitClaimStore(
            self.ledger_path.with_suffix(".permits.sqlite") if self.ledger_path else None
        )
        if self.ledger_path is not None:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def register_dispatcher(self, surface: str, dispatcher: InlineDispatcher) -> None:
        self.dispatchers[_surface_key(surface)] = dispatcher

    def authorize(
        self,
        request: InlineGatewayRequest | Mapping[str, Any],
    ) -> InlineGatewayDecision:
        gateway_request = _coerce_request(request)
        context = dict(gateway_request.context)
        context.setdefault("gateway_request_id", gateway_request.stable_request_id)
        outcome = self.admission_layer.evaluate(
            gateway_request.proposed_action,
            world_state=context,
            logical_step=gateway_request.logical_step,
            replay_id=gateway_request.replay_id,
        )
        approval_request = self._create_inline_approval_request(gateway_request, outcome)
        ledger_record = self._write_inline_ledger(
            gateway_request,
            outcome,
            phase="pre_execution",
            approval_request=approval_request,
        )
        admission_evidence = (
            ledger_record.get("admission_evidence")
            if isinstance(ledger_record, Mapping)
            else None
        )
        return InlineGatewayDecision(
            request=gateway_request,
            admission_outcome=outcome,
            approval_request=approval_request,
            admission_evidence=admission_evidence
            if isinstance(admission_evidence, Mapping)
            else None,
            ledger_record=ledger_record,
        )

    def run(
        self,
        request: InlineGatewayRequest | Mapping[str, Any],
    ) -> InlineGatewayResult:
        decision = self.authorize(request)
        execution_receipt = self.dispatch_admitted(decision)
        self._write_execution_observation(decision, execution_receipt)
        return InlineGatewayResult(decision=decision, execution_receipt=execution_receipt)

    def run_approved(
        self,
        decision: InlineGatewayDecision,
        approval_receipt: ApprovalReceipt | Mapping[str, Any] | str,
        *,
        proposed_action: Mapping[str, Any] | None = None,
    ) -> InlineGatewayResult:
        execution_receipt = self.dispatch_approved(
            decision,
            approval_receipt,
            proposed_action=proposed_action,
        )
        self._write_execution_observation(decision, execution_receipt)
        return InlineGatewayResult(decision=decision, execution_receipt=execution_receipt)

    def dispatch_admitted(self, decision: InlineGatewayDecision) -> ExecutionReceipt:
        outcome = decision.admission_outcome
        action = outcome.canonical_action
        if outcome.decision is not ProofDecision.ADMITTED:
            return ExecutionReceipt.rejected(
                permit=None,
                action=action,
                reason=f"admission decision was {outcome.decision.value}",
            )
        dispatcher = self.dispatchers.get(_surface_key(action.surface))
        if dispatcher is None:
            return ExecutionReceipt.rejected(
                permit=None,
                action=action,
                reason=f"no dispatcher registered for surface {action.surface}",
            )

        def handler(admitted_action: CanonicalAction) -> JsonObject:
            receipt = dispatcher.dispatch(
                admitted_action,
                context=decision.request.context,
            )
            return receipt.to_dict()

        try:
            prepared = self._prepare_inline_execution(decision)
            signer = self.signer or load_demo_ed25519_signer()
            context = _permit_validation_context(
                prepared.permit,
                action=action,
                contract=self.admission_layer.contract,
                signer=signer,
            )
            executor = VelvetExecutor(
                claim_store=self.permit_claim_store,
                signer=signer,
                signing_key_id=self.signing_key_id,
                executor_id="velvet-inline-gateway",
            )
            authorized = executor.authorize(prepared, context=context, claimant="inline_gateway")
            return executor.execute(authorized, handler=handler)
        except ExecutionPermitError as error:
            return ExecutionReceipt.rejected(
                permit=None,
                action=action,
                reason=f"{error.code}: {error}",
            )

    def dispatch_approved(
        self,
        decision: InlineGatewayDecision,
        approval_receipt: ApprovalReceipt | Mapping[str, Any] | str,
        *,
        proposed_action: Mapping[str, Any] | None = None,
    ) -> ExecutionReceipt:
        if decision.decision is not ProofDecision.ESCALATED:
            return _approval_reappraise_receipt(
                decision,
                "approval dispatch requires an escalated pre-execution decision",
            )
        if self.approval_store is None:
            return _approval_reappraise_receipt(decision, "approval store is not configured")
        if decision.approval_request is None:
            return _approval_reappraise_receipt(decision, "approval request is missing")

        approval_request = ApprovalRequest.from_dict(decision.approval_request)
        current_request = _current_dispatch_request(decision, proposed_action)
        try:
            current_action = self.admission_layer.normalizer.normalize(
                current_request.proposed_action,
                self.admission_layer.contract,
                ledger=None,
            )
        except MaskedActionFailure as error:
            return _approval_reappraise_receipt(
                decision,
                f"current action is not canonicalizable: {error}",
            )

        if current_action.canonical_action_hash != decision.canonical_action.canonical_action_hash:
            return _approval_reappraise_receipt(
                decision,
                "approval canonical action hash mismatch",
                current_action=current_action,
            )
        bound_hash = approval_request.warrant.get("canonical_action_hash")
        if bound_hash != current_action.canonical_action_hash:
            return _approval_reappraise_receipt(
                decision,
                "approval warrant canonical action hash mismatch",
                current_action=current_action,
            )

        request_hash = canonical_hash_sha256(current_request.to_dict())
        arguments_hash = _inline_arguments_hash(current_action, current_request)
        policy_hash = canonical_hash_sha256(self.admission_layer.contract.to_dict())
        tool_schema_hash = _inline_tool_schema_hash(current_action)
        try:
            redeemed_receipt = self.approval_store.redeem_receipt_for_request(
                _coerce_approval_receipt(approval_receipt).approval_receipt_id
                if not isinstance(approval_receipt, str)
                else approval_receipt,
                approval_request.approval_request_id,
                tenant_id=current_action.tenant_id or self.admission_layer.contract.tenant_id,
                environment=current_action.environment,
                subject_id=cast(str | None, current_request.context.get("user_id")),
                user_id=cast(str | None, current_request.context.get("user_id")),
                agent_id=current_action.agent_id,
                tool_key=current_action.tool_name,
                request_hash_value=request_hash,
                arguments_hash_value=arguments_hash,
                policy_hash=policy_hash,
                policy_version=self.admission_layer.contract.policy_version,
                tool_schema_hash=tool_schema_hash,
            )
        except (ApprovalValidationError, KeyError, ValueError) as error:
            return _approval_reappraise_receipt(
                decision,
                f"approval receipt binding mismatch: {error}",
                current_action=current_action,
            )

        dispatcher = self.dispatchers.get(_surface_key(current_action.surface))
        if dispatcher is None:
            return ExecutionReceipt.rejected(
                permit=None,
                action=current_action,
                reason=f"no dispatcher registered for surface {current_action.surface}",
            )

        def handler(admitted_action: CanonicalAction) -> JsonObject:
            receipt = dispatcher.dispatch(admitted_action, context=current_request.context)
            output = receipt.to_dict()
            output["approval_receipt_id"] = redeemed_receipt.approval_receipt_id
            output["approval_request_id"] = approval_request.approval_request_id
            output["approval_status"] = "approved"
            output["canonical_action_hash"] = _ensure_sha256(admitted_action.canonical_action_hash)
            return output

        try:
            prepared = self._prepare_inline_execution(
                replace(decision, request=current_request),
                approval_receipt_hash=redeemed_receipt.receipt_hash,
            )
            signer = self.signer or load_demo_ed25519_signer()
            context = _permit_validation_context(
                prepared.permit,
                action=current_action,
                contract=self.admission_layer.contract,
                signer=signer,
            )
            executor = VelvetExecutor(
                claim_store=self.permit_claim_store,
                signer=signer,
                signing_key_id=self.signing_key_id,
                executor_id="velvet-inline-gateway",
            )
            authorized = executor.authorize(
                prepared,
                context=context,
                claimant=f"inline_gateway:{redeemed_receipt.approval_receipt_id}",
            )
            return executor.execute(authorized, handler=handler)
        except ExecutionPermitError as error:
            return ExecutionReceipt.rejected(
                permit=None,
                action=current_action,
                reason=f"{error.code}: {error}",
            )

    def _prepare_inline_execution(
        self,
        decision: InlineGatewayDecision,
        *,
        approval_receipt_hash: str | None = None,
    ) -> Any:
        record = decision.ledger_record
        if not isinstance(record, Mapping):
            record = build_pre_execution_record(
                decision.admission_outcome,
                request=decision.request.to_dict(),
                tenant_id=decision.canonical_action.tenant_id,
                environment=decision.canonical_action.environment,
            )
        record_hash = record.get("inline_record_hash") or record.get("artifact_hash")
        if not isinstance(record_hash, str) or not record_hash:
            raise ExecutionPermitError(
                "pre_execution_record_missing",
                "inline pre-execution record hash is missing",
            )
        action = decision.canonical_action
        selected = _inline_selected_warrant(
            decision.admission_outcome,
            request=decision.request,
            contract=self.admission_layer.contract,
        )
        pre_execution_record: JsonObject = {
            "artifact_type": "ledger_record",
            "record_id": str(record.get("request_id") or decision.request.stable_request_id),
            "artifact_hash": record_hash,
            "decision": decision.decision.value,
            "canonical_action_hash": _ensure_sha256(action.canonical_action_hash),
            "request_hash": str(selected["request_hash"]),
            "arguments_hash": str(selected["arguments_hash"]),
            "policy_hash": str(selected["policy_hash"]),
            "policy_version": str(selected["policy_version"]),
            "tool_schema_hash": str(selected["tool_schema_hash"]),
        }
        return prepare_execution(
            decision.admission_outcome,
            actual_request=decision.request.to_dict(),
            pre_execution_record=pre_execution_record,
            contract=self.admission_layer.contract,
            tenant_id=str(selected["tenant_id"]),
            environment=str(selected["environment"]),
            audience="velvet.inline_gateway",
            product_surface="velvet_inline_gateway",
            method=str(selected["action_type"]),
            tool_key=str(selected["tool_key"]),
            tool_schema_hash=str(selected["tool_schema_hash"]),
            policy_hash=str(selected["policy_hash"]),
            policy_version=str(selected["policy_version"]),
            subject_id=cast(str | None, decision.request.context.get("user_id")),
            session_id=cast(str | None, decision.request.context.get("session_id")),
            approval_receipt_hash=approval_receipt_hash,
            issued_at=_now_iso(),
            lifetime_seconds=self.admission_layer.contract.execution_permit_ttl_seconds,
            logical_step=decision.request.logical_step,
            signer=self.signer or load_demo_ed25519_signer(),
            signing_key_id=self.signing_key_id,
            claim_store=self.permit_claim_store,
        )

    def _write_inline_ledger(
        self,
        request: InlineGatewayRequest,
        outcome: AdmissionOutcome,
        *,
        phase: str,
        approval_request: Mapping[str, Any] | None = None,
    ) -> JsonObject | None:
        if self.ledger_path is None:
            return None
        sequence_number, previous_record_hash = _inline_sequence_state(self.ledger_path)
        record: JsonObject = {
            "schema_version": "velvet.inline_gateway.ledger_record.v1",
            "phase": phase,
            "sequence_number": sequence_number,
            "previous_record_hash": previous_record_hash,
            "request_id": request.stable_request_id,
            "decision": outcome.decision.value,
            "canonical_action_hash": outcome.canonical_action.canonical_action_hash,
            "canonical_action": outcome.canonical_action.to_dict(),
            "admission_outcome_hash": canonical_hash(outcome.to_dict()),
            "upstream_execution_status": _pre_execution_status(outcome.decision),
        }
        evidence_decision_payload = {
            "product_surface": "velvet_inline_gateway",
            "seal_id": outcome.envelope.envelope_id,
            "thread_id": request.replay_id,
            "decision": {
                "decision": _public_decision(outcome.decision),
                "reason": _inline_reason(outcome),
                "action_type": outcome.canonical_action.canonical_type,
            },
            "selected_warrant": _inline_selected_warrant(
                outcome,
                request=request,
                contract=self.admission_layer.contract,
            ),
        }
        admission_evidence = build_admission_evidence(
            request=request.to_dict(),
            admission_decision=evidence_decision_payload,
            sequence_number=sequence_number,
            previous_record_hash=previous_record_hash,
            previous_frame_hash=None,
            ledger_path=self.ledger_path,
            approval_request=approval_request,
            signer=self.signer,
            signing_key_id=self.signing_key_id,
            tenant_id=self.admission_layer.contract.tenant_id,
            environment=str(request.proposed_action.get("environment") or "local"),
        )
        record["approval_request"] = dict(approval_request) if approval_request else None
        record["admission_evidence_hash"] = admission_evidence["admission_evidence_hash"]
        record["admission_evidence_ref"] = _admission_evidence_ref(admission_evidence)
        record["admission_evidence"] = admission_evidence
        record["inline_record_hash"] = _inline_record_hash(record)
        self._append_inline_record(record)
        return record

    def _create_inline_approval_request(
        self,
        request: InlineGatewayRequest,
        outcome: AdmissionOutcome,
    ) -> JsonObject | None:
        if self.approval_store is None or outcome.decision is not ProofDecision.ESCALATED:
            return None
        selected = _inline_selected_warrant(
            outcome,
            request=request,
            contract=self.admission_layer.contract,
        )
        created_at = _now_iso()
        expires_at = _expires_after_minutes(15)
        payload: JsonObject = {
            "schema_version": APPROVAL_REQUEST_SCHEMA_VERSION,
            "approval_request_id": "",
            "tenant_id": str(selected.get("tenant_id") or self.admission_layer.contract.tenant_id),
            "environment": str(selected.get("environment") or "local"),
            "subject_id": str(request.context.get("user_id"))
            if request.context.get("user_id")
            else None,
            "user_id": str(request.context.get("user_id"))
            if request.context.get("user_id")
            else None,
            "agent_id": str(request.proposed_action.get("agent_id"))
            if request.proposed_action.get("agent_id")
            else None,
            "tool_key": str(selected["tool_key"]),
            "request_hash": str(selected["request_hash"]),
            "arguments_hash": str(selected["arguments_hash"]),
            "policy_hash": str(selected["policy_hash"]),
            "policy_version": str(selected["policy_version"]),
            "tool_schema_hash": str(selected["tool_schema_hash"]),
            "reason": _inline_reason(outcome),
            "created_at": created_at,
            "expires_at": expires_at,
            "status": ApprovalStatus.PENDING.value,
            "decision": "escalate",
            "risk_class": str(selected.get("risk_class") or "unknown"),
            "requester": "velvet_inline_gateway",
            "approver_groups": ["velvet-concierge"],
            "seal_id": outcome.envelope.envelope_id,
            "thread_id": request.replay_id,
            "action_type": outcome.canonical_action.canonical_type,
            "original_request": request.to_dict(),
            "redacted_request": redact_sensitive_value(request.to_dict()),
            "warrant": selected,
            "metadata": {"requester": "velvet_inline_gateway"},
        }
        payload["approval_request_id"] = _inline_approval_request_id(payload)
        approval_request = ApprovalRequest.from_dict(payload)
        snapshot = self.approval_store.load()
        existing = {item.approval_request_id: item for item in snapshot.requests}
        if approval_request.approval_request_id in existing:
            return existing[approval_request.approval_request_id].to_dict()
        self.approval_store.save(
            ApprovalSnapshot(
                requests=snapshot.requests + (approval_request,),
                receipts=snapshot.receipts,
            )
        )
        return approval_request.to_dict()

    def _write_execution_observation(
        self,
        decision: InlineGatewayDecision,
        execution_receipt: ExecutionReceipt,
    ) -> None:
        if self.ledger_path is None:
            return
        sequence_number, previous_record_hash = _inline_sequence_state(self.ledger_path)
        record: JsonObject = {
            "schema_version": "velvet.inline_gateway.ledger_record.v1",
            "phase": "post_execution",
            "sequence_number": sequence_number,
            "previous_record_hash": previous_record_hash,
            "request_id": decision.request.stable_request_id,
            "decision": decision.decision.value,
            "canonical_action_hash": decision.canonical_action.canonical_action_hash,
            "execution_receipt": execution_receipt.to_dict(),
            "upstream_execution_status": _upstream_status(execution_receipt),
        }
        record["inline_record_hash"] = _inline_record_hash(record)
        self._append_inline_record(record)

    def _append_inline_record(self, record: Mapping[str, Any]) -> None:
        if self.ledger_path is None:
            return
        payload = stable_json_object(record)
        if not self.ledger_path.exists():
            self.ledger_path.write_text("", encoding="utf-8")
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _coerce_request(request: InlineGatewayRequest | Mapping[str, Any]) -> InlineGatewayRequest:
    if isinstance(request, InlineGatewayRequest):
        return request
    return InlineGatewayRequest.from_dict(request)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _expires_after_minutes(minutes: int) -> str:
    return (datetime.now(tz=UTC) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def _inline_sequence_state(ledger_path: Path) -> tuple[int, str]:
    if not ledger_path.exists():
        return 1, f"sha256:{'0' * 64}"
    records = [
        json.loads(line)
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not records:
        return 1, f"sha256:{'0' * 64}"
    previous = records[-1]
    previous_hash = previous.get("inline_record_hash")
    if not isinstance(previous_hash, str):
        previous_hash = _inline_record_hash(cast(Mapping[str, Any], previous))
    return len(records) + 1, previous_hash


def _inline_record_hash(record: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(
        {str(key): value for key, value in record.items() if key != "inline_record_hash"}
    )


def _permit_validation_context(
    permit: Any,
    *,
    action: CanonicalAction,
    contract: AdmissionContract,
    signer: SigningProvider,
) -> PermitValidationContext:
    return PermitValidationContext(
        tenant_id=permit.tenant_id,
        environment=permit.environment,
        audience=permit.audience,
        policy_hash=permit.policy.policy_hash,
        policy_version=permit.policy.policy_version,
        tool_schema_hash=permit.scope.tool_schema_hash,
        scope=permit.scope,
        subject=SubjectBinding(
            subject_id_hash=canonical_hash_sha256({"identifier": action.actor_id}),
            agent_id_hash=canonical_hash_sha256({"identifier": action.agent_id}),
        ),
        now=permit.validity.not_before,
        logical_step=permit.validity.issued_at_logical_step,
        max_ttl_seconds=contract.max_execution_permit_ttl_seconds,
        trusted_signer=signer,
        trusted_key_id=permit.signature.get("key_id")
        if isinstance(permit.signature, Mapping)
        else None,
    )


def _ensure_sha256(value: str) -> str:
    if value.startswith("sha256:"):
        return value
    if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
        return f"sha256:{value}"
    return canonical_hash_sha256({"value": value})


def _public_decision(decision: ProofDecision) -> str:
    if decision is ProofDecision.ADMITTED:
        return "execute"
    if decision is ProofDecision.ESCALATED:
        return "escalate"
    return "block"


def _pre_execution_status(decision: ProofDecision) -> str:
    if decision is ProofDecision.ADMITTED:
        return "forward_authorized"
    if decision is ProofDecision.ESCALATED:
        return "pending_approval"
    return "not_forwarded"


def _inline_reason(outcome: AdmissionOutcome) -> str:
    reasons = list(outcome.unified_decision.reasons)
    return ", ".join(str(reason) for reason in reasons) or outcome.decision.value


def _inline_selected_warrant(
    outcome: AdmissionOutcome,
    *,
    request: InlineGatewayRequest,
    contract: AdmissionContract,
) -> JsonObject:
    action = outcome.canonical_action
    proposed = stable_json_object(request.proposed_action)
    request_hash = canonical_hash_sha256(request.to_dict())
    tool_schema_hash = _inline_tool_schema_hash(action)
    arguments_hash = _inline_arguments_hash(action, request)
    policy_hash = canonical_hash_sha256(contract.to_dict())
    decision = _public_decision(outcome.decision)
    unified = outcome.unified_decision.to_dict()
    appraisal = outcome.appraisal.to_dict()
    return {
        "warrant_id": f"wrnt_{outcome.envelope.envelope_id}",
        "issued_at": _now_iso(),
        "tenant_id": action.tenant_id or contract.tenant_id,
        "environment": action.environment or str(proposed.get("environment") or "local"),
        "request_id": request.stable_request_id,
        "request_hash": request_hash,
        "canonical_action_hash": action.canonical_action_hash,
        "policy_hash": policy_hash,
        "tool_schema_hash": tool_schema_hash,
        "arguments_hash": arguments_hash,
        "tool_name": action.tool_name,
        "tool_key": action.tool_name,
        "mcp_server": str(proposed.get("server")) if proposed.get("server") else None,
        "mcp_tool": str(proposed.get("tool")) if proposed.get("tool") else None,
        "decision": decision,
        "reason": _inline_reason(outcome),
        "action_type": action.canonical_type,
        "policy_version": contract.policy_version,
        "policy_statuses": [outcome.decision.value],
        "policy_reasons": [str(reason) for reason in outcome.unified_decision.reasons],
        "approval_required": outcome.decision is ProofDecision.ESCALATED,
        "risk_class": action.authority_class.value,
        "pricing_status": "priced",
        "entry_price": appraisal.get("admission_price"),
        "clearance_score": 1 if outcome.decision is ProofDecision.ADMITTED else 0,
        "risk_penalty": appraisal.get("admission_price"),
        "scarcity_pressure": action.economic_exposure,
        "authority_ledger_sequence": outcome.envelope.logical_step,
        "authority_budget_before": unified.get("authority_budget_before"),
        "authority_budget_after": unified.get("authority_budget_after"),
        "certificate": unified.get("certificate"),
        "agent_id": action.agent_id,
        "actor_user_id": action.actor_id,
        "product_surface": "velvet_inline_gateway",
        "seal_id": outcome.envelope.envelope_id,
        "thread_id": request.replay_id,
    }


def _inline_approval_request_id(payload: Mapping[str, Any]) -> str:
    stable = {str(key): value for key, value in payload.items() if key != "approval_request_id"}
    return "appr_" + canonical_hash_sha256(stable).removeprefix("sha256:")[:32]


def _is_proof_hash(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:")


def _inline_arguments_hash(
    action: CanonicalAction,
    request: InlineGatewayRequest,
) -> str:
    if _is_proof_hash(action.arguments_hash):
        return action.arguments_hash
    proposed = stable_json_object(request.proposed_action)
    arguments = proposed.get("arguments")
    arguments_payload = (
        cast(Mapping[str, Any], arguments)
        if isinstance(arguments, Mapping)
        else action.normalized_payload
    )
    return canonical_hash_sha256(arguments_payload)


def _inline_tool_schema_hash(action: CanonicalAction) -> str:
    if _is_proof_hash(action.tool_schema_hash):
        return cast(str, action.tool_schema_hash)
    return canonical_hash_sha256(
        {
            "surface": action.surface,
            "tool_name": action.tool_name,
            "schema_version": action.schema_version,
        }
    )


def _admission_evidence_ref(evidence: Mapping[str, Any] | None) -> JsonObject | None:
    if evidence is None:
        return None
    raw_action = evidence.get("raw_action")
    if not isinstance(raw_action, Mapping):
        return None
    raw_ref = raw_action.get("raw_action_ref")
    return dict(cast(Mapping[str, Any], raw_ref)) if isinstance(raw_ref, Mapping) else None


def _surface_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _upstream_status(receipt: ExecutionReceipt) -> str:
    if receipt.outcome == "succeeded":
        return "forwarded"
    if receipt.outcome in {"rejected", "failed_before_dispatch"}:
        return "not_forwarded"
    return "indeterminate"


def _current_dispatch_request(
    decision: InlineGatewayDecision,
    proposed_action: Mapping[str, Any] | None,
) -> InlineGatewayRequest:
    if proposed_action is None:
        return decision.request
    return replace(decision.request, proposed_action=stable_json_object(proposed_action))


def _coerce_approval_receipt(
    receipt: ApprovalReceipt | Mapping[str, Any],
) -> ApprovalReceipt:
    if isinstance(receipt, ApprovalReceipt):
        return receipt
    return ApprovalReceipt.from_dict(receipt)


def _approval_reappraise_receipt(
    decision: InlineGatewayDecision,
    reason: str,
    *,
    current_action: CanonicalAction | None = None,
) -> ExecutionReceipt:
    action = current_action or decision.canonical_action
    return ExecutionReceipt.rejected(
        permit=None,
        action=action,
        reason=reason,
    )
