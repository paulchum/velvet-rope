"""Sealed proof envelopes for Velvet admission decisions."""

from __future__ import annotations

from dataclasses import dataclass, field

from velvet.actions import CanonicalAction, ProofDecision
from velvet.appraisal import AppraisalResult
from velvet.contracts import AdmissionContract
from velvet.fallback import VelvetFallback
from velvet.serialization import JsonObject, canonical_hash, stable_json_object
from velvet.signing import (
    PURPOSE_PROOF_ENVELOPE,
    SigningProvider,
    default_demo_signer,
    payload_hash,
    sign_payload_hash,
    signature_record_signature,
    verify_signature_record,
)


@dataclass(frozen=True)
class ProofEnvelope:
    envelope_id: str
    decision: ProofDecision
    proposed_action: JsonObject
    canonical_action: JsonObject
    canonical_action_hash: str
    authority_class: str
    velvet_fallback: JsonObject
    admission_price: int
    appraisal_coverage: JsonObject
    authority_budget_before: int
    authority_budget_after: int
    boundary_key: str
    read_set_hash: str
    state_hash_before: str
    state_hash_after: str
    contract_version: str
    policy_version: str
    estimator_version: str
    denial_reason: str | None
    escalation_reason: str | None
    replay_id: str
    logical_step: int
    deterministic_trace_hash: str
    signature: str
    signature_record: JsonObject = field(default_factory=dict)

    def unsigned_payload(self) -> JsonObject:
        return {
            "envelope_id": self.envelope_id,
            "decision": self.decision.value,
            "proposed_action": stable_json_object(self.proposed_action),
            "canonical_action": stable_json_object(self.canonical_action),
            "canonical_action_hash": self.canonical_action_hash,
            "authority_class": self.authority_class,
            "velvet_fallback": stable_json_object(self.velvet_fallback),
            "admission_price": self.admission_price,
            "appraisal_coverage": stable_json_object(self.appraisal_coverage),
            "authority_budget_before": self.authority_budget_before,
            "authority_budget_after": self.authority_budget_after,
            "boundary_key": self.boundary_key,
            "read_set_hash": self.read_set_hash,
            "state_hash_before": self.state_hash_before,
            "state_hash_after": self.state_hash_after,
            "contract_version": self.contract_version,
            "policy_version": self.policy_version,
            "estimator_version": self.estimator_version,
            "denial_reason": self.denial_reason,
            "escalation_reason": self.escalation_reason,
            "replay_id": self.replay_id,
            "logical_step": self.logical_step,
            "deterministic_trace_hash": self.deterministic_trace_hash,
        }

    def to_dict(self) -> JsonObject:
        payload = self.unsigned_payload()
        payload["signature"] = self.signature
        payload["signature_record"] = stable_json_object(self.signature_record)
        return payload

    def verify_signature(
        self,
        contract: AdmissionContract,
        *,
        signer: SigningProvider | None = None,
    ) -> bool:
        record = self.signature_record
        if not record:
            return self.signature == sign_envelope(self.unsigned_payload(), contract)
        signature = signature_record_signature(record)
        if signature != self.signature:
            return False
        return verify_signature_record(
            record,
            payload_hash(self.unsigned_payload()),
            purpose=PURPOSE_PROOF_ENVELOPE,
            tenant_id=_contract_tenant_id(contract),
            key_id=contract.signing_key_id,
            signer=signer or _contract_signer(contract),
        )


def build_proof_envelope(
    *,
    decision: ProofDecision,
    proposed_action: JsonObject,
    canonical_action: CanonicalAction,
    velvet_fallback: VelvetFallback,
    appraisal: AppraisalResult,
    authority_budget_before: int,
    authority_budget_after: int,
    state_hash_before: str,
    state_hash_after: str,
    contract: AdmissionContract,
    denial_reason: str | None,
    escalation_reason: str | None,
    replay_id: str,
    logical_step: int,
    signer: SigningProvider | None = None,
    signed_at: str | None = None,
) -> ProofEnvelope:
    deterministic_trace_hash = canonical_hash(
        {
            "decision": decision.value,
            "canonical_action_hash": canonical_action.canonical_action_hash,
            "fallback_hash": velvet_fallback.fallback_hash,
            "admission_price": appraisal.admission_price,
            "state_hash_before": state_hash_before,
            "logical_step": logical_step,
        }
    )
    envelope_id = (
        "env_"
        + canonical_hash(
            {
                "replay_id": replay_id,
                "logical_step": logical_step,
                "trace_hash": deterministic_trace_hash,
            }
        )[:32]
    )
    unsigned = {
        "envelope_id": envelope_id,
        "decision": decision.value,
        "proposed_action": stable_json_object(proposed_action),
        "canonical_action": canonical_action.to_dict(),
        "canonical_action_hash": canonical_action.canonical_action_hash,
        "authority_class": canonical_action.authority_class.value,
        "velvet_fallback": velvet_fallback.to_dict(),
        "admission_price": appraisal.admission_price,
        "appraisal_coverage": appraisal.coverage,
        "authority_budget_before": authority_budget_before,
        "authority_budget_after": authority_budget_after,
        "boundary_key": canonical_action.boundary_key,
        "read_set_hash": canonical_action.read_set_hash,
        "state_hash_before": state_hash_before,
        "state_hash_after": state_hash_after,
        "contract_version": contract.contract_version,
        "policy_version": contract.policy_version,
        "estimator_version": contract.estimator_version,
        "denial_reason": denial_reason,
        "escalation_reason": escalation_reason,
        "replay_id": replay_id,
        "logical_step": logical_step,
        "deterministic_trace_hash": deterministic_trace_hash,
    }
    signature_record = sign_envelope_record(
        unsigned,
        contract,
        signer=signer,
        signed_at=signed_at,
    )
    signature = signature_record_signature(signature_record)
    if signature is None:
        raise ValueError("proof envelope signer did not return a signature")
    return ProofEnvelope(
        envelope_id=envelope_id,
        decision=decision,
        proposed_action=stable_json_object(proposed_action),
        canonical_action=canonical_action.to_dict(),
        canonical_action_hash=canonical_action.canonical_action_hash,
        authority_class=canonical_action.authority_class.value,
        velvet_fallback=velvet_fallback.to_dict(),
        admission_price=appraisal.admission_price,
        appraisal_coverage=stable_json_object(appraisal.coverage),
        authority_budget_before=authority_budget_before,
        authority_budget_after=authority_budget_after,
        boundary_key=canonical_action.boundary_key,
        read_set_hash=canonical_action.read_set_hash,
        state_hash_before=state_hash_before,
        state_hash_after=state_hash_after,
        contract_version=contract.contract_version,
        policy_version=contract.policy_version,
        estimator_version=contract.estimator_version,
        denial_reason=denial_reason,
        escalation_reason=escalation_reason,
        replay_id=replay_id,
        logical_step=logical_step,
        deterministic_trace_hash=deterministic_trace_hash,
        signature=signature,
        signature_record=signature_record,
    )


def sign_envelope(
    payload: JsonObject,
    contract: AdmissionContract,
    *,
    signer: SigningProvider | None = None,
    signed_at: str | None = None,
) -> str:
    signature = signature_record_signature(
        sign_envelope_record(payload, contract, signer=signer, signed_at=signed_at)
    )
    if signature is None:
        raise ValueError("proof envelope signer did not return a signature")
    return signature


def sign_envelope_record(
    payload: JsonObject,
    contract: AdmissionContract,
    *,
    signer: SigningProvider | None = None,
    signed_at: str | None = None,
) -> JsonObject:
    return sign_payload_hash(
        payload_hash(stable_json_object(payload)),
        purpose=PURPOSE_PROOF_ENVELOPE,
        tenant_id=_contract_tenant_id(contract),
        key_id=contract.signing_key_id,
        signer=signer or _contract_signer(contract),
        signed_at=signed_at,
    )


def _contract_tenant_id(contract: AdmissionContract) -> str:
    return contract.tenant_id


def _contract_signer(contract: AdmissionContract) -> SigningProvider:
    return default_demo_signer(
        contract.signature_key,
        key_version=contract.signing_key_version,
    )
