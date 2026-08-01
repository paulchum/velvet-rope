"""Velvet Admission Layer orchestration.

Admission evaluation produces decision evidence only. Execution authority is
prepared later through Execution Permits in :mod:`velvet.execution`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from velvet.actions import CanonicalAction, MaskedActionFailure, ProofDecision
from velvet.admission import (
    UnifiedAdmissionDecision,
    UnifiedAdmissionDecisionType,
    UnifiedAdmissionReason,
    decide_joint_admission,
    masked_action_decision,
)
from velvet.appraisal import AppraisalEngine, AppraisalResult
from velvet.contracts import AdmissionContract
from velvet.envelope import ProofEnvelope, build_proof_envelope
from velvet.execution import ExecutionReceipt, VelvetExecutor  # noqa: F401
from velvet.fallback import VelvetFallback, VelvetFallbackCompiler
from velvet.ledger import AuthorityLedger, LedgerReservation
from velvet.normalizer import VelvetActionNormalizer
from velvet.serialization import JsonObject, canonical_hash, stable_json_object


@dataclass(frozen=True)
class AdmissionOutcome:
    decision: ProofDecision
    envelope: ProofEnvelope
    canonical_action: CanonicalAction
    velvet_fallback: VelvetFallback
    appraisal: AppraisalResult
    unified_decision: UnifiedAdmissionDecision

    def to_dict(self) -> JsonObject:
        return {
            "decision": self.decision.value,
            "envelope": self.envelope.to_dict(),
            "canonical_action": self.canonical_action.to_dict(),
            "velvet_fallback": self.velvet_fallback.to_dict(),
            "appraisal": self.appraisal.to_dict(),
            "unified_decision": self.unified_decision.to_dict(),
        }


class VelvetAdmissionLayer:
    """The model proposes; Velvet admits."""

    def __init__(
        self,
        contract: AdmissionContract | None = None,
        *,
        ledger: AuthorityLedger | None = None,
        normalizer: VelvetActionNormalizer | None = None,
        fallback_compiler: VelvetFallbackCompiler | None = None,
        appraiser: AppraisalEngine | None = None,
    ) -> None:
        self.contract = contract or AdmissionContract()
        self.ledger = ledger or AuthorityLedger(
            default_authority_budget=self.contract.default_authority_budget,
            initial_budgets=self.contract.authority_budgets,
        )
        self.normalizer = normalizer or VelvetActionNormalizer()
        self.fallback_compiler = fallback_compiler or VelvetFallbackCompiler()
        self.appraiser = appraiser or AppraisalEngine()

    def evaluate(
        self,
        proposed_action: Mapping[str, Any],
        *,
        world_state: Mapping[str, Any] | None = None,
        logical_step: int,
        replay_id: str = "velvet_replay",
        proof_signed_at: str | None = None,
    ) -> AdmissionOutcome:
        proposal = stable_json_object(proposed_action)
        state_hash = canonical_hash(world_state or {})
        try:
            canonical_action = self.normalizer.normalize(
                proposal,
                self.contract,
                ledger=self.ledger,
            )
        except MaskedActionFailure as failure:
            return self._masked_action_outcome(
                failure,
                state_hash=state_hash,
                logical_step=logical_step,
                replay_id=replay_id,
                proof_signed_at=proof_signed_at,
            )

        fallback = self.fallback_compiler.compile(canonical_action)
        appraisal = self.appraiser.appraise(
            canonical_action,
            fallback,
            self.contract,
            current_world_state_hash=state_hash,
            authority_ledger=self.ledger,
            policy_version=self.contract.policy_version,
        )
        budget = self.contract.boundary_budget(canonical_action.boundary_key)
        split_group_key = canonical_action.split_group_key
        split_bundle_required = int(appraisal.coverage.get("split_bundle_budget_required", 0))
        if split_group_key and split_bundle_required > 0:
            preview = self.ledger.split_bundle_incremental_price(
                canonical_action.boundary_key,
                split_group_key,
                split_bundle_required,
                budget=budget,
            )
        else:
            before = self.ledger.remaining_authority(canonical_action.boundary_key, budget=budget)
            preview = LedgerReservation(
                success=appraisal.admission_price <= before,
                boundary_key=canonical_action.boundary_key,
                admission_price=appraisal.admission_price,
                authority_budget_before=before,
                authority_budget_after=before,
                authority_ledger_sequence=self.ledger.current_sequence(
                    canonical_action.boundary_key
                ),
            )
        priced_appraisal = (
            _appraisal_with_split_reservation(appraisal, preview)
            if split_group_key and split_bundle_required > 0
            else appraisal
        )
        unified_decision = decide_joint_admission(
            action=canonical_action,
            appraisal=priced_appraisal,
            proposed_action=proposal,
            contract=self.contract,
            authority_budget_before=preview.authority_budget_before,
        )
        if unified_decision.decision is UnifiedAdmissionDecisionType.Admitted:
            if split_group_key and split_bundle_required > 0:
                reservation = self.ledger.reserve_split_bundle(
                    canonical_action.boundary_key,
                    split_group_key,
                    split_bundle_required,
                    budget=budget,
                )
                priced_appraisal = _appraisal_with_split_reservation(appraisal, reservation)
            else:
                reservation = self.ledger.reserve(
                    canonical_action.boundary_key,
                    priced_appraisal.admission_price,
                    budget=budget,
                )
            if reservation.success:
                unified_decision = replace(
                    unified_decision,
                    reserve=priced_appraisal.admission_price,
                    authority_budget_before=reservation.authority_budget_before,
                    authority_budget_after=reservation.authority_budget_after,
                )
            else:
                unified_decision = _downgrade_after_reservation_race(
                    unified_decision,
                    reservation=reservation,
                )
        else:
            reservation = LedgerReservation(
                success=False,
                boundary_key=canonical_action.boundary_key,
                admission_price=priced_appraisal.admission_price,
                authority_budget_before=preview.authority_budget_before,
                authority_budget_after=preview.authority_budget_before,
                authority_ledger_sequence=preview.authority_ledger_sequence,
            )
        appraisal = _appraisal_with_unified_decision(priced_appraisal, unified_decision)
        if (
            unified_decision.decision is UnifiedAdmissionDecisionType.Admitted
            and reservation.success
        ):
            decision = ProofDecision.ADMITTED
            denial_reason = None
            escalation_reason = None
        else:
            decision = _proof_decision_for_unified(
                unified_decision,
                canonical_action.authority_class.value,
                self.contract,
            )
            self.ledger.record_non_admitted(
                canonical_action.boundary_key,
                decision.value,
                budget=budget,
            )
            denial_reason = _denial_reason(unified_decision)
            escalation_reason = (
                "signature required" if decision is ProofDecision.ESCALATED else None
            )

        envelope = build_proof_envelope(
            decision=decision,
            proposed_action=proposal,
            canonical_action=canonical_action,
            velvet_fallback=fallback,
            appraisal=appraisal,
            authority_budget_before=reservation.authority_budget_before,
            authority_budget_after=reservation.authority_budget_after,
            state_hash_before=state_hash,
            state_hash_after=state_hash,
            contract=self.contract,
            denial_reason=denial_reason,
            escalation_reason=escalation_reason,
            replay_id=replay_id,
            logical_step=logical_step,
            signed_at=proof_signed_at,
        )
        return AdmissionOutcome(
            decision=decision,
            envelope=envelope,
            canonical_action=canonical_action,
            velvet_fallback=fallback,
            appraisal=appraisal,
            unified_decision=unified_decision,
        )

    def _masked_action_outcome(
        self,
        failure: MaskedActionFailure,
        *,
        state_hash: str,
        logical_step: int,
        replay_id: str,
        proof_signed_at: str | None,
    ) -> AdmissionOutcome:
        if failure.ambiguity_set:
            priced = [
                (
                    action,
                    self.fallback_compiler.compile(action),
                )
                for action in failure.ambiguity_set
            ]
            appraisals = [
                (
                    action,
                    fallback,
                    self.appraiser.appraise(
                        action,
                        fallback,
                        self.contract,
                        current_world_state_hash=state_hash,
                        authority_ledger=self.ledger,
                        policy_version=self.contract.policy_version,
                    ),
                )
                for action, fallback in priced
            ]
            canonical_action, fallback, appraisal = max(
                appraisals,
                key=lambda item: (item[2].admission_price, item[0].canonical_type),
            )
        else:
            canonical_action = _masked_placeholder_action(failure.proposed_action, self.contract)
            fallback = self.fallback_compiler.compile(canonical_action)
            appraisal = AppraisalResult(
                admission_price=0,
                confidence="none",
                coverage={"ambiguity_set": 0},
                explanation="No deterministic plausible action could be constructed.",
                failure_mode="unpriced_masked_action_failure",
                estimator_version=self.contract.estimator_version,
            )
        budget = self.contract.boundary_budget(canonical_action.boundary_key)
        before = self.ledger.remaining_authority(canonical_action.boundary_key, budget=budget)
        unified_decision = masked_action_decision(
            reserve=appraisal.admission_price,
            authority_budget_before=before,
            contract=self.contract,
        )
        appraisal = _appraisal_with_unified_decision(appraisal, unified_decision)
        self.ledger.record_non_admitted(
            canonical_action.boundary_key,
            ProofDecision.MASKED_ACTION_FAILURE.value,
            budget=budget,
        )
        envelope = build_proof_envelope(
            decision=ProofDecision.MASKED_ACTION_FAILURE,
            proposed_action=failure.proposed_action,
            canonical_action=canonical_action,
            velvet_fallback=fallback,
            appraisal=appraisal,
            authority_budget_before=before,
            authority_budget_after=before,
            state_hash_before=state_hash,
            state_hash_after=state_hash,
            contract=self.contract,
            denial_reason=failure.reason,
            escalation_reason="masked action policy requires signature"
            if self.contract.masked_action_policy == "escalate"
            else None,
            replay_id=replay_id,
            logical_step=logical_step,
            signed_at=proof_signed_at,
        )
        return AdmissionOutcome(
            decision=ProofDecision.MASKED_ACTION_FAILURE,
            envelope=envelope,
            canonical_action=canonical_action,
            velvet_fallback=fallback,
            appraisal=appraisal,
            unified_decision=unified_decision,
        )


def _appraisal_with_split_reservation(
    appraisal: AppraisalResult,
    reservation: LedgerReservation,
) -> AppraisalResult:
    coverage = dict(appraisal.coverage)
    coverage["split_bundle_incremental_price"] = reservation.admission_price
    coverage["split_preauthorization_blocked"] = not reservation.success
    return replace(appraisal, admission_price=reservation.admission_price, coverage=coverage)


def _appraisal_with_unified_decision(
    appraisal: AppraisalResult,
    unified_decision: UnifiedAdmissionDecision,
) -> AppraisalResult:
    coverage = dict(appraisal.coverage)
    coverage["joint_admission"] = unified_decision.to_dict()
    return replace(appraisal, coverage=coverage)


def _downgrade_after_reservation_race(
    unified_decision: UnifiedAdmissionDecision,
    *,
    reservation: LedgerReservation,
) -> UnifiedAdmissionDecision:
    reasons = list(unified_decision.reasons)
    if UnifiedAdmissionReason.RESERVE_EXCEEDS_BUDGET.value not in reasons:
        reasons.append(UnifiedAdmissionReason.RESERVE_EXCEEDS_BUDGET.value)
    return replace(
        unified_decision,
        decision=UnifiedAdmissionDecisionType.DowngradeReserve,
        reasons=tuple(reasons),
        authority_budget_before=reservation.authority_budget_before,
        authority_budget_after=reservation.authority_budget_after,
        fallback_only=True,
    )


def _proof_decision_for_unified(
    unified_decision: UnifiedAdmissionDecision,
    authority_class: str,
    contract: AdmissionContract,
) -> ProofDecision:
    if unified_decision.decision is UnifiedAdmissionDecisionType.Escalate:
        return ProofDecision.ESCALATED
    if unified_decision.decision is UnifiedAdmissionDecisionType.LockoutUpside:
        return ProofDecision.REFUSED
    if unified_decision.decision is UnifiedAdmissionDecisionType.Refine:
        return (
            ProofDecision.FALLBACK_EXECUTED
            if contract.execute_fallback_on_insufficient_budget
            else ProofDecision.HELD
        )
    if unified_decision.decision is UnifiedAdmissionDecisionType.MaskedActionFailure:
        return ProofDecision.MASKED_ACTION_FAILURE
    return _non_admitted_decision(authority_class, contract)


def _denial_reason(unified_decision: UnifiedAdmissionDecision) -> str:
    reason_list = ", ".join(unified_decision.reasons)
    if unified_decision.decision is UnifiedAdmissionDecisionType.DowngradeReserve:
        return (
            f"Reserve {unified_decision.reserve} exceeds remaining authority budget "
            f"{unified_decision.authority_budget_before}; reasons: {reason_list}."
        )
    if unified_decision.decision is UnifiedAdmissionDecisionType.UpsideInsufficient:
        return (
            f"Certified upside {unified_decision.certified_upside} does not clear "
            f"reserve {unified_decision.reserve}; reasons: {reason_list}."
        )
    if unified_decision.decision is UnifiedAdmissionDecisionType.LockoutUpside:
        return (
            f"Upper upside certificate {unified_decision.certified_upper_upside} cannot "
            f"clear reserve {unified_decision.reserve}; reasons: {reason_list}."
        )
    if unified_decision.decision is UnifiedAdmissionDecisionType.Refine:
        return f"Joint admission gates are marginal; reasons: {reason_list}."
    if unified_decision.decision is UnifiedAdmissionDecisionType.Escalate:
        return f"Joint admission requires review; reasons: {reason_list}."
    return f"Joint admission did not admit the action; reasons: {reason_list}."


def _non_admitted_decision(authority_class: str, contract: AdmissionContract) -> ProofDecision:
    if authority_class in {"SPEND_HIGH", "BIND_EXTERNAL"}:
        return ProofDecision.ESCALATED
    if authority_class in {"SPEND_LOW", "OBSERVE", "APPEND"}:
        return ProofDecision.HELD
    if authority_class == "DESTROY":
        return (
            ProofDecision.FALLBACK_EXECUTED
            if contract.execute_fallback_on_insufficient_budget
            else ProofDecision.REFUSED
        )
    if authority_class == "ALTER":
        return (
            ProofDecision.FALLBACK_EXECUTED
            if contract.execute_fallback_on_insufficient_budget
            else ProofDecision.HELD
        )
    if contract.execute_fallback_on_insufficient_budget:
        return ProofDecision.FALLBACK_EXECUTED
    return ProofDecision.HELD


def _masked_placeholder_action(
    proposed_action: JsonObject,
    contract: AdmissionContract,
) -> CanonicalAction:
    from velvet.actions import AuthorityClass, MutationKind, Reversibility

    payload = {
        "masked_action_failure": True,
        "proposed_payload_hash": canonical_hash(proposed_action),
    }
    return CanonicalAction(
        action_id="act_" + canonical_hash(payload)[:24],
        actor_id=str(proposed_action.get("actor_id", "actor")),
        agent_id=str(proposed_action.get("agent_id", "agent")),
        boundary_key=str(proposed_action.get("boundary_key", "agent:agent:default")),
        tool_name="masked.action",
        canonical_type="masked_action_failure",
        authority_class=AuthorityClass.BIND_EXTERNAL,
        target_resource="resource:ambiguous",
        economic_exposure=0,
        external_party="external:ambiguous",
        mutation_kind=MutationKind.NONE,
        reversibility=Reversibility.NONE,
        read_set_hash=canonical_hash({"read_set": "ambiguous"}),
        proposed_payload_hash=canonical_hash(proposed_action),
        normalized_payload=stable_json_object(payload),
        timestamp_input="1970-01-01T00:00:00.000Z",
        contract_version=contract.contract_version,
        policy_version=contract.policy_version,
    )
