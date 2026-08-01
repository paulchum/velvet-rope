"""Deterministic rule-based appraisal for Velvet admission decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from velvet.actions import CanonicalAction
from velvet.contracts import AdmissionContract
from velvet.fallback import VelvetFallback
from velvet.serialization import JsonObject, stable_json_object


class LedgerView(Protocol):
    def denial_pressure(self, boundary_key: str) -> int: ...


@dataclass(frozen=True)
class AppraisalResult:
    admission_price: int
    confidence: str
    coverage: JsonObject
    explanation: str
    failure_mode: str | None
    estimator_version: str

    def to_dict(self) -> JsonObject:
        return {
            "admission_price": self.admission_price,
            "confidence": self.confidence,
            "coverage": stable_json_object(self.coverage),
            "explanation": self.explanation,
            "failure_mode": self.failure_mode,
            "estimator_version": self.estimator_version,
        }


class AppraisalEngine:
    def appraise(
        self,
        action: CanonicalAction,
        velvet_fallback: VelvetFallback,
        contract: AdmissionContract,
        *,
        current_world_state_hash: str,
        authority_ledger: LedgerView,
        policy_version: str,
    ) -> AppraisalResult:
        if policy_version != contract.policy_version:
            return AppraisalResult(
                admission_price=0,
                confidence="none",
                coverage={"policy_version": policy_version},
                explanation="Policy version mismatch; action is not appraisable.",
                failure_mode="policy_version_mismatch",
                estimator_version=contract.estimator_version,
            )

        authority_class = action.authority_class.value
        base = contract.base_prices[authority_class]
        multiplier = contract.class_multipliers[authority_class]
        split_bundle_reserve = split_retention_price(
            action.aggregated_economic_exposure,
            contract,
        )
        split_bundle_applies = (
            contract.split_preauthorization_enabled
            and action.split_group_key is not None
            and action.aggregated_economic_exposure > action.economic_exposure
        )
        priced_exposure = max(action.economic_exposure, action.aggregated_economic_exposure)
        reversibility_penalty = contract.reversibility_penalties[action.reversibility.value]
        externality_penalty = contract.externality_penalty if action.external_party else 0
        fraud_penalty = 300 if action.normalized_payload.get("fraud_flagged") is True else 0
        pressure = authority_ledger.denial_pressure(action.boundary_key)
        pressure_penalty = pressure * contract.denial_pressure_weight
        split_penalty = (
            contract.split_aggregation_penalty
            if action.aggregated_economic_exposure > action.economic_exposure
            else 0
        )
        member_price = (
            base * multiplier
            + priced_exposure
            + reversibility_penalty
            + externality_penalty
            + fraud_penalty
            + pressure_penalty
            + split_penalty
        )
        admission_price = (
            max(member_price, split_bundle_reserve) if split_bundle_applies else member_price
        )
        return AppraisalResult(
            admission_price=int(admission_price),
            confidence="deterministic-rules",
            coverage={
                "class_multiplier": multiplier,
                "base_price": base,
                "economic_exposure": action.economic_exposure,
                "aggregated_economic_exposure": action.aggregated_economic_exposure,
                "reversibility_penalty": reversibility_penalty,
                "externality_penalty": externality_penalty,
                "fraud_penalty": fraud_penalty,
                "denial_pressure": pressure,
                "denial_pressure_penalty": pressure_penalty,
                "split_aggregation_penalty": split_penalty,
                "split_bundle_reserve": split_bundle_reserve if split_bundle_applies else 0,
                "split_bundle_budget_required": split_bundle_reserve
                if split_bundle_applies
                else 0,
                "split_preauthorization_blocked": False,
                "fallback_hash": velvet_fallback.fallback_hash,
                "world_state_hash": current_world_state_hash,
            },
            explanation=(
                "Deterministic appraisal from authority class, exposure, reversibility, "
                "externality, boundary denial pressure, and split aggregation."
            ),
            failure_mode=None,
            estimator_version=contract.estimator_version,
        )


def split_retention_price(aggregate_exposure: int, contract: AdmissionContract) -> int:
    retained = max(aggregate_exposure - contract.split_retention_floor, 0)
    return (retained * contract.split_retention_rate_basis_points + 9_999) // 10_000
