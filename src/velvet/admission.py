"""Joint admission decisions for Velvet appraise / seal / admit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from enum import StrEnum
from math import isfinite
from typing import Any

from velvet.actions import AuthorityClass, CanonicalAction
from velvet.appraisal import AppraisalResult
from velvet.contracts import AdmissionContract
from velvet.serialization import JsonObject, stable_json_object


class UnifiedAdmissionDecisionType(StrEnum):
    Admitted = "Admitted"
    DowngradeReserve = "DowngradeReserve"
    UpsideInsufficient = "UpsideInsufficient"
    LockoutUpside = "LockoutUpside"
    Refine = "Refine"
    Escalate = "Escalate"
    MaskedActionFailure = "MaskedActionFailure"


class UnifiedAdmissionReason(StrEnum):
    MASKED_ACTION_UNCANONICALIZABLE = "MASKED_ACTION_UNCANONICALIZABLE"
    HIGH_AUTHORITY_REVIEW_REQUIRED = "HIGH_AUTHORITY_REVIEW_REQUIRED"
    RESERVE_EXCEEDS_BUDGET = "RESERVE_EXCEEDS_BUDGET"
    RESERVE_FITS_BUDGET = "RESERVE_FITS_BUDGET"
    UPSIDE_CERTIFICATE_MISSING = "UPSIDE_CERTIFICATE_MISSING"
    UPSIDE_CERTIFICATE_INVALID = "UPSIDE_CERTIFICATE_INVALID"
    UPSIDE_CERTIFICATE_INSUFFICIENT = "UPSIDE_CERTIFICATE_INSUFFICIENT"
    UPSIDE_UPPER_CERTIFICATE_LOCKOUT = "UPSIDE_UPPER_CERTIFICATE_LOCKOUT"
    UPSIDE_CERTIFICATE_CLEARS_RESERVE = "UPSIDE_CERTIFICATE_CLEARS_RESERVE"
    JOINT_GATE_MARGINAL = "JOINT_GATE_MARGINAL"
    RESERVE_ONLY_COMPATIBILITY_MODE = "RESERVE_ONLY_COMPATIBILITY_MODE"
    CONTRACT_NUMERAIRE_CONVERSION = "CONTRACT_NUMERAIRE_CONVERSION"


@dataclass(frozen=True)
class UpsideCertificateView:
    inspection_lower_bound: Decimal
    safe_upper_bound: Decimal | None
    delight_multiplier: Decimal
    source: str
    payload: JsonObject

    @property
    def has_upper_certificate(self) -> bool:
        return self.safe_upper_bound is not None


@dataclass(frozen=True)
class UnifiedAdmissionDecision:
    decision: UnifiedAdmissionDecisionType
    reasons: tuple[str, ...]
    reserve: int
    authority_budget_before: int
    authority_budget_after: int
    certified_upside: int | None
    certified_upper_upside: int | None
    value_numeraire: str
    upside_value_scale: int
    admission_mode: str
    fallback_only: bool
    certificate: JsonObject | None = None

    def to_dict(self) -> JsonObject:
        return stable_json_object(
            {
                "decision": self.decision.value,
                "reasons": list(self.reasons),
                "reserve": self.reserve,
                "authority_budget_before": self.authority_budget_before,
                "authority_budget_after": self.authority_budget_after,
                "certified_upside": self.certified_upside,
                "certified_upper_upside": self.certified_upper_upside,
                "value_numeraire": self.value_numeraire,
                "upside_value_scale": self.upside_value_scale,
                "admission_mode": self.admission_mode,
                "fallback_only": self.fallback_only,
                "certificate": self.certificate,
            }
        )


def decide_joint_admission(
    *,
    action: CanonicalAction,
    appraisal: AppraisalResult,
    proposed_action: Mapping[str, Any],
    contract: AdmissionContract,
    authority_budget_before: int,
) -> UnifiedAdmissionDecision:
    reserve = int(appraisal.admission_price)
    reasons: list[UnifiedAdmissionReason] = []
    if reserve > authority_budget_before:
        reasons.append(UnifiedAdmissionReason.RESERVE_EXCEEDS_BUDGET)
    else:
        reasons.append(UnifiedAdmissionReason.RESERVE_FITS_BUDGET)

    certificate = extract_upside_certificate(proposed_action)
    certified_upside: int | None = None
    certified_upper_upside: int | None = None
    if contract.admission_mode == "reserve_only":
        certified_upside = reserve
        reasons.append(UnifiedAdmissionReason.RESERVE_ONLY_COMPATIBILITY_MODE)
    elif certificate is None:
        reasons.append(UnifiedAdmissionReason.UPSIDE_CERTIFICATE_MISSING)
    else:
        lower_units = value_in_authority_units(
            certificate.inspection_lower_bound,
            certificate.delight_multiplier,
            contract,
        )
        certified_upside = lower_units
        if certificate.safe_upper_bound is not None:
            certified_upper_upside = value_in_authority_units(
                certificate.safe_upper_bound,
                certificate.delight_multiplier,
                contract,
            )
        reasons.append(UnifiedAdmissionReason.CONTRACT_NUMERAIRE_CONVERSION)
        if certified_upside >= reserve:
            reasons.append(UnifiedAdmissionReason.UPSIDE_CERTIFICATE_CLEARS_RESERVE)
        else:
            reasons.append(UnifiedAdmissionReason.UPSIDE_CERTIFICATE_INSUFFICIENT)
        if certified_upper_upside is not None and certified_upper_upside < reserve:
            reasons.append(UnifiedAdmissionReason.UPSIDE_UPPER_CERTIFICATE_LOCKOUT)

    joint_mode = contract.admission_mode != "reserve_only"
    reserve_marginal = joint_mode and _within_band(
        authority_budget_before - reserve,
        contract.joint_marginal_authority_band,
    )
    reserve_shortfall = reserve - authority_budget_before
    reserve_shortfall_marginal = (
        joint_mode
        and 0 < reserve_shortfall <= max(0, int(contract.joint_marginal_authority_band))
    )
    upside_marginal = joint_mode and (
        certified_upside is not None
        and certified_upside >= reserve
        and _within_band(certified_upside - reserve, contract.joint_marginal_authority_band)
    )
    if reserve_marginal and upside_marginal:
        reasons.append(UnifiedAdmissionReason.JOINT_GATE_MARGINAL)
    high_authority = action.authority_class in {
        AuthorityClass.DESTROY,
        AuthorityClass.SPEND_HIGH,
        AuthorityClass.BIND_EXTERNAL,
    }
    if high_authority and (
        (reserve_marginal and upside_marginal) or reserve_shortfall_marginal
    ):
        reasons.append(UnifiedAdmissionReason.HIGH_AUTHORITY_REVIEW_REQUIRED)

    decision = _primary_decision(
        reasons=tuple(reasons),
        reserve_fits=reserve <= authority_budget_before,
        upside_clears=certified_upside is not None and certified_upside >= reserve,
    )
    return UnifiedAdmissionDecision(
        decision=decision,
        reasons=tuple(reason.value for reason in _dedupe_reasons(reasons)),
        reserve=reserve,
        authority_budget_before=authority_budget_before,
        authority_budget_after=(
            authority_budget_before
            if decision is not UnifiedAdmissionDecisionType.Admitted
            else authority_budget_before - reserve
        ),
        certified_upside=certified_upside,
        certified_upper_upside=certified_upper_upside,
        value_numeraire=contract.value_numeraire,
        upside_value_scale=contract.upside_value_scale,
        admission_mode=contract.admission_mode,
        fallback_only=decision in {
            UnifiedAdmissionDecisionType.DowngradeReserve,
            UnifiedAdmissionDecisionType.Refine,
        },
        certificate=certificate.payload if certificate is not None else None,
    )


def masked_action_decision(
    *,
    reserve: int,
    authority_budget_before: int,
    contract: AdmissionContract,
) -> UnifiedAdmissionDecision:
    return UnifiedAdmissionDecision(
        decision=UnifiedAdmissionDecisionType.MaskedActionFailure,
        reasons=(UnifiedAdmissionReason.MASKED_ACTION_UNCANONICALIZABLE.value,),
        reserve=reserve,
        authority_budget_before=authority_budget_before,
        authority_budget_after=authority_budget_before,
        certified_upside=None,
        certified_upper_upside=None,
        value_numeraire=contract.value_numeraire,
        upside_value_scale=contract.upside_value_scale,
        admission_mode=contract.admission_mode,
        fallback_only=True,
        certificate=None,
    )


def extract_upside_certificate(proposed_action: Mapping[str, Any]) -> UpsideCertificateView | None:
    for source, payload in _candidate_certificate_payloads(proposed_action):
        parsed = _parse_certificate(source, payload)
        if parsed is not None:
            return parsed
    return None


def value_in_authority_units(
    certificate_value: Decimal,
    delight_multiplier: Decimal,
    contract: AdmissionContract,
) -> int:
    converted = certificate_value * delight_multiplier * Decimal(contract.upside_value_scale)
    if converted <= 0:
        return 0
    return int(converted.to_integral_value(rounding=ROUND_FLOOR))


def _primary_decision(
    *,
    reasons: tuple[UnifiedAdmissionReason, ...],
    reserve_fits: bool,
    upside_clears: bool,
) -> UnifiedAdmissionDecisionType:
    reason_set = set(reasons)
    if UnifiedAdmissionReason.MASKED_ACTION_UNCANONICALIZABLE in reason_set:
        return UnifiedAdmissionDecisionType.MaskedActionFailure
    if UnifiedAdmissionReason.HIGH_AUTHORITY_REVIEW_REQUIRED in reason_set:
        return UnifiedAdmissionDecisionType.Escalate
    if not reserve_fits:
        return UnifiedAdmissionDecisionType.DowngradeReserve
    if UnifiedAdmissionReason.UPSIDE_UPPER_CERTIFICATE_LOCKOUT in reason_set:
        return UnifiedAdmissionDecisionType.LockoutUpside
    if not upside_clears:
        return UnifiedAdmissionDecisionType.UpsideInsufficient
    if UnifiedAdmissionReason.JOINT_GATE_MARGINAL in reason_set:
        return UnifiedAdmissionDecisionType.Refine
    return UnifiedAdmissionDecisionType.Admitted


def _candidate_certificate_payloads(
    proposed_action: Mapping[str, Any],
) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    payloads: list[tuple[str, Mapping[str, Any]]] = []
    for key in ("upside_certificate", "max_de_certificate", "certificate"):
        value = proposed_action.get(key)
        if isinstance(value, Mapping):
            payloads.append((key, value))
    for parent_key in ("metadata", "proof_envelope"):
        parent = proposed_action.get(parent_key)
        if not isinstance(parent, Mapping):
            continue
        for key in ("upside_certificate", "max_de_certificate", "certificate"):
            value = parent.get(key)
            if isinstance(value, Mapping):
                payloads.append((f"{parent_key}.{key}", value))
    return tuple(payloads)


def _parse_certificate(
    source: str,
    payload: Mapping[str, Any],
) -> UpsideCertificateView | None:
    if not isinstance(payload.get("typed_effect"), Mapping):
        return None
    lower = _decimal_value(payload.get("inspection_lower_bound"))
    if lower is None:
        return None
    upper = _decimal_value(payload.get("safe_upper_bound"))
    delight_multiplier = _decimal_value(payload.get("delight_scale"))
    if delight_multiplier is None:
        delight_multiplier = _decimal_value(payload.get("delight_multiplier"))
    if delight_multiplier is None:
        delight_multiplier = Decimal("1")
    if lower < 0 or delight_multiplier <= 0:
        return None
    if upper is not None and (upper < 0 or upper < lower):
        return None
    normalized = stable_json_object(dict(payload))
    normalized["certificate_source"] = source
    return UpsideCertificateView(
        inspection_lower_bound=lower,
        safe_upper_bound=upper,
        delight_multiplier=delight_multiplier,
        source=source,
        payload=normalized,
    )


def _decimal_value(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        if not isfinite(value):
            return None
        return Decimal(str(value))
    if isinstance(value, str):
        try:
            parsed = Decimal(value)
        except InvalidOperation:
            return None
        return parsed if parsed.is_finite() else None
    return None


def _within_band(gap: int, band: int) -> bool:
    return 0 <= gap <= max(0, int(band))


def _dedupe_reasons(
    reasons: list[UnifiedAdmissionReason],
) -> tuple[UnifiedAdmissionReason, ...]:
    seen: set[UnifiedAdmissionReason] = set()
    deduped: list[UnifiedAdmissionReason] = []
    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        deduped.append(reason)
    return tuple(deduped)
