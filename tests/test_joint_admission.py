from __future__ import annotations

from velvet import AdmissionContract, UnifiedAdmissionDecisionType, UnifiedAdmissionReason
from velvet.actions import ProofDecision
from velvet.executor import VelvetAdmissionLayer


def _typed_upside_certificate(lower: float, upper: float | None) -> dict[str, object]:
    certificate: dict[str, object] = {
        "schema_version": "velvet.certificate_evidence.v2",
        "family": "beta_bernoulli",
        "arm_id": "joint",
        "baseline": 0.0,
        "lookback_horizon": 1,
        "delight_scale": 1.0,
        "liability_price": 0.0,
        "threshold": 0.0,
        "inspection_lower_bound": lower,
        "outcome": "inspect",
        "liability_mode": "posterior_certificate",
        "typed_effect": {
            "max_payoff": 1.0,
            "mean_bound": min(lower, 1.0),
            "variance_bound": 0.0,
            "resource_scope": "joint_admission_test",
            "write_footprint": [],
            "filtration_hash": "joint-filtration",
            "filtration_index": 0,
            "adapted": True,
        },
    }
    if upper is not None:
        certificate["safe_upper_bound"] = upper
    return certificate


def _refund_with_certificate(
    *,
    lower: float,
    upper: float | None,
    budget: int = 500,
    band: int = 0,
) -> tuple[VelvetAdmissionLayer, dict[str, object]]:
    contract = AdmissionContract(
        admission_mode="joint",
        default_authority_budget=budget,
        upside_value_scale=1_000,
        joint_marginal_authority_band=band,
    )
    proposal: dict[str, object] = {
        "surface": "function",
        "name": "refund",
        "operation": "refund",
        "refund_amount": 100,
        "boundary_key": "case:joint",
        "upside_certificate": _typed_upside_certificate(lower, upper),
    }
    return VelvetAdmissionLayer(contract), proposal


def test_joint_admission_requires_reserve_and_certified_upside() -> None:
    layer, proposal = _refund_with_certificate(lower=0.16, upper=0.2)

    outcome = layer.evaluate(proposal, logical_step=1)

    assert outcome.decision is ProofDecision.ADMITTED
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.Admitted
    assert outcome.unified_decision.reserve == 155
    assert outcome.unified_decision.certified_upside == 160
    assert UnifiedAdmissionReason.RESERVE_FITS_BUDGET.value in outcome.unified_decision.reasons
    assert (
        UnifiedAdmissionReason.UPSIDE_CERTIFICATE_CLEARS_RESERVE.value
        in outcome.envelope.appraisal_coverage["joint_admission"]["reasons"]
    )


def test_joint_precedence_keeps_reserve_downgrade_primary_with_secondary_upside_reason() -> None:
    layer, proposal = _refund_with_certificate(lower=0.05, upper=0.2, budget=100)

    outcome = layer.evaluate(proposal, logical_step=1)

    assert outcome.decision is ProofDecision.HELD
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.DowngradeReserve
    assert outcome.unified_decision.fallback_only is True
    assert UnifiedAdmissionReason.RESERVE_EXCEEDS_BUDGET.value in outcome.unified_decision.reasons
    assert (
        UnifiedAdmissionReason.UPSIDE_CERTIFICATE_INSUFFICIENT.value
        in outcome.unified_decision.reasons
    )


def test_joint_lockout_requires_upper_certificate() -> None:
    layer, proposal = _refund_with_certificate(lower=0.05, upper=0.15)

    outcome = layer.evaluate(proposal, logical_step=1)

    assert outcome.decision is ProofDecision.REFUSED
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.LockoutUpside
    assert outcome.unified_decision.certified_upper_upside == 150
    assert (
        UnifiedAdmissionReason.UPSIDE_UPPER_CERTIFICATE_LOCKOUT.value
        in outcome.unified_decision.reasons
    )


def test_joint_insufficient_without_upper_certificate_is_not_lockout() -> None:
    layer, proposal = _refund_with_certificate(lower=0.05, upper=None)

    outcome = layer.evaluate(proposal, logical_step=1)

    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.UpsideInsufficient
    assert (
        UnifiedAdmissionReason.UPSIDE_UPPER_CERTIFICATE_LOCKOUT.value
        not in outcome.unified_decision.reasons
    )


def test_joint_refine_when_both_gates_are_marginal() -> None:
    layer, proposal = _refund_with_certificate(lower=0.156, upper=0.2, budget=160, band=5)

    outcome = layer.evaluate(proposal, logical_step=1)

    assert outcome.decision is ProofDecision.FALLBACK_EXECUTED
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.Refine
    assert UnifiedAdmissionReason.JOINT_GATE_MARGINAL.value in outcome.unified_decision.reasons


def test_joint_high_authority_marginal_case_escalates() -> None:
    layer = VelvetAdmissionLayer(
        AdmissionContract(
            admission_mode="joint",
            default_authority_budget=1_105,
            upside_value_scale=10_000,
            joint_marginal_authority_band=5,
        )
    )

    outcome = layer.evaluate(
        {
            "surface": "connector",
            "connector": "send_email",
            "operation": "send_email",
            "boundary_key": "case:external",
            "upside_certificate": _typed_upside_certificate(0.1101, 0.2),
        },
        logical_step=1,
    )

    assert outcome.decision is ProofDecision.ESCALATED
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.Escalate
    assert (
        UnifiedAdmissionReason.HIGH_AUTHORITY_REVIEW_REQUIRED.value
        in outcome.unified_decision.reasons
    )


def test_reserve_only_mode_remains_compatible_without_upside_certificate() -> None:
    layer = VelvetAdmissionLayer(AdmissionContract(default_authority_budget=500))

    outcome = layer.evaluate(
        {
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:reserve-only",
        },
        logical_step=1,
    )

    assert outcome.decision is ProofDecision.ADMITTED
    assert outcome.unified_decision.decision is UnifiedAdmissionDecisionType.Admitted
    assert (
        UnifiedAdmissionReason.RESERVE_ONLY_COMPATIBILITY_MODE.value
        in outcome.unified_decision.reasons
    )
