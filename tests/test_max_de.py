from __future__ import annotations

from dataclasses import replace

from velvet import (
    ActionType,
    BetaBernoulliPosteriorSpec,
    CandidateAction,
    CertificateEvidence,
    CertificateOutcome,
    DecisionType,
    DirichletCategoricalPosteriorSpec,
    Router,
    build_beta_bernoulli_certificate,
    build_dirichlet_categorical_certificate,
    build_reserve_priced_beta_bernoulli_certificate,
    certified_beta_bernoulli_candidate,
    certified_dirichlet_categorical_candidate,
)

ZERO_COST = {
    "tokens": 0.0,
    "latency": 0.0,
    "money": 0.0,
    "compute": 0.0,
    "api_calls": 0.0,
    "context_pollution": 0.0,
    "memory_bloat": 0.0,
    "user_attention": 0.0,
    "privacy_exposure": 0.0,
    "coordination_overhead": 0.0,
    "opportunity_cost": 0.0,
}

ZERO_RISK = {
    "privacy_risk": 0.0,
    "tool_risk": 0.0,
    "external_side_effect_risk": 0.0,
    "hallucination_risk": 0.0,
    "staleness_risk": 0.0,
    "source_quality_risk": 0.0,
    "irreversibility": 0.0,
    "sensitivity": 0.0,
    "compliance_risk": 0.0,
    "user_trust_risk": 0.0,
    "future_misuse_risk": 0.0,
}
NON_BUDGET = {"non_budget_affecting": True}


def test_beta_bernoulli_spec_builds_runtime_certificate_candidate() -> None:
    spec = BetaBernoulliPosteriorSpec(
        arm_id="arm_2",
        alpha=1.0,
        beta=2.0,
        baseline=0.55,
        lambda_value=0.06,
        lookback_horizon=3,
        liability_mode="false_lockout",
    )

    candidate = spec.candidate(
        ActionType.RETRIEVE_CONTEXT,
        description="Recoverable posterior arm.",
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
    )

    assert candidate.certificate is not None
    assert candidate.certificate.outcome == CertificateOutcome.INSPECT
    assert candidate.certificate.typed_effect.mean_bound < candidate.certificate.liability_price
    assert candidate.certificate.inspection_lower_bound >= candidate.certificate.threshold
    assert candidate.certificate.safe_upper_bound >= candidate.certificate.inspection_lower_bound
    assert candidate.certificate.typed_effect.resource_scope == "posterior_option"
    assert candidate.metadata["max_de_engine"] == "certified_max_de_v1"


def test_certified_candidate_routes_through_runtime_certificate_engine() -> None:
    candidate = certified_beta_bernoulli_candidate(
        ActionType.RETRIEVE_CONTEXT,
        arm_id="arm_2",
        alpha=1.0,
        beta=2.0,
        baseline=0.55,
        lambda_value=0.06,
        lookback_horizon=3,
        liability_mode="false_lockout",
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
        metadata=NON_BUDGET,
    )
    host = CandidateAction(
        ActionType.ANSWER_DIRECTLY,
        expected_improvement=0.02,
        novelty=1.0,
        confidence=1.0,
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
        metadata=NON_BUDGET,
    )

    decision = Router().decide(
        {
            "host_action": "ANSWER_DIRECTLY",
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.06,
                "lambda_cap": 0.06,
            },
        },
        [host, candidate],
    )

    assert decision.action_type == ActionType.RETRIEVE_CONTEXT
    assert decision.selected_candidate is not None
    assert decision.selected_candidate.admission_score is None
    assert decision.selected_candidate.admission_trace is not None
    assert decision.selected_candidate.effect_vector is not None
    assert candidate.certificate is not None
    assert decision.selected_candidate.effect_vector.utility_bound.lower_bps > 0
    assert (
        decision.selected_candidate.admission_trace.objective_components.utility_lcb_bps
        == decision.selected_candidate.effect_vector.utility_bound.lower_bps
    )


def test_runtime_blocks_inconsistent_max_de_certificate() -> None:
    valid = build_beta_bernoulli_certificate(
        arm_id="arm_2",
        alpha=1.0,
        beta=3.0,
        baseline=0.55,
        lambda_value=0.06,
        lookback_horizon=3,
        liability_mode="certifiable_waste",
    )
    inconsistent = replace(valid, outcome=CertificateOutcome.INSPECT)

    decision = Router().decide(
        {},
        [
            CandidateAction(
                ActionType.RETRIEVE_CONTEXT,
                certificate=inconsistent,
            )
        ],
    )

    assert decision.decision == DecisionType.BLOCK
    assert decision.candidate_decisions[0].short_circuit == "invalid_certificate"


def test_reserve_priced_certificate_declares_authority_numeraire() -> None:
    certificate = build_reserve_priced_beta_bernoulli_certificate(
        arm_id="arm_joint",
        alpha=5.0,
        beta=2.0,
        baseline=0.25,
        reserve_price=155,
        upside_value_scale=1_000,
        delight_scale=1.0,
    )

    assert certificate.reserve_price == 155.0
    assert certificate.value_numeraire == "authority_budget_units"
    assert certificate.upside_value_scale == 1_000
    assert certificate.threshold == certificate.liability_price


def test_dirichlet_categorical_spec_builds_runtime_certificate_candidate() -> None:
    spec = DirichletCategoricalPosteriorSpec(
        arm_id="categorical_arm",
        alpha=(2.0, 3.0, 1.5, 4.0),
        payoffs=(-1.0, 0.5, 0.5, 2.0),
        baseline=0.4,
        lambda_value=0.5,
        lookback_horizon=4,
    )

    candidate = spec.candidate(
        ActionType.RETRIEVE_CONTEXT,
        description="Bounded categorical payoff arm.",
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
    )

    assert candidate.certificate is not None
    assert candidate.certificate.family == "dirichlet_categorical"
    assert candidate.certificate.outcome == CertificateOutcome.INSPECT
    assert (
        candidate.certificate.typed_effect.mean_bound
        < candidate.certificate.inspection_lower_bound
    )
    assert candidate.metadata["payoff_levels"] == [-1.0, 0.5, 2.0]
    assert candidate.metadata["payoff_level_alpha"] == [2.0, 4.5, 4.0]
    assert candidate.metadata["max_de_upper_certificate"]["method"] == "exact"
    scalable = candidate.metadata["max_de_scalable_upper_certificate"]
    assert scalable["method"] == "moment"
    assert scalable["q_v_source"] == "positive_part_second_moment"
    assert "q_v=G_2(gamma,c;v+m_v)" in scalable["moment_terms"]


def test_dirichlet_categorical_candidate_routes_through_certificate_engine() -> None:
    candidate = certified_dirichlet_categorical_candidate(
        ActionType.RETRIEVE_CONTEXT,
        arm_id="categorical_arm",
        alpha=(2.0, 3.0, 1.5, 4.0),
        payoffs=(-1.0, 0.5, 0.5, 2.0),
        baseline=0.4,
        lambda_value=0.5,
        lookback_horizon=4,
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
        metadata=NON_BUDGET,
    )
    host = CandidateAction(
        ActionType.ANSWER_DIRECTLY,
        expected_improvement=0.02,
        novelty=1.0,
        confidence=1.0,
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
        metadata=NON_BUDGET,
    )

    decision = Router().decide(
        {
            "host_action": "ANSWER_DIRECTLY",
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.5,
                "lambda_cap": 0.5,
            },
        },
        [host, candidate],
    )

    assert decision.action_type == ActionType.RETRIEVE_CONTEXT
    assert decision.selected_candidate is not None
    assert decision.selected_candidate.admission_score is None
    assert decision.selected_candidate.admission_trace is not None
    assert decision.selected_candidate.effect_vector is not None
    assert candidate.certificate is not None
    assert decision.selected_candidate.effect_vector.utility_bound.lower_bps > 0
    assert (
        decision.selected_candidate.admission_trace.objective_components.utility_lcb_bps
        == decision.selected_candidate.effect_vector.utility_bound.lower_bps
    )


def test_dirichlet_categorical_router_accepts_non_unit_interval_baseline() -> None:
    certificate = build_dirichlet_categorical_certificate(
        arm_id="wide_payoff_arm",
        alpha=(2.0, 4.0, 4.5),
        payoffs=(-1.0, 0.0, 2.0),
        baseline=1.2,
        lambda_value=1.0,
        lookback_horizon=2,
    )

    decision = Router().decide(
        {},
        [
            CandidateAction(
                ActionType.RETRIEVE_CONTEXT,
                certificate=certificate,
            )
        ],
    )

    assert certificate.outcome == CertificateOutcome.LOCKOUT
    assert decision.decision == DecisionType.BLOCK
    assert decision.candidate_decisions[0].short_circuit == "certified_lockout"


def test_typed_certificate_serialization_round_trips_without_scalar_interval() -> None:
    certificate = build_beta_bernoulli_certificate(
        arm_id="arm_2",
        alpha=1.0,
        beta=2.0,
        baseline=0.55,
        lambda_value=0.06,
    )

    payload = certificate.to_dict()

    assert "typed_effect" in payload
    assert "expected_improvement" not in payload
    assert "lower_certificate" not in payload
    assert "upper_certificate" not in payload
    assert "lambda" not in payload
    assert CertificateEvidence.from_dict(payload) == certificate


def test_scalar_only_certificate_payload_is_rejected() -> None:
    scalar_only = {
        "family": "beta_bernoulli",
        "arm_id": "arm_2",
        "baseline": 0.55,
        "lookback_horizon": 3,
        "delight_scale": 1.0,
        "lambda": 0.06,
        "threshold": 0.06,
        "expected_improvement": 0.03,
        "lower_certificate": 0.07,
        "upper_certificate": 0.11,
        "outcome": "inspect",
        "liability_mode": "posterior_certificate",
    }

    try:
        CertificateEvidence.from_dict(scalar_only)
    except (KeyError, ValueError):
        pass
    else:  # pragma: no cover - defensive failure branch
        raise AssertionError("scalar-only certificate payload parsed as typed evidence")
