from __future__ import annotations

import numpy as np
import pytest

from velvet.research.gamma_rate import (
    GAMMA_RATE_FAMILY,
    GammaRateAdmissionVerdict,
    GammaRateCertificateMethod,
    GammaRatePosteriorSpec,
    certified_gamma_rate_candidate,
    gamma_rate_bounds,
    gamma_rate_tail_first_moment,
    gamma_rate_tail_probability,
    gamma_rate_tail_second_moment,
    l2_upper_certificate,
    m_v_plus,
    monte_carlo_lcb,
    positive_part_moments,
    q_v_plus,
    s_v_plus,
)

ALPHA = 2.0
BETA = 1.0
BASELINE = 1.0


def test_gamma_rate_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="alpha"):
        GammaRatePosteriorSpec(alpha=0.0, beta=BETA, baseline=BASELINE)
    with pytest.raises(ValueError, match="beta"):
        GammaRatePosteriorSpec(alpha=ALPHA, beta=0.0, baseline=BASELINE)
    with pytest.raises(ValueError, match="baseline"):
        GammaRatePosteriorSpec(alpha=ALPHA, beta=BETA, baseline=-0.1)


def test_gamma_rate_family_is_explicit() -> None:
    spec = GammaRatePosteriorSpec(alpha=ALPHA, beta=BETA, baseline=BASELINE)

    assert spec.family == GAMMA_RATE_FAMILY
    with pytest.raises(ValueError, match="family"):
        GammaRatePosteriorSpec(
            alpha=ALPHA,
            beta=BETA,
            baseline=BASELINE,
            family="gamma",
        )


def test_gamma_rate_mean_and_variance_formulas() -> None:
    spec = GammaRatePosteriorSpec(alpha=3.5, beta=2.0, baseline=0.4)

    assert spec.mean == 1.75
    assert spec.variance == 0.875


def test_gamma_rate_tail_helpers_match_closed_form_fixture() -> None:
    assert np.isclose(
        gamma_rate_tail_probability(ALPHA, BETA, BASELINE),
        0.7357588823428847,
        atol=1e-12,
    )
    assert np.isclose(
        gamma_rate_tail_first_moment(ALPHA, BETA, BASELINE),
        1.8393972058572117,
        atol=1e-12,
    )
    assert np.isclose(
        gamma_rate_tail_second_moment(ALPHA, BETA, BASELINE),
        5.886071058743077,
        atol=1e-12,
    )


def test_gamma_rate_verified_positive_part_fixtures() -> None:
    moments = positive_part_moments(ALPHA, BETA, BASELINE)
    bounds = gamma_rate_bounds(ALPHA, BETA, BASELINE)

    assert np.isclose(m_v_plus(ALPHA, BETA, BASELINE), 1.1036383235, atol=1e-9)
    assert np.isclose(s_v_plus(ALPHA, BETA, BASELINE), 2.9430355294, atol=1e-9)
    assert np.isclose(q_v_plus(ALPHA, BETA, BASELINE), 1.2454071931, atol=1e-9)
    assert np.isclose(l2_upper_certificate(ALPHA, BETA, BASELINE), 3.3355945893, atol=1e-9)

    assert np.isclose(moments.mean_positive_part, 1.1036383235, atol=1e-9)
    assert np.isclose(moments.second_moment_positive_part, 2.9430355294, atol=1e-9)
    assert np.isclose(moments.q_positive_part, 1.2454071931, atol=1e-9)
    assert np.isclose(bounds.preferred_upper_bound, 3.3355945893, atol=1e-9)


def test_gamma_rate_shifted_q_regression_inequality() -> None:
    moments = positive_part_moments(ALPHA, BETA, BASELINE)

    assert moments.q_positive_part <= (
        moments.second_moment_positive_part - moments.mean_positive_part**2
    )


def test_gamma_rate_exposes_no_bounded_log_envelope_upper() -> None:
    payload = gamma_rate_bounds(ALPHA, BETA, BASELINE).to_dict()

    assert payload["bounded_payoff_cap"] == "infinity"
    assert "log_envelope_upper" not in payload
    assert "bounded_log_envelope_upper" not in payload


def test_gamma_rate_fallback_upper_is_looser_than_shifted_q_upper() -> None:
    bounds = gamma_rate_bounds(ALPHA, BETA, BASELINE)

    assert bounds.fallback_upper_bound >= bounds.preferred_upper_bound


def test_gamma_rate_monte_carlo_estimate_matches_closed_form_with_fixed_seed() -> None:
    result = monte_carlo_lcb(
        ALPHA,
        BETA,
        BASELINE,
        sample_count=200_000,
        delta=0.05,
        seed=12345,
    )

    assert np.isclose(result.empirical_mean, m_v_plus(ALPHA, BETA, BASELINE), atol=0.02)


def test_gamma_rate_monte_carlo_lcb_is_below_empirical_mean() -> None:
    result = monte_carlo_lcb(
        ALPHA,
        BETA,
        BASELINE,
        sample_count=32_000,
        delta=0.1,
        seed=2468,
    )

    assert 0.0 <= result.lower_confidence_bound <= result.empirical_mean


def test_gamma_rate_certificates_serialize_canonically() -> None:
    spec = GammaRatePosteriorSpec(
        alpha=ALPHA,
        beta=BETA,
        baseline=BASELINE,
        arm_id="incident_rate",
    )

    first = spec.l2_upper_certificate()
    second = spec.l2_upper_certificate()

    assert first.to_dict() == second.to_dict()
    assert first.payload_hash() == second.payload_hash()
    assert first.method == GammaRateCertificateMethod.L2_UPPER


def test_gamma_rate_reserve_admits_when_lower_clears_price() -> None:
    decision = certified_gamma_rate_candidate(
        alpha=ALPHA,
        beta=BETA,
        baseline=BASELINE,
        reserve_price=1.0,
    )

    assert decision.admit is True
    assert decision.verdict == GammaRateAdmissionVerdict.INSPECT
    assert decision.lower_method == GammaRateCertificateMethod.DETERMINISTIC_ONE_STEP_LOWER


def test_gamma_rate_reserve_rejects_when_upper_cannot_clear_price() -> None:
    decision = certified_gamma_rate_candidate(
        alpha=ALPHA,
        beta=BETA,
        baseline=BASELINE,
        reserve_price=4.0,
    )

    assert decision.admit is False
    assert decision.verdict == GammaRateAdmissionVerdict.REJECT


def test_gamma_rate_reserve_refines_when_lower_does_not_clear_but_upper_might() -> None:
    decision = certified_gamma_rate_candidate(
        alpha=ALPHA,
        beta=BETA,
        baseline=BASELINE,
        reserve_price=2.0,
    )

    assert decision.admit is False
    assert decision.verdict == GammaRateAdmissionVerdict.REFINEMENT


def test_gamma_rate_reserve_price_is_not_a_certificate_method() -> None:
    methods = {item.value for item in GammaRateCertificateMethod}

    assert "reserve_priced_lower" not in methods
