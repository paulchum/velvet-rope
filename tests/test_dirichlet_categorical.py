from __future__ import annotations

import numpy as np
import pytest

from velvet.research import dirichlet_categorical as dirichlet_module
from velvet.research.bernoulli import BetaBernoulliPosterior
from velvet.research.dirichlet_categorical import (
    DirichletCategoricalPosterior,
    DirichletLowerCertificateDetails,
)


def test_dirichlet_categorical_moments_match_validation_cases() -> None:
    cases = [
        ((2.5, 4.0), (1.0, 0.0), 0.35, 0.09070797645647227, 0.02288699491154872),
        ((2.0, 3.0, 1.5, 4.0), (-1.0, 0.5, 0.5, 2.0), 0.40, 0.406266648, 0.247345474),
        ((3.0, 2.0, 5.0), (-1.0, 0.25, 1.4), 0.10, 0.374105223, 0.214720163),
        (
            (2.0, 1.0, 3.0, 0.5, 4.0),
            (-1.0, 0.0, 0.0, 2.0, 2.0),
            0.60,
            0.179744669,
            0.085298689,
        ),
    ]

    for alpha, payoffs, baseline, expected_m, expected_s in cases:
        posterior = DirichletCategoricalPosterior.from_sequences(alpha, payoffs)

        assert np.isclose(posterior.expected_improvement(baseline), expected_m, atol=5e-8)
        assert np.isclose(posterior.second_moment(baseline), expected_s, atol=5e-8)


def test_dirichlet_pathwise_and_terminal_lower_certificates() -> None:
    cases = [
        ((2.5, 4.0), (1.0, 0.0), 0.35, 0.134896108, 0.269341650),
        ((2.0, 3.0, 1.5, 4.0), (-1.0, 0.5, 0.5, 2.0), 0.40, 0.494864494, 0.963156329),
        ((3.0, 2.0, 5.0), (-1.0, 0.25, 1.4), 0.10, 0.462032526, 0.840084120),
        (
            (2.0, 1.0, 3.0, 0.5, 4.0),
            (-1.0, 0.0, 0.0, 2.0, 2.0),
            0.60,
            0.250109587,
            0.548704785,
        ),
    ]

    for alpha, payoffs, baseline, expected_pathwise, expected_upper in cases:
        posterior = DirichletCategoricalPosterior.from_sequences(alpha, payoffs)
        pathwise = posterior.lower_certificate(baseline, 4, terminal_augmented=False)
        terminal = posterior.lower_certificate(baseline, 4)
        terminal_exact = posterior.lower_certificate(baseline, 4, method="exact")
        upper = posterior.upper_certificate(baseline)
        exact_upper = posterior.upper_certificate(baseline, method="exact")

        assert np.isclose(pathwise, expected_pathwise, atol=5e-8)
        assert terminal >= pathwise
        assert terminal_exact == terminal
        assert exact_upper == upper
        assert upper >= terminal
        assert np.isclose(upper, expected_upper, atol=5e-8)


def test_dirichlet_cheap_lower_is_bounded_and_below_exact() -> None:
    cases = [
        ((2.5, 4.0), (1.0, 0.0), 0.35),
        ((2.0, 3.0, 1.5, 4.0), (-1.0, 0.5, 0.5, 2.0), 0.40),
        ((3.0, 2.0, 5.0), (-1.0, 0.25, 1.4), 0.10),
        ((2.0, 1.0, 3.0, 0.5, 4.0), (-1.0, 0.0, 0.0, 2.0, 2.0), 0.60),
    ]

    for alpha, payoffs, baseline in cases:
        posterior = DirichletCategoricalPosterior.from_sequences(alpha, payoffs)
        cheap = posterior.lower_certificate(baseline, 4, method="cheap")
        exact = posterior.lower_certificate(baseline, 4, method="exact")
        payoff_bound = max(max(payoffs) - baseline, 0.0)

        assert cheap == posterior.cheap_lower_certificate(baseline)
        assert 0.0 <= cheap <= payoff_bound
        assert cheap <= exact


def test_dirichlet_cheap_lower_avoids_exact_grouped_recursion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 1.5, 3.0, 4.0),
        (-1.0, 0.2, 0.8, 2.0),
    )

    def fail_lower_certificate_grouped(
        gamma: tuple[float, ...],
        levels: tuple[float, ...],
        baseline: float,
        horizon: int,
        terminal_augmented: bool,
        quadrature_order: int,
    ) -> float:
        raise AssertionError("cheap lower must not use exact grouped recursion")

    monkeypatch.setattr(
        dirichlet_module,
        "_lower_certificate_grouped",
        fail_lower_certificate_grouped,
    )

    assert posterior.lower_certificate(0.4, 8, method="cheap") > 0.0


def test_dirichlet_monte_carlo_lcb_is_seeded_bounded_and_below_exact() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0, 1.5, 4.0),
        (-1.0, 0.5, 0.5, 2.0),
    )
    delta = 1e-12
    sample_count = 64
    rng = np.random.default_rng(12345)

    mc_lcb = posterior.monte_carlo_lower_certificate(
        0.4,
        4,
        delta=delta,
        sample_count=sample_count,
        rng=rng,
    )
    exact = posterior.lower_certificate(0.4, 4, method="exact")
    payoff_bound = 2.0 - 0.4

    assert 0.0 <= mc_lcb <= payoff_bound
    assert mc_lcb <= exact


def test_dirichlet_monte_carlo_lcb_details_mark_probabilistic() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (3.0, 2.0, 5.0),
        (-1.0, 0.25, 1.4),
    )
    details = posterior.lower_certificate_details(
        0.1,
        3,
        method="mc_lcb",
        delta=1e-12,
        sample_count=64,
        rng=np.random.default_rng(2468),
    )

    assert isinstance(details, DirichletLowerCertificateDetails)
    assert details.method == "mc_lcb"
    assert details.deterministic is False
    assert details.confidence_delta == 1e-12
    assert details.sample_count == 64
    assert details.horizon == 3
    assert details.terminal_augmented is True
    assert details.grouped_level_count == 3


def test_dirichlet_lower_certificate_rejects_invalid_scalable_inputs() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0),
        (0.0, 1.0),
    )

    with pytest.raises(ValueError, match="method"):
        posterior.lower_certificate(0.5, 2, method="bogus")
    with pytest.raises(ValueError, match="horizon"):
        posterior.lower_certificate(0.5, -1, method="cheap")
    with pytest.raises(ValueError, match="delta"):
        posterior.lower_certificate(0.5, 2, method="mc_lcb")
    with pytest.raises(ValueError, match="delta"):
        posterior.lower_certificate(0.5, 2, method="mc_lcb", delta=0.0)
    with pytest.raises(ValueError, match="delta"):
        posterior.lower_certificate(0.5, 2, method="mc_lcb", delta=1.0)
    with pytest.raises(ValueError, match="sample_count"):
        posterior.lower_certificate(0.5, 2, method="mc_lcb", delta=0.05, sample_count=0)


def test_dirichlet_repeated_payoff_aggregation_is_exact() -> None:
    original = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0, 1.5, 4.0),
        (-1.0, 0.5, 0.5, 2.0),
    )
    grouped = DirichletCategoricalPosterior.from_sequences(
        (2.0, 4.5, 4.0),
        (-1.0, 0.5, 2.0),
    )

    assert np.isclose(original.expected_improvement(0.4), grouped.expected_improvement(0.4))
    assert np.isclose(original.second_moment(0.4), grouped.second_moment(0.4))
    assert np.isclose(original.lower_certificate(0.4, 3), grouped.lower_certificate(0.4, 3))
    assert np.isclose(original.upper_certificate(0.4), grouped.upper_certificate(0.4))


def test_dirichlet_bernoulli_reduction_matches_beta_bernoulli() -> None:
    dirichlet = DirichletCategoricalPosterior.from_sequences(
        (2.5, 4.0),
        (1.0, 0.0),
    )
    beta = BetaBernoulliPosterior(
        alpha=np.array([2.5], dtype=np.float64),
        beta=np.array([4.0], dtype=np.float64),
    )

    assert np.isclose(dirichlet.expected_improvement(0.35), beta.expected_improvement(0.35)[0])
    assert np.isclose(dirichlet.lower_certificate(0.35, 4), beta.lower_certificate(0.35, 4)[0])
    assert np.isclose(
        dirichlet.lower_certificate(0.35, 4, method="exact"),
        beta.lower_certificate(0.35, 4)[0],
    )
    assert np.isclose(dirichlet.upper_certificate(0.35), beta.upper_certificate(0.35)[0])
    assert np.isclose(
        dirichlet.upper_certificate(0.35, method="moment"),
        beta.upper_certificate(0.35)[0],
    )


def test_dirichlet_moment_upper_uses_verified_one_sided_q_fixture() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0, 1.5, 4.0),
        (-1.0, 0.5, 0.5, 2.0),
    )

    m_v = posterior.expected_improvement(0.4)
    s_v = posterior.second_moment(0.4)
    q_v = posterior.second_moment(0.4 + m_v)
    exact_upper = posterior.upper_certificate(0.4, method="exact")
    moment_upper = posterior.upper_certificate(0.4, method="moment")

    assert np.isclose(exact_upper, 0.9631563286520408)
    assert np.isclose(q_v, 0.044915903026346696)
    assert np.isclose(moment_upper, 0.830134094132821)
    assert q_v <= s_v - m_v**2
    assert moment_upper <= exact_upper


def test_dirichlet_scalable_upper_delegates_to_moment_method() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (3.0, 2.0, 5.0),
        (-1.0, 0.25, 1.4),
    )

    assert posterior.scalable_upper_certificate(0.1) == posterior.upper_certificate(
        0.1,
        method="moment",
    )


def test_dirichlet_upper_certificate_rejects_invalid_method() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0),
        (0.0, 1.0),
    )

    with pytest.raises(ValueError, match="method"):
        posterior.upper_certificate(0.5, method="bogus")


def test_dirichlet_moment_upper_zero_conventions() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0, 4.0),
        (-2.0, -1.0, 0.0),
    )

    assert posterior.upper_certificate(0.0, method="moment") == 0.0
    assert posterior.scalable_upper_certificate(0.0) == 0.0


def test_dirichlet_j4_scalable_upper_avoids_exact_positive_part_moments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 1.5, 3.0, 4.0),
        (-1.0, 0.2, 0.8, 2.0),
    )

    def fail_positive_part_moment(
        gamma: tuple[float, ...],
        levels: tuple[float, ...],
        baseline: float,
        power: int,
        quadrature_order: int,
    ) -> float:
        raise AssertionError("scalable J>=4 path must not use exact positive-part moments")

    monkeypatch.setattr(
        dirichlet_module,
        "_positive_part_moment_cached",
        fail_positive_part_moment,
    )

    assert posterior.scalable_upper_certificate(0.4) > 0.0


def test_dirichlet_j4_moment_upper_dominates_exact_finite_horizon_lower() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 1.5, 3.0, 4.0),
        (-1.0, 0.2, 0.8, 2.0),
    )

    lower = posterior.lower_certificate(0.4, 2)
    upper = posterior.scalable_upper_certificate(0.4)

    assert upper >= lower


def test_dirichlet_refined_upper_dominates_lower_and_tightens_o1() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (2.0, 3.0, 1.5, 4.0),
        (-1.0, 0.5, 0.5, 2.0),
    )

    refined_values = [posterior.refined_upper_certificate(0.4, horizon) for horizon in range(3)]

    assert refined_values[2] >= posterior.lower_certificate(0.4, 2)
    assert refined_values[1] <= posterior.upper_certificate(0.4, method="exact")
    assert refined_values == sorted(refined_values, reverse=True)


def test_dirichlet_martingale_identity_residual_is_small() -> None:
    posterior = DirichletCategoricalPosterior.from_sequences(
        (3.0, 2.0, 5.0),
        (-1.0, 0.25, 1.4),
    )

    assert posterior.martingale_residual(0.1, 4) < 1e-6
