from __future__ import annotations

import numpy as np

from velvet.research.bernoulli import BernoulliBandit, BetaBernoulliPosterior
from velvet.research.experiment import run_policy
from velvet.research.policies import (
    CertifiedMaxDEPolicy,
    DelightGatedPolicy,
    EpsilonGreedyPolicy,
    schedule_epsilon,
)


def test_uniform_prior_expected_improvement_matches_closed_form() -> None:
    posterior = BetaBernoulliPosterior.uniform_prior(3)

    ei = posterior.expected_improvement(0.5)

    assert np.allclose(ei, np.full(3, 0.125))


def test_beta_one_two_lower_certificate_matches_recovery_window_value() -> None:
    posterior = BetaBernoulliPosterior(
        alpha=np.array([1.0], dtype=np.float64),
        beta=np.array([2.0], dtype=np.float64),
    )

    values = [posterior.lower_certificate(0.5, horizon)[0] for horizon in range(4)]

    assert values[0] <= values[1] <= values[2] <= values[3]
    assert np.isclose(values[3], 0.09209824159135536)


def test_upper_certificate_dominates_tested_lower_certificates() -> None:
    posterior = BetaBernoulliPosterior(
        alpha=np.array([1.0, 2.0, 1.0, 10.0], dtype=np.float64),
        beta=np.array([2.0, 2.0, 6.0, 1.0], dtype=np.float64),
    )

    lower = posterior.lower_certificate(0.5, 3)
    upper = posterior.upper_certificate(0.5)

    assert np.all(upper >= lower)


def test_refined_upper_certificate_matches_regression_fixtures() -> None:
    cases = [
        (2.0, 2.0, 0.1, 4, 0.6377872300, 0.7160520522),
        (1.0, 2.0, 0.5, 3, 0.1339727777, 0.1452044437),
    ]

    for alpha, beta, baseline, horizon, expected_refined, expected_o1 in cases:
        posterior = BetaBernoulliPosterior(
            alpha=np.array([alpha], dtype=np.float64),
            beta=np.array([beta], dtype=np.float64),
        )

        lower = posterior.lower_certificate(baseline, horizon)[0]
        upper = posterior.upper_certificate(baseline)[0]
        refined = posterior.refined_upper_certificate(baseline, horizon)[0]
        refined_path = [
            posterior.refined_upper_certificate(baseline, depth)[0]
            for depth in range(horizon + 1)
        ]

        assert np.isclose(upper, expected_o1, atol=5e-10)
        assert np.isclose(refined, expected_refined, atol=5e-10)
        assert refined >= lower
        assert refined <= upper
        assert all(
            next_value <= current_value
            for current_value, next_value in zip(refined_path, refined_path[1:], strict=False)
        )


def test_compensator_step_records_nonnegative_upper_envelope_increment() -> None:
    posterior = BetaBernoulliPosterior(
        alpha=np.array([1.0], dtype=np.float64),
        beta=np.array([2.0], dtype=np.float64),
    )

    step = posterior.compensator_step(0, baseline=0.5, horizon=3)

    assert step.increment >= 0.0
    assert step.initial_optionality > 0.0
    assert step.cumulative_increment == step.increment


def test_epsilon_schedule_starts_at_one_and_halves_at_half_life() -> None:
    assert schedule_epsilon(100.0, 0) == 1.0
    assert schedule_epsilon(100.0, 100) == 0.5


def test_delight_gate_shuts_off_untried_arms_above_uniform_threshold() -> None:
    posterior = BetaBernoulliPosterior.uniform_prior(4)
    posterior.alpha[0] = 10.0
    posterior.beta[0] = 1.0
    policy = DelightGatedPolicy(gate_price=0.1, surprisal_cap=10.0)

    scores = policy.score(posterior)

    assert scores.baseline > 1.0 - np.sqrt(2.0 * policy.gate_price / policy.surprisal_cap)
    assert not np.any(scores.gate_mask[1:])


def test_certified_max_de_recovers_one_failure_arm_that_myopic_gate_skips() -> None:
    posterior = BetaBernoulliPosterior(
        alpha=np.array([1.0, 1.0], dtype=np.float64),
        beta=np.array([1.0, 2.0], dtype=np.float64),
    )

    myopic = DelightGatedPolicy(gate_price=0.08, surprisal_cap=1.0).score(posterior)
    certified = CertifiedMaxDEPolicy(
        gate_price=0.08,
        lookback_horizon=3,
        surprisal_cap=1.0,
    ).score(posterior)

    assert not myopic.gate_mask[1]
    assert certified.inspect_mask[1]
    assert not certified.lockout_mask[1]


def test_runner_returns_cumulative_regret_trace() -> None:
    bandit = BernoulliBandit(means=np.array([0.2, 0.8], dtype=np.float64))
    trace = run_policy(
        bandit=bandit,
        policy=EpsilonGreedyPolicy(half_life=10.0),
        horizon=25,
        seed=7,
    )

    assert trace.cumulative_regret.shape == (25,)
    assert trace.total_regret >= 0.0
    assert 0.0 <= trace.override_rate <= 1.0
