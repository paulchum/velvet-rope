from __future__ import annotations

import math
from fractions import Fraction

import pytest

from velvet.research.actual_kernel import (
    BernoulliState,
    BetaPosterior,
    candidate_excluded_baseline,
    enumerate_transitions,
    host_arm,
    host_override_probabilities,
    kernel_expectation,
    moving_certificate,
)


def _beta_func_integer(alpha: int, beta: int) -> Fraction:
    numerator = math.factorial(alpha - 1) * math.factorial(beta - 1)
    denominator = math.factorial(alpha + beta - 1)
    return Fraction(numerator, denominator)


def _psi_beta_integer(alpha: int, beta: int, v: Fraction) -> Fraction:
    if v <= 0:
        return Fraction(alpha, alpha + beta)
    if v >= 1:
        return Fraction(0, 1)

    total = Fraction(0, 1)
    for j in range(beta):
        coeff = Fraction((-1) ** j * math.comb(beta - 1, j), 1)
        power = alpha + j
        term = (1 - v ** (power + 1)) / (power + 1) - v * (
            (1 - v**power) / power
        )
        total += coeff * term
    return total / _beta_func_integer(alpha, beta)


def _mean(alpha: tuple[int, ...], beta: tuple[int, ...], arm: int) -> Fraction:
    return Fraction(alpha[arm], alpha[arm] + beta[arm])


def _update(
    alpha: tuple[int, ...],
    beta: tuple[int, ...],
    arm: int,
    success: bool,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    alpha_next = list(alpha)
    beta_next = list(beta)
    if success:
        alpha_next[arm] += 1
    else:
        beta_next[arm] += 1
    return tuple(alpha_next), tuple(beta_next)


def _excluded_baseline(
    alpha: tuple[int, ...],
    beta: tuple[int, ...],
    candidate: int,
) -> Fraction:
    return max(_mean(alpha, beta, arm) for arm in range(len(alpha)) if arm != candidate)


def _exact_certificate(alpha: tuple[int, ...], beta: tuple[int, ...], candidate: int) -> Fraction:
    baseline = _excluded_baseline(alpha, beta, candidate)
    return _psi_beta_integer(alpha[candidate], beta[candidate], baseline)


def _branch_expected_certificate(
    alpha: tuple[int, ...],
    beta: tuple[int, ...],
    candidate: int,
    pulled_arm: int,
) -> Fraction:
    success_alpha, success_beta = _update(alpha, beta, pulled_arm, True)
    failure_alpha, failure_beta = _update(alpha, beta, pulled_arm, False)
    mean = _mean(alpha, beta, pulled_arm)
    return mean * _exact_certificate(success_alpha, success_beta, candidate) + (
        1 - mean
    ) * _exact_certificate(failure_alpha, failure_beta, candidate)


def _branch_drift(
    alpha: tuple[int, ...],
    beta: tuple[int, ...],
    candidate: int,
    pulled_arm: int,
) -> Fraction:
    expected = _branch_expected_certificate(alpha, beta, candidate, pulled_arm)
    return expected - _exact_certificate(
        alpha,
        beta,
        candidate,
    )


def _one_step_crossing_probability(
    alpha: tuple[int, ...],
    beta: tuple[int, ...],
    candidate: int,
    probabilities: tuple[Fraction, ...],
    threshold: Fraction,
) -> Fraction:
    total = Fraction(0, 1)
    for arm, probability in enumerate(probabilities):
        mean = _mean(alpha, beta, arm)
        success_alpha, success_beta = _update(alpha, beta, arm, True)
        failure_alpha, failure_beta = _update(alpha, beta, arm, False)
        if _exact_certificate(success_alpha, success_beta, candidate) >= threshold:
            total += probability * mean
        if _exact_certificate(failure_alpha, failure_beta, candidate) >= threshold:
            total += probability * (1 - mean)
    return total


def test_host_and_candidate_excluded_certificate() -> None:
    state = BernoulliState((BetaPosterior(1, 1), BetaPosterior(3, 3), BetaPosterior(2, 1)))
    assert host_arm(state) == 2
    assert candidate_excluded_baseline(state, 1) == pytest.approx(2.0 / 3.0)
    assert moving_certificate(state, 1) >= 0.0


def test_host_override_probabilities_respect_mixture() -> None:
    state = BernoulliState((BetaPosterior(2, 2), BetaPosterior(3, 1)))

    def q_rule(t: int, x: BernoulliState) -> tuple[float, float]:
        return (1.0, 0.0)

    probabilities = host_override_probabilities(
        state,
        t=3,
        exploration_mass=1.0,
        override_rule=q_rule,
    )
    assert probabilities == pytest.approx((0.25, 0.75))
    assert math.fsum(probabilities) == pytest.approx(1.0)


def test_enumerate_transitions_updates_exactly_one_arm() -> None:
    state = BernoulliState((BetaPosterior(2, 2), BetaPosterior(3, 1)))
    transitions = enumerate_transitions(state, t=0, exploration_mass=1.0)
    assert math.fsum(transition.probability for transition in transitions) == pytest.approx(1.0)
    assert {transition.action for transition in transitions} == {1}

    for transition in transitions:
        changed = [
            index
            for index, (before, after) in enumerate(
                zip(state.arms, transition.state.arms, strict=True)
            )
            if before != after
        ]
        assert changed == [transition.action]


def test_candidate_update_is_bayesian_predictive_neutral_for_certificate() -> None:
    state = BernoulliState((BetaPosterior(2, 2), BetaPosterior(3, 2)))
    candidate = 0
    candidate_mean = state.arms[candidate].mean
    current = moving_certificate(state, candidate)
    after_candidate_update = (
        candidate_mean * moving_certificate(state.update(candidate, 1), candidate)
        + (1.0 - candidate_mean) * moving_certificate(state.update(candidate, 0), candidate)
    )
    assert after_candidate_update == pytest.approx(current)


def test_kernel_expectation_uses_actual_transition_weights() -> None:
    state = BernoulliState((BetaPosterior(2, 2), BetaPosterior(3, 1)))

    def q_rule(t: int, x: BernoulliState) -> tuple[float, float]:
        return (1.0, 0.0)

    expected_action = kernel_expectation(
        state,
        t=3,
        exploration_mass=1.0,
        override_rule=q_rule,
        value_function=lambda next_state: float(
            next_state.arms[0].alpha + next_state.arms[0].beta
        ),
    )
    assert expected_action == pytest.approx(4.25)


def test_exact_candidate_update_has_zero_bayesian_predictive_drift() -> None:
    states = [
        ((1, 20), (1, 10)),
        ((1, 2), (1, 1)),
        ((1, 1, 1), (1, 1, 1)),
        ((3, 2, 5), (4, 3, 2)),
    ]

    for alpha, beta in states:
        for candidate in range(len(alpha)):
            assert _branch_drift(alpha, beta, candidate, candidate) == 0


def test_exact_noncandidate_drift_can_be_positive_or_negative() -> None:
    assert _branch_drift((1, 2), (1, 1), candidate=0, pulled_arm=1) == Fraction(
        1,
        144,
    )
    assert _branch_drift((1, 1, 1), (1, 1, 1), candidate=0, pulled_arm=1) == Fraction(
        -5,
        144,
    )


def test_exact_candidate_clock_overstates_actual_one_pull_crossing() -> None:
    alpha = (1, 20)
    beta = (1, 10)
    threshold = Fraction(9, 100)

    artificial_probability = _one_step_crossing_probability(
        alpha,
        beta,
        candidate=0,
        probabilities=(Fraction(1, 1), Fraction(0, 1)),
        threshold=threshold,
    )
    actual_probability = _one_step_crossing_probability(
        alpha,
        beta,
        candidate=0,
        probabilities=(Fraction(1, 10), Fraction(9, 10)),
        threshold=threshold,
    )

    assert artificial_probability == Fraction(1, 2)
    assert actual_probability == Fraction(1, 20)
