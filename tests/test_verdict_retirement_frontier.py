from __future__ import annotations

import math

import pytest

from velvet.verdict.retirement_frontier import (
    binary_kl,
    candidate_log_likelihood_ratio,
    directed_comparator_target,
    retirement_regret_lower_bound,
    retirement_sample_lower_bound,
)


def _binomial_probability(n: int, p: float, predicate) -> float:
    return sum(
        math.comb(n, s) * p**s * (1.0 - p) ** (n - s)
        for s in range(n + 1)
        if predicate(s)
    )


def test_never_retire_is_excluded_by_usefulness() -> None:
    with pytest.raises(ValueError, match="useful retirement"):
        retirement_sample_lower_bound(
            useful_retirement_probability=0.0,
            false_retirement_tolerance=0.05,
            retired_mean=0.4,
            comparator_mean=0.6,
        )


def test_retirement_frontier_arithmetic() -> None:
    bound = retirement_sample_lower_bound(
        useful_retirement_probability=0.9,
        false_retirement_tolerance=0.05,
        retired_mean=0.4,
        comparator_mean=0.6,
    )
    assert bound == pytest.approx(binary_kl(0.9, 0.05) / binary_kl(0.4, 0.6))
    assert retirement_regret_lower_bound(
        useful_retirement_probability=0.9,
        false_retirement_tolerance=0.05,
        retired_mean=0.4,
        comparator_mean=0.6,
    ) == pytest.approx(0.2 * bound)


def test_finite_event_obeys_change_of_measure() -> None:
    n = 4
    bad_mean = 0.2
    good_mean = 0.8
    p_retire = _binomial_probability(n, bad_mean, lambda s: s <= 1)
    q_retire = _binomial_probability(n, good_mean, lambda s: s <= 1)
    assert p_retire > q_retire
    assert n * binary_kl(bad_mean, good_mean) >= binary_kl(p_retire, q_retire)


def test_post_lockout_likelihood_ratio_is_frozen() -> None:
    before = candidate_log_likelihood_ratio(
        successes=2, failures=3, mean=0.4, alternative_mean=0.7
    )
    after_other_arm_rewards = before
    assert after_other_arm_rewards == before


def test_binary_kl_boundaries() -> None:
    assert binary_kl(0.0, 0.5) == pytest.approx(math.log(2.0))
    assert binary_kl(1.0, 0.5) == pytest.approx(math.log(2.0))
    assert math.isinf(binary_kl(0.2, 0.0))


def test_directed_comparator_target_is_stable_and_dominant() -> None:
    targets = [directed_comparator_target(n) for n in range(1, 200)]
    assert targets == sorted(targets)
    assert all(target >= n for n, target in enumerate(targets, start=1))
    assert targets[-1] / 199 >= math.log(math.e + 199)
