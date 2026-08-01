"""Fixed-mean retirement-frontier arithmetic.

The theorem is in ``docs/math/useful_retirement_frontier.txt``. These helpers
are theorem-regression utilities, not a retirement policy implementation.
"""

from __future__ import annotations

import math


def binary_kl(p: float, q: float) -> float:
    """Bernoulli relative entropy with standard boundary conventions."""

    if not 0.0 <= p <= 1.0 or not 0.0 <= q <= 1.0:
        raise ValueError("Bernoulli parameters must lie in [0, 1]")
    if p == q:
        return 0.0
    if q == 0.0:
        return math.inf if p > 0.0 else 0.0
    if q == 1.0:
        return math.inf if p < 1.0 else 0.0
    left = 0.0 if p == 0.0 else p * math.log(p / q)
    right = 0.0 if p == 1.0 else (1.0 - p) * math.log((1.0 - p) / (1.0 - q))
    return left + right


def retirement_sample_lower_bound(
    *,
    useful_retirement_probability: float,
    false_retirement_tolerance: float,
    retired_mean: float,
    comparator_mean: float,
) -> float:
    """Return d(p, delta) / kl(mu_a, mu_star)."""

    p = useful_retirement_probability
    delta = false_retirement_tolerance
    if not 0.0 <= delta < p <= 1.0:
        raise ValueError("useful retirement requires 0 <= delta < p <= 1")
    if not 0.0 <= retired_mean < comparator_mean <= 1.0:
        raise ValueError("require 0 <= retired_mean < comparator_mean <= 1")
    information = binary_kl(retired_mean, comparator_mean)
    if information == 0.0:
        return math.inf
    return binary_kl(p, delta) / information


def retirement_regret_lower_bound(**kwargs: float) -> float:
    """Return the candidate-pull regret implied by the sample lower bound."""

    sample_bound = retirement_sample_lower_bound(**kwargs)
    gap = kwargs["comparator_mean"] - kwargs["retired_mean"]
    return gap * sample_bound


def candidate_log_likelihood_ratio(
    *, successes: int, failures: int, mean: float, alternative_mean: float
) -> float:
    """Log likelihood ratio contributed by the candidate's observed rewards."""

    if successes < 0 or failures < 0:
        raise ValueError("counts must be nonnegative")
    if not 0.0 < mean < 1.0 or not 0.0 < alternative_mean < 1.0:
        raise ValueError("likelihood-ratio means must lie in (0, 1)")
    return successes * math.log(mean / alternative_mean) + failures * math.log(
        (1.0 - mean) / (1.0 - alternative_mean)
    )


def directed_comparator_target(candidate_count: int) -> int:
    """Comparator count used by the directed retirement audit at stage n."""

    if candidate_count < 1:
        raise ValueError("candidate_count must be positive")
    return math.ceil(candidate_count * math.log(math.e + candidate_count))
