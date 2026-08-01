"""pass^k reliability estimates for repeated benchmark runs."""

from __future__ import annotations

from collections.abc import Sequence
from math import comb

JsonObject = dict[str, float | None]

DEFAULT_PASS_K_VALUES = (1, 2, 5, 10, 20)


def pass_k_estimate(success_count: int, sample_count: int, k: int) -> float | None:
    """Estimate probability that all k sampled runs are successful."""

    if k < 1:
        raise ValueError("k must be at least 1")
    if sample_count < 0:
        raise ValueError("sample_count must be non-negative")
    if success_count < 0:
        raise ValueError("success_count must be non-negative")
    if success_count > sample_count:
        raise ValueError("success_count cannot exceed sample_count")
    if sample_count < k:
        return None
    if success_count < k:
        return 0.0
    return comb(success_count, k) / comb(sample_count, k)


def pass_k_curve(
    run_successes: Sequence[bool],
    *,
    k_values: Sequence[int] = DEFAULT_PASS_K_VALUES,
) -> JsonObject:
    """Return pass^k estimates for the supported k values in a run set."""

    sample_count = len(run_successes)
    success_count = sum(1 for item in run_successes if item)
    curve: JsonObject = {}
    for k in k_values:
        estimate = pass_k_estimate(success_count, sample_count, k)
        if estimate is not None:
            curve[str(k)] = round(float(estimate), 6)
    return curve
