"""Dependency-free Beta posterior means and expected-improvement helpers."""

from __future__ import annotations

import math

_LOGSUM_BINOMIAL_MAX_N = 512
_BETA_CF_MAX_ITERATIONS = 10_000
_BETA_CF_EPSILON = 3e-14
_BETA_CF_FPMIN = 1e-300


def _require_positive_int(name: str, value: int) -> None:
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_unit_interval(name: str, value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if value < 0.0 or value > 1.0:
        raise ValueError(f"{name} must lie in [0, 1]")
    return value


def beta_mean(alpha: int, beta: int) -> float:
    """Return the mean of ``Beta(alpha, beta)``."""

    _require_positive_int("alpha", alpha)
    _require_positive_int("beta", beta)
    return alpha / (alpha + beta)


def beta_upper_tail(alpha: int, beta: int, v: float) -> float:
    """Return ``P[X > v]`` for integer-shape ``X ~ Beta(alpha, beta)``."""

    _require_positive_int("alpha", alpha)
    _require_positive_int("beta", beta)
    v = _require_unit_interval("v", v)
    if v <= 0.0:
        return 1.0
    if v >= 1.0:
        return 0.0

    n = alpha + beta - 1
    if n <= _LOGSUM_BINOMIAL_MAX_N:
        tail = _binomial_cdf_logsum(n, alpha - 1, v)
    else:
        tail = _beta_upper_tail_continued_fraction(alpha, beta, v)
    return min(1.0, max(0.0, tail))


def beta_expected_improvement(alpha: int, beta: int, v: float) -> float:
    """Return ``E[(X - v)^+]`` for ``X ~ Beta(alpha, beta)``."""

    v = _require_unit_interval("v", v)
    if v <= 0.0:
        return beta_mean(alpha, beta)
    if v >= 1.0:
        return 0.0

    tail = beta_upper_tail(alpha, beta, v)
    moment_tail = beta_mean(alpha, beta) * beta_upper_tail(alpha + 1, beta, v)
    expected_improvement = moment_tail - v * tail
    return max(0.0, expected_improvement)


def _binomial_cdf_logsum(n: int, k: int, p: float) -> float:
    """Return ``P[Binomial(n, p) <= k]`` by shifted log-space summation."""

    if k < 0:
        return 0.0
    if k >= n:
        return 1.0

    lower_terms = k + 1
    upper_terms = n - k
    if lower_terms <= upper_terms:
        log_sum = _binomial_logsum_range(n, 0, k, p)
        return math.exp(log_sum) if math.isfinite(log_sum) else 0.0

    log_upper = _binomial_logsum_range(n, k + 1, n, p)
    if not math.isfinite(log_upper):
        return 1.0
    return _one_minus_exp(log_upper)


def _binomial_logsum_range(n: int, start: int, end: int, p: float) -> float:
    """Return ``log(sum_{j=start}^end Bin(n,j) p^j (1-p)^(n-j))``."""

    if start > end:
        return float("-inf")

    log_p = math.log(p)
    log_q = math.log1p(-p)
    log_term = (
        math.lgamma(n + 1)
        - math.lgamma(start + 1)
        - math.lgamma(n - start + 1)
        + start * log_p
        + (n - start) * log_q
    )
    max_log = log_term
    scaled_sum = 1.0

    for j in range(start, end):
        log_term += math.log(n - j) - math.log(j + 1) + log_p - log_q
        if log_term > max_log:
            scaled_sum = scaled_sum * math.exp(max_log - log_term) + 1.0
            max_log = log_term
        else:
            scaled_sum += math.exp(log_term - max_log)

    return max_log + math.log(scaled_sum)


def _beta_upper_tail_continued_fraction(alpha: int, beta: int, v: float) -> float:
    """Return the upper Beta tail using the regularized incomplete beta."""

    threshold = (alpha + 1.0) / (alpha + beta + 2.0)
    if v < threshold:
        lower = _regularized_beta_lower_direct(alpha, beta, v)
        return 1.0 - lower
    return _regularized_beta_lower_direct(beta, alpha, 1.0 - v)


def _regularized_beta_lower_direct(a: int, b: int, x: float) -> float:
    """Return the direct continued-fraction formula for ``I_x(a,b)``."""

    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0

    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    if log_bt == float("-inf"):
        return 0.0
    value = math.exp(log_bt) * _beta_continued_fraction(a, b, x) / a
    return min(1.0, max(0.0, value))


def _beta_continued_fraction(a: int, b: int, x: float) -> float:
    """Evaluate the incomplete-beta continued fraction."""

    qab = a + b
    qap = a + 1.0
    qam = a - 1.0

    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _BETA_CF_FPMIN:
        d = _BETA_CF_FPMIN
    d = 1.0 / d
    h = d

    for m in range(1, _BETA_CF_MAX_ITERATIONS + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_CF_FPMIN:
            d = _BETA_CF_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_CF_FPMIN:
            c = _BETA_CF_FPMIN
        d = 1.0 / d
        h *= d * c

        aa = -((a + m) * (qab + m) * x) / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_CF_FPMIN:
            d = _BETA_CF_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_CF_FPMIN:
            c = _BETA_CF_FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta

        if abs(delta - 1.0) <= _BETA_CF_EPSILON:
            return h

    raise ArithmeticError("incomplete beta continued fraction did not converge")


def _one_minus_exp(log_value: float) -> float:
    """Return ``1 - exp(log_value)`` accurately for ``log_value <= 0``."""

    if log_value >= 0.0:
        return 0.0
    if log_value > -0.6931471805599453:
        return -math.expm1(log_value)
    return 1.0 - math.exp(log_value)
