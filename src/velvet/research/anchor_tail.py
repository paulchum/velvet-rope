"""Log-safe Bernoulli/Beta anchor-tail helpers.

These helpers support theorem-regression checks for protected-anchor lockout
notes. They compute Bayesian-predictive tail certificates only; they do not
implement a full certification runtime.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class LogChernoffResult:
    """Optimized log Chernoff bound for one Beta anchor."""

    log_error: float
    lambda_star: float


@dataclass(frozen=True)
class ProductAnchorTailBound:
    """Product e-certificate over a fixed separated anchor set."""

    log_error: float
    anchor_indexes: tuple[int, ...]
    component_log_errors: tuple[float, ...]
    lambda_stars: tuple[float, ...]


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


def _log_beta(alpha: int, beta: int) -> float:
    return math.lgamma(alpha) + math.lgamma(beta) - math.lgamma(alpha + beta)


def beta_negative_mgf(
    alpha: int,
    beta: int,
    lam: float,
    *,
    quadrature_points: int = 4001,
) -> float:
    """Return ``E[exp(-lam * X)]`` for ``X ~ Beta(alpha, beta)``.

    Integer-shape Beta posteriors are integrated by Simpson quadrature to keep
    the scaffold dependency-free. The default resolution is intentionally
    conservative for theorem-regression tests.
    """

    _require_positive_int("alpha", alpha)
    _require_positive_int("beta", beta)
    lam = float(lam)
    if not math.isfinite(lam) or lam < 0.0:
        raise ValueError("lam must be finite and nonnegative")
    if quadrature_points < 3:
        raise ValueError("quadrature_points must be at least 3")
    if quadrature_points % 2 == 0:
        quadrature_points += 1
    if lam == 0.0:
        return 1.0

    log_norm = _log_beta(alpha, beta)
    step = 1.0 / (quadrature_points - 1)
    total = 0.0
    for index in range(quadrature_points):
        x = index * step
        if x <= 0.0 or x >= 1.0:
            if alpha > 1 and beta > 1:
                density_part = 0.0
            else:
                clipped = min(max(x, 1e-12), 1.0 - 1e-12)
                density_part = math.exp(
                    -lam * clipped
                    + (alpha - 1) * math.log(clipped)
                    + (beta - 1) * math.log1p(-clipped)
                    - log_norm,
                )
        else:
            density_part = math.exp(
                -lam * x
                + (alpha - 1) * math.log(x)
                + (beta - 1) * math.log1p(-x)
                - log_norm,
            )
        weight = 1 if index in (0, quadrature_points - 1) else (4 if index % 2 else 2)
        total += weight * density_part
    return max(0.0, total * step / 3.0)


def beta_anchor_drop_log_bound(
    alpha: int,
    beta: int,
    r: float,
    *,
    quadrature_points: int = 4001,
    opt_tol: float = 1e-10,
) -> LogChernoffResult:
    """Return ``log inf_lam exp(lam*r) E exp(-lam*theta)`` for one anchor."""

    _require_positive_int("alpha", alpha)
    _require_positive_int("beta", beta)
    r = _require_unit_interval("r", r)
    mean = alpha / (alpha + beta)
    if r <= 0.0:
        return LogChernoffResult(float("-inf"), float("inf"))
    if r >= mean:
        return LogChernoffResult(0.0, 0.0)

    def objective(lam: float) -> float:
        mgf = beta_negative_mgf(
            alpha,
            beta,
            lam,
            quadrature_points=quadrature_points,
        )
        if mgf <= 0.0:
            return float("inf")
        return lam * r + math.log(mgf)

    lo = 0.0
    hi = 1.0
    while objective(hi + 1e-3) < objective(hi) and hi < 1e6:
        hi *= 2.0

    inv_phi = 0.6180339887498949
    x1 = hi - inv_phi * (hi - lo)
    x2 = lo + inv_phi * (hi - lo)
    f1 = objective(x1)
    f2 = objective(x2)
    while hi - lo > opt_tol:
        if f1 < f2:
            hi = x2
            x2 = x1
            f2 = f1
            x1 = hi - inv_phi * (hi - lo)
            f1 = objective(x1)
        else:
            lo = x1
            x1 = x2
            f1 = f2
            x2 = lo + inv_phi * (hi - lo)
            f2 = objective(x2)

    lam_star = 0.5 * (lo + hi)
    return LogChernoffResult(min(0.0, objective(lam_star)), lam_star)


def product_anchor_drop_log_bound(
    anchors: Sequence[tuple[int, int]],
    r: float,
    *,
    quadrature_points: int = 4001,
    opt_tol: float = 1e-10,
) -> ProductAnchorTailBound:
    """Return the product e-certificate over all anchors separated above ``r``."""

    r = _require_unit_interval("r", r)
    indexes: list[int] = []
    logs: list[float] = []
    lambdas: list[float] = []
    for index, (alpha, beta) in enumerate(anchors):
        _require_positive_int("alpha", alpha)
        _require_positive_int("beta", beta)
        if alpha / (alpha + beta) <= r:
            continue
        result = beta_anchor_drop_log_bound(
            alpha,
            beta,
            r,
            quadrature_points=quadrature_points,
            opt_tol=opt_tol,
        )
        indexes.append(index)
        logs.append(result.log_error)
        lambdas.append(result.lambda_star)

    return ProductAnchorTailBound(
        log_error=math.fsum(logs),
        anchor_indexes=tuple(indexes),
        component_log_errors=tuple(logs),
        lambda_stars=tuple(lambdas),
    )
