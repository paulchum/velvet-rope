"""Rescue-risk certificate arithmetic for retirement verdicts.

Given a candidate arm's posterior at the moment a policy proposes retiring it,
these helpers bound the probability that the candidate would have been
rescued: ``protected_threshold`` computes the protected floor
``r = max(z_c(Pi_a), m_a)`` and ``rescue_risk_bound`` evaluates the product
anchor-tail bound ``e_c^prod`` over the separating anchors. If that bound is
below ``delta`` the retirement is delta-safe; otherwise the verdict layer must
answer ``required_inspection`` or ``refusal``.

Category boundary: every quantity here is Bayesian-predictive ([BP]). An
"uncertified kill" means the certificate would not have licensed the
retirement, NOT "the arm was truly better". Canonical statements:
``docs/math/truncation_anchor_tail_certificate.txt`` and
``docs/math/theorem_v_finite_horizon_verdict.txt``.

Ported from the maxde-replay study (``src/replay/certificate.py``) and the
Max-DE response engine (``src/maxde/counterexample.py``), relicensed by the
copyright owner (Coriolis Labs Inc.) under Apache-2.0; see
``src/velvet/verdict/UPSTREAM.md``. The optional Rust replay kernel seam was
intentionally dropped in this port; the SciPy fast path and the Simpson
quadrature fallback are retained.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from velvet.research.actual_kernel import BetaPosterior
from velvet.research.anchor_tail import product_anchor_drop_log_bound
from velvet.research.beta_ei import beta_expected_improvement

_hyp1f1: Callable[[float, float, float], float] | None
try:  # Optional acceleration; quadrature remains the reproducible path.
    from scipy.special import hyp1f1 as _scipy_hyp1f1  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - exercised in minimal environments.
    _hyp1f1 = None
else:
    _hyp1f1 = _scipy_hyp1f1

DEFAULT_GATE = 0.01
DEFAULT_DELTA = 0.05
# Simpson quadrature resolution for the anchor-tail MGF. Lower than the
# upstream theorem-regression default (4001) for throughput; the accuracy
# cross-check against 4001 points is pinned in tests/test_verdict_rescue.py.
DEFAULT_QUADRATURE_POINTS = 1001

ArmPosterior = tuple[int, int]  # (alpha, beta)


def reopen_threshold(
    posterior: BetaPosterior,
    gate_level_c: float,
    *,
    tolerance: float = 1e-12,
) -> float:
    """Return ``z_c(Pi) = sup{v in [0, 1]: psi(Pi, v) >= c}``.

    If the candidate cannot clear the gate even at baseline zero, the set is
    empty and ``-inf`` is returned.
    """

    c = _require_threshold(gate_level_c)
    if tolerance <= 0.0:
        raise ValueError("tolerance must be positive")
    if c == 0.0:
        return 1.0
    if beta_expected_improvement(posterior.alpha, posterior.beta, 0.0) < c:
        return float("-inf")

    low = 0.0
    high = 1.0
    while high - low > tolerance:
        mid = (low + high) / 2.0
        if beta_expected_improvement(posterior.alpha, posterior.beta, mid) >= c:
            low = mid
        else:
            high = mid
    return low


def protected_threshold(posterior: BetaPosterior, gate_level_c: float) -> float:
    """Return the protected floor ``max{z_c(Pi), m(Pi)}`` for the candidate."""

    _require_threshold(gate_level_c)
    return max(reopen_threshold(posterior, gate_level_c), posterior.mean)


def rescue_risk_bound(
    arms: Sequence[ArmPosterior],
    candidate: int,
    gate: float = DEFAULT_GATE,
    *,
    quadrature_points: int = DEFAULT_QUADRATURE_POINTS,
) -> float:
    """Upper bound on the candidate's rescue probability, ``e_c^prod``.

    The protected floor ``r = max(z_c(Pi_a), m_a)`` is computed from the
    candidate's own posterior; anchors are the other arms whose posterior mean
    sits above ``r``. With no separating anchor the bound is ``1.0`` (no
    certified lockout is possible).
    """

    _require_index(arms, candidate)
    cand_alpha, cand_beta = arms[candidate]
    floor = protected_threshold(BetaPosterior(cand_alpha, cand_beta), gate)
    anchors = [
        (alpha, beta)
        for index, (alpha, beta) in enumerate(arms)
        if index != candidate and _mean(alpha, beta) > floor
    ]
    if not anchors:
        return 1.0
    log_error = _product_anchor_drop_log_error(
        anchors,
        floor,
        quadrature_points=quadrature_points,
    )
    return math.exp(log_error)


def rescue_risk_log_bound(
    arms: Sequence[ArmPosterior],
    candidate: int,
    gate: float = DEFAULT_GATE,
    *,
    quadrature_points: int = DEFAULT_QUADRATURE_POINTS,
) -> float:
    """Quadrature-only log upper bound on the candidate rescue probability.

    This helper is intentionally separate from ``rescue_risk_bound``. The
    ordinary per-decision path may use SciPy acceleration; fleet e-BH
    certificates need a reproducible log-space value and record that MGF path
    explicitly, so this helper always uses the Simpson quadrature.
    """

    _require_index(arms, candidate)
    cand_alpha, cand_beta = arms[candidate]
    floor = protected_threshold(BetaPosterior(cand_alpha, cand_beta), gate)
    anchors = [
        (alpha, beta)
        for index, (alpha, beta) in enumerate(arms)
        if index != candidate and _mean(alpha, beta) > floor
    ]
    if not anchors:
        return 0.0
    return _product_anchor_drop_log_error_quadrature(
        anchors,
        floor,
        quadrature_points=quadrature_points,
    )


def _mean(alpha: int, beta: int) -> float:
    return alpha / (alpha + beta)


def _require_threshold(c: float) -> float:
    c = float(c)
    if not math.isfinite(c) or c < 0.0:
        raise ValueError("c must be a finite nonnegative certificate-height threshold")
    return c


def _require_index(arms: Sequence[ArmPosterior], candidate: int) -> None:
    if not isinstance(candidate, int) or candidate < 0 or candidate >= len(arms):
        raise IndexError("candidate index out of range")


def _product_anchor_drop_log_error(
    anchors: Sequence[ArmPosterior],
    r: float,
    *,
    quadrature_points: int,
) -> float:
    if _hyp1f1 is None:
        return _product_anchor_drop_log_error_quadrature(
            anchors,
            r,
            quadrature_points=quadrature_points,
        )
    try:
        logs = [
            _beta_anchor_drop_log_error_fast(alpha, beta, r)
            for alpha, beta in anchors
            if _mean(alpha, beta) > r
        ]
        return math.fsum(logs)
    except Exception:
        return _product_anchor_drop_log_error_quadrature(
            anchors,
            r,
            quadrature_points=quadrature_points,
        )


def _product_anchor_drop_log_error_quadrature(
    anchors: Sequence[ArmPosterior],
    r: float,
    *,
    quadrature_points: int,
) -> float:
    return product_anchor_drop_log_bound(
        anchors,
        r,
        quadrature_points=quadrature_points,
    ).log_error


def _beta_anchor_drop_log_error_fast(
    alpha: int,
    beta: int,
    r: float,
    *,
    opt_tol: float = 1e-10,
) -> float:
    mean = _mean(alpha, beta)
    if r <= 0.0:
        return float("-inf")
    if r >= mean:
        return 0.0

    def objective(lam: float) -> float:
        mgf = _beta_negative_mgf_fast(alpha, beta, lam)
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

    return min(0.0, objective(0.5 * (lo + hi)))


def _beta_negative_mgf_fast(alpha: int, beta: int, lam: float) -> float:
    if _hyp1f1 is None:
        raise ArithmeticError("SciPy hyp1f1 is unavailable")
    value = float(_hyp1f1(alpha, alpha + beta, -lam))
    if not math.isfinite(value) or value < 0.0:
        raise ArithmeticError("SciPy hyp1f1 returned an invalid Beta MGF")
    return value
