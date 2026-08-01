"""Pointwise protected-anchor truncation certificates.

This module implements dependency-free Bayesian-predictive certificate
arithmetic for small Bernoulli/Beta states. It is a theorem-regression
companion to ``docs/math/truncation_anchor_tail_certificate.txt``; it is not a
fixed-mu regret layer.

Ported from the Max-DE response engine (``src/maxde/truncation_certificate.py``),
relicensed by the copyright owner (Coriolis Labs Inc.) under Apache-2.0; see
``src/velvet/verdict/UPSTREAM.md``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from functools import cache, lru_cache

from velvet.research.actual_kernel import (
    BernoulliState,
    BetaPosterior,
    OverrideRule,
    enumerate_transitions,
    host_delta_override,
    moving_certificate,
)
from velvet.research.anchor_tail import product_anchor_drop_log_bound
from velvet.research.beta_ei import beta_expected_improvement
from velvet.research.crossing_dp import finite_horizon_crossing_probability


class CertificationStatus(str, Enum):
    """Lockout certificate status values from the truncation note."""

    CertifiedSafe = "CertifiedSafe"
    CertifiedNotSafe = "CertifiedNotSafe"
    UncertifiedNeedsRefinement = "UncertifiedNeedsRefinement"
    UncertifiedNeedsMoreHorizon = "UncertifiedNeedsMoreHorizon"


@dataclass(frozen=True)
class AnchorTailSummary:
    """Terminal protected-anchor tail arithmetic at one concrete state."""

    protected_floor: float
    anchor_indexes: tuple[int, ...]
    l2_value: float
    l2_anchor: int | None
    product_value: float
    product_log_error: float
    product_anchor_indexes: tuple[int, ...]
    product_component_log_errors: tuple[float, ...]
    product_lambda_stars: tuple[float, ...]
    final_value: float
    final_method: str
    product_certified: bool


@dataclass(frozen=True)
class CertificateDecision:
    """Pointwise lockout decision with both probability and value scales."""

    status: CertificationStatus
    candidate: int
    c: float
    delta: float
    horizon: int
    finite_horizon_crossing_probability: float
    terminal_tail: AnchorTailSummary
    terminal_tail_probability_contribution: float
    total_probability_upper_bound: float
    total_certified_upper_bound: float
    safety_threshold: float

    @property
    def margin(self) -> float:
        return self.safety_threshold - self.total_certified_upper_bound


def certify_lockout(
    state: BernoulliState,
    candidate: int,
    c: float,
    delta: float,
    horizon: int,
    *,
    start_time: int = 0,
    exploration_mass: float = 0.0,
    override_rule: OverrideRule = host_delta_override,
    quadrature_points: int = 801,
    opt_tol: float = 1e-8,
    tail_loaded_use_product: bool = True,
) -> CertificateDecision:
    """Return a pointwise protected-anchor lockout certificate.

    ``c`` is the certificate-height threshold. ``delta`` is the probability
    tolerance. The safe comparison is made on value scale against ``c*delta``.
    """

    c = _require_positive("c", c)
    delta = _require_probability_tolerance(delta)
    _require_horizon(horizon)
    _require_candidate(state, candidate)

    # Regression companion to truncation_certificate.md. The canonical note now
    # certifies the host-aware rescue set (Theorem V); this pointwise module
    # evaluates the note's gate-only *lower diagnostic* (Corollary V.2). Its
    # tail-loaded recursion below stops on the gate channel only, so the finite
    # term is the matching gate-only crossing probability (host_aware=False). A
    # host-aware certified evaluation sets host_aware=True; see the note's
    # Section 2.1 and crossing_dp.finite_horizon_crossing_probability.
    finite = finite_horizon_crossing_probability(
        state,
        candidate,
        c,
        horizon,
        start_time=start_time,
        exploration_mass=exploration_mass,
        override_rule=override_rule,
        host_aware=False,
    )
    total_probability = tail_loaded_crossing_probability_bound(
        state,
        candidate,
        c,
        horizon,
        start_time=start_time,
        exploration_mass=exploration_mass,
        override_rule=override_rule,
        quadrature_points=quadrature_points,
        opt_tol=opt_tol,
        use_product_tail=tail_loaded_use_product,
    )
    total_value = c * total_probability
    safety_threshold = c * delta
    terminal_tail = protected_anchor_tail(
        state,
        candidate,
        c,
        quadrature_points=quadrature_points,
        opt_tol=opt_tol,
    )
    tail_contribution = max(0.0, total_probability - finite)

    status = _classify_status(
        finite_horizon_crossing_probability=finite,
        total_certified_upper_bound=total_value,
        safety_threshold=safety_threshold,
        delta=delta,
        terminal_tail=terminal_tail,
        terminal_tail_probability_contribution=tail_contribution,
    )

    return CertificateDecision(
        status=status,
        candidate=candidate,
        c=c,
        delta=delta,
        horizon=horizon,
        finite_horizon_crossing_probability=finite,
        terminal_tail=terminal_tail,
        terminal_tail_probability_contribution=tail_contribution,
        total_probability_upper_bound=total_probability,
        total_certified_upper_bound=total_value,
        safety_threshold=safety_threshold,
    )


def tail_loaded_crossing_probability_bound(
    initial_state: BernoulliState,
    candidate: int,
    c: float,
    horizon: int,
    *,
    start_time: int = 0,
    exploration_mass: float = 0.0,
    override_rule: OverrideRule = host_delta_override,
    quadrature_points: int = 801,
    opt_tol: float = 1e-8,
    use_product_tail: bool = True,
) -> float:
    """Return the exact point-state tail-loaded crossing upper bound."""

    c = _require_positive("c", c)
    _require_horizon(horizon)
    _require_candidate(initial_state, candidate)
    if not isinstance(start_time, int) or start_time < 0:
        raise ValueError("start_time must be a nonnegative integer")
    terminal_time = start_time + horizon

    @cache
    def value(time: int, state: BernoulliState) -> float:
        if moving_certificate(state, candidate) >= c:
            return 1.0
        if time == terminal_time:
            return protected_anchor_tail(
                state,
                candidate,
                c,
                quadrature_points=quadrature_points,
                opt_tol=opt_tol,
                use_product=use_product_tail,
            ).final_value
        continuation = math.fsum(
            transition.probability * value(time + 1, transition.state)
            for transition in enumerate_transitions(
                state=state,
                t=time,
                exploration_mass=exploration_mass,
                override_rule=override_rule,
            )
        )
        return _as_probability(continuation)

    return value(start_time, initial_state)


@lru_cache(maxsize=200_000)
def _cached_tail(
    arms: tuple[tuple[int, int], ...],
    candidate: int,
    c: float,
    quadrature_points: int,
    opt_tol: float,
    use_product: bool,
) -> AnchorTailSummary:
    return _protected_anchor_tail_uncached(
        BernoulliState(tuple(BetaPosterior(alpha, beta) for alpha, beta in arms)),
        candidate,
        c,
        quadrature_points=quadrature_points,
        opt_tol=opt_tol,
        use_product=use_product,
    )


def protected_anchor_tail(
    state: BernoulliState,
    candidate: int,
    c: float,
    *,
    quadrature_points: int = 801,
    opt_tol: float = 1e-8,
    use_product: bool = True,
) -> AnchorTailSummary:
    """Return both terminal tail branches and their certified minimum."""

    c = _require_positive("c", c)
    _require_candidate(state, candidate)
    arms = tuple((arm.alpha, arm.beta) for arm in state.arms)
    return _cached_tail(arms, candidate, c, quadrature_points, opt_tol, use_product)


def _protected_anchor_tail_uncached(
    state: BernoulliState,
    candidate: int,
    c: float,
    *,
    quadrature_points: int,
    opt_tol: float,
    use_product: bool,
) -> AnchorTailSummary:
    floor = protected_floor(state.arms[candidate], c)
    anchors = tuple(
        index
        for index, arm in enumerate(state.arms)
        if index != candidate and arm.mean > floor
    )

    l2_value = 1.0
    l2_anchor: int | None = None
    for index in anchors:
        arm = state.arms[index]
        margin = arm.mean - floor
        if margin <= 0.0:
            continue
        candidate_value = min(1.0, beta_posterior_variance(arm) / (margin * margin))
        if candidate_value < l2_value:
            l2_value = candidate_value
            l2_anchor = index

    product_value = 1.0
    product_log_error = 0.0
    product_anchor_indexes: tuple[int, ...] = ()
    component_logs: tuple[float, ...] = ()
    lambdas: tuple[float, ...] = ()
    product_certified = True
    if anchors and use_product:
        try:
            product = product_anchor_drop_log_bound(
                tuple((state.arms[index].alpha, state.arms[index].beta) for index in anchors),
                floor,
                quadrature_points=quadrature_points,
                opt_tol=opt_tol,
            )
            product_log_error = min(0.0, product.log_error)
            product_value = (
                0.0 if product_log_error == float("-inf") else math.exp(product_log_error)
            )
            product_anchor_indexes = tuple(anchors[index] for index in product.anchor_indexes)
            component_logs = product.component_log_errors
            lambdas = product.lambda_stars
        except (ArithmeticError, OverflowError, ValueError):
            # Pointwise audit convention: an uncertified exponential branch is
            # replaced by the trivial certified upper bound 1.
            product_certified = False
            product_value = 1.0
            product_log_error = 0.0

    if l2_value <= product_value:
        final_value = l2_value
        final_method = "L2Fallback" if anchors else "NoAnchor"
    else:
        final_value = product_value
        final_method = "ProductExpChernoffBetaMgf"

    return AnchorTailSummary(
        protected_floor=floor,
        anchor_indexes=anchors,
        l2_value=_as_probability(l2_value),
        l2_anchor=l2_anchor,
        product_value=_as_probability(product_value),
        product_log_error=product_log_error,
        product_anchor_indexes=product_anchor_indexes,
        product_component_log_errors=component_logs,
        product_lambda_stars=lambdas,
        final_value=_as_probability(final_value),
        final_method=final_method,
        product_certified=product_certified,
    )


def protected_floor(candidate_posterior: BetaPosterior, c: float) -> float:
    """Return ``r_c(Pi) = max{z_c(Pi), m(Pi)}``."""

    c = _require_positive("c", c)
    return max(reservation_floor(candidate_posterior, c), candidate_posterior.mean)


def reservation_floor(
    candidate_posterior: BetaPosterior,
    c: float,
    *,
    tolerance: float = 1e-12,
) -> float:
    """Return ``z_c(Pi) = sup{v in [0,1]: psi(Pi,v) >= c}``."""

    c = _require_positive("c", c)
    if tolerance <= 0.0:
        raise ValueError("tolerance must be positive")
    if beta_expected_improvement(candidate_posterior.alpha, candidate_posterior.beta, 0.0) < c:
        return float("-inf")
    lo = 0.0
    hi = 1.0
    while hi - lo > tolerance:
        mid = 0.5 * (lo + hi)
        if beta_expected_improvement(candidate_posterior.alpha, candidate_posterior.beta, mid) >= c:
            lo = mid
        else:
            hi = mid
    return lo


def beta_posterior_variance(posterior: BetaPosterior) -> float:
    """Return the variance of a Beta posterior."""

    total = posterior.alpha + posterior.beta
    return posterior.alpha * posterior.beta / (total * total * (total + 1))


def _classify_status(
    *,
    finite_horizon_crossing_probability: float,
    total_certified_upper_bound: float,
    safety_threshold: float,
    delta: float,
    terminal_tail: AnchorTailSummary,
    terminal_tail_probability_contribution: float,
) -> CertificationStatus:
    if total_certified_upper_bound < safety_threshold:
        return CertificationStatus.CertifiedSafe
    if finite_horizon_crossing_probability >= delta:
        return CertificationStatus.CertifiedNotSafe
    if not terminal_tail.anchor_indexes:
        return CertificationStatus.UncertifiedNeedsMoreHorizon
    if (
        terminal_tail.final_value >= delta
        or terminal_tail_probability_contribution >= finite_horizon_crossing_probability
    ):
        return CertificationStatus.UncertifiedNeedsMoreHorizon
    return CertificationStatus.UncertifiedNeedsRefinement


def _require_candidate(state: BernoulliState, candidate: int) -> None:
    if not isinstance(candidate, int) or candidate < 0 or candidate >= len(state):
        raise IndexError("candidate index out of range")
    if len(state) < 2:
        raise ValueError("lockout certificates require at least two arms")


def _require_positive(name: str, value: float) -> float:
    value = float(value)
    if not math.isfinite(value) or value <= 0.0:
        raise ValueError(f"{name} must be finite and positive")
    return value


def _require_probability_tolerance(delta: float) -> float:
    delta = float(delta)
    if not math.isfinite(delta) or delta <= 0.0 or delta >= 1.0:
        raise ValueError("delta must lie in (0, 1)")
    return delta


def _require_horizon(horizon: int) -> None:
    if not isinstance(horizon, int) or horizon < 0:
        raise ValueError("horizon must be a nonnegative integer")


def _as_probability(value: float) -> float:
    if not math.isfinite(value):
        raise ArithmeticError("probability value is not finite")
    tolerance = 1e-12
    if value < -tolerance or value > 1.0 + tolerance:
        raise ArithmeticError("probability value left [0, 1]")
    return min(1.0, max(0.0, value))
