"""Finite-horizon actual-kernel rescue/crossing dynamic program.

The default stopping set is the host-aware rescue set of Theorem V
(``{N^a >= c} u {h = a}``): the gate channel alone does not bound host
promotion, so a ``safe_kill`` verdict must certify the host-aware event.
The gate-only stopping set remains available as an explicit diagnostic
(``host_aware=False``; Corollary V.2). Canonical statement:
``docs/math/theorem_v_finite_horizon_verdict.txt``.
"""

from __future__ import annotations

import math
from functools import cache

from velvet.research.actual_kernel import (
    BernoulliState,
    OverrideRule,
    enumerate_transitions,
    host_arm,
    moving_certificate,
)


def crossing_indicator(state: BernoulliState, candidate: int, c: float) -> int:
    """Return ``1{N^a(x) >= c}`` for certificate-height threshold ``c``.

    This is the gate-only channel. The Theorem V verdict stopping set also
    includes the host channel; see :func:`rescue_indicator`.
    """

    c = _require_threshold(c)
    return int(moving_certificate(state, candidate) >= c)


def rescue_indicator(state: BernoulliState, candidate: int, c: float) -> int:
    """Return ``1{N^a(x) >= c or h(x) = a}``, the host-aware rescue indicator.

    This is the offset-0 member of the Theorem V stopping set
    ``S_R = {N^a >= c} u {h = a}``: a candidate that is gate-eligible or is
    already the greedy host counts as rescued.
    """

    c = _require_threshold(c)
    return int(
        moving_certificate(state, candidate) >= c or host_arm(state) == candidate
    )


def finite_horizon_crossing_probability(
    initial_state: BernoulliState,
    candidate: int,
    c: float,
    horizon: int,
    *,
    start_time: int = 0,
    exploration_mass: float = 1.0,
    override_rule: OverrideRule,
    host_aware: bool = True,
) -> float:
    """Compute the exact small-state finite-horizon stopped-event probability.

    With the default ``host_aware=True`` the stopped event is the host-aware
    rescue event of Theorem V,
    ``R_H = {exists r in {0..H}: N^a(X_{t+r}) >= c or h(X_{t+r}) = a}``,
    computed by the actual-kernel stopped DP
    ``V_s = 1{x in S_R} + 1{x not in S_R} K_s V_{s+1}`` with stopping set
    ``S_R = {N^a >= c} u {h = a}``. This is the event a ``safe_kill`` verdict
    certifies; the gate channel alone does not bound host promotion.

    ``host_aware=False`` computes the gate-only crossing event
    ``C_H = {exists r in {0..H}: N^a(X_{t+r}) >= c}`` (stopping set ``S_C``).
    That value is a diagnostic only (Corollary V.2); it must never be quoted
    as a no-rescue or no-touch certificate.

    The horizon is the number of one-step transitions allowed from
    ``start_time``. ``horizon=0`` returns the initial stopping indicator.
    """

    c = _require_threshold(c)
    if not isinstance(horizon, int) or horizon < 0:
        raise ValueError("horizon must be a nonnegative integer")
    if not isinstance(start_time, int) or start_time < 0:
        raise ValueError("start_time must be a nonnegative integer")

    terminal_time = start_time + horizon

    @cache
    def value(time: int, state: BernoulliState) -> float:
        if moving_certificate(state, candidate) >= c or (
            host_aware and host_arm(state) == candidate
        ):
            return 1.0
        if time == terminal_time:
            return 0.0
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


def _require_threshold(c: float) -> float:
    c = float(c)
    if not math.isfinite(c) or c < 0.0:
        raise ValueError("c must be a finite nonnegative certificate-height threshold")
    return c


def _as_probability(value: float) -> float:
    if not math.isfinite(value):
        raise ArithmeticError("crossing probability is not finite")
    tolerance = 1e-12
    if value < -tolerance or value > 1.0 + tolerance:
        raise ArithmeticError("crossing probability left [0, 1]")
    return min(1.0, max(0.0, value))
