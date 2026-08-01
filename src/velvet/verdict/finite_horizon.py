"""Finite-horizon product verdicts for certified kill decisions.

This module is deliberately separate from ``velvet.verdict.rescue``.  The
rescue helpers bound the infinite-horizon anchor-tail certificate.  The
objects here are product-facing finite-window verdicts: they call the exact
stopped DP with the Theorem V host-aware stopping set and attach expiry,
bounded-drift degradation, and simple price primitives.  Canonical statement:
``docs/math/theorem_v_finite_horizon_verdict.txt``.

Ported from the maxde-replay study (``src/replay/finite_horizon_verdict.py``),
relicensed by the copyright owner (Coriolis Labs Inc.) under Apache-2.0; see
``src/velvet/verdict/UPSTREAM.md``.  The optional Rust replay-kernel backend
was intentionally dropped in this port; every verdict runs the pure-Python
exact DP or the certified upper bound.

The certified event is the host-aware rescue event

    ``R_H = {exists r in {0..H}: N^a(X_{t+r}) >= c or h(X_{t+r}) = a}``,

not the gate-only crossing event: a ``safe_kill`` asserts that with
probability at least ``1 - delta`` under the modeled kernel (robustified over
the declared bounded drift class) the candidate neither becomes gate-eligible
nor becomes the greedy host at any offset in the window.  The gate-only DP
(Corollary V.2) remains available as an explicit diagnostic via
``host_aware=False`` on the DP primitives; it is never the kill contract
because it does not bound host promotion (exact separation: ``P(C_1) = 0``
while ``P(R_1) = 1/3`` on ``arms=[(2, 1), (251, 249)]``, ``candidate=1``).
"""

from __future__ import annotations

import math
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import date, datetime, time, timedelta
from functools import cache
from typing import Literal

from velvet.research.actual_kernel import (
    BernoulliState,
    BetaPosterior,
    OverrideRule,
    enumerate_transitions,
    host_arm,
    moving_certificate,
)
from velvet.research.crossing_dp import finite_horizon_crossing_probability
from velvet.verdict.rescue import DEFAULT_QUADRATURE_POINTS, rescue_risk_bound

DEFAULT_GATE = 0.01
DEFAULT_DELTA = 0.05
DEFAULT_EXPLORATION_MASS = 100.0
DEFAULT_MEMORY_BUDGET_BYTES = 2 * 1024 * 1024 * 1024
SUPPORTED_BASELINE_MODE = "posterior_candidate_excluded"

ArmPosterior = tuple[int, int]
Verdict = Literal["safe_kill", "required_inspection", "refusal"]
VerdictMethod = Literal["exact_dp", "certified_upper_bound"]


@dataclass(frozen=True)
class TailPrice:
    """Native and optional dollar price of accepting the finite-H tail.

    ``crossing_probability`` is the exact host-aware rescue probability
    ``P(R_H)`` when ``method=exact_dp`` (a certified upper bound on the
    infinite-horizon rescue event when ``method=certified_upper_bound``).
    """

    probability_bound: float
    crossing_probability: float
    drift_penalty: float
    posterior_expected_shortfall: float
    dollars: float | None = None
    dollars_source: str | None = None


@dataclass(frozen=True)
class InspectionPrice:
    """Native and optional dollar price of buying more inspection rounds.

    ``expected_rounds_to_gate_crossing`` is the rescue-time primitive
    ``E[min(tau_rescue, H)]``: expected rounds under continued DE play until
    the candidate is rescued (gate crossing or host promotion) or the window
    expires.
    """

    expected_rounds_to_gate_crossing: float
    dollars: float | None = None
    dollars_source: str | None = None


@dataclass(frozen=True)
class FiniteHorizonVerdict:
    """Serializable product verdict for one finite-horizon kill decision."""

    verdict: Verdict
    method: VerdictMethod
    delta: float
    horizon_H: int
    rounds_remaining: int
    expiry_date: str | None
    rounds_per_day: float | None
    product_grade: bool
    price_of_inspection: InspectionPrice
    price_of_tail: TailPrice
    refusal_reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)


def finite_horizon_verdict(
    arms: Sequence[ArmPosterior],
    candidate: int,
    *,
    horizon_H: int,
    gate: float = DEFAULT_GATE,
    delta: float = DEFAULT_DELTA,
    start_time: int = 0,
    exploration_mass: float = DEFAULT_EXPLORATION_MASS,
    drift_epsilon: float = 0.0,
    initial_mean_error: float = 0.0,
    stable_arm_set: bool = True,
    baseline_mode: str = SUPPORTED_BASELINE_MODE,
    exogenous_baseline: bool = False,
    override_rule: OverrideRule | None = None,
    issued_at: date | datetime | str | None = None,
    rounds_per_day: float | None = None,
    value_per_metric_unit: float | None = None,
    cost_per_round: float | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    quadrature_points: int = DEFAULT_QUADRATURE_POINTS,
) -> FiniteHorizonVerdict:
    """Return a finite-window verdict for retiring ``candidate``.

    ``safe_kill`` certifies the host-aware no-rescue event of Theorem V: with
    probability at least ``1 - delta`` under the modeled posterior-predictive
    kernel (plus the declared bounded-drift penalty), there is no offset
    ``r <= horizon_H`` at which ``N^a(X_{t+r}) >= gate`` or
    ``h(X_{t+r}) = candidate``.  For gated override rules this also bounds the
    probability that the policy pulls the candidate anywhere in the window.

    Rounds are the validity clock.  ``expiry_date`` is only a projection from
    caller-supplied calendar assumptions; when those assumptions are absent the
    verdict is still valid in rounds but marked ``product_grade=False``.
    """

    horizon = _require_nonnegative_int("horizon_H", horizon_H)
    start = _require_nonnegative_int("start_time", start_time)
    c = _require_threshold(gate)
    tolerance = _require_delta(delta)
    state = _state_from_arms(arms)
    _require_candidate(state, candidate)
    value_unit = _optional_nonnegative_float(
        "value_per_metric_unit", value_per_metric_unit
    )
    round_cost = _optional_nonnegative_float("cost_per_round", cost_per_round)
    budget = _require_positive_int("memory_budget_bytes", memory_budget_bytes)
    quadrature = _require_positive_int("quadrature_points", quadrature_points)
    calendar = _expiry_projection(horizon, issued_at, rounds_per_day)
    current_shortfall = moving_certificate(state, candidate)

    if not stable_arm_set:
        return _refusal(
            "bounded-drift lemma requires a stable finite arm set",
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )
    if exogenous_baseline:
        return _refusal(
            "bounded-drift lemma does not cover exogenous moving baselines",
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )
    if baseline_mode != SUPPORTED_BASELINE_MODE:
        return _refusal(
            f"unsupported baseline_mode: {baseline_mode}",
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )
    if override_rule is None and len(state) != 2:
        return _refusal(
            "default finite-horizon verdict policy supports two-arm DE only",
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )

    drift_error = _validate_drift_input("initial_mean_error", initial_mean_error)
    if drift_error is not None:
        return _refusal(
            drift_error,
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )
    epsilon_error = _validate_drift_input("drift_epsilon", drift_epsilon)
    if epsilon_error is not None:
        return _refusal(
            epsilon_error,
            tolerance,
            horizon,
            calendar,
            current_shortfall,
            value_unit,
            round_cost,
        )

    drift_penalty = bounded_drift_penalty(
        horizon,
        drift_epsilon=float(drift_epsilon),
        initial_mean_error=float(initial_mean_error),
    )
    rule = override_rule if override_rule is not None else _two_arm_de_override_rule(c)

    method: VerdictMethod = "exact_dp"
    if current_shortfall >= c or host_arm(state) == candidate:
        # Offset-0 member of the Theorem V stopping set S_R: the candidate is
        # already gate-eligible or is the greedy host at issue.
        crossing_probability = 1.0
        expected_rounds = 0.0
    else:
        if _exact_dp_exceeds_budget(horizon, budget):
            if override_rule is not None:
                return _refusal(
                    "certified upper-bound branch supports the default two-arm DE policy only",
                    tolerance,
                    horizon,
                    calendar,
                    current_shortfall,
                    value_unit,
                    round_cost,
                )
            method = "certified_upper_bound"
            crossing_probability = _certified_upper_bound_crossing_probability(
                arms,
                candidate,
                c,
                quadrature_points=quadrature,
            )
            expected_rounds = float(horizon)
        else:
            crossing_probability = finite_horizon_crossing_probability(
                state,
                candidate,
                c,
                horizon,
                start_time=start,
                exploration_mass=exploration_mass,
                override_rule=rule,
            )
            expected_rounds = expected_rounds_to_gate_crossing(
                state,
                candidate,
                c,
                horizon,
                start_time=start,
                exploration_mass=exploration_mass,
                override_rule=rule,
            )
    price_of_tail = _tail_price(
        crossing_probability,
        drift_penalty,
        current_shortfall,
        value_unit,
    )
    price_of_inspection = _inspection_price(expected_rounds, round_cost)

    verdict: Verdict = (
        "safe_kill"
        if price_of_tail.probability_bound < tolerance
        else "required_inspection"
    )
    return FiniteHorizonVerdict(
        verdict=verdict,
        method=method,
        delta=tolerance,
        horizon_H=horizon,
        rounds_remaining=horizon,
        expiry_date=calendar.expiry_date,
        rounds_per_day=calendar.rounds_per_day,
        product_grade=calendar.product_grade,
        price_of_inspection=price_of_inspection,
        price_of_tail=price_of_tail,
        refusal_reason=None,
    )


def bounded_drift_penalty(
    horizon_H: int,
    *,
    drift_epsilon: float,
    initial_mean_error: float = 0.0,
) -> float:
    """Return the finite-H total-variation degradation bound.

    If the true Bernoulli means can be coupled to the posterior-predictive means
    with initial error ``initial_mean_error`` and per-round drift at most
    ``drift_epsilon``, then every H-round event probability differs by at most
    ``initial_mean_error * H + drift_epsilon * H * (H - 1) / 2``, capped at one.
    """

    horizon = _require_nonnegative_int("horizon_H", horizon_H)
    for name, value in (
        ("drift_epsilon", drift_epsilon),
        ("initial_mean_error", initial_mean_error),
    ):
        error = _validate_drift_input(name, value)
        if error is not None:
            raise ValueError(error)
    raw = (
        float(initial_mean_error) * horizon
        + float(drift_epsilon) * horizon * (horizon - 1) / 2.0
    )
    return min(1.0, raw)


def max_certifiable_horizon(
    drift_epsilon: float,
    initial_mean_error: float,
    delta: float,
) -> int:
    """Return the largest finite ``H`` with ``bounded_drift_penalty(H) < delta``.

    The bound is checked by solving the quadratic closed form and then adjusting
    by integer neighbor checks.  If both drift terms are zero, every finite
    horizon is certifiable and the function returns ``sys.maxsize`` as the
    practical unbounded sentinel.
    """

    tolerance = _require_delta(delta)
    for name, value in (
        ("drift_epsilon", drift_epsilon),
        ("initial_mean_error", initial_mean_error),
    ):
        error = _validate_drift_input(name, value)
        if error is not None:
            raise ValueError(error)
    epsilon = float(drift_epsilon)
    initial = float(initial_mean_error)
    if epsilon == 0.0 and initial == 0.0:
        return sys.maxsize
    if epsilon == 0.0:
        estimate = math.ceil(tolerance / initial) - 1
    else:
        # Solve epsilon/2 * H^2 + (initial - epsilon/2) * H - delta < 0.
        a = epsilon / 2.0
        b = initial - epsilon / 2.0
        root = (-b + math.sqrt(b * b + 4.0 * a * tolerance)) / (2.0 * a)
        estimate = math.ceil(root) - 1
    horizon = max(0, int(estimate))
    while horizon > 0 and bounded_drift_penalty(
        horizon,
        drift_epsilon=epsilon,
        initial_mean_error=initial,
    ) >= tolerance:
        horizon -= 1
    while bounded_drift_penalty(
        horizon + 1,
        drift_epsilon=epsilon,
        initial_mean_error=initial,
    ) < tolerance:
        horizon += 1
    return horizon


def expected_rounds_to_gate_crossing(
    initial_state: BernoulliState,
    candidate: int,
    c: float,
    horizon: int,
    *,
    start_time: int = 0,
    exploration_mass: float = DEFAULT_EXPLORATION_MASS,
    override_rule: OverrideRule,
    host_aware: bool = True,
) -> float:
    """Exact expected rounds under continued DE play until rescue or expiry.

    This is ``E[min(tau_rescue, H)]``: the expected number of rounds until the
    trajectory first enters the Theorem V stopping set
    ``S_R = {N^a >= c} u {h = a}`` (the candidate re-crosses the gate or is
    promoted to greedy host), stopped at the finite window.  It uses the same
    stopping set as the verdict's rescue probability DP.  It is a rescue-time
    primitive, not the frequentist audit sample bill; the latter is a separate
    later primitive.

    ``host_aware=False`` restricts the stop to the gate channel only
    (diagnostic; Corollary V.2 semantics).
    """

    threshold = _require_threshold(c)
    remaining = _require_nonnegative_int("horizon", horizon)
    start = _require_nonnegative_int("start_time", start_time)
    _require_candidate(initial_state, candidate)
    terminal_time = start + remaining

    @cache
    def value(time_index: int, state: BernoulliState) -> float:
        if moving_certificate(state, candidate) >= threshold or (
            host_aware and host_arm(state) == candidate
        ):
            return 0.0
        if time_index == terminal_time:
            return 0.0
        continuation = math.fsum(
            transition.probability * value(time_index + 1, transition.state)
            for transition in enumerate_transitions(
                state=state,
                t=time_index,
                exploration_mass=exploration_mass,
                override_rule=override_rule,
            )
        )
        return _as_nonnegative(1.0 + continuation)

    return value(start, initial_state)


def _two_arm_de_override_rule(gate: float) -> OverrideRule:
    threshold = _require_threshold(gate)

    def rule(t: int, state: BernoulliState) -> tuple[float, ...]:
        if len(state) != 2:
            raise ValueError(
                "default finite-horizon verdict policy supports two-arm DE only"
            )
        host = host_arm(state)
        non_host = 1 - host
        selected = (
            non_host
            if moving_certificate(state, non_host) >= threshold
            else host
        )
        return tuple(1.0 if index == selected else 0.0 for index in range(len(state)))

    return rule


@dataclass(frozen=True)
class _CalendarProjection:
    expiry_date: str | None
    rounds_per_day: float | None
    product_grade: bool


def _expiry_projection(
    horizon: int,
    issued_at: date | datetime | str | None,
    rounds_per_day: float | None,
) -> _CalendarProjection:
    rpd = _optional_positive_float("rounds_per_day", rounds_per_day)
    if issued_at is None or rpd is None:
        return _CalendarProjection(None, rpd, False)
    issued = _parse_issued_at(issued_at)
    expiry = issued + timedelta(days=horizon / rpd)
    return _CalendarProjection(expiry.date().isoformat(), rpd, True)


def _parse_issued_at(value: date | datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, time())
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("issued_at must be an ISO date or datetime") from exc
    raise TypeError("issued_at must be a date, datetime, ISO string, or None")


def _refusal(
    reason: str,
    delta: float,
    horizon: int,
    calendar: _CalendarProjection,
    current_shortfall: float,
    value_per_metric_unit: float | None,
    cost_per_round: float | None,
) -> FiniteHorizonVerdict:
    return FiniteHorizonVerdict(
        verdict="refusal",
        method="exact_dp",
        delta=delta,
        horizon_H=horizon,
        rounds_remaining=horizon,
        expiry_date=calendar.expiry_date,
        rounds_per_day=calendar.rounds_per_day,
        product_grade=calendar.product_grade,
        price_of_inspection=_inspection_price(float(horizon), cost_per_round),
        price_of_tail=_tail_price(1.0, 0.0, current_shortfall, value_per_metric_unit),
        refusal_reason=reason,
    )


def _tail_price(
    crossing_probability: float,
    drift_penalty: float,
    posterior_expected_shortfall: float,
    value_per_metric_unit: float | None,
) -> TailPrice:
    probability_bound = min(1.0, crossing_probability + drift_penalty)
    dollars = None
    source = None
    if value_per_metric_unit is not None:
        dollars = (
            probability_bound
            * posterior_expected_shortfall
            * value_per_metric_unit
        )
        source = "derived_from_caller_inputs"
    return TailPrice(
        probability_bound=probability_bound,
        crossing_probability=crossing_probability,
        drift_penalty=drift_penalty,
        posterior_expected_shortfall=posterior_expected_shortfall,
        dollars=dollars,
        dollars_source=source,
    )


def _inspection_price(
    expected_rounds: float,
    cost_per_round: float | None,
) -> InspectionPrice:
    dollars = None
    source = None
    if cost_per_round is not None:
        dollars = expected_rounds * cost_per_round
        source = "derived_from_caller_inputs"
    return InspectionPrice(
        expected_rounds_to_gate_crossing=expected_rounds,
        dollars=dollars,
        dollars_source=source,
    )


def _state_from_arms(arms: Sequence[ArmPosterior]) -> BernoulliState:
    return BernoulliState(tuple(BetaPosterior(alpha, beta) for alpha, beta in arms))


def _require_candidate(state: BernoulliState, candidate: int) -> None:
    if not isinstance(candidate, int) or candidate < 0 or candidate >= len(state):
        raise IndexError("candidate index out of range")


def _require_nonnegative_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def _require_positive_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _require_threshold(c: float) -> float:
    threshold = float(c)
    if not math.isfinite(threshold) or threshold < 0.0:
        raise ValueError("gate must be a finite nonnegative certificate-height threshold")
    return threshold


def _require_delta(delta: float) -> float:
    tolerance = float(delta)
    if not math.isfinite(tolerance) or tolerance <= 0.0 or tolerance > 1.0:
        raise ValueError("delta must be a probability tolerance in (0, 1]")
    return tolerance


def _validate_drift_input(name: str, value: float) -> str | None:
    try:
        drift = float(value)
    except (TypeError, ValueError):
        return f"{name} must be finite and in [0, 1]"
    if not math.isfinite(drift) or drift < 0.0 or drift > 1.0:
        return f"{name} must be finite and in [0, 1]"
    return None


def _optional_nonnegative_float(name: str, value: float | None) -> float | None:
    if value is None:
        return None
    converted = float(value)
    if not math.isfinite(converted) or converted < 0.0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return converted


def _optional_positive_float(name: str, value: float | None) -> float | None:
    if value is None:
        return None
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0.0:
        raise ValueError(f"{name} must be finite and positive")
    return converted


def _as_nonnegative(value: float) -> float:
    if not math.isfinite(value):
        raise ArithmeticError("expected rounds is not finite")
    if value < -1e-12:
        raise ArithmeticError("expected rounds became negative")
    return max(0.0, value)


def _two_arm_lattice_state_count_at_depth(depth: int) -> int:
    """Return the full two-arm posterior lattice size after ``depth`` updates."""

    d = _require_nonnegative_int("depth", depth)
    return (d + 1) * (d + 2) * (d + 3) // 6


def _exact_dp_live_bytes(horizon: int) -> int:
    """Conservative live bytes for two value tables at adjacent depths.

    Rust stores crossing and expected-round values as ``f64`` tables.  A
    backward sweep needs the current and next depths live, so each state-cell is
    budgeted for two values across two adjacent depths.
    """

    h = _require_nonnegative_int("horizon", horizon)
    current = _two_arm_lattice_state_count_at_depth(h)
    previous = _two_arm_lattice_state_count_at_depth(max(0, h - 1))
    return (current + previous) * 2 * 8


def _exact_dp_exceeds_budget(horizon: int, memory_budget_bytes: int) -> bool:
    return _exact_dp_live_bytes(horizon) > memory_budget_bytes


def _certified_upper_bound_crossing_probability(
    arms: Sequence[ArmPosterior],
    candidate: int,
    gate: float,
    *,
    quadrature_points: int,
) -> float:
    """Return a sound finite-H rescue upper bound from the infinite-H anchor tail.

    The finite-window host-aware event is contained in the eventual rescue
    event: ``P(R_H) <= P(R_inf)``.  The product anchor-tail certificate used by
    ``replay.certificate`` upper-bounds the latter by ``e_c_final``; its
    protected floor ``r_c = max(z_c, m_a)`` covers both the gate channel and
    the host channel, so both verdict branches certify the same host-aware
    event family.  Because the finite-window probability is monotone in ``H``,
    this bound is sound for every window size and can replace an exact DP when
    the exact arena exceeds the memory budget.
    """

    return rescue_risk_bound(
        arms,
        candidate,
        gate,
        quadrature_points=quadrature_points,
    )


__all__ = [
    "DEFAULT_DELTA",
    "DEFAULT_EXPLORATION_MASS",
    "DEFAULT_GATE",
    "FiniteHorizonVerdict",
    "InspectionPrice",
    "SUPPORTED_BASELINE_MODE",
    "TailPrice",
    "bounded_drift_penalty",
    "expected_rounds_to_gate_crossing",
    "finite_horizon_verdict",
    "max_certifiable_horizon",
]
