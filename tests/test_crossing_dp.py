from __future__ import annotations

import pytest

from velvet.research.actual_kernel import BernoulliState, BetaPosterior, moving_certificate
from velvet.research.crossing_dp import crossing_indicator, finite_horizon_crossing_probability


def host_only_q(t: int, state: BernoulliState) -> tuple[float, ...]:
    return (1.0, 0.0)


def test_horizon_zero_is_crossing_indicator() -> None:
    state = BernoulliState((BetaPosterior(1, 1), BetaPosterior(3, 1)))
    c = moving_certificate(state, candidate=0) + 0.01
    assert finite_horizon_crossing_probability(
        state,
        candidate=0,
        c=c,
        horizon=0,
        override_rule=host_only_q,
    ) == crossing_indicator(state, candidate=0, c=c)


def test_crossing_probability_stays_in_unit_interval() -> None:
    state = BernoulliState((BetaPosterior(1, 2), BetaPosterior(2, 1)))
    probability = finite_horizon_crossing_probability(
        state,
        candidate=0,
        c=0.01,
        horizon=3,
        exploration_mass=1.0,
        override_rule=host_only_q,
    )
    assert 0.0 <= probability <= 1.0


def test_zero_threshold_crosses_immediately() -> None:
    state = BernoulliState((BetaPosterior(1, 2), BetaPosterior(2, 1)))
    assert finite_horizon_crossing_probability(
        state,
        candidate=0,
        c=0.0,
        horizon=3,
        override_rule=host_only_q,
    ) == pytest.approx(1.0)


def test_one_step_recursion_uses_actual_transition_enumeration() -> None:
    state = BernoulliState((BetaPosterior(1, 3), BetaPosterior(2, 1)))
    c = 0.01
    probability = finite_horizon_crossing_probability(
        state,
        candidate=0,
        c=c,
        horizon=1,
        exploration_mass=0.0,
        override_rule=host_only_q,
    )
    host_mean = state.arms[1].mean
    success_state = state.update(1, 1)
    failure_state = state.update(1, 0)
    expected = (
        host_mean * crossing_indicator(success_state, candidate=0, c=c)
        + (1.0 - host_mean) * crossing_indicator(failure_state, candidate=0, c=c)
    )
    assert probability == pytest.approx(expected)
