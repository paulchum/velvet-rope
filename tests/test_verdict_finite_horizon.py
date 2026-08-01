from __future__ import annotations

from datetime import date

import pytest

from velvet.research.actual_kernel import (
    BernoulliState,
    BetaPosterior,
    host_arm,
    moving_certificate,
)
from velvet.research.crossing_dp import crossing_indicator, finite_horizon_crossing_probability
from velvet.verdict.finite_horizon import (
    DEFAULT_DELTA,
    DEFAULT_EXPLORATION_MASS,
    DEFAULT_GATE,
    _two_arm_de_override_rule,
    bounded_drift_penalty,
    expected_rounds_to_gate_crossing,
    finite_horizon_verdict,
    max_certifiable_horizon,
)


def _state(arms: list[tuple[int, int]]) -> BernoulliState:
    return BernoulliState(tuple(BetaPosterior(alpha, beta) for alpha, beta in arms))


def test_safe_kill_uses_finite_horizon_crossing_dp() -> None:
    verdict = finite_horizon_verdict([(700, 300), (100, 150)], 1, horizon_H=3)

    assert verdict.verdict == "safe_kill"
    assert verdict.method == "exact_dp"
    assert verdict.price_of_tail.crossing_probability == pytest.approx(0.0)
    assert verdict.price_of_tail.probability_bound < DEFAULT_DELTA
    assert verdict.refusal_reason is None


def test_required_inspection_when_candidate_already_crosses_gate() -> None:
    verdict = finite_horizon_verdict([(6, 4), (5, 5)], 1, horizon_H=3)

    assert verdict.verdict == "required_inspection"
    assert verdict.price_of_tail.crossing_probability == pytest.approx(1.0)
    assert verdict.price_of_inspection.expected_rounds_to_gate_crossing == pytest.approx(0.0)


def test_horizon_zero_matches_immediate_crossing_indicator() -> None:
    arms = [(700, 300), (100, 150)]
    state = BernoulliState(tuple(BetaPosterior(a, b) for a, b in arms))
    verdict = finite_horizon_verdict(arms, 1, horizon_H=0)

    assert moving_certificate(state, 1) < DEFAULT_GATE
    assert verdict.price_of_tail.crossing_probability == pytest.approx(
        crossing_indicator(state, 1, DEFAULT_GATE)
    )
    assert verdict.price_of_inspection.expected_rounds_to_gate_crossing == pytest.approx(0.0)


def test_theorem_v_host_promotion_flips_gate_only_safe_kill() -> None:
    """Pack 01 Theorem V / obstruction O1 (verify_theorem_v T5).

    ``arms=[(2, 1), (251, 249)]``, ``candidate=1``, ``c=0.01``, ``H=1``: the
    gate-only DP is exactly 0 (the pre-Theorem-V reading would have issued
    ``safe_kill`` at ``delta=0.05``) while the host-aware rescue probability is
    exactly 1/3, so the verdict must be ``required_inspection``.
    """

    arms = [(2, 1), (251, 249)]
    rule = _two_arm_de_override_rule(DEFAULT_GATE)

    gate_only = finite_horizon_crossing_probability(
        _state(arms),
        1,
        DEFAULT_GATE,
        1,
        start_time=0,
        exploration_mass=DEFAULT_EXPLORATION_MASS,
        override_rule=rule,
        host_aware=False,
    )
    assert gate_only == 0.0
    assert gate_only < DEFAULT_DELTA

    verdict = finite_horizon_verdict(arms, 1, horizon_H=1, delta=0.05)
    assert verdict.verdict == "required_inspection"
    assert verdict.method == "exact_dp"
    assert verdict.price_of_tail.crossing_probability == pytest.approx(
        1.0 / 3.0, abs=1e-15
    )
    assert verdict.price_of_tail.probability_bound >= 0.05


def test_theorem_v_host_at_issue_is_rescued_at_offset_zero() -> None:
    """Pack 01 Theorem V / verify_theorem_v T5b.

    ``arms=[(900, 100), (890, 110)]``, ``candidate=0``, ``c=0.02``, ``H=1``:
    the candidate is the greedy host at issue while below the gate, so the
    host-aware rescue probability is exactly 1 (host channel at offset 0) and
    the rescue-time primitive is 0, while the gate-only DP is exactly 0.
    """

    arms = [(900, 100), (890, 110)]
    state = _state(arms)
    assert host_arm(state) == 0
    assert moving_certificate(state, 0) < 0.02

    verdict = finite_horizon_verdict(arms, 0, horizon_H=1, gate=0.02)
    assert verdict.verdict == "required_inspection"
    assert verdict.price_of_tail.crossing_probability == 1.0
    assert verdict.price_of_inspection.expected_rounds_to_gate_crossing == 0.0

    rule = _two_arm_de_override_rule(0.02)
    gate_only = finite_horizon_crossing_probability(
        state,
        0,
        0.02,
        1,
        start_time=0,
        exploration_mass=DEFAULT_EXPLORATION_MASS,
        override_rule=rule,
        host_aware=False,
    )
    assert gate_only == 0.0


def test_theorem_v_pinned_instance_gate_and_rescue_values_coincide() -> None:
    """Pack 01 verify_theorem_v T8: exact values on ``arms=[(2, 1), (1, 3)]``.

    ``P(C_3) = P(R_3) = 2/5`` exactly and ``P(C_10) = P(R_10) = 236/495``; the
    rescue-time primitive is unchanged by the host channel on this instance.
    """

    arms = [(2, 1), (1, 3)]
    state = _state(arms)
    rule = _two_arm_de_override_rule(DEFAULT_GATE)
    common = dict(
        start_time=0,
        exploration_mass=DEFAULT_EXPLORATION_MASS,
        override_rule=rule,
    )

    for host_aware in (True, False):
        assert (
            finite_horizon_crossing_probability(
                state, 1, DEFAULT_GATE, 3, host_aware=host_aware, **common
            )
            == 0.4
        )
        assert finite_horizon_crossing_probability(
            state, 1, DEFAULT_GATE, 10, host_aware=host_aware, **common
        ) == pytest.approx(236.0 / 495.0, abs=1e-14)
        assert expected_rounds_to_gate_crossing(
            state, 1, DEFAULT_GATE, 3, host_aware=host_aware, **common
        ) == pytest.approx(7.0 / 3.0, abs=1e-15)

    verdict = finite_horizon_verdict(arms, 1, horizon_H=3)
    assert verdict.price_of_tail.crossing_probability == 0.4


def test_drift_adjustment_tightens_delta_and_large_drift_refuses() -> None:
    mild = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=3,
        drift_epsilon=0.001,
    )
    assert bounded_drift_penalty(3, drift_epsilon=0.001) == pytest.approx(0.003)
    assert mild.verdict == "safe_kill"
    assert mild.price_of_tail.drift_penalty == pytest.approx(0.003)
    assert mild.price_of_tail.probability_bound == pytest.approx(0.003)

    large = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=3,
        drift_epsilon=0.02,
    )
    assert large.verdict == "required_inspection"
    assert large.refusal_reason is None


def test_invalid_drift_and_exogenous_baseline_refuse() -> None:
    invalid = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=3,
        drift_epsilon=-0.01,
    )
    assert invalid.verdict == "refusal"
    assert "drift_epsilon" in str(invalid.refusal_reason)

    moving_baseline = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=3,
        exogenous_baseline=True,
    )
    assert moving_baseline.verdict == "refusal"
    assert "exogenous moving baselines" in str(moving_baseline.refusal_reason)


def test_expiry_uses_rounds_as_canonical_clock() -> None:
    rounds_only = finite_horizon_verdict([(700, 300), (100, 150)], 1, horizon_H=4)
    assert rounds_only.rounds_remaining == 4
    assert rounds_only.expiry_date is None
    assert rounds_only.rounds_per_day is None
    assert rounds_only.product_grade is False

    projected = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=4,
        issued_at=date(2026, 7, 5),
        rounds_per_day=2,
    )
    assert projected.rounds_remaining == 4
    assert projected.expiry_date == "2026-07-07"
    assert projected.rounds_per_day == pytest.approx(2.0)
    assert projected.product_grade is True


def test_price_fields_are_native_unless_caller_supplies_economics() -> None:
    native = finite_horizon_verdict([(2, 1), (1, 3)], 1, horizon_H=3)
    assert native.price_of_tail.crossing_probability == pytest.approx(0.4)
    assert native.price_of_tail.posterior_expected_shortfall > 0.0
    assert native.price_of_tail.dollars is None
    assert native.price_of_inspection.expected_rounds_to_gate_crossing == pytest.approx(
        2.333333333333333
    )
    assert native.price_of_inspection.dollars is None

    priced = finite_horizon_verdict(
        [(2, 1), (1, 3)],
        1,
        horizon_H=3,
        value_per_metric_unit=100.0,
        cost_per_round=5.0,
    )
    assert priced.price_of_tail.dollars == pytest.approx(
        priced.price_of_tail.probability_bound
        * priced.price_of_tail.posterior_expected_shortfall
        * 100.0
    )
    assert priced.price_of_tail.dollars_source == "derived_from_caller_inputs"
    assert priced.price_of_inspection.dollars == pytest.approx(
        priced.price_of_inspection.expected_rounds_to_gate_crossing * 5.0
    )
    assert priced.price_of_inspection.dollars_source == "derived_from_caller_inputs"
    assert isinstance(priced.as_dict()["price_of_tail"], dict)


def test_max_certifiable_horizon_matches_drift_penalty_boundary() -> None:
    cases = [
        (0.0, 0.01, 0.05),
        (0.001, 0.0, 0.05),
        (0.001, 0.002, 0.05),
        (0.02, 0.0, 0.05),
    ]
    for drift_epsilon, initial_mean_error, delta in cases:
        horizon = max_certifiable_horizon(drift_epsilon, initial_mean_error, delta)
        assert bounded_drift_penalty(
            horizon,
            drift_epsilon=drift_epsilon,
            initial_mean_error=initial_mean_error,
        ) < delta
        assert bounded_drift_penalty(
            horizon + 1,
            drift_epsilon=drift_epsilon,
            initial_mean_error=initial_mean_error,
        ) >= delta


def test_large_horizon_uses_certified_upper_bound_instead_of_refusal() -> None:
    verdict = finite_horizon_verdict(
        [(700, 300), (100, 150)],
        1,
        horizon_H=50,
        memory_budget_bytes=1,
        quadrature_points=101,
    )

    assert verdict.method == "certified_upper_bound"
    assert verdict.verdict == "safe_kill"
    assert verdict.refusal_reason is None
    assert verdict.price_of_tail.crossing_probability < DEFAULT_DELTA
    assert verdict.price_of_inspection.expected_rounds_to_gate_crossing == pytest.approx(50.0)
