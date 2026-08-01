from __future__ import annotations

import pytest

from velvet.research.actual_kernel import BernoulliState, BetaPosterior
from velvet.verdict.truncation import (
    CertificationStatus,
    certify_lockout,
    protected_anchor_tail,
    protected_floor,
)


def test_certification_status_values_are_canonical() -> None:
    assert tuple(status.value for status in CertificationStatus) == (
        "CertifiedSafe",
        "CertifiedNotSafe",
        "UncertifiedNeedsRefinement",
        "UncertifiedNeedsMoreHorizon",
    )


def test_protected_floor_matches_counterexample_thresholds() -> None:
    assert protected_floor(BetaPosterior(1, 4), 0.01) == pytest.approx(
        0.45071972834648477,
        abs=1e-12,
    )
    assert protected_floor(BetaPosterior(1, 3), 0.01) == pytest.approx(
        0.5527864044997841,
        abs=1e-12,
    )


def test_anchor_tail_reports_l2_and_product_branches() -> None:
    state = BernoulliState((BetaPosterior(1, 4), BetaPosterior(2, 1)))

    tail = protected_anchor_tail(state, candidate=0, c=0.01, quadrature_points=401, opt_tol=1e-7)

    assert tail.protected_floor == pytest.approx(0.45071972834648477)
    assert tail.anchor_indexes == (1,)
    assert tail.l2_value == pytest.approx(1.0)
    assert tail.product_value == pytest.approx(0.683223037708276, rel=1e-10)
    assert tail.final_value == pytest.approx(tail.product_value)
    assert tail.final_method == "ProductExpChernoffBetaMgf"


def test_lockout_decision_safe_fixture_is_pinned() -> None:
    state = BernoulliState((BetaPosterior(1, 4), BetaPosterior(20, 5)))

    decision = certify_lockout(
        state,
        candidate=0,
        c=0.01,
        delta=0.05,
        horizon=5,
        quadrature_points=401,
        opt_tol=1e-7,
        tail_loaded_use_product=False,
    )

    assert decision.status is CertificationStatus.CertifiedSafe
    assert decision.finite_horizon_crossing_probability == pytest.approx(0.0)
    assert decision.total_probability_upper_bound == pytest.approx(0.04430824802969284)
    assert decision.total_certified_upper_bound == pytest.approx(0.0004430824802969284)
    assert decision.terminal_tail.final_value == pytest.approx(0.0012169847865116507)


def test_lockout_decision_not_safe_uses_exact_dp_lower_bound() -> None:
    state = BernoulliState((BetaPosterior(1, 3), BetaPosterior(2, 1)))

    decision = certify_lockout(
        state,
        candidate=0,
        c=0.01,
        delta=0.05,
        horizon=5,
        quadrature_points=401,
        opt_tol=1e-7,
        tail_loaded_use_product=False,
    )

    assert decision.status is CertificationStatus.CertifiedNotSafe
    assert decision.finite_horizon_crossing_probability == pytest.approx(0.4285714285714286)
    assert decision.total_probability_upper_bound == pytest.approx(0.6592831448398538)
