"""Upstream parity goldens for the ported verdict decision layer.

The verdict modules were ported from two sibling repositories that are not
present in CI, so parity is pinned as golden numerics rather than live
imports. Values below were produced by the ported code at port time and
verified to match the upstream engines at these commits:

- maxde-response ``93c61cdd40bab8952e7e13ea24c69a7bdde54a1d`` (2026-07-09)
- maxde-replay   ``fc2f082c688df4dfc6faad94b70b5b68a9a8424b`` (2026-07-08)

See ``src/velvet/verdict/UPSTREAM.md`` for the provenance and relicensing
statement. Tolerances are 1e-9 relative where SciPy/libm is involved (values
are deterministic per platform but not bit-identical across platforms) and
exact where the arithmetic is integer or rational.
"""

from __future__ import annotations

import pytest

from velvet.research.actual_kernel import (
    BernoulliState,
    BetaPosterior,
    host_delta_override,
)
from velvet.research.crossing_dp import finite_horizon_crossing_probability
from velvet.verdict import drift_expiry as de
from velvet.verdict.audit_glr import e_value, log_e_value
from velvet.verdict.flr_ebh import DecisionProposal, FLREGate
from velvet.verdict.rescue import (
    protected_threshold,
    rescue_risk_bound,
    rescue_risk_log_bound,
)


def test_theorem_v_separation_instance() -> None:
    """The pinned Theorem V separation: gate-only P(C_1)=0, host-aware P(R_1)=1/3.

    On ``arms=[(2,1),(251,249)]`` with ``candidate=1`` and ``c=0.01`` the
    gate-only diagnostic certifies nothing is wrong while the host-aware
    stopping set exposes a 1/3 rescue probability. This is the exact instance
    from the Theorem V obstruction catalogue; it is why ``safe_kill`` verdicts
    must never be issued from the gate-only DP.
    """

    state = BernoulliState(((2, 1), (251, 249)))
    gate_only = finite_horizon_crossing_probability(
        state, 1, 0.01, 1, override_rule=host_delta_override, host_aware=False
    )
    host_aware = finite_horizon_crossing_probability(
        state, 1, 0.01, 1, override_rule=host_delta_override, host_aware=True
    )
    assert gate_only == 0.0
    assert host_aware == pytest.approx(1.0 / 3.0, abs=1e-15)


def test_rescue_risk_goldens() -> None:
    """Protected floor and anchor-tail rescue bounds match upstream values."""

    assert protected_threshold(BetaPosterior(3, 7), 0.01) == pytest.approx(
        0.46851070938737394, rel=1e-9
    )
    arms = [(3, 7), (8, 2)]
    assert rescue_risk_bound(arms, 0, 0.01, quadrature_points=1001) == pytest.approx(
        0.0746932899868913, rel=1e-9
    )
    log_1001 = rescue_risk_log_bound(arms, 0, 0.01, quadrature_points=1001)
    log_4001 = rescue_risk_log_bound(arms, 0, 0.01, quadrature_points=4001)
    assert log_1001 == pytest.approx(-2.5943650170243577, rel=1e-9)
    # Quadrature-resolution cross-check: 1001 vs 4001 points agree closely.
    assert log_1001 == pytest.approx(log_4001, rel=1e-10)


def test_glr_kt_normalized_e_value_goldens() -> None:
    """Family M e-values match upstream: KT-normalized, not raw exp(Z)."""

    assert log_e_value(50, 40, 50, 20) == pytest.approx(-4.37561670070335, rel=1e-9)
    # One observation per arm, one success vs zero: the KT normalization pins
    # the e-value at 1/4 (raw exp(Z) would NOT be an e-value here).
    assert e_value(1, 1, 1, 0) == pytest.approx(0.25, rel=1e-12)


def test_flr_ebh_gate_golden_sequence() -> None:
    """e-BH gate thresholds K_max/(delta*(|R|+1)) reproduce upstream."""

    gate = FLREGate(k_max=10, delta=0.05)
    first = gate.process(
        DecisionProposal(
            decision_id="d1", arm_id="a", tau=1, e_value=250.0, e_process_id="ep-1"
        )
    )
    second = gate.process(
        DecisionProposal(
            decision_id="d2", arm_id="b", tau=2, e_value=10.0, e_process_id="ep-2"
        )
    )
    assert first.verdict.value == "executed"
    assert first.threshold_used == pytest.approx(200.0)
    assert second.verdict.value == "gated_out"
    assert second.threshold_used == pytest.approx(100.0)


def test_drift_expiry_golden_verdict() -> None:
    """A pinned CertifiedSafe drift verdict with expiry and forced recheck."""

    verdict = de.issue_verdict(
        [(60.0, 40.0), (30.0, 70.0)],
        cand=1,
        c=0.01,
        delta=0.05,
        rho=0.001,
        delta_tail=0.05,
    )
    assert verdict.status == "CertifiedSafe"
    assert verdict.W == pytest.approx(157.0)
    assert verdict.T_hat == pytest.approx(157.0)
    assert verdict.tail_bound == pytest.approx(0.047877031311317125, rel=1e-9)
    assert verdict.expiry_time is not None
    expired = de.check_expiry(verdict, now=float(verdict.expiry_time) + 1.0)
    assert expired.status == "Expired"
    assert expired.reason_code == "expired"
