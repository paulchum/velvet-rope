"""Battery for velvet.verdict.flr_ebh (spec E2), ported verbatim from the external
portfolio false-lockout control package (audited 2026-07-07); only the
import block differs. Includes the exact-enumeration pins for Lemma 3
(tight instance) and Proposition CX (selection hazard)."""
import dataclasses
import itertools
import math
import random
from fractions import Fraction

import pytest
from verdict_flr_experiment import (
    build_ladder_mixed,
    build_tight_disjoint,
    clopper_pearson_lower,
    clopper_pearson_upper,
    hoeffding_lcb,
    hoeffding_ucb,
    ladder_exact_mean_fdp,
    near_tight_rate,
    run_f2d,
    run_f2h,
    run_power_selftest,
    selection_hazard_fleet,
)
from verdict_flr_experiment import (
    run as run_f2,
)

from velvet.verdict.flr_ebh import (
    BudgetState,
    DecisionProposal,
    ELondGate,
    FLREGate,
    RefusalReason,
    Verdict,
    VerdictRecord,
    realized_flr,
    threshold_for,
    uniform_window_gamma,
)


def proposal(decision_id, e_value, arm_id="arm", tau=1, e_process_id=None, metadata=None):
    return DecisionProposal(
        decision_id=decision_id,
        arm_id=arm_id,
        tau=tau,
        e_value=e_value,
        e_process_id=e_process_id or f"ep-{decision_id}",
        metadata={} if metadata is None else metadata,
    )


def test_t0_dataclass_fields_are_frozen_interface():
    assert [f.name for f in dataclasses.fields(DecisionProposal)] == [
        "decision_id",
        "arm_id",
        "tau",
        "e_value",
        "e_process_id",
        "window_id",
        "metadata",
    ]
    assert [f.name for f in dataclasses.fields(VerdictRecord)] == [
        "decision_id",
        "arm_id",
        "window_id",
        "verdict",
        "threshold_used",
        "e_value",
        "executed_count_before",
        "executed_count_after",
        "registered_count",
        "budget_state",
        "refusal_reason",
        "sequence_index",
        "metadata",
    ]
    assert [f.name for f in dataclasses.fields(BudgetState)] == [
        "window_id",
        "k_max",
        "delta",
        "registered",
        "executed",
        "remaining",
        "status",
    ]


def test_verdict_record_serialization_is_stable():
    gate = FLREGate(k_max=5, delta=0.1)
    record = gate.process(proposal("d1", 50.0, metadata={"source": "unit"}))
    assert record.to_dict() == {
        "decision_id": "d1",
        "arm_id": "arm",
        "window_id": "default",
        "verdict": "executed",
        "threshold_used": 50.0,
        "e_value": 50.0,
        "executed_count_before": 0,
        "executed_count_after": 1,
        "registered_count": 1,
        "budget_state": {
            "window_id": "default",
            "k_max": 5,
            "delta": 0.1,
            "registered": 1,
            "executed": 1,
            "remaining": 4,
            "status": "open",
        },
        "refusal_reason": None,
        "sequence_index": 1,
        "metadata": {"source": "unit"},
    }


def test_gate_arithmetic_and_boundary_are_pinned():
    assert threshold_for(k_max=10, delta=0.05, executed_count_before=0) == 200.0
    assert threshold_for(k_max=10, delta=0.05, executed_count_before=1) == 100.0
    assert threshold_for(k_max=10, delta=0.05, executed_count_before=3) == 50.0

    gate = FLREGate(k_max=10, delta=0.05)
    low = gate.process(proposal("low", 199.999))
    hit = gate.process(proposal("hit", 200.0))
    assert low.verdict is Verdict.GATED_OUT
    assert hit.verdict is Verdict.EXECUTED


def test_monotone_self_consistency_slacks_are_at_least_one():
    gate = FLREGate(k_max=3, delta=0.1)
    records = gate.process_batch(
        [
            proposal("b", 15.0, tau=1),
            proposal("c", 10.0, tau=1),
            proposal("a", 30.0, tau=1),
        ]
    )
    assert [r.decision_id for r in records] == ["a", "b", "c"]
    assert [r.verdict for r in records] == [
        Verdict.EXECUTED,
        Verdict.EXECUTED,
        Verdict.EXECUTED,
    ]
    assert gate.self_consistency_slacks() == pytest.approx([3.0, 1.5, 1.0])


def test_budget_exhaustion_refuses_without_registering_extra_family_member():
    gate = FLREGate(k_max=2, delta=0.5)
    assert gate.process(proposal("d1", 0.0)).verdict is Verdict.GATED_OUT
    assert gate.process(proposal("d2", 0.0)).verdict is Verdict.GATED_OUT
    refused = gate.process(proposal("d3", 10_000.0))
    assert refused.verdict is Verdict.REFUSED
    assert refused.refusal_reason is RefusalReason.BUDGET_EXHAUSTED
    assert refused.registered_count == 2
    assert refused.budget_state.remaining == 0


def test_refusal_paths_for_malformed_duplicate_reused_and_wrong_window():
    gate = FLREGate(k_max=5, delta=0.2, window_id="w1")

    malformed = gate.process(
        DecisionProposal("bad", "arm", tau=float("nan"), e_value=1.0, e_process_id="ep-bad", window_id="w1")
    )
    assert malformed.refusal_reason is RefusalReason.MALFORMED_DECISION

    contract = gate.process(
        DecisionProposal("bad-e", "arm", tau=1, e_value=float("inf"), e_process_id="ep-inf", window_id="w1")
    )
    assert contract.refusal_reason is RefusalReason.CONTRACT_VIOLATION

    first = gate.process(
        DecisionProposal("d1", "arm", tau=1, e_value=100.0, e_process_id="ep-1", window_id="w1")
    )
    assert first.verdict is Verdict.EXECUTED

    dup = gate.process(
        DecisionProposal("d1", "arm", tau=2, e_value=100.0, e_process_id="ep-new", window_id="w1")
    )
    assert dup.refusal_reason is RefusalReason.DUPLICATE_DECISION

    reused = gate.process(
        DecisionProposal("d2", "arm", tau=3, e_value=100.0, e_process_id="ep-1", window_id="w1")
    )
    assert reused.refusal_reason is RefusalReason.REUSED_EPROCESS

    wrong_window = gate.process(
        DecisionProposal("d3", "arm", tau=4, e_value=100.0, e_process_id="ep-3", window_id="w2")
    )
    assert wrong_window.refusal_reason is RefusalReason.UNSUPPORTED_WINDOW


def test_recurring_arm_is_decision_keyed_with_fresh_evidence():
    gate = FLREGate(k_max=3, delta=0.5)
    d1 = gate.process(proposal("retire-1", 10.0, arm_id="arm-A", e_process_id="ep-1"))
    d2 = gate.process(proposal("retire-2", 10.0, arm_id="arm-A", e_process_id="ep-2"))
    d3 = gate.process(proposal("retire-3", 10.0, arm_id="arm-A", e_process_id="ep-2"))
    assert d1.verdict is Verdict.EXECUTED
    assert d2.verdict is Verdict.EXECUTED
    assert d3.verdict is Verdict.REFUSED
    assert d3.refusal_reason is RefusalReason.REUSED_EPROCESS
    assert gate.executed_decision_ids == ("retire-1", "retire-2")


def test_simultaneous_batch_is_input_order_invariant():
    base = [
        proposal("a", 30.0, tau=7),
        proposal("b", 15.0, tau=7),
        proposal("c", 10.0, tau=7),
    ]
    expected = None
    for perm in itertools.permutations(base):
        gate = FLREGate(k_max=3, delta=0.1)
        out = [(r.decision_id, r.verdict.value) for r in gate.process_batch(perm)]
        if expected is None:
            expected = out
        assert out == expected
        assert gate.executed_decision_ids == ("a", "b", "c")


def test_realized_flr_accounting():
    gate = FLREGate(k_max=4, delta=0.25)
    gate.process_batch(
        [
            proposal("d1", 16.0, tau=1),
            proposal("d2", 8.0, tau=1),
            proposal("d3", 0.0, tau=1),
        ]
    )
    report = realized_flr(gate.history, true_null_decision_ids={"d1", "d3"})
    assert report == {
        "executed": 2,
        "false_lockouts": 1,
        "flr": 0.5,
        "false_lockout_decision_ids": ["d1"],
    }


def test_seeded_proposal_stream_is_deterministic():
    def run(seed):
        rng = random.Random(seed)
        gate = FLREGate(k_max=20, delta=0.5)
        proposals = [
            proposal(f"d{i:02d}", 100.0 * rng.random(), tau=i)
            for i in range(20)
        ]
        for p in proposals:
            gate.process(p)
        return gate.executed_decision_ids

    assert run(12345) == run(12345)
    assert run(12345) != run(54321)


def test_constructor_rejects_bad_budget_parameters():
    with pytest.raises(ValueError):
        FLREGate(k_max=0, delta=0.1)
    with pytest.raises(ValueError):
        FLREGate(k_max=1, delta=1.0)
    with pytest.raises(ValueError):
        FLREGate(k_max=1, delta=0.0)


def test_clopper_pearson_zero_success_pin():
    assert clopper_pearson_upper(0, 10, alpha=0.05) == pytest.approx(
        1.0 - 0.05 ** 0.1
    )


def test_f2_smoke_callable_passes_and_labels_sim_currency():
    code, lines = run_f2("smoke", seed=20260707)
    assert code == 0
    assert lines[0].startswith("[SIM] starting F2")
    assert any("F2a" in line for line in lines)
    assert any("F2b" in line for line in lines)
    assert any("F2c replay spec" in line for line in lines)
    assert any("quorum_ok=True" in line for line in lines)
    assert any("violation_detected=True" in line for line in lines)
    for line in lines:
        if "verdict=" in line:
            assert "verdict=PASS" in line or "verdict=INDETERMINATE" not in line


class _FixedU:
    """Deterministic rng stub exposing only random(), for exact instance tests."""

    def __init__(self, u):
        self._u = u

    def random(self):
        return self._u


def test_lemma3_tight_instance_exact_by_enumeration():
    """[MATH] pin of CERTIFICATION T1 Lemma 3: on the disjoint-spike instance
    the gate executes exactly one (false) decision iff U < delta, so
    FLR = sum of interval lengths = delta exactly."""

    k, delta = 5, 0.1
    fdp_region = Fraction(0)
    for j in range(k):
        u = (j + 0.5) * delta / k  # interior of I_j
        proposals, nulls = build_tight_disjoint(_FixedU(u), k, delta)
        gate = FLREGate(k_max=k, delta=delta)
        gate.process_batch(proposals)
        assert gate.executed_decision_ids == (f"d{j:03d}",)
        assert realized_flr(gate.history, nulls)["flr"] == 1.0
        fdp_region += Fraction(1, 10) / k  # exact length of I_j
    for u in (delta + 1e-9, 0.5, 0.99):
        proposals, nulls = build_tight_disjoint(_FixedU(u), k, delta)
        gate = FLREGate(k_max=k, delta=delta)
        gate.process_batch(proposals)
        assert gate.executed_decision_ids == ()
        assert realized_flr(gate.history, nulls)["flr"] == 0.0
    assert fdp_region == Fraction(1, 10)  # exact FLR == delta


def test_subthreshold_tripwire_never_executes_even_if_all_spike():
    """Worst case of the tripwire cell: every null spikes at 1/delta.  The
    correct gate's first threshold is K/delta > 1/delta for K >= 2 and cannot
    fall without executions, so nothing executes: exact FLR = 0."""

    k, delta = 20, 0.1
    gate = FLREGate(k_max=k, delta=delta)
    spike = 1.0 / (delta * 1.0)
    proposals = [
        DecisionProposal(
            decision_id=f"d{i:03d}",
            arm_id=f"arm-{i}",
            tau=1,
            e_value=spike,
            e_process_id=f"ep-{i}",
        )
        for i in range(k)
    ]
    gate.process_batch(proposals)
    assert gate.executed_decision_ids == ()


def test_near_tight_formula_matches_product_loop():
    k, delta = 50, 0.1
    p = 0.7 * delta / k
    prod = 1.0
    for _ in range(k):
        prod *= 1.0 - p
    assert near_tight_rate(k, delta) == pytest.approx(1.0 - prod, abs=1e-15)
    assert near_tight_rate(k, delta) < delta  # instance sits strictly below the bound


def test_ladder_exact_mean_fdp_direction_and_comonotone_closed_form():
    for k in (30, 50):
        delta = 0.1
        n_null = k - math.ceil(0.7 * k)
        sub_bound = delta * n_null / k  # theorem's delta*|H0|/K_max refinement
        for como in (False, True):
            exact = ladder_exact_mean_fdp(k, delta, comonotone=como)
            assert 0.0 < exact <= sub_bound + 1e-12
            assert exact < delta
    # comonotone closed form: p * N/(A+N) with p = delta*(A+1)/K
    a, n_null = 35, 15
    p = 0.1 * (a + 1) / 50
    assert ladder_exact_mean_fdp(50, 0.1, comonotone=True) == pytest.approx(
        p * n_null / (a + n_null)
    )


def test_ladder_instance_executes_all_alternatives_and_spiking_nulls():
    k, delta = 30, 0.1
    proposals, nulls = build_ladder_mixed(_FixedU(0.0), k, delta, comonotone=True)
    gate = FLREGate(k_max=k, delta=delta)
    gate.process_batch(proposals)
    executed = set(gate.executed_decision_ids)
    alt_ids = {p.decision_id for p in proposals if p.decision_id not in nulls}
    assert alt_ids <= executed  # every alternative executes
    assert nulls <= executed  # shared U = 0.0 < p: every null spikes and executes


def test_clopper_pearson_lower_pins():
    # P[X >= n] = p^n = alpha at the lower bound when k == n
    assert clopper_pearson_lower(10, 10, alpha=0.05) == pytest.approx(0.05 ** 0.1)
    assert clopper_pearson_lower(0, 10) == 0.0
    lo, hi = clopper_pearson_lower(30, 300), clopper_pearson_upper(30, 300)
    assert 0.0 < lo < 0.1 < hi < 0.2  # interval brackets the point estimate


def test_hoeffding_bound_pins():
    radius = math.sqrt(math.log(1.0 / 0.05) / (2.0 * 200))
    assert hoeffding_ucb(0.5, 200) == pytest.approx(0.5 + radius)
    assert hoeffding_lcb(0.5, 200) == pytest.approx(0.5 - radius)
    assert hoeffding_ucb(0.999, 10) == 1.0  # clamped
    assert hoeffding_lcb(0.001, 10) == 0.0  # clamped


def test_power_selftest_detects_broken_gate():
    detected, lines = run_power_selftest(seed=20260707)
    assert detected
    assert "violation_detected=True" in lines[0]


def test_proposition_cx_selection_hazard_exact_enumeration():
    """[MATH] pin of CERTIFICATION Proposition CX: with A = ceil(1/delta)
    optimal arms and per-arm mean-1 disjoint spikes, retiring the spiking arm
    and reporting its own e-value executes for EVERY U (FLR = 1), while both
    certified repairs (selection dividend, arithmetic e-merge) execute for NO U
    (FLR = 0)."""

    delta = 0.1
    grid = [(j + 0.5) / 10 for j in range(10)]  # one U inside each arm interval
    assert all(selection_hazard_fleet(u, delta, "none") == 1.0 for u in grid)
    assert all(selection_hazard_fleet(u, delta, "divide") == 0.0 for u in grid)
    assert all(selection_hazard_fleet(u, delta, "merge") == 0.0 for u in grid)


def test_f2h_certifies_hazard_and_repairs():
    ok, lines = run_f2h(seed=20260707)
    assert ok
    assert any("hazard_violation_certified=True" in line for line in lines)
    assert sum("controlled=True" in line for line in lines) == 2


def test_elond_threshold_arithmetic_is_pinned():
    gate = ELondGate(delta=0.1)  # telescoping gamma_j = 1/(j(j+1))
    # at r = j-1 (all prior executed) the threshold is 10*(j+1)
    assert gate.threshold(1, 0) == pytest.approx(20.0)
    assert gate.threshold(2, 1) == pytest.approx(30.0)
    assert gate.threshold(3, 2) == pytest.approx(40.0)
    # weight zero => infinite threshold
    assert ELondGate(delta=0.1, gamma=uniform_window_gamma(3)).threshold(4, 0) == math.inf


def test_elond_uniform_weights_reproduce_route_a_exactly():
    """CERTIFICATION T1b unification: gamma_j = 1/K on the window makes
    ELondGate's verdict stream identical to FLREGate's, including the
    budget-exhausted refusal past K."""

    k, delta = 7, 0.2
    rng = random.Random(424242)
    proposals = [
        proposal(f"d{i:02d}", rng.choice([0.0, 3.0, 12.0, 40.0, 200.0]) * (1 + rng.random()), tau=i)
        for i in range(k + 3)  # three past the budget
    ]
    gate_a = FLREGate(k_max=k, delta=delta)
    gate_b = ELondGate(delta=delta, gamma=uniform_window_gamma(k))
    out_a = [(r.verdict, r.refusal_reason) for r in map(gate_a.process, proposals)]
    out_b = [(r.verdict, r.refusal_reason) for r in map(gate_b.process, proposals)]
    assert out_a == out_b
    assert gate_a.executed_decision_ids == gate_b.executed_decision_ids
    # thresholds agree to float tolerance at every executed count
    for r in range(k):
        assert gate_b.threshold(1, r) == pytest.approx(gate_a.threshold(r), rel=1e-12)


def test_elond_partial_sum_guard_refuses_overweight_streams():
    gate = ELondGate(delta=0.1, gamma=lambda j: 0.6)
    first = gate.process(proposal("d1", 1.0))
    second = gate.process(proposal("d2", 1.0))
    assert first.verdict in (Verdict.EXECUTED, Verdict.GATED_OUT)
    assert second.verdict is Verdict.REFUSED
    assert second.refusal_reason is RefusalReason.CONTRACT_VIOLATION
    assert gate.registered_count == 1  # refused proposal never registered


def test_elond_moderate_no_ladder_executes_exactly_nine():
    """Deterministic route-(b) power pin: e = 0.2002*threshold(0), all slots.
    Telescoping thresholds at r = j-1 are 10*(j+1) for delta = 0.1, so slots
    j = 1..9 execute and slot 10 (threshold 110) freezes the stream."""

    k, delta = 50, 0.1
    e = threshold_for(k, delta, 0) * 0.2002
    gate = ELondGate(delta=delta)
    for i in range(k):
        gate.process(proposal(f"d{i:03d}", e, tau=i))
    assert len(gate.executed_decision_ids) == 9
    # route (a) on the same stream executes nothing
    gate_a = FLREGate(k_max=k, delta=delta)
    for i in range(k):
        gate_a.process(proposal(f"d{i:03d}", e, tau=i))
    assert gate_a.executed_decision_ids == ()


def test_f2d_power_comparison_documents_tradeoff():
    ok, lines = run_f2d("smoke", seed=20260707)
    assert ok
    assert any("tradeoff_documented=True" in line for line in lines)
    assert any("consistent=True" in line for line in lines)
