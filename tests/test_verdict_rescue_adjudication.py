"""Executed pins for predictive_rescue_adjudication.md (O2.1).

Run:
  python3 tests/test_predictive_rescue_adjudication.py
  python3 -m pytest -q tests/test_predictive_rescue_adjudication.py
  python3 -m unittest -v tests/test_predictive_rescue_adjudication.py

Workhorse instances (2 arms, candidate FROZEN, base pulled each round):
  P2  : cand Beta(2,1), base Beta(4,1), c = 7/100,  W = 2
        -> P(A^0)=0, P(A^1)=1/5, P(A^2)=1/3
  POW : cand Beta(2,1), base Beta(4,1), c = 99/1000, W = 2
        -> P(A^2)=1/15, crossing set {FF}
  SEL : pre-pull base once from Beta(4,1):
        state F (p=1/5): base (4,2), crossed at issue  -> pointwise u_F = 1
        state S (p=4/5): base (5,1), W=2 tight         -> pointwise u_S = 1/6
Every probability below is an exact Fraction by enumeration.  [BP] unless noted.
"""
from __future__ import annotations

import random
import unittest
from fractions import Fraction
from itertools import product

from velvet.verdict.rescue_adjudication import (
    Certificate,
    ContractBreach,
    ExpiryRefusal,
    FleetAccountant,
    bernoulli_from_fraction,
    cell_label,
    certify_decomposed,
    certify_infinite,
    certify_windowed,
    cp_lower,
    cp_upper,
    crossed_now,
    crossing_probs,
    finalize,
    psi,
    sample_crossed,
)

F = Fraction
CAND = (2, 1)
BASE = (4, 1)
C_P2 = F(7, 100)
C_POW = F(99, 1000)
SEED = 20260707


# ---------------------------------------------------------------- exact pins

def test_T01_psi_closed_form():
    # psi(Beta(2,1), v) = 2/3 - v + v^3/3, spot-pinned at every state we use
    pins = {F(4, 5): F(14, 375), F(2, 3): F(8, 81), F(5, 6): F(17, 648),
            F(5, 7): F(76, 1029), F(6, 7): F(20, 1029), F(3, 4): F(11, 192),
            F(7, 8): F(23, 1536), F(4, 7): F(54, 343)}
    for v, want in pins.items():
        got = psi(2, 1, v)
        assert got == want, (v, got, want)
        assert got == F(2, 3) - v + v ** 3 / 3
    print("T01 PASS — psi closed-form pins (8 states, exact rationals)")


def test_T02_P2_enumeration():
    p = crossing_probs(CAND, BASE, C_P2, 2)
    assert p == [F(0), F(1, 5), F(1, 3)], p
    print("T02 PASS — P2: P(A^0)=0, P(A^1)=1/5, P(A^2)=1/3")


def test_T03_HgtW_kill():
    # N2/O3: adjudicate A^2 against a tight W=1 certificate
    p = crossing_probs(CAND, BASE, C_P2, 2)
    u1 = p[1]
    ratio = p[2] / u1
    assert ratio == F(5, 3) and ratio > 1
    print("T03 PASS — H>W kill: E[1{A^2}]/u(W=1) = 5/3 > 1")


def test_T04_upper_bracket_kill():
    # N1/O2: certified bracket at tau+1 in the numerator
    u = crossing_probs(CAND, BASE, C_P2, 2)[2]          # 1/3, tight W=2
    assert crossed_now(CAND, (4, 2), C_P2)              # after F: P(A^2|.)=1
    cond_S = crossing_probs(CAND, (5, 1), C_P2, 1)[1]
    assert cond_S == F(1, 6)
    bracket = F(1, 5) * 1 + F(4, 5) * F(1, 4)           # slack after S: 1/4
    assert bracket / u == F(6, 5) and bracket / u > 1
    exact = (F(1, 5) * 1 + F(4, 5) * cond_S) / u
    assert exact == 1  # boundary-valid but a forecast, never adjudicable
    print("T04 PASS — bracket kill: E[B/u]=6/5>1; exact conditional =1 "
          "(non-adjudicable boundary)")


def test_T05_validity_pins():
    p2 = crossing_probs(CAND, BASE, C_P2, 2)[2]
    tight = certify_windowed(CAND, BASE, C_P2, 2)
    assert tight.u == F(1, 3)
    assert p2 / tight.u == 1                             # boundary
    slack = certify_windowed(CAND, BASE, C_P2, 2, slack=F(1, 15))
    assert slack.u == F(2, 5) and p2 / slack.u == F(5, 6)
    print("T05 PASS — validity: E[E_hat]=1 (tight u=1/3), 5/6 (slack u=2/5)")


def test_T06_decomposition_remainder():
    cert = certify_decomposed(CAND, BASE, C_P2, H_adj=1, H_total=2)
    assert (cert.W, cert.u, cert.t) == (1, F(1, 3), F(2, 15))
    p = crossing_probs(CAND, BASE, C_P2, 2)
    assert p[1] / cert.u == F(3, 5) <= 1                 # E[E_hat]
    assert p[2] - p[1] == cert.t                         # remainder line, equality
    print("T06 PASS — decomposition: u=1/5+2/15=1/3; E[E_hat]=3/5; "
          "E[late]=2/15=t (certified line tight)")


def test_T07_selection_states():
    uF = certify_windowed(CAND, (4, 2), C_P2, 2).u
    uS = certify_windowed(CAND, (5, 1), C_P2, 2).u
    assert uF == 1 and uS == F(1, 6)
    assert F(1, 5) * uF + F(4, 5) * uS == F(1, 3)        # the dishonest average
    print("T07 PASS — SEL states: u_F=1, u_S=1/6, state-average=1/3")


def test_T08_fake_average_violation():
    # O7/Prop 7: 6 slots, adversary executes only F-slots under u_bar=1/3,
    # gate u<=delta=2/5 admits. FLR=1 iff >=1 F-slot.
    e_flr = 1 - F(4, 5) ** 6
    assert e_flr == F(11529, 15625) and e_flr > F(2, 5)
    acct = FleetAccountant("naive-broken", F(2, 5))
    for st in "FSSFSS":
        if st == "F":
            r = acct.consider(F(1, 3), Certificate(W=2, u=F(1, 3),
                                                   note="state-averaged"))
            assert r["executed"]
            acct.adjudicate(r["id"], True)   # F-state crosses at issue
    assert acct.report()["flr"] == 1
    print("T08 PASS — fake-average cert: E[FLR]=11529/15625≈.738 > 2/5 "
          "(VIOLATION pinned); mechanical FSSFSS -> FLR=1")


def test_T09_pointwise_twin_passes():
    # Same gate (u<=2/5), certificates swapped to pointwise: F refused, S runs.
    e_flr = F(1, 6) * (1 - F(1, 5) ** 6)
    assert e_flr == F(2604, 15625) and e_flr <= F(2, 5)
    acct = FleetAccountant("naive-broken", F(2, 5))
    for st in "FSSFSS":
        u = F(1) if st == "F" else F(1, 6)
        r = acct.consider(u, Certificate(W=2, u=u, note="pointwise tight"))
        assert r["executed"] == (st == "S")
    rep = acct.report()
    assert rep["n_executed"] == 4 and rep["n_considered"] == 6
    print("T09 PASS — pointwise twin, same gate: E[FLR]=2604/15625≈.167 "
          "<= 2/5; gate refuses exactly the F-states")


def test_T10_largest_u_adversary_and_Splus():
    # C-SEL: two independent pre-pulls, adversary retires the LARGEST-u pair,
    # honest gate (ebh, K_max=1, delta=2/5). Refused unless both S.
    e_sel = F(4, 5) ** 2 * F(1, 6)
    assert e_sel == F(8, 75) and e_sel <= F(2, 5)
    e_splus = F(4, 5) * F(1, 6)
    assert e_splus == F(2, 15) and e_splus <= F(2, 5)
    print("T10 PASS — largest-u adversary vs pointwise+gate: E[FLR]=8/75 "
          "<= 2/5; S+ single-slot: 2/15 <= 2/5")


def test_T11_naive_gate_falsified_exact():
    # O1/N5 (the mandated broken variant): delta=1/3, slot1 u=P=1/3,
    # stop-on-rescue else 3 more iid slots.
    tail = sum(F(1, 3) ** k * F(2, 3) ** (3 - k)
               * F(k, 4) * __import__("math").comb(3, k) for k in range(4))
    e_flr = F(1, 3) * 1 + F(2, 3) * tail
    assert e_flr == F(1, 2) and e_flr > F(1, 3)
    acct = FleetAccountant("naive-broken", F(1, 3))
    r = acct.consider(F(1, 3))
    assert r["executed"] and r["bar"] == F(1, 3)
    print("T11 PASS — naive gate FALSIFIED exactly: E[FLR]=1/2 > delta=1/3 "
          "(optional stopping); r_j factor is necessary")


def test_T12_honest_gate_disarms_trap():
    acct = FleetAccountant("elond", F(1, 3), gammas=[F(1, 4)] * 4)
    for _ in range(4):
        r = acct.consider(F(1, 3))
        assert not r["executed"] and r["bar"] == F(1, 12)
    rep = acct.report()
    assert rep["n_executed"] == 0 and rep["flr"] == 0
    print("T12 PASS — honest e-LOND on the same trap: bar=1/12 refuses all; "
          "FLR=0 (trap disarmed)")


def test_T13_powered_honest_fleet_exact():
    p = crossing_probs(CAND, BASE, C_POW, 2)
    assert p == [F(0), F(0), F(1, 15)]                   # crossing set {FF}
    acct = FleetAccountant("elond", F(1, 3), gammas=[F(1, 4)] * 4)
    bars = []
    for _ in range(4):
        r = acct.consider(F(1, 15))
        bars.append(r["bar"])
        assert r["executed"]
    assert bars == [F(1, 12), F(1, 6), F(1, 4), F(1, 3)]
    # anytime pin: E[sup_k prefix-FLR] over 4 sequential iid Bern(1/15) slots
    pr_1 = F(1, 15)
    esup = F(0)
    for bits in product((0, 1), repeat=4):
        pr = F(1)
        s, best = 0, F(0)
        for k, b in enumerate(bits, 1):
            pr *= pr_1 if b else 1 - pr_1
            s += b
            best = max(best, F(s, k))
        esup += pr * best
    assert esup <= F(1, 3), esup
    assert 4 * F(1, 15) / 4 == F(1, 15)                  # E[FLR_final]
    print(f"T13 PASS — powered honest fleet: all 4 execute "
          f"(bars 1/12,1/6,1/4,1/3 >= u=1/15); E[FLR]=1/15; "
          f"E[sup_t FLR_t]={esup} = {float(esup):.4f} <= 1/3 (anytime)")


def test_T14_tightness():
    acct = FleetAccountant("ebh", F(1, 3), k_max=1)
    r = acct.consider(F(1, 3))
    assert r["executed"] and r["bar"] == F(1, 3)
    assert crossing_probs(CAND, BASE, C_P2, 2)[2] == F(1, 3)  # E[FLR]=delta
    print("T14 PASS — tightness: single slot u=P=delta=1/3 executes at "
          "equality; E[FLR]=1/3=delta (constant unimprovable)")


def test_T15_u_zero_convention():
    z = Certificate(W=1, u=F(0))
    assert finalize(False, z) == 0
    try:
        finalize(True, z)
        raise AssertionError("ContractBreach not raised")
    except ContractBreach:
        pass
    print("T15 PASS — 0/0:=0; crossing on {u=0} trips ContractBreach")


def test_T16_expiry_semantics():
    try:
        certify_windowed(CAND, BASE, C_P2, W=3, T_hat=2)
        raise AssertionError("ExpiryRefusal not raised")
    except ExpiryRefusal:
        pass
    try:
        certify_infinite(drift=True)
        raise AssertionError("ExpiryRefusal not raised")
    except ExpiryRefusal:
        pass
    cert = certify_infinite(drift=False, cand=CAND, base=BASE, c=C_P2,
                            H_adj=1, H_total=2)
    assert (cert.u, cert.t) == (F(1, 3), F(2, 15))
    # N4 exhibit: A_j (infinite horizon) undetermined at small finite h:
    # from base (5,1) (uncrossed), both continuations have positive prob.
    assert crossing_probs(CAND, (5, 1), C_P2, 2)[2] > 0          # can cross
    assert crossing_probs(CAND, (5, 1), C_P2, 2)[2] < 1          # can not-cross
    print("T16 PASS — expiry: W>T_hat refused; infinite-horizon under drift "
          "refused; stationary decomposition u=1/3=1/5+2/15; N4 exhibit "
          "(A undetermined at finite h)")


def test_T17_gate_on_Ehat_illposed():
    # N3/O4: peeking oracle executes only rescued decisions (2 iid P2 slots)
    e_flr = 1 - F(2, 3) ** 2
    assert e_flr == F(5, 9) and e_flr > F(1, 3)
    import inspect
    assert "crossed" not in inspect.signature(FleetAccountant.consider).parameters
    print("T17 PASS — gating on E_hat ill-posed: peek-oracle E[FLR]=5/9 > 1/3;"
          " consider() cannot see outcomes (API-enforced measurability)")


def test_T18_clopper_pearson_sanity():
    assert abs(cp_upper(0, 100, 0.05) - (1 - 0.05 ** 0.01)) < 2e-3
    assert abs(cp_lower(100, 100, 0.05) - 0.05 ** 0.01) < 2e-3
    assert cp_lower(0, 50) == 0.0 and cp_upper(50, 50) == 1.0
    assert cp_lower(30, 100) < 0.30 < cp_upper(30, 100)
    print("T18 PASS — Clopper-Pearson pins (k=0 upper, k=n lower, coverage)")


def test_T20_accountant_u_certificate_consistency():
    cert = Certificate(W=2, u=F(1, 3), note="pointwise tight")
    assert crossing_probs(CAND, BASE, C_P2, 2)[2] == cert.u
    # Old bug: with delta=1/4, a fake gate u=1/4 would execute while the
    # theorem-bearing denominator/event has expected rescue fraction 1/3 > 1/4.
    try:
        FleetAccountant("ebh", F(1, 4), k_max=1).consider(F(1, 4), cert)
        raise AssertionError("mismatched u/cert.u was not rejected")
    except ValueError as e:
        assert "gate u" in str(e)
    acct = FleetAccountant("ebh", F(1, 3), k_max=1)
    r = acct.consider(cert=cert)
    assert r["u"] == cert.u and r["executed"] and r["cert"] is cert
    try:
        FleetAccountant("ebh", F(1, 3), k_max=1).consider()
        raise AssertionError("missing u/cert was not rejected")
    except ValueError as e:
        assert "requires u or cert" in str(e)
    print("T20 PASS — accountant enforces u == cert.u; cert.u is the single "
          "gate/denominator envelope; old delta=1/4 mismatch is rejected")


def test_T21_pointwise_denominator_tower_clarification():
    # O9: a genuine pointwise post-hoc denominator for the SAME event is not
    # counterexampled.  For A^2 after the first base pull: F gives q=1;
    # S gives q=P(A^2|S)=1/6.  Then E[1_A/q | F_tau] = 1.
    p_F = F(1, 5)
    p_S = F(4, 5)
    q_exact_S = crossing_probs(CAND, (5, 1), C_P2, 1)[1]
    assert q_exact_S == F(1, 6)
    exact = p_F * 1 + p_S * (q_exact_S / q_exact_S)
    slack = p_F * 1 + p_S * (q_exact_S / F(1, 4))
    assert exact == 1 and slack == F(11, 15) and slack <= 1
    print("T21 PASS — pointwise same-event denominator obeys tower: exact=1, "
          "slack=11/15<=1; the killed trap is numerator/coverage misuse")


# ------------------------------------------------------------- [SIM] cells

def _cell(name, builder, n, seed, target, side, predicted):
    rng = random.Random(seed)
    k = 0
    for _ in range(n):
        k += bernoulli_from_fraction(builder(rng), rng)  # exact E[Y]=E[FLR]
    label = cell_label(predicted, n, k)
    if label == "VACUOUS":
        print(f"  [SIM] {name}: events=0/{n} -> PASS(vacuous)")
        return "PASS(vacuous)", k
    if side == "validity":
        ub = cp_upper(k, n, 0.05)
        ok = ub <= target
        print(f"  [SIM] {name}: k={k}/{n} CP-upper={ub:.4f} target<={target} "
              f"-> {'PASS' if ok else 'FAIL'} ({label})")
        assert ok and label == "POWERED", name
        return "PASS", k
    lb = cp_lower(k, n, 0.05)
    ok = lb > target
    print(f"  [SIM] {name}: k={k}/{n} CP-lower={lb:.4f} target>{target} "
          f"-> {'FALSIFIED' if ok else 'NOT-FALSIFIED'} ({label})")
    assert ok and label == "POWERED", name
    return "FALSIFIED", k


def _b_honest(rng):
    cert = _b_honest.cert
    acct = FleetAccountant("elond", F(1, 3), gammas=[F(1, 4)] * 4)
    for _ in range(4):
        r = acct.consider(cert.u, cert)
        assert r["executed"]
        acct.adjudicate(r["id"], sample_crossed(CAND, BASE, C_POW, 2, rng))
    return acct.report()["flr"]
_b_honest.cert = None


def _b_naive(rng):
    acct = FleetAccountant("naive-broken", F(1, 3))
    r = acct.consider(F(1, 3))
    if acct.adjudicate(r["id"], sample_crossed(CAND, BASE, C_P2, 2, rng)) > 0:
        return acct.report()["flr"]                      # stop on rescue
    for _ in range(3):
        r = acct.consider(F(1, 3))
        acct.adjudicate(r["id"], sample_crossed(CAND, BASE, C_P2, 2, rng))
    return acct.report()["flr"]


def _b_fake(rng):
    acct = FleetAccountant("naive-broken", F(2, 5))      # gate u<=delta
    for _ in range(6):
        if rng.randrange(5) < 4:                          # pre-pull: S w.p. 4/5
            continue                                      # adversary withholds S
        r = acct.consider(F(1, 3), Certificate(W=2, u=F(1, 3),
                                               note="state-averaged"))
        acct.adjudicate(r["id"], True)                    # F crosses at issue
    return acct.report()["flr"]


def _b_csel(rng):
    us = [F(1) if rng.randrange(5) >= 4 else F(1, 6) for _ in range(2)]
    u = max(us)                                           # largest-u adversary
    acct = FleetAccountant("ebh", F(2, 5), k_max=1)
    r = acct.consider(u, Certificate(W=2, u=u, note="pointwise tight"))
    if r["executed"]:                                     # only the S-state runs
        acct.adjudicate(r["id"], sample_crossed(CAND, (5, 1), C_P2, 2, rng))
    return acct.report()["flr"]


def _b_vacuous(rng):
    cert = _b_vacuous.cert
    acct = FleetAccountant("ebh", F(2, 5), k_max=1)
    r = acct.consider(cert.u, cert)
    acct.adjudicate(r["id"], sample_crossed(CAND, BASE, F(9, 10), 2, rng))
    return acct.report()["flr"]
_b_vacuous.cert = None


def test_T19_sim_cells():
    assert crossed_now(CAND, (4, 2), C_P2)               # fake-cell premise
    _b_honest.cert = certify_windowed(CAND, BASE, C_POW, 2)
    _b_vacuous.cert = certify_windowed(CAND, BASE, F(9, 10), 2)
    assert _b_vacuous.cert.u == 0
    print("T19 [SIM] cells (seeded, one-sided CP, alpha=.05):")
    _cell("honest e-LOND (E=1/15, delta=1/3)", _b_honest, 1500, SEED + 1,
          1 / 3, "validity", 1 / 15)
    _cell("BROKEN naive gate (E=1/2, delta=1/3)", _b_naive, 1500, SEED + 2,
          1 / 3, "violation", 1 / 2)
    _cell("fake-average cert (E=.738, delta=2/5)", _b_fake, 1500, SEED + 3,
          2 / 5, "violation", 11529 / 15625)
    _cell("largest-u adversary, pointwise (E=8/75, delta=2/5)", _b_csel,
          1500, SEED + 4, 2 / 5, "validity", 8 / 75)
    _cell("vacuous (c=9/10, u=0)", _b_vacuous, 300, SEED + 5,
          2 / 5, "validity", 0.0)
    print("T19 PASS — broken variant falsified; honest cells pass POWERED; "
          "vacuous prints PASS(vacuous)")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_T")]


def load_tests(loader, tests, pattern):
    """Expose the exact-pin functions to `python -m unittest` without
    duplicating pytest collection. Direct execution below remains the most
    verbose runner; pytest still collects the plain test_T* functions.
    """
    suite = unittest.TestSuite()
    for t in TESTS:
        suite.addTest(unittest.FunctionTestCase(t))
    return suite

if __name__ == "__main__":
    for t in TESTS:
        t()
    print(f"\nALL {len(TESTS)} TESTS PASS "
          "(exact pins + mechanical checks + 5 [SIM] cells)")
