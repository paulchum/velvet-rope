"""Pins for velvet.verdict.lease (T4D retirement leases under drift).

Near-verbatim port of gating-moonshot @ 3e0e7cf src/test_t4d.py (see
src/velvet/verdict/UPSTREAM.md), plus velvet product-surface tests for the
lease adjudicator's forced refusals. The upstream `*_kill_results_recorded`
test (reads the moonshot experiments/ records) is intentionally not ported.

Pin discipline (inherited): exact floats/counts under seeded default_rng
streams are regression pins; the guards (validity counts under CP-style
bounds, the deterministic shifted-boundary crossing, zero violations of the
windowed scheme, naive-violated == naive-executed, the lease-ceiling and
boundary-shift identities, predictor ratio bands) carry the falsification
meaning. All simulator output is [SIM].
"""
from __future__ import annotations

import math

import numpy as np
from verdict_moonshot_sim import (
    mc_ledger_boundary,
    mc_ramp_term,
    run_lease_sim,
)

from velvet.verdict.eprocess import ledger_ln_e
from velvet.verdict.lease import (
    design_cycle,
    lease_ceiling,
    lease_verdict,
    predict_lease_bill,
    q_of_t,
    rho_uncond_max,
    theta_shifted,
)
from velvet.verdict.retirement import (
    QuantileQuestion,
    ReasonCode,
    n_floor,
    n_ret_star,
)

T = 65536
DT = 1.0 / (float(T) * T)
THETA, YSTAR, DELTA = 0.4, 0.3, 0.1
COMPS_A = [dict(q0=0.0), dict(q0=0.0),
           dict(q0=0.0, onset="at_fire", q_cap=THETA), dict(q0=THETA)]
PARKED = [dict(q0=0.01, onset="at_fire", q_cap=THETA)]


def test_t4d_design_arithmetic_exact():
    # migration/shift identities (Theorem D2's arithmetic surface)
    assert abs(theta_shifted(0.4, 2e-4, 246, 754) - 0.2) < 1e-12
    assert lease_ceiling(0.4, 0.0, 2e-4) == 2000.0        # D1(c) ceiling
    assert lease_ceiling(0.4, 0.01, 2e-4) == 1950.0       # the parked truth
    # unconditional refusal boundary (Theorem D4(d))
    assert n_floor(0.4, 0.1) == 4
    assert abs(rho_uncond_max(0.4, 0.1) - 0.1) < 1e-12
    # canonical designs (kill cells' exact parameters)
    dB = design_cycle(0.4, 2e-4, 0.1, 64, DT, 4)
    assert (dB.w_r, dB.t_lease, dB.n_led) == (246, 754, 41)
    assert abs(dB.rho_max - 0.0008097165991902835) < 1e-15
    dA = design_cycle(0.4, 5e-5, 0.1, 64, DT, 16)
    assert (dA.w_r, dA.t_lease, dA.n_led) == (984, 3016, 41)
    assert abs(dA.rho_max - 0.00020304568527918784) < 1e-15
    # the forced refusal past the design boundary (Theorem D3(a))
    dbad = design_cycle(0.4, 1e-3, 0.1, 64, DT, 4)
    assert dbad.status == "DriftTooFast" and dbad.t_lease <= 0
    assert not dbad.feasible
    assert dbad.forced_refusal is ReasonCode.DRIFT_TOO_FAST
    # shifted-boundary crossing property: n*(thetat) fires, n*-1 does not
    n41 = n_ret_star(0.2, math.log(640.0), DT)
    assert n41 == 41
    rate = math.log(1.0 / (1.0 - 0.2 * (1.0 - DT)))
    assert n41 * rate >= math.log(640.0) + 0.5 * math.log(n41) + math.log(2.0)
    assert (n41 - 1) * rate < math.log(640.0) + 0.5 * math.log(n41 - 1) \
        + math.log(2.0)
    # drift path evaluator
    assert q_of_t(100, 0.0, -1, 2e-4, 0.4) == 0.0          # static
    assert abs(q_of_t(1500, 0.0, 500, 2e-4, 0.4) - 0.2) < 1e-12
    assert q_of_t(10 ** 6, 0.0, 500, 2e-4, 0.4) == 0.4     # capped


def test_t4d_stale_evidence_false_at_issue_mini():
    # Theorem D1(a): the unwindowed ledger, one B=1 from crossing, fires on
    # an alive-at-theta component with conditional probability b* ~ 0.6.
    l_eff = math.log(640.0)
    bstar = 1.0 - THETA * (1.0 - DT)
    ln16 = float(ledger_ln_e(np.array([16]), np.array([16]), bstar)[0])
    ln17 = float(ledger_ln_e(np.array([17]), np.array([17]), bstar)[0])
    assert ln16 < l_eff <= ln17            # crossing exactly at n* = 17
    rng = np.random.default_rng(96001)
    fires = int((rng.random(2000) < bstar).sum())
    assert fires == 1207                   # regression pin (rate 0.60 >> delta)
    assert fires > 0.5 * 2000              # guard: false-at-issue is the rule


def test_t4d_unwindowed_false_permanence_mini():
    # Theorem D1(b): permanent claim, true at issue, violated by the onset
    # drifter — FLR_lease = 1/3 deterministically at these params.
    for seed in (96101, 96102, 96103):
        r = run_lease_sim(24000, THETA, YSTAR, DELTA, 64, 5e-5, COMPS_A,
                          seed, windowed=False)
        assert r["executed"] == 3 and r["violated"] == 1
        assert r["viol_true_at_issue"] == 1        # true at issue, then false
        assert r["false_at_issue"] == 0
        assert abs(r["flr_lease"] - 1.0 / 3.0) < 1e-12
        assert r["cycle_trials"][2] == [17]        # deterministic n*(theta)


def test_t4d_windowed_repair_mini():
    # Theorem D2/D3: same environment, windowed cycle ledger — leases fire
    # at exactly n*(thetat) = 41 trials, zero violations, zero shortfalls.
    d = design_cycle(THETA, 5e-5, DELTA, 64, DT, 16)
    r = run_lease_sim(24000, THETA, YSTAR, DELTA, 64, 5e-5, COMPS_A, 96201,
                      windowed=True, w_r=d.w_r, t_lease=d.t_lease)
    assert r["executed"] == 15 and r["violated"] == 0
    assert r["shortfalls"] == 0 and r["no_cert_terms"] == 44
    dead_trials = r["cycle_trials"][0] + r["cycle_trials"][1]
    assert set(dead_trials) == {41} and len(dead_trials) == 14
    assert r["cycle_trials"][2] == [41]            # drifter's one true lease


def test_t4d_ramp_and_boundary_minis():
    # Theorem D2 validity at the worst legal ramp + the iid binding case.
    d = design_cycle(THETA, 2e-4, DELTA, 64, DT, 4)
    ra = mc_ramp_term(THETA, 2e-4, d.w_r, d.t_lease, DELTA, 64, DT, 4,
                      400, 96301, shifted=True)
    rb = mc_ramp_term(THETA, 2e-4, d.w_r, d.t_lease, DELTA, 64, DT, 4,
                      400, 96301, shifted=False)
    assert ra["fires"] == 0                        # shifted clock: silent
    assert rb["fires"] == 60                       # naive clock: pinned flag
    assert rb["fires"] > 20                        # guard: >> delta * reps
    bb = mc_ledger_boundary(0.2, DT, 0.05, 800, 400, seed=96401)
    assert bb["fires_kt"] == 5                     # regression pin
    assert bb["fires_kt"] <= 20 + 3 * math.sqrt(400 * .05 * .95)  # CP guard
    assert bb["fires_raw"] == 51                   # raw clock invalid: power
    assert bb["fires_raw"] > 3 * bb["fires_kt"]


def test_t4d_parked_margin_mini():
    # Theorem D1(c): the ceiling alone does not protect — a naive lease
    # inside the q0=0 ceiling but past the true q0-ceiling is falsified;
    # the shifted design fires the same adversary safely.
    d = design_cycle(THETA, 2e-4, DELTA, 64, DT, 4)
    for seed in (96501, 96502, 96503):
        rn = run_lease_sim(8000, THETA, YSTAR, DELTA, 64, 2e-4, PARKED,
                           seed, windowed=True, w_r=d.w_r, t_lease=1960,
                           thetat=THETA)
        rs = run_lease_sim(8000, THETA, YSTAR, DELTA, 64, 2e-4, PARKED,
                           seed, windowed=True, w_r=d.w_r,
                           t_lease=d.t_lease)
        assert rn["executed"] == 1 and rn["violated"] == 1
        assert rs["executed"] == 1 and rs["violated"] == 0


def test_t4d_bill_predictor_and_regression():
    # Theorem D3(c): the maintenance-law predictor and a real-pulls pin.
    pb1 = predict_lease_bill(0.6, YSTAR, THETA, 2e-5, DELTA, 64, DT, wait=4)
    pb2 = predict_lease_bill(0.6, YSTAR, THETA, 1e-5, DELTA, 64, DT, wait=4)
    assert (pb1.design.w_r, pb1.design.t_lease, pb1.cycle_realized) == \
        (8364, 1636, 7212)
    assert abs(pb1.amortized - 0.4502495840266223) < 1e-15
    assert (pb2.design.w_r, pb2.design.t_lease, pb2.cycle_realized) == \
        (8364, 11636, 17212)
    assert abs(pb2.amortized - 0.1886590750639089) < 1e-15
    # leases lengthen as drift slows; amortized falls
    assert pb2.design.t_lease > pb1.design.t_lease
    assert pb2.amortized < pb1.amortized
    r = run_lease_sim(40000, THETA, YSTAR, DELTA, 64, 2e-5, [dict(q0=0.0)],
                      96601, windowed=True, w_r=pb1.design.w_r,
                      t_lease=pb1.design.t_lease, spacing=4, real_pulls=True,
                      s_depth=0.6, delta_T=DT)
    assert r["executed"] == 5 and r["violated"] == 0
    assert r["pulls_led"] == 30909                 # regression pin
    assert abs(r["reg_led"] - 18545.40000000001) < 1e-9
    assert set(r["cycle_trials"][0]) == {41}
    ratio = (r["reg_led"] / r["rounds"]) / pb1.amortized
    assert 0.85 <= ratio <= 1.15                   # guard band


# ---------------------------------------------------------------------------
# Velvet product surface (not upstream ports)
# ---------------------------------------------------------------------------

QUESTION = QuantileQuestion(
    component_id="comp-1", y_star=YSTAR, theta=THETA, delta=DELTA,
    delta_T=DT, k_max=64,
)


def test_lease_verdict_drift_too_fast_is_forced():
    # past the design boundary
    d_bad = design_cycle(THETA, 1e-3, DELTA, 64, DT, 4)
    v = lease_verdict(QUESTION, rho=1e-3, design=d_bad,
                      n_admissions_in_term=0, drop_count_in_term=0,
                      term_elapsed_rounds=0)
    assert v.verdict == "refusal"
    assert v.reason_code is ReasonCode.DRIFT_TOO_FAST
    # past the unconditional staleness ceiling, even with a feasible design
    d_ok = design_cycle(THETA, 2e-4, DELTA, 64, DT, 4)
    v2 = lease_verdict(QUESTION, rho=rho_uncond_max(THETA, DELTA), design=d_ok,
                       n_admissions_in_term=d_ok.n_led,
                       drop_count_in_term=d_ok.n_led,
                       term_elapsed_rounds=1)
    assert v2.verdict == "refusal"
    assert v2.reason_code is ReasonCode.DRIFT_TOO_FAST


def test_lease_verdict_safe_kill_buys_the_design_lease():
    d = design_cycle(THETA, 2e-4, DELTA, 64, DT, 4)
    # deterministic all-drops crossing at n_led (the shifted boundary)
    v = lease_verdict(QUESTION, rho=2e-4, design=d,
                      n_admissions_in_term=d.n_led,
                      drop_count_in_term=d.n_led,
                      term_elapsed_rounds=d.w_r)
    assert v.verdict == "safe_kill" and v.is_safe_kill
    assert v.lease_rounds == d.t_lease
    # one fewer trial: still open
    v_prev = lease_verdict(QUESTION, rho=2e-4, design=d,
                           n_admissions_in_term=d.n_led - 1,
                           drop_count_in_term=d.n_led - 1,
                           term_elapsed_rounds=d.w_r)
    assert v_prev.verdict == "required_inspection"
    assert v_prev.reason_code is ReasonCode.UNCERTIFIED_NEEDS_MORE_HORIZON


def test_lease_verdict_cadence_shortfall_is_evidence_censored_drift():
    d = design_cycle(THETA, 2e-4, DELTA, 64, DT, 4)
    v = lease_verdict(QUESTION, rho=2e-4, design=d,
                      n_admissions_in_term=d.n_led // 2,
                      drop_count_in_term=d.n_led // 2,
                      term_elapsed_rounds=d.w_r + 1)
    assert v.verdict == "refusal"
    assert v.reason_code is ReasonCode.EVIDENCE_CENSORED_DRIFT
