"""Pins for velvet.verdict.retirement (T4B quantile component retirement).

Near-verbatim port of gating-moonshot @ 3e0e7cf src/test_t4b.py (see
src/velvet/verdict/UPSTREAM.md), plus velvet product-surface tests for the
verdict adjudicator, the forced mean-certificate refusal, and the
flr_ebh.threshold_for parity. The upstream `*_kill_results_recorded` test
(reads the moonshot experiments/ records) is intentionally not ported.

Pin discipline (inherited): exact floats/counts under seeded default_rng
streams are regression pins; the guards (validity counts under CP-style
bounds, raw-clock power domination, proof-grade >= sharp domination, the
depth-cancellation inequality, zero false certificates, deterministic
ledger crossing) carry the falsification meaning. All simulator output is
[SIM].
"""
from __future__ import annotations

import math

import numpy as np
import pytest
from verdict_moonshot_sim import (
    mc_dead_bill,
    mc_ledger_boundary,
    run_mix,
    run_w_trial,
)

from velvet.verdict.retirement import (
    MeanCertificateUnpriceable,
    QuantileQuestion,
    ReasonCode,
    cap_ext_proof,
    ebh_ln_threshold,
    gamma_led,
    j_star,
    k_w_proof,
    mean_certificate,
    n_floor,
    n_ret_star,
    predict_ret_bill,
    quantile_retirement_verdict,
)

T = 65536
LT = math.log(float(T) * T)
DT = 1.0 / (float(T) * T)
COMPS = [
    [(0.03, 0.5), (0.7, 0.5)],
    [(0.6, 1.0)],
    [(0.3, 0.4), (0.6, 0.6)],
    [(0.1, 0.5), (0.6, 0.5)],
    [(0.45, 1.0)],
]


def test_t4b_fixed_points_and_floor_arithmetic():
    # fixed points used throughout the theorem file + experiment
    assert j_star(0.6, 0.3, LT) == 132
    assert j_star(0.2, 0.1, LT) == 587
    assert j_star(0.03, 0.3, LT) == 102          # witness side, same formula
    assert n_ret_star(0.4, math.log(5 / 0.1), DT) == 12   # e-BH R=0 threshold
    assert n_ret_star(0.4, math.log(20.0), DT) == 10
    assert n_ret_star(0.15, math.log(20.0), DT) == 34
    # crossing property: n* fires, n*-1 does not (deterministic all-ones)
    for th, L in [(0.4, math.log(50.0)), (0.15, math.log(20.0))]:
        n = n_ret_star(th, L, DT)
        rate = math.log(1.0 / (1.0 - th * (1.0 - DT)))
        assert n * rate >= L + 0.5 * math.log(n) + math.log(2.0)
        assert (n - 1) * rate < L + 0.5 * math.log(n - 1) + math.log(2.0)
    # the unconditional count floor (Theorem C-iv(a))
    assert n_floor(0.4, 0.02) == 7
    assert n_floor(0.4, 0.025) == 6
    assert n_floor(0.1, 0.02) == 31
    # e-BH plumbing
    assert abs(ebh_ln_threshold(5, 0.1, 0) - math.log(50.0)) < 1e-12
    assert abs(ebh_ln_threshold(5, 0.1, 1) - math.log(25.0)) < 1e-12


def test_t4b_proof_grade_dominates_sharp_and_depth_cancellation():
    # proof-grade bills dominate the sharp fixed points (Lemma C3 honest)
    for u in (0.61, 0.7, 0.9):
        assert k_w_proof(u, 0.3, T) >= j_star(u, 0.3, LT)
    # K_ext dominates K_W on u >= 2y*
    for u in (0.6, 0.7, 0.9, 1.0):
        assert cap_ext_proof(0.3, T) >= k_w_proof(u, 0.3, T)
    # the depth cancellation (Theorem C-iii(d)): pulls(u) * u <= gamma_led,
    # with pulls = K_W(u) when fired (u >= 2y*), K_ext when capped (u < 2y*)
    g = gamma_led(T)
    for u in np.linspace(0.6, 1.0, 9):
        assert k_w_proof(float(u), 0.3, T) * u <= g
    for u in np.linspace(0.05, 0.6, 12):
        assert cap_ext_proof(0.3, T) * u <= g


def test_t4b_w_trial_regression():
    rng = np.random.default_rng(95001)
    pins = [(1, 144), (1, 122), (1, 113)]
    for b, pulls in pins:
        tr = run_w_trial(rng, 0.6, 0.3, LT, 396)
        assert tr["B"] == b and tr["pulls"] == pulls and tr["fired_nw"]
    tr = run_w_trial(np.random.default_rng(95005), 0.03, 0.3, LT, 396)
    assert tr["B"] == 0 and tr["fired_w"] and tr["pulls"] == 110


def test_t4b_ledger_boundary_mini():
    # validity guard at the exact null boundary (binding case of Lemma C1)
    r = mc_ledger_boundary(0.4, DT, 0.05, 800, 400, seed=95003)
    assert r["fires_kt"] == 5                      # regression pin
    assert r["fires_kt"] <= 20 + 3 * math.sqrt(400 * .05 * .95)  # CP guard
    assert r["fires_raw"] == 48                    # regression pin
    assert r["fires_raw"] > 3 * r["fires_kt"]      # raw clock invalid: power


def test_t4b_dead_bill_regression_and_predictor():
    db = mc_dead_bill(0.6, 0.4, 0.3, 0.05, DT, cap=396, reps=5, seed=95004)
    assert list(db["trials"]) == [10] * 5          # deterministic crossing
    assert bool(db["fired"].all())
    assert int(db["pulls"].sum()) == 6605          # regression pin
    pred = predict_ret_bill(0.6, 0.4, 0.3, math.log(20.0), LT, 396)
    assert pred.n_ret == 10 and pred.pulls == 1320
    ratio = db["pulls"].mean() / pred.pulls
    assert 0.7 <= ratio <= 1.3                     # guard band


def test_t4b_run_mix_regression_cell():
    o = run_mix(T=T, p=0.4, eps=0.5, y=0.05, comps=COMPS, ystar=0.3,
                theta=0.4, delta=0.1, seed=95002)
    assert abs(o["regret"] - 11794.71000000001) < 1e-6   # regression pin
    assert list(o["retired"].astype(int)) == [0, 1, 0, 0, 0]
    assert int(o["nB"][1]) == 12                   # deterministic n* pin
    assert o["flr"] == 0.0
    assert o["false_nw"] == 0 and o["false_w"] == 0
    assert o["false_accepts"] == 0 and o["false_half"] == 0
    assert o["status"][1] == "Retired"
    # the alive components are refused, never retired, in this cell
    assert o["status"][0] == "NotSeparated"


def test_t4b_clause7_violation_witness():
    # CE-7 mini: filtered ALIVE component gets retired with zero false certs
    hits = 0
    for r in range(3):
        o = run_mix(T=T, p=0.4, eps=0.5, y=0.05, comps=COMPS, ystar=0.3,
                    theta=0.4, delta=0.1, seed=95100 + r,
                    filter_min={2: 0.5})
        hits += int(o["retired"][2])
        assert o["false_nw"] == 0 and o["false_w"] == 0
    assert hits == 3


def test_t4b_clause8_off_evidence_censored():
    # C-F demo: without ledger admissions the gate starves every question
    o = run_mix(T=T, p=0.4, eps=0.5, y=0.05, comps=COMPS, ystar=0.3,
                theta=0.4, delta=0.1, seed=95200, ledger_admission=False)
    assert not o["retired"].any()
    fl = n_floor(0.4, 0.1 / 5)
    assert all(int(n) < fl for n in o["nB"])
    assert all(s == "EvidenceCensored" for s in o["status"])


# ---------------------------------------------------------------------------
# Velvet product surface (not upstream ports)
# ---------------------------------------------------------------------------

QUESTION = QuantileQuestion(
    component_id="comp-1", y_star=0.3, theta=0.4, delta=0.1, delta_T=DT, k_max=5
)


def test_ebh_threshold_matches_flr_ebh_threshold_for():
    from velvet.verdict.flr_ebh import threshold_for
    for executed in (0, 1, 2, 7):
        assert ebh_ln_threshold(8, 0.05, executed) == math.log(
            threshold_for(8, 0.05, executed)
        )


def test_quantile_question_derived_fields():
    assert QUESTION.n_floor == n_floor(0.4, 0.1 / 5)
    assert abs(QUESTION.b_star - (1.0 - 0.4 * (1.0 - DT))) < 1e-15


def test_verdict_evidence_censored_below_floor_is_forced():
    # below the unconditional floor the FORCED output is EvidenceCensored,
    # deterministically, regardless of the drop stream
    fl = QUESTION.n_floor
    for drops in range(fl):
        v = quantile_retirement_verdict(QUESTION, n_admissions=drops, drop_count=drops)
        assert v.verdict == "refusal"
        assert v.reason_code is ReasonCode.EVIDENCE_CENSORED


def test_verdict_safe_kill_at_deterministic_crossing():
    # the all-drops stream crosses exactly at n_ret_star (e-BH rung R=0)
    n_star = n_ret_star(0.4, ebh_ln_threshold(5, 0.1, 0), DT)
    v = quantile_retirement_verdict(QUESTION, n_admissions=n_star, drop_count=n_star)
    assert v.verdict == "safe_kill" and v.is_safe_kill
    assert v.reason_code is None
    v_prev = quantile_retirement_verdict(
        QUESTION, n_admissions=n_star - 1, drop_count=n_star - 1
    )
    assert v_prev.verdict == "required_inspection"
    assert v_prev.reason_code is ReasonCode.UNCERTIFIED_NEEDS_MORE_HORIZON


def test_verdict_not_separated_at_exhausted_allowance():
    v = quantile_retirement_verdict(
        QUESTION, n_admissions=24, drop_count=6, allowance=24
    )
    assert v.verdict == "refusal"
    assert v.reason_code is ReasonCode.NOT_SEPARATED


def test_mean_certificate_is_refused_as_api():
    with pytest.raises(MeanCertificateUnpriceable):
        mean_certificate()


def test_quantile_question_validation():
    with pytest.raises(ValueError):
        QuantileQuestion(
            component_id="x", y_star=0.0, theta=0.4, delta=0.1, delta_T=DT, k_max=5
        )
    with pytest.raises(ValueError):
        QuantileQuestion(
            component_id="x", y_star=0.3, theta=1.0, delta=0.1, delta_T=DT, k_max=5
        )
    with pytest.raises(ValueError):
        quantile_retirement_verdict(QUESTION, n_admissions=3, drop_count=4)
