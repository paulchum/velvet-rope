"""Golden parity: velvet product code reproduces the upstream moonshot values.

The committed fixture ``tests/fixtures/moonshot_parity_v1.json`` records
outputs of the gating-moonshot witnesses at the commit pinned in
``src/velvet/verdict/UPSTREAM.md`` (regenerate with
``scripts/generate_moonshot_parity.py`` — only after the upstream battery
passes). This test asserts the velvet ports reproduce every value, so
parity survives without the sibling repos present.

Integers must match exactly; floats to 1e-12 relative (same IEEE ops, so
they are bit-identical in practice — the tolerance covers libm variation).
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import numpy as np

from velvet.verdict.eprocess import (
    ledger_log_e,
    pair_z_vec,
    w_thresholds,
    w_z_prefix,
    z_half_scalar,
)
from velvet.verdict.lease import (
    design_cycle,
    lease_ceiling,
    predict_lease_bill,
    q_of_t,
    rho_uncond_max,
    theta_shifted,
)
from velvet.verdict.retirement import (
    cap_ext_proof,
    ebh_ln_threshold,
    gamma_led,
    j_star,
    k_w_proof,
    n_floor,
    n_ret_star,
    predict_ret_bill,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "moonshot_parity_v1.json"
REL_TOL = 1e-12


def _fixture() -> dict[str, Any]:
    with FIXTURE_PATH.open() as f:
        data: dict[str, Any] = json.load(f)
    return data


def _close(a: float, b: float) -> bool:
    return math.isclose(a, b, rel_tol=REL_TOL, abs_tol=1e-15)


def test_fixture_source_commit_is_pinned_in_upstream_md() -> None:
    fx = _fixture()
    commit = fx["source"]["commit"]
    upstream = (
        Path(__file__).resolve().parent.parent / "src" / "velvet" / "verdict" / "UPSTREAM.md"
    ).read_text()
    assert commit[:7] in upstream, (
        "fixture was generated from a commit not pinned in UPSTREAM.md — "
        "regenerate after updating the provenance table"
    )


def test_parity_t4b_scalar_predictors() -> None:
    fx = _fixture()
    for row in fx["j_star"]:
        assert j_star(row["u"], row["ystar"], row["ln_inv_delta"]) == row["value"]
    for row in fx["n_ret_star"]:
        assert n_ret_star(row["theta"], row["ln_inv_delta_eff"], row["delta_T"]) == row["value"]
    for row in fx["n_floor"]:
        assert n_floor(row["theta"], row["delta"]) == row["value"]
    for row in fx["ebh_ln_threshold"]:
        assert _close(
            ebh_ln_threshold(row["k_max"], row["delta"], row["executed"]), row["value"]
        )
    pg = fx["proof_grade"]
    for row in pg["k_w_proof"]:
        assert k_w_proof(row["u"], row["ystar"], row["T"]) == row["value"]
    assert cap_ext_proof(pg["cap_ext_proof"]["ystar"], pg["cap_ext_proof"]["T"]) == (
        pg["cap_ext_proof"]["value"]
    )
    assert _close(gamma_led(pg["gamma_led"]["T"]), pg["gamma_led"]["value"])
    prb = fx["predict_ret_bill"]
    bill = predict_ret_bill(
        prb["inputs"]["s"],
        prb["inputs"]["theta"],
        prb["inputs"]["ystar"],
        prb["inputs"]["ln_inv_delta_eff"],
        prb["inputs"]["ln_inv_delta_T"],
        prb["inputs"]["cap"],
    )
    assert bill.n_ret == prb["n_ret"]
    assert bill.pulls == prb["pulls"]
    assert bill.per_trial == prb["per_trial"]


def test_parity_e_statistics() -> None:
    fx = _fixture()
    for row in fx["ledger_ln_e"]:
        assert _close(ledger_log_e(row["n"], row["s"], row["bstar"]), row["value"])
    wp = fx["w_prefix"]
    successes = np.asarray(wp["successes"])
    j = np.arange(1, len(successes) + 1)
    z_nw, z_w = w_z_prefix(j, successes, wp["ystar"])
    thr = w_thresholds(j, math.log(float(65536) * 65536))
    for i in range(len(successes)):
        assert _close(float(z_nw[i]), wp["z_nw"][i])
        assert _close(float(z_w[i]), wp["z_w"][i])
        assert _close(float(thr[i]), wp["thresholds"][i])
    for row in fx["z_half"]:
        assert _close(z_half_scalar(row["k"], row["s_c"], row["n"], row["s_a"]), row["value"])
    for row in fx["pair_z"]:
        got = float(
            pair_z_vec(
                np.array([row["n_a"]]),
                np.array([row["s_a"]]),
                np.array([row["n_b"]]),
                np.array([row["s_b"]]),
            )[0]
        )
        assert _close(got, row["value"])


def test_parity_t4d_design_arithmetic() -> None:
    fx = _fixture()
    sc = fx["t4d_scalars"]
    ts = sc["theta_shifted"]
    assert _close(
        theta_shifted(ts["theta"], ts["rho"], ts["w_r"], ts["t_lease"]), ts["value"]
    )
    assert _close(lease_ceiling(0.4, 0.0, 2e-4), sc["lease_ceiling_dead"])
    assert _close(lease_ceiling(0.4, 0.01, 2e-4), sc["lease_ceiling_parked"])
    assert _close(rho_uncond_max(0.4, 0.1), sc["rho_uncond_max"])
    for row in sc["q_of_t"]:
        assert _close(
            q_of_t(row["t"], row["q0"], row["onset"], row["rho"], row["cap"]),
            row["value"],
        )
    for case in fx["design_cycle"]:
        i, out = case["inputs"], case["output"]
        d = design_cycle(
            i["theta"], i["rho"], i["delta"], i["k_slots"], i["delta_T"], i["spacing"]
        )
        assert d.n_led == out["n_led"]
        assert d.w_r == out["w_r"]
        assert d.t_lease == out["t_lease"]
        assert d.cycle == out["cycle"]
        assert d.feasible == out["feasible"]
        assert d.status == out["status"]
        assert _close(d.theta_shifted, out["thetat"])
        assert _close(d.rho_max, out["rho_max"])
        assert _close(d.l_eff, out["l_eff"])
        assert _close(d.b_star_shifted, out["bstar_shifted"])
    for case in fx["predict_lease_bill"]:
        i, out = case["inputs"], case["output"]
        bill = predict_lease_bill(
            i["s_depth"], i["ystar"], i["theta"], i["rho"], i["delta"],
            i["k_slots"], i["delta_T"], i["wait"],
        )
        assert bill.design.w_r == out["w_r"]
        assert bill.design.t_lease == out["t_lease"]
        assert bill.design.n_led == out["n_led"]
        assert bill.per_trial_pulls == out["per_trial_pulls"]
        assert bill.per_cycle_pulls == out["per_cycle_pulls"]
        assert bill.cycle_realized == out["cycle_realized"]
        assert _close(bill.amortized, out["amortized"])
        assert bill.per_cycle_regret is not None
        assert _close(bill.per_cycle_regret, out["per_cycle_regret"])
