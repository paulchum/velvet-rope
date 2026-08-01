#!/usr/bin/env python3
"""Regenerate tests/fixtures/moonshot_parity_v1.json from the sibling repos.

Runs ONLY where the sibling research repos exist (developer machines); the
committed fixture is the CI artifact, so parity survives without the
siblings present (same doctrine as tests/test_verdict_upstream_parity.py).

The fixture records outputs of the UPSTREAM witnesses (gating-moonshot @
the pinned commit in src/velvet/verdict/UPSTREAM.md); the parity test then
asserts the velvet product modules reproduce every value. Regenerate only
after re-running the upstream battery (132/132 ALL PASS) and update the
pinned commit in UPSTREAM.md if the upstream tree moved.

Usage: uv run python scripts/generate_moonshot_parity.py
       uv run python scripts/generate_moonshot_parity.py --moonshot-src /path/to/src
"""
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

DEFAULT_MOONSHOT_SRC = Path(__file__).resolve().parents[2] / "gating-moonshot" / "src"
OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "moonshot_parity_v1.json"

T = 65536
LT = math.log(float(T) * T)
DT = 1.0 / (float(T) * T)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--moonshot-src", type=Path, default=DEFAULT_MOONSHOT_SRC)
    args = parser.parse_args(argv)
    moonshot_src = args.moonshot_src.resolve()
    if not moonshot_src.exists():
        print(f"sibling repo not found at {moonshot_src}; fixture left unchanged")
        return 1
    sys.path.insert(0, str(moonshot_src))
    import numpy as np
    import t4b_witness as t4b
    import t4d_witness as t4d
    from tna_witness import z_half_vec

    git = shutil.which("git")
    if git is None:
        print("git executable not found; fixture left unchanged")
        return 1
    commit = subprocess.run(  # noqa: S603  # nosec B603
        [git, "-C", str(moonshot_src.parent), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    fixture: dict[str, object] = {
        "source": {
            "repo": "gating-moonshot",
            "commit": commit,
            "note": "outputs of the upstream witnesses; velvet product code "
                    "must reproduce every value (tests/test_verdict_moonshot_parity.py)",
        },
    }

    # --- t4b scalar predictors -------------------------------------------
    fixture["j_star"] = [
        {"u": u, "ystar": ys, "ln_inv_delta": LT, "value": t4b.j_star(u, ys, LT)}
        for (u, ys) in [(0.6, 0.3), (0.2, 0.1), (0.03, 0.3), (0.7, 0.3), (0.45, 0.3)]
    ]
    fixture["n_ret_star"] = [
        {"theta": th, "ln_inv_delta_eff": L, "delta_T": DT,
         "value": t4b.n_ret_star(th, L, DT)}
        for (th, L) in [(0.4, math.log(5 / 0.1)), (0.4, math.log(20.0)),
                        (0.15, math.log(20.0)), (0.2, math.log(640.0)),
                        (0.4, math.log(640.0))]
    ]
    fixture["n_floor"] = [
        {"theta": th, "delta": d, "value": t4b.n_floor(th, d)}
        for (th, d) in [(0.4, 0.02), (0.4, 0.025), (0.1, 0.02), (0.4, 0.1),
                        (0.4, 0.02 / 5)]
    ]
    fixture["ebh_ln_threshold"] = [
        {"k_max": k, "delta": d, "executed": e,
         "value": t4b.ebh_ln_threshold(k, d, e)}
        for (k, d, e) in [(5, 0.1, 0), (5, 0.1, 1), (8, 0.05, 0), (64, 0.1, 3)]
    ]
    fixture["proof_grade"] = {
        "k_w_proof": [
            {"u": u, "ystar": 0.3, "T": T, "value": t4b.k_w_proof(u, 0.3, T)}
            for u in (0.61, 0.7, 0.9, 1.0)
        ],
        "cap_ext_proof": {"ystar": 0.3, "T": T, "value": t4b.cap_ext_proof(0.3, T)},
        "gamma_led": {"T": T, "value": t4b.gamma_led(T)},
    }
    prb = t4b.predict_ret_bill(0.6, 0.4, 0.3, math.log(20.0), LT, 396)
    fixture["predict_ret_bill"] = {
        "inputs": {"s": 0.6, "theta": 0.4, "ystar": 0.3,
                   "ln_inv_delta_eff": math.log(20.0), "ln_inv_delta_T": LT,
                   "cap": 396},
        "n_ret": prb["n_ret"], "pulls": prb["pulls"], "per_trial": prb["per_trial"],
    }

    # --- e-statistic grids ------------------------------------------------
    bstar = 1.0 - 0.4 * (1.0 - DT)
    grid = [(1, 1), (5, 5), (10, 10), (12, 12), (16, 16), (17, 17),
            (20, 13), (40, 25), (100, 61)]
    fixture["ledger_ln_e"] = [
        {"n": n, "s": s, "bstar": bstar,
         "value": float(t4b.ledger_ln_e(np.array([n]), np.array([s]), bstar)[0])}
        for (n, s) in grid
    ]
    j = np.arange(1, 41)
    s_stream = np.cumsum((np.arange(40) % 3 == 0).astype(int))
    z_nw, z_w = t4b.w_z_prefix(j, s_stream, 0.3)
    fixture["w_prefix"] = {
        "ystar": 0.3,
        "successes": s_stream.tolist(),
        "z_nw": z_nw.tolist(),
        "z_w": z_w.tolist(),
        "thresholds": t4b.w_thresholds(j, LT).tolist(),
    }
    half_grid = [(30, 6, 60, 45), (10, 1, 40, 30), (25, 5, 25, 20), (8, 4, 8, 5)]
    fixture["z_half"] = [
        {"k": k, "s_c": sc, "n": n, "s_a": sa,
         "value": float(z_half_vec(np.array([k]), np.array([sc]),
                                   np.array([n]), np.array([sa]))[0])}
        for (k, sc, n, sa) in half_grid
    ]
    pair_grid = [(30, 12, 30, 20), (50, 20, 25, 18), (12, 3, 40, 28)]
    fixture["pair_z"] = [
        {"n_a": na, "s_a": sa, "n_b": nb, "s_b": sb,
         "value": float(t4b._pair_z_vec(np.array([na]), np.array([sa]),
                                        np.array([nb]), np.array([sb]))[0])}
        for (na, sa, nb, sb) in pair_grid
    ]

    # --- t4d design arithmetic --------------------------------------------
    fixture["t4d_scalars"] = {
        "theta_shifted": {"theta": 0.4, "rho": 2e-4, "w_r": 246, "t_lease": 754,
                          "value": t4d.theta_shifted(0.4, 2e-4, 246, 754)},
        "lease_ceiling_dead": t4d.lease_ceiling(0.4, 0.0, 2e-4),
        "lease_ceiling_parked": t4d.lease_ceiling(0.4, 0.01, 2e-4),
        "rho_uncond_max": t4d.rho_uncond_max(0.4, 0.1),
        "q_of_t": [
            {"t": 100, "q0": 0.0, "onset": -1, "rho": 2e-4, "cap": 0.4,
             "value": t4d.q_of_t(100, 0.0, -1, 2e-4, 0.4)},
            {"t": 1500, "q0": 0.0, "onset": 500, "rho": 2e-4, "cap": 0.4,
             "value": t4d.q_of_t(1500, 0.0, 500, 2e-4, 0.4)},
        ],
    }
    designs = []
    for (theta, rho, delta, k_slots, spacing) in [
        (0.4, 2e-4, 0.1, 64, 4),
        (0.4, 5e-5, 0.1, 64, 16),
        (0.4, 1e-3, 0.1, 64, 4),
    ]:
        d = t4d.design_cycle(theta, rho, delta, k_slots, DT, spacing)
        designs.append({"inputs": {"theta": theta, "rho": rho, "delta": delta,
                                   "k_slots": k_slots, "delta_T": DT,
                                   "spacing": spacing}, "output": d})
    fixture["design_cycle"] = designs
    bills = []
    for rho in (2e-5, 1e-5):
        b = t4d.predict_lease_bill(0.6, 0.3, 0.4, rho, 0.1, 64, DT, wait=4)
        bills.append({"inputs": {"s_depth": 0.6, "ystar": 0.3, "theta": 0.4,
                                 "rho": rho, "delta": 0.1, "k_slots": 64,
                                 "delta_T": DT, "wait": 4}, "output": b})
    fixture["predict_lease_bill"] = bills

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT} from gating-moonshot @ {commit[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
