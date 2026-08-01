#!/usr/bin/env python3
"""F3/F4 falsification runner.

All output is simulation currency: every emitted line starts with [SIM].
Smoke mode is a quick wiring check. Full mode is the pre-registered adjudicator:
F3a uses one-sided Clopper-Pearson upper bounds, F3b checks the [0.5, 2] sample
band and Hoeffding comparison, and F4 checks quote-interval coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import random
import sys
from collections.abc import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from velvet.verdict.audit_glr import (
    AnytimeGLRAudit,
    G_half,
    HoeffdingAudit,
    clopper_pearson_upper,
    n_cert,
)

LN2 = math.log(2.0)


def stable_seed(*parts) -> int:
    data = repr(parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big") & 0x7FFFFFFF


def sim_line(message: str) -> None:
    print("[SIM] " + message)


def simulate_pair(mu, seed: int, t_max: int, delta: float,
                  family: str = "mixture_exact"):
    rng = random.Random(seed)
    audit = AnytimeGLRAudit(2, delta, family=family)
    arm = 0
    while audit.t < t_max:
        audit.update(arm, 1 if rng.random() < mu[arm] else 0)
        fired = audit.check_all()
        if fired:
            return fired[0][0], fired[0][1], audit.t
        arm = 1 - arm
    return None, None, audit.t


def predicted_total(m1: float, m2: float, delta: float) -> float:
    gh = G_half(m1, m2)
    n_total = 2.0
    for _ in range(200):
        n_total = (math.log(1.0 / delta) + math.log(max(n_total / 2.0, 1.0))
                   + 2.0 * LN2) / gh
    return n_total


def run_f3a(mode: str) -> None:
    if mode == "smoke":
        grid_mu = [(0.5, 0.5), (0.45, 0.55), (0.75, 0.85)]
        grid_delta = [0.20]
        reps, t_max = 80, 800
        families = ("mixture_exact",)
    else:
        grid_mu = [(0.5, 0.5), (0.45, 0.55), (0.75, 0.85),
                   (0.05, 0.10), (0.2, 0.8)]
        grid_delta = [0.10, 0.05]
        reps, t_max = 2000, 3000
        families = ("mixture_exact", "stitched")

    for family in families:
        for mu in grid_mu:
            opt = 1 if mu[1] >= mu[0] else 0
            for delta in grid_delta:
                false_rej = 0
                for r in range(reps):
                    rej, _, _ = simulate_pair(
                        mu, stable_seed("F3a", mode, family, mu, delta, r),
                        t_max, delta, family)
                    if rej is not None and (mu[0] == mu[1] or rej == opt):
                        false_rej += 1
                ub = clopper_pearson_upper(false_rej, reps, alpha=0.05)
                sim_line("F3a mode=%s family=%s mu=%s delta=%.3g false=%d/%d "
                         "cp_upper=%.5f" %
                         (mode, family, mu, delta, false_rej, reps, ub))
                if ub > delta:
                    raise SystemExit(
                        "[SIM] KILL F3a: threshold family falsified; "
                        "Hoeffding audit remains canonical")


def run_f3b(mode: str) -> None:
    if mode == "smoke":
        grid = [(0.30, 0.70), (0.75, 0.85)]
        reps, t_max, delta, t_hoeff = 8, 50000, 0.10, 10 ** 4
        enforce = False
    else:
        grid = [(a / 100.0, b / 100.0)
                for a in range(5, 96, 15)
                for b in range(5, 96, 15) if a < b]
        reps, t_max, delta, t_hoeff = 200, 250000, 1e-3, 10 ** 4
        enforce = True

    for mu in grid:
        pred = predicted_total(mu[0], mu[1], delta)
        totals = []
        beat_h = 0
        for r in range(reps):
            seed = stable_seed("F3b", mode, mu, r)
            rej, _, t_glr = simulate_pair(mu, seed, t_max, delta)
            if rej is None:
                if enforce:
                    raise SystemExit("[SIM] F3b unresolved cell %s" % (mu,))
                continue
            totals.append(t_glr)
            rng = random.Random(seed)
            h = HoeffdingAudit(2, t_hoeff)
            arm, t_h = 0, None
            while h.t < t_max:
                h.update(arm, 1 if rng.random() < mu[arm] else 0)
                if h.check_all():
                    t_h = h.t
                    break
                arm = 1 - arm
            if t_h is None or t_glr < t_h:
                beat_h += 1
        mean_total = sum(totals) / len(totals) if totals else float("inf")
        ratio = mean_total / pred
        sim_line("F3b mode=%s mu=%s resolved=%d/%d mean_total=%.2f "
                 "pred=%.2f ratio=%.3f beat_hoeffding=%d/%d" %
                 (mode, mu, len(totals), reps, mean_total, pred, ratio,
                  beat_h, reps))
        if enforce and not (0.5 <= ratio <= 2.0):
            raise SystemExit("[SIM] F3b sharpness band failure at %s" % (mu,))
        if enforce and abs((mu[0] + mu[1]) / 2.0 - 0.5) >= 0.15 and beat_h != reps:
            raise SystemExit("[SIM] F3b dominance failure at %s" % (mu,))


def run_f4(mode: str) -> None:
    if mode == "smoke":
        grid = [((0.75, 0.85), 0.10)]
        reps, pilot, t_max, n_boot = 8, 40, 50000, 80
        enforce = False
    else:
        grid = [((0.75, 0.85), 1e-3), ((0.60, 0.70), 1e-3),
                ((0.40, 0.60), 1e-3), ((0.20, 0.30), 1e-3),
                ((0.75, 0.85), 1e-5)]
        reps, pilot, t_max, n_boot = 300, 60, 500000, 800
        enforce = True

    for mu, delta in grid:
        cover, trials = 0, 0
        for r in range(reps):
            seed = stable_seed("F4", mode, mu, delta, r)
            rng = random.Random(seed)
            sa = sum(1 for _ in range(pilot) if rng.random() < mu[0])
            sb = sum(1 for _ in range(pilot) if rng.random() < mu[1])
            if sa / pilot >= sb / pilot:
                continue
            quote = n_cert(pilot, sa, pilot, sb, delta=delta,
                           n_boot=n_boot, seed=seed)
            rej, _, t_used = simulate_pair(mu, seed ^ 0x5A5A, t_max, delta,
                                           family="mixture_envelope")
            if rej is None and enforce:
                raise SystemExit("[SIM] F4 unresolved cell %s" % (mu,))
            if rej is None:
                continue
            lo, hi = quote["ci"]
            trials += 1
            if lo <= t_used <= (hi if not math.isinf(hi) else float("inf")):
                cover += 1
        frac = cover / float(trials) if trials else 1.0
        sim_line("F4 mode=%s mu=%s delta=%.1e trials=%d coverage=%.3f" %
                 (mode, mu, delta, trials, frac))
        if enforce and frac < 0.85:
            raise SystemExit("[SIM] F4 quote calibration falsified; widen interval")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    args = parser.parse_args(argv)
    sim_line("starting falsification runner mode=%s" % args.mode)
    run_f3a(args.mode)
    run_f3b(args.mode)
    run_f4(args.mode)
    sim_line("completed mode=%s" % args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
