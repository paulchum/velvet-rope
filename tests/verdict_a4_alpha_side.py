#!/usr/bin/env python3
"""a4_alpha_side.py -- A-4 instrument: exact single-anchor worst case.

Two exactly-computable objects per instance (alpha, beta, r, rho, W), each
bracketed rigorously over theta:

  Q_env(D~)   -- the S5 content: first-passage probability of the ENVELOPE
                 walk (alpha+S(n))/(alpha+beta+n) <= r, S(n) ~ Bin(n, g(th)),
                 g(th) = (th - rho*W)^+, n <= W. No adversary (allocation-
                 free). DP over (n, s).
  Q_worst     -- the TRUE single-anchor worst case: adversary controls pull
                 timing (pull/idle each round) and the drift path inside the
                 D+ ball |mu(s) - th| <= rho*(s-t). For ONE anchor the
                 worst drift is the pointwise floor mu_k = (th - rho*k)^+
                 (uniform-coupling monotonicity: lowering mu turns successes
                 into failures, which lowers every later posterior mean
                 pathwise and can only advance the crossing; the floor path
                 is itself admissible). DP over rounds x (pulls, successes)
                 with a pull/idle choice.

Both are decreasing in theta (same coupling), so a theta-grid with
left-endpoint evaluation gives a certified UPPER bracket of the prior
mixture and right-endpoint a LOWER bracket (plus exact Beta cell masses).

Verdicts per instance against the D+ conclusion value exp(-I(r + rho*W)):
  CONCLUSION-VIOLATION  if Q_worst_LO > exp(-I_lo)   [D+ conclusion FALSE]
  S5-CONTENT-VIOLATION  if Q_env_LO   > exp(-I_lo)   [proof object fails]
  SAFE                  if Q_*_HI    <= exp(-I_hi)   [certified no violation]
POSITIVE CONTROL: the D- instance (alpha=1, beta=1e-8, r=0.5, rho=0.1, W=2)
must show a conclusion violation of factor ~12.5 (Lemma D-, proved).
[MATH modulo quadrature bracket; grid resolution reported per instance.]
"""
import argparse
import math
import sys
from pathlib import Path

import numpy as np
from scipy.stats import beta as beta_dist

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import velvet.verdict.drift_expiry as de  # noqa: E402


def q_env_given_theta(alpha, beta, r, rho, W, thetas):
    """First-passage prob of the envelope walk within n <= W, per theta.
    DP over (n, s): P(exists n' <= W: (alpha+s)/(alpha+beta+n') <= r)."""
    g = np.maximum(thetas - rho * W, 0.0)
    nth = len(thetas)
    # crossed(n, s) iff alpha + s <= r*(alpha+beta+n)
    # value V(n, s): prob of crossing from prefix-state (n, s)
    V = np.zeros((W + 2, W + 2, nth))
    for n in range(W, -1, -1):
        for s in range(n, -1, -1):
            crossed = (alpha + s) <= r * (alpha + beta + n)
            if crossed:
                V[n, s] = 1.0
            elif n == W:
                V[n, s] = 0.0
            else:
                V[n, s] = g * V[n + 1, s + 1] + (1.0 - g) * V[n + 1, s]
    return V[0, 0]


def q_worst_given_theta(alpha, beta, r, rho, W, thetas):
    """TRUE single-anchor worst case per theta: rounds k = 0..W-1, states
    (pulls n, successes s); adversary chooses pull (at the round-k drift
    floor mu = (theta - rho*k)^+) or idle; crossing checked on start-of-round
    states X_0..X_W (n pulls have happened before the state)."""
    nth = len(thetas)
    # value-to-go from round k with (n, s), BEFORE the round-k state check
    # is absorbed: we mark crossed states directly.
    Vnext = np.zeros((W + 2, W + 2, nth))   # at k = W+1 (past the window)
    for k in range(W, -1, -1):
        Vk = np.zeros((W + 2, W + 2, nth))
        mu = np.maximum(thetas - rho * k, 0.0)
        for n in range(min(k, W), -1, -1):
            for s in range(n, -1, -1):
                if (alpha + s) <= r * (alpha + beta + n):
                    Vk[n, s] = 1.0
                    continue
                if k == W:
                    Vk[n, s] = 0.0
                    continue
                idle = Vnext[n, s]
                pull = mu * Vnext[n + 1, s + 1] + (1.0 - mu) * Vnext[n + 1, s]
                Vk[n, s] = np.maximum(idle, pull)
        Vnext = Vk
    return Vnext[0, 0]


def bracket_mixture(fn, alpha, beta, n_grid=4000):
    """Certified bracket of E_theta[fn(theta)] for DECREASING fn: exact Beta
    cell masses x left endpoints (upper) / right endpoints (lower)."""
    qs = beta_dist.ppf(np.linspace(0.0, 1.0, n_grid + 1), alpha, beta)
    qs[0], qs[-1] = 0.0, 1.0
    masses = np.diff(beta_dist.cdf(qs, alpha, beta))
    pts = np.unique(np.clip(qs, 0.0, 1.0))
    vals = fn(pts)
    v_by = dict(zip(pts, vals))
    left = np.array([v_by[x] for x in qs[:-1]])
    right = np.array([v_by[x] for x in qs[1:]])
    hi = float(np.sum(masses * left))
    lo = float(np.sum(masses * right))
    return lo, hi


def analyze(alpha, beta, r, rho, W, n_grid=4000, quiet=False):
    u = r + rho * W
    m = alpha / (alpha + beta)
    I_lo, I_hi = de.rate_I_bracket(alpha, beta, u)
    cert_hi = math.exp(-I_lo)          # upper end of the certified e^{-I}
    cert_lo = math.exp(-I_hi) if math.isfinite(I_hi) else 0.0
    qe_lo, qe_hi = bracket_mixture(
        lambda th: q_env_given_theta(alpha, beta, r, rho, W, th),
        alpha, beta, n_grid)
    qw_lo, qw_hi = bracket_mixture(
        lambda th: q_worst_given_theta(alpha, beta, r, rho, W, th),
        alpha, beta, n_grid)
    verdict = "safe"
    if qw_lo > cert_hi:
        verdict = "CONCLUSION-VIOLATION"
    elif qe_lo > cert_hi:
        verdict = "S5-CONTENT-VIOLATION"
    elif max(qw_hi, qe_hi) <= cert_lo:
        verdict = "SAFE(certified)"
    out = dict(alpha=alpha, beta=beta, r=r, rho=rho, W=W, u=u, m=m,
               I_lo=I_lo, I_hi=I_hi, cert=(cert_lo, cert_hi),
               q_env=(qe_lo, qe_hi), q_worst=(qw_lo, qw_hi),
               ratio_worst=qw_lo / cert_hi if cert_hi > 0 else math.inf,
               verdict=verdict)
    if not quiet:
        print(f"[A4] a={alpha:g} b={beta:g} r={r:g} rho={rho:g} W={W} "
              f"(m={m:.3f} u={u:.3f}): e^-I in [{cert_lo:.4g},{cert_hi:.4g}] "
              f"Q_env=[{qe_lo:.4g},{qe_hi:.4g}] "
              f"Q_worst=[{qw_lo:.4g},{qw_hi:.4g}] "
              f"worst/cert={out['ratio_worst']:.3f} -> {verdict}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--grid", type=int, default=4000)
    args = ap.parse_args()

    print("== positive control: the D- beta-side instance (must violate) ==")
    ctrl = analyze(1.0, 1e-8, 0.5, 0.1, 2, args.grid)
    assert ctrl["verdict"] == "CONCLUSION-VIOLATION", "control failed!"
    print(f"   (Lemma D- proves factor >= 12.5; instrument measures "
          f"{ctrl['ratio_worst']:.1f})")

    print("\n== alpha-side scan: alpha < 1 <= beta ==")
    import time as _t
    t0 = _t.monotonic()
    rows = []
    for alpha in (0.9, 0.7, 0.5, 0.3, 0.1, 0.05):
        for beta in (1.0, 2.0, 5.0):
            m = alpha / (alpha + beta)
            # r targets: one failure crosses (D- mechanism), a few failures,
            # and a deep floor; rho*W from thin to fat fractions of m - r
            for r_mode in ("one-fail", "three-fail", "deep"):
                if r_mode == "one-fail":
                    r = alpha / (alpha + beta + 1) * 1.001
                elif r_mode == "three-fail":
                    r = alpha / (alpha + beta + 3) * 1.001
                else:
                    r = m / 4.0
                if r >= m:
                    continue
                for frac in (0.25, 0.6, 0.9):
                    for W in (2, 6, 16):
                        rho = frac * (m - r) / W
                        if r + rho * W >= m:
                            continue
                        rows.append(analyze(alpha, beta, r, rho, W,
                                            args.grid, quiet=True))
                        if len(rows) % 40 == 0:
                            print(f"  ... {len(rows)} instances, "
                                  f"{_t.monotonic()-t0:.0f}s", flush=True)
    worst = sorted(rows, key=lambda d: -d["ratio_worst"])[:12]
    print(f"scanned {len(rows)} instances; top worst/cert ratios:")
    for d in worst:
        print(f"  a={d['alpha']:g} b={d['beta']:g} r={d['r']:.4g} "
              f"rho={d['rho']:.4g} W={d['W']}: "
              f"Q_worst_lo={d['q_worst'][0]:.4g} vs cert_hi="
              f"{d['cert'][1]:.4g} ratio={d['ratio_worst']:.3f} "
              f"[{d['verdict']}]")
    n_viol = sum(1 for d in rows if "VIOLATION" in d["verdict"])
    print(f"\nviolations found: {n_viol}/{len(rows)}")


if __name__ == "__main__":
    main()
