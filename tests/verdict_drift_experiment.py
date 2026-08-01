#!/usr/bin/env python3
"""run_drift_expiry_experiment.py -- F1 falsification protocol, revision r1.

Implements docs/SPEC_CERTIFIED_RETIREMENT.md Section 3.5 (F1) for the
drift-expiry certificate layer (theorem_package/drift_expiry.md). Ported
from the external drift-expiry hardened package (falsify_F1.py, git 324197a,
audited 2026-07-07); the only substantive change is the r1 burn-in candidate
(see the r1 note below). Requires the optional [drift] extra (numpy, scipy).

Currency: [SIM] -- simulation, never proof. Purpose: attempt to falsify T1.1
(A1 kill test) and calibrate T_hat (A2). Every printed claim is labeled
[SIM]. The reported horizon is T_hat, the code's conservative name for the
spec's T* column (T_hat <= true T*; see theorem_package/drift_expiry.md
T1.2 and the conservative-naming note).

Spec elements implemented from Section 3.5 / Deliverable 6:
  * Grid: rho in {1e-5,3e-5,1e-4,3e-4,1e-3} x Delta in {0.05,0.10,0.20} x
    K in {2,10,50} x style in {ramp,sinusoid,reflected-RW} = 135 cells, plus
    ONE adversarial fractional-shape cell.
  * n >= 400 seeds/cell (--full); c = 0.01, delta = 0.05,
    eps_s = M/(M+s) with M = 100; seed(cell,i) = sha256(cell_id || i)->uint64.
  * Deterministic burn-in pinning issue-time posteriors, with LOUD
    precondition failure (a burn-in bug, never a silent re-draw).
    All arms start Beta(1,1); anchors 40 pulls each with
    s0 = round(40*(0.30+Delta)) successes -> Beta(1+s0, 41-s0); candidate 13
    pulls, 2 successes -> Beta(3,12) (revision r1; see below); global clock
    t = total burn-in pulls.
    Refusals at issue are excluded from the A1 denominator and reported
    separately (burn-in is deterministic, so refusal is cell-level).
  * Adversarial cell: one anchor warm-started with min(alpha,beta) < 1
    (Beta(0.9,0.3) prior plus fractional counts -> Beta(0.95,0.35)); the
    harness OBSERVES drop-and-disclose, and A1 is adjudicated on the
    disclosed eligible set.
  * Per-seed environment: theta_b ~ issue-time posterior for ALL arms,
    independently. Adversarial orientation: anchors drift DOWN, candidate
    drifts UP. Drift styles (all satisfy per-step |d mu| <= rho and ball
    |mu(t+k) - theta| <= rho k; clip/reflect are 1-Lipschitz, preserving
    both):
      ramp:      mu(t+k) = clip(theta -/+ rho*k)
      sinusoid:  mu(t+k) = clip(theta -/+ A sin(w k)), w = 2*pi/T_hat,
                 A = rho*T_hat/(2*pi); per-step <= A*w = rho; envelope
                 <= rho*k via sin x <= x
      reflected-RW: mu(t+k+1) = reflect_[0,1](mu(t+k) + rho*xi_k), xi_k
                 Rademacher (seeded); reflection is 1-Lipschitz.
  * Run: continue the global clock; play W = T_hat rounds of the ACTUAL
    policy (host + eps-uniform over gate-eligible, fallback host); rewards
    Bernoulli(mu_b(s)) for the pulled arm only; ordinary counting.
    Rescue = exists s in [t, t+T_hat]: N^a(X_s) >= c or host = a at
    start-of-round (W+1 start-of-round states).
  * A1 kill test: per cell, x = rescues among n_cert certified seeds;
    UCB = BetaInv(0.95; x+1, n_cert-x); PASS iff UCB <= delta in EVERY cell
    -- spec-verbatim. Documented conservatism: a cell can fail with true
    rate < delta; the two-stage escalation (re-run violating cells at 4000
    seeds) is a DIAGNOSTIC ANNEX ONLY; the kill criterion remains the
    spec's. Kill localization ladder on any A1 violation:
      L1: replay every rescue trajectory and check Lemma C pathwise (a
          pulled before s*, or some m_b(X_{s*}) > r_c => assembly/convention
          bug, e.g. gate-convention mismatch);
      L2: estimate Q(SIM_{S_W}(r_c)) directly and compare its CP LOWER bound
          against the product bound -- exceedance implicates the D+
          invocation;
      L3: re-run audit_dplus_invocation per cell.
  * A2 (calibration, not validity): harness flag force_W bypasses the
    W > T_hat refusal (the harness simply simulates W_test rounds); sweep
    W_test in {1, 1.5, 2, 3, 5, 8} * T_hat; W_viol_hat = smallest W_test
    whose realized rescue frequency has one-sided CP LOWER bound > delta.
    Accept iff R(rho) = W_viol_hat / T_hat exists and
    max_rho R / min_rho R <= 3 across the rho sweep (per Delta, K, style).
    A2 failure downgrades T_hat to an internal bound without falsifying
    T1.1.
  * Outputs: per-cell CSV (cell id, (rho, Delta, K, style), n_seeds, n_cert,
    n_refused, rescues, p_hat, CP-UCB, T_hat, dropped anchors) plus a
    summary verdict table (A1 pass/fail per cell, A2 ratios per rho).

Modes: --smoke (small seeds, few cells; CI) and --full (the real 135+1-cell
run at n >= 400). Smoke adjudication is UNDERPOWERED by design and is not
the kill test; the kill test is --full.

Revision r1 of the burn-in constants (2026-07-07). The original (v1) pinned
candidate Beta(3,8) violates the issue precondition N^a(X_t) < c at
Delta in {0.05, 0.10}: it is already gate-eligible against those anchor
baselines (psi(3,8, 15/42) ~= 0.0227 and psi(3,8, 17/42) ~= 0.0131, both
>= c = 0.01; only Delta = 0.20 gives ~0.0036 < c and proceeds), so 90/135
grid cells failed burn-in loudly and were never adjudicated. r1 keeps the
protocol shape (integer counting from Beta(1,1), 2 successes) and weakens
the candidate to 13 pulls, 2 successes -> Beta(3,12), whose psi against the
three anchor baselines is 0.0046 / 0.0020 / 0.00028 -- all < 0.8*c, verified
preconditions on every cell. The v1 candidate is retained as
BURNIN_V1_CANDIDATE for the pinned supersession regression. The loud
precondition check remains: any future constant bug is a BURN-IN
PRECONDITION FAILURE, never a silent re-draw, and such cells are excluded
from the A1 denominator (reported in their own bucket, distinct from
refusal-at-issue).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np
from scipy.special import betainc
from scipy.stats import beta as beta_dist

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import velvet.verdict.drift_expiry as de

# ------------------------- spec constants (r1) -------------------------------
RHOS = [1e-5, 3e-5, 1e-4, 3e-4, 1e-3]
DELTAS_SEP = [0.05, 0.10, 0.20]          # Delta (anchor separation knob)
KS = [2, 10, 50]
STYLES = ["ramp", "sinusoid", "reflected-RW"]
C_GATE = 0.01
DELTA_CERT = 0.05
M_EPS = 100
N_FULL = 400
A2_MULTS = [1, 1.5, 2, 3, 5, 8]
CP_LEVEL = 0.95                          # one-sided
STATUS_BURNIN_FAIL = "BurnInPreconditionFailed"
# Superseded v1 burn-in candidate (9 pulls, 2 successes). Retained ONLY for
# the pinned supersession regression: psi(Beta(3,8), V_Delta) >= c at
# Delta in {0.05, 0.10}, the G9 finding that forced revision r1.
BURNIN_V1_CANDIDATE = (3.0, 8.0)


# ------------------------------- seeding ------------------------------------
def seed_for(cell_id: str, i: int) -> int:
    """seed(cell, i) = sha256(cell_id || i) -> uint64 (first 8 bytes)."""
    h = hashlib.sha256(f"{cell_id}||{i}".encode()).digest()
    return int.from_bytes(h[:8], "big")


# --------------------------- Clopper-Pearson --------------------------------
def cp_upper(x: int, n: int, level: float = CP_LEVEL) -> float:
    """One-sided CP UPPER bound: BetaInv(level; x+1, n-x). A1 side."""
    if n <= 0:
        return float("nan")
    if x >= n:
        return 1.0
    return float(beta_dist.ppf(level, x + 1, n - x))


def cp_lower(x: int, n: int, level: float = CP_LEVEL) -> float:
    """One-sided CP LOWER bound: BetaInv(1-level; x, n-x+1). A2/L2 side."""
    if n <= 0:
        return float("nan")
    if x <= 0:
        return 0.0
    return float(beta_dist.ppf(1.0 - level, x, n - x + 1))


# --------------------------- deterministic burn-in --------------------------
class BurnInError(RuntimeError):
    """LOUD precondition failure: a burn-in bug, never a silent re-draw."""


def burn_in(K: int, Delta: float, adversarial: bool = False):
    """Deterministic burn-in pinning the issue-time posteriors (revision r1).

    All arms start Beta(1,1). Candidate = arm 0: 13 pulls, 2 successes ->
    Beta(3,12) (r1; the v1 candidate Beta(3,8) violated the issue
    precondition at Delta in {0.05, 0.10} -- see the module docstring).
    Anchors 1..K-1: 40 pulls each with s0 = round(40*(0.30+Delta))
    successes -> Beta(1+s0, 41-s0). Global clock t = total burn-in pulls.
    Adversarial cell: anchor 1 is instead warm-started with a fractional
    prior Beta(0.9,0.3) plus fractional counts (0.05,0.05) ->
    Beta(0.95,0.35), min(alpha,beta) < 1 (contributes 0 integer pulls to the
    clock; its warm start is pre-t history)."""
    s0 = round(40 * (0.30 + Delta))
    post = [(3.0, 12.0)]                     # candidate: 13 pulls, 2 successes
    t = 13
    for j in range(1, K):
        if adversarial and j == 1:
            post.append((0.9 + 0.05, 0.3 + 0.05))   # Beta(0.95, 0.35)
        else:
            post.append((1.0 + s0, 41.0 - s0))
            t += 40
    return post, float(t)


def check_preconditions(post: Sequence[tuple[float, float]], cand: int,
                        c: float) -> None:
    """Verify programmatically (a not host; N^a(X_t) < c); FAIL LOUDLY."""
    means = [a / (a + b) for (a, b) in post]
    host = int(np.argmax(means))
    if host == cand:
        raise BurnInError(
            f"burn-in bug: candidate {cand} is host at issue (means={means})")
    n_a = de.N_cert(post, cand)
    if n_a >= c:
        raise BurnInError(
            f"burn-in bug: N^a(X_t)={n_a} >= c={c} at issue (gate-eligible)")


# ------------------------------ drift paths ---------------------------------
def _reflect01(x: np.ndarray) -> np.ndarray:
    """Fold into [0,1]; 1-Lipschitz, identity on [0,1]."""
    y = np.mod(x, 2.0)
    return 1.0 - np.abs(1.0 - y)


def drift_paths(style: str, theta: np.ndarray, rho: float, W: int,
                cand: int, T_ref: float, rng: np.random.Generator) -> np.ndarray:
    """mu array of shape (W+1, K): mu[k, b] = mu_b(t+k), k = 0..W.

    Adversarial orientation: anchors DOWN, candidate UP (sign array). All
    three styles satisfy the per-step bound |d mu| <= rho and the ball
    |mu(t+k) - theta| <= rho*k; clipping to [0,1] and reflection are
    1-Lipschitz, so they preserve both (spec's Lipschitz-preservation
    notes). mu(t) = theta exactly (admissibility radius 0 at s = t)."""
    K = theta.shape[0]
    sign = -np.ones(K)
    sign[cand] = +1.0
    ks = np.arange(W + 1, dtype=float)[:, None]          # (W+1, 1)
    if style == "ramp":
        mu = np.clip(theta[None, :] + sign[None, :] * rho * ks, 0.0, 1.0)
    elif style == "sinusoid":
        omega = 2.0 * math.pi / max(T_ref, 1.0)
        A = rho * max(T_ref, 1.0) / (2.0 * math.pi)      # A*omega = rho
        mu = np.clip(theta[None, :]
                     + sign[None, :] * A * np.sin(omega * ks), 0.0, 1.0)
    elif style == "reflected-RW":
        xi = rng.integers(0, 2, size=(W, K)) * 2 - 1     # Rademacher, seeded
        mu = np.empty((W + 1, K))
        mu[0] = theta
        for k in range(W):
            mu[k + 1] = _reflect01(mu[k] + rho * xi[k])
    else:
        raise ValueError(f"unknown drift style {style!r}")
    return mu


# ------------------------------ the actual policy ---------------------------
def _psi_vec(a: np.ndarray, b: np.ndarray, v: np.ndarray) -> np.ndarray:
    """Vectorized psi(Beta(a,b), v) = m*S_{a+1,b}(v) - v*S_{a,b}(v)."""
    m = a / (a + b)
    v = np.clip(v, 0.0, 1.0)
    sf1 = 1.0 - betainc(a + 1.0, b, v)
    sf0 = 1.0 - betainc(a, b, v)
    return m * sf1 - v * sf0


@dataclass
class SeedResult:
    rescued: bool
    s_star_rel: int | None            # k of first rescue (start-of-round)
    cand_pulled_before: bool             # Lemma C pathwise check (L1)
    max_other_mean_at_sstar: float | None  # Lemma C(b) pathwise check (L1)
    sim_occurred: bool                   # SIM_{S_W}(r_c) within [t, t+W] (L2)


def run_policy_window(post0, cand: int, t: float, W: int,
                      mu: np.ndarray, rng: np.random.Generator,
                      c: float, r_c: float,
                      SW_idx: Sequence[int],
                      exact_gate: bool = False) -> SeedResult:
    """Play W rounds of the ACTUAL policy from state post0 at clock t.

    Policy: p_s = (1-eps_s) 1{host} + eps_s * uniform over
    G(X_s) = {b != host : N^b(X_s) >= c}, fallback host when G empty;
    eps_s = M/(M+s) on the GLOBAL clock. Rewards Bernoulli(mu_b(s)) for the
    pulled arm only; ordinary Beta counting. Rescue and SIM are evaluated on
    the W+1 START-OF-ROUND states X_t .. X_{t+W}. Stops at first rescue.

    Rescue predicate (F-2a). Default is the FAST predicate of Lemma FP
    (CERTIFICATION.md, Phase F addenda): with the candidate frozen (Lemma C),
    rescue on a start-of-round state is equivalent to V^a(X_s) <= r_c up to
    the gate/tie boundary; the harness adopts the CONSERVATIVE convention of
    counting V <= r_c as rescue, which may only ever ADD rescues (numerical
    z_c pad; tie sliver) -- safe for A1. exact_gate=True restores the
    per-round psi evaluation (used by the L1/L2 localization replay and the
    pinned equivalence battery). Domain guard: fall back to exact when
    r_c >= 1 - 1e-15 (the only regime where the clamp could under-count)."""
    counts = np.array(post0, dtype=float)                # (K, 2)
    K = counts.shape[0]
    others = np.arange(K) != cand
    SW = np.asarray(list(SW_idx), dtype=int)
    cand_pulled = False
    sim_occurred = False
    if r_c >= 1.0 - 1e-15:
        exact_gate = True                                # Lemma FP domain guard
    for k in range(W + 1):
        m = counts[:, 0] / (counts[:, 0] + counts[:, 1])
        host = int(np.argmax(m))                          # lowest-index tie-break
        # SIM_{S_W}(r_c) on the start-of-round state (for L2)
        if SW.size and not sim_occurred and np.all(m[SW] <= r_c):
            sim_occurred = True
        # rescue on the start-of-round state
        V_c = float(np.max(m[others]))
        if exact_gate:
            N_c = float(_psi_vec(counts[cand, 0:1], counts[cand, 1:2],
                                 np.array([V_c]))[0])
            fired = (host == cand) or (N_c >= c)
        else:
            fired = (host == cand) or (V_c <= r_c)        # Lemma FP fast path
        if fired:
            return SeedResult(True, k, cand_pulled, float(np.max(m[others])),
                              sim_occurred)
        if k == W:
            break                                         # W+1 states checked
        # one pull (round t+k), continuing the global clock
        eps = M_EPS / (M_EPS + (t + k))
        if rng.random() < eps:
            # gate-eligible set (weak gate: N >= c), vectorized
            top = np.argsort(m)[-2:]
            V = np.full(K, m[top[-1]])
            V[top[-1]] = m[top[-2]]                       # exclude self from max
            N = _psi_vec(counts[:, 0], counts[:, 1], V)
            G = [b for b in range(K) if b != host and N[b] >= c]
            pulled = int(rng.choice(G)) if G else host    # fallback host
        else:
            pulled = host
        if pulled == cand:
            cand_pulled = True                            # Lemma C says: never
        y = 1 if rng.random() < mu[k, pulled] else 0
        counts[pulled, 0] += y
        counts[pulled, 1] += 1 - y
    return SeedResult(False, None, cand_pulled, None, sim_occurred)


# ---------------- F-2b: vectorized engine (lockstep across seeds) -----------
# Per-seed randomness has a FIXED, state-independent draw layout so runs are
# deterministic, resumable, and exactly reproducible by the test oracle:
#   theta = rng.beta(alphas, betas)                       -- once, first
#   then per round-block of size `block` (nb = rounds in this block):
#     xi   = rng.integers(0,2,(nb,K))*2-1  (reflected-RW style only)
#     U_eps    = rng.random(nb)
#     U_choice = rng.random(nb)   (drawn for every K; unused when G empty)
#     U_reward = rng.random(nb)
# The scalar reference runner consumes randomness in a different
# (state-dependent) order, so vec results are NOT bit-identical to it; the
# pinned equivalence is vec == independent oracle on the SAME streams
# (test_phase_f.py), plus the F-2a fast/exact-boundary battery.
VEC_BLOCK = 4096


def _draw_block(rng: np.random.Generator, nb: int, K: int, style: str):
    """Single source of truth for the per-seed per-block draw layout (engine
    AND oracle): xi (reflected-RW only), U_eps, U_choice, U_reward."""
    xi = (rng.integers(0, 2, size=(nb, K)) * 2 - 1).astype(np.int8) \
        if style == "reflected-RW" else None
    return xi, rng.random(nb), rng.random(nb), rng.random(nb)


def _mu_at(style: str, theta: np.ndarray, sign: np.ndarray, rho: float,
           k: int, T_ref: float) -> np.ndarray:
    """Closed-form mu(t+k) rows for ramp/sinusoid ((n,K) in, (n,K) out).
    reflected-RW is stateful and handled by the caller."""
    if style == "ramp":
        return np.clip(theta + sign[None, :] * rho * k, 0.0, 1.0)
    if style == "sinusoid":
        omega = 2.0 * math.pi / max(T_ref, 1.0)
        A = rho * max(T_ref, 1.0) / (2.0 * math.pi)
        return np.clip(theta + sign[None, :] * A * math.sin(omega * k), 0.0, 1.0)
    raise ValueError(style)


def run_policy_window_vec(post0, cand: int, t: float, W: int, cell_id: str,
                          style: str, rho: float, T_ref: float, n_seeds: int,
                          c: float, r_c: float, SW_idx: Sequence[int],
                          exact_gate: bool = False,
                          seed_offset: int = 0) -> list[SeedResult]:
    """Vectorized run of `run_policy_window` semantics across n_seeds seeds in
    lockstep (numpy row ops; per-seed host/gate via argmax and masks).

    Policy semantics are IDENTICAL to the scalar runner: weak gate, host =
    lowest-index argmax, eps_s = M/(M+s) on the global clock, fallback host on
    empty G, rewards Bernoulli(mu(s)) for the pulled arm only, rescue/SIM on
    the W+1 start-of-round states, stop-at-first-rescue per seed. Rescue uses
    the Lemma FP fast predicate unless exact_gate (domain guard as scalar).
    K = 2 shortcut (provable): pre-rescue the only non-host arm is the
    candidate and N^cand >= c would itself BE the gate rescue, so G is empty
    and every pull is the host -- no psi evaluation at all."""
    K = len(post0)
    alphas = np.array([p[0] for p in post0])
    betas = np.array([p[1] for p in post0])
    if r_c >= 1.0 - 1e-15:
        exact_gate = True                                 # Lemma FP domain guard
    sign = -np.ones(K)
    sign[cand] = +1.0
    SW = np.asarray(list(SW_idx), dtype=int)
    n = n_seeds
    counts = np.broadcast_to(np.array(post0, float), (n, K, 2)).copy()
    theta = np.empty((n, K))
    rngs = []
    for i in range(n):
        rng = np.random.default_rng(seed_for(cell_id, seed_offset + i))
        theta[i] = rng.beta(alphas, betas)
        rngs.append(rng)
    alive = np.ones(n, dtype=bool)
    fired_k = np.full(n, -1, dtype=int)
    V_at_fire = np.full(n, np.nan)
    sim = np.zeros(n, dtype=bool)
    cand_pulled = np.zeros(n, dtype=bool)
    cand_pulled_at_fire = np.zeros(n, dtype=bool)
    mu_rw = theta.copy() if style == "reflected-RW" else None
    others = np.arange(K) != cand
    blk_idx = -1
    xi_b = Ue = Uc = Ur = None
    for k in range(W + 1):
        tot = counts[..., 0] + counts[..., 1]
        m = counts[..., 0] / tot
        # SIM_{S_W}(r_c) on the start-of-round state (L2), pre-freeze rounds only
        if SW.size:
            sim |= alive & np.all(m[:, SW] <= r_c, axis=1)
        host = np.argmax(m, axis=1)                       # lowest-index ties
        mo = np.where(others[None, :], m, -np.inf)
        V = mo.max(axis=1)
        if exact_gate:
            N_c = _psi_vec(counts[:, cand, 0], counts[:, cand, 1], V)
            fired = alive & ((host == cand) | (N_c >= c))
        else:
            fired = alive & ((host == cand) | (V <= r_c))  # Lemma FP fast path
        if fired.any():
            fired_k[fired] = k
            V_at_fire[fired] = V[fired]
            cand_pulled_at_fire[fired] = cand_pulled[fired]
            alive &= ~fired
        if k == W or not alive.any():
            break
        # one pull (round t+k) for every alive seed
        j = k % VEC_BLOCK
        if k // VEC_BLOCK != blk_idx:
            blk_idx = k // VEC_BLOCK
            nb = min(VEC_BLOCK, W - blk_idx * VEC_BLOCK)
            per = [_draw_block(r, nb, K, style) for r in rngs]
            xi_b = None if per[0][0] is None else np.stack([p[0] for p in per])
            Ue = np.stack([p[1] for p in per])
            Uc = np.stack([p[2] for p in per])
            Ur = np.stack([p[3] for p in per])
        eps = M_EPS / (M_EPS + (t + k))
        pull = host.copy()
        if K > 2:
            sel = alive & (Ue[:, j] < eps)
            if sel.any():
                ms = m[sel]                                # (ns, K)
                i1 = np.argmax(ms, axis=1)
                m1 = ms[np.arange(ms.shape[0]), i1]
                ms2 = ms.copy()
                ms2[np.arange(ms.shape[0]), i1] = -np.inf
                m2 = ms2.max(axis=1)
                Vb = np.where(np.arange(K)[None, :] == i1[:, None],
                              m2[:, None], m1[:, None])   # excluded-max per arm
                N = _psi_vec(counts[sel, :, 0], counts[sel, :, 1], Vb)
                Gmask = (N >= c) & (np.arange(K)[None, :] != host[sel, None])
                gcount = Gmask.sum(axis=1)
                has = gcount > 0
                if has.any():
                    # uniform choice over G via U_choice: index into G members
                    order = np.argsort(~Gmask, axis=1, kind="stable")
                    pos = np.minimum((Uc[sel, j] * gcount).astype(int),
                                     np.maximum(gcount - 1, 0))
                    chosen = order[np.arange(order.shape[0]), pos]
                    rows = np.flatnonzero(sel)[has]
                    pull[rows] = chosen[has]
        # K == 2: G empty pre-rescue (Lemma FP corollary) -> pull = host always
        if style == "reflected-RW":
            mu_k = mu_rw
        else:
            mu_k = _mu_at(style, theta, sign, rho, k, T_ref)
        rows = np.flatnonzero(alive)
        pa = pull[rows]
        y = (Ur[rows, j] < mu_k[rows, pa]).astype(float)
        counts[rows, pa, 0] += y
        counts[rows, pa, 1] += 1.0 - y
        cand_pulled |= alive & (pull == cand)
        if style == "reflected-RW":
            mu_rw = _reflect01(mu_rw + rho * xi_b[:, j, :])
    out = []
    for i in range(n):
        resc = fired_k[i] >= 0
        out.append(SeedResult(bool(resc), int(fired_k[i]) if resc else None,
                              bool(cand_pulled_at_fire[i]) if resc
                              else bool(cand_pulled[i]),
                              float(V_at_fire[i]) if resc else None,
                              bool(sim[i])))
    return out


def run_cell_vec(cell: Cell, n_seeds: int, force_W: int | None = None,
                 exact_gate: bool = False) -> CellResult:
    """Vectorized run_cell: identical adjudication, engine = lockstep numpy.
    Not bit-identical to the scalar runner (different randomness layout);
    pinned against the independent oracle in test_phase_f.py."""
    post, t, v = issue_for_cell(cell)
    if cell.adversarial:
        if not any(i == 1 for (i, a, b) in v.dropped_anchors):
            raise BurnInError("adversarial cell: fractional-shape anchor was "
                              "NOT dropped-and-disclosed -- harness kill")
    if v.status != de.CERTIFIED_SAFE:
        return CellResult(cell, n_seeds, 0, n_seeds, 0, float("nan"),
                          float("nan"), v.T_hat, v.dropped_anchors,
                          v.status, v.reason_code, None)
    W = int(v.W) if force_W is None else int(force_W)
    r_c = v.protected_floor
    u = r_c + cell.rho * v.W
    SW = tuple(b for b in v.eligible_anchors
               if post[b][0] / (post[b][0] + post[b][1]) > u)
    results = run_policy_window_vec(post, 0, t, W, cell.cell_id, cell.style,
                                    cell.rho, float(v.T_hat), n_seeds,
                                    C_GATE, r_c, SW, exact_gate=exact_gate)
    rescues = sum(int(r.rescued) for r in results)
    p_hat = rescues / n_seeds
    ucb = cp_upper(rescues, n_seeds)
    return CellResult(cell, n_seeds, n_seeds, 0, rescues, p_hat, ucb,
                      v.T_hat, v.dropped_anchors, v.status, v.reason_code,
                      bool(ucb <= DELTA_CERT), results, r_c, SW, v.tail_bound)


# ------------------------------- cells --------------------------------------
@dataclass
class Cell:
    rho: float
    Delta: float
    K: int
    style: str
    adversarial: bool = False
    # F-1b powered companion cells: explicit issue-time posteriors (candidate
    # first) and global clock, bypassing the spec burn-in. Delta then records
    # the anchor separation m_anchor - r_c (informational).
    post: tuple | None = None
    t0: float = 0.0
    tag: str = ""

    @property
    def cell_id(self) -> str:
        if self.post is not None:
            return (f"PWR_{self.tag}_rho{self.rho:g}_K{self.K}_{self.style}")
        tag = "ADVfrac_" if self.adversarial else ""
        return f"{tag}rho{self.rho:g}_D{self.Delta:g}_K{self.K}_{self.style}"


@dataclass
class CellResult:
    cell: Cell
    n_seeds: int
    n_cert: int
    n_refused: int
    rescues: int
    p_hat: float
    cp_ucb: float
    T_hat: float | None
    dropped: tuple
    verdict_status: str
    verdict_reason_code: str
    a1_pass: bool | None              # None = vacuous (refused at issue)
    seed_results: list = field(default_factory=list)
    r_c: float | None = None
    SW: tuple = ()
    product_bound: float | None = None


_ISSUE_CACHE: dict[str, tuple] = {}


def issue_for_cell(cell: Cell):
    """Issue-time state for a cell. Deterministic (burn-in is pinned), so the
    result is memoized by cell_id: A2 sweeps and re-runs stop paying the
    rate-bisection issuance cost (~0.6 s/cell) per multiplier. Cached `post`
    is never mutated by any runner (both engines copy into their own arrays)."""
    hit = _ISSUE_CACHE.get(cell.cell_id)
    if hit is not None:
        return hit
    if cell.post is not None:
        post, t = [tuple(p) for p in cell.post], float(cell.t0)
    else:
        post, t = burn_in(cell.K, cell.Delta, adversarial=cell.adversarial)
    check_preconditions(post, 0, C_GATE)                  # LOUD on violation
    v = de.issue_verdict(post, 0, C_GATE, DELTA_CERT, cell.rho)
    out = (post, t, v)
    _ISSUE_CACHE[cell.cell_id] = out
    return out


def run_cell(cell: Cell, n_seeds: int, force_W: int | None = None,
             quiet: bool = False, exact_gate: bool = False) -> CellResult:
    post, t, v = issue_for_cell(cell)
    if cell.adversarial:
        # the harness must OBSERVE drop-and-disclose of the fractional anchor
        if not any(i == 1 for (i, a, b) in v.dropped_anchors):
            raise BurnInError("adversarial cell: fractional-shape anchor was "
                              "NOT dropped-and-disclosed -- harness kill")
    if v.status != de.CERTIFIED_SAFE:
        # refusal at issue: excluded from the A1 denominator, reported
        return CellResult(cell, n_seeds, 0, n_seeds, 0, float("nan"),
                          float("nan"), v.T_hat, v.dropped_anchors,
                          v.status, v.reason_code, None)
    W = int(v.W) if force_W is None else int(force_W)
    r_c = v.protected_floor
    u = r_c + cell.rho * v.W
    SW = tuple(b for b in v.eligible_anchors
               if post[b][0] / (post[b][0] + post[b][1]) > u)
    prod_bound = v.tail_bound
    means_post = np.array([a / (a + b) for (a, b) in post])
    rescues = 0
    results: list[SeedResult] = []
    alphas = np.array([p[0] for p in post])
    betas = np.array([p[1] for p in post])
    for i in range(n_seeds):
        rng = np.random.default_rng(seed_for(cell.cell_id, i))
        theta = rng.beta(alphas, betas)                  # issue-time predictive
        mu = drift_paths(cell.style, theta, cell.rho, W, 0, float(v.T_hat), rng)
        res = run_policy_window(post, 0, t, W, mu, rng, C_GATE, r_c, SW,
                                exact_gate=exact_gate)
        rescues += int(res.rescued)
        results.append(res)
    p_hat = rescues / n_seeds
    ucb = cp_upper(rescues, n_seeds)
    return CellResult(cell, n_seeds, n_seeds, 0, rescues, p_hat, ucb,
                      v.T_hat, v.dropped_anchors, v.status, v.reason_code,
                      bool(ucb <= DELTA_CERT), results, r_c, SW, prod_bound)


# ------------------- F-1a: statistical-power adjudication -------------------
POWER_POWERED = "POWERED"
POWER_VACUOUS = "VACUOUS"


def sum_ncross(post: Sequence[tuple[float, float]], cand: int,
               r_c: float) -> int:
    """Corollary NV (CERTIFICATION.md, Phase F addenda): minimum total anchor
    pulls for a rescue -- each b != a with m_b > r_c needs n_cross(b) =
    ceil(alpha_b/r_c - (alpha_b+beta_b)) ALL-FAILURE pulls to reach
    m_b <= r_c. If the sum exceeds the window W, P(rescue) = 0 exactly.
    The 1e-12 slack lowers n_cross at float boundaries: UNDER-counting makes
    the vacuity declaration harder, never a false vacuity claim."""
    tot = 0
    for i, (a, b) in enumerate(post):
        if i == cand or a / (a + b) <= r_c:
            continue
        tot += max(0, math.ceil(a / r_c - (a + b) - 1e-12))
    return tot


def classify_power(cr: CellResult, post, n_seeds: int,
                   a2_res: dict | None = None) -> tuple[str, str]:
    """F-1a power column for a CERTIFIED cell: (power, reason).

    VACUOUS triggers, in order:
      structural  -- Corollary NV: sum n_cross > W (true rescue prob EXACTLY 0)
      tail-floor  -- certified tail below the resolvability floor
                     1/(10*n_seeds): even a tight bound is unmeasurable at n
      no-onset    -- the adaptive A2 sweep found no violation onset at its cap
                     (only when A2 data is present)
    Otherwise POWERED. The reason string names the triggers that were
    actually CHECKED, so a POWERED label never silently claims an unrun check."""
    W = int(cr.T_hat)
    snc = sum_ncross(post, 0, cr.r_c)
    if snc > W:
        return POWER_VACUOUS, (f"structural: sum n_cross={snc} > W={W} "
                               f"(Corollary NV: rescue probability exactly 0)")
    floor = 1.0 / (10.0 * n_seeds)
    if cr.product_bound is not None and cr.product_bound < floor:
        return POWER_VACUOUS, (f"tail-floor: certified tail "
                               f"{cr.product_bound:.3g} < 1/(10n)={floor:.3g}")
    if a2_res is not None and a2_res.get("verdict") == A2_INDETERMINATE:
        return POWER_VACUOUS, ("no-onset: adaptive A2 found no violation "
                               f"onset at cap {a2_res['cap_mult']}x")
    checked = "structural+tail-floor" + ("+A2-onset" if a2_res else
                                         " (A2 n/a)")
    return POWER_POWERED, f"checked: {checked}"


# --------------------------- kill localization ------------------------------
def localization_ladder(cr: CellResult) -> list[str]:
    """L1-L3 on an A1 violation. Returns diagnostic lines, all [SIM].

    L1/L2 always replay with the EXACT rescue predicate (exact_gate=True):
    under the Lemma FP fast path the containment check V <= r_c would be
    tautological, so localization must not inherit it."""
    out = []
    # L1: replay every rescue trajectory with the exact predicate
    cr = run_cell(cr.cell, cr.n_seeds, exact_gate=True)
    bad_pull = sum(1 for r in cr.seed_results
                   if r.rescued and r.cand_pulled_before)
    bad_mean = sum(1 for r in cr.seed_results
                   if r.rescued and r.max_other_mean_at_sstar is not None
                   and r.max_other_mean_at_sstar > cr.r_c + 1e-12)
    out.append(f"[SIM] L1: {bad_pull} rescue paths pulled the candidate "
               f"before s*; {bad_mean} had some m_b(X_s*) > r_c "
               f"({'assembly/convention bug indicated' if bad_pull or bad_mean else 'Lemma C holds pathwise on every rescue trajectory'})")
    # L2: Q(SIM_{S_W}(r_c)) direct estimate, CP LOWER vs product bound
    x_sim = sum(1 for r in cr.seed_results if r.sim_occurred)
    lcb = cp_lower(x_sim, cr.n_cert)
    exceed = lcb > (cr.product_bound or 1.0)
    out.append(f"[SIM] L2: SIM_(S_W)(r_c) hits={x_sim}/{cr.n_cert}, CP-lower="
               f"{lcb:.4g} vs product bound {cr.product_bound:.4g} -> "
               f"{'EXCEEDANCE: D+ invocation implicated' if exceed else 'no exceedance'}")
    # L3: re-run the D+ audit for this cell
    post, _, v = issue_for_cell(cr.cell)
    try:
        if cr.SW:
            de.audit_dplus_invocation([post[b] for b in cr.SW],
                                      cr.r_c, cr.cell.rho, int(v.W))
        out.append("[SIM] L3: audit_dplus_invocation PASSES for this cell")
    except de.AuditError as e:
        out.append(f"[SIM] L3: audit FAILS: {e}")
    return out


# ----------------------------------- A2 -------------------------------------
A2_INDETERMINATE = "A2-INDETERMINATE"
A2_ONSET = "onset"
A2_MULTS_EXT = [16, 32, 64]              # F-1c adaptive extension (doubling)
A2_CELL_BUDGET_S = 300.0                 # wall-clock budget per cell sweep


def _violates_tag(rescues: int, lcb: float):
    """F-3i: a zero-rescue row carries the INDETERMINATE tag, never a silent
    False -- zero observed rescues at this n is absence of evidence, not
    evidence of calibration."""
    if rescues == 0:
        return "INDETERMINATE"
    return bool(lcb > DELTA_CERT)


def a2_sweep(cell: Cell, n_seeds: int, runner=None, adaptive: bool = False,
             budget_s: float = A2_CELL_BUDGET_S) -> dict | None:
    """A2 calibration: force_W bypasses the W > T_hat refusal (the harness
    simulates W_test rounds directly); returns per-multiplier stats and
    W_viol_hat (smallest W_test with CP LOWER > delta), or None if the cell
    refused at issue. A2 failure downgrades T_hat to an internal bound
    WITHOUT falsifying T1.1. runner: run_cell (scalar) or run_cell_vec
    (default engine).

    F-1c adjudication: onset-not-found is A2-INDETERMINATE -- first-class,
    distinct from pass and fail. When adaptive, the multiplier sweep extends
    past 8x by doubling (16, 32, 64) until an onset is found, the ~64x cap is
    reached, or the wall-clock budget is exhausted; absence of onset is NEVER
    read as calibration success (per-rho ratios use onset cells only).
    verdict in {"onset", "A2-INDETERMINATE"}; cap_mult = largest multiplier
    actually swept; budget_exhausted flags an early stop."""
    import time as _time
    runner = runner or run_cell_vec
    post, t, v = issue_for_cell(cell)
    if v.status != de.CERTIFIED_SAFE:
        return None
    t_start = _time.monotonic()
    rows, W_viol = [], None
    mults = list(A2_MULTS)
    budget_exhausted = False
    i = 0
    while i < len(mults):
        mult = mults[i]
        i += 1
        W_test = max(1, int(round(mult * v.T_hat)))
        cr = runner(cell, n_seeds, force_W=W_test)
        lcb = cp_lower(cr.rescues, cr.n_cert)
        rows.append(dict(mult=mult, W_test=W_test, rescues=cr.rescues,
                         n=cr.n_cert, p_hat=cr.p_hat, cp_lcb=lcb,
                         violates=_violates_tag(cr.rescues, lcb)))
        if W_viol is None and lcb > DELTA_CERT:
            W_viol = W_test
            break                        # smallest violating W_test found
        if adaptive and i == len(mults) and W_viol is None:
            remaining = [m for m in A2_MULTS_EXT if m > mults[-1]]
            if remaining:
                if _time.monotonic() - t_start > budget_s:
                    budget_exhausted = True
                else:
                    mults.append(remaining[0])
    R = (W_viol / v.T_hat) if W_viol is not None else None
    verdict = A2_ONSET if W_viol is not None else A2_INDETERMINATE
    return dict(cell_id=cell.cell_id, T_hat=v.T_hat, rows=rows,
                W_viol_hat=W_viol, R=R, verdict=verdict,
                cap_mult=mults[-1] if mults else None,
                max_rescues=max((r["rescues"] for r in rows), default=0),
                budget_exhausted=budget_exhausted)


# ----------------------------------- CSV ------------------------------------
# Spec columns first (Deliverable 6, verbatim), then the F-1 additions:
# power/power_reason (F-1a), sum_ncross (Corollary NV witness), engine, ts.
CSV_FIELDS = ["cell_id", "rho", "Delta", "K", "style", "n_seeds", "n_cert",
              "n_refused", "rescues", "p_hat", "cp_ucb", "T_hat",
              "dropped_anchors", "verdict_status", "verdict_reason_code",
              "A1", "power", "power_reason", "sum_ncross", "engine", "ts"]

A2_CSV_FIELDS = ["cell_id", "T_hat", "mult", "W_test", "rescues", "n",
                 "p_hat", "cp_lcb", "violates", "verdict", "engine", "ts"]


class IncrementalCsv:
    """Append-per-row CSV with resume (F-0d interruption safety): rows are
    flushed as they complete; --resume skips keys already present."""

    def __init__(self, path: str, fields: list[str], key_cols: list[str],
                 resume: bool):
        self.path = path
        self.fields = fields
        self.key_cols = key_cols
        self.done = set()
        exists = os.path.exists(path) and os.path.getsize(path) > 0
        if exists and resume:
            with open(path, newline="") as f:
                for row in csv.DictReader(f):
                    self.done.add(tuple(row.get(k, "") for k in key_cols))
        mode = "a" if (exists and resume) else "w"
        self.f = open(path, mode, newline="")
        self.w = csv.DictWriter(self.f, fieldnames=fields, extrasaction="ignore")
        if mode == "w":
            self.w.writeheader()
            self.f.flush()

    def has(self, **key) -> bool:
        return tuple(str(key[k]) for k in self.key_cols) in self.done

    def write(self, row: dict) -> None:
        self.w.writerow(row)
        self.f.flush()
        self.done.add(tuple(str(row.get(k, "")) for k in self.key_cols))

    def close(self):
        self.f.close()


def cell_row(r: CellResult, n_run: int, engine: str,
             a2_res: dict | None = None) -> dict:
    """Assemble the per-cell CSV row, including the F-1a power column."""
    power, reason, snc = "", "", ""
    if r.a1_pass is not None:
        post, _, _ = issue_for_cell(r.cell)
        power, reason = classify_power(r, post, n_run, a2_res)
        snc = sum_ncross(post, 0, r.r_c)
    a1 = ("PASS" if r.a1_pass else
          "FAIL" if r.a1_pass is not None else
          "N/A (burn-in precondition failed)"
          if r.verdict_status == STATUS_BURNIN_FAIL else
          "N/A (refused at issue)")
    if r.a1_pass and power == POWER_VACUOUS:
        a1 = "PASS(vacuous)"
    import time as _time
    return dict(
        cell_id=r.cell.cell_id, rho=r.cell.rho, Delta=r.cell.Delta,
        K=r.cell.K, style=r.cell.style, n_seeds=r.n_seeds,
        n_cert=r.n_cert, n_refused=r.n_refused, rescues=r.rescues,
        p_hat=(f"{r.p_hat:.6f}" if r.n_cert else "NA"),
        cp_ucb=(f"{r.cp_ucb:.6f}" if r.n_cert else "NA"),
        T_hat=r.T_hat, dropped_anchors=str(tuple(r.dropped)),
        verdict_status=r.verdict_status,
        verdict_reason_code=r.verdict_reason_code,
        A1=a1, power=power, power_reason=reason, sum_ncross=snc,
        engine=engine, ts=f"{_time.time():.0f}")


def write_cells_csv(path: str, results: list[CellResult],
                    engine: str = "vec") -> None:
    """Batch writer kept for compatibility; wraps the incremental writer."""
    out = IncrementalCsv(path, CSV_FIELDS, ["cell_id"], resume=False)
    for r in results:
        out.write(cell_row(r, r.n_seeds, engine))
    out.close()


# ----------------------------------- main -----------------------------------
def full_grid() -> list[Cell]:
    cells = [Cell(rho, D, K, st)
             for rho in RHOS for D in DELTAS_SEP for K in KS for st in STYLES]
    # plus ONE adversarial fractional-shape cell
    cells.append(Cell(1e-3, 0.20, 10, "ramp", adversarial=True))
    return cells


def smoke_grid() -> list[Cell]:
    """Few cells for CI: exercises certified cells (all three drift styles),
    refused-at-issue cells (both refusal channels), and the adversarial
    drop-and-disclose cell. Underpowered by design; not the kill test."""
    cells = [Cell(rho, 0.20, 10, st) for rho in (3e-4, 1e-3) for st in STYLES]
    cells += [Cell(1e-3, 0.10, 10, "ramp"),      # refused: no separated anchor
              Cell(1e-3, 0.20, 2, "ramp")]       # refused: degenerate window
    cells.append(Cell(1e-3, 0.20, 10, "ramp", adversarial=True))
    return cells


# --------- F-1b: POWERED companion grid (kill-capable by construction) -------
# Emitted by tools/design_powered.py (pinned literal; do not hand-edit).
# K = 2 only; candidate Beta(30,80) (r_c = 0.2895): the spec burn-in
# candidate Beta(3,8) admits NO K=2 anchor that certifies at delta = 0.05
# within the 1.5-3 sd band (nearest is kappa = 3.10) -- design finding,
# see CHANGELOG. Anchors are integer-counting states (auto shape-eligible),
# 5-12 pseudo-observations, mean within 1.5-3 posterior sd of r_c;
# REACHABILITY (Corollary NV) n_cross <= T_hat verified per cell at design
# time and re-verified at runtime in run_powered_preflight().
POWERED_CANDIDATE = (30.0, 80.0)
# Selection rule (tools/design_powered.py, executed pilots at n=400):
# drift-material designs (rho*T_hat >= 0.05 of the separation; here 0.11-0.12)
# plus ONE light barely-certifying anchor as a stationary-power control
# (Beta(5,2): u-headroom ~ 0, so rho*T_hat/sep ~ 0.004 by necessity -- its
# power is the theta-tail, not drift). All 12 cells pilot-verified: rescue
# mass at W = T_hat (p_hat 0.0025-0.02) and rescues at the 8x cap, per style;
# no pilot CP-lower approached delta (no kill signal).
POWERED_CELLS: list[Cell] = [
    Cell(rho=7.818033e-04, Delta=0.4105, K=2, style='ramp',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T60'),
    Cell(rho=7.818033e-04, Delta=0.4105, K=2, style='sinusoid',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T60'),
    Cell(rho=7.818033e-04, Delta=0.4105, K=2, style='reflected-RW',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T60'),
    Cell(rho=3.909017e-04, Delta=0.4105, K=2, style='ramp',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T120'),
    Cell(rho=3.909017e-04, Delta=0.4105, K=2, style='sinusoid',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T120'),
    Cell(rho=3.909017e-04, Delta=0.4105, K=2, style='reflected-RW',
         post=((30.0, 80.0), (7.0, 3.0)), t0=116.0, tag='A7B3T120'),
    Cell(rho=3.521851e-04, Delta=0.3533, K=2, style='ramp',
         post=((30.0, 80.0), (9.0, 5.0)), t0=120.0, tag='A9B5T120'),
    Cell(rho=3.521851e-04, Delta=0.3533, K=2, style='sinusoid',
         post=((30.0, 80.0), (9.0, 5.0)), t0=120.0, tag='A9B5T120'),
    Cell(rho=3.521851e-04, Delta=0.3533, K=2, style='reflected-RW',
         post=((30.0, 80.0), (9.0, 5.0)), t0=120.0, tag='A9B5T120'),
    Cell(rho=2.978299e-05, Delta=0.4248, K=2, style='ramp',
         post=((30.0, 80.0), (5.0, 2.0)), t0=113.0, tag='A5B2T60'),
    Cell(rho=2.978299e-05, Delta=0.4248, K=2, style='sinusoid',
         post=((30.0, 80.0), (5.0, 2.0)), t0=113.0, tag='A5B2T60'),
    Cell(rho=2.978299e-05, Delta=0.4248, K=2, style='reflected-RW',
         post=((30.0, 80.0), (5.0, 2.0)), t0=113.0, tag='A5B2T60'),
]


def powered_grid() -> list[Cell]:
    if not POWERED_CELLS:
        raise SystemExit("powered grid not designed yet: run "
                         "tools/design_powered.py and pin POWERED_CELLS")
    return list(POWERED_CELLS)


def quorum_verdict(a2_results: dict[str, dict]):
    """F-1b acceptance: quorum met iff >= 2/3 of certified powered cells show
    empirical rescue frequency > 0 at the swept A2 cap. Returns
    (met, cells_with_rescue, total_certified)."""
    with_rescue = sum(1 for res in a2_results.values()
                      if res and res["max_rescues"] > 0)
    total = sum(1 for res in a2_results.values() if res)
    met = total > 0 and (with_rescue / total) >= 2.0 / 3.0
    return met, with_rescue, total


def run_powered_preflight(cells: list[Cell]) -> None:
    """REACHABILITY REQUIRED per powered cell: the all-failure downcrossing
    count from the anchor state to r_c must fit inside T_hat (else the cell
    is misdesigned and the run must not pretend to be powered)."""
    for cell in cells:
        post, t, v = issue_for_cell(cell)
        if v.status != de.CERTIFIED_SAFE:
            raise BurnInError(f"powered cell {cell.cell_id} refused at issue: "
                              f"{v.status}/{v.reason_code} -- redesign")
        snc = sum_ncross(post, 0, v.protected_floor)
        if snc > int(v.T_hat):
            raise BurnInError(f"powered cell {cell.cell_id}: reachability "
                              f"violated (sum n_cross={snc} > T_hat="
                              f"{int(v.T_hat)}) -- redesign")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true",
                      help="small seeds, few cells (CI); not the kill test")
    mode.add_argument("--full", action="store_true",
                      help="the spec-verbatim 135+1-cell COMPLIANCE run at "
                           "n >= 400 [SIM]")
    mode.add_argument("--powered", action="store_true",
                      help="the F-1b POWERED companion grid (K=2, "
                           "kill-capable by construction); A1 here is the "
                           "real kill test")
    ap.add_argument("--n", type=int, default=None,
                    help="seeds per cell (default: 100 smoke / 400 full "
                         "and powered)")
    ap.add_argument("--a2", action="store_true",
                    help="also run the A2 calibration sweep (adaptive "
                         "extension to ~64x; onset-not-found is first-class "
                         "A2-INDETERMINATE)")
    ap.add_argument("--a2-budget-secs", type=float, default=A2_CELL_BUDGET_S,
                    help="wall-clock budget per cell for the adaptive A2 "
                         "extension")
    ap.add_argument("--engine", choices=["vec", "scalar"], default="vec",
                    help="seed engine: vectorized lockstep (default) or the "
                         "scalar reference; adjudication is identical, "
                         "randomness layouts differ (both seeded/deterministic)")
    ap.add_argument("--outdir", default="f1_out",
                    help="output directory (committed runs use runs/)")
    ap.add_argument("--resume", action="store_true",
                    help="skip cells whose rows already exist in the target "
                         "CSVs (interruption-safe long runs)")
    args = ap.parse_args(argv)

    runner = run_cell_vec if args.engine == "vec" else run_cell
    if args.powered:
        cells = powered_grid()
        run_powered_preflight(cells)
        gridname = "powered"
    elif args.smoke:
        cells = smoke_grid()
        gridname = "smoke"
    else:
        cells = full_grid()
        gridname = "full"
    n = args.n or (100 if args.smoke else N_FULL)
    os.makedirs(args.outdir, exist_ok=True)
    tagline = {"smoke": "COMPLIANCE SMOKE (spec-verbatim cells, small n; "
                        "NOT the kill test)",
               "full": f"COMPLIANCE FULL (spec-verbatim 135+1 cells, n={n})",
               "powered": f"POWERED companion grid (kill-capable by "
                          f"construction; A1 here is the real kill test; "
                          f"n={n})"}[gridname]
    print(f"[SIM] falsify_F1: {tagline}; {len(cells)} cells, n={n} seeds/cell; "
          f"engine={args.engine}")
    print(f"[SIM] c={C_GATE}, delta={DELTA_CERT}, eps_s=M/(M+s) with M={M_EPS}; "
          f"seed=sha256(cell_id||i)->uint64")

    cells_csv = IncrementalCsv(os.path.join(args.outdir, "f1_cells.csv"),
                               CSV_FIELDS, ["cell_id"], resume=args.resume)
    a2_csv = IncrementalCsv(os.path.join(args.outdir, "f1_a2.csv"),
                            A2_CSV_FIELDS, ["cell_id", "mult"],
                            resume=args.resume) if args.a2 else None

    results: list[CellResult] = []
    a2_results: dict[str, dict] = {}
    any_violation = False
    import time as _time
    resume_skips = 0
    for cell in cells:
        if args.resume and cells_csv.has(cell_id=cell.cell_id) and \
                (not args.a2 or a2_csv.has(cell_id=cell.cell_id, mult=1)):
            print(f"[SIM] {cell.cell_id}: resume-skip (rows exist)")
            resume_skips += 1
            continue
        try:
            cr = runner(cell, n)
        except BurnInError as e:
            print(f"[SIM] {cell.cell_id}: BURN-IN PRECONDITION FAILURE "
                  f"(LOUD, per spec: a burn-in bug, not a re-draw event): {e}")
            bad = CellResult(
                cell, n, 0, 0, 0, float("nan"), float("nan"), None, (),
                STATUS_BURNIN_FAIL, "burn_in_precondition_failed", None)
            results.append(bad)
            if not cells_csv.has(cell_id=cell.cell_id):
                cells_csv.write(cell_row(bad, n, args.engine))
            continue
        results.append(cr)
        # A2 first (adaptive), so the power column can use its onset verdict
        a2_res = None
        if args.a2 and not cell.adversarial and cr.a1_pass is not None:
            a2_res = a2_sweep(cell, n, runner=runner, adaptive=True,
                              budget_s=args.a2_budget_secs)
            a2_results[cell.cell_id] = a2_res
            if a2_res is not None:
                for row in a2_res["rows"]:
                    if not a2_csv.has(cell_id=cell.cell_id, mult=row["mult"]):
                        a2_csv.write(dict(
                            cell_id=cell.cell_id, T_hat=a2_res["T_hat"],
                            mult=row["mult"], W_test=row["W_test"],
                            rescues=row["rescues"], n=row["n"],
                            p_hat=f"{row['p_hat']:.6f}",
                            cp_lcb=f"{row['cp_lcb']:.6f}",
                            violates=row["violates"],
                            verdict=a2_res["verdict"], engine=args.engine,
                            ts=f"{_time.time():.0f}"))
                print(f"[SIM] A2 {cell.cell_id}: verdict={a2_res['verdict']} "
                      f"W_viol_hat={a2_res['W_viol_hat']} R={a2_res['R']} "
                      f"cap={a2_res['cap_mult']}x "
                      f"max_rescues={a2_res['max_rescues']}"
                      + (" [budget exhausted]" if a2_res["budget_exhausted"]
                         else ""))
        row = cell_row(cr, n, args.engine, a2_res)
        if not cells_csv.has(cell_id=cell.cell_id):
            cells_csv.write(row)
        if cr.a1_pass is None:
            print(f"[SIM] {cr.cell.cell_id}: REFUSED at issue "
                  f"({cr.verdict_status}/{cr.verdict_reason_code}); excluded "
                  f"from A1 denominator, reported separately")
        else:
            flag = row["A1"]
            print(f"[SIM] {cr.cell.cell_id}: T_hat={cr.T_hat:.0f} rescues="
                  f"{cr.rescues}/{cr.n_cert} p_hat={cr.p_hat:.4f} "
                  f"CP-UCB={cr.cp_ucb:.4f} vs delta={DELTA_CERT} -> A1 {flag} "
                  f"[{row['power']}]"
                  + (f"  dropped={tuple(cr.dropped)}" if cr.dropped else ""))
            if cr.a1_pass is False:
                any_violation = True
                for line in localization_ladder(cr):
                    print("  " + line)
                # diagnostic annex ONLY: two-stage escalation re-run
                n_esc = 4000 if not args.smoke else min(10 * n, 2000)
                esc = runner(cell, n_esc)
                print(f"  [SIM] diagnostic annex (NOT the kill criterion): "
                      f"re-run at n={n_esc}: rescues={esc.rescues}/{esc.n_cert}"
                      f" CP-UCB={esc.cp_ucb:.4f}")
    cells_csv.close()
    if a2_csv:
        a2_csv.close()
    print(f"[SIM] per-cell CSV written: {cells_csv.path}")

    # ------------------------------- summary --------------------------------
    if args.resume and resume_skips:
        print(f"[SIM] NOTE: {resume_skips} resume-skipped cells are in the "
              f"CSVs but not in this process's summary lines; the CSVs are "
              f"the artifact of record")
    adjudicated = [r for r in results if r.a1_pass is not None]
    burnfail = [r for r in results if r.verdict_status == STATUS_BURNIN_FAIL]
    refused = [r for r in results
               if r.a1_pass is None and r.verdict_status != STATUS_BURNIN_FAIL]
    powered_ct = vacuous_ct = 0
    for r in adjudicated:
        post, _, _ = issue_for_cell(r.cell)
        p, _ = classify_power(r, post, n, a2_results.get(r.cell.cell_id))
        if p == POWER_POWERED:
            powered_ct += 1
        else:
            vacuous_ct += 1
    verdict = "PASS" if adjudicated and not any_violation else \
        ("FAIL" if any_violation else "VACUOUS (no certified cells)")
    print(f"[SIM] A1 summary: {sum(1 for r in adjudicated if r.a1_pass)}"
          f"/{len(adjudicated)} certified cells pass CP-UCB <= delta "
          f"({powered_ct} POWERED, {vacuous_ct} VACUOUS); "
          f"{len(refused)} cells refused at issue; {len(burnfail)} cells "
          f"failed burn-in preconditions (loud) -> A1 {verdict}"
          + (" (spec kill criterion applies to --full only)" if args.smoke
             else ""))

    # F-1b quorum verdict (powered grid): >= 2/3 of certified powered cells
    # show empirical rescue frequency > 0 at the A2 cap.
    if args.powered and args.a2:
        met, with_rescue, total = quorum_verdict(a2_results)
        print(f"[SIM] POWERED QUORUM: {with_rescue}/{total} cells show "
              f"rescues > 0 at the swept A2 cap -> "
              f"{'QUORUM MET' if met else 'QUORUM NOT MET'} "
              f"(threshold 2/3)")

    # A2 per-rho calibration ratios: ONSET CELLS ONLY (F-1c); INDETERMINATE
    # cells are counted, never averaged in.
    if args.a2:
        groups: dict[tuple, dict[float, float]] = {}
        indet = 0
        for cell in cells:
            res = a2_results.get(cell.cell_id)
            if res is None:
                continue
            if res["verdict"] == A2_INDETERMINATE:
                indet += 1
                continue
            key = (cell.Delta, cell.K, cell.style)
            groups.setdefault(key, {})[cell.rho] = res["R"]
        print(f"[SIM] A2: {indet} cells A2-INDETERMINATE (no onset at cap; "
              f"first-class, not calibration success)")
        for key, Rs in groups.items():
            if len(Rs) >= 2:
                ratio = max(Rs.values()) / min(Rs.values())
                print(f"[SIM] A2 ratio for Delta,K,style={key}: "
                      f"max/min R = {ratio:.2f} over {len(Rs)} onset cells -> "
                      f"{'ACCEPT (<= 3)' if ratio <= 3 else 'A2 FAIL: T_hat downgraded to internal bound (T1.1 NOT falsified)'}")
    return 1 if any_violation else 0


if __name__ == "__main__":
    sys.exit(main())
