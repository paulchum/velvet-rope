#!/usr/bin/env python3
"""Seeded [SIM] simulators for the Certified Exploration surface.

Near-verbatim ports of the moonshot falsification drivers (gating-moonshot
@ 3e0e7cf: src/t4b_witness.py run_w_trial / mc_* / run_mix, src/t4d_witness.py
run_lease_sim / mc_ramp_term) with imports rewritten to the velvet product
modules; the RNG call order inside every driver is untouched, so the upstream
regression pins reproduce exactly. See src/velvet/verdict/UPSTREAM.md.

All output is [SIM]: falsification evidence for the ported [FM] arithmetic,
never product claims, and never inputs to signed certificates.
"""
from __future__ import annotations

import math

import numpy as np

from velvet.verdict.eprocess import (
    LOG2,
    kl_bernoulli_vec,
    ledger_ln_e,
    ledger_sup_crossings,
    pair_z_vec,
    w_thresholds,
    w_z_prefix,
    z_half_vec,
)
from velvet.verdict.lease import q_of_t, theta_shifted
from velvet.verdict.retirement import ebh_ln_threshold, j_star, n_floor, n_ret_star

_kl_vec = kl_bernoulli_vec
_pair_z_vec = pair_z_vec


# ----------------------------------------------------------------------------
# T4B drivers
# ----------------------------------------------------------------------------

def run_w_trial(rng, u, ystar, ln_inv_delta, cap):
    """One ledger trial at true depth u: pull to witness/non-witness fire or
    cap. Returns dict(B, pulls, fired_nw, fired_w). Vectorized: one block."""
    x = (rng.random(cap) < 1.0 - u).astype(np.int64)
    j = np.arange(1, cap + 1)
    s = np.cumsum(x)
    z_nw, z_w = w_z_prefix(j, s, ystar)
    thr = w_thresholds(j, ln_inv_delta)
    hit_nw = z_nw >= thr
    hit_w = z_w >= thr
    i_nw = int(hit_nw.argmax()) if hit_nw.any() else cap + 1
    i_w = int(hit_w.argmax()) if hit_w.any() else cap + 1
    if i_nw < i_w:
        return {"B": 1, "pulls": i_nw + 1, "fired_nw": True, "fired_w": False}
    if i_w < i_nw:
        return {"B": 0, "pulls": i_w + 1, "fired_nw": False, "fired_w": True}
    return {"B": 0, "pulls": cap, "fired_nw": False, "fired_w": False}


def mc_refuter_boundary_fixed(ystar, delta, reps, cap, seed):
    """Kill cell C-A: candidate depth EXACTLY y* (truth on the non-witness
    null boundary). Counts KT-clock firings and raw-Z-clock firings of the
    non-witness refuter over `reps` trials of length `cap`."""
    rng = np.random.default_rng(seed)
    L = math.log(1.0 / delta)
    mu = 1.0 - ystar
    fires_kt = fires_raw = 0
    for _ in range(reps):
        x = (rng.random(cap) < mu).astype(np.int64)
        j = np.arange(1, cap + 1)
        s = np.cumsum(x)
        z_nw, _ = w_z_prefix(j, s, ystar)
        if (z_nw >= w_thresholds(j, L)).any():
            fires_kt += 1
        if (z_nw >= L).any():
            fires_raw += 1
    return {"fires_kt": fires_kt, "fires_raw": fires_raw, "reps": reps}


def mc_ledger_boundary(theta, delta_T, delta_ret, n_max, reps, seed,
                       adversary=False):
    """Kill cell C-B: B-streams at the exact null boundary. iid arm:
    B ~ Bernoulli(b*). Adversarial arm (adversary=True): predictable
    conditional mean = b* while the running mean is below b*, else
    b* - 0.25 (a mean-reverting adapted stress inside the null class of
    Lemma C1). Returns KT and raw crossing counts of ln(1/delta_ret)."""
    rng = np.random.default_rng(seed)
    bstar = 1.0 - theta * (1.0 - delta_T)
    if not adversary:
        B = (rng.random((reps, n_max)) < bstar).astype(np.int64)
    else:
        B = np.zeros((reps, n_max), dtype=np.int64)
        S = np.zeros(reps)
        for i in range(n_max):
            sh = S / max(i, 1) if i > 0 else np.zeros(reps)
            pmean = np.where(sh <= bstar, bstar, bstar - 0.25)
            B[:, i] = rng.random(reps) < pmean
            S += B[:, i]
    L = math.log(1.0 / delta_ret)
    kt, _ = ledger_sup_crossings(B, bstar, L, raw=False)
    raw, _ = ledger_sup_crossings(B, bstar, L, raw=True)
    return {"fires_kt": kt, "fires_raw": raw, "reps": reps}


def mc_dead_bill(s_depth, theta, ystar, delta_eff, delta_T, cap, reps, seed):
    """Retirement bill for an (s, 0)-dead component fed to the ledger as a
    pure trial stream (admissions granted; the end-to-end integration is
    C-C's job). Measures trials-to-fire and total pulls per rep."""
    rng = np.random.default_rng(seed)
    bstar = 1.0 - theta * (1.0 - delta_T)
    L_eff = math.log(1.0 / delta_eff)
    L_T = math.log(1.0 / delta_T)
    trials_used = np.zeros(reps, dtype=np.int64)
    pulls_used = np.zeros(reps, dtype=np.int64)
    fired = np.zeros(reps, dtype=bool)
    max_trials = 40 * n_ret_star(theta, L_eff, delta_T)
    for r in range(reps):
        nB = sB = 0
        pulls = 0
        for _ in range(max_trials):
            tr = run_w_trial(rng, s_depth, ystar, L_T, cap)
            pulls += tr["pulls"]
            nB += 1
            sB += tr["B"]
            lnE = float(ledger_ln_e(np.array([nB]), np.array([sB]),
                                    bstar)[0])
            if lnE >= L_eff:
                fired[r] = True
                break
        trials_used[r] = nB
        pulls_used[r] = pulls
    return {"trials": trials_used, "pulls": pulls_used, "fired": fired}


def run_mix(T, p, eps, y, comps, ystar, theta, delta, seed, w=None,
            k_max=None, delta_T=None, cap_mult=3.0, allow_mult=2.0,
            filter_min=None, ledger=True, ledger_admission=True):
    """One run of CC-L on the mixture kernel N_mix(T, p, ceil(eps*T); w, rho).

    comps: list of atom lists [(depth, prob), ...] per component (probs sum
    to 1). w: mixture weights over components (default uniform). On each
    offer a component label is drawn ~ w over NON-RETIRED components
    (retiring k zeroes w_k and renormalizes: the retirement ACTION), then a
    depth ~ that component's atoms. filter_min: dict {comp: dmin} — the
    clause-7 VIOLATION: that component's admitted draws are conditioned on
    depth >= dmin (adversarial pre-filtering; H_k unchanged).

    Climb = CC (accept + half-null pair audit, gate at 1-(7/8)y, latch N_g),
    with the pair audit run in a per-trial vectorized block. Ledger trials
    strictly serial, first-`cap` window; climb admissions double as ledger
    trials; when the gate declines an offer, clause-8 (ledger_admission)
    admits open-question components as pure ledger trials. Allowance
    allow_mult * n_ret_star per component, then NotSeparated. Statuses:
    Retired / NotSeparated / EvidenceCensored (open at horizon with fewer
    trials than the count floor) / Open.

    Returns per-component outcomes + global tallies. [SIM].
    """
    rng = np.random.default_rng(seed)
    K = len(comps)
    w = np.full(K, 1.0 / K) if w is None else np.asarray(w, dtype=float)
    w = w / w.sum()
    if delta_T is None:
        delta_T = 1.0 / (float(T) * float(T))
    if k_max is None:
        k_max = K
    filter_min = filter_min or {}
    L_T = math.log(1.0 / delta_T)
    n_b = int(math.ceil(eps * T))
    budget = n_b
    gate_thr = 1.0 - 0.875 * y
    beta = 3.0 * math.log(max(T, 2))
    n_g = int(math.ceil(2048.0 * beta / max(y, 1e-12)))
    cap = int(math.ceil(cap_mult * j_star(2.0 * ystar, ystar, L_T)))
    bstar = 1.0 - theta * (1.0 - delta_T)
    n_ret_pred = n_ret_star(theta, ebh_ln_threshold(k_max, delta, 0),
                            delta_T)
    allowance = int(math.ceil(allow_mult * n_ret_pred))

    # per-component atom tables (with the clause-7 filter applied to the
    # PROPOSED law; the true rho_k — used only for scoring — is unfiltered)
    depths, probs, tail_mass = [], [], []
    for ci, atoms in enumerate(comps):
        d = np.array([a[0] for a in atoms], dtype=float)
        q = np.array([a[1] for a in atoms], dtype=float)
        q = q / q.sum()
        tail_mass.append(float(q[d <= ystar + 1e-12].sum()))
        if ci in filter_min:
            keep = d >= filter_min[ci]
            d, q = d[keep], q[keep]
            q = q / q.sum()
        depths.append(d)
        probs.append(np.cumsum(q))
    alive = np.array([tm >= theta - 1e-12 for tm in tail_mass])

    mu_i, n_i, s_i = 0.0, 0, 0
    t = 0
    reg = 0.0
    latched = False
    retired = np.zeros(K, dtype=bool)
    nB = np.zeros(K, dtype=np.int64)
    sB = np.zeros(K, dtype=np.int64)
    trials = np.zeros(K, dtype=np.int64)
    lnE_led = np.full(K, -np.inf)
    retire_time = np.full(K, -1, dtype=np.int64)
    exhausted = np.zeros(K, dtype=bool)     # allowance spent
    executed = 0
    pulls_pair = pulls_ext = pulls_ledger = 0
    n_cand = n_inst = n_ref_pair = 0
    false_nw = false_w = false_acc = false_half = 0

    def q_open(ci):
        return ledger and not retired[ci] and not exhausted[ci]

    def exploit(rounds):
        nonlocal t, reg, n_i, s_i
        rounds = int(min(rounds, T - t))
        if rounds <= 0:
            return
        reg += rounds * (1.0 - mu_i)
        if mu_i > 0:
            s_i += int(rng.binomial(rounds, mu_i))
        n_i += rounds
        t += rounds

    def record_B(ci, b):
        nonlocal executed
        if not q_open(ci):
            return
        nB[ci] += 1
        sB[ci] += int(b)
        lnE = float(ledger_ln_e(np.array([nB[ci]]), np.array([sB[ci]]),
                                bstar)[0])
        lnE_led[ci] = lnE
        if lnE >= ebh_ln_threshold(k_max, delta, executed):
            retired[ci] = True
            retire_time[ci] = t
            executed += 1
        elif nB[ci] >= trials[ci] and trials[ci] >= allowance:
            exhausted[ci] = True

    def draw_depth(ci):
        r = float(rng.random())
        idx = int(np.searchsorted(probs[ci], r))
        idx = min(idx, len(depths[ci]) - 1)
        return float(depths[ci][idx])

    def w_open_mass():
        m = w * (~retired)
        return m / m.sum() if m.sum() > 0 else m

    def climb_trial(ci, u):
        """Full CC pair audit + W window, strictly serial. Returns when both
        the pair audit and (if counting) the W verdict settle, or budget/
        horizon/gate-latch interrupt."""
        nonlocal mu_i, n_i, s_i, budget, t, reg, pulls_pair, pulls_ext
        nonlocal n_inst, n_ref_pair, false_acc, false_half, false_nw, false_w
        counting = q_open(ci)
        if counting:
            trials[ci] += 1
        mu_c = 1.0 - u
        kk, sc = 0, 0
        w_settled = False
        w_val = 0
        pair_resolved = False
        installed = False
        # phase 1: alternation until pair resolves (candidate pull = 1
        # override, 2 rounds per step)
        while not pair_resolved and budget > 0 and t + 1 < T:
            b = int(min(256, budget, (T - t) // 2))
            if b <= 0:
                break
            xs = (rng.random(b) < mu_c).astype(np.int64)
            ys = (rng.random(b) < mu_i).astype(np.int64) if mu_i > 0 \
                else np.zeros(b, dtype=np.int64)
            kg = kk + 1 + np.arange(b)
            scg = sc + np.cumsum(xs)
            ng = n_i + 1 + np.arange(b)
            sig = s_i + np.cumsum(ys)
            reg_k = 0.5 * np.log(np.maximum(kg, 1)) + LOG2
            reg_n = 0.5 * np.log(np.maximum(ng, 1)) + LOG2
            ln_acc = _pair_z_vec(ng, sig, kg, scg) - reg_k - reg_n
            ln_half = z_half_vec(kg, scg, ng, sig) - reg_k - reg_n
            z_nw, z_w = w_z_prefix(kg, scg, ystar)
            thr_w = w_thresholds(kg, L_T)
            in_win = kg <= cap
            hit_nw = (z_nw >= thr_w) & in_win & (not w_settled)
            hit_w = (z_w >= thr_w) & in_win & (not w_settled)
            hit_pair = (ln_acc >= L_T) | (ln_half >= L_T)
            # W settlements inside the block do not stop the pair audit; the
            # first W event within the committed pulls is recorded below.
            i_pair = int(hit_pair.argmax()) if hit_pair.any() else b
            steps = i_pair + 1 if hit_pair.any() else b
            if not w_settled:
                i_nw = int(hit_nw.argmax()) if hit_nw.any() else steps + cap
                i_w = int(hit_w.argmax()) if hit_w.any() else steps + cap
                i_west = min(i_nw, i_w)
                if i_west < steps:
                    w_settled = True
                    w_val = 1 if i_nw < i_w else 0
                    if w_val == 1:
                        if u <= ystar + 1e-12:
                            false_nw += 1
                    else:
                        if u >= ystar - 1e-12:
                            false_w += 1
                elif kk + steps >= cap:
                    w_settled = True   # window exhausted inside pair audit
                    w_val = 0
            reg += steps * (u + (1.0 - mu_i))
            pulls_pair += steps
            budget -= steps
            t += 2 * steps
            kk += steps
            sc = int(scg[steps - 1])
            n_i += steps
            s_i = int(sig[steps - 1])
            if hit_pair.any():
                pair_resolved = True
                accept = bool(ln_acc[i_pair] >= L_T)
                if accept:
                    n_inst += 1
                    installed = True
                    if mu_c <= mu_i:
                        false_acc += 1
                    mu_i, n_i, s_i = mu_c, kk, sc
                else:
                    n_ref_pair += 1
                    if u <= (1.0 - mu_i) / 2.0:
                        false_half += 1
        # phase 2: settle the W window if still open and counting
        if counting and not w_settled:
            if installed:
                # host plays top the candidate stream up for free
                while not w_settled and t < T:
                    b = int(min(256, cap - kk, T - t))
                    if b <= 0:
                        w_settled = True
                        break
                    xs = (rng.random(b) < mu_i).astype(np.int64)
                    kg = kk + 1 + np.arange(b)
                    scg = sc + np.cumsum(xs)
                    z_nw, z_w = w_z_prefix(kg, scg, ystar)
                    thr_w = w_thresholds(kg, L_T)
                    hit = (z_nw >= thr_w) | (z_w >= thr_w)
                    steps = int(hit.argmax()) + 1 if hit.any() else b
                    reg += steps * (1.0 - mu_i)
                    t += steps
                    kk += steps
                    sc = int(scg[steps - 1])
                    # the candidate IS the incumbent: one stream, two names
                    n_i += steps
                    s_i += int(np.sum(xs[:steps]))
                    if hit.any():
                        w_settled = True
                        i_nw = np.where(z_nw >= thr_w)[0]
                        i_w = np.where(z_w >= thr_w)[0]
                        first_nw = i_nw[0] if len(i_nw) else b + cap
                        first_w = i_w[0] if len(i_w) else b + cap
                        w_val = 1 if first_nw < first_w else 0
                        if w_val == 1 and u <= ystar + 1e-12:
                            false_nw += 1
                        if w_val == 0 and u >= ystar - 1e-12:
                            false_w += 1
                    if kk >= cap:
                        w_settled = True
            else:
                # extension: candidate-only pulls (1 round, 1 override each)
                while not w_settled and budget > 0 and t < T and kk < cap:
                    b = int(min(256, cap - kk, budget, T - t))
                    if b <= 0:
                        break
                    xs = (rng.random(b) < mu_c).astype(np.int64)
                    kg = kk + 1 + np.arange(b)
                    scg = sc + np.cumsum(xs)
                    z_nw, z_w = w_z_prefix(kg, scg, ystar)
                    thr_w = w_thresholds(kg, L_T)
                    hit = (z_nw >= thr_w) | (z_w >= thr_w)
                    steps = int(hit.argmax()) + 1 if hit.any() else b
                    reg += steps * u
                    pulls_ext += steps
                    budget -= steps
                    t += steps
                    kk += steps
                    sc = int(scg[steps - 1])
                    if hit.any():
                        w_settled = True
                        i_nw = np.where(z_nw >= thr_w)[0]
                        i_w = np.where(z_w >= thr_w)[0]
                        first_nw = i_nw[0] if len(i_nw) else b + cap
                        first_w = i_w[0] if len(i_w) else b + cap
                        w_val = 1 if first_nw < first_w else 0
                        if w_val == 1 and u <= ystar + 1e-12:
                            false_nw += 1
                        if w_val == 0 and u >= ystar - 1e-12:
                            false_w += 1
                if kk >= cap and not w_settled:
                    w_settled = True   # cap: B = 0
        if counting:
            record_B(ci, w_val if w_settled else 0)

    def ledger_trial(ci, u):
        nonlocal budget, t, reg, pulls_ledger, false_nw, false_w
        trials[ci] += 1
        mu_c = 1.0 - u
        kk, sc = 0, 0
        settled = False
        b_val = 0
        while not settled and budget > 0 and t < T and kk < cap:
            b = int(min(256, cap - kk, budget, T - t))
            if b <= 0:
                break
            xs = (rng.random(b) < mu_c).astype(np.int64)
            kg = kk + 1 + np.arange(b)
            scg = sc + np.cumsum(xs)
            z_nw, z_w = w_z_prefix(kg, scg, ystar)
            thr_w = w_thresholds(kg, L_T)
            hit = (z_nw >= thr_w) | (z_w >= thr_w)
            steps = int(hit.argmax()) + 1 if hit.any() else b
            reg += steps * u
            pulls_ledger += steps
            budget -= steps
            t += steps
            kk += steps
            sc = int(scg[steps - 1])
            if hit.any():
                settled = True
                i_nw = np.where(z_nw >= thr_w)[0]
                i_w = np.where(z_w >= thr_w)[0]
                first_nw = i_nw[0] if len(i_nw) else b + cap
                first_w = i_w[0] if len(i_w) else b + cap
                b_val = 1 if first_nw < first_w else 0
                if b_val == 1 and u <= ystar + 1e-12:
                    false_nw += 1
                if b_val == 0 and u >= ystar - 1e-12:
                    false_w += 1
        record_B(ci, b_val)      # cap / truncation record 0 (conservative)

    # ---------------- main loop (event-driven, serial) ----------------
    while t < T:
        m_hat = (s_i / n_i) if n_i > 0 else 0.0
        gate_open = (m_hat < gate_thr) and not latched
        if gate_open and budget > 0:
            g = int(rng.geometric(p))
            exploit(g - 1)
            if t >= T:
                break
            wm = w_open_mass()
            ci = int(rng.choice(K, p=wm))
            u = draw_depth(ci)
            n_cand += 1
            climb_trial(ci, u)
            if (s_i / max(n_i, 1)) >= gate_thr and n_i >= n_g:
                latched = True
            continue
        # gate declined (or budget dead): ledger admissions only
        open_q = [ci for ci in range(K) if q_open(ci)]
        if (not ledger_admission) or (not open_q) or budget <= 0:
            exploit(T - t)
            break
        p_int = float(w_open_mass()[open_q].sum())
        if p_int <= 0:
            exploit(T - t)
            break
        g = int(rng.geometric(p * p_int))
        exploit(g - 1)
        if t >= T:
            break
        wm = w_open_mass()
        cond = np.zeros(K)
        cond[open_q] = wm[open_q]
        cond = cond / cond.sum()
        ci = int(rng.choice(K, p=cond))
        u = draw_depth(ci)
        n_cand += 1
        ledger_trial(ci, u)

    fl = n_floor(theta, delta / k_max)
    status = []
    for ci in range(K):
        if retired[ci]:
            status.append("Retired")
        elif exhausted[ci]:
            status.append("NotSeparated")
        elif nB[ci] < fl:
            status.append("EvidenceCensored")
        else:
            status.append("Open")
    n_retired = int(retired.sum())
    n_false = int((retired & alive).sum())
    return {"regret": reg, "retired": retired.copy(), "alive": alive.copy(),
            "status": status, "retire_time": retire_time.copy(),
            "nB": nB.copy(), "sB": sB.copy(), "trials": trials.copy(),
            "flr": (n_false / n_retired) if n_retired else 0.0,
            "n_retired": n_retired, "n_false_retired": n_false,
            "pulls_pair": pulls_pair, "pulls_ext": pulls_ext,
            "pulls_ledger": pulls_ledger, "cands": n_cand,
            "installs": n_inst, "pair_refutes": n_ref_pair,
            "false_nw": false_nw, "false_w": false_w,
            "false_accepts": false_acc, "false_half": false_half,
            "final_depth": 1.0 - mu_i, "budget_left": budget,
            "latched": latched, "cap": cap, "allowance": allowance}


# ----------------------------------------------------------------------------
# T4D drivers
# ----------------------------------------------------------------------------

def run_lease_sim(T, theta, ystar, delta, k_slots, rho, comps, seed,
                  windowed=True, w_r=None, t_lease=None, thetat=None,
                  spacing=4, real_pulls=False, s_depth=0.6, u_good=0.05,
                  cap=None, delta_T=None):
    """One run of the lease scheme on the serial stream-grain evidence
    channel.

    comps: list of dicts {"q0": float, "onset": "at_fire" | int (round) |
    None, "q_cap": float}. q_cap >= theta means the drifter becomes alive.
    The drift rate of every drifter is the full declared budget rho (the
    max-rate legal adversary).

    windowed=True: the term-cycle scheme at boundary thetat (must be
    supplied with w_r, t_lease — use design_cycle); fire -> lease of
    t_lease rounds (weight off), then re-arm; term rollover restarts the
    ledger. windowed=False: the T4B unwindowed ledger verbatim at
    boundary theta — permanent claim [tau, T].

    Violation accounting: claim (k, tau, t_end) is VIOLATED iff
    q_k(min(t_end, T)) >= theta - 1e-12 (drift paths are monotone).
    true_at_issue: q_k(tau) < theta. Fixed fleet threshold
    ln(k_slots/delta) (hardest e-BH rung; conservative).

    Returns dict of tallies. [SIM]
    """
    rng = np.random.default_rng(seed)
    K = len(comps)
    if delta_T is None:
        delta_T = 1.0 / (65536.0 * 65536.0)
    l_t = math.log(1.0 / delta_T)
    l_eff = math.log(k_slots / delta)
    if windowed:
        assert w_r is not None and t_lease is not None
        if thetat is None:
            thetat = theta_shifted(theta, rho, w_r, t_lease)
        bound = 1.0 - thetat * (1.0 - delta_T)
    else:
        thetat = theta
        bound = 1.0 - theta * (1.0 - delta_T)
    if cap is None:
        cap = int(math.ceil(3.0 * j_star(2.0 * ystar, ystar, l_t)))

    q0 = np.array([c["q0"] for c in comps], dtype=float)
    q_cap = np.array([c.get("q_cap", c["q0"]) for c in comps], dtype=float)
    onset_spec = [c.get("onset") for c in comps]
    t_onset = np.array([o if isinstance(o, (int, np.integer)) else -1
                        for o in onset_spec], dtype=float)

    def q_now(ci, t):
        return q_of_t(t, q0[ci], t_onset[ci], rho, q_cap[ci])

    n_led = n_ret_star(thetat, l_eff, delta_T)
    nB = np.zeros(K, dtype=np.int64)
    sB = np.zeros(K, dtype=np.int64)
    term_start = np.zeros(K, dtype=np.int64)
    leased_until = np.full(K, -1, dtype=np.int64)
    perm_retired = np.zeros(K, dtype=bool)
    claims = []            # (ci, tau, t_end, true_at_issue)
    fired_ever = np.zeros(K, dtype=bool)
    cycle_trials = [[] for _ in range(K)]   # trials at each firing
    shortfalls = 0         # term rolled with < n_led trials (cadence)
    no_cert_terms = 0      # term hosted >= n_led trials, no fire (honest)
    pulls_led = 0
    reg_led = 0.0
    t = 0

    def admissible(ci, t):
        if perm_retired[ci]:
            return False
        if leased_until[ci] >= 0 and t < leased_until[ci]:
            return False
        return True

    rr = 0  # round-robin pointer
    while t < T:
        # lease expiry / re-arm bookkeeping happens implicitly via time.
        cands = [ci for ci in range(K) if admissible(ci, t)]
        if not cands:
            nxt = min(int(leased_until[ci]) for ci in range(K)
                      if leased_until[ci] >= 0 and leased_until[ci] > t) \
                if any(leased_until[ci] > t and not perm_retired[ci]
                       for ci in range(K)) else T
            t = max(t + 1, nxt)
            continue
        ci = cands[rr % len(cands)]
        rr += 1
        # windowed: term rollover check at admission
        if windowed:
            if leased_until[ci] >= 0 and t >= leased_until[ci]:
                # re-arm: fresh term
                leased_until[ci] = -1
                nB[ci] = sB[ci] = 0
                term_start[ci] = t
            if t - term_start[ci] > w_r:
                if 0 < nB[ci] < n_led:
                    shortfalls += 1
                elif nB[ci] >= n_led:
                    no_cert_terms += 1
                nB[ci] = sB[ci] = 0
                term_start[ci] = t
        t += spacing                       # admission wait
        if t >= T:
            break
        q = q_now(ci, t)
        if real_pulls:
            good = rng.random() < q
            u = u_good if good else s_depth
            tr = run_w_trial(rng, u, ystar, l_t, cap)
            b = tr["B"]
            pulls_led += tr["pulls"]
            reg_led += tr["pulls"] * u
            t += tr["pulls"]
        else:
            b = int(rng.random() < 1.0 - q * (1.0 - delta_T))
        nB[ci] += 1
        sB[ci] += b
        ln_e = float(ledger_ln_e(np.array([nB[ci]]), np.array([sB[ci]]),
                                 bound)[0])
        if ln_e >= l_eff:
            tau = t
            if onset_spec[ci] == "at_fire" and not fired_ever[ci]:
                t_onset[ci] = tau
            fired_ever[ci] = True
            cycle_trials[ci].append(int(nB[ci]))
            true_iss = q_now(ci, tau) < theta - 1e-12
            if windowed:
                t_end = tau + t_lease
                leased_until[ci] = t_end
                nB[ci] = sB[ci] = 0
            else:
                t_end = T
                perm_retired[ci] = True
            claims.append((ci, tau, t_end, bool(true_iss)))

    executed = len(claims)
    violated = 0
    viol_true_iss = 0
    for (ci, tau, t_end, true_iss) in claims:
        qe = q_now(ci, min(t_end, T))
        v = qe >= theta - 1e-12
        violated += int(v)
        viol_true_iss += int(v and true_iss)
    return {"executed": executed, "violated": violated,
            "viol_true_at_issue": viol_true_iss,
            "false_at_issue": sum(1 for c in claims if not c[3]),
            "flr_lease": violated / executed if executed else 0.0,
            "claims": claims, "cycle_trials": cycle_trials,
            "shortfalls": shortfalls, "no_cert_terms": no_cert_terms,
            "n_led": int(n_led), "pulls_led": pulls_led,
            "reg_led": reg_led, "rounds": min(t, T),
            "thetat": thetat, "bound": bound}


def mc_ramp_term(theta, rho, w_r, t_lease, delta, k_slots, delta_T,
                 spacing, reps, seed, shifted=True):
    """One evidence term against the pre-climbing ramp — the worst legal
    violation path: q_t = thetat + rho*t through the term (TV-legal), so a
    fire at term end with lease t_lease has its claim falsified exactly at
    lease end. Counts term-firings of the shifted clock (btilde*) or the
    naive unshifted clock (b*). On violation paths every in-term evidence
    time satisfies q >= thetat, so the shifted count is bound by delta
    (Theorem D2); the unshifted clock has no such bound. Returns fires and
    realized violations (fire at tau -> violated iff q(tau + t_lease) >=
    theta)."""
    rng = np.random.default_rng(seed)
    thetat = theta_shifted(theta, rho, w_r, t_lease)
    bound = 1.0 - (thetat if shifted else theta) * (1.0 - delta_T)
    l_eff = math.log(k_slots / delta)
    n_max = w_r // spacing
    t_adm = spacing * (1 + np.arange(n_max))
    q_path = np.minimum(thetat + rho * t_adm, theta)
    p1 = 1.0 - q_path * (1.0 - delta_T)
    B = (rng.random((reps, n_max)) < p1[None, :]).astype(np.int64)
    n = np.arange(1, n_max + 1, dtype=float)[None, :]
    S = np.cumsum(B, axis=1)
    sh = S / n

    z = n * _kl_vec(sh, bound)
    z = np.where(sh > bound, z, 0.0)
    stat = z - (0.5 * np.log(n) + LOG2)
    hit = stat >= l_eff
    any_hit = hit.any(axis=1)
    first = np.where(any_hit, hit.argmax(axis=1), -1)
    fires = int(any_hit.sum())
    viol = 0
    for r in np.where(any_hit)[0]:
        tau = float(t_adm[first[r]])
        q_end = min(thetat + rho * (tau + t_lease), theta)
        viol += int(q_end >= theta - 1e-12)
    return {"fires": fires, "violated": viol, "reps": reps,
            "n_max": int(n_max), "thetat": thetat, "bound": bound}
