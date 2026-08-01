"""F1 harness battery (Phase F: power labels, powered grid, adaptive A2).

Ported from the drift-expiry hardened package test_phase_f.py (git 324197a);
the import block differs, the compliance-geometry pins are re-pinned to the
r1 burn-in constants (executed values), and the r1/v1 supersession
regression is added at the end. The test_drift_expiry.py battery is the
sealed baseline and is not modified. Requires the [drift] extra.
"""
import math

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")


import verdict_drift_experiment as f1

import velvet.verdict.drift_expiry as de


# ------------------------ F-2a: fast rescue predicate ------------------------
def _battery_states():
    """(post, cand, t, rho, style, W) grid: K=2 kill-capable states with real
    rescue mass, a K=3 state exercising the eps-override/G machinery, and a
    long forced window. t=50 makes eps ~ 2/3 (override branch hot)."""
    cells = []
    for style in f1.STYLES:
        cells.append(([(30.0, 80.0), (6.0, 2.0)], 0, 10000.0, 2e-3, style, 400))
        cells.append(([(3.0, 8.0), (10.0, 3.0)], 0, 50.0, 2e-3, style, 300))
    cells.append(([(30.0, 80.0), (6.0, 2.0), (8.0, 3.0)], 0, 50.0, 1e-3,
                  "ramp", 500))
    return cells


def test_F2a_fast_path_vs_exact_gate_battery():
    """Lemma FP pin (CERTIFICATION.md, Phase F addenda): the fast rescue
    predicate V <= r_c may only ever ADD rescues relative to the exact
    per-round psi predicate, and only on exact-boundary states; whenever the
    exact predicate rescues, the fast path rescues no later. The battery must
    itself be non-vacuous (rescues observed)."""
    total_exact = 0
    diverged = 0
    for post, cand, t, rho, style, W in _battery_states():
        r_c = de.protected_floor(post, cand, f1.C_GATE)
        SW = [b for b in range(len(post)) if b != cand
              and post[b][0] / (post[b][0] + post[b][1]) > r_c]
        alphas = np.array([p[0] for p in post])
        betas = np.array([p[1] for p in post])
        for i in range(40):
            results = {}
            for mode in (False, True):
                rng = np.random.default_rng(f1.seed_for(f"F2a_{style}_{W}", i))
                theta = rng.beta(alphas, betas)
                mu = f1.drift_paths(style, theta, rho, W, cand, float(W), rng)
                results[mode] = f1.run_policy_window(
                    post, cand, t, W, mu, rng, f1.C_GATE, r_c, SW,
                    exact_gate=mode)
            fast, exact = results[False], results[True]
            total_exact += int(exact.rescued)
            if exact.rescued:
                # fast path never misses and never fires later
                assert fast.rescued
                assert fast.s_star_rel <= exact.s_star_rel
            if fast.rescued and not exact.rescued:
                # ADD-only divergence: must sit on the exact boundary sliver
                diverged += 1
                V = fast.max_other_mean_at_sstar
                a_, b_ = post[cand]
                assert V <= r_c
                assert de.psi(a_, b_, V) < f1.C_GATE
                assert r_c - V <= 1e-9, "fast-path add off the boundary sliver"
    assert total_exact > 0, "battery vacuous: no rescues observed"
    # the sliver has ~1e-12 width; generically no divergence at all
    assert diverged <= 2


# ---------------- F-2b: vectorized engine vs independent oracle --------------
def _oracle_seed(post0, cand, t, W, cell_id, style, rho, T_ref, i,
                 c, r_c, SW, exact_gate=False):
    """Independent scalar re-derivation of the policy semantics, consuming the
    vec engine's EXACT per-seed stream layout (theta first, then block-ordered
    xi/U_eps/U_choice/U_reward via f1._draw_block). Shares no stepping code
    with the engine: V^b is computed by direct per-arm exclusion (not the
    top-2 trick), G by list comprehension, the walk by plain floats."""
    K = len(post0)
    alphas = np.array([p[0] for p in post0])
    betas = np.array([p[1] for p in post0])
    rng = np.random.default_rng(f1.seed_for(cell_id, i))
    theta = rng.beta(alphas, betas)
    xis, ues, ucs, urs = [], [], [], []
    for k0 in range(0, W, f1.VEC_BLOCK):
        nb = min(f1.VEC_BLOCK, W - k0)
        xi, ue, uc, ur = f1._draw_block(rng, nb, K, style)
        if xi is not None:
            xis.append(xi)
        ues.append(ue)
        ucs.append(uc)
        urs.append(ur)
    Ue = np.concatenate(ues) if ues else np.empty(0)
    Uc = np.concatenate(ucs) if ucs else np.empty(0)
    Ur = np.concatenate(urs) if urs else np.empty(0)
    Xi = np.concatenate(xis) if xis else None
    counts = [[float(a), float(b)] for (a, b) in post0]
    if style == "reflected-RW":
        mu = list(theta)
    sim = False
    cand_pulled = False
    for k in range(W + 1):
        m = [a / (a + b) for (a, b) in counts]
        if len(SW) and not sim and all(m[b] <= r_c for b in SW):
            sim = True
        host = max(range(K), key=lambda b: (m[b], -b))  # first max wins
        V = max(m[b] for b in range(K) if b != cand)
        if exact_gate:
            fired = (host == cand) or (de.psi(*post0[cand], V) >= c)
        else:
            fired = (host == cand) or (V <= r_c)
        if fired:
            return dict(rescued=True, s=k, V=V, sim=sim, cand_pulled=cand_pulled)
        if k == W:
            break
        eps = f1.M_EPS / (f1.M_EPS + (t + k))
        pull = host
        if Ue[k] < eps and K > 2:
            G = []
            for b in range(K):
                if b == host:
                    continue
                Vb = max(m[bb] for bb in range(K) if bb != b)
                if de.psi(counts[b][0], counts[b][1], Vb) >= c:
                    G.append(b)
            if G:
                pull = G[min(int(Uc[k] * len(G)), len(G) - 1)]
        if style == "reflected-RW":
            mu_pull = mu[pull]
        elif style == "ramp":
            mu_pull = min(1.0, max(0.0, theta[pull]
                                   + (1.0 if pull == cand else -1.0) * rho * k))
        else:  # sinusoid
            om = 2.0 * math.pi / max(T_ref, 1.0)
            A = rho * max(T_ref, 1.0) / (2.0 * math.pi)
            mu_pull = min(1.0, max(0.0, theta[pull]
                                   + (1.0 if pull == cand else -1.0)
                                   * A * math.sin(om * k)))
        y = 1.0 if Ur[k] < mu_pull else 0.0
        counts[pull][0] += y
        counts[pull][1] += 1.0 - y
        if pull == cand:
            cand_pulled = True
        if style == "reflected-RW":
            z = np.mod(np.array(mu) + rho * Xi[k].astype(float), 2.0)
            mu = list(1.0 - np.abs(1.0 - z))
    return dict(rescued=False, s=None, V=None, sim=sim, cand_pulled=cand_pulled)


def test_F2b_vec_engine_matches_independent_oracle():
    """The vectorized engine and the independent oracle agree seed-by-seed on
    (rescued, s*, sim_occurred, cand_pulled) across styles, K in {2, 3, 10},
    fast and exact predicates, and a forced long window."""
    K10 = [(3.0, 8.0)] + [(21.0, 21.0)] * 9
    configs = [
        # (post, t, rho, style, W, exact_gate, cid)
        ([(30.0, 80.0), (6.0, 2.0)], 10000.0, 2e-3, "ramp", 400, False, "v1"),
        ([(30.0, 80.0), (6.0, 2.0)], 10000.0, 2e-3, "sinusoid", 400, False, "v2"),
        ([(30.0, 80.0), (6.0, 2.0)], 200.0, 2e-3, "reflected-RW", 400, False, "v3"),
        ([(30.0, 80.0), (6.0, 2.0), (8.0, 3.0)], 50.0, 1e-3, "ramp", 300, False, "v4"),
        (K10, 369.0, 1e-3, "ramp", 90, False, "v5"),
        (K10, 369.0, 1e-3, "reflected-RW", 90, False, "v6"),
        ([(30.0, 80.0), (6.0, 2.0)], 10000.0, 2e-3, "ramp", 400, True, "v7"),
    ]
    n = 25
    total_rescues = 0
    for post, t, rho, style, W, ex, cid in configs:
        cand = 0
        r_c = de.protected_floor(post, cand, f1.C_GATE)
        SW = [b for b in range(len(post)) if b != cand
              and post[b][0] / (post[b][0] + post[b][1]) > r_c]
        vec = f1.run_policy_window_vec(post, cand, t, W, cid, style, rho,
                                       float(W), n, f1.C_GATE, r_c, SW,
                                       exact_gate=ex)
        for i in range(n):
            o = _oracle_seed(post, cand, t, W, cid, style, rho, float(W), i,
                             f1.C_GATE, r_c, SW, exact_gate=ex)
            v = vec[i]
            assert v.rescued == o["rescued"], (cid, i)
            assert (v.s_star_rel == o["s"]), (cid, i, v.s_star_rel, o["s"])
            assert v.sim_occurred == o["sim"], (cid, i)
            assert v.cand_pulled_before == o["cand_pulled"], (cid, i)
            total_rescues += int(v.rescued)
    assert total_rescues > 0, "oracle battery vacuous"


def test_F2b_run_cell_vec_smoke_consistency():
    """run_cell_vec adjudicates like run_cell on a compliance smoke cell:
    same refusal behavior on refused cells; certified cells produce valid
    bookkeeping, determinism across calls, and the adversarial cell's
    drop-and-disclose check fires. (r1 geometry: the refusal cell is
    Delta=0.05, K=2 -- the v1 refusal cell Delta=0.20, K=2 certifies
    under r1.)"""
    refused = f1.run_cell_vec(f1.Cell(1e-3, 0.05, 2, "ramp"), n_seeds=5)
    assert refused.n_cert == 0 and refused.n_refused == 5
    assert refused.a1_pass is None
    cell = f1.Cell(1e-3, 0.20, 10, "ramp")
    a = f1.run_cell_vec(cell, n_seeds=12)
    b = f1.run_cell_vec(cell, n_seeds=12)
    assert a.n_cert == 12 and a.rescues == b.rescues
    assert 0 <= a.rescues <= 12 and a.T_hat >= 1
    adv = f1.Cell(1e-3, 0.20, 10, "ramp", adversarial=True)
    cr = f1.run_cell_vec(adv, n_seeds=6)
    assert any(i == 1 for (i, a_, b_) in cr.dropped)


def test_F2a_domain_guard_falls_back_to_exact():
    """r_c >= 1 - 1e-15 forces the exact predicate (the only regime where the
    clamped fast predicate could under-count)."""
    post = [(2.0, 8.0), (30.0, 10.0)]
    rng = np.random.default_rng(0)
    theta = np.array([0.2, 0.75])
    mu = f1.drift_paths("ramp", theta, 1e-3, 10, 0, 10.0, rng)
    # degenerate floor: guard flips to exact; run must not rescue spuriously
    res = f1.run_policy_window(post, 0, 100.0, 10, mu, rng, f1.C_GATE,
                               1.0 - 1e-16, [1], exact_gate=False)
    assert not res.rescued


# ----------------------- F-1a: power column adjudication ---------------------
def test_F1a_structural_vacuity_on_compliance_cells():
    """Corollary NV adjudication on the r1 compliance geometry (K=10,
    Delta=0.20, ramp; candidate Beta(3,12), r_c = 0.3073): sum n_cross = 243
    against T_hat in {435, 130}. At rho=1e-3 the window cannot fund the
    crossings -- rescue probability exactly 0, power = VACUOUS(structural),
    A1 prints PASS(vacuous). At rho=3e-4 reachability HOLDS (243 <= 435):
    the r1 revision makes this compliance cell kill-capable, pinned here as
    POWERED. (Under the superseded v1 candidate Beta(3,8) these cells were
    T_hat in {38, 11} with sum n_cross = 72 -- both structurally vacuous.)"""
    # n = 61 is the smallest n with CP-UCB(0, n) <= delta; below that even a
    # zero-rescue cell prints FAIL (documented spec conservatism, not a bug)
    for rho, T_exp, expect_power in (
        (3e-4, 435, "POWERED"),
        (1e-3, 130, "VACUOUS"),
    ):
        cell = f1.Cell(rho, 0.20, 10, "ramp")
        cr = f1.run_cell_vec(cell, n_seeds=61)
        post, _, _ = f1.issue_for_cell(cell)
        assert int(cr.T_hat) == T_exp
        assert abs(cr.r_c - 0.3073) < 5e-4
        assert f1.sum_ncross(post, 0, cr.r_c) == 243
        power, reason = f1.classify_power(cr, post, 61)
        if expect_power == "VACUOUS":
            assert cr.rescues == 0          # Corollary NV: exactly impossible
            assert power == f1.POWER_VACUOUS and "structural" in reason
            row = f1.cell_row(cr, 61, "vec")
            assert row["A1"] == "PASS(vacuous)" and row["power"] == "VACUOUS"
        else:
            assert power == f1.POWER_POWERED
            assert f1.sum_ncross(post, 0, cr.r_c) <= int(cr.T_hat)


def test_F1a_powered_and_floor_and_noonset_triggers():
    """POWERED on a powered-grid cell (structural + tail-floor pass); the
    tail-floor and A2-no-onset triggers each flip to VACUOUS."""
    cell = f1.POWERED_CELLS[0]
    cr = f1.run_cell_vec(cell, n_seeds=20)
    post, _, _ = f1.issue_for_cell(cell)
    power, reason = f1.classify_power(cr, post, 20)
    assert power == f1.POWER_POWERED and "A2 n/a" in reason
    # tail-floor trigger: pretend the certified tail is unresolvably small
    import dataclasses
    tiny = dataclasses.replace(cr, product_bound=1e-9)
    power, reason = f1.classify_power(tiny, post, 20)
    assert power == f1.POWER_VACUOUS and "tail-floor" in reason
    # no-onset trigger: an INDETERMINATE adaptive A2 flips to VACUOUS
    fake = dict(verdict=f1.A2_INDETERMINATE, cap_mult=64)
    power, reason = f1.classify_power(cr, post, 20, fake)
    assert power == f1.POWER_VACUOUS and "no-onset" in reason
    # onset A2 keeps POWERED and records the check
    fake = dict(verdict=f1.A2_ONSET, cap_mult=8)
    power, reason = f1.classify_power(cr, post, 20, fake)
    assert power == f1.POWER_POWERED and "A2-onset" in reason


# ------------------- F-1b: powered grid design invariants --------------------
def test_F1b_powered_grid_certifies_inband_reachable():
    """Every pinned powered cell: K=2, integer-counting shape-eligible anchor
    with 5-12 pseudo-observations, mean within 1.5-3 posterior sd of r_c,
    certifies at delta=0.05, and REACHABILITY holds (n_cross <= T_hat,
    Corollary NV). Preflight passes as a whole."""
    import math as m
    assert len(f1.POWERED_CELLS) == 12
    f1.run_powered_preflight(f1.POWERED_CELLS)
    for cell in f1.POWERED_CELLS:
        assert cell.K == 2 and cell.post[0] == f1.POWERED_CANDIDATE
        (a, b) = cell.post[1]
        n0 = (a - 1) + (b - 1)
        assert a == int(a) and b == int(b) and min(a, b) >= 1
        assert 5 <= n0 <= 12
        post, t, v = f1.issue_for_cell(cell)
        assert v.status == de.CERTIFIED_SAFE and v.T_hat >= 1
        r_c = v.protected_floor
        mean = a / (a + b)
        sd = m.sqrt(a * b / ((a + b) ** 2 * (a + b + 1)))
        kappa = (mean - r_c) / sd
        assert 1.5 <= kappa <= 3.0
        snc = f1.sum_ncross(post, 0, r_c)
        assert 0 < snc <= int(v.T_hat)


def test_F1b_powered_cells_have_rescue_mass():
    """Kill capability: across the powered grid at n=60 with the production
    PWR_ streams, rescues occur at W = T_hat in at least one cell (the design
    pilots measured p_hat ~ 0.0025-0.02 per cell at n=400)."""
    total = 0
    for cell in f1.POWERED_CELLS[:6]:
        cr = f1.run_cell_vec(cell, n_seeds=60)
        assert cr.n_cert == 60
        total += cr.rescues
    assert total > 0


# ------------------ F-1c: adaptive A2 with INDETERMINATE ---------------------
def test_F1c_violates_tag_and_indeterminate():
    assert f1._violates_tag(0, 0.0) == "INDETERMINATE"
    assert f1._violates_tag(3, 0.01) is False
    assert f1._violates_tag(30, 0.08) is True


def test_F1c_adaptive_a2_extends_and_adjudicates():
    """A2 adjudication on the r1 compliance geometry (rho=1e-3, D=0.20,
    K=10). Ramp: onset at W = 650 = 5.0 x T_hat(130) -- zero-rescue rows
    INDETERMINATE-tagged (F-3i), the onset row True, the sweep stops at
    onset. Sinusoid: structurally cannot onset (amplitude locked to T_ref),
    so the doubling extension runs 16 -> 32 -> 64 to the cap and returns
    first-class A2-INDETERMINATE, never calibration success. (Under the
    superseded v1 constants the ramp onset sat at 352 = 32 x T_hat(11),
    past the old 8x cap -- the original G10 finding; the r1 geometry moves
    it inside the fixed sweep, and the cap-extension machinery is exercised
    by the sinusoid leg.) All pins executed values; seeds are
    sha256-deterministic per cell."""
    cell = f1.Cell(1e-3, 0.20, 10, "ramp")
    res = f1.a2_sweep(cell, n_seeds=40, adaptive=True, budget_s=600.0)
    assert res is not None
    assert res["verdict"] == f1.A2_ONSET
    assert res["W_viol_hat"] == 650 and res["R"] == 5.0
    mults = [r["mult"] for r in res["rows"]]
    assert mults == [1, 1.5, 2, 3, 5]             # stop at onset
    for row in res["rows"]:
        if row["rescues"] == 0:
            assert row["violates"] == "INDETERMINATE"   # F-3i tag
        else:
            assert row["violates"] is True
    # doubling extension to the 64x cap: sinusoid cannot onset by design
    cs = f1.Cell(1e-3, 0.20, 10, "sinusoid")
    rs = f1.a2_sweep(cs, n_seeds=40, adaptive=True, budget_s=600.0)
    assert rs["verdict"] == f1.A2_INDETERMINATE
    assert [r["mult"] for r in rs["rows"]] == f1.A2_MULTS + [16, 32, 64]
    assert all(r["violates"] == "INDETERMINATE" for r in rs["rows"])
    # legacy non-adaptive call keeps the fixed sweep and finds the same onset
    res0 = f1.a2_sweep(cell, n_seeds=8, adaptive=False)
    assert [r["mult"] for r in res0["rows"]] == [1, 1.5, 2, 3, 5]
    assert res0["verdict"] == f1.A2_ONSET


def test_F1c_powered_a2_finds_onset_or_indeterminate():
    """On a powered ramp cell the adaptive sweep either finds an onset (R
    defined) or honestly returns INDETERMINATE; with n=200 on the T60 ramp
    cell an onset within the cap is expected from the design pilots."""
    cell = f1.POWERED_CELLS[0]          # A7B3T60 ramp
    res = f1.a2_sweep(cell, n_seeds=200, adaptive=True, budget_s=600.0)
    assert res["verdict"] in (f1.A2_ONSET, f1.A2_INDETERMINATE)
    if res["verdict"] == f1.A2_ONSET:
        assert res["R"] >= 1 and res["W_viol_hat"] >= res["T_hat"]
    assert res["max_rescues"] > 0        # quorum contribution


# --------------------- F-1/F-3ii: quorum + resume plumbing -------------------
def test_F3ii_quorum_verdict():
    ok = dict(verdict=f1.A2_ONSET, max_rescues=3)
    bad = dict(verdict=f1.A2_INDETERMINATE, max_rescues=0)
    met, w, t = f1.quorum_verdict({"a": ok, "b": ok, "c": bad})
    assert (met, w, t) == (True, 2, 3)
    met, w, t = f1.quorum_verdict({"a": ok, "b": bad, "c": bad})
    assert (met, w, t) == (False, 1, 3)
    met, w, t = f1.quorum_verdict({})
    assert met is False


def test_F1_incremental_csv_resume(tmp_path):
    p = str(tmp_path / "cells.csv")
    w = f1.IncrementalCsv(p, ["cell_id", "x"], ["cell_id"], resume=False)
    w.write({"cell_id": "c1", "x": 1})
    w.write({"cell_id": "c2", "x": 2})
    w.close()
    w2 = f1.IncrementalCsv(p, ["cell_id", "x"], ["cell_id"], resume=True)
    assert w2.has(cell_id="c1") and w2.has(cell_id="c2")
    assert not w2.has(cell_id="c3")
    w2.write({"cell_id": "c3", "x": 3})
    w2.close()
    import csv as _csv
    with open(p) as fh:
        rows = list(_csv.DictReader(fh))
    assert [r["cell_id"] for r in rows] == ["c1", "c2", "c3"]


# ------------- F1 revision r1: burn-in constants regression ------------------
def test_F1r1_burnin_preconditions_hold_and_v1_supersession_pinned():
    """The r1 candidate Beta(3,12) satisfies the issue preconditions
    (a not host; N^a(X_t) < c) on every compliance cell, and the superseded
    v1 candidate Beta(3,8) fails them at Delta in {0.05, 0.10} -- the G9
    finding that forced revision r1. Both directions pinned by execution;
    the v1 leg is an eternal arithmetic fact, not a configuration."""
    c = f1.C_GATE
    for Delta in f1.DELTAS_SEP:
        for K in f1.KS:
            post, _t = f1.burn_in(K, Delta)
            assert post[0] == (3.0, 12.0)
            f1.check_preconditions(post, 0, c)   # must not raise
    for Delta, expect_gate_eligible in ((0.05, True), (0.10, True),
                                        (0.20, False)):
        s0 = round(40 * (0.30 + Delta))
        post_v1 = [f1.BURNIN_V1_CANDIDATE] + [(1.0 + s0, 41.0 - s0)] * 9
        n_a = de.N_cert(post_v1, 0)
        assert (n_a >= c) == expect_gate_eligible
