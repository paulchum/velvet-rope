"""Theorem T2 (staggered-crossing sharpening) battery: pinned by execution.

Ported verbatim from the drift-expiry hardened package test_phase_a.py
(git 324197a); only this import block differs. Requires the [drift] extra.
"""
import math

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")


import verdict_drift_experiment as f1

import velvet.verdict.drift_expiry as de

POST_K10 = [(3.0, 8.0)] + [(21.0, 21.0)] * 9      # the compliance geometry
POST_MIX = [(3.0, 8.0), (30.0, 12.0), (25.0, 10.0)]
POST_K2 = [(30.0, 80.0), (7.0, 3.0)]              # powered A7B3 geometry


# ------------------------- T2 core inequalities ------------------------------
def test_A1_T2_never_exceeds_product():
    """tail_T2 <= product tail everywhere on a battery (Theorem T2(i))."""
    for post in (POST_K10, POST_MIX, POST_K2):
        r_c = de.protected_floor(post, 0, 0.01)
        for rho in (1e-4, 1e-3):
            for W in (1, 7, 40, 130):
                p = de.windowed_tail(post, 0, r_c, rho, W)
                t2 = de.windowed_tail_T2(post, 0, r_c, rho, W)
                assert t2 <= p + 1e-15


def test_A1_T2_NV_zero_region_exact():
    """tail_T2 = 0 exactly when sum n_cross > W (Theorem T2(ii)); the
    compliance geometry has sum n_cross = 72."""
    r_c = de.protected_floor(POST_K10, 0, 0.01)
    ncs = [de.n_cross_of(a, b, r_c) for (a, b) in POST_K10[1:]]
    assert sum(ncs) == 72
    for rho, T_prod in ((3e-4, 38), (1e-3, 11)):
        assert de.staggered_tail(POST_K10, 0, r_c, rho, T_prod) == 0.0
        assert de.staggered_tail(POST_K10, 0, r_c, rho, 71) == 0.0
        assert de.staggered_tail(POST_K10, 0, r_c, rho, 72) > 0.0


def test_A1_T2_monotone_in_W():
    """tail_T2 nondecreasing in W (Theorem T2(iii)) -- the bisection's
    soundness hypothesis, checked across the MCAP fallback boundary too."""
    for post, rho in ((POST_K10, 1e-3), (POST_MIX, 1e-3), (POST_K2, 7.8e-4)):
        r_c = de.protected_floor(post, 0, 0.01)
        vals = [de.windowed_tail_T2(post, 0, r_c, rho, W)
                for W in range(0, 140, 7)]
        for v1, v2 in zip(vals, vals[1:]):
            assert v2 >= v1 - 1e-12


def test_A1_T2_horizon_extension_pinned():
    """Pinned executed values: the compliance geometry gains 2.5x-7.9x
    (K=10) and 2.9x-8.6x (K=50) certified horizon; each pinned horizon is
    maximal (tail crosses delta_tail at T+1); the single-anchor powered
    geometry is unchanged; T2 never falls below the product horizon."""
    r_c = de.protected_floor(POST_K10, 0, 0.01)
    assert de.expiry_horizon_That(POST_K10, 0, r_c, 3e-4, 0.05) == 38
    assert de.expiry_horizon_That_T2(POST_K10, 0, r_c, 3e-4, 0.05) == 96.0
    assert de.expiry_horizon_That(POST_K10, 0, r_c, 1e-3, 0.05) == 11
    assert de.expiry_horizon_That_T2(POST_K10, 0, r_c, 1e-3, 0.05) == 87.0
    assert de.windowed_tail_T2(POST_K10, 0, r_c, 1e-3, 87) <= 0.05
    assert de.windowed_tail_T2(POST_K10, 0, r_c, 1e-3, 88) > 0.05
    post50 = [(3.0, 8.0)] + [(21.0, 21.0)] * 49
    r50 = de.protected_floor(post50, 0, 0.01)
    assert de.expiry_horizon_That(post50, 0, r50, 1e-3, 0.05) == 46
    assert de.expiry_horizon_That_T2(post50, 0, r50, 1e-3, 0.05) == 394.0
    r2 = de.protected_floor(POST_K2, 0, 0.01)
    t_p = de.expiry_horizon_That(POST_K2, 0, r2, 7.818033e-4, 0.05)
    t_2 = de.expiry_horizon_That_T2(POST_K2, 0, r2, 7.818033e-4, 0.05)
    assert t_p == 60 and t_2 == 60.0
    r3 = de.protected_floor(POST_MIX, 0, 0.01)
    tp = de.expiry_horizon_That(POST_MIX, 0, r3, 1e-3, 0.05)
    t2 = de.expiry_horizon_That_T2(POST_MIX, 0, r3, 1e-3, 0.05)
    assert t2 >= tp


def test_A1_T2_rho0_untouched():
    """rho = 0 keeps the exact stationary reduction bit-for-bit, including
    the unfiltered fractional-shape branch (B4)."""
    post = [(2, 8), (1.0, 1e-8)]
    r_c = de.protected_floor(post, 0, 0.01)
    assert (de.windowed_tail_T2(post, 0, r_c, 0.0, 5)
            == de.windowed_tail(post, 0, r_c, 0.0, 5))
    assert (de.expiry_horizon_That_T2(post, 0, r_c, 0.0, 0.05)
            == de.expiry_horizon_That(post, 0, r_c, 0.0, 0.05) == math.inf)
    v = de.issue_verdict(post, 0, 0.01, 0.05, 0.0, sharpening="T2")
    assert v.status == de.CERTIFIED_SAFE and v.sharpening == "product"


# ------------------- T2-B: the crossing-cost upper bound ---------------------
def test_A1_T2_B_integrand_nonincreasing():
    """h_{m}(theta) nonincreasing in theta -- the hypothesis licensing the
    left-endpoint grid majorization (T2-B)."""
    for (a, b, r, delta, m) in [(21, 21, 0.4264, 0.05, 10),
                                (7, 3, 0.2895, 0.02, 20),
                                (30, 12, 0.45, 0.0, 15)]:
        x = r * (a + b + m) - a
        if x < 0:
            continue
        q = min(1.0, x / m)
        thetas = np.linspace(0.0, 1.0, 400)
        g = np.maximum(thetas - delta, 0.0)
        h = np.ones_like(g)
        mask = g > q
        gm = g[mask]
        kl = (q * (np.log(q) - np.log(gm)) if q > 0 else -0.0) \
            + (1 - q) * (np.log1p(-q) - np.log1p(-gm))
        h[mask] = np.exp(-m * kl)
        assert np.all(np.diff(h) <= 1e-12)


def test_A1_T2_B_upper_vs_monte_carlo():
    """crossing_cost_B_upper really upper-bounds Q(m_tilde(m) <= r):
    seeded MC with the CP-LOWER side certifying any violation (none)."""
    rng = np.random.default_rng(20260706)
    n = 40000
    for (a, b, r, delta, ms) in [(21.0, 21.0, 0.4264, 0.011, [8, 12, 20]),
                                 (7.0, 3.0, 0.2895, 0.047, [15, 25, 40]),
                                 (30.0, 12.0, 0.45, 0.0, [22, 35])]:
        Bs = de.crossing_cost_B_upper(a, b, r, delta, np.array(ms))
        theta = rng.beta(a, b, size=n)
        g = np.maximum(theta - delta, 0.0)
        for m, B in zip(ms, Bs):
            S = rng.binomial(m, g)
            hits = int(np.sum((a + S) / (a + b + m) <= r))
            lcb = f1.cp_lower(hits, n)
            assert lcb <= B, (a, b, m, hits / n, B)


def test_A1_T2_ncross_floor_holds_pathwise():
    """tau >= n_cross on simulated envelope walks (T2-F, seeded)."""
    rng = np.random.default_rng(7)
    a, b, r, delta = 21.0, 21.0, 0.4264, 0.02
    nc = de.n_cross_of(a, b, r)
    for _ in range(2000):
        theta = rng.beta(a, b)
        g = max(theta - delta, 0.0)
        S = 0
        for n in range(1, nc):
            S += rng.random() < g
            assert (a + S) / (a + b + n) > r  # cannot cross before n_cross
    assert nc == 8


# ---------------------- issuance wiring and disclosure ------------------------
def test_A1_T2_issue_verdict_sharpening():
    v_p = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4)
    v_2 = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, sharpening="T2")
    assert v_p.status == v_2.status == de.CERTIFIED_SAFE
    assert v_p.sharpening == "product" and v_2.sharpening == "T2"
    assert v_2.T_hat == 96.0 and v_p.T_hat == 38.0
    assert v_p.tail_bound_product == v_p.tail_bound  # product path quotes both
    assert v_2.W == 96.0 and v_2.expiry_time == v_2.issue_time + 96
    # both bounds quoted; the sharpened tail never exceeds the product tail
    assert v_2.tail_bound_product is not None
    assert v_2.tail_bound <= v_2.tail_bound_product <= 1.0
    assert v_2.tail_bound <= v_2.delta_tail
    assert "T2" in v_2.reason
    # requested W between the horizons: refused under product, certified under T2
    v_between = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, W=70)
    assert v_between.status == de.UNCERT_REFINE
    assert v_between.reason_code == de.RC_W_PAST_THAT
    v_between2 = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, W=70,
                                  sharpening="T2")
    assert v_between2.status == de.CERTIFIED_SAFE
    assert v_between2.tail_bound <= 0.05
    # refusal machinery identical under T2
    r1 = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, delta_tail=0.5,
                          sharpening="T2")
    assert r1.reason_code == de.RC_DELTA_TAIL_INVALID
    r2 = de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, route="B",
                          sharpening="T2")
    assert r2.reason_code == de.RC_ROUTE_NOT_A
    with pytest.raises(ValueError):
        de.issue_verdict(POST_K10, 0, 0.01, 0.05, 3e-4, sharpening="T9")
    # recertification preserves the sharpening
    rec = de.recertify(POST_K10, v_2, now=v_2.expiry_time)
    assert rec.status == de.RECERTIFIED and rec.sharpening == "T2"


# --------------------- A-3: certified two-sided rate bracket -----------------
def test_A3_bracket_is_bracket_and_matches_reference():
    """(I_lo, I_hi) is a genuine bracket of certified width; a high-precision
    mpmath evaluation (Kummer-transformed, so the series is positive) lands
    inside it. Collapse (0,0) at u >= m preserved."""
    import mpmath as mp
    mp.mp.dps = 30
    assert de.rate_I_bracket(2, 2, 0.7) == (0.0, 0.0)
    # mpmath cross-check where its series is short (lam* <= ~600)
    for (a, b, u) in [(300, 100, 0.43), (21, 21, 0.30)]:
        lo, hi = de.rate_I_bracket(a, b, u)
        assert 0.0 < lo <= hi < math.inf
        assert (hi - lo) / lo < 2e-2

        def phi(lam):
            return float(-lam * u + lam
                         - mp.log(mp.hyp1f1(b, a + b, lam, maxterms=10**6)))
        m = a / (a + b)
        lam0 = max(1e-2, (m - u) * (a + b + 1) / (m * (1 - m)))
        gr = (math.sqrt(5) - 1) / 2
        x1, x2 = lam0 / 8.0, 8.0 * lam0
        for _ in range(40):
            c, d = x2 - gr * (x2 - x1), x1 + gr * (x2 - x1)
            if phi(c) > phi(d):
                x2 = d
            else:
                x1 = c
        I_mp = phi(0.5 * (x1 + x2))
        assert I_mp <= hi + 1e-6
        assert abs(I_mp - lo) / lo < 2e-3
    # concentrated anchors: certified width + the PROVED Karlin-Novikoff
    # fixed-mean concentration ordering (Fact B) as the external invariant
    lo1, hi1 = de.rate_I_bracket(300, 100, 0.43)
    lo2, hi2 = de.rate_I_bracket(3000, 1000, 0.43)
    lo3, hi3 = de.rate_I_bracket(30000, 10000, 0.43)
    for lo, hi in ((lo2, hi2), (lo3, hi3)):
        assert 0.0 < lo <= hi < math.inf and (hi - lo) / lo < 2e-2
    assert lo1 <= hi2 and lo2 <= hi3          # I nondecreasing in kappa
    assert lo2 >= lo1 and lo3 >= lo2


def test_A3_saturation_removed_and_gated():
    """The concentrated-anchor saturation is killed (Beta(30000,10000):
    grid ~15 -> certified >= 8400) while moderate anchors keep the exact
    grid arm (gate) and the T*-0 collapse stays exact."""
    g = de._rate_I_lower_grid(30000, 10000, 0.43)
    assert g < 20.0                              # the old saturation, pinned
    assert de.rate_I_lower(30000, 10000, 0.43) >= 8400.0
    assert (de.rate_I_lower(21, 21, 0.4264)
            == de._rate_I_lower_grid(21, 21, 0.4264))   # gate: grid arm kept
    assert de.rate_I_lower(2, 2, 0.5) == 0.0
    assert de.rate_I_lower(2, 2, 0.7) == 0.0
    a, b, u = 30, 10, 0.4
    assert de.rate_I_lower(a, b, u) >= 2 * (a / (a + b) - u) ** 2 - 1e-15


def test_A3_certificate_recovery_pinned():
    """Executed evidence: extreme tail budgets forfeited by the grid cap are
    recovered by the series arm (Beta(3000,1000), rho=1e-3: delta_tail=1e-150
    was REFUSED, now T_hat=122; 1e-250 was REFUSED, now T_hat=60). At the
    standard delta_tail=0.05 the frontier rate ~3 was never saturated and
    T_hat is unchanged (306) -- recorded honestly."""
    post = [(3.0, 8.0), (3000.0, 1000.0)]
    r_c = de.protected_floor(post, 0, 0.01)
    old = de._A3_SERIES_THRESHOLD
    try:
        de._A3_SERIES_THRESHOLD = float("inf")
        assert de.expiry_horizon_That(post, 0, r_c, 1e-3, 1e-150) is None
        assert de.expiry_horizon_That(post, 0, r_c, 1e-3, 1e-250) is None
        t_before = de.expiry_horizon_That(post, 0, r_c, 1e-3, 0.05)
    finally:
        de._A3_SERIES_THRESHOLD = old
    assert de.expiry_horizon_That(post, 0, r_c, 1e-3, 1e-150) == 122
    assert de.expiry_horizon_That(post, 0, r_c, 1e-3, 1e-250) == 60
    assert de.expiry_horizon_That(post, 0, r_c, 1e-3, 0.05) == t_before == 306


# ------------------ A-4: alpha-side shape boundary (S4'/S5') -----------------
def test_A4_S4prime_completed_bound_holds():
    """Lemma S4' (note_A4_alpha_side.md): E[g|Y] <= (1+s)/(1+beta+n), the
    shape-COMPLETED naive mean, for alpha <= 1 <= beta -- including the
    pinned instance (0.01, 5, 0.3, 1, 1) where S4's own bound FAILS (both
    facts asserted). Exact mpmath quadrature."""
    import mpmath as mp
    mp.mp.dps = 30

    def post_g_mean(alpha, beta, delta, n, s):
        def lik(th):
            g = max(th - delta, 0)
            return (g ** s if s else 1.0) * (1 - g) ** (n - s)
        num = mp.quad(lambda th: (th - delta) * lik(th)
                      * th ** (alpha - 1) * (1 - th) ** (beta - 1),
                      [delta, 1])
        den = mp.quad(lambda th: lik(th)
                      * th ** (alpha - 1) * (1 - th) ** (beta - 1),
                      [0, delta, 1])
        return float(num / den)

    # the pinned S4 violation, reproduced ...
    psi = post_g_mean(0.01, 5, 0.3, 1, 1)
    assert psi > (0.01 + 1) / (0.01 + 5 + 1) + 1e-4      # S4 fails here
    assert psi <= (1 + 1) / (1 + 5 + 1) + 1e-9           # S4' holds
    # ... and S4' across shapes/observations
    for (a, b, d, n, s) in [(0.5, 5, 0.3, 2, 1), (0.9, 1, 0.2, 3, 0),
                            (0.3, 2, 0.4, 4, 2), (0.05, 1, 0.25, 2, 0),
                            (1.0, 5, 0.3, 1, 1)]:
        assert post_g_mean(a, b, d, n, s) <= (1 + s) / (1 + b + n) + 1e-9


def test_A4_instrument_control_and_alpha_side():
    """The A-4 DP instrument: (i) reproduces Lemma D-'s proved beta-side
    conclusion violation (positive control, factor ~12.5); (ii) finds NO
    violation of the un-inflated bound on representative alpha-side
    instances (the full scan is in the committed run log)."""
    import verdict_a4_alpha_side as a4
    ctrl = a4.analyze(1.0, 1e-8, 0.5, 0.1, 2, n_grid=1500, quiet=True)
    assert ctrl["verdict"] == "CONCLUSION-VIOLATION"
    assert ctrl["ratio_worst"] > 10.0
    for (alpha, beta) in [(0.5, 1.0), (0.1, 2.0), (0.9, 1.0)]:
        m = alpha / (alpha + beta)
        r = alpha / (alpha + beta + 1) * 1.001
        rho = 0.6 * (m - r) / 6
        res = a4.analyze(alpha, beta, r, rho, 6, n_grid=1500, quiet=True)
        assert "VIOLATION" not in res["verdict"]
        assert res["q_worst"][0] <= res["cert"][1] + 1e-12


def test_A1_T2_monotone_in_rho_preserved():
    """T_hat_T2 nonincreasing in rho (inherited: every arm is)."""
    r_c = de.protected_floor(POST_K10, 0, 0.01)
    ts = [de.expiry_horizon_That_T2(POST_K10, 0, r_c, rho, 0.05)
          for rho in (1e-4, 3e-4, 1e-3, 3e-3)]
    assert all(t is not None for t in ts)
    for t1, t2 in zip(ts, ts[1:]):
        assert t2 <= t1
