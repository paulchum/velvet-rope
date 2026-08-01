"""test_drift_expiry.py -- required test battery for velvet.verdict.drift_expiry.

Ported from the drift-expiry hardened package (git 324197a). Differences
from the sealed original: this import block, and the two B7 harness tests,
whose cell-geometry pins are re-pinned to the r1 burn-in constants (the v1
constants violated the issue preconditions at Delta in {0.05, 0.10}; see
scripts/run_drift_expiry_experiment.py). The theorem-facing battery is
byte-identical. Requires the optional [drift] extra (numpy, scipy); the
battery skips cleanly where those are absent so the stdlib verification
command stays green.
"""
import math

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")


import velvet.verdict.drift_expiry as de


# ------------------ pinned closed forms + K4 identity -----------------------
def test_psi_closed_forms_pinned():
    for v in np.linspace(0.0, 0.99, 25):
        assert abs(de.psi(1, 2, v) - (1 - v) ** 3 / 3.0) < 1e-12          # g_v(1,2)
        assert abs(de.psi(2, 2, v) - (1 - v) ** 3 * (1 + v) / 2.0) < 1e-12  # g_v(2,2)
        assert abs(de.psi(1, 3, v) - (1 - v) ** 4 / 4.0) < 1e-12          # g_v(1,3)


def test_K4_identity_grid():
    """m * psi(Pi+, v) + (1-m) * psi(Pi-, v) == psi(Pi, v), exactly (no
    depth-one value rescue; probability scale never mixed with value scale).
    Includes the Beta(1,2) closed-form instance."""
    grid_ab = [(1, 2), (2, 2), (1, 3), (3, 5), (2.5, 7.5), (10, 3), (1, 1)]
    vs = np.linspace(0.01, 0.95, 12)
    for (a, b) in grid_ab:
        m = a / (a + b)
        for v in vs:
            lhs = m * de.psi(a + 1, b, v) + (1 - m) * de.psi(a, b + 1, v)
            assert abs(lhs - de.psi(a, b, v)) < 1e-10
    # closed-form K4 instance at Beta(1,2):
    for v in np.linspace(0.0, 0.99, 15):
        lhs = (1 / 3) * (1 - v) ** 3 * (1 + v) / 2 + (2 / 3) * (1 - v) ** 4 / 4
        assert abs(lhs - (1 - v) ** 3 / 3.0) < 1e-12


# --------------------- rho = 0 stationary reduction -------------------------
def test_rho0_reduces_to_stationary_exact():
    post = [(3, 8), (20, 10), (15, 9), (2, 30)]
    cand = 0
    r_c = de.protected_floor(post, cand, 0.01)
    elig, _ = de.split_shape_eligible(post, cand)
    E0 = de.windowed_exponent(post, cand, r_c, 0.0, 0, elig=elig)
    for W in [1, 5, 50, 1000]:
        assert de.windowed_exponent(post, cand, r_c, 0.0, W, elig=elig) == E0
    direct = sum(de.rate_I_lower(post[b][0], post[b][1], r_c) for b in elig)
    assert E0 == direct  # exact equality on the eligible set


# ------------------------- T* monotonicity both ways ------------------------
def test_Tstar_monotone_in_rho():
    post = [(3, 8), (30, 12), (25, 10), (40, 18)]
    cand = 0
    r_c = de.protected_floor(post, cand, 0.01)
    rhos = [1e-4, 3e-4, 1e-3, 3e-3]
    Ts = [de.expiry_horizon_Tstar(post, cand, r_c, r, 0.05) for r in rhos]
    assert all(t is not None for t in Ts)
    for t1, t2 in zip(Ts, Ts[1:]):
        assert t2 <= t1


def test_Tstar_monotone_in_pseudocounts():
    cand, c, delta, rho = 0, 0.01, 0.05, 1e-3
    base = [(3, 8), (30, 12), (25, 10)]
    r_c = de.protected_floor(base, cand, c)  # depends only on the candidate
    T0 = de.expiry_horizon_Tstar(base, cand, r_c, rho, delta)
    # adding successes to an eligible anchor (MLR up) raises T*
    T1 = de.expiry_horizon_Tstar([(3, 8), (40, 12), (25, 10)], cand, r_c, rho, delta)
    # proportional scaling at fixed mean (convex-order concentration) raises T*
    T2 = de.expiry_horizon_Tstar([(3, 8), (60, 24), (50, 20)], cand, r_c, rho, delta)
    assert T0 is not None and T1 is not None and T2 is not None
    assert T1 >= T0
    assert T2 >= T0


def test_Tstar_rho0_stationary():
    post = [(3, 8), (30, 12), (25, 10)]
    r_c = de.protected_floor(post, 0, 0.01)
    assert de.expiry_horizon_Tstar(post, 0, r_c, 0.0, 0.05) == math.inf


# ------------------------------- refusals -----------------------------------
def test_refusal_past_expiry_and_oversized_request():
    post = [(3, 8), (30, 12), (25, 10)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=None, issue_time=100.0)
    assert v.status == de.CERTIFIED_SAFE
    assert v.W == v.T_star and v.expiry_time == 100.0 + v.W
    ex = de.check_expiry(v, now=v.expiry_time + 1)
    assert ex.status == de.EXPIRED
    assert de.check_expiry(v, now=v.expiry_time).status == de.CERTIFIED_SAFE  # through expiry
    v2 = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=int(v.T_star) + 5, issue_time=100.0)
    assert v2.status == de.UNCERT_REFINE  # refusal, not a stale certificate


def test_refusal_degenerate_window():
    # single weak, diffuse anchor: E(0) < log(1/delta) => T* undefined => refuse
    post = [(2, 8), (1, 1.5)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    assert v.status in (de.UNCERT_MORE_HORIZON, de.UNCERT_REFINE)
    assert v.T_star is None and v.W is None and v.expiry_time is None


def test_refusal_all_ineligible_shape():
    post = [(2, 8), (0.5, 0.7), (0.9, 3.0)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    assert v.status == de.UNCERT_REFINE
    assert v.reason == de.REASON_NO_ELIGIBLE_SHAPE  # exact spec string
    assert len(v.dropped_anchors) == 2


# -------------------- shape eligibility: drop and disclose -------------------
def test_shape_drop_and_disclose():
    """A Beta(1, 1e-8)-style anchor (mean ~ 1, beta < 1) MUST be dropped, the
    verdict MUST disclose it, and the certificate is computed on the
    remaining eligible anchors only."""
    post = [(2, 8), (1.0, 1e-8), (30, 10)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    assert any(i == 1 for (i, a, b) in v.dropped_anchors)
    assert 1 not in v.eligible_anchors
    assert v.status == de.CERTIFIED_SAFE  # eligible Beta(30,10) carries the rate
    tb = de.windowed_tail(post, 0, v.protected_floor, v.rho, int(v.W),
                          elig=list(v.eligible_anchors))
    assert abs(tb - v.tail_bound) < 1e-15


# --------------------- collapse: non-separated arms give 0 -------------------
def test_collapse_nonseparated_zero():
    assert de.rate_I_lower(2, 2, 0.5) == 0.0   # u == m
    assert de.rate_I_lower(2, 2, 0.7) == 0.0   # u > m
    assert de.rate_I_lower(2, 2, 0.3) > 0.0


def test_set_valued_collapse_in_exponent():
    cand = 0
    post = [(2, 8), (30, 10)]
    post2 = [(2, 8), (30, 10), (2, 30)]  # extra eligible anchor, mean 1/16 < r_c
    r_c = de.protected_floor(post, cand, 0.01)
    for W in [0, 10, 100]:
        E1 = de.windowed_exponent(post, cand, r_c, 1e-3, W)
        E2 = de.windowed_exponent(post2, cand, r_c, 1e-3, W)
        assert E1 == E2  # exact: restriction to S_W is exact, not lossy


# ------------------------ D+ hypothesis-audit test ---------------------------
def test_audit_rejects_interface_violations():
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(0.5, 2.0)], 0.3, 1e-3, 5)   # shape < 1
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(2.0, 2.0)], 1.0, 1e-3, 5)   # r not in [0,1)
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(2.0, 2.0)], 0.3, -1e-3, 5)  # rho < 0
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(2.0, 2.0)], 0.3, 1e-3, 2.5) # W not integer
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(2.0, 2.0)], 0.3, 1e-3, -1)  # W negative
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([], 0.3, 1e-3, 5)             # empty anchor set
    with pytest.raises(de.AuditError):
        de.audit_dplus_invocation([(np.inf, 2.0)], 0.3, 1e-3, 5)  # improper Beta
    assert de.audit_dplus_invocation([(2.0, 3.0), (1.0, 1.0)], 0.3, 1e-3, 5)


# ---------------------- preconditions and transitions ------------------------
def test_certified_not_safe_when_host_or_gated():
    v = de.issue_verdict([(30, 10), (2, 8)], 0, 0.01, 0.05, 1e-3)  # cand is host
    assert v.status == de.CERTIFIED_NOT_SAFE
    post2 = [(5, 5), (6, 5)]  # candidate near host: N^a well above c
    assert de.N_cert(post2, 0) >= 0.01
    v2 = de.issue_verdict(post2, 0, 0.01, 0.05, 1e-3)
    assert v2.status == de.CERTIFIED_NOT_SAFE


def test_recertify_paths():
    post = [(3, 8), (30, 12), (25, 10)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, issue_time=0.0)
    assert v.status == de.CERTIFIED_SAFE
    rec = de.recertify(post, v, now=v.expiry_time)
    assert rec.status == de.RECERTIFIED
    rec2 = de.recertify([(3, 8), (1, 1.5)], v, now=v.expiry_time)  # anchors collapsed
    assert rec2.status == de.REQUIRED_INSPECTION


# ------------------- B1: no zero-window certificate under drift --------------
def test_B1_zero_window_refused_under_drift():
    """Repro: T_hat = 0 under rho = 0.05 used to yield CertifiedSafe with
    W = 0 and expiry_time == issue_time (expired at birth). Must refuse."""
    post = [(600, 400), (1, 3)]
    v = de.issue_verdict(post, 1, 0.01, 0.05, 0.05, issue_time=7.0)
    assert v.status == de.UNCERT_MORE_HORIZON
    assert v.reason_code == de.RC_SUB_ONE_HORIZON
    assert "sub-one-round" in v.reason
    assert v.W is None and v.expiry_time is None and v.tail_bound is None
    # a nearby instance with T_hat >= 1 still certifies, with W >= 1 and a
    # strictly later expiry
    v2 = de.issue_verdict(post, 1, 0.01, 0.05, 0.005, issue_time=7.0)
    assert v2.status == de.CERTIFIED_SAFE
    assert v2.W >= 1 and math.isfinite(v2.W)
    assert v2.expiry_time > v2.issue_time
    # an explicit zero-window request under drift is a first-class refusal,
    # never a zero-window certificate
    v3 = de.issue_verdict(post, 1, 0.01, 0.05, 0.005, W=0)
    assert v3.status == de.UNCERT_REFINE
    assert v3.reason_code == de.RC_W_BELOW_ONE


# ---------------------- B2: delta vs delta_tail split ------------------------
def test_B2_delta_tail_split_honored_and_quoted():
    post = [(3, 8), (30, 12), (25, 10)]
    v = de.issue_verdict(post, 0, 0.01, 0.10, 1e-3, delta_tail=0.05)
    assert v.status == de.CERTIFIED_SAFE
    assert v.delta == 0.10 and v.delta_tail == 0.05          # BOTH quoted
    assert v.tail_bound <= v.delta_tail <= v.delta           # tail(W) <= delta too
    # T_hat is computed from delta_tail: it matches the single-delta run at
    # 0.05 and is no larger than the run with the looser delta_tail = 0.10
    v_ref = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    assert v.T_star == v_ref.T_star
    v_loose = de.issue_verdict(post, 0, 0.01, 0.10, 1e-3, delta_tail=0.10)
    assert v_loose.T_star >= v.T_star
    # coherent pure-tail default: delta_tail = delta, quoted on the verdict
    assert v_ref.delta_tail == v_ref.delta == 0.05


def test_B2_delta_tail_invalid_refuses_first_class():
    post = [(3, 8), (30, 12), (25, 10)]
    r = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, delta_tail=0.10)
    assert r.status == de.UNCERT_REFINE
    assert r.reason_code == de.RC_DELTA_TAIL_INVALID
    assert r.W is None and r.tail_bound is None
    r2 = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, delta_tail=0.0)
    assert r2.status == de.UNCERT_REFINE
    assert r2.reason_code == de.RC_DELTA_TAIL_INVALID


# ------------------ B3: expected-invalid requests refuse ---------------------
def test_B3_request_refusals_battery():
    post = [(3, 8), (30, 12), (25, 10)]
    # non-integer W under drift: first-class refusal, NOT a ValueError
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=1.2)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_W_NONINTEGER
    # negative W (any rho)
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=-1)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_W_NEGATIVE
    v = de.issue_verdict(post, 0, 0.01, 0.05, 0.0, W=-3)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_W_NEGATIVE
    # W < 1 under drift: no zero-window mode
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=0)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_W_BELOW_ONE
    # W > T_hat
    ok = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=int(ok.T_star) + 5)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_W_PAST_THAT
    # delta_tail > delta
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, delta_tail=0.5)
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_DELTA_TAIL_INVALID
    # route flag: anything but "A" must never certify
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, route="B")
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_ROUTE_NOT_A
    assert "Route B" in v.reason
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, route="discounted")
    assert v.status == de.UNCERT_REFINE and v.reason_code == de.RC_ROUTE_NOT_A


def test_B3_structural_malformed_still_raises():
    good = [(3, 8), (30, 12)]
    with pytest.raises(ValueError):
        de.issue_verdict([(3, 8)], 0, 0.01, 0.05, 1e-3)              # K < 2
    with pytest.raises(ValueError):
        de.issue_verdict(good, 0, -0.01, 0.05, 1e-3)                 # c <= 0
    with pytest.raises(ValueError):
        de.issue_verdict(good, 0, 0.01, 1.5, 1e-3)                   # delta not in (0,1)
    with pytest.raises(ValueError):
        de.issue_verdict(good, 0, 0.01, 0.05, -1e-3)                 # rho < 0
    with pytest.raises((TypeError, ValueError)):
        de.issue_verdict([(3, 8), ("x", 12)], 0, 0.01, 0.05, 1e-3)   # non-numeric
    with pytest.raises(TypeError):
        de.issue_verdict(good, 0, 0.01, 0.05, 1e-3, W="five")        # non-numeric W


# ------------- B4: rho = 0 exact stationary reduction, unfiltered ------------
def test_B4_rho0_stationary_unfiltered_both_directions():
    """A Beta(1, 1e-8)-style anchor is INCLUDED and certifies at rho = 0
    (exact stationary reduction, K2 / S4 at delta = 0: conjugacy for ALL
    shapes), and the SAME anchor is dropped-and-disclosed at rho > 0 (D+'s
    shape hypothesis). Both directions in one test."""
    post = [(2, 8), (1.0, 1e-8)]   # the only anchor is sub-uniform (beta < 1)
    # direction 1: rho = 0 includes it, certifies, drops nothing
    v0 = de.issue_verdict(post, 0, 0.01, 0.05, 0.0)
    assert v0.status == de.CERTIFIED_SAFE
    assert 1 in v0.eligible_anchors and len(v0.dropped_anchors) == 0
    assert v0.W == math.inf and v0.tail_bound <= v0.delta
    # the stationary exponent is the direct UNFILTERED sum (here: one term)
    r_c = de.protected_floor(post, 0, 0.01)
    E0 = de.windowed_exponent(post, 0, r_c, 0.0, 0)
    assert E0 == de.rate_I_lower(1.0, 1e-8, r_c)
    assert E0 >= math.log(1 / 0.05)
    # direction 2: rho > 0 drops-and-discloses it; nothing eligible remains
    v1 = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3)
    assert v1.status == de.UNCERT_REFINE
    assert v1.reason == de.REASON_NO_ELIGIBLE_SHAPE
    assert any(i == 1 for (i, a, b) in v1.dropped_anchors)
    assert 1 not in v1.eligible_anchors


# -------------- B5: conservative-rate naming (T_hat <= T*) -------------------
def test_B5_T_hat_naming_alias_and_conservative_language():
    post = [(3, 8), (30, 12), (25, 10)]
    v = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, issue_time=0.0)
    assert v.status == de.CERTIFIED_SAFE
    # the field is T_hat; T_star is a backward-compatible alias of it
    assert v.T_hat is not None and v.T_star == v.T_hat
    # both the function names agree (alias)
    r_c = de.protected_floor(post, 0, 0.01)
    assert (de.expiry_horizon_That(post, 0, r_c, 1e-3, 0.05)
            == de.expiry_horizon_Tstar(post, 0, r_c, 1e-3, 0.05))
    # past-T_hat refusal says the CONSERVATIVE certificate expires, and never
    # claims the true tail exceeds tolerance
    r = de.issue_verdict(post, 0, 0.01, 0.05, 1e-3, W=int(v.T_hat) + 5)
    assert r.status == de.UNCERT_REFINE and r.reason_code == de.RC_W_PAST_THAT
    assert "conservative" in r.reason.lower() and "T_hat" in r.reason
    assert "true" not in r.reason.lower() or "T_hat <= true T*" in r.reason
    ex = de.check_expiry(v, now=v.expiry_time + 1)
    assert ex.status == de.EXPIRED and ex.reason_code == de.RC_EXPIRED
    assert "CONSERVATIVE" in ex.reason and "not a danger claim" in ex.reason


# --------- B6: pinned failure-increment regression (Fact A, down) ------------
def test_B6_failure_increment_pinned_collapse():
    """The failure direction is PROVED (Fact A: adding failures moves T_hat
    down). Pinned numeric regression: eligible anchor (3,2) has positive
    rate at u = 0.55; ONE failure -> (3,3), m = 0.5 < u, rate exactly 0, and
    T_hat collapses. Both the collapse and its disclosure are asserted."""
    # pinned rate facts at the spec's u = 0.55
    assert de.rate_I_lower(3, 2, 0.55) > 0.0
    assert de.rate_I_lower(3, 3, 0.55) == 0.0     # exact collapse, not approx
    # end-to-end: candidate Beta(2000,2000) pins r_c = m_a = 0.5 and keeps
    # the containment preconditions valid across the failure increment
    cand = 1
    before = [(3, 2), (2000, 2000)]
    after = [(3, 3), (2000, 2000)]                # ONE failure on the anchor
    r_c = de.protected_floor(before, cand, 0.01)
    assert r_c == 0.5
    I0 = de.rate_I_lower(3, 2, r_c)
    assert I0 > 0.0
    dt = math.exp(-I0 / 2.0)                      # a budget the anchor carries
    # T_hat collapse at the horizon level: defined -> None
    assert de.expiry_horizon_That(before, cand, r_c, 1e-4, dt) is not None
    assert de.expiry_horizon_That(after, cand, r_c, 1e-4, dt) is None
    # verdict level: certificate before; first-class refusal DISCLOSING the
    # collapse after (anchor mean 0.5 <= r_c: separation lost, rate 0)
    vb = de.issue_verdict(before, cand, 0.01, dt, 1e-4)
    assert vb.status == de.CERTIFIED_SAFE and vb.W >= 1
    va = de.issue_verdict(after, cand, 0.01, dt, 1e-4)
    assert va.status == de.UNCERT_REFINE
    assert va.reason_code == de.RC_NO_SEPARATED
    assert "no separated anchor" in va.reason
    assert va.W is None and va.T_hat is None and va.tail_bound is None


# ------------- B7: F1 harness (spec pieces, r1 constants) --------------------
def test_B7_f1_harness_components():
    import verdict_drift_experiment as f1
    # deterministic seeding: sha256(cell_id || i) -> uint64
    assert f1.seed_for("cellX", 3) == f1.seed_for("cellX", 3)
    assert f1.seed_for("cellX", 3) != f1.seed_for("cellX", 4)
    assert 0 <= f1.seed_for("a", 0) < 2 ** 64
    # Clopper-Pearson: A1 uses the UPPER bound, A2/L2 the LOWER bound
    assert f1.cp_upper(0, 100) > 0.0 and f1.cp_upper(100, 100) == 1.0
    assert f1.cp_lower(0, 100) == 0.0
    assert f1.cp_lower(5, 100) < 5 / 100 < f1.cp_upper(5, 100)
    # deterministic burn-in pins the documented posteriors and the clock (r1)
    post, t = f1.burn_in(10, 0.20)
    assert post[0] == (3.0, 12.0) and t == 13 + 9 * 40
    assert all(p == (21.0, 21.0) for p in post[1:])
    f1.check_preconditions(post, 0, 0.01)          # holds for the r1 burn-in
    with pytest.raises(f1.BurnInError):            # LOUD failure, no re-draw
        f1.check_preconditions([(30, 10), (2, 8)], 0, 0.01)   # cand is host
    # drift styles: mu(t) = theta; per-step |d mu| <= rho; ball <= rho*k
    rng = np.random.default_rng(0)
    theta = np.array([0.5, 0.4, 0.6])
    for style in f1.STYLES:
        mu = f1.drift_paths(style, theta, 1e-3, 50, 0, 20.0, rng)
        assert np.allclose(mu[0], theta)
        assert np.all(np.abs(np.diff(mu, axis=0)) <= 1e-3 + 1e-12)
        ks = np.arange(51)[:, None]
        assert np.all(np.abs(mu - theta[None, :]) <= 1e-3 * ks + 1e-12)
        assert np.all((mu >= 0.0) & (mu <= 1.0))


def test_B7_f1_cells_refusal_certify_adversarial_and_A2():
    import verdict_drift_experiment as f1
    # r1 burn-in constants satisfy the issue preconditions on every cell
    # (the v1 candidate violated N^a < c at Delta in {0.05, 0.10}; the
    # supersession is pinned in test_drift_expiry_f1.py). Tight-gap cells
    # now refuse HONESTLY at issue -- excluded from the A1 denominator,
    # reported separately -- instead of failing burn-in.
    for D, K in ((0.05, 2), (0.05, 10), (0.10, 2)):
        cr = f1.run_cell(f1.Cell(1e-3, D, K, "ramp"), n_seeds=2)
        assert cr.n_cert == 0 and cr.n_refused == 2 and cr.a1_pass is None
        assert cr.verdict_status == de.UNCERT_MORE_HORIZON
    # Delta=0.20, K=2 refused under v1 (E(0) < L at r_c = 0.4264); under r1
    # (r_c = 0.3073) the single anchor clears the budget and it certifies
    cr = f1.run_cell(f1.Cell(1e-3, 0.20, 2, "ramp"), n_seeds=5)
    assert cr.n_cert == 5 and cr.verdict_status == de.CERTIFIED_SAFE
    assert int(cr.T_hat) == 11
    # certified micro cell: bookkeeping consistent, deterministic under seeds
    cell = f1.Cell(1e-3, 0.20, 10, "ramp")
    cr2 = f1.run_cell(cell, n_seeds=8)
    assert cr2.n_cert == 8 and cr2.n_refused == 0
    assert 0 <= cr2.rescues <= 8 and cr2.T_hat >= 1
    assert f1.run_cell(cell, n_seeds=8).rescues == cr2.rescues
    # adversarial fractional-shape cell: drop-and-disclose OBSERVED; A1 is
    # adjudicated on the disclosed eligible set (certificate still issues)
    adv = f1.Cell(1e-3, 0.20, 10, "ramp", adversarial=True)
    cr3 = f1.run_cell(adv, n_seeds=6)
    assert any(i == 1 for (i, a, b) in cr3.dropped)
    assert cr3.n_cert == 6 and cr3.verdict_status == de.CERTIFIED_SAFE
    # A2 machinery: force_W bypasses the W > T_hat refusal at the HARNESS
    # level; the full multiplier set is swept and CP LOWER is the criterion
    res = f1.a2_sweep(cell, n_seeds=6)
    assert res is not None
    assert [r["mult"] for r in res["rows"]] == f1.A2_MULTS
    assert all(r["W_test"] >= 1 for r in res["rows"])
    assert all(0.0 <= r["cp_lcb"] <= 1.0 for r in res["rows"])


# ----------------------- certified-direction sanity --------------------------
def test_rate_lower_bound_at_least_hoeffding_and_safe_direction():
    a, b, u = 30, 10, 0.4
    m = a / (a + b)
    I = de.rate_I_lower(a, b, u)
    assert I >= 2 * (m - u) ** 2 - 1e-15  # Hoeffding floor honored
    assert I > 0.0
