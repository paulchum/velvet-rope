"""
test_audit_glr.py — tests and falsification harnesses for velvet.verdict.audit_glr.

Ported from the external KL/GLR audit package (audited 2026-07-07).
Differences from the source: the import block, and the F4 coverage test's
denominator, which is corrected to count issued quotes only (matching the
T4.1 claim and the standalone falsifier; the source divided by all pilots,
counting NotSeparated refusals against coverage) plus a separation power
guard. Executed F4 record: reports/glr_audit_f3/f4_calibration_sweep.log.

Deterministic tests RUN BY DEFAULT (closed-form kl checks, GLR bisection vs
closed form, Lemma R, threshold monotonicity, e-value identities incl. the
exp(Z) counterexample, Clopper-Pearson closed form, N_cert statuses, gate
lemma, engine flow).

SIMULATION HARNESSES ARE DELIVERED AS RUNNABLE SPECIFICATIONS, GATED:
  RUN_MC=1              -> empirical supermartingale property of STOPPED
                           e-values on simulated nulls (mean <= 1 + MC tol)
  RUN_FALSIFICATION=1   -> F3a adversarial-stopping validity (Clopper-Pearson
                           UPPER bound <= delta per grid cell; KILL CRITERION),
                           F3b sharpness (factor [0.5, 2] of the KL-theoretic
                           prediction; strictly fewer samples than Hoeffding
                           away from 1/2), F4 quote calibration (per-cell
                           coverage >= 85% else the QUOTING RULE is falsified
                           and the interval must widen).
Per the session protocol these are not executed here; they are complete and
seeded so any runner reproduces the adjudication exactly.
"""

import math
import os
import random
import unittest

from velvet.verdict.audit_glr import (
    AnytimeGLRAudit,
    G_half,
    G_pair,
    HoeffdingAudit,
    _ncert_point,
    clopper_pearson_upper,
    e_value,
    g_eta,
    gate_value_beta,
    glr_pair,
    kl_bernoulli,
    kl_inverse,
    kl_inverse_lower,
    kl_inverse_upper,
    kt_regret,
    log_e_value,
    log_mle,
    make_audit,
    n_cert,
    pooled_mean,
    predictive_reopen_probability,
    threshold_mixture_envelope,
    threshold_mixture_exact,
    threshold_stitched,
)

RUN_MC = os.environ.get("RUN_MC") == "1"
RUN_FALSIFICATION = os.environ.get("RUN_FALSIFICATION") == "1"
LN2 = math.log(2.0)


class TestKLClosedForms(unittest.TestCase):
    def test_zero_on_diagonal(self):
        for p in [0.1, 0.5, 0.93]:
            self.assertAlmostEqual(kl_bernoulli(p, p), 0.0, places=15)

    def test_boundary_branches(self):
        q = 0.3
        self.assertAlmostEqual(kl_bernoulli(0.0, q), -math.log(1 - q), places=14)
        self.assertAlmostEqual(kl_bernoulli(1.0, q), -math.log(q), places=14)
        self.assertEqual(kl_bernoulli(0.5, 0.0), float("inf"))
        self.assertEqual(kl_bernoulli(0.5, 1.0), float("inf"))
        self.assertEqual(kl_bernoulli(0.0, 0.0), 0.0)
        self.assertEqual(kl_bernoulli(1.0, 1.0), 0.0)

    def test_verified_values(self):
        self.assertAlmostEqual(kl_bernoulli(0.75, 0.85), 0.03383405, places=7)
        self.assertAlmostEqual(kl_bernoulli(0.02, 0.03), 0.00194207, places=7)
        self.assertAlmostEqual(G_pair(0.75, 0.85), 0.01576061, places=7)
        self.assertAlmostEqual(G_half(0.75, 0.85), 0.00788031, places=7)

    def test_pinsker_and_gap(self):
        # kl >= 2 Delta^2 (Pinsker) and G_pair < kl strictly (Fact 0.2)
        for (a, b) in [(0.75, 0.85), (0.02, 0.03), (0.05, 0.95), (0.4, 0.6)]:
            self.assertGreaterEqual(kl_bernoulli(a, b), 2 * (b - a) ** 2 - 1e-12)
            self.assertLess(G_pair(a, b), kl_bernoulli(a, b))


class TestKLInverse(unittest.TestCase):
    def test_reconstructs_level_on_both_sides(self):
        for p in [0.02, 0.2, 0.5, 0.83, 0.98]:
            for c in [1e-8, 1e-4, 0.01, 0.3]:
                lo = kl_inverse_lower(p, c)
                hi = kl_inverse_upper(p, c)
                self.assertLessEqual(lo, p)
                self.assertGreaterEqual(hi, p)
                self.assertAlmostEqual(kl_bernoulli(p, lo), c, delta=1e-9)
                self.assertAlmostEqual(kl_bernoulli(p, hi), c, delta=1e-9)

    def test_monotone_and_boundary_conservative(self):
        p = 0.37
        lower = [kl_inverse(p, c, "lower") for c in [0.001, 0.01, 0.1]]
        upper = [kl_inverse(p, c, "upper") for c in [0.001, 0.01, 0.1]]
        self.assertGreater(lower[0], lower[1])
        self.assertGreater(lower[1], lower[2])
        self.assertLess(upper[0], upper[1])
        self.assertLess(upper[1], upper[2])
        self.assertEqual(kl_inverse_lower(0.0, 1.0), 0.0)
        self.assertEqual(kl_inverse_upper(1.0, 1.0), 1.0)
        with self.assertRaises(ValueError):
            kl_inverse(0.5, 0.1, "middle")


class TestGLR(unittest.TestCase):
    def test_zero_when_order_ok(self):
        z, m = glr_pair(30, 20, 30, 10)   # muhat_a > muhat_b
        self.assertEqual(z, 0.0)

    def test_bisection_matches_closed_form(self):
        cases = [(37, 11, 53, 40), (5, 0, 7, 7), (200, 150, 100, 95),
                 (1, 0, 1, 1), (400, 100, 400, 399)]
        for (na, sa, nb, sb) in cases:
            if sa / na >= sb / nb:
                continue
            z, m = glr_pair(na, sa, nb, sb)
            m_cf = pooled_mean(na, sa, nb, sb)
            self.assertAlmostEqual(m, m_cf, places=10)
            z_cf = na * kl_bernoulli(sa / na, m_cf) + nb * kl_bernoulli(sb / nb, m_cf)
            self.assertAlmostEqual(z, z_cf, places=10)

    def test_likelihood_identity(self):
        # Z = logMLE_a + logMLE_b - pooled log-likelihood at m* (Identity 6.1)
        na, sa, nb, sb = 40, 12, 60, 45
        z, m = glr_pair(na, sa, nb, sb)
        pooled_ll = (sa + sb) * math.log(m) + (na - sa + nb - sb) * math.log(1 - m)
        self.assertAlmostEqual(z, log_mle(na, sa) + log_mle(nb, sb) - pooled_ll,
                               places=9)


class TestLemmaR(unittest.TestCase):
    def test_nonneg_and_bound(self):
        for n in list(range(1, 120)) + [300, 1000]:
            for s in range(0, n + 1, max(1, n // 17)):
                R = kt_regret(n, s)
                self.assertGreaterEqual(R, -1e-12)
                self.assertLessEqual(R, 0.5 * math.log(n) + LN2 + 1e-12)

    def test_equality_at_n1(self):
        self.assertAlmostEqual(kt_regret(1, 0), LN2, places=12)
        self.assertAlmostEqual(kt_regret(1, 1), LN2, places=12)

    def test_boundary_identity(self):
        for n in [2, 10, 100]:
            lhs = kt_regret(n, n)
            rhs = 0.5 * math.log(math.pi) + math.lgamma(n + 1) - math.lgamma(n + 0.5)
            self.assertAlmostEqual(lhs, rhs, places=10)


class TestThresholds(unittest.TestCase):
    def test_monotone_in_delta(self):
        for beta in (lambda d: threshold_mixture_envelope(50, 50, d),
                     lambda d: threshold_stitched(50, 50, d),
                     lambda d: threshold_mixture_exact(50, 25, 50, 25, d)):
            self.assertLess(beta(0.1), beta(0.01))
            self.assertLess(beta(0.01), beta(1e-8))

    def test_envelope_dominates_exact(self):
        for (na, sa, nb, sb) in [(10, 3, 20, 15), (100, 99, 100, 100), (7, 0, 9, 9)]:
            self.assertLessEqual(
                threshold_mixture_exact(na, sa, nb, sb, 0.05),
                threshold_mixture_envelope(na, nb, 0.05) + 1e-12)

    def test_stitched_nondecreasing_in_n(self):
        vals = [g_eta(n, 0.05) for n in [1, 2, 5, 20, 100, 1000, 10 ** 6]]
        for x, y in zip(vals, vals[1:]):
            self.assertLessEqual(x, y + 1e-12)


class TestEValue(unittest.TestCase):
    def test_initial_value_one(self):
        self.assertAlmostEqual(log_e_value(0, 0, 0, 0), 0.0, places=15)

    def test_exp_z_counterexample_and_evalue_fix(self):
        # THEOREM.md 6.2: E[exp Z] = 1.75 > 1; corrected e-value mean = 0.4375 <= 1
        raw, fixed = 0.0, 0.0
        for xa in (0, 1):
            for xb in (0, 1):
                z, _ = glr_pair(1, xa, 1, xb)
                raw += 0.25 * math.exp(z)
                fixed += 0.25 * e_value(1, xa, 1, xb)
        self.assertAlmostEqual(raw, 1.75, places=12)
        self.assertLessEqual(fixed, 1.0 + 1e-12)
        self.assertAlmostEqual(fixed, 0.4375, places=12)

    def test_rejection_iff_evalue_crossing(self):
        na, sa, nb, sb, d = 60, 20, 60, 50, 1e-3
        z, _ = glr_pair(na, sa, nb, sb)
        lhs = z >= threshold_mixture_exact(na, sa, nb, sb, d)
        rhs = log_e_value(na, sa, nb, sb) >= math.log(1.0 / d)
        self.assertEqual(lhs, rhs)
        self.assertTrue(lhs)  # this state is decisively separated

    def test_t0_public_api_returns_normalized_evalue(self):
        a = AnytimeGLRAudit(n_arms=2, delta=0.05)
        for _ in range(10):
            a.update(0, 0)
            a.update(1, 1)
        z = a.z(0, 1)
        self.assertAlmostEqual(a.log_e_value_at(0, 1), log_e_value(10, 0, 10, 10),
                               places=12)
        self.assertAlmostEqual(a.e_value_at(0, 1), e_value(10, 0, 10, 10),
                               places=12)
        self.assertLess(a.e_value_at(0, 1), math.exp(z))


class TestWorkedComparisonPins(unittest.TestCase):
    def test_t8_constants(self):
        T, delta, D = 10 ** 4, 1.0 / (4.0 * (10 ** 4) ** 3), 0.10
        beta_T = math.log(4.0 * T ** 3)
        self.assertAlmostEqual(beta_T, 29.017315, places=6)
        self.assertEqual(math.ceil(8.0 * beta_T / (D ** 2)), 23214)
        self.assertEqual(_ncert_point(0.75, 0.85, delta), 4848)
        self.assertAlmostEqual(kl_bernoulli(0.75, 0.85) / (2.0 * D ** 2),
                               1.6917, places=4)
        self.assertAlmostEqual(kl_bernoulli(0.02, 0.03) / (2.0 * 0.01 ** 2),
                               9.7103, places=4)


class TestClopperPearson(unittest.TestCase):
    def test_zero_successes_closed_form(self):
        for n, a in [(59, 0.05), (200, 0.1)]:
            self.assertAlmostEqual(clopper_pearson_upper(0, n, a),
                                   1 - a ** (1.0 / n), places=6)

    def test_edges_and_monotonicity(self):
        self.assertEqual(clopper_pearson_upper(10, 10, 0.05), 1.0)
        u1 = clopper_pearson_upper(1, 100, 0.05)
        u2 = clopper_pearson_upper(5, 100, 0.05)
        self.assertLess(u1, u2)


class TestNCert(unittest.TestCase):
    def test_point_matches_verified_numbers(self):
        # per-arm 2424 at delta=1/(4e12), (0.75,0.85) -> total 4848
        q = _ncert_point(0.75, 0.85, 1.0 / (4.0 * (10 ** 4) ** 3))
        self.assertEqual(q, 4848)

    def test_refusal_paths(self):
        out = n_cert(200, 150, 200, 170, delta=2.5e-13, budget=4000,
                     n_boot=50, seed=7)
        self.assertEqual(out["status"], "UncertifiedNeedsMoreHorizon")
        self.assertEqual(out["shortfall"], out["quote"] - 4000)
        out2 = n_cert(50, 40, 50, 30, delta=1e-3, budget=100, n_boot=20, seed=1)
        self.assertEqual(out2["status"], "NotSeparated")
        self.assertEqual(out2["shortfall"], float("inf"))

    def test_currencies_kept_separate(self):
        out = n_cert(200, 150, 200, 170, delta=1e-6, budget=10 ** 9,
                     n_boot=20, seed=3, include_bayes=(0.6, 0.03))
        self.assertEqual(out["currency"], "frequentist")
        self.assertEqual(out["bayes_companion"]["currency"], "bayesian-predictive")
        self.assertNotIn("p_reopen_one_inspection", out)  # not blended at top level


class TestPredictiveGate(unittest.TestCase):
    def test_lemma_B(self):
        for v in [0.0, 0.1, 0.3, 0.6, 0.9]:
            e12, e22 = gate_value_beta(1, 2, v), gate_value_beta(2, 2, v)
            e13 = gate_value_beta(1, 3, v)
            self.assertLess(e13, e12)
            self.assertLess(e12, e22)
            c = 0.5 * (e12 + e22)  # inside the proved window
            out = predictive_reopen_probability(v, c)
            self.assertAlmostEqual(out["p_reopen_one_inspection"], 1.0 / 3.0, places=12)
            self.assertTrue(out["in_proved_window"])
            self.assertAlmostEqual(
                predictive_reopen_probability(v, e22 * 1.0001 + 1e-12)
                ["p_reopen_one_inspection"], 0.0, places=12)
            self.assertTrue(predictive_reopen_probability(v, e12 * 0.5)
                            ["already_eligible"])


class TestEngines(unittest.TestCase):
    def test_glr_engine_fires_on_decisive_data(self):
        a = AnytimeGLRAudit(n_arms=2, delta=0.05)
        for _ in range(60):
            a.update(0, 0)
            a.update(1, 1)
        fired = a.check_all()
        self.assertEqual(fired, [(0, 1)])
        self.assertEqual(a.active_arms(), [1])
        with self.assertRaises(RuntimeError):
            a.update(0, 1)

    def test_no_rejection_without_separation(self):
        a = AnytimeGLRAudit(2, 0.05)
        for _ in range(200):
            a.update(0, 1)
            a.update(1, 1)
        self.assertEqual(a.check_all(), [])

    def test_dropin_factory_and_hoeffding(self):
        h = make_audit("hoeffding", n_arms=2, T=10 ** 4)
        self.assertAlmostEqual(h.beta_T, math.log(4e12), places=9)
        g = make_audit("glr", n_arms=3, delta=0.06, protect="optimal")
        self.assertAlmostEqual(g.delta_pair, 0.03, places=12)
        g2 = make_audit("glr", n_arms=3, delta=0.06, protect="all_nulls")
        self.assertAlmostEqual(g2.delta_pair, 0.01, places=12)


# ============================================================================
# SIMULATION HARNESSES — runnable specifications, gated per session protocol.
# All seeded; grids pre-registered here in code so a runner reproduces the
# adjudication exactly.
# ============================================================================

def _simulate_pair(mu, seed, t_max, delta, family="mixture_exact",
                   allocation="balanced"):
    """One path: forced schedule on an unresolved pair; returns
    (rejected_arm or None, via, total_pulls, audit)."""
    rng = random.Random(seed)
    a = AnytimeGLRAudit(2, delta, family=family)
    arm_seq = 0
    while a.t < t_max:
        if allocation == "balanced":
            arm = arm_seq
            arm_seq = 1 - arm_seq
        else:  # 'adaptive-ish': data-dependent but predictable (A2)
            arm = arm_seq if rng.random() < 0.5 else (
                0 if (a.n[1] and a.n[0] and a.mean(0) > a.mean(1)) else 1)
            arm_seq = 1 - arm_seq
        a.update(arm, 1 if rng.random() < mu[arm] else 0)
        fired = a.check_all()
        if fired:
            return fired[0][0], fired[0][1], a.t, a
    return None, None, a.t, a


@unittest.skipUnless(RUN_MC, "set RUN_MC=1 to run the stopped-e-value MC spec")
class TestSupermartingaleMC(unittest.TestCase):
    """Empirical optional-stopping check of T3.3: mean of STOPPED e-values on
    simulated nulls <= 1 + MC tolerance. Adversarial stopping: tau = first t
    with E >= bar (favors large values), else t_max."""

    REPS, T_MAX, BAR = 4000, 400, 5.0
    NULLS = [(0.5, 0.5), (0.7, 0.4), (0.9, 0.9), (0.3, 0.1)]  # all mu_a >= mu_b

    def test_stopped_mean_le_one(self):
        for (ma, mb) in self.NULLS:
            for alloc in ("balanced", "adaptive"):
                rng = random.Random(hash((ma, mb, alloc)) & 0xFFFF)
                vals = []
                for r in range(self.REPS):
                    na = sa = nb = sb = 0
                    stopped = None
                    for t in range(self.T_MAX):
                        if alloc == "balanced":
                            arm = t % 2
                        else:
                            arm = 0 if (na <= nb) else 1
                            if rng.random() < 0.3:
                                arm = 1 - arm
                        x = 1 if rng.random() < (ma if arm == 0 else mb) else 0
                        if arm == 0:
                            na, sa = na + 1, sa + x
                        else:
                            nb, sb = nb + 1, sb + x
                        if na and nb:
                            ev = e_value(na, sa, nb, sb)  # pair (a,b): null TRUE
                            if ev >= self.BAR:
                                stopped = ev
                                break
                    vals.append(stopped if stopped is not None
                                else e_value(na, sa, nb, sb))
                mean = sum(vals) / len(vals)
                sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
                tol = 3 * sd / len(vals) ** 0.5
                self.assertLessEqual(
                    mean, 1.0 + tol,
                    "stopped-mean %.4f > 1+%.4f at null %s/%s" % (mean, tol,
                                                                  (ma, mb), alloc))


@unittest.skipUnless(RUN_FALSIFICATION, "set RUN_FALSIFICATION=1 for F3a/F3b/F4")
class TestF3aAdversarialStopping(unittest.TestCase):
    """F3a: adversary halts the moment the optimal arm looks rejectable.
    False safe rejection of the optimal arm must not exceed delta on ANY grid
    cell, adjudicated with one-sided Clopper-Pearson UPPER bounds.
    KILL CRITERION: any cell failing falsifies the threshold family and
    blocks the swap (the Hoeffding audit remains canonical)."""

    GRID_MU = [(0.5, 0.5), (0.45, 0.55), (0.75, 0.85), (0.05, 0.10), (0.2, 0.8)]
    GRID_DELTA = [0.10, 0.05]
    REPS, T_MAX = 2000, 3000
    FAMILIES_UNDER_TEST = ("mixture_exact", "stitched")

    def test_false_rejection_rate_cp_upper(self):
        for family in self.FAMILIES_UNDER_TEST:
            for (m1, m2) in self.GRID_MU:
                opt = 1 if m2 >= m1 else 0
                for d in self.GRID_DELTA:
                    false_rej = 0
                    for r in range(self.REPS):
                        rej, via, _, _ = _simulate_pair(
                            (m1, m2), seed=(hash((family, m1, m2, d)) ^ r) & 0x7FFFFFFF,
                            t_max=self.T_MAX, delta=d, family=family)
                        # adversary 'halts the moment it looks rejectable':
                        # first rejection IS the stopping time; count if optimal.
                        if rej is not None and rej == opt and not (m1 == m2):
                            false_rej += 1
                        if rej is not None and m1 == m2:
                            false_rej += 1  # any rejection is false on a tie
                    ub = clopper_pearson_upper(false_rej, self.REPS, alpha=0.05)
                    self.assertLessEqual(
                        ub, d,
                        "KILL: F3a cell mu=%s delta=%.3g family=%s: CP-upper "
                        "%.4f > delta — threshold family falsified; Hoeffding "
                        "audit remains canonical" % ((m1, m2), d, family, ub))


@unittest.skipUnless(RUN_FALSIFICATION, "set RUN_FALSIFICATION=1 for F3a/F3b/F4")
class TestF3bSharpness(unittest.TestCase):
    """F3b: realized rejection sample counts within [0.5, 2] x KL-theoretic
    prediction across the mu-grid; strictly fewer than the Hoeffding audit
    whenever means are away from 1/2."""

    REPS, T_MAX, DELTA, T_HOEFF = 200, 250000, 1e-3, 10 ** 4

    def _pred_total(self, m1, m2):
        gh = G_half(m1, m2)
        N = 2.0
        for _ in range(200):
            N = (math.log(1 / self.DELTA) + math.log(max(N / 2, 1)) + 2 * LN2) / gh
        return N

    def test_band_and_dominance(self):
        grid = [(a / 100.0, b / 100.0)
                for a in range(5, 96, 15) for b in range(5, 96, 15) if a < b]
        for (m1, m2) in grid:
            pred = self._pred_total(m1, m2)
            tot = []
            beat_h = 0
            for r in range(self.REPS):
                seed = (hash((m1, m2)) ^ (7919 * r)) & 0x7FFFFFFF
                rej, _, t_glr, _ = _simulate_pair((m1, m2), seed, self.T_MAX,
                                                  self.DELTA)
                self.assertIsNotNone(rej, "GLR failed to resolve in T_MAX")
                tot.append(t_glr)
                rng = random.Random(seed)  # same outcome stream for Hoeffding
                h = HoeffdingAudit(2, self.T_HOEFF)
                arm_seq, t_h = 0, None
                while h.t < self.T_MAX:
                    arm = arm_seq
                    arm_seq = 1 - arm_seq
                    h.update(arm, 1 if rng.random() < (m1, m2)[arm] else 0)
                    if h.check_all():
                        t_h = h.t
                        break
                if t_h is None or t_glr < t_h:
                    beat_h += 1
            mean_tot = sum(tot) / len(tot)
            self.assertGreaterEqual(mean_tot, 0.5 * pred,
                                    "below band at %s" % ((m1, m2),))
            self.assertLessEqual(mean_tot, 2.0 * pred,
                                 "above band at %s" % ((m1, m2),))
            if abs((m1 + m2) / 2 - 0.5) >= 0.15:  # 'away from 1/2'
                self.assertEqual(beat_h, self.REPS,
                                 "GLR not strictly faster than Hoeffding at %s"
                                 % ((m1, m2),))


@unittest.skipUnless(RUN_FALSIFICATION, "set RUN_FALSIFICATION=1 for F3a/F3b/F4")
class TestF4QuoteCalibration(unittest.TestCase):
    """F4: empirical coverage of the quoted interval >= 85% on EVERY cell of
    the pre-registered grid; a failing cell falsifies the QUOTING RULE (the
    interval must widen) — never the audit's validity (T3.1)."""

    GRID = [((0.75, 0.85), 1e-3), ((0.60, 0.70), 1e-3), ((0.40, 0.60), 1e-3),
            ((0.20, 0.30), 1e-3), ((0.75, 0.85), 1e-5)]
    REPS, PILOT_PER_ARM, T_MAX = 300, 60, 500000

    def test_coverage_per_cell(self):
        for ((m1, m2), d) in self.GRID:
            cover = 0
            trials = 0
            for r in range(self.REPS):
                seed = (hash((m1, m2, d)) ^ (104729 * r)) & 0x7FFFFFFF
                rng = random.Random(seed)
                # pilot state from which the quote is issued
                sa = sum(1 for _ in range(self.PILOT_PER_ARM) if rng.random() < m1)
                sb = sum(1 for _ in range(self.PILOT_PER_ARM) if rng.random() < m2)
                if sa / self.PILOT_PER_ARM >= sb / self.PILOT_PER_ARM:
                    continue  # NotSeparated pilot: refusal path, not a coverage trial
                q = n_cert(self.PILOT_PER_ARM, sa, self.PILOT_PER_ARM, sb,
                           delta=d, n_boot=800, seed=seed)
                # realized resolution cost on a FRESH run (same instance)
                rej, _, t_used, _ = _simulate_pair((m1, m2), seed ^ 0x5A5A,
                                                   self.T_MAX, d,
                                                   family="mixture_envelope")
                self.assertIsNotNone(rej)
                lo, hi = q["ci"]
                trials += 1
                if lo <= t_used <= (hi if not math.isinf(hi) else float("inf")):
                    cover += 1
            # Denominator fix (port, 2026-07-07): coverage is adjudicated
            # among ISSUED quotes, exactly as the T4.1 claim states and as
            # run_glr_audit_experiment.py::run_f4 computes it. The original
            # test divided by REPS, counting NotSeparated refusal pilots
            # (its own comment: "not a coverage trial") against coverage --
            # the same adjudicating-a-non-claim error class the E2 package's
            # Pass-B caught in its v1 falsifier (O6). The power guard keeps
            # the cell honest: most pilots must separate.
            self.assertGreaterEqual(
                trials, self.REPS // 2,
                "F4 cell mu=%s delta=%.1e: only %d/%d pilots separated -- "
                "cell underpowered, redesign the pilot"
                % ((m1, m2), d, trials, self.REPS))
            frac = cover / float(trials)
            self.assertGreaterEqual(
                frac, 0.85,
                "F4 cell mu=%s delta=%.1e coverage %.3f < 0.85 — quoting rule "
                "falsified: WIDEN the interval (e.g. percentile (0.02,0.98) or "
                "+lnln inflation of beta)" % ((m1, m2), d, frac))


if __name__ == "__main__":
    unittest.main(verbosity=2)
