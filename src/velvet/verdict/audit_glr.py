"""
audit_glr.py - Anytime-valid KL/GLR audit for Bernoulli arms (spec E3).

Canonical source: docs/math/anytime_glr_audit_family_m.txt. Ported verbatim from the
external KL/GLR audit package (audited 2026-07-07). Pure stdlib. Log-space
arithmetic throughout.

Contracts (see docs/math/anytime_glr_audit_family_m.txt for proofs; section refs in brackets):
  * e-process [T3.3, §6]: for each ordered pair (a,b), E_ab(t) with
    ln E_ab(t) = Z_ab(t) - R_a(t) - R_b(t) satisfies, for EVERY (mu_a, mu_b)
    with mu_a >= mu_b and EVERY stopping time tau (any adaptive allocation,
    any data-dependent stopping):  E[E_ab(tau)] <= 1,  E_ab(0) = 1,  E_ab >= 0.
    Ville: P(exists t: E_ab(t) >= 1/delta) <= delta.
  * Family M (default) rejection  Z >= ln(1/delta) + R_a + R_b  is EXACTLY the
    crossing E_ab >= 1/delta  ==> anytime validity at level exactly delta [T3.1].
  * Family S (stitched) rejection Z >= g_eta(n_a, delta/2) + g_eta(n_b, delta/2)
    is proved anytime valid with explicit constants [TF-S, §4.2].
  * N_cert quote [T4.1, §9] is an ESTIMATOR with an empirical calibration
    target (F4), not a theorem; refusal path returns
    UncertifiedNeedsMoreHorizon with the shortfall attached.
  * predictive_reopen_probability [§9.4] is BAYESIAN-PREDICTIVE currency,
    never blended with the frequentist quote.

Raw exp(Z) is NOT an e-process (E[exp Z] = 1.75 already at one sample each,
mu=1/2; docs/math/anytime_glr_audit_family_m.txt §6.2) and is deliberately not exposed.
"""

from __future__ import annotations

import math
from math import exp, lgamma, log, sqrt
from typing import Any

LN2 = math.log(2.0)
_PI = math.pi


# ----------------------------------------------------------------------------
# Bernoulli KL, numerically stable near {0,1}
# ----------------------------------------------------------------------------

def kl_bernoulli(p: float, q: float) -> float:
    """kl(p,q) = p ln(p/q) + (1-p) ln((1-p)/(1-q)); exact boundary branches.

    Conventions: 0 ln 0 = 0; kl(p,0)=inf for p>0; kl(p,1)=inf for p<1;
    kl(0,0)=kl(1,1)=0. Uses log1p-style differences implicitly via exact
    branches rather than clamping, so values near {0,1} are exact.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    if q <= 0.0:
        return 0.0 if p == 0.0 else float("inf")
    if q >= 1.0:
        return 0.0 if p == 1.0 else float("inf")
    out = 0.0
    if p > 0.0:
        out += p * (log(p) - log(q))
    if p < 1.0:
        out += (1.0 - p) * (log(1.0 - p) - log(1.0 - q))
    return out


def kl_inverse_lower(p: float, c: float, tol: float = 1e-14,
                     max_iter: int = 200) -> float:
    """Smallest-side inverse: return q in [0,p] with kl(p,q)=c.

    The map q -> kl(p,q) is continuous and strictly decreasing on [0,p] when
    p>0, with value 0 at q=p and +inf at q=0 for p>0. Boundary cases are the
    conservative endpoints. This is the lower confidence-bound inverse used by
    KL-style intervals; the returned value is on the conservative side.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    if c < 0.0:
        raise ValueError("c must be nonnegative")
    if c == 0.0 or p == 0.0:
        return p
    lo, hi = 0.0, p
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        if mid == lo or mid == hi or abs(kl_bernoulli(p, mid) - c) <= tol:
            break
        if kl_bernoulli(p, mid) > c:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def kl_inverse_upper(p: float, c: float, tol: float = 1e-14,
                     max_iter: int = 200) -> float:
    """Largest-side inverse: return q in [p,1] with kl(p,q)=c.

    The map q -> kl(p,q) is continuous and strictly increasing on [p,1] when
    p<1, with value 0 at q=p and +inf at q=1 for p<1. Boundary cases are the
    conservative endpoints. This is the upper confidence-bound inverse used by
    KL-style intervals; the returned value is on the conservative side.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    if c < 0.0:
        raise ValueError("c must be nonnegative")
    if c == 0.0 or p == 1.0:
        return p
    lo, hi = p, 1.0
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        if mid == lo or mid == hi or abs(kl_bernoulli(p, mid) - c) <= tol:
            break
        if kl_bernoulli(p, mid) < c:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def kl_inverse(p: float, c: float, side: str) -> float:
    """Bisection inverse for kl(p,q)=c.

    side="lower" returns q<=p; side="upper" returns q>=p. The direction is
    explicit because Bernoulli KL is not globally one-to-one in q.
    """
    if side == "lower":
        return kl_inverse_lower(p, c)
    if side == "upper":
        return kl_inverse_upper(p, c)
    raise ValueError("side must be 'lower' or 'upper'")


def pooled_mean(na: int, sa: int, nb: int, sb: int) -> float:
    """Closed-form minimizer of m -> na*kl(mua,m)+nb*kl(mub,m) (Fact 0.1)."""
    return (sa + sb) / float(na + nb)


def glr_pair(na: int, sa: int, nb: int, sb: int,
             tol: float = 1e-14, max_iter: int = 200) -> tuple[float, float | None]:
    """GLR statistic Z_ab for the null H: mu_a >= mu_b, via BISECTION in m.

    Returns (Z, m_star). Z = 0 when muhat_a >= muhat_b (Fact 0.1). Otherwise
    bisects on the sign of f'(m) = [na(m-mua)+nb(m-mub)]/(m(1-m)) over
    (muhat_a, muhat_b); the root is the pooled mean, used as a cross-check
    (tests assert bisection == closed form to 1e-12).
    """
    if na <= 0 or nb <= 0:
        return 0.0, None
    mua, mub = sa / float(na), sb / float(nb)
    if mua >= mub:
        return 0.0, None
    lo, hi = mua, mub
    # numerator of f'(m); sign only (denominator m(1-m) > 0 on (0,1))
    def dnum(m: float) -> float:
        return na * (m - mua) + nb * (m - mub)
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        if hi - lo < tol:
            break
        if dnum(mid) < 0.0:
            lo = mid
        else:
            hi = mid
    m = 0.5 * (lo + hi)
    # guard the open interval for kl evaluation when mua==0 or mub==1
    m = min(max(m, 1e-300), 1.0 - 1e-16)
    z = na * kl_bernoulli(mua, m) + nb * kl_bernoulli(mub, m)
    return z, m


def G_pair(x: float, y: float) -> float:
    """kl(x, (x+y)/2) + kl(y, (x+y)/2): per-PAIR balanced drift of Z."""
    m = 0.5 * (x + y)
    return kl_bernoulli(x, m) + kl_bernoulli(y, m)


def G_half(x: float, y: float) -> float:
    """inf_m [ .5 kl(x,m) + .5 kl(y,m) ] = G_pair/2: per-SAMPLE balanced drift
    (the quantity in the prompt's N_cert formula)."""
    return 0.5 * G_pair(x, y)


# ----------------------------------------------------------------------------
# KT / Jeffreys mixture and the exact prediction-regret correction (Lemma R)
# ----------------------------------------------------------------------------

def log_kt(n: int, s: int) -> float:
    """ln KT(n,s) = ln[Gamma(s+1/2)Gamma(n-s+1/2) / (pi Gamma(n+1))].
    KT(0,0) = 1. Equals the Jeffreys Beta(1/2,1/2) marginal likelihood, which
    equals the product of KT predictive probabilities (L1-b)."""
    if n == 0:
        return 0.0
    f = n - s
    return lgamma(s + 0.5) + lgamma(f + 0.5) - lgamma(n + 1.0) - log(_PI)


def log_mle(n: int, s: int) -> float:
    """ln sup_p p^s (1-p)^(n-s) = s ln(s/n) + (n-s) ln((n-s)/n); 0 at n=0."""
    if n == 0:
        return 0.0
    f = n - s
    out = 0.0
    if s > 0:
        out += s * (log(s) - log(n))
    if f > 0:
        out += f * (log(f) - log(n))
    return out


def kt_regret(n: int, s: int) -> float:
    """R(n,s) = ln MLE - ln KT >= 0; Lemma R: R <= 0.5 ln n + ln 2 for n>=1."""
    return log_mle(n, s) - log_kt(n, s)


# ----------------------------------------------------------------------------
# e-process (T3.3): ln E_ab = Z_ab - R_a - R_b  (one formula, both muhat cases)
# ----------------------------------------------------------------------------

def log_e_value(na: int, sa: int, nb: int, sb: int) -> float:
    """ln E_ab(t) for the ordered pair (a,b), null H_ab: mu_a >= mu_b.

    Contract [T3.3]: E(0)=1; E>=0; for every null point and EVERY stopping
    time tau, E[E(tau)] <= 1 (E is dominated by the nonnegative mean-one
    martingale KT_a KT_b / (L_a(mu_a) L_b(mu_b)), any adaptive allocation);
    hence P(sup_t E >= 1/delta) <= delta. Values across different pairs are
    arbitrarily dependent; downstream composition must be dependence-robust
    (e-BH / averaging), which needs exactly this contract and nothing more.
    """
    z, _ = glr_pair(na, sa, nb, sb)
    return z - kt_regret(na, sa) - kt_regret(nb, sb)


def e_value(na: int, sa: int, nb: int, sb: int) -> float:
    return exp(log_e_value(na, sa, nb, sb))


# ----------------------------------------------------------------------------
# Threshold families (docs/math/anytime_glr_audit_family_m.txt §4). Reject a via b
# iff muhat_a < muhat_b and Z_ab >= beta(t, delta).
# ----------------------------------------------------------------------------

def threshold_mixture_exact(na: int, sa: int, nb: int, sb: int,
                            delta: float) -> float:
    """Family M, exact: beta_M = ln(1/delta) + R_a + R_b. Crossing Z >= beta_M
    is IDENTICAL to E_ab >= 1/delta -> validity at exactly delta [T3.1-M]."""
    return log(1.0 / delta) + kt_regret(na, sa) + kt_regret(nb, sb)


def threshold_mixture_envelope(na: int, nb: int, delta: float) -> float:
    """Family M deterministic envelope (Lemma R):
    ln(1/delta) + .5 ln n_a + .5 ln n_b + 2 ln 2  >= beta_M."""
    return log(1.0 / delta) + 0.5 * log(na) + 0.5 * log(nb) + 2.0 * LN2


def g_eta(n: int, delta_prime: float, eta: float = 1.1) -> float:
    """Family S per-arm two-sided envelope [TF-S(i)]:
    g_eta(n, d') = eta [ ln(2/d') + ln((k+1)(k+2)) ], k = floor(ln n / ln eta).
    P(exists t, n_i(t)>=1: n_i kl(muhat_i, mu_i) >= g_eta(n_i, d')) <= d'."""
    if n < 1:
        raise ValueError("n >= 1 required")
    k = int(math.floor(log(n) / log(eta))) if n > 1 else 0
    return eta * (log(2.0 / delta_prime) + log((k + 1.0) * (k + 2.0)))


def threshold_stitched(na: int, nb: int, delta: float, eta: float = 1.1) -> float:
    """Family S pair threshold [TF-S(ii)]:
    beta_S = g_eta(n_a, delta/2) + g_eta(n_b, delta/2)."""
    return g_eta(na, delta / 2.0, eta) + g_eta(nb, delta / 2.0, eta)


FAMILIES = ("mixture_exact", "mixture_envelope", "stitched")


# ----------------------------------------------------------------------------
# Audit engines: AnytimeGLRAudit (default) and HoeffdingAudit (baseline),
# behind a common drop-in interface (make_audit flag).
# ----------------------------------------------------------------------------

class AnytimeGLRAudit:
    """Anytime-valid GLR audit [T3.1]. No horizon anywhere.

    protect="optimal": each ordered pair tested at delta/(K-1); guarantees
      P(the optimal arm is ever safely rejected) <= delta under ANY adaptive
      allocation and ANY stopping time (docs/math/anytime_glr_audit_family_m.txt
      Thm T3.1). K=2 -> per-pair level = delta.
    protect="all_nulls": per-pair level delta/(K(K-1)) (ordered pairs) for
      family-wise protection of every true null (explicit accounting; the
      additive union cost is ln of the pair count, never a hidden K^2 in
      samples).
    family in FAMILIES; "mixture_exact" is the default and the theorem-exact
    rule; "stitched" uses eta (default 1.1).
    """

    def __init__(self, n_arms: int, delta: float, family: str = "mixture_exact",
                 eta: float = 1.1, protect: str = "optimal"):
        if n_arms < 2:
            raise ValueError("need >= 2 arms")
        if not (0.0 < delta < 1.0):
            raise ValueError("delta in (0,1)")
        if family not in FAMILIES:
            raise ValueError(f"family must be one of {FAMILIES}")
        self.K = n_arms
        self.delta = delta
        self.family = family
        self.eta = eta
        self.protect = protect
        npairs = (n_arms - 1) if protect == "optimal" else n_arms * (n_arms - 1)
        self.delta_pair = delta / npairs
        self.n = [0] * n_arms
        self.s = [0] * n_arms
        self.rejected: set[int] = set()
        self.t = 0

    # -- data path ------------------------------------------------------
    def update(self, arm: int, x: int) -> None:
        if arm in self.rejected:
            raise RuntimeError(f"locked-out arm pulled: {arm}")
        if x not in (0, 1):
            raise ValueError("Bernoulli outcome expected")
        self.n[arm] += 1
        self.s[arm] += x
        self.t += 1

    def mean(self, i: int) -> float:
        return self.s[i] / self.n[i] if self.n[i] > 0 else float("nan")

    # -- evidence -------------------------------------------------------
    def z(self, a: int, b: int) -> float:
        zz, _ = glr_pair(self.n[a], self.s[a], self.n[b], self.s[b])
        return zz

    def log_e_value_at(self, a: int, b: int) -> float:
        """ln E_ab at the current time; T3.3 contract (see module docstring)."""
        return log_e_value(self.n[a], self.s[a], self.n[b], self.s[b])

    def e_value_at(self, a: int, b: int) -> float:
        return exp(self.log_e_value_at(a, b))

    def threshold(self, a: int, b: int) -> float:
        if self.family == "mixture_exact":
            return threshold_mixture_exact(self.n[a], self.s[a],
                                           self.n[b], self.s[b], self.delta_pair)
        if self.family == "mixture_envelope":
            return threshold_mixture_envelope(self.n[a], self.n[b], self.delta_pair)
        return threshold_stitched(self.n[a], self.n[b], self.delta_pair, self.eta)

    # -- decisions ------------------------------------------------------
    def should_reject(self, a: int, b: int) -> bool:
        """Safe rejection of a via b (A5): muhat_a < muhat_b and Z >= beta."""
        if self.n[a] == 0 or self.n[b] == 0:
            return False
        if self.mean(a) >= self.mean(b):
            return False
        return self.z(a, b) >= self.threshold(a, b)

    def check_all(self) -> list[tuple[int, int]]:
        """Run every ordered active pair; lock out any rejected arm.
        Returns the list of (rejected_arm, via_arm) events fired now."""
        fired: list[tuple[int, int]] = []
        active = [i for i in range(self.K) if i not in self.rejected]
        for a in active:
            for b in active:
                if a == b or a in self.rejected:
                    continue
                if self.should_reject(a, b):
                    self.rejected.add(a)
                    fired.append((a, b))
                    break
        return fired

    def active_arms(self) -> list[int]:
        return [i for i in range(self.K) if i not in self.rejected]

    def status(self) -> dict[str, Any]:
        return {"engine": "glr", "family": self.family, "delta": self.delta,
                "delta_pair": self.delta_pair, "protect": self.protect,
                "t": self.t, "n": list(self.n), "s": list(self.s),
                "rejected": sorted(self.rejected)}


class HoeffdingAudit:
    """Baseline fixed-horizon audit (drop-in): beta_T = ln(4 T^3),
    rad(n) = sqrt(beta_T/(2n)), reject a via b iff UCB_a <= LCB_b.
    Requires the horizon T declared in advance — the defect this project
    removes. Kept behind the make_audit flag for A/B and F3b comparisons.
    """

    def __init__(self, n_arms: int, T: int):
        self.K = n_arms
        self.T = T
        self.beta_T = log(4.0 * T ** 3)
        self.n = [0] * n_arms
        self.s = [0] * n_arms
        self.rejected: set[int] = set()
        self.t = 0

    def update(self, arm: int, x: int) -> None:
        if arm in self.rejected:
            raise RuntimeError(f"locked-out arm pulled: {arm}")
        self.n[arm] += 1
        self.s[arm] += x
        self.t += 1

    def mean(self, i: int) -> float:
        return self.s[i] / self.n[i] if self.n[i] > 0 else float("nan")

    def rad(self, i: int) -> float:
        return sqrt(self.beta_T / (2.0 * self.n[i])) if self.n[i] > 0 else float("inf")

    def should_reject(self, a: int, b: int) -> bool:
        if self.n[a] == 0 or self.n[b] == 0:
            return False
        return self.mean(a) + self.rad(a) <= self.mean(b) - self.rad(b)

    def check_all(self) -> list[tuple[int, int]]:
        fired: list[tuple[int, int]] = []
        active = [i for i in range(self.K) if i not in self.rejected]
        for a in active:
            for b in active:
                if a == b or a in self.rejected:
                    continue
                if self.should_reject(a, b):
                    self.rejected.add(a)
                    fired.append((a, b))
                    break
        return fired

    def active_arms(self) -> list[int]:
        return [i for i in range(self.K) if i not in self.rejected]

    def status(self) -> dict[str, Any]:
        return {"engine": "hoeffding", "T": self.T, "beta_T": self.beta_T,
                "t": self.t, "n": list(self.n), "s": list(self.s),
                "rejected": sorted(self.rejected)}


def make_audit(engine: str = "glr", **kw: Any) -> AnytimeGLRAudit | HoeffdingAudit:
    """Drop-in factory. engine='glr' -> AnytimeGLRAudit(n_arms, delta, ...);
    engine='hoeffding' -> HoeffdingAudit(n_arms, T). Same downstream interface
    (update / should_reject / check_all / active_arms / status)."""
    if engine == "glr":
        return AnytimeGLRAudit(**kw)
    if engine == "hoeffding":
        return HoeffdingAudit(**kw)
    raise ValueError("engine must be 'glr' or 'hoeffding'")


# ----------------------------------------------------------------------------
# T4.1: calibrated cost quote N_cert — an ESTIMATOR with an empirical
# calibration target (F4), not a theorem. Refusal path included.
# ----------------------------------------------------------------------------

def _ncert_point(mua: float, mub: float, delta: float,
                 family: str = "mixture_envelope", eta: float = 1.1) -> float:
    """Self-consistent point quote: smallest total inspections N (balanced,
    n_a = n_b = N/2) with (N/2)*G_pair(mua,mub) >= beta(N/2, N/2, delta),
    i.e. N >= beta / G_half. Fixed-point iteration (monotone; Lemma INV
    certifies the size). Returns inf when muhat_a >= muhat_b."""
    if not (mua < mub):
        return float("inf")
    gh = G_half(mua, mub)
    if gh <= 0.0:
        return float("inf")
    N = 2.0
    for _ in range(200):
        half = max(N / 2.0, 1.0)
        if family == "stitched":
            beta = threshold_stitched(int(math.ceil(half)), int(math.ceil(half)),
                                      delta, eta)
        else:
            beta = log(1.0 / delta) + log(half) + 2.0 * LN2  # M envelope, balanced
        N_new = beta / gh
        if abs(N_new - N) < 1e-9:
            N = N_new
            break
        N = N_new
    return math.ceil(N)


def n_cert(na: int, sa: int, nb: int, sb: int, delta: float,
           budget: float | None = None, n_boot: int = 2000, seed: int = 0,
           family: str = "mixture_envelope", eta: float = 1.1,
           ci: tuple[float, float] = (0.02, 0.98),
           include_bayes: tuple[float, float] | None = None) -> dict[str, Any]:
    """T4.1 quote at the current audit state.

    Point quote (prompt formula, self-consistent threshold):
        N_cert = ceil( beta(t_hat, delta) / G_half(muhat_a, muhat_b) ),
    total forced inspections at balanced allocation. Parametric bootstrap
    interval: resample S_i ~ Bin(n_i, muhat_i), recompute; percentile ci.
    Degenerate resamples (muhat_a >= muhat_b) yield inf and are RETAINED
    (an infinite upper end is informative, not an error).

    CURRENCY: fixed-mu frequentist. Calibration status: the ">= 90% coverage
    on the pre-registered grid" is an EMPIRICAL claim adjudicated by F4;
    failure falsifies the quoting rule (widen the interval), never T3.1.
    F4 executed 2026-07-07 (reports/glr_audit_f3/): the original (0.05, 0.95)
    percentiles pass the 85% kill threshold on every cell (coverage among
    issued quotes 0.853-0.951) but MISS the 90% target at mu=(0.4, 0.6);
    the pre-registered widening to (0.02, 0.98) -- now the default -- gives
    0.92-0.98 on every cell, meeting the target with margin.

    Refusal path: if the point quote exceeds `budget`, status =
    "UncertifiedNeedsMoreHorizon" with shortfall attached. If the pair is not
    separated, status = "NotSeparated" (quote inf; any finite budget refused
    with shortfall inf).

    include_bayes=(v, c): also attach the SEPARATE Bayesian-predictive figure
    from predictive_reopen_probability(v, c) under its own key — the two
    currencies are never combined into one number.
    """
    if na <= 0 or nb <= 0:
        raise ValueError("both arms need >= 1 observation")
    mua, mub = sa / float(na), sb / float(nb)
    point = _ncert_point(mua, mub, delta, family, eta)

    import random as _random

    # This seeded generator drives reproducible bootstrap resampling, not cryptography.
    rng = _random.Random(seed)  # noqa: S311  # nosec B311
    boots, degenerate = [], 0
    for _ in range(n_boot):
        sa_r = sum(1 for _ in range(na) if rng.random() < mua)
        sb_r = sum(1 for _ in range(nb) if rng.random() < mub)
        q = _ncert_point(sa_r / na, sb_r / nb, delta, family, eta)
        if math.isinf(q):
            degenerate += 1
        boots.append(q)
    boots.sort()
    lo = boots[max(0, min(n_boot - 1, int(math.floor(ci[0] * n_boot))))]
    hi = boots[max(0, min(n_boot - 1, int(math.floor(ci[1] * n_boot))))]

    if math.isinf(point):
        status, shortfall = "NotSeparated", (float("inf") if budget is not None else None)
    elif budget is not None and point > budget:
        status, shortfall = "UncertifiedNeedsMoreHorizon", point - budget
    else:
        status, shortfall = "Certifiable", 0 if budget is not None else None

    out = {"quote": point, "ci": (lo, hi), "ci_levels": ci, "status": status,
           "shortfall": shortfall, "delta": delta, "family": family,
           "n_boot": n_boot, "n_boot_degenerate": degenerate,
           "currency": "frequentist",
           "calibration": "empirical target (F4): coverage >= 90% on grid; "
                          "per-cell < 85% falsifies the QUOTING RULE only"}
    if include_bayes is not None:
        v, c = include_bayes
        out["bayes_companion"] = predictive_reopen_probability(v, c)
    return out


# ----------------------------------------------------------------------------
# §9.4 Bayesian-predictive companion (currency: BAYESIAN-PREDICTIVE; proved
# Lemma B in docs/math/anytime_glr_audit_family_m.txt). Never blended with the frequentist quote.
# ----------------------------------------------------------------------------

def gate_value_beta(a: int, b: int, v: float) -> float:
    """E[(X - v)^+] under Beta(a,b) for the three proved cases (closed form)."""
    if (a, b) == (1, 2):
        return (1.0 - v) ** 3 / 3.0
    if (a, b) == (2, 2):
        return (1.0 - v) ** 3 * (1.0 + v) / 2.0
    if (a, b) == (1, 3):
        return (1.0 - v) ** 4 / 4.0
    raise ValueError("closed forms provided for Beta(1,2)->{(2,2),(1,3)} only")


def predictive_reopen_probability(v: float, c: float) -> dict[str, Any]:
    """P(one mandated inspection restores gate eligibility), candidate Beta(1,2),
    gate: eligible iff E[(X - v)^+] >= c.  CURRENCY: BAYESIAN-PREDICTIVE.

    Proved (docs/math/anytime_glr_audit_family_m.txt Lemma B): if
    (1-v)^3/3 < c <= (1-v)^3 (1+v)/2, the
    probability is exactly 1/3 (y=1 reopens via Beta(2,2); y=0 -> Beta(1,3)
    never reopens since (1-v)^4/4 < (1-v)^3/3 < c). General value returned
    outside the window from the same closed forms.
    """
    if not (0.0 <= v < 1.0):
        raise ValueError("v in [0,1)")
    e12 = gate_value_beta(1, 2, v)
    e22 = gate_value_beta(2, 2, v)
    e13 = gate_value_beta(1, 3, v)
    already = c <= e12
    p = (1.0 / 3.0) * (1.0 if c <= e22 else 0.0) \
        + (2.0 / 3.0) * (1.0 if c <= e13 else 0.0)
    return {"p_reopen_one_inspection": p, "currency": "bayesian-predictive",
            "already_eligible": already, "window": (e12, e22),
            "in_proved_window": (e12 < c <= e22),
            "posterior_values": {"Beta(2,2)": e22, "Beta(1,3)": e13}}


# ----------------------------------------------------------------------------
# Clopper–Pearson one-sided UPPER bound (log-space; used by F3a adjudication)
# ----------------------------------------------------------------------------

def _logsumexp(xs: list[float]) -> float:
    m = max(xs)
    if m == float("-inf"):
        return m
    return m + log(sum(exp(x - m) for x in xs))


def _log_binom_cdf(x: int, n: int, p: float) -> float:
    """ln P(Bin(n,p) <= x), exact in log-space."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 0.0 if x >= n else float("-inf")
    lp, l1p = log(p), log(1.0 - p)
    terms = [lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)
             + k * lp + (n - k) * l1p for k in range(0, x + 1)]
    return _logsumexp(terms)


def clopper_pearson_upper(x: int, n: int, alpha: float) -> float:
    """One-sided (1-alpha) UPPER confidence bound for a binomial proportion:
    the U solving P(Bin(n,U) <= x) = alpha (U=1 if x=n). Closed form at x=0:
    U = 1 - alpha^(1/n) (used as a unit test). Bisection in log-space."""
    if x >= n:
        return 1.0
    la = log(alpha)
    lo, hi = x / float(n), 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if _log_binom_cdf(x, n, mid) > la:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


# ----------------------------------------------------------------------------
# Arithmetic demo only (no simulation is executed here, per the protocol).
