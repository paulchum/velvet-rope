"""
drift_expiry.py -- reference implementation for windowed delta-safe lockout
certificates under drift (assembly of Lemma C + Lemma D+ into T1.1/T1.2).

Canonical source: docs/math/drift_expiry_certificates.txt. Ported verbatim from the
external drift-expiry hardened package (git 324197a, audited 2026-07-07);
requires the optional [drift] dependency extra (numpy, scipy).

Conventions (matching the proofs):
  * Weak gate: gate-eligible iff N^a >= c; rescue = {N^a >= c} or {a is host},
    evaluated on start-of-round states; host = argmax posterior mean with
    deterministic lowest-index tie-break.
  * Probability scale end to end: the certification test is
        exp(-sum_{b in S_W} I_b(r_c + rho*W)) <= delta
    (threshold delta directly; NO c*delta -- that conversion belongs to the
    value-scale/Ville route, not used here).
  * Certified numerical directions (all error pushed toward refusal):
      - rate_I_lower UNDERSHOOTS I: it takes a sup over finitely many lambda
        against a rigorous UPPER bound on E e^{-lambda*theta} (left-endpoint
        cell majorization + a phantom cell covering any underflowed mass),
        plus the Hoeffding floor 2(m-u)^2. Undershooting I shrinks the
        exponent, ENLARGES the certified tail bound, converts passes to
        refusals and shortens T* -- never unsound.
      - z_floor is padded UPWARD (+1e-12): raises r_c, raises the rate
        argument, lowers I -- conservative.
  * Non-separated eligible anchors contribute exactly 0 to the exponent
    (rate_I_lower(u) == 0.0 for u >= m), so the set-valued dependence of
    S_W on W (the T*-0 collapse) needs no branching.
  * Shape eligibility min(alpha,beta) >= 1 is inherited from Lemma D+ and is
    NOT optional FOR rho > 0. Ineligible anchors are dropped (conservative by
    Lemma S) and ALWAYS disclosed in the verdict. Standard-start posteriors
    descended from Beta(1,1) by integer counting are automatically eligible;
    the condition binds only fractional-shape warm starts. At rho == 0 the
    certificate does not invoke D+ at all: it reduces EXACTLY to the
    stationary product tail (K2; equivalently S4 at delta = 0, exact
    conjugacy for ALL shapes), so the stationary exponent is computed over
    ALL separated anchors, unfiltered, and nothing is dropped.
  * All quantities are bookkeeping quantities; every windowed number is a
    certified BOUND, Bayesian-predictive at issue time under the stated model.
    No fixed-mu claim is made anywhere in this module.
  * Raise-vs-refuse line (issue_verdict). STRUCTURALLY MALFORMED INPUT --
    K < 2, non-numeric posterior entries, c <= 0, delta not in (0,1),
    rho < 0, non-numeric W -- RAISES (ValueError/TypeError): the caller broke
    the API type contract. EXPECTED-INVALID REQUESTS -- non-integer W under
    rho > 0, W < 0, W < 1 under rho > 0 (no zero-window mode), W > T_hat,
    delta_tail outside 0 < delta_tail <= delta, route != "A" -- return
    FIRST-CLASS REFUSAL Verdicts with machine-readable reason_code: these are
    well-formed questions whose certified answer is a refusal. Route "A"
    (ordinary Beta counting) is the only certifying route; Route B /
    discounted posteriors must never certify.
  * Horizon naming: the computed exponent LOWER-bounds the true rate, so the
    computed horizon LOWER-bounds the true T*; the Verdict reports it as
    T_hat with the documented relation T_hat <= T*. Past-T_hat refusals say
    the CONSERVATIVE certificate expires, never that the true tail exceeds
    tolerance.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any, cast

import numpy as np
from scipy.special import betainc, logsumexp  # type: ignore[import-untyped]
from scipy.stats import beta as _beta_dist  # type: ignore[import-untyped]

# ----------------------------- statuses ------------------------------------
CERTIFIED_SAFE = "CertifiedSafe"
CERTIFIED_NOT_SAFE = "CertifiedNotSafe"
UNCERT_MORE_HORIZON = "UncertifiedNeedsMoreHorizon"
UNCERT_REFINE = "UncertifiedNeedsRefinement"
REQUIRED_INSPECTION = "RequiredInspection"
EXPIRED = "Expired"
RECERTIFIED = "Recertified"

REASON_NO_ELIGIBLE_SHAPE = "no eligible anchor (shape < 1)"

# Machine-readable reason codes (Verdict.reason_code). Prose stays in .reason.
RC_SUB_ONE_HORIZON = "sub_one_round_horizon"        # B1: T_hat < 1 under rho > 0
RC_W_BELOW_ONE = "window_below_one_under_drift"     # requested W < 1, rho > 0
RC_W_NEGATIVE = "window_negative"                   # requested W < 0
RC_W_NONINTEGER = "window_not_integer_under_drift"  # requested W not an integer, rho > 0
RC_W_PAST_THAT = "window_exceeds_T_hat"             # requested W > T_hat
RC_DELTA_TAIL_INVALID = "delta_tail_invalid"        # not 0 < delta_tail <= delta
RC_ROUTE_NOT_A = "route_not_A"                      # Route B / discounted posteriors
RC_NO_ELIGIBLE = "no_eligible_shape"
RC_NO_SEPARATED = "no_separated_anchor"
RC_DEGENERATE_W0 = "tail_exceeds_delta_tail_at_W0"
RC_PRE_HOST = "precondition_candidate_is_host"
RC_PRE_GATE = "precondition_gate_eligible"
RC_EXPIRED = "expired"


class AuditError(ValueError):
    """Raised when a Lemma D+ invocation violates the interface checklist."""


# --------------------------- Beta utilities --------------------------------
def beta_mean(a: float, b: float) -> float:
    return a / (a + b)


def beta_sf(a: float, b: float, v: float) -> float:
    """P(theta > v) for theta ~ Beta(a,b)."""
    if v <= 0.0:
        return 1.0
    if v >= 1.0:
        return 0.0
    return float(1.0 - betainc(a, b, v))


def psi(a: float, b: float, v: float) -> float:
    """psi(Beta(a,b), v) = E[(theta - v)^+].

    Closed form: m * S_{a+1,b}(v) - v * S_{a,b}(v) (regularized incomplete
    beta). Linear extension psi = m - v for v < 0. Nonincreasing and
    1-Lipschitz in v; psi(0) = m, psi(1) = 0.
    """
    m = beta_mean(a, b)
    if v <= 0.0:
        return m - v
    if v >= 1.0:
        return 0.0
    return m * beta_sf(a + 1.0, b, v) - v * beta_sf(a, b, v)


def z_floor(a: float, b: float, c: float, iters: int = 200) -> float:
    """z_c = sup{v : psi(Beta(a,b), v) >= c}.

    Returns m - c (< 0) when c > m (linear branch; the gate channel then
    cannot fire on v in (0,1)). Bisection otherwise; padded UPWARD by 1e-12,
    which raises r_c and is therefore conservative.
    """
    if c <= 0.0:
        raise ValueError("gate height c must be > 0")
    m = beta_mean(a, b)
    if c > m:
        return m - c
    lo, hi = 0.0, 1.0
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        if psi(a, b, mid) >= c:
            lo = mid
        else:
            hi = mid
    return min(1.0, lo + 1e-12)


def protected_floor(post: Sequence[tuple[float, float]], cand: int, c: float) -> float:
    """r_c(x,a) = max(z_c(Pi_a), m_a). Lies in (0,1) for a proper Beta."""
    a_, b_ = post[cand]
    r = max(z_floor(a_, b_, c), beta_mean(a_, b_))
    return min(max(r, 1e-15), 1.0 - 1e-15)


def V_excl(post: Sequence[tuple[float, float]], cand: int) -> float:
    """Candidate-excluded baseline V^a(x) = max_{b != a} m_b(x)."""
    if len(post) < 2:
        raise ValueError("need K >= 2 arms")
    return max(beta_mean(a, b) for i, (a, b) in enumerate(post) if i != cand)


def N_cert(post: Sequence[tuple[float, float]], cand: int) -> float:
    """Moving certificate N^a(x) = psi(Pi_a, V^a(x))."""
    a_, b_ = post[cand]
    return psi(a_, b_, V_excl(post, cand))


# ----------------- certified lower bound on the rate I ---------------------
_GRID_CACHE: dict[tuple[float, float], tuple[np.ndarray, np.ndarray]] = {}


def _support_cells(a: float, b: float,
                   n_quant: int = 2048, n_unif: int = 2048,
                   n_geo: int = 48) -> tuple[np.ndarray, np.ndarray]:
    """Partition of [0,1] adapted to Beta(a,b): equal-probability quantile
    cells + uniform cells + geometric refinement toward 0. Returns
    (left endpoints, log cell masses), including a phantom cell at 0 whose
    mass covers any dropped/underflowed probability, so the left-endpoint
    majorization remains a rigorous upper bound."""
    key = (float(a), float(b))
    if key in _GRID_CACHE:
        return _GRID_CACHE[key]
    qs = _beta_dist.ppf(np.linspace(0.0, 1.0, n_quant + 1), a, b)
    us = np.linspace(0.0, 1.0, n_unif + 1)
    pos = qs[qs > 0]
    q1 = float(pos.min()) if pos.size else 1e-6
    geo = q1 * np.power(2.0, -np.arange(1, n_geo + 1, dtype=float))
    pts = np.unique(np.clip(np.concatenate([qs, us, geo, [0.0, 1.0]]), 0.0, 1.0))
    F = betainc(a, b, pts)
    p = np.diff(F)
    left = pts[:-1]
    mask = p > 0.0
    dropped = max(0.0, 1.0 - float(p[mask].sum()))
    lefts = np.concatenate([[0.0], left[mask]])
    masses = np.concatenate([[max(dropped, 1e-300)], p[mask]])
    out = (lefts, np.log(masses))
    _GRID_CACHE[key] = out
    return out


def log_mgf_upper(a: float, b: float, lam: float | np.ndarray) -> np.ndarray:
    """Rigorous upper bound on log E e^{-lam*theta}: on each cell
    [l_i, r_i], e^{-lam*theta} <= e^{-lam*l_i}; sum p_i e^{-lam*l_i} in
    log space (logsumexp). Valid for every lam >= 0."""
    lefts, logp = _support_cells(a, b)
    lam = np.atleast_1d(np.asarray(lam, dtype=float))
    return cast(np.ndarray,
                logsumexp(logp[None, :] - lam[:, None] * lefts[None, :], axis=1))


def _rate_I_lower_grid(a: float, b: float, u: float) -> float:
    """The original grid-majorization lower rate (see rate_I_lower)."""
    m = beta_mean(a, b)
    if u >= m:
        return 0.0
    u = max(u, 1e-300)
    lams = np.geomspace(1e-3, 1e7, 141)
    vals = -lams * u - log_mgf_upper(a, b, lams)
    k = int(np.argmax(vals))
    lo = lams[max(k - 1, 0)]
    hi = lams[min(k + 1, len(lams) - 1)]
    lams2 = np.geomspace(lo, hi, 81)
    vals2 = -lams2 * u - log_mgf_upper(a, b, lams2)
    best = max(float(vals.max()), float(vals2.max()))
    hoeff = 2.0 * (m - u) ** 2
    return max(best, hoeff, 0.0)


def rate_I_lower(a: float, b: float, u: float) -> float:
    """Certified-conservative LOWER bound on I_{a,b}(u).

    Returns exactly 0.0 when u >= m (true value: sup at lambda=0), which
    implements the T*-0 collapse. For u < m: sup over a geometric lambda
    sweep with local refinement of [-lam*u - log_mgf_upper], floored by
    Hoeffding: log E e^{-lam*theta} <= -lam*m + lam^2/8 for theta in [0,1],
    hence I(u) >= 2 (m-u)^2. Undershooting I is the SAFE direction: the
    exponent shrinks, the certified tail bound grows, passes become refusals
    and T* shortens -- never the reverse.

    A-3 (Phase A): when the grid arm sits near its saturation cap
    (concentrated anchors; GAPS G7), the certified Kummer-series bracket
    (rate_I_bracket) is consulted and the MAX of the two lower brackets is
    returned -- still a certified lower bound, no longer saturating. The
    gate keeps moderate anchors on the cheap exact-enough grid arm."""
    base = _rate_I_lower_grid(a, b, u)
    if base < _A3_SERIES_THRESHOLD or u >= beta_mean(a, b):
        return base
    I_lo, _ = rate_I_bracket(a, b, u, want_upper=False)
    return max(base, I_lo)


# ------------- A-3: certified two-sided MGF bracket (kills saturation) ------
# E[e^{-lam*theta}] for theta ~ Beta(a,b) equals M(a; a+b; -lam)
# = e^{-lam} * M(b; a+b; lam) (Kummer transformation). The transformed series
# sum_k (b)_k/(a+b)_k lam^k/k! has ALL-POSITIVE terms: partial sums are
# rigorous LOWER brackets, and since the term ratio t_{k+1}/t_k =
# (b+k) lam / ((a+b+k)(k+1)) <= lam/(N+1) =: rho < 1 for k >= N >= 2 lam,
# the tail is <= t_N * rho/(1-rho) -- a rigorous UPPER bracket. Everything
# in log space (cumsum of log ratios + logsumexp). [MATH mod IEEE, G7.]
_A3_NCAP = 20_000_000     # series length cap; beyond it return None (fallback)


def log_mgf_bracket(a: float, b: float, lam: float) -> tuple[float, float] | None:
    """Rigorous (lo, hi) bracket on log E[e^{-lam*theta}], theta ~ Beta(a,b),
    lam >= 0; None when the series would exceed the length cap."""
    if lam <= 0.0:
        return 0.0, 0.0
    N = int(max(64, 2.0 * lam + 64))
    if N > _A3_NCAP:
        return None
    k = np.arange(N, dtype=float)
    logr = (np.log(b + k) + math.log(lam)
            - np.log(a + b + k) - np.log1p(k))
    logt = np.concatenate([[0.0], np.cumsum(logr)])   # log t_0 .. log t_N
    S = float(logsumexp(logt))
    rho = lam / (N + 1)                               # >= t_{k+1}/t_k, k >= N
    log_rem = float(logt[-1]) + math.log(rho) - math.log1p(-rho)
    return -lam + S, -lam + float(np.logaddexp(S, log_rem))


def rate_I_bracket(a: float, b: float, u: float,
                   rel_tol: float = 1e-9,
                   want_upper: bool = True) -> tuple[float, float]:
    """Certified bracket (I_lo, I_hi) on I_{a,b}(u) via the series MGF
    bracket. I_lo: sup over evaluated lam of [-lam*u - mgf_hi(lam)] -- every
    evaluation is individually valid. I_hi: phi is concave with
    phi'(0) = m - u and phi' = T(lam) - u where the tilted mean T is
    nonincreasing (T' = -Var_tilt <= 0), so (i) on [x_i, x_{i+1}] a secant
    slope bound from the LEFT interval upper-bounds phi'(x_i+), giving
    sup phi <= phi_hi(x_i) + max(0, s_up) * dx; (ii) past Lambda with
    T_hi(Lambda) < u, phi is decreasing and contributes nothing new.
    Exact (0, 0) for u >= m. Falls back to (grid rate, inf) if the series
    cap is hit before the peak is bracketed."""
    m = beta_mean(a, b)
    if u >= m:
        return 0.0, 0.0
    u = max(u, 1e-300)

    memo: dict[float, tuple[float, float] | None] = {}

    def pair(lam: float) -> tuple[float, float] | None:
        if lam not in memo:
            br = log_mgf_bracket(a, b, lam)
            memo[lam] = None if br is None else \
                (-lam * u - br[1], -lam * u - br[0])   # (phi_lo, phi_hi)
        return memo[lam]

    # Fast path (I_lo only): seed the concave search at the Gaussian-tilt
    # estimate lam0 ~ (m-u)(a+b+1)/(m(1-m)) and golden-refine around it.
    # ANY evaluated lambda yields a valid lower bound, so a misplaced seed
    # only weakens (never breaks) I_lo; the full geometric sweep remains the
    # backup and the want_upper path.
    lams: list[float] | np.ndarray
    if not want_upper:
        lam0 = max(1e-2, (m - u) * (a + b + 1.0) / max(m * (1.0 - m), 1e-12))
        lams = [lam0 / 8.0, lam0, 8.0 * lam0]
    else:
        lams = np.geomspace(1e-2, 3e7, 120)
    vals = []
    best_seen = -math.inf
    decline = 0
    for lam in lams:
        p = pair(lam)
        if p is None:
            break
        vals.append((p[0], lam))
        # phi is concave: once well past the peak, stop paying for huge-lam
        # series (only I_lo validity matters, and every visited lam is valid)
        if p[0] > best_seen:
            best_seen = p[0]
            decline = 0
        else:
            decline += 1
            if decline >= 3 and p[0] < best_seen - max(2.0, 0.2 * abs(best_seen)):
                break
    if not vals:
        return max(_rate_I_lower_grid(a, b, u), 0.0), math.inf
    vals_arr = [v for v, _ in vals]
    j = int(np.argmax(vals_arr))
    if j == len(vals) - 1 and len(vals) < len(lams):
        # peak beyond the series cap: keep the certified lower, no upper
        return max(vals_arr[j], _rate_I_lower_grid(a, b, u), 0.0), math.inf
    lam_hat = vals[j][1]
    if not want_upper and j == len(vals) - 1:
        # endpoint still rising: double outward until the peak is passed
        while lam_hat < 3e7:
            p = pair(min(2.0 * lam_hat, 3e7))
            if p is None:
                break
            vals.append((p[0], min(2.0 * lam_hat, 3e7)))
            if p[0] <= vals_arr[-1]:
                break
            vals_arr.append(p[0])
            lam_hat = min(2.0 * lam_hat, 3e7)
    # golden refinement inside [lam_hat/2, 2*lam_hat]
    gr = (math.sqrt(5.0) - 1.0) / 2.0
    x1, x2 = lam_hat / 2.0, min(2.0 * lam_hat, 3e7)
    for _ in range(60):
        if (x2 - x1) <= rel_tol * x2:
            break
        c, d = x2 - gr * (x2 - x1), x1 + gr * (x2 - x1)
        pc, pd = pair(c), pair(d)
        if pc is None or pd is None:
            break
        if pc[0] > pd[0]:
            x2 = d
        else:
            x1 = c
    lam_best = 0.5 * (x1 + x2)
    # pair(lam_hat) was evaluated non-None in the sweep above and is memoized
    p_best = pair(lam_best) or cast("tuple[float, float]", pair(lam_hat))
    I_lo = max(max(v for v, _ in vals), p_best[0],
               _rate_I_lower_grid(a, b, u), 0.0)
    if not want_upper:
        return I_lo, math.inf

    # ---- certified upper: secant-slope mesh over [0, Lambda] + monotone tail
    Lam = min(4.0 * lam_hat, 3e7)
    # tail certificate: T(lam) nonincreasing; T_hi(Lam) < u kills phi' beyond
    def tilted_mean_hi(lam: float) -> float | None:
        num = log_mgf_bracket(a + 1.0, b, lam)   # E_{Beta(a+1,b)} e^{-lam th}
        den = log_mgf_bracket(a, b, lam)
        if num is None or den is None:
            return None
        # T(lam) = m * M(a+1, g+1; -lam)/M(a, g; -lam); the Beta(a+1,b)
        # identity: E[th e^{-lam th}]/E[e^{-lam th}] = m * E_{a+1,b}/E_{a,b}
        return m * math.exp(num[1] - den[0])

    t_hi = tilted_mean_hi(Lam)
    guard = 0
    while (t_hi is None or t_hi >= u) and guard < 20 and Lam < 3e7:
        Lam = min(2.0 * Lam, 3e7)
        t_hi = tilted_mean_hi(Lam)
        guard += 1
    if t_hi is None or t_hi >= u:
        return I_lo, math.inf                     # cannot certify the tail
    mesh = np.unique(np.concatenate([
        [0.0],
        np.geomspace(max(lam_best * 1e-4, 1e-6), Lam, 320),
        np.linspace(max(x1 * 0.98, 1e-6), min(x2 * 1.02, Lam), 80),
    ]))
    ph = []
    for lam in mesh:
        if lam == 0.0:
            ph.append((0.0, 0.0))
            continue
        p = pair(float(lam))
        if p is None:
            return I_lo, math.inf
        ph.append(p)
    I_hi = 0.0
    for i in range(len(mesh) - 1):
        dx = mesh[i + 1] - mesh[i]
        if i == 0:
            s_up = m - u                          # phi'(0) = m - u exactly
        else:
            # phi'(x_i+) <= secant slope on the left interval, computed with
            # bracket endpoints in the safe direction
            s_up = (ph[i][1] - ph[i - 1][0]) / (mesh[i] - mesh[i - 1])
        I_hi = max(I_hi, ph[i][1] + max(0.0, s_up) * dx)
    I_hi = max(I_hi, ph[-1][1])
    return I_lo, max(I_lo, I_hi)


_A3_SERIES_THRESHOLD = 6.0


# -------------------- eligibility, exponent, D+ audit ----------------------
def split_shape_eligible(post: Sequence[tuple[float, float]],
                         cand: int) -> tuple[list[int], list[int]]:
    """Both S_W conditions live here and in the rate: this returns the
    shape-eligible indices (min(alpha,beta) >= 1, b != a) and the dropped
    ones; the separation condition m_b > r_c + rho*W is enforced by the rate
    itself (0 for u >= m)."""
    elig: list[int] = []
    dropped: list[int] = []
    for i, (a, b) in enumerate(post):
        if i == cand:
            continue
        (elig if min(a, b) >= 1.0 else dropped).append(i)
    return elig, dropped


def anchors_included(post: Sequence[tuple[float, float]], cand: int,
                     rho: float) -> tuple[list[int], list[int]]:
    """Anchor inclusion is drift-aware (B4).

    rho > 0: the certificate invokes Lemma D+, whose hypothesis
    min(alpha, beta) >= 1 is NOT optional; sub-shape anchors are dropped
    (conservative by Lemma S) and always disclosed.
    rho == 0: the certificate does not invoke D+ at all -- it reduces EXACTLY
    to the source package's stationary product tail (K2; equivalently D+'s
    S4 at delta = 0, which is exact conjugacy for ALL shapes alpha, beta > 0;
    see the rho = 0 recovery in lemma_D_plus_writeup.md S6 and (KS) in
    lemma_D_minus_writeup.md S0). The stationary exponent is therefore
    computed over ALL non-candidate anchors, unfiltered, and nothing is
    dropped. Separation is still enforced by the rate itself (0 for u >= m).
    """
    if rho == 0.0:
        return [i for i in range(len(post)) if i != cand], []
    return split_shape_eligible(post, cand)


def audit_dplus_invocation(anchors: Sequence[tuple[float, float]],
                           r: float, rho: float, W: float | np.integer) -> bool:
    """Enforce the Lemma D+ interface checklist on an invocation.

    anchors: the (alpha,beta) pairs of the anchor set A actually passed to
    D+; r: the floor; rho: drift bound; W: window in rounds of the
    one-pull-per-round clock (nonnegative integer).
    """
    if len(anchors) == 0:
        raise AuditError("D+ invoked with empty anchor set")
    for (a, b) in anchors:
        if not (np.isfinite(a) and np.isfinite(b) and a > 0 and b > 0):
            raise AuditError("anchor is not a proper Beta posterior")
        # Shape hypothesis is D+'s (rho > 0). At rho == 0 the invocation is
        # the exact stationary reduction (K2 / S4 at delta = 0), valid for
        # ALL shapes alpha, beta > 0 -- no shape check applies there.
        if rho > 0.0 and min(a, b) < 1.0:
            raise AuditError("shape condition violated: min(alpha,beta) < 1")
    if not (0.0 <= r < 1.0):
        raise AuditError("floor r must lie in [0,1)")
    if rho < 0.0:
        raise AuditError("rho must be >= 0")
    if not (isinstance(W, (int, np.integer)) and W >= 0):
        raise AuditError("W must be a nonnegative integer (one-pull-per-round clock)")
    return True


def windowed_exponent(post: Sequence[tuple[float, float]], cand: int, r_c: float,
                      rho: float, W: float | int,
                      elig: Sequence[int] | None = None) -> float:
    """E(W) = sum over shape-eligible anchors of I(r_c + rho*W).
    Non-separated anchors contribute exactly 0 (collapse), so this equals the
    sum over S_W. Used with real W inside the bisection. Default inclusion is
    drift-aware (B4): shape-filtered at rho > 0, unfiltered at rho == 0."""
    if elig is None:
        elig, _ = anchors_included(post, cand, rho)
    u = r_c + rho * W
    return sum(rate_I_lower(post[b][0], post[b][1], u) for b in elig)


def windowed_tail(post: Sequence[tuple[float, float]], cand: int, r_c: float,
                  rho: float, W: float | int,
                  elig: Sequence[int] | None = None) -> float:
    """Certified tail bound e^{-E(W)} for integer W; the D+ invocation on the
    separated eligible set S_W is audited first. Empty S_W => bound 1 (the
    exponent is 0), returned without invoking D+. Default inclusion is
    drift-aware (B4): shape-filtered at rho > 0, unfiltered at rho == 0."""
    if elig is None:
        elig, _ = anchors_included(post, cand, rho)
    u = r_c + rho * W
    SW = [b for b in elig if beta_mean(post[b][0], post[b][1]) > u]
    if SW:
        audit_dplus_invocation([post[b] for b in SW], r_c, rho, W)
    return math.exp(-windowed_exponent(post, cand, r_c, rho, W, elig=elig))


# ----------------- Theorem T2: staggered-crossing sharpening ----------------
# CERTIFICATION.md, Phase A: SIM_A(r) subset {sum_b tau_b <= W} pathwise
# (T2-C), tau_b independent (T2-I), tau_b >= n_cross(b) (T2-F), per-time
# crossing cost B_b(m) via binomial KL Chernoff mixed over the prior (T2-B),
# per-anchor tail Phi_b(n) = min(S5 arm, sum of B) (T2-Phi), vertex bound
# (T2-V) and Chernoff composition (T2-X). tail_T2 <= product tail always;
# = 0 when sum n_cross > W; nondecreasing in W. Applied at rho > 0 only
# (the rho = 0 branch keeps the exact stationary reduction untouched).
T2_MCAP = 4096       # B-sum term cap; past it the S5 arm alone is used
_T2_LAMBDAS = np.geomspace(1e-4, 8.0, 48)


def _kl_bernoulli(q: float, p: np.ndarray) -> np.ndarray:
    """kl(q, p) for scalar q in [0,1), vector p in (q, 1); kl(0,p) = -log(1-p)."""
    p = np.asarray(p, dtype=float)
    out: np.ndarray = np.empty_like(p)
    if q <= 0.0:
        return cast(np.ndarray, -np.log1p(-p))
    out = q * (math.log(q) - np.log(p)) + (1.0 - q) * (math.log1p(-q) - np.log1p(-p))
    return out


def n_cross_of(a: float, b: float, r: float) -> int:
    """All-failure downcrossing count (Corollary NV / T2-F). The 1e-12 slack
    UNDER-estimates the floor, which only enlarges T2 budgets -- safe."""
    m = a / (a + b)
    if m <= r:
        return 0
    return max(0, math.ceil(a / r - (a + b) - 1e-12))


def crossing_cost_B_upper(a: float, b: float, r: float, delta: float,
                          ms: np.ndarray) -> np.ndarray:
    """Certified UPPER bound on Q(m_tilde(m) <= r) for each m in ms (T2-B).

    Given theta, S(m) ~ Binomial(m, g(theta)), g(theta) = (theta - delta)^+;
    crossing needs S(m) <= x_m = r(a+b+m) - a. Chernoff: for g > q = x_m/m,
    P <= exp(-m kl(q, g)); else bound 1. The integrand is NONINCREASING in
    theta, so the left-endpoint cell majorization with phantom cell (the
    log_mgf_upper grid) yields a rigorous upper bound on the prior mixture.
    x_m < 0 gives exactly 0. Values are capped at 1. Vectorized over m in
    chunks against the cell grid."""
    lefts, logp = _support_cells(a, b)
    g = np.maximum(lefts - delta, 0.0)
    ms = np.asarray(ms, dtype=int)
    out = np.empty(len(ms), dtype=float)
    x = r * (a + b + ms) - a
    neg = x < 0.0
    zero_m = ms == 0
    out[neg] = 0.0
    out[zero_m & ~neg] = 1.0     # x_0 >= 0 iff prior mean <= r
    todo = np.flatnonzero(~neg & ~zero_m)
    CH = 256
    for j0 in range(0, len(todo), CH):
        idx = todo[j0:j0 + CH]
        m_c = ms[idx].astype(float)[:, None]              # (c,1)
        q_c = np.minimum(1.0, (x[idx] / ms[idx])[:, None])  # (c,1)
        p = g[None, :]                                     # (1,cells)
        mask = p > q_c
        with np.errstate(divide="ignore", invalid="ignore"):
            kl = (np.where(q_c > 0, q_c * (np.log(q_c) - np.log(p)), 0.0)
                  + (1.0 - q_c) * (np.log1p(-q_c) - np.log1p(-p)))
        logh = np.where(mask, -m_c * kl, 0.0)
        vals = logsumexp(logp[None, :] + logh, axis=1)
        out[idx] = np.minimum(1.0, np.exp(vals))
    return out


def staggered_tail(post: Sequence[tuple[float, float]], cand: int, r_c: float,
                   rho: float, W: float | int,
                   elig: Sequence[int] | None = None) -> float:
    """tail_T2(W): certified upper bound on Q(SIM) via Theorem T2 --
    min(product arm, vertex bound T2-V, Chernoff composition T2-X). Valid for
    integer W >= 0 at rho > 0 under T1.1's hypotheses; the caller keeps the
    rho = 0 branch on the exact stationary reduction. Never exceeds the
    product tail; exactly 0 when sum n_cross > W. Anchors whose B-window
    exceeds T2_MCAP terms fall back to the S5 arm alone (valid,
    conservative)."""
    if elig is None:
        elig, _ = anchors_included(post, cand, rho)
    W = int(W)
    delta = rho * W
    u = r_c + delta
    anchors = [(post[b][0], post[b][1]) for b in elig]
    if not anchors:
        return 1.0
    Is = [rate_I_lower(a, b, u) for (a, b) in anchors]
    product = math.exp(-sum(Is))
    ncs = [n_cross_of(a, b, r_c) for (a, b) in anchors]
    N_tot = sum(ncs)
    if N_tot > W:
        return 0.0
    s5 = [math.exp(-rate) for rate in Is]
    # per-anchor B arrays over m in [nc, min(W, nc + T2_MCAP)], shared by
    # both bounds; cumsum gives every needed prefix sum; identical anchors
    # (same shape pair) share one computation
    csums = []
    _memo: dict[tuple[float, float], tuple[np.ndarray, np.ndarray]] = {}
    for (a, b), nc in zip(anchors, ncs, strict=True):
        key = (a, b)
        if key not in _memo:
            m_hi = min(W, nc + T2_MCAP)
            Bs = crossing_cost_B_upper(a, b, r_c, delta,
                                       np.arange(nc, m_hi + 1))
            _memo[key] = (np.cumsum(Bs), Bs)
        csums.append(_memo[key])
    # vertex bound (T2-V)
    vertex = 1.0
    for (_a, _b), nc, s, (cs, _) in zip(anchors, ncs, s5, csums, strict=True):
        budget = W - (N_tot - nc)
        if budget < nc:
            vertex = 0.0
            break
        if budget - nc >= len(cs):        # window exceeds the computed cap
            phi = s
        else:
            phi = min(s, float(cs[budget - nc]))
        vertex *= phi
    # Chernoff composition (T2-X); valid per lambda, min over the grid;
    # requires the full B-window for every anchor, else skip (product holds)
    chern = product
    if all(W - nc < len(cs) + 1 and W - nc <= T2_MCAP
           for nc, (cs, _) in zip(ncs, csums, strict=True)):
        for lam in _T2_LAMBDAS:
            log_bound = lam * W
            dead = False
            for nc, s, (_, Bs) in zip(ncs, s5, csums, strict=True):
                ms = np.arange(nc, W + 1)
                arm1 = float(np.sum(np.exp(-lam * ms) * Bs[:W - nc + 1]))
                arm2 = math.exp(-lam * nc) * s
                psi_b = min(arm1, arm2)
                if psi_b <= 0.0:
                    dead = True
                    break
                log_bound += math.log(psi_b)
            if dead:
                chern = 0.0
                break
            chern = min(chern, math.exp(min(log_bound, 0.0)))
    return min(product, vertex, chern)


def windowed_tail_T2(post: Sequence[tuple[float, float]], cand: int, r_c: float,
                     rho: float, W: float | int,
                     elig: Sequence[int] | None = None) -> float:
    """Certified tail under Theorem T2: min(product tail, tail_T2). The D+
    audit surface is the product path's (T2's S5 citations are on the same
    anchors; its remaining ingredients are shape-free). rho = 0 keeps the
    exact stationary reduction untouched."""
    base = windowed_tail(post, cand, r_c, rho, W, elig=elig)
    if rho == 0.0:
        return base
    return min(base, staggered_tail(post, cand, r_c, rho, int(W), elig=elig))


def expiry_horizon_That_T2(post: Sequence[tuple[float, float]], cand: int,
                           r_c: float, rho: float,
                           delta_tail: float) -> float | None:
    """T_hat under the T2-sharpened tail: max{W in N : tail_T2(W) <=
    delta_tail}. tail_T2 is nondecreasing in W (Theorem T2(iii)), so integer
    exponential search + bisection is valid. Always >= the product T_hat
    (tail_T2 <= product tail). rho = 0 delegates to the stationary branch."""
    if rho == 0.0:
        return expiry_horizon_That(post, cand, r_c, rho, delta_tail)
    elig, _ = anchors_included(post, cand, rho)
    if not elig:
        return None

    def ok(Wi: int) -> bool:
        return windowed_tail_T2(post, cand, r_c, rho, Wi, elig=elig) <= delta_tail

    base = expiry_horizon_That(post, cand, r_c, rho, delta_tail)
    lo = int(base) if (base is not None and math.isfinite(base)) else 0
    if not ok(lo):
        # numerical guard: tail_T2 <= product tail makes this unreachable
        # when the product T_hat exists; scan down for safety
        while lo > 0 and not ok(lo):
            lo -= 1
        return float(lo) if ok(lo) else None
    m_max = max(beta_mean(post[b][0], post[b][1]) for b in elig)
    if m_max <= r_c:
        return None if base is None else base
    # Rigorous ceiling: at rho*W >= 1 the envelope floor g == 0, so every
    # B(m >= n_cross) = 1, s5 = 1, and tail_T2 = 1 > delta_tail. (The
    # product's separation ceiling (m_max - r_c)/rho does NOT bound the T2
    # arms: NV counting and the walk costs live at the crossing line r, not
    # u, and stay informative past u-separation.)
    W_ceil = int(1.0 / rho) + 2
    hi = max(lo, 1)
    while hi < W_ceil and ok(hi):
        hi = min(W_ceil, 2 * hi)
    if ok(hi):
        return float(hi)                        # ceiling reached while valid
    # invariant: ok(lo), not ok(hi)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid):
            lo = mid
        else:
            hi = mid
    return float(lo)


# ------------------------------- T* ----------------------------------------
def expiry_horizon_That(post: Sequence[tuple[float, float]], cand: int,
                        r_c: float, rho: float,
                        delta_tail: float) -> float | None:
    """T_hat = max{W in N : E(W) >= log(1/delta_tail)} on the CERTIFIED
    (conservative) exponent E. Because E lower-bounds the true windowed rate
    sum, T_hat lower-bounds the true expiry horizon: T_hat <= T* (B5).

    Returns None when undefined (E(0) < L: refuse, degenerate window);
    math.inf when rho == 0 and E(0) >= L (stationary certificate).
    Bisection is valid: E is continuous, nonincreasing, strictly decreasing
    where positive, and vanishes past (max eligible mean - r_c)/rho. The
    set-valued dependence of S_W is absorbed by the collapse (rates are 0
    exactly where separation fails)."""
    L = math.log(1.0 / delta_tail)
    elig, _ = anchors_included(post, cand, rho)
    if not elig:
        return None
    E0 = windowed_exponent(post, cand, r_c, rho, 0, elig=elig)
    if E0 < L:
        return None
    if rho == 0.0:
        return math.inf
    m_max = max(beta_mean(post[b][0], post[b][1]) for b in elig)
    if m_max <= r_c:
        return None  # unreachable given E0 >= L > 0, kept for safety
    lo, hi = 0.0, (m_max - r_c) / rho + 1.0  # E(hi) = 0 < L
    for _ in range(200):
        if hi - lo <= 0.25:
            break
        mid = 0.5 * (lo + hi)
        if windowed_exponent(post, cand, r_c, rho, mid, elig=elig) >= L:
            lo = mid
        else:
            hi = mid
    k = int(math.floor(hi))
    while k >= 0:
        if windowed_exponent(post, cand, r_c, rho, k, elig=elig) >= L:
            return k
        k -= 1
    return None  # unreachable: E(0) >= L guarantees k = 0 passes


# Backward-compatible alias (B5): the historical name; the returned value is
# the conservative T_hat <= true T*.
expiry_horizon_Tstar = expiry_horizon_That


# ------------------------------ verdicts -----------------------------------
@dataclass(frozen=True)
class Verdict:
    status: str
    candidate: int
    c: float
    delta: float
    rho: float
    W: float | None                # certified window (int; inf when rho=0)
    issue_time: float
    expiry_time: float | None      # issue_time + W; None if no certificate
    dropped_anchors: tuple[tuple[int, float, float], ...]
                                      # ((idx, alpha, beta), ...) -- ALWAYS disclosed
    eligible_anchors: tuple[int, ...]  # shape-eligible anchor indices
    protected_floor: float | None
    tail_bound: float | None       # certified e^{-E(W)} for the issued W
    T_hat: float | None            # REPORTED conservative horizon; the
                                      # computed exponent lower-bounds the true
                                      # rate, so T_hat <= true T* (B5)
    reason: str = ""
    reason_code: str = ""             # machine-readable RC_* code
    delta_tail: float | None = None  # tail budget; T_hat computed from it;
                                        # BOTH delta and delta_tail are quoted
    sharpening: str = "product"         # tail machinery: "product" (T1.1) or
                                        # "T2" (Theorem T2, Phase A): T2 is
                                        # min(product, staggered) and never
                                        # exceeds the product tail
    tail_bound_product: float | None = None  # the T1.1 product tail at the
                                        # issued W, quoted alongside any
                                        # sharpened bound for disclosure

    @property
    def T_star(self) -> float | None:
        """Backward-compatible alias for T_hat.

        The certified exponent LOWER-bounds the true rate, hence the reported
        horizon LOWER-bounds the true expiry horizon: T_hat <= T*. Reading
        this alias never entitles the consumer to the true T*."""
        return self.T_hat


def issue_verdict(post: Sequence[tuple[float, float]], cand: int, c: float,
                  delta: float, rho: float, W: float | None = None,
                  issue_time: float = 0.0, delta_tail: float | None = None,
                  route: str = "A", sharpening: str | None = None) -> Verdict:
    """Issue a certificate for retiring candidate `cand`.

    Statuses: CertifiedSafe (with expiry whenever rho > 0), CertifiedNotSafe
    (containment preconditions fail), UncertifiedNeedsRefinement (no eligible
    anchor / no separated anchor / invalid request / requested W > T_hat),
    UncertifiedNeedsMoreHorizon (E(0) < log(1/delta_tail), or T_hat < 1 under
    drift: more anchor evidence needed). Refusal is a first-class output;
    every certificate quotes (c, delta, delta_tail, rho, W, expiry,
    dropped_anchors).

    delta budgets (B2): `delta` is the certified rescue tolerance; T_hat is
    computed from `delta_tail` (default: delta_tail = delta, the coherent
    default in the pure-tail theorem where both conditions share one
    functional), and the issued certificate additionally checks
    tail(W) <= delta. Requests with delta_tail outside 0 < delta_tail <=
    delta refuse first-class. No delta_win + delta_tail <= delta budget is
    claimed (unproven; see GAPS.md).

    sharpening (Phase A): None/"product" issues on the T1.1 product tail
    (canonical); "T2" issues on Theorem T2's staggered-crossing tail
    min(product, T2-V, T2-X), never larger than the product tail, so T_hat
    can only extend; BOTH bounds are quoted on the verdict
    (tail_bound_product). rho = 0 is identical under either setting (the
    exact stationary reduction is untouched)."""
    post = [(float(a), float(b)) for (a, b) in post]
    if len(post) < 2:
        raise ValueError("need K >= 2 arms")
    if not (0.0 < delta < 1.0):
        raise ValueError("delta must lie in (0,1)")
    if c <= 0.0:
        raise ValueError("gate height c must be > 0")
    if rho < 0.0:
        raise ValueError("rho must be >= 0")
    if W is not None and not isinstance(W, (int, float, np.integer, np.floating)):
        raise TypeError("W must be numeric or None")  # structural, not a request

    means = [beta_mean(a, b) for (a, b) in post]
    host = int(np.argmax(means))  # lowest-index deterministic tie-break
    # Drift-aware inclusion (B4): shape filter at rho > 0 only; at rho == 0
    # ALL non-candidate anchors enter the exact stationary reduction.
    elig, dropped_idx = anchors_included(post, cand, rho)
    dropped = tuple((i, post[i][0], post[i][1]) for i in dropped_idx)
    if delta_tail is None:
        delta_tail = delta  # coherent pure-tail default
    if sharpening not in (None, "product", "T2"):
        raise ValueError(f"unknown sharpening {sharpening!r}")
    use_T2 = (sharpening == "T2") and rho > 0.0
    base: dict[str, Any] = dict(candidate=cand, c=c, delta=delta, rho=rho,
                                issue_time=issue_time,
                                dropped_anchors=dropped, eligible_anchors=tuple(elig),
                                delta_tail=float(delta_tail),
                                sharpening=("T2" if use_T2 else "product"))

    # Request validation (B2): the tail budget must satisfy
    # 0 < delta_tail <= delta < 1; anything else is an expected-invalid
    # REQUEST and refuses first-class (never raises, never certifies).
    if not (0.0 < delta_tail <= delta):
        return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                       protected_floor=None, tail_bound=None, T_hat=None,
                       reason=f"invalid tail budget: require 0 < delta_tail <= "
                              f"delta < 1, got delta_tail={delta_tail}, "
                              f"delta={delta}; refusing",
                       reason_code=RC_DELTA_TAIL_INVALID, **base)

    # Request validation (B3): route flag. Only Route A (ordinary Beta
    # counting) is proved; Route B / discounted posteriors must NEVER certify.
    if route != "A":
        return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                       protected_floor=None, tail_bound=None, T_hat=None,
                       reason=f"route={route!r} requested: only route='A' "
                              f"(ordinary Beta counting) is proved; Route B / "
                              f"discounted posteriors must never certify; refusing",
                       reason_code=RC_ROUTE_NOT_A, **base)

    # Request validation (B3): the window. Expected-invalid REQUESTS refuse
    # first-class with machine-readable reasons; they never raise and never
    # certify. (At rho = 0 the stationary certificate supersedes any
    # requested W >= 0; W semantics under drift require an integer >= 1.)
    if W is not None:
        if W < 0:
            return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                           protected_floor=None, tail_bound=None, T_hat=None,
                           reason=f"requested W={W} is negative; refusing",
                           reason_code=RC_W_NEGATIVE, **base)
        if rho > 0.0:
            if W != int(W):
                return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                               protected_floor=None, tail_bound=None, T_hat=None,
                               reason=f"requested W={W} is not an integer; the "
                                      f"one-pull-per-round clock counts whole "
                                      f"rounds under drift; refusing",
                               reason_code=RC_W_NONINTEGER, **base)
            if W < 1:
                return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                               protected_floor=None, tail_bound=None, T_hat=None,
                               reason=f"requested W={int(W)} < 1 under drift "
                                      f"rho={rho}: no zero-window mode exists; "
                                      f"refusing",
                               reason_code=RC_W_BELOW_ONE, **base)
            W = int(W)

    # Containment preconditions (Lemma C).
    if host == cand:
        return Verdict(status=CERTIFIED_NOT_SAFE, W=None, expiry_time=None,
                       protected_floor=None, tail_bound=None, T_hat=None,
                       reason="precondition failed: candidate is host",
                       reason_code=RC_PRE_HOST, **base)
    if N_cert(post, cand) >= c:
        return Verdict(status=CERTIFIED_NOT_SAFE, W=None, expiry_time=None,
                       protected_floor=None, tail_bound=None, T_hat=None,
                       reason="precondition failed: N^a(x) >= c (already gate-eligible)",
                       reason_code=RC_PRE_GATE, **base)

    r_c = protected_floor(post, cand, c)

    if not elig:
        return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=None, T_hat=None,
                       reason=REASON_NO_ELIGIBLE_SHAPE,
                       reason_code=RC_NO_ELIGIBLE, **base)
    if not any(means[b] > r_c for b in elig):
        return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=None, T_hat=None,
                       reason="no separated anchor at W=0 (all eligible means <= r_c)",
                       reason_code=RC_NO_SEPARATED, **base)

    T_hat = (expiry_horizon_That_T2(post, cand, r_c, rho, delta_tail)
             if use_T2 else
             expiry_horizon_That(post, cand, r_c, rho, delta_tail))
    if T_hat is None:
        return Verdict(status=UNCERT_MORE_HORIZON, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=None, T_hat=None,
                       reason="certified tail exceeds delta_tail already at W=0; "
                              "T_hat undefined -- refusing rather than reporting a "
                              "degenerate window; more anchor evidence needed",
                       reason_code=RC_DEGENERATE_W0, **base)

    if rho == 0.0:
        tb = windowed_tail(post, cand, r_c, 0.0, 0, elig=elig)
        if not (tb <= delta):  # implied by tb <= delta_tail <= delta; enforced
            return Verdict(status=UNCERT_MORE_HORIZON, W=None, expiry_time=None,
                           protected_floor=r_c, tail_bound=tb, T_hat=None,
                           reason=f"certified tail {tb} exceeds delta={delta}",
                           reason_code=RC_DEGENERATE_W0, **base)
        return Verdict(status=CERTIFIED_SAFE, W=math.inf, expiry_time=math.inf,
                       protected_floor=r_c, tail_bound=tb, T_hat=math.inf,
                       reason="stationary certificate (rho = 0): exact "
                              "stationary product tail over ALL separated "
                              "anchors, unfiltered (K2 / S4 at delta = 0); no "
                              "expiry required",
                       tail_bound_product=tb, **base)

    # B1: under drift a CertifiedSafe verdict requires a finite expiry with
    # W >= 1. A zero-window certificate (expiry_time == issue_time) is
    # expired at birth and must never be issued; there is no zero-window mode.
    if T_hat < 1:
        return Verdict(status=UNCERT_MORE_HORIZON, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=None, T_hat=float(T_hat),
                       reason=f"sub-one-round horizon: T_hat={int(T_hat)} < 1 "
                              f"under drift rho={rho}; a CertifiedSafe verdict "
                              f"under drift requires a finite expiry with W >= 1 "
                              f"(a zero-window certificate would expire at "
                              f"birth); refusing -- more anchor evidence or a "
                              f"smaller drift budget needed",
                       reason_code=RC_SUB_ONE_HORIZON, **base)

    if W is None:
        W = int(T_hat)
    if W > T_hat:
        return Verdict(status=UNCERT_REFINE, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=None, T_hat=float(T_hat),
                       reason=f"requested W={W} exceeds the reported conservative "
                              f"expiry horizon T_hat={int(T_hat)} (T_hat <= true T*); "
                              f"this certificate cannot vouch past T_hat -- refusing "
                              f"rather than issuing past expiry",
                       reason_code=RC_W_PAST_THAT, **base)

    tb_prod = windowed_tail(post, cand, r_c, rho, W, elig=elig)
    tb = (min(tb_prod, staggered_tail(post, cand, r_c, rho, W, elig=elig))
          if use_T2 else tb_prod)
    if not (tb <= delta):  # implied by W <= T_hat and delta_tail <= delta; enforced
        return Verdict(status=UNCERT_MORE_HORIZON, W=None, expiry_time=None,
                       protected_floor=r_c, tail_bound=tb, T_hat=float(T_hat),
                       reason=f"certified tail {tb} exceeds delta={delta}",
                       reason_code=RC_DEGENERATE_W0,
                       tail_bound_product=tb_prod, **base)
    return Verdict(status=CERTIFIED_SAFE, W=float(W), expiry_time=issue_time + W,
                   protected_floor=r_c, tail_bound=tb, T_hat=float(T_hat),
                   reason="safe to retire through expiry at tolerance delta, valid "
                          "for drift budget rho, computed on the disclosed eligible "
                          "anchors"
                          + (" (Theorem T2 staggered-crossing tail; product "
                             "bound quoted alongside)" if use_T2 else ""),
                   tail_bound_product=tb_prod, **base)


def check_expiry(verdict: Verdict, now: float) -> Verdict:
    """Past expiry the correct output is refusal (Expired), never a stale
    certificate. Valid THROUGH the expiry date (strict > triggers)."""
    if verdict.status not in (CERTIFIED_SAFE, RECERTIFIED):
        return verdict
    if verdict.expiry_time is not None and now > verdict.expiry_time:
        return replace(verdict, status=EXPIRED,
                       reason=f"the CONSERVATIVE certificate expired at "
                              f"t={verdict.expiry_time} (its reported horizon "
                              f"T_hat lower-bounds the true T*); refusal, not a "
                              f"stale certificate and not a danger claim",
                       reason_code=RC_EXPIRED)
    return verdict


def recertify(post: Sequence[tuple[float, float]], verdict: Verdict,
              now: float) -> Verdict:
    """Re-certification at expiry: recompute on the CURRENT state; on success
    return Recertified, otherwise return the candidate to RequiredInspection."""
    fresh = issue_verdict(post, verdict.candidate, verdict.c, verdict.delta,
                          verdict.rho, W=None, issue_time=now,
                          delta_tail=verdict.delta_tail,
                          sharpening=(verdict.sharpening
                                      if verdict.sharpening != "product"
                                      else None))
    if fresh.status == CERTIFIED_SAFE:
        return replace(fresh, status=RECERTIFIED)
    return replace(fresh, status=REQUIRED_INSPECTION,
                   reason=f"recertification failed ({fresh.status}: {fresh.reason}); "
                          f"returned to RequiredInspection")
