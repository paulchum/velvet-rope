"""Convention A for predictive rescue-event e-values (O2.1).  [BP]

Canonical source: docs/math/drift_expiry_certificates.txt (adjudication convention O2.1).

Convention A:
  * adjudication horizon H_j := W_j, the certificate's own window;
  * finalized e-value  E_hat_j := 1{A_j^{W_j}} / u_j, with 0/0 := 0;
  * remainder: stationary -> denominator via certified decomposition
    u = u_DP(W) + t(W), plus an additive certified report line
    E[#late rescues among R] <= E[sum_{j in R} t_j]; the reported
    sum_t is a predictable certified charge; drift -> refusal past expiry
    (the certified answer beyond T_hat_j is refusal, not a number).

Pure stdlib. Exact Fraction arithmetic everywhere except Clopper-Pearson
(log-space floats). Toy exact engine covers the 2-arm shape used by every
pinned instance: FROZEN candidate Beta(ca,cb) (the retired arm a_j), one
base arm Beta(ba,bb) pulled once per round in the window; baseline
V = mean(base); gate value N = psi(candidate posterior, V).
"""
from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from math import comb, exp, factorial, lgamma, log
from typing import Any

Frac = Fraction

# ----------------------------------------------------------------------
# exact psi(Beta(a,b), v) = E_{theta~Beta(a,b)} (theta - v)^+        [MATH]
# ----------------------------------------------------------------------

def beta_const(a: int, b: int) -> Fraction:
    """B(a,b) for positive integers, exact."""
    return Frac(factorial(a - 1) * factorial(b - 1), factorial(a + b - 1))


def psi(a: int, b: int, v: Fraction | int | float) -> Fraction:
    """Exact E_{theta~Beta(a,b)}(theta - v)^+ for integer a,b >= 1."""
    v = Frac(v)
    if v >= 1:
        return Frac(0)
    if v <= 0:
        return Frac(a, a + b) - v
    num = Frac(0)
    # (1-t)^{b-1} = sum_k C(b-1,k) (-1)^k t^k
    for k in range(b):
        coef = comb(b - 1, k) * ((-1) ** k)
        n1 = a + k + 1  # integral of t^{a+k}
        n0 = a + k      # integral of t^{a-1+k}
        term = Frac(1 - v ** n1, 1) / n1 - v * Frac(1 - v ** n0, 1) / n0
        num += coef * term
    return num / beta_const(a, b)


def gate_value(cand: tuple[int, int], base: tuple[int, int]) -> Fraction:
    """N^{a}(x) = psi(Pi_cand, V) with V = posterior mean of the base arm."""
    ba, bb = base
    return psi(cand[0], cand[1], Frac(ba, ba + bb))


def crossed_now(cand: tuple[int, int], base: tuple[int, int],
                c: Fraction | int | float) -> bool:
    return gate_value(cand, base) >= Frac(c)


# ----------------------------------------------------------------------
# exact enumeration of windowed crossing probabilities              [BP]
# P(A^h | F_tau) for h = 0..W under the predictive law (base pulled
# each round; candidate frozen). Crossing is absorbing; sup includes
# the issue state s = tau.
# ----------------------------------------------------------------------

def crossing_probs(cand: tuple[int, int], base: tuple[int, int],
                   c: Fraction | int | float, W: int) -> list[Fraction]:
    c = Frac(c)
    out = [Frac(0)] * (W + 1)

    def rec(ba: int, bb: int, depth: int, prob: Fraction) -> None:
        if psi(cand[0], cand[1], Frac(ba, ba + bb)) >= c:
            for h in range(depth, W + 1):
                out[h] += prob
            return
        if depth == W:
            return
        p_s = Frac(ba, ba + bb)
        rec(ba + 1, bb, depth + 1, prob * p_s)
        rec(ba, bb + 1, depth + 1, prob * (1 - p_s))

    rec(base[0], base[1], 0, Frac(1))
    return out


# ----------------------------------------------------------------------
# certificates (frozen interface, consumed as a box)                [BP]
# ----------------------------------------------------------------------

class ExpiryRefusal(Exception):
    """Certified answer past expiry (or infinite horizon under drift) is
    refusal, not a number."""


class ContractBreach(Exception):
    """Tripwire: the pointwise certificate contract was violated
    (event occurred on {u_j = 0})."""


@dataclass(frozen=True)
class Certificate:
    W: int                      # adjudication window = certificate window
    u: Fraction                 # u >= P(A^W | F_tau) pointwise at realized state
    t: Fraction | None = None   # certified tail line (stationary decomposition)
    T_hat: int | None = None    # expiry horizon (drift); None = stationary
    note: str = ""


def certify_windowed(cand: tuple[int, int], base: tuple[int, int],
                     c: Fraction | int | float, W: int, T_hat: int | None = None,
                     slack: Fraction | int | float = 0) -> Certificate:
    """Tight windowed certificate at the realized state (+ optional slack).
    Refuses if the requested window outlives the expiry horizon."""
    if T_hat is not None and W > T_hat:
        raise ExpiryRefusal(
            f"requested window W={W} exceeds expiry T_hat={T_hat}: "
            "certified answer is refusal")
    p = crossing_probs(cand, base, c, W)[W]
    u = min(Frac(1), p + Frac(slack))
    return Certificate(W=W, u=u, T_hat=T_hat,
                       note="tight windowed" + (" +slack" if slack else ""))


def certify_decomposed(cand: tuple[int, int], base: tuple[int, int],
                       c: Fraction | int | float, H_adj: int,
                       H_total: int) -> Certificate:
    """Stationary truncation+tail decomposition (toy proxy: 'infinite'
    horizon modeled by H_total): u = u_DP(H_adj) + t, t = P(A^{H_total}) -
    P(A^{H_adj}) >= P(A \\ A^{H_adj}). Adjudication window is H_adj; the
    unadjudicated remainder rides in the denominator AND on the t line."""
    ps = crossing_probs(cand, base, c, H_total)
    u_dp, u_full = ps[H_adj], ps[H_total]
    return Certificate(W=H_adj, u=u_full, t=u_full - u_dp,
                       note="stationary truncation+tail (u = u_DP + t)")


def certify_infinite(drift: bool, cand: tuple[int, int] | None = None,
                     base: tuple[int, int] | None = None,
                     c: Fraction | int | float | None = None,
                     H_adj: int = 1, H_total: int = 2) -> Certificate:
    """Infinite-horizon certification. Under drift: refusal (Lemma N4)."""
    if drift:
        raise ExpiryRefusal(
            "infinite-horizon certification under drift: past expiry the "
            "certified answer is refusal, not a number")
    # cand/base/c may be None only on the drift path, which raised above.
    return certify_decomposed(cand, base, c, H_adj, H_total)  # type: ignore[arg-type]


# ----------------------------------------------------------------------
# finalize / adjudicate                                              [BP]
# ----------------------------------------------------------------------

def finalize(crossed: bool, cert: Certificate) -> Fraction:
    """E_hat = 1{A^W}/u with 0/0 := 0. On {u=0} the contract forces
    P(A^W|F_tau)=0, so a crossing there is a contract breach (tripwire)."""
    if cert.u == 0:
        if crossed:
            raise ContractBreach("A^W occurred on {u=0}")
        return Frac(0)
    return Frac(1) / cert.u if crossed else Frac(0)


# ----------------------------------------------------------------------
# fleet accountant: gate on the PLEDGE (F_tau-observable), adjudicate
# at tau_j + W_j, report [BP] quantities only.
# Modes: 'elond'  bar_j = delta * gamma_j * r_j     (Thm 8; sum gamma <= 1)
#        'ebh'    bar_j = delta * r_j / K_max       (Cor 9; frozen gate shape)
#        'spend'  bar_j = eps_j, sum eps_j <= eps   (Cor 10; expected count)
#        'naive-broken'  bar_j = delta              (O1/N5; MUST be falsified)
# r_j = (#executed before j) + 1 = position j would take.
# Measurability guard: consider() never sees the outcome.
# ----------------------------------------------------------------------

class FleetAccountant:
    def __init__(self, mode: str, delta: Fraction | int | float,
                 gammas: Sequence[Fraction | int | float] | None = None,
                 k_max: int | None = None,
                 epsilons: Sequence[Fraction | int | float] | None = None):
        assert mode in ("elond", "ebh", "spend", "naive-broken")
        self.mode = mode
        self.delta = Frac(delta)
        self.gammas = [Frac(g) for g in gammas] if gammas else None
        if self.gammas is not None:
            assert sum(self.gammas) <= 1
        self.k_max = k_max
        self.epsilons = [Frac(e) for e in epsilons] if epsilons else None
        self.decisions: list[dict[str, Any]] = []

    # -- gate (at tau_j; uses only F_tau-observables) --
    def _bar(self, idx: int, r: int) -> Fraction:
        if self.mode == "elond":
            # mode invariant: gammas supplied for 'elond' (asserted in __init__ use)
            return self.delta * self.gammas[idx] * r  # type: ignore[index]
        if self.mode == "ebh":
            # mode invariant: k_max supplied for 'ebh'
            return self.delta * r / self.k_max  # type: ignore[operator]
        if self.mode == "spend":
            # mode invariant: epsilons supplied for 'spend'
            return self.epsilons[idx]  # type: ignore[index]
        return self.delta  # naive-broken

    def consider(self, u: Fraction | int | float | None = None,
                 cert: Certificate | None = None) -> dict[str, Any]:
        """Issue-time gate. If a certificate is supplied, cert.u is the
        single theorem-bearing envelope: it is used both for the gate and
        later as the finalized denominator. Passing a mismatched explicit u
        is rejected because it represents a policy outside Theorem 8.
        """
        if cert is not None:
            if u is not None and Frac(u) != cert.u:
                raise ValueError("gate u must equal certificate denominator cert.u")
            u = cert.u
        if u is None:
            raise ValueError("consider() requires u or cert")
        u = Frac(u)
        idx = len(self.decisions)
        r = sum(1 for d in self.decisions if d["executed"]) + 1
        bar = self._bar(idx, r)
        rec = {"id": idx, "u": u, "bar": bar, "r": r,
               "executed": u <= bar, "cert": cert,
               "adjudicated": False, "crossed": None, "e_hat": None}
        self.decisions.append(rec)
        return rec

    # -- adjudication (at tau_j + W_j; pure observation of the trace) --
    def adjudicate(self, decision_id: int, crossed: bool) -> Fraction:
        rec = self.decisions[decision_id]
        assert rec["executed"], "only executed decisions are adjudicated"
        assert not rec["adjudicated"], "already adjudicated"
        cert = rec["cert"] or Certificate(W=0, u=rec["u"])
        e_hat = finalize(crossed, cert)
        rec.update(adjudicated=True, crossed=crossed, e_hat=e_hat)
        return e_hat

    # -- [BP] fleet report --
    def report(self) -> dict[str, Any]:
        ex = [d for d in self.decisions if d["executed"]]
        adj = [d for d in ex if d["adjudicated"]]
        V = sum(1 for d in adj if d["crossed"])
        n_ex = len(ex)
        flr = Frac(V, max(n_ex, 1))
        tails = [d["cert"].t for d in ex if d["cert"] and d["cert"].t is not None]
        predictable_tail_charge = sum(tails, Frac(0)) if tails else None
        return {
            "currency": "[BP]",
            "mode": self.mode, "delta": self.delta,
            "n_considered": len(self.decisions), "n_executed": n_ex,
            "n_adjudicated": len(adj), "n_pending": n_ex - len(adj),
            "rescues_adjudicated": V,
            "flr": flr, "flr_float": float(flr),
            # Predictable certified charge: for stationary decompositions,
            # E[# executed late rescues] <= E[predictable_tail_charge].
            "predictable_tail_charge": predictable_tail_charge,
            "remainder_line": predictable_tail_charge,  # backwards-compatible alias
            "remainder_line_kind": ("predictable_certified_charge_sum_t"
                                      if tails else None),
            "note": "FLR = adjudicated bookkeeping reversals within certified "
                    "windows / executed; NOT ground truth; stationary tails "
                    "are reported as a separate predictable charge",
        }


# ----------------------------------------------------------------------
# simulation under the predictive law                               [SIM]
# ----------------------------------------------------------------------

def sample_pull(a: int, b: int, rng: random.Random) -> bool:
    """One Bernoulli pull from the posterior predictive: P(1) = a/(a+b),
    exact via integer sampling."""
    return rng.randrange(a + b) < a


def sample_crossed(cand: tuple[int, int], base: tuple[int, int],
                   c: Fraction | int | float, W: int, rng: random.Random,
                   return_state: bool = False) -> bool | tuple[bool, tuple[int, int]]:
    """Walk the window under the predictive law; crossing sup includes
    the issue state."""
    c = Frac(c)
    ba, bb = base
    crossed = psi(cand[0], cand[1], Frac(ba, ba + bb)) >= c
    for _ in range(W):
        if crossed:
            break
        if sample_pull(ba, bb, rng):
            ba += 1
        else:
            bb += 1
        crossed = psi(cand[0], cand[1], Frac(ba, ba + bb)) >= c
    return (crossed, (ba, bb)) if return_state else crossed


def bernoulli_from_fraction(fr: Fraction, rng: random.Random) -> int:
    """Exact randomized rounding: Y=1 w.p. fr; E[Y] = fr."""
    return 1 if rng.randrange(fr.denominator) < fr.numerator else 0


# ----------------------------------------------------------------------
# one-sided Clopper-Pearson (log-space, bisection)                  [MATH]
# ----------------------------------------------------------------------

def _log_binom_cdf(k: int, n: int, p: float) -> float:
    """log P(Bin(n,p) <= k), stable."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 0.0 if k >= n else float("-inf")
    k = min(k, n)
    lp, l1p = log(p), log(1.0 - p)
    terms = [lgamma(n + 1) - lgamma(i + 1) - lgamma(n - i + 1)
             + i * lp + (n - i) * l1p for i in range(k + 1)]
    m = max(terms)
    return m + log(sum(exp(t - m) for t in terms))


def cp_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """Smallest p with P(Bin(n,p) <= k) <= alpha (one-sided upper bound
    for the mean). Validity cells: PASS iff cp_upper <= target."""
    if k >= n:
        return 1.0
    lo, hi = k / n if n else 0.0, 1.0
    la = log(alpha)
    for _ in range(80):
        mid = (lo + hi) / 2
        if _log_binom_cdf(k, n, mid) > la:
            lo = mid
        else:
            hi = mid
    return hi


def cp_lower(k: int, n: int, alpha: float = 0.05) -> float:
    """Largest p with P(Bin(n,p) >= k) <= alpha (one-sided lower bound).
    Violation cells: certified iff cp_lower > target."""
    if k <= 0:
        return 0.0
    lo, hi = 0.0, k / n if n else 1.0
    l1a = log(1.0 - alpha)
    for _ in range(80):
        mid = (lo + hi) / 2
        if _log_binom_cdf(k - 1, n, mid) >= l1a:
            lo = mid
        else:
            hi = mid
    return lo


def cell_label(predicted_rate: float, n: int, events: int) -> str:
    if events == 0:
        return "VACUOUS"
    return "POWERED" if predicted_rate * n >= 10 else "UNDERPOWERED"
