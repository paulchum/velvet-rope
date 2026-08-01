"""First-class anytime e-processes for Certified Exploration ([FM]).

An *e-process* is a nonnegative process whose value at every adapted
stopping time has expectation at most 1 under the declared null; by
Ville's inequality ``P(sup ln E >= ln(1/delta)) <= delta`` uniformly over
stopping rules. Every retirement, lease, and drop certificate issued by
the Certified Exploration surface is a crossing event of one of the
concrete e-processes in this module, so validity never depends on any
model posterior being calibrated (posterior-free validity; moonshot
T3-i).

Ported from gating-moonshot @ ``3e0e7cf`` (``src/t4b_witness.py``,
``src/tna_witness.py``); arithmetic preserved verbatim, shapes re-typed.
See ``src/velvet/verdict/UPSTREAM.md``. The vectorized prefix functions
are exported for the test batteries and the parity fixture; runtime code
uses the stateful classes.

Claim-currency: everything in this module is fixed-mean frequentist
[FM] — valid under arbitrary adapted allocation, stopping, and any
(mis)calibrated proposer/posterior. [SIM] quantities never enter these
statistics.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol

import numpy as np

LOG2 = math.log(2.0)
_EPS = 1e-12

__all__ = [
    "LOG2",
    "EProcess",
    "FixedScaleWProcess",
    "HalfNullEProcess",
    "LedgerEProcess",
    "PairGLREProcess",
    "eprocess_threshold",
    "kl_bernoulli_vec",
    "ledger_log_e",
    "ledger_ln_e",
    "ledger_sup_crossings",
    "pair_z_vec",
    "w_thresholds",
    "w_z_prefix",
    "z_half_scalar",
    "z_half_vec",
]


def eprocess_threshold(delta: float) -> float:
    """Ville crossing threshold ``ln(1/delta)`` for an anytime e-process."""
    if not 0.0 < delta < 1.0:
        raise ValueError(f"delta must be in (0, 1), got {delta}")
    return math.log(1.0 / delta)


def kl_bernoulli_vec(p: np.ndarray, q: np.ndarray) -> np.ndarray:
    """Vectorized Bernoulli KL divergence (mirrors ``audit_glr.kl_bernoulli``)."""
    p = np.clip(np.asarray(p, dtype=float), _EPS, 1.0 - _EPS)
    q = np.clip(np.asarray(q, dtype=float), _EPS, 1.0 - _EPS)
    result: np.ndarray = p * np.log(p / q) + (1.0 - p) * np.log((1.0 - p) / (1.0 - q))
    return result


# ---------------------------------------------------------------------------
# Fixed-scale W statistics (single candidate stream at a declared depth scale)
# ---------------------------------------------------------------------------


def w_z_prefix(j: np.ndarray, s: np.ndarray, ystar: float) -> tuple[np.ndarray, np.ndarray]:
    """Z of the non-witness refuter and the witness along a candidate prefix.

    ``j``: pull counts 1..n; ``s``: cumulative reward successes. Returns
    ``(z_nw, z_w)``: ``z_nw = j*kl(m_hat, 1-y*)`` on ``{m_hat < 1-y*}``
    (the null "IS y*-deep" violated empirically from below); ``z_w`` is the
    symmetric statistic on ``{m_hat > 1-y*}``. Firing the non-witness
    certifies depth ``U_c > y*``; firing the witness certifies ``U_c < y*``.
    Fixing the scale decouples ledger evidence from the moving incumbent
    (moonshot T4B).
    """
    j = np.asarray(j, dtype=float)
    m0 = 1.0 - ystar
    mhat = np.asarray(s, dtype=float) / np.maximum(j, 1.0)
    z = j * kl_bernoulli_vec(mhat, np.asarray(m0))
    z_nw = np.where(mhat < m0, z, 0.0)
    z_w = np.where(mhat > m0, z, 0.0)
    return z_nw, z_w


def w_thresholds(j: np.ndarray, ln_inv_delta: float) -> np.ndarray:
    """Bound-KT firing threshold on Z at count j: ``L + 0.5 ln j + ln 2``."""
    j = np.asarray(j, dtype=float)
    result: np.ndarray = ln_inv_delta + 0.5 * np.log(np.maximum(j, 1.0)) + LOG2
    return result


# ---------------------------------------------------------------------------
# Ledger e-process (component-conditional quantile certificate stream)
# ---------------------------------------------------------------------------


def ledger_ln_e(nvec: np.ndarray, svec: np.ndarray, bstar: float) -> np.ndarray:
    """``ln E`` of the ledger e-process at prefix counts ``nvec`` with
    drop-sums ``svec``: one-sided GLR vs ``b*``, bound-KT clock (moonshot
    T4B Lemmas C1/C2 — anytime delta-valid under arbitrary adapted
    admission)."""
    n = np.asarray(nvec, dtype=float)
    sh = np.asarray(svec, dtype=float) / np.maximum(n, 1.0)
    z = n * kl_bernoulli_vec(sh, np.asarray(bstar))
    z = np.where(sh > bstar, z, 0.0)
    result: np.ndarray = z - (0.5 * np.log(np.maximum(n, 1.0)) + LOG2)
    return result


def ledger_log_e(n: int, s: int, bstar: float) -> float:
    """Scalar ``ledger_ln_e`` at trial count ``n`` with ``s`` recorded drops."""
    return float(ledger_ln_e(np.array([n]), np.array([s]), bstar)[0])


def ledger_sup_crossings(
    B: np.ndarray, bstar: float, ln_thresh: float, raw: bool = False
) -> tuple[int, np.ndarray]:
    """Count rows of the 0/1 trial matrix ``B`` whose ledger e-process (or
    raw-Z clock when ``raw=True`` — the invalid comparator) ever crosses
    ``ln_thresh``. Returns ``(count, first_crossing_index)`` with -1 for
    never."""
    B = np.asarray(B, dtype=float)
    _, N = B.shape
    n = np.arange(1, N + 1, dtype=float)[None, :]
    S = np.cumsum(B, axis=1)
    sh = S / n
    z = n * kl_bernoulli_vec(sh, np.asarray(bstar))
    z = np.where(sh > bstar, z, 0.0)
    stat = z if raw else z - (0.5 * np.log(n) + LOG2)
    hit = stat >= ln_thresh
    any_hit = hit.any(axis=1)
    first = np.where(any_hit, hit.argmax(axis=1) + 1, -1)
    return int(any_hit.sum()), first


# ---------------------------------------------------------------------------
# Pair and half-null e-statistics (accept / drop audits)
# ---------------------------------------------------------------------------


def pair_z_vec(
    n_a: np.ndarray, s_a: np.ndarray, n_b: np.ndarray, s_b: np.ndarray
) -> np.ndarray:
    """Pooled GLR Z for the accept null ``H: mu_a >= mu_b`` (incumbent >=
    candidate), vectorized. Combine with the bound-KT clock
    ``- (0.5 ln n_a + ln 2) - (0.5 ln n_b + ln 2)`` for the anytime pair
    e-process (moonshot T3-i shape; ``audit_glr`` carries the exact-KT
    Family-M variant of the same audit)."""
    n_a = np.asarray(n_a, dtype=float)
    n_b = np.asarray(n_b, dtype=float)
    ma = np.asarray(s_a, dtype=float) / np.maximum(n_a, 1.0)
    mb = np.asarray(s_b, dtype=float) / np.maximum(n_b, 1.0)
    pooled = (np.asarray(s_a, dtype=float) + np.asarray(s_b, dtype=float)) / np.maximum(
        n_a + n_b, 1.0
    )
    z = n_a * kl_bernoulli_vec(ma, pooled) + n_b * kl_bernoulli_vec(mb, pooled)
    result: np.ndarray = np.where((ma < mb) & (n_a >= 1) & (n_b >= 1), z, 0.0)
    return result


def z_half_vec(
    k: np.ndarray, s_c: np.ndarray, n: np.ndarray, s_a: np.ndarray
) -> np.ndarray:
    """Vectorized Z for the half-null ``H_half: mu_c >= (1 + mu_a)/2``.

    Z = inf over the null of ``[k kl(m_c, m1) + n kl(m_a, m2)]``, computed
    by bisection on the (monotone) derivative along the boundary
    ``m1 = (1+m2)/2``, then reported as ``phi(m_hi) - width*max(g(m_hi),0)
    - 1e-9``: a CERTIFIED LOWER bound on the true infimum (overstating Z
    would break validity; a lower bound only delays the crossing). Zero
    when the empirical pair is inside the null. Firing refutes "the
    candidate is at least a factor-2 improvement" — the certified-drop
    statistic (moonshot TNA)."""
    k = np.asarray(k, dtype=float)
    n = np.asarray(n, dtype=float)
    a = np.asarray(s_c, dtype=float) / np.maximum(k, 1.0)
    b = np.asarray(s_a, dtype=float) / np.maximum(n, 1.0)
    active = (a < (1.0 + b) / 2.0 - 1e-15) & (k >= 1) & (n >= 1)
    lo = np.maximum(2.0 * a - 1.0, 1e-9)
    hi = np.maximum(b, lo + 1e-15)

    def g(m: np.ndarray) -> np.ndarray:
        m1 = (1.0 + m) / 2.0
        t1 = 0.5 * k * (m1 - a) / np.maximum(m1 * (1.0 - m1), _EPS)
        t2 = n * (m - b) / np.maximum(m * (1.0 - m), _EPS)
        result: np.ndarray = t1 + t2
        return result

    lo_w, hi_w = lo.copy(), hi.copy()
    for _ in range(48):
        mid = 0.5 * (lo_w + hi_w)
        neg = g(mid) < 0.0
        lo_w = np.where(neg, mid, lo_w)
        hi_w = np.where(neg, hi_w, mid)
    m = hi_w
    phi = k * kl_bernoulli_vec(a, (1.0 + m) / 2.0) + n * kl_bernoulli_vec(b, m)
    slack = (hi_w - lo_w) * np.maximum(g(hi_w), 0.0) + 1e-9
    result: np.ndarray = np.where(active, np.maximum(phi - slack, 0.0), 0.0)
    return result


def z_half_scalar(k: int, s_c: int, n: int, s_a: int) -> float:
    """Scalar ``z_half_vec``."""
    return float(
        z_half_vec(np.array([k]), np.array([s_c]), np.array([n]), np.array([s_a]))[0]
    )


# ---------------------------------------------------------------------------
# Stateful e-process objects (the runtime surface)
# ---------------------------------------------------------------------------


class EProcess(Protocol):
    """Anytime-valid e-process over a serially observed stream.

    ``log_e`` is the current ``ln E``; a certificate may be issued exactly
    when ``log_e`` crosses the declared threshold (``eprocess_threshold``
    for a per-decision level, ``flr_ebh.threshold_for`` for the fleet
    e-BH rung). Silence — never crossing — is never evidence for the
    null; refusal statuses exist for that."""

    @property
    def log_e(self) -> float:
        """Current ``ln E`` of the process."""
        ...

    @property
    def count(self) -> int:
        """Number of observations consumed."""
        ...


@dataclass
class LedgerEProcess:
    """Per-component ledger e-process on the 0/1 trial stream (T4B).

    The null is "conditional mean of B <= b*" with
    ``b* = 1 - theta*(1 - delta_T)``; firing certifies the
    component-conditional QUANTILE statement ``rho_k((0, y*]) < theta``.
    Valid under arbitrary adapted admission ([FM]); trials must be
    STRICTLY SERIAL (settle before next admission).
    """

    b_star: float
    n: int = 0
    s: int = 0

    def update(self, b: int) -> float:
        """Record one settled trial outcome ``b in {0, 1}``; returns ``log_e``."""
        if b not in (0, 1):
            raise ValueError(f"trial outcome must be 0 or 1, got {b}")
        self.n += 1
        self.s += b
        return self.log_e

    @property
    def log_e(self) -> float:
        if self.n == 0:
            return -math.inf
        return ledger_log_e(self.n, self.s, self.b_star)

    @property
    def count(self) -> int:
        return self.n


@dataclass
class FixedScaleWProcess:
    """Fixed-scale W trial: two one-sided GLR e-processes at depth scale
    ``y*`` on one candidate's reward stream (T4B).

    ``update`` consumes one 0/1 reward observation. The trial settles when
    the non-witness refuter fires (``B = 1``: depth certified > y*), the
    witness fires (``B = 0``: depth certified < y*), or the window cap is
    reached (``B = 0`` — conservative FOR the component, so truncation can
    never manufacture drop-evidence).
    """

    y_star: float
    ln_inv_delta: float
    cap: int
    j: int = 0
    s: int = 0
    fired_nonwitness: bool = False
    fired_witness: bool = False

    def update(self, x: int) -> None:
        """Consume one reward observation ``x in {0, 1}``."""
        if self.settled:
            raise RuntimeError("W trial already settled")
        if x not in (0, 1):
            raise ValueError(f"reward observation must be 0 or 1, got {x}")
        self.j += 1
        self.s += x
        z_nw, z_w = w_z_prefix(np.array([self.j]), np.array([self.s]), self.y_star)
        thr = float(w_thresholds(np.array([self.j]), self.ln_inv_delta)[0])
        if float(z_nw[0]) >= thr:
            self.fired_nonwitness = True
        elif float(z_w[0]) >= thr:
            self.fired_witness = True

    @property
    def settled(self) -> bool:
        return self.fired_nonwitness or self.fired_witness or self.j >= self.cap

    @property
    def outcome(self) -> int:
        """The trial's ledger record ``B`` (only meaningful once settled)."""
        return 1 if self.fired_nonwitness else 0

    @property
    def log_e(self) -> float:
        if self.j == 0:
            return -math.inf
        z_nw, z_w = w_z_prefix(np.array([self.j]), np.array([self.s]), self.y_star)
        clock = 0.5 * math.log(max(self.j, 1)) + LOG2
        return float(max(z_nw[0], z_w[0])) - clock

    @property
    def count(self) -> int:
        return self.j


@dataclass
class PairGLREProcess:
    """Anytime pair e-process for the accept null ``H: mu_a >= mu_b``
    (incumbent a, candidate b) with the bound-KT clock (T3-i shape).

    Firing certifies the candidate strictly improves on the incumbent.
    ``audit_glr.AnytimeGLRAudit`` is the exact-KT Family-M variant of the
    same audit; this class keeps the moonshot bound-KT form so the T4B/T5
    stack's crossings reproduce to the integer.
    """

    n_a: int = 0
    s_a: int = 0
    n_b: int = 0
    s_b: int = 0

    def update(self, side: str, x: int) -> float:
        """Record one 0/1 observation on side ``"a"`` (incumbent) or
        ``"b"`` (candidate); returns ``log_e``."""
        if x not in (0, 1):
            raise ValueError(f"observation must be 0 or 1, got {x}")
        if side == "a":
            self.n_a += 1
            self.s_a += x
        elif side == "b":
            self.n_b += 1
            self.s_b += x
        else:
            raise ValueError(f"side must be 'a' or 'b', got {side!r}")
        return self.log_e

    @property
    def log_e(self) -> float:
        if self.n_a == 0 or self.n_b == 0:
            return -math.inf
        z = float(
            pair_z_vec(
                np.array([self.n_a]),
                np.array([self.s_a]),
                np.array([self.n_b]),
                np.array([self.s_b]),
            )[0]
        )
        reg_a = 0.5 * math.log(max(self.n_a, 1)) + LOG2
        reg_b = 0.5 * math.log(max(self.n_b, 1)) + LOG2
        return z - reg_a - reg_b

    @property
    def count(self) -> int:
        return self.n_a + self.n_b


@dataclass
class HalfNullEProcess:
    """Anytime half-null e-process: refutes ``H_half: mu_c >= (1+mu_a)/2``
    with the bound-KT clock — the certified-drop statistic (TNA).

    Firing certifies "the candidate is NOT a factor-2 improvement", which
    is what licenses dropping it (house rule: candidate drops carry
    certificates too; silence is never evidence of death)."""

    k: int = 0
    s_c: int = 0
    n: int = 0
    s_a: int = 0

    def update(self, side: str, x: int) -> float:
        """Record one 0/1 observation on side ``"c"`` (candidate) or
        ``"a"`` (anchor/incumbent); returns ``log_e``."""
        if x not in (0, 1):
            raise ValueError(f"observation must be 0 or 1, got {x}")
        if side == "c":
            self.k += 1
            self.s_c += x
        elif side == "a":
            self.n += 1
            self.s_a += x
        else:
            raise ValueError(f"side must be 'c' or 'a', got {side!r}")
        return self.log_e

    @property
    def log_e(self) -> float:
        if self.k == 0 or self.n == 0:
            return -math.inf
        z = z_half_scalar(self.k, self.s_c, self.n, self.s_a)
        reg_k = 0.5 * math.log(max(self.k, 1)) + LOG2
        reg_n = 0.5 * math.log(max(self.n, 1)) + LOG2
        return z - reg_k - reg_n

    @property
    def count(self) -> int:
        return self.k + self.n
