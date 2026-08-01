"""Quantile component retirement — the T4B certificate surface ([FM]).

A component (tool route, variant family, expert, mixture slot) is retired
against a declared QUANTILE null: "the component's mass at depth scale
``y*`` is below ``theta``" — never against its mean. Mean certificates
are unpriceable (moonshot T4B Prop M: the inspection bill diverges as
``Omega(1/eta)``), so ``mean_certificate`` refuses by construction.

The retirement pipeline: serial fixed-scale W trials
(``eprocess.FixedScaleWProcess``) feed the per-component ledger e-process
(``eprocess.LedgerEProcess``); execution passes the online e-BH fleet
gate so the fleet false-lockout rate is held at or below ``delta``
(``flr_ebh``). Refusal statuses are first-class outputs: below the
unconditional evidence floor ``n_floor`` the FORCED output is
``EvidenceCensored`` (no delta-valid rule retires with power >= 1/2 on
fewer admitted candidates, regardless of pulls — Theorem C-iv(a));
an exhausted allowance without a crossing is ``NotSeparated``.

Ported from gating-moonshot @ ``3e0e7cf`` (``src/t4b_witness.py``);
arithmetic preserved verbatim. See ``src/velvet/verdict/UPSTREAM.md``.
Claim-currency: [FM]. Guarantees hold on Bernoulli/bounded-reward
declared-contract classes under the Proposer Contract; clause 7
(unfiltered ledger draws) is a proposer DESIGN obligation no runtime
check replaces (CE-7).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from velvet.verdict.eprocess import LOG2, ledger_log_e
from velvet.verdict.flr_ebh import threshold_for

__all__ = [
    "MeanCertificateUnpriceable",
    "QuantileQuestion",
    "ReasonCode",
    "RetirementBill",
    "RetirementVerdict",
    "b_star",
    "cap_ext_proof",
    "ebh_ln_threshold",
    "gamma_led",
    "j_star",
    "k_w_proof",
    "mean_certificate",
    "n_floor",
    "n_ret_star",
    "predict_ret_bill",
    "quantile_retirement_verdict",
]


class ReasonCode(str, Enum):
    """Machine-readable refusal/inspection reason registry.

    Shared by the Certified Exploration surface (retirement, leases,
    planner); values appear verbatim in signed certificates' free-string
    reason field so downstream verifiers can dispatch without parsing
    prose. Refusals are outputs, not failures.
    """

    EVIDENCE_CENSORED = "EvidenceCensored"
    EVIDENCE_CENSORED_DRIFT = "EvidenceCensoredDrift"
    NOT_SEPARATED = "NotSeparated"
    UNCERTIFIED_NEEDS_MORE_HORIZON = "UncertifiedNeedsMoreHorizon"
    DRIFT_TOO_FAST = "DriftTooFast"
    MARGIN_BAND = "MarginBand"
    MODULUS_TOO_COARSE = "ModulusTooCoarse"
    MEAN_CERTIFICATE_UNPRICEABLE = "MeanCertificateUnpriceable"
    MARGINAL_KAPPA_REFUSED = "MarginalKappaRefused"
    RECOVERY_WITNESS = "RecoveryWitness"


class MeanCertificateUnpriceable(Exception):
    """Raised by ``mean_certificate``: mean-form retirement certificates
    are refused as unpriceable (T4B Prop M — the inspection bill diverges
    as ``Omega(1/eta)`` near the boundary; the quantile form is forced)."""


@dataclass(frozen=True)
class QuantileQuestion:
    """A declared component-retirement question.

    ``component_id``: the component the question is about (its identity in
    the fleet's declared key set). ``y_star``: the retirement depth scale.
    ``theta``: the retirement mass key — the null retired against is
    "rho_component((0, y*]) >= theta". ``delta``: the FLEET false-lockout
    tolerance. ``delta_T``: the per-trial audit level. ``k_max``: the
    declared fleet question window (e-BH denominator).
    """

    component_id: str
    y_star: float
    theta: float
    delta: float
    delta_T: float
    k_max: int

    def __post_init__(self) -> None:
        if not 0.0 < self.y_star < 1.0:
            raise ValueError(f"y_star must be in (0, 1), got {self.y_star}")
        if not 0.0 < self.theta < 1.0:
            raise ValueError(f"theta must be in (0, 1), got {self.theta}")
        if not 0.0 < self.delta < 1.0:
            raise ValueError(f"delta must be in (0, 1), got {self.delta}")
        if not 0.0 < self.delta_T < 1.0:
            raise ValueError(f"delta_T must be in (0, 1), got {self.delta_T}")
        if self.k_max < 1:
            raise ValueError(f"k_max must be >= 1, got {self.k_max}")

    @property
    def b_star(self) -> float:
        """The ledger null boundary ``b* = 1 - theta*(1 - delta_T)``."""
        return b_star(self.theta, self.delta_T)

    @property
    def n_floor(self) -> int:
        """The unconditional per-component evidence floor at the fleet's
        per-question level ``delta / k_max``."""
        return n_floor(self.theta, self.delta / self.k_max)


def b_star(theta: float, delta_T: float) -> float:
    """Ledger null boundary ``b* = 1 - theta*(1 - delta_T)``."""
    return 1.0 - theta * (1.0 - delta_T)


def j_star(u: float, ystar: float, ln_inv_delta: float) -> int:
    """Deterministic-mean-path crossing of the W e-process for a candidate
    at depth ``u`` (either side of ``y*``): smallest integer j with
    ``j*kl(1-u, 1-y*) >= L + 0.5 ln j + ln 2``. Returns a large sentinel
    if the rate is ~0 (``u = y*``: never fires on the mean path)."""
    rate = _kl_bern(1.0 - u, 1.0 - ystar)
    if rate <= 1e-12:
        return 10**9
    j = max((ln_inv_delta + LOG2) / rate, 2.0)
    for _ in range(200):
        j = (ln_inv_delta + 0.5 * math.log(j) + LOG2) / rate
    ji = int(math.ceil(j))
    while ji * rate < ln_inv_delta + 0.5 * math.log(ji) + LOG2:
        ji += 1
    return ji


def n_ret_star(theta: float, ln_inv_delta_eff: float, delta_T: float) -> int:
    """Ledger crossing count on the all-drops stream (dead component,
    ``B == 1``): smallest n with ``n*ln(1/b*) >= L_eff + 0.5 ln n + ln 2``.
    Exact for ``B == 1`` (deterministic)."""
    bstar = b_star(theta, delta_T)
    rate = math.log(1.0 / bstar)
    n = max((ln_inv_delta_eff + LOG2) / rate, 2.0)
    for _ in range(200):
        n = (ln_inv_delta_eff + 0.5 * math.log(n) + LOG2) / rate
    ni = int(math.ceil(n))
    while ni * rate < ln_inv_delta_eff + 0.5 * math.log(ni) + LOG2:
        ni += 1
    return ni


def n_floor(theta: float, delta: float) -> int:
    """Unconditional candidate-count floor (T4B Theorem C-iv(a)): no
    delta-valid rule retires an alive-at-``(y*, theta)`` component with
    power >= 1/2 after fewer than ``n_floor`` admitted ledger candidates —
    regardless of pulls, even with exact depth revelation."""
    return int(math.ceil(math.log(1.0 / (2.0 * delta)) / math.log(1.0 / (1.0 - theta))))


def k_w_proof(u: float, ystar: float, T: int) -> int:
    """Proof-grade W bill (T4B Lemma C3): on the Freedman good event, a
    candidate at depth ``u >= 2y*`` fires its non-witness refuter within
    ``ceil((523 beta + 8 Lam_T) * u / (u - y*)^2)`` pulls."""
    beta = 3.0 * math.log(max(T, 2))
    lam = 3.0 * math.log(max(T, 2)) + 2.0 * LOG2
    d = u - ystar
    if d <= 0:
        return 10**12
    return int(math.ceil((523.0 * beta + 8.0 * lam) * u / (d * d)))


def cap_ext_proof(ystar: float, T: int) -> int:
    """Proof-grade extension cap ``K_ext = ceil(2(523 beta + 8 Lam_T)/y*)``:
    dominates ``k_w_proof(u)`` for every ``u >= 2y*``."""
    beta = 3.0 * math.log(max(T, 2))
    lam = 3.0 * math.log(max(T, 2)) + 2.0 * LOG2
    return int(math.ceil(2.0 * (523.0 * beta + 8.0 * lam) / ystar))


def gamma_led(T: int) -> float:
    """Uniform per-trial regret bound ``gamma_led = 2092 beta + 32 Lam_T + 1``
    (T4B Theorem C-iii: ``pulls(u) * u <= gamma_led`` for every depth u,
    fired or capped — the depth cancellation)."""
    beta = 3.0 * math.log(max(T, 2))
    lam = 3.0 * math.log(max(T, 2)) + 2.0 * LOG2
    return 2092.0 * beta + 32.0 * lam + 1.0


def ebh_ln_threshold(k_max: int, delta: float, executed: int) -> float:
    """Online e-BH execution threshold (T3-i corollary): ``ln E`` must reach
    ``ln(K_max / (delta * (executed+1)))``. Delegates to
    ``flr_ebh.threshold_for`` (same formula; parity pinned by test)."""
    return math.log(threshold_for(k_max, delta, executed))


@dataclass(frozen=True)
class RetirementBill:
    """Sharp mean-path bill for retiring an ``(s, 0)``-dead component."""

    n_ret: int
    pulls: int
    per_trial: int


def predict_ret_bill(
    s: float,
    theta: float,
    ystar: float,
    ln_inv_delta_eff: float,
    ln_inv_delta_T: float,
    cap: int,
) -> RetirementBill:
    """Sharp predictor for the ``(s, 0)``-dead retirement bill: trials to
    fire ``n_ret_star`` and pulls ``= n_ret * min(j_star(s), cap)``.
    Mean-path calculus; the seeded MC brackets it (T4B kill test C-E)."""
    n_ret = n_ret_star(theta, ln_inv_delta_eff, 0.0)
    per = min(j_star(s, ystar, ln_inv_delta_T), cap)
    return RetirementBill(n_ret=n_ret, pulls=n_ret * per, per_trial=per)


@dataclass(frozen=True)
class RetirementVerdict:
    """Outcome of a quantile-retirement question at a stopping time.

    ``verdict``: ``safe_kill`` (the quantile certificate crossed its e-BH
    rung), ``refusal`` (forced: ``EvidenceCensored`` below the floor,
    ``NotSeparated`` at an exhausted allowance), or
    ``required_inspection`` (``UncertifiedNeedsMoreHorizon``: the question
    is open — more serial trials are needed; silence is never evidence).
    """

    verdict: str
    reason_code: ReasonCode | None
    question: QuantileQuestion
    n_admissions: int
    drop_count: int
    log_e: float
    ln_threshold: float
    executed_count_before: int

    @property
    def is_safe_kill(self) -> bool:
        return self.verdict == "safe_kill"


def quantile_retirement_verdict(
    question: QuantileQuestion,
    n_admissions: int,
    drop_count: int,
    executed_count_before: int = 0,
    allowance: int | None = None,
) -> RetirementVerdict:
    """Adjudicate a component-retirement question from its settled ledger.

    ``n_admissions``: settled serial ledger trials for this component;
    ``drop_count``: how many recorded ``B = 1``; ``executed_count_before``:
    fleet retirements already executed (the e-BH rung); ``allowance``:
    optional declared trial allowance — exhausting it without a crossing
    forces ``NotSeparated``.

    Order of adjudication: the unconditional floor first (below
    ``n_floor`` the FORCED output is ``EvidenceCensored`` — PC clause 8),
    then the e-BH crossing, then allowance exhaustion, then open.
    """
    if drop_count < 0 or n_admissions < 0 or drop_count > n_admissions:
        raise ValueError(
            f"invalid ledger counts: n_admissions={n_admissions}, drop_count={drop_count}"
        )
    ln_thr = ebh_ln_threshold(question.k_max, question.delta, executed_count_before)
    log_e = (
        ledger_log_e(n_admissions, drop_count, question.b_star)
        if n_admissions > 0
        else -math.inf
    )
    floor = question.n_floor
    if n_admissions < floor:
        return RetirementVerdict(
            verdict="refusal",
            reason_code=ReasonCode.EVIDENCE_CENSORED,
            question=question,
            n_admissions=n_admissions,
            drop_count=drop_count,
            log_e=log_e,
            ln_threshold=ln_thr,
            executed_count_before=executed_count_before,
        )
    if log_e >= ln_thr:
        return RetirementVerdict(
            verdict="safe_kill",
            reason_code=None,
            question=question,
            n_admissions=n_admissions,
            drop_count=drop_count,
            log_e=log_e,
            ln_threshold=ln_thr,
            executed_count_before=executed_count_before,
        )
    if allowance is not None and n_admissions >= allowance:
        return RetirementVerdict(
            verdict="refusal",
            reason_code=ReasonCode.NOT_SEPARATED,
            question=question,
            n_admissions=n_admissions,
            drop_count=drop_count,
            log_e=log_e,
            ln_threshold=ln_thr,
            executed_count_before=executed_count_before,
        )
    return RetirementVerdict(
        verdict="required_inspection",
        reason_code=ReasonCode.UNCERTIFIED_NEEDS_MORE_HORIZON,
        question=question,
        n_admissions=n_admissions,
        drop_count=drop_count,
        log_e=log_e,
        ln_threshold=ln_thr,
        executed_count_before=executed_count_before,
    )


def mean_certificate(*_args: object, **_kwargs: object) -> None:
    """Mean-form retirement certificates are REFUSED as unpriceable.

    T4B Prop M: certifying "the component mean is below m" to any
    tolerance costs ``Omega(1/eta)`` inspections as the alive mass ``eta``
    near the boundary shrinks — the bill diverges, so no honest price
    exists. The quantile form (``quantile_retirement_verdict``) is forced.
    This function exists so the refusal is an API, not a documentation
    footnote."""
    raise MeanCertificateUnpriceable(
        "mean-form retirement certificates are unpriceable (T4B Prop M); "
        "declare a quantile question (y_star, theta) instead"
    )


def _kl_bern(p: float, q: float) -> float:
    eps = 1e-12
    p = min(max(p, eps), 1 - eps)
    q = min(max(q, eps), 1 - eps)
    return p * math.log(p / q) + (1 - p) * math.log((1 - p) / (1 - q))
