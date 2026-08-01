"""Retirement leases under declared drift — the T4D surface ([FM]).

Under any nonzero drift budget an unwindowed ("permanent") retirement
certificate has NO valid reading: the onset drifter falsifies it with
certainty (T4D Theorem D1). Retirement under drift is therefore a LEASE —
"the component's mass at the key scale stays below ``theta`` on
``[tau, tau + t_lease]``" — issued from evidence gathered inside a
declared window at the drift-SHIFTED boundary
``theta~ = theta - rho*(w_r + t_lease)``, with a self-computed lease
length, fleet lease-FLR <= delta, and forced refusals: ``DriftTooFast``
past the design boundary (and unconditionally past
``rho >= theta/n_floor``), ``EvidenceCensoredDrift`` when the declared
cadence cannot host the required trials. A lease is never silently
extended: expiry forces re-arm, and re-certification issues a SUCCESSOR
certificate.

Ported from gating-moonshot @ ``3e0e7cf`` (``src/t4d_witness.py``);
arithmetic preserved verbatim. See ``src/velvet/verdict/UPSTREAM.md``.
Claim-currency: [FM] under the declared drift class DC_TV(rho) on the
component depth law (TV per round; the migration lemma makes the key-scale
mass rho-Lipschitz).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from velvet.verdict.eprocess import ledger_log_e
from velvet.verdict.retirement import (
    QuantileQuestion,
    ReasonCode,
    b_star,
    j_star,
    n_floor,
    n_ret_star,
)

__all__ = [
    "LeaseBill",
    "LeaseDesign",
    "LeaseVerdict",
    "design_cycle",
    "lease_ceiling",
    "lease_verdict",
    "predict_lease_bill",
    "q_of_t",
    "rho_uncond_max",
    "theta_shifted",
]


def q_of_t(t: float, q0: float, t_onset: float, rho: float, q_cap: float) -> float:
    """Mass at the key scale at round ``t`` for an onset drifter: ``q0``
    until ``t_onset``, then ``q0 + rho*(t - t_onset)``, capped at
    ``q_cap``. ``t_onset = -1`` means "never" (static)."""
    if t_onset < 0 or t < t_onset:
        return q0
    return min(q0 + rho * (t - t_onset), q_cap)


def lease_ceiling(theta: float, q0: float, rho: float) -> float:
    """T4D Theorem D1(b): the sharp lease ceiling. A lease of length
    ``>= (theta - q0)/rho`` issued to a component sitting at mass ``q0``
    is violated DETERMINISTICALLY by the onset-at-fire drifter. No
    evidence can support a longer lease. For the dead component
    (``q0 = 0``): ``t_lease < theta/rho``."""
    return (theta - q0) / rho


def theta_shifted(theta: float, rho: float, w_r: float, t_lease: float) -> float:
    """The drift-shifted evidence boundary (T4D Theorem D2): on any
    violation path, every in-term evidence time has
    ``q >= theta - rho*(w_r + t_lease)``."""
    return theta - rho * (w_r + t_lease)


def rho_uncond_max(theta: float, delta: float) -> float:
    """T4D Theorem D4: holding a lease at time t against DC_TV(rho)
    requires ``>= n_floor`` admissions inside the trailing ``theta/rho``
    rounds (staleness: the pre-onset likelihood ratio is exactly 1) and
    admissions are <= 1 per round. Past ``rho >= theta/n_floor`` NO
    delta-valid scheme retains retirement power at all: total refusal is
    forced."""
    return theta / n_floor(theta, delta)


@dataclass(frozen=True)
class LeaseDesign:
    """Canonical split design for the windowed cycle ledger (T4D D2/D3).

    ``theta_shifted``: the in-term evidence boundary; ``n_led``: ledger
    trials required per term (deterministic all-drops crossing at the
    shifted boundary); ``w_r``: evidence-term length in rounds;
    ``t_lease``: the lease length bought by a firing; ``cycle`` =
    ``w_r + t_lease``; ``rho_max``: the design's feasibility boundary —
    past it the forced status is ``DriftTooFast``.
    """

    theta_shifted: float
    n_led: int
    w_r: int
    t_lease: int
    cycle: int
    rho_max: float
    l_eff: float
    b_star_shifted: float
    feasible: bool
    status: str

    @property
    def forced_refusal(self) -> ReasonCode | None:
        return None if self.feasible else ReasonCode.DRIFT_TOO_FAST


def design_cycle(
    theta: float,
    rho: float,
    delta: float,
    k_slots: int,
    delta_T: float,
    spacing: float,
    w_mult: float = 1.5,
    split: float = 0.5,
) -> LeaseDesign:
    """Solve the canonical split design: ``theta~ = split*theta``, with the
    evidence term ``w_r`` sized to host ``n_led`` trials at the declared
    cadence ``spacing`` (rounds per trial) with slack ``w_mult``, and
    ``rho*(w_r + t_lease) <= theta - theta~``. Fixed (executed-independent)
    fleet threshold ``ln(k_slots/delta)`` — the hardest e-BH rung,
    conservative. Infeasible (``t_lease < 1``) => ``DriftTooFast``."""
    thetat = split * theta
    l_eff = math.log(k_slots / delta)
    n_led = n_ret_star(thetat, l_eff, delta_T)
    w_r = int(math.ceil(w_mult * n_led * spacing))
    budget = (theta - thetat) / rho
    t_lease = int(math.floor(budget)) - w_r
    rho_max = (theta - thetat) / (w_r + 1.0)
    feasible = t_lease >= 1
    return LeaseDesign(
        theta_shifted=thetat,
        n_led=n_led,
        w_r=w_r,
        t_lease=t_lease,
        cycle=w_r + t_lease,
        rho_max=rho_max,
        l_eff=l_eff,
        b_star_shifted=b_star(thetat, delta_T),
        feasible=feasible,
        status="OK" if feasible else "DriftTooFast",
    )


@dataclass(frozen=True)
class LeaseBill:
    """Per-cycle and amortized maintenance bill for holding a retirement
    under drift (T4D Theorem D3 — the ``Theta~(rho/theta^2)`` maintenance
    law). ``amortized`` is ``inf`` when the design refuses."""

    design: LeaseDesign
    per_trial_pulls: int | None
    spacing: float | None
    per_cycle_pulls: int | None
    per_cycle_regret: float | None
    cycle_realized: int | None
    amortized: float


def predict_lease_bill(
    s_depth: float,
    ystar: float,
    theta: float,
    rho: float,
    delta: float,
    k_slots: int,
    delta_T: float,
    wait: float,
    w_mult: float = 1.5,
    split: float = 0.5,
) -> LeaseBill:
    """Sharp per-cycle and amortized bill predictor for maintaining the
    retirement of an ``(s, 0)``-dead component under drift budget ``rho``.
    Mean-path calculus: per-trial pulls ``j_star(s)``, spacing =
    ``wait + pulls``, per-cycle trials ``n_led`` (deterministic all-drops
    crossing at the shifted boundary), amortized regret per round =
    per-cycle regret / realized cycle."""
    l_t = math.log(1.0 / delta_T)
    per_pulls = j_star(s_depth, ystar, l_t)
    spacing = wait + per_pulls
    design = design_cycle(theta, rho, delta, k_slots, delta_T, spacing, w_mult=w_mult, split=split)
    if not design.feasible:
        return LeaseBill(
            design=design,
            per_trial_pulls=None,
            spacing=None,
            per_cycle_pulls=None,
            per_cycle_regret=None,
            cycle_realized=None,
            amortized=float("inf"),
        )
    per_cycle_pulls = design.n_led * per_pulls
    per_cycle_regret = per_cycle_pulls * s_depth
    # Validity uses the DECLARED w_r (worst-case evidence-to-lease-end span,
    # which sets theta~); the realized cycle is shorter — evidence ends at
    # the deterministic firing, not at the window edge.
    cycle_real = design.n_led * int(spacing) + design.t_lease
    return LeaseBill(
        design=design,
        per_trial_pulls=per_pulls,
        spacing=spacing,
        per_cycle_pulls=per_cycle_pulls,
        per_cycle_regret=per_cycle_regret,
        cycle_realized=cycle_real,
        amortized=per_cycle_regret / cycle_real,
    )


@dataclass(frozen=True)
class LeaseVerdict:
    """Outcome of a lease-retirement question at a stopping time.

    A ``safe_kill`` here licenses a LEASE of ``lease_rounds`` rounds from
    the issuing round — never permanence. Expiry forces re-arm; a
    successor certificate (never an extension) continues the retirement.
    """

    verdict: str
    reason_code: ReasonCode | None
    question: QuantileQuestion
    design: LeaseDesign
    n_admissions_in_term: int
    drop_count_in_term: int
    log_e: float
    ln_threshold: float
    lease_rounds: int | None

    @property
    def is_safe_kill(self) -> bool:
        return self.verdict == "safe_kill"


def lease_verdict(
    question: QuantileQuestion,
    rho: float,
    design: LeaseDesign,
    n_admissions_in_term: int,
    drop_count_in_term: int,
    term_elapsed_rounds: int,
) -> LeaseVerdict:
    """Adjudicate a lease question from the current evidence term's ledger.

    Forced refusals first: the unconditional staleness ceiling
    (``rho >= rho_uncond_max`` — T4D D4) and the design boundary
    (``DriftTooFast``); a term that rolled over hosting fewer than
    ``n_led`` trials is a cadence shortfall (``EvidenceCensoredDrift``).
    A crossing of the shifted-boundary ledger at the fleet threshold
    issues the lease. Otherwise the question is open
    (``UncertifiedNeedsMoreHorizon``)."""
    if drop_count_in_term < 0 or drop_count_in_term > n_admissions_in_term:
        raise ValueError(
            "invalid term ledger counts: "
            f"n={n_admissions_in_term}, drops={drop_count_in_term}"
        )
    log_e = (
        ledger_log_e(n_admissions_in_term, drop_count_in_term, design.b_star_shifted)
        if n_admissions_in_term > 0
        else -math.inf
    )

    def _verdict(
        verdict: str, reason: ReasonCode | None, lease_rounds: int | None
    ) -> LeaseVerdict:
        return LeaseVerdict(
            verdict=verdict,
            reason_code=reason,
            question=question,
            design=design,
            n_admissions_in_term=n_admissions_in_term,
            drop_count_in_term=drop_count_in_term,
            log_e=log_e,
            ln_threshold=design.l_eff,
            lease_rounds=lease_rounds,
        )

    if rho >= rho_uncond_max(question.theta, question.delta):
        return _verdict("refusal", ReasonCode.DRIFT_TOO_FAST, None)
    if not design.feasible:
        return _verdict("refusal", ReasonCode.DRIFT_TOO_FAST, None)
    if log_e >= design.l_eff:
        return _verdict("safe_kill", None, design.t_lease)
    if term_elapsed_rounds > design.w_r:
        if 0 < n_admissions_in_term < design.n_led:
            return _verdict("refusal", ReasonCode.EVIDENCE_CENSORED_DRIFT, None)
        # A full term without a crossing is an honest no-certificate term.
        return _verdict("required_inspection", ReasonCode.NOT_SEPARATED, None)
    return _verdict(
        "required_inspection", ReasonCode.UNCERTIFIED_NEEDS_MORE_HORIZON, None
    )
