"""Certified Decisions: the Velvet verdict layer.

Every irreversible decision about an agent, tool route, variant, or expert —
retire it, kill it, permanently lock it out — must be answered by a verdict
``{safe_kill | required_inspection | refusal}`` that is delta-bounded under
stated hypotheses, priced, expiring under drift, and (via
``velvet.verdict.certificate``) signed and ledgered.

Claim-currency doctrine (inherited from the Max-DE corpus; see
``src/velvet/verdict/UPSTREAM.md``): Bayesian-predictive [BP], fixed-mean
frequentist [FM], and simulation [SIM] quantities are never blended, averaged,
or interconverted. A [BP] ``safe_kill`` is a statement about the modeled
posterior-predictive kernel at level delta, never a truth claim about the
retired arm.

Module map:

- ``finite_horizon`` — Theorem V host-aware finite-window verdicts with
  inspection/tail prices ([BP]).
- ``rescue`` — protected-floor and anchor-tail rescue-risk bounds ([BP]).
- ``truncation`` — pointwise protected-anchor lockout certificates ([BP]).
- ``drift_expiry`` — windowed delta-safe lockout under bounded drift with a
  computable expiry horizon and forced recertification ([BP]).
- ``rescue_adjudication`` — Convention A predictive rescue-event e-values and
  the fleet accountant ([BP]).
- ``fleet`` — same-snapshot anchor-tail e-BH portfolio verdicts ([BP]).
- ``audit_glr`` — anytime-valid KL/GLR retirement audit, Family M exact
  thresholds, N_cert inspection quotes ([FM]).
- ``flr_ebh`` — online e-BH gate holding the fleet false-lockout rate at or
  below delta under arbitrary dependence ([FM]).
- ``retirement_frontier`` — the d(p, delta)/kl lower bound on inspections any
  useful retirement rule must pay ([FM]).

Certified Exploration surface (moonshot corpus port; see UPSTREAM.md):

- ``eprocess`` — first-class anytime e-processes: ledger, fixed-scale W,
  pair, half-null; validity is posterior-free ([FM]).
- ``retirement`` — quantile component retirement at a declared (y*, theta)
  key with the unconditional evidence floor; mean certificates refused as
  unpriceable; forced refusals are outputs ([FM]).
- ``lease`` — retirement leases under a declared drift budget: shifted
  evidence boundary, self-computed expiry, DriftTooFast /
  EvidenceCensoredDrift forced refusals, re-arm as successor ([FM]).
"""

from __future__ import annotations

from velvet.verdict.audit_glr import (
    AnytimeGLRAudit,
    HoeffdingAudit,
    e_value,
    log_e_value,
    make_audit,
    n_cert,
)
from velvet.verdict.certificate import (
    VerdictVerification,
    certificate_from_drift_verdict,
    certificate_from_finite_horizon,
    issue_verdict_certificate,
    verdict_certificate_hash,
    verify_verdict_certificate,
)
from velvet.verdict.drift_expiry import (
    Verdict as DriftVerdict,
)
from velvet.verdict.drift_expiry import (
    check_expiry,
    expiry_horizon_That,
    issue_verdict,
    recertify,
)
from velvet.verdict.eprocess import (
    EProcess,
    FixedScaleWProcess,
    HalfNullEProcess,
    LedgerEProcess,
    PairGLREProcess,
    eprocess_threshold,
    ledger_log_e,
)
from velvet.verdict.finite_horizon import (
    FiniteHorizonVerdict,
    InspectionPrice,
    TailPrice,
    Verdict,
    VerdictMethod,
    bounded_drift_penalty,
    expected_rounds_to_gate_crossing,
    finite_horizon_verdict,
    max_certifiable_horizon,
)
from velvet.verdict.fleet import (
    FleetCertificate,
    FleetDecision,
    FleetVerdict,
    anchor_tail_fleet_certificate,
    fleet_verdict,
    refusal_fleet_certificate,
)
from velvet.verdict.flr_ebh import (
    BudgetState,
    DecisionProposal,
    ELondGate,
    FLREGate,
    RefusalReason,
    VerdictRecord,
    realized_flr,
    threshold_for,
)
from velvet.verdict.flr_ebh import Verdict as FleetGateOutcome
from velvet.verdict.lease import (
    LeaseBill,
    LeaseDesign,
    LeaseVerdict,
    design_cycle,
    lease_ceiling,
    lease_verdict,
    predict_lease_bill,
    rho_uncond_max,
    theta_shifted,
)
from velvet.verdict.rescue import (
    protected_threshold,
    rescue_risk_bound,
    rescue_risk_log_bound,
)
from velvet.verdict.retirement import (
    MeanCertificateUnpriceable,
    QuantileQuestion,
    ReasonCode,
    RetirementBill,
    RetirementVerdict,
    ebh_ln_threshold,
    mean_certificate,
    n_floor,
    n_ret_star,
    predict_ret_bill,
    quantile_retirement_verdict,
)
from velvet.verdict.retirement_frontier import (
    retirement_regret_lower_bound,
    retirement_sample_lower_bound,
)
from velvet.verdict.service import DeploymentResult, VerdictCertificateService
from velvet.verdict.truncation import (
    CertificateDecision,
    CertificationStatus,
    certify_lockout,
)

__all__ = [
    "AnytimeGLRAudit",
    "BudgetState",
    "CertificateDecision",
    "CertificationStatus",
    "DecisionProposal",
    "DeploymentResult",
    "DriftVerdict",
    "ELondGate",
    "EProcess",
    "FLREGate",
    "FiniteHorizonVerdict",
    "FixedScaleWProcess",
    "FleetCertificate",
    "FleetDecision",
    "FleetGateOutcome",
    "FleetVerdict",
    "HalfNullEProcess",
    "HoeffdingAudit",
    "InspectionPrice",
    "LeaseBill",
    "LeaseDesign",
    "LeaseVerdict",
    "LedgerEProcess",
    "MeanCertificateUnpriceable",
    "PairGLREProcess",
    "QuantileQuestion",
    "ReasonCode",
    "RefusalReason",
    "RetirementBill",
    "RetirementVerdict",
    "TailPrice",
    "Verdict",
    "VerdictCertificateService",
    "VerdictMethod",
    "VerdictRecord",
    "VerdictVerification",
    "anchor_tail_fleet_certificate",
    "bounded_drift_penalty",
    "certificate_from_drift_verdict",
    "certificate_from_finite_horizon",
    "certify_lockout",
    "check_expiry",
    "design_cycle",
    "e_value",
    "ebh_ln_threshold",
    "eprocess_threshold",
    "expected_rounds_to_gate_crossing",
    "expiry_horizon_That",
    "finite_horizon_verdict",
    "fleet_verdict",
    "issue_verdict",
    "issue_verdict_certificate",
    "lease_ceiling",
    "lease_verdict",
    "ledger_log_e",
    "log_e_value",
    "make_audit",
    "max_certifiable_horizon",
    "mean_certificate",
    "n_cert",
    "n_floor",
    "n_ret_star",
    "predict_lease_bill",
    "predict_ret_bill",
    "protected_threshold",
    "quantile_retirement_verdict",
    "realized_flr",
    "recertify",
    "rho_uncond_max",
    "theta_shifted",
    "refusal_fleet_certificate",
    "rescue_risk_bound",
    "rescue_risk_log_bound",
    "retirement_regret_lower_bound",
    "retirement_sample_lower_bound",
    "threshold_for",
    "verdict_certificate_hash",
    "verify_verdict_certificate",
]
