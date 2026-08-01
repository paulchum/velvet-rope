"""Certified Max-DE helpers for posterior-typed Velvet candidates."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

import numpy as np

from velvet.research.bernoulli import (
    BetaBernoulliPosterior,
    _positive_part_second_moment_scalar,
)
from velvet.research.dirichlet_categorical import DirichletCategoricalPosterior
from velvet.research.gamma_rate import (
    GammaRateAdmissionDecision as GammaRateAdmissionDecision,
)
from velvet.research.gamma_rate import (
    GammaRateBounds as GammaRateBounds,
)
from velvet.research.gamma_rate import (
    GammaRateCertificate as GammaRateCertificate,
)
from velvet.research.gamma_rate import (
    GammaRateCertificateMethod as GammaRateCertificateMethod,
)
from velvet.research.gamma_rate import (
    GammaRateMonteCarloLCB as GammaRateMonteCarloLCB,
)
from velvet.research.gamma_rate import (
    GammaRatePositivePartMoments as GammaRatePositivePartMoments,
)
from velvet.research.gamma_rate import (
    GammaRatePosteriorSpec as GammaRatePosteriorSpec,
)
from velvet.research.gamma_rate import (
    certified_gamma_rate_candidate as certified_gamma_rate_candidate,
)
from velvet.serialization import canonical_hash_sha256
from velvet.types import (
    ActionType,
    CandidateAction,
    CandidateSource,
    CertificateEffect,
    CertificateEvidence,
    CertificateOutcome,
    CompensatorStep,
    certificate_effect_safe_upper_bound,
)

DEFAULT_MAX_DE_THEOREM_REFS: tuple[str, ...] = (
    "docs/math/lower_certificates_for_max_de_inspection_theorem.txt",
    "docs/math/O1_Martingale_Maximal_Certificates_for_Safe_Lockout.txt",
    "docs/math/certified_max_de_theorem.txt",
    "docs/math/information_budget_for_martingale_supremum_exploration.txt",
)

DEFAULT_DIRICHLET_CATEGORICAL_THEOREM_REFS: tuple[str, ...] = (
    "docs/math/dirichlet_categorical_max_de_certificates.txt",
    "docs/math/dirichlet_categorical_upper_certificate.txt",
    "docs/math/O1_Martingale_Maximal_Certificates_for_Safe_Lockout.txt",
    "docs/math/certified_max_de_theorem.txt",
    "docs/math/information_budget_for_martingale_supremum_exploration.txt",
)

CERTIFICATE_SCHEMA_VERSION = "velvet.certificate_evidence.v2"


def _dirichlet_scalable_upper_metadata(
    payoff_level_count: int,
    theorem_refs: Sequence[str],
) -> dict[str, Any]:
    exact_reduction = "beta_bernoulli" if payoff_level_count == 2 else None
    if payoff_level_count <= 3:
        moment_terms = (
            "B_v",
            "m_v=G_1(gamma,c;v)",
            "q_v=G_2(gamma,c;v+m_v)",
            "log_envelope",
            "one_sided_l2_envelope",
        )
        q_v_source = "positive_part_second_moment"
        quadrature_free = payoff_level_count <= 2
    else:
        moment_terms = (
            "B_v",
            "raw_E_X",
            "raw_E_X2",
            "E[(X-v)^2]_majorant",
            "variance_fallback",
        )
        q_v_source = "raw_moment_fallback"
        quadrature_free = True
    return {
        "method": "moment",
        "quadrature_free": quadrature_free,
        "exact_reduction": exact_reduction,
        "q_v_source": q_v_source,
        "moment_terms": list(moment_terms),
        "theorem_refs": [str(item) for item in theorem_refs],
    }


@dataclass(frozen=True)
class BetaBernoulliPosteriorSpec:
    """Runtime-facing posterior spec for Velvet's Max-DE certificate engine."""

    arm_id: str
    alpha: float
    beta: float
    baseline: float
    lambda_value: float
    lookback_horizon: int = 3
    delight_scale: float = 1.0
    liability_mode: str = "posterior_certificate"
    theorem_refs: Sequence[str] = DEFAULT_MAX_DE_THEOREM_REFS
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def certificate(self) -> CertificateEvidence:
        return build_beta_bernoulli_certificate(
            arm_id=self.arm_id,
            alpha=self.alpha,
            beta=self.beta,
            baseline=self.baseline,
            lambda_value=self.lambda_value,
            lookback_horizon=self.lookback_horizon,
            delight_scale=self.delight_scale,
            liability_mode=self.liability_mode,
            theorem_refs=self.theorem_refs,
        )

    def candidate(
        self,
        action_type: ActionType | str,
        *,
        description: str = "",
        cost_overrides: Mapping[str, float] | None = None,
        risk_overrides: Mapping[str, float] | None = None,
        parameters: Mapping[str, Any] | None = None,
        source: CandidateSource = CandidateSource.SCENARIO,
    ) -> CandidateAction:
        """Return a Velvet candidate carrying computed Max-DE evidence."""

        metadata = {
            "posterior_family": "beta_bernoulli",
            "posterior_alpha": self.alpha,
            "posterior_beta": self.beta,
            "max_de_engine": "certified_max_de_v1",
            "price_source": "explicit_lambda",
            **dict(self.metadata),
        }
        return CandidateAction(
            ActionType(str(action_type)),
            description=description,
            certificate=self.certificate(),
            cost_overrides=dict(cost_overrides or {}),
            risk_overrides=dict(risk_overrides or {}),
            metadata=metadata,
            source=source,
            parameters=dict(parameters or {}),
        )


@dataclass(frozen=True)
class DirichletCategoricalPosteriorSpec:
    """Runtime-facing Dirichlet-categorical Max-DE posterior spec."""

    arm_id: str
    alpha: Sequence[float]
    payoffs: Sequence[float]
    baseline: float
    lambda_value: float
    lookback_horizon: int = 3
    delight_scale: float = 1.0
    liability_mode: str = "posterior_certificate"
    theorem_refs: Sequence[str] = DEFAULT_DIRICHLET_CATEGORICAL_THEOREM_REFS
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def certificate(self) -> CertificateEvidence:
        return build_dirichlet_categorical_certificate(
            arm_id=self.arm_id,
            alpha=self.alpha,
            payoffs=self.payoffs,
            baseline=self.baseline,
            lambda_value=self.lambda_value,
            lookback_horizon=self.lookback_horizon,
            delight_scale=self.delight_scale,
            liability_mode=self.liability_mode,
            theorem_refs=self.theorem_refs,
        )

    def candidate(
        self,
        action_type: ActionType | str,
        *,
        description: str = "",
        cost_overrides: Mapping[str, float] | None = None,
        risk_overrides: Mapping[str, float] | None = None,
        parameters: Mapping[str, Any] | None = None,
        source: CandidateSource = CandidateSource.SCENARIO,
    ) -> CandidateAction:
        """Return a Velvet candidate carrying computed Dirichlet Max-DE evidence."""

        posterior = DirichletCategoricalPosterior.from_sequences(self.alpha, self.payoffs)
        grouped_alpha, payoff_levels = posterior.grouped_parameters()
        metadata = {
            "posterior_family": "dirichlet_categorical",
            "posterior_alpha": [float(value) for value in self.alpha],
            "posterior_payoffs": [float(value) for value in self.payoffs],
            "payoff_level_alpha": [float(value) for value in grouped_alpha],
            "payoff_levels": [float(value) for value in payoff_levels],
            "category_count": len(self.alpha),
            "max_de_engine": "certified_max_de_v1",
            "max_de_upper_certificate": {
                "method": "exact",
                "quadrature_free": False,
                "exact_reduction": "beta_bernoulli" if len(payoff_levels) == 2 else None,
                "moment_terms": ["B_v", "m_v", "s_v", "variance"],
                "theorem_refs": [str(item) for item in self.theorem_refs],
            },
            "max_de_scalable_upper_certificate": _dirichlet_scalable_upper_metadata(
                len(payoff_levels),
                self.theorem_refs,
            ),
            "price_source": "explicit_lambda",
            **dict(self.metadata),
        }
        return CandidateAction(
            ActionType(str(action_type)),
            description=description,
            certificate=self.certificate(),
            cost_overrides=dict(cost_overrides or {}),
            risk_overrides=dict(risk_overrides or {}),
            metadata=metadata,
            source=source,
            parameters=dict(parameters or {}),
        )


def build_beta_bernoulli_certificate(
    *,
    arm_id: str,
    alpha: float,
    beta: float,
    baseline: float,
    lambda_value: float,
    lookback_horizon: int = 3,
    delight_scale: float = 1.0,
    liability_mode: str = "posterior_certificate",
    theorem_refs: Sequence[str] = DEFAULT_MAX_DE_THEOREM_REFS,
    reserve_price: float | None = None,
    value_numeraire: str | None = None,
    upside_value_scale: int | None = None,
    resource_scope: str = "posterior_option",
    write_footprint: Sequence[str] = (),
    declared_write_set_hash: str | None = None,
    dependence_group: str | None = None,
    dependence_kind: str = "unspecified",
    covariance_reserve_gamma: float | None = None,
    correlation_bound: float | None = None,
    filtration_hash: str | None = None,
    filtration_index: int = 0,
    adapted: bool = True,
    adaptation_marker: str | None = "max_de_posterior_filtration",
    write_conflict_policy: str = "exclusive",
    commutativity_certificate_hash: str | None = None,
    continuation_condition_hash: str | None = None,
) -> CertificateEvidence:
    """Compute a Max-DE certificate instead of hand-authoring outcome fields."""

    if alpha <= 0.0 or beta <= 0.0:
        raise ValueError("alpha and beta must be positive")
    if not 0.0 <= baseline <= 1.0:
        raise ValueError("baseline must be in [0, 1]")
    if lookback_horizon < 0:
        raise ValueError("lookback_horizon must be non-negative")
    if delight_scale <= 0.0:
        raise ValueError("delight_scale must be positive")
    if lambda_value < 0.0:
        raise ValueError("lambda_value must be non-negative")

    posterior = BetaBernoulliPosterior(
        alpha=np.array([float(alpha)], dtype=np.float64),
        beta=np.array([float(beta)], dtype=np.float64),
    )
    expected_improvement = float(posterior.expected_improvement(baseline)[0])
    lower = float(posterior.lower_certificate(baseline, lookback_horizon)[0])
    second_moment = float(_positive_part_second_moment_scalar(alpha, beta, baseline))
    variance = max(second_moment - expected_improvement**2, 0.0)
    max_payoff = max(1.0 - float(baseline), 0.0)
    effect = _certificate_effect(
        max_payoff=max_payoff,
        mean_bound=expected_improvement,
        variance_bound=variance,
        second_moment_bound=second_moment,
        resource_scope=resource_scope,
        write_footprint=write_footprint,
        declared_write_set_hash=declared_write_set_hash,
        dependence_group=dependence_group,
        dependence_kind=dependence_kind,
        covariance_reserve_gamma=covariance_reserve_gamma,
        correlation_bound=correlation_bound,
        filtration_hash=filtration_hash,
        filtration_index=filtration_index,
        adapted=adapted,
        adaptation_marker=adaptation_marker,
        write_conflict_policy=write_conflict_policy,
        commutativity_certificate_hash=commutativity_certificate_hash,
        continuation_condition_hash=continuation_condition_hash,
        hash_material={
            "family": "beta_bernoulli",
            "arm_id": arm_id,
            "alpha": float(alpha),
            "beta": float(beta),
            "baseline": float(baseline),
            "lookback_horizon": int(lookback_horizon),
        },
    )
    upper = certificate_effect_safe_upper_bound(
        mean_bound=effect.mean_bound,
        max_payoff=effect.max_payoff,
        variance_bound=effect.variance() or 0.0,
    )
    threshold = float(lambda_value) / float(delight_scale)
    if lower >= threshold:
        outcome = CertificateOutcome.INSPECT
    elif upper < threshold:
        outcome = CertificateOutcome.LOCKOUT
    else:
        outcome = CertificateOutcome.REFINEMENT
    compensator = posterior.compensator_step(
        0,
        baseline=baseline,
        horizon=lookback_horizon,
    )
    return CertificateEvidence(
        schema_version=CERTIFICATE_SCHEMA_VERSION,
        family="beta_bernoulli",
        arm_id=arm_id,
        baseline=float(baseline),
        lookback_horizon=int(lookback_horizon),
        delight_scale=float(delight_scale),
        liability_price=float(lambda_value),
        threshold=threshold,
        inspection_lower_bound=lower,
        safe_upper_bound=upper,
        outcome=outcome,
        liability_mode=liability_mode,
        typed_effect=effect,
        compensator_step=CompensatorStep.from_dict(compensator.to_dict()),
        theorem_refs=tuple(str(item) for item in theorem_refs),
        reserve_price=reserve_price,
        value_numeraire=value_numeraire,
        upside_value_scale=upside_value_scale,
    )


def build_dirichlet_categorical_certificate(
    *,
    arm_id: str,
    alpha: Sequence[float],
    payoffs: Sequence[float],
    baseline: float,
    lambda_value: float,
    lookback_horizon: int = 3,
    delight_scale: float = 1.0,
    liability_mode: str = "posterior_certificate",
    theorem_refs: Sequence[str] = DEFAULT_DIRICHLET_CATEGORICAL_THEOREM_REFS,
    resource_scope: str = "posterior_option",
    write_footprint: Sequence[str] = (),
    declared_write_set_hash: str | None = None,
    dependence_group: str | None = None,
    dependence_kind: str = "unspecified",
    covariance_reserve_gamma: float | None = None,
    correlation_bound: float | None = None,
    filtration_hash: str | None = None,
    filtration_index: int = 0,
    adapted: bool = True,
    adaptation_marker: str | None = "max_de_posterior_filtration",
    write_conflict_policy: str = "exclusive",
    commutativity_certificate_hash: str | None = None,
    continuation_condition_hash: str | None = None,
) -> CertificateEvidence:
    """Compute a bounded Dirichlet-categorical Max-DE certificate."""

    if lookback_horizon < 0:
        raise ValueError("lookback_horizon must be non-negative")
    if delight_scale <= 0.0:
        raise ValueError("delight_scale must be positive")
    if lambda_value < 0.0:
        raise ValueError("lambda_value must be non-negative")
    if not np.isfinite(baseline):
        raise ValueError("baseline must be finite")

    posterior = DirichletCategoricalPosterior.from_sequences(alpha, payoffs)
    expected_improvement = float(posterior.expected_improvement(baseline))
    lower = float(posterior.lower_certificate(baseline, lookback_horizon))
    second_moment = float(posterior.second_moment(baseline))
    variance = max(second_moment - expected_improvement**2, 0.0)
    _, payoff_levels = posterior.grouped_parameters()
    max_payoff = max(float(payoff_levels[-1]) - float(baseline), 0.0)
    effect = _certificate_effect(
        max_payoff=max_payoff,
        mean_bound=expected_improvement,
        variance_bound=variance,
        second_moment_bound=second_moment,
        resource_scope=resource_scope,
        write_footprint=write_footprint,
        declared_write_set_hash=declared_write_set_hash,
        dependence_group=dependence_group,
        dependence_kind=dependence_kind,
        covariance_reserve_gamma=covariance_reserve_gamma,
        correlation_bound=correlation_bound,
        filtration_hash=filtration_hash,
        filtration_index=filtration_index,
        adapted=adapted,
        adaptation_marker=adaptation_marker,
        write_conflict_policy=write_conflict_policy,
        commutativity_certificate_hash=commutativity_certificate_hash,
        continuation_condition_hash=continuation_condition_hash,
        hash_material={
            "family": "dirichlet_categorical",
            "arm_id": arm_id,
            "alpha": [float(value) for value in alpha],
            "payoffs": [float(value) for value in payoffs],
            "baseline": float(baseline),
            "lookback_horizon": int(lookback_horizon),
        },
    )
    upper = certificate_effect_safe_upper_bound(
        mean_bound=effect.mean_bound,
        max_payoff=effect.max_payoff,
        variance_bound=effect.variance() or 0.0,
    )
    threshold = float(lambda_value) / float(delight_scale)
    if lower >= threshold:
        outcome = CertificateOutcome.INSPECT
    elif upper < threshold:
        outcome = CertificateOutcome.LOCKOUT
    else:
        outcome = CertificateOutcome.REFINEMENT
    return CertificateEvidence(
        schema_version=CERTIFICATE_SCHEMA_VERSION,
        family="dirichlet_categorical",
        arm_id=arm_id,
        baseline=float(baseline),
        lookback_horizon=int(lookback_horizon),
        delight_scale=float(delight_scale),
        liability_price=float(lambda_value),
        threshold=threshold,
        inspection_lower_bound=lower,
        safe_upper_bound=upper,
        outcome=outcome,
        liability_mode=liability_mode,
        typed_effect=effect,
        compensator_step=None,
        theorem_refs=tuple(str(item) for item in theorem_refs),
    )


def _certificate_effect(
    *,
    max_payoff: float,
    mean_bound: float,
    variance_bound: float,
    second_moment_bound: float,
    resource_scope: str,
    write_footprint: Sequence[str],
    declared_write_set_hash: str | None,
    dependence_group: str | None,
    dependence_kind: str,
    covariance_reserve_gamma: float | None,
    correlation_bound: float | None,
    filtration_hash: str | None,
    filtration_index: int,
    adapted: bool,
    adaptation_marker: str | None,
    write_conflict_policy: str,
    commutativity_certificate_hash: str | None,
    continuation_condition_hash: str | None,
    hash_material: Mapping[str, Any],
) -> CertificateEffect:
    return CertificateEffect(
        max_payoff=float(max_payoff),
        mean_bound=float(mean_bound),
        variance_bound=float(variance_bound),
        second_moment_bound=float(second_moment_bound),
        resource_scope=str(resource_scope),
        write_footprint=tuple(str(item) for item in write_footprint),
        declared_write_set_hash=declared_write_set_hash,
        dependence_group=dependence_group,
        correlation_bound=correlation_bound,
        covariance_reserve_gamma=covariance_reserve_gamma,
        dependence_kind=dependence_kind,
        filtration_hash=filtration_hash
        or canonical_hash_sha256(
            {
                "typed_effect_filtration": hash_material,
            }
        ),
        filtration_index=int(filtration_index),
        adapted=bool(adapted),
        adaptation_marker=adaptation_marker,
        write_conflict_policy=write_conflict_policy,
        commutativity_certificate_hash=commutativity_certificate_hash,
        continuation_condition_hash=continuation_condition_hash,
    )


def build_reserve_priced_beta_bernoulli_certificate(
    *,
    arm_id: str,
    alpha: float,
    beta: float,
    baseline: float,
    reserve_price: int,
    upside_value_scale: int,
    value_numeraire: str = "authority_budget_units",
    lookback_horizon: int = 3,
    delight_scale: float = 1.0,
    liability_mode: str = "posterior_certificate",
    theorem_refs: Sequence[str] = DEFAULT_MAX_DE_THEOREM_REFS,
) -> CertificateEvidence:
    """Compute a Max-DE certificate priced by the action's downside reserve."""

    if reserve_price < 0:
        raise ValueError("reserve_price must be non-negative")
    if upside_value_scale <= 0:
        raise ValueError("upside_value_scale must be positive")
    lambda_value = float(reserve_price) / float(upside_value_scale)
    certificate = build_beta_bernoulli_certificate(
        arm_id=arm_id,
        alpha=alpha,
        beta=beta,
        baseline=baseline,
        lambda_value=lambda_value,
        lookback_horizon=lookback_horizon,
        delight_scale=delight_scale,
        liability_mode=liability_mode,
        theorem_refs=theorem_refs,
        reserve_price=float(reserve_price),
        value_numeraire=value_numeraire,
        upside_value_scale=int(upside_value_scale),
    )
    threshold = float(reserve_price) / (float(upside_value_scale) * float(delight_scale))
    return replace(certificate, threshold=threshold)


def certified_dirichlet_categorical_candidate(
    action_type: ActionType | str,
    *,
    arm_id: str,
    alpha: Sequence[float],
    payoffs: Sequence[float],
    baseline: float,
    lambda_value: float,
    description: str = "",
    lookback_horizon: int = 3,
    delight_scale: float = 1.0,
    liability_mode: str = "posterior_certificate",
    cost_overrides: Mapping[str, float] | None = None,
    risk_overrides: Mapping[str, float] | None = None,
    metadata: Mapping[str, Any] | None = None,
    parameters: Mapping[str, Any] | None = None,
    source: CandidateSource = CandidateSource.SCENARIO,
) -> CandidateAction:
    """Convenience wrapper for Dirichlet-categorical certified candidates."""

    spec = DirichletCategoricalPosteriorSpec(
        arm_id=arm_id,
        alpha=alpha,
        payoffs=payoffs,
        baseline=baseline,
        lambda_value=lambda_value,
        lookback_horizon=lookback_horizon,
        delight_scale=delight_scale,
        liability_mode=liability_mode,
        metadata=dict(metadata or {}),
    )
    return spec.candidate(
        action_type,
        description=description,
        cost_overrides=cost_overrides,
        risk_overrides=risk_overrides,
        parameters=parameters,
        source=source,
    )


def certified_beta_bernoulli_candidate(
    action_type: ActionType | str,
    *,
    arm_id: str,
    alpha: float,
    beta: float,
    baseline: float,
    lambda_value: float,
    description: str = "",
    lookback_horizon: int = 3,
    delight_scale: float = 1.0,
    liability_mode: str = "posterior_certificate",
    cost_overrides: Mapping[str, float] | None = None,
    risk_overrides: Mapping[str, float] | None = None,
    metadata: Mapping[str, Any] | None = None,
    parameters: Mapping[str, Any] | None = None,
    source: CandidateSource = CandidateSource.SCENARIO,
) -> CandidateAction:
    """Convenience wrapper for callers that do not need to keep the spec."""

    spec = BetaBernoulliPosteriorSpec(
        arm_id=arm_id,
        alpha=alpha,
        beta=beta,
        baseline=baseline,
        lambda_value=lambda_value,
        lookback_horizon=lookback_horizon,
        delight_scale=delight_scale,
        liability_mode=liability_mode,
        metadata=dict(metadata or {}),
    )
    return spec.candidate(
        action_type,
        description=description,
        cost_overrides=cost_overrides,
        risk_overrides=risk_overrides,
        parameters=parameters,
        source=source,
    )
