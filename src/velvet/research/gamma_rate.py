"""Gamma-rate Max-DE certificates for positive rate/intensity posteriors."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite, sqrt
from typing import Any, Literal, cast

import numpy as np
from scipy.special import gammaincc  # type: ignore[import-untyped]

from velvet.serialization import canonical_hash_sha256

GAMMA_RATE_FAMILY = "gamma_rate"
GAMMA_RATE_CERTIFICATE_SCHEMA_VERSION = "velvet.gamma_rate_max_de_certificate.v1"
GAMMA_RATE_ADMISSION_SCHEMA_VERSION = "velvet.gamma_rate_reserve_admission.v1"
GAMMA_RATE_THEOREM_REFS = ("docs/math/gamma_max_de_certificates.txt",)
NUMERICAL_CLEANUP_TOLERANCE = 1e-12

ReserveComparisonPolicy = Literal["inclusive", "strict"]


class GammaRateCertificateMethod(StrEnum):
    CLOSED_FORM_POSITIVE_PART = "closed_form_positive_part"
    DETERMINISTIC_ONE_STEP_LOWER = "deterministic_one_step_lower"
    MONTE_CARLO_LCB = "monte_carlo_lcb"
    L2_UPPER = "l2_upper"


class GammaRateAdmissionVerdict(StrEnum):
    INSPECT = "inspect"
    REJECT = "reject"
    REFINEMENT = "refinement"


@dataclass(frozen=True)
class GammaRatePosteriorSpec:
    """Shape-rate Gamma posterior over a positive rate/intensity."""

    alpha: float
    beta: float
    baseline: float
    family: str = GAMMA_RATE_FAMILY
    arm_id: str = ""

    def __post_init__(self) -> None:
        _validate_family(self.family)
        _validate_gamma_rate_parameters(self.alpha, self.beta, self.baseline)

    @property
    def mean(self) -> float:
        return float(self.alpha) / float(self.beta)

    @property
    def variance(self) -> float:
        return float(self.alpha) / float(self.beta) ** 2

    def positive_part_moments(self) -> GammaRatePositivePartMoments:
        return positive_part_moments(self.alpha, self.beta, self.baseline)

    def bounds(self) -> GammaRateBounds:
        return gamma_rate_bounds(self.alpha, self.beta, self.baseline)

    def deterministic_one_step_lower_certificate(self) -> GammaRateCertificate:
        moments = self.positive_part_moments()
        bounds = gamma_rate_bounds_from_moments(moments)
        return GammaRateCertificate(
            family=GAMMA_RATE_FAMILY,
            alpha=float(self.alpha),
            beta=float(self.beta),
            baseline=float(self.baseline),
            method=GammaRateCertificateMethod.DETERMINISTIC_ONE_STEP_LOWER,
            lower_bound=moments.mean_positive_part,
            upper_bound=None,
            moments=moments,
            bounds=bounds,
            deterministic=True,
            theorem_refs=GAMMA_RATE_THEOREM_REFS,
            arm_id=self.arm_id,
        )

    def l2_upper_certificate(self) -> GammaRateCertificate:
        moments = self.positive_part_moments()
        bounds = gamma_rate_bounds_from_moments(moments)
        return GammaRateCertificate(
            family=GAMMA_RATE_FAMILY,
            alpha=float(self.alpha),
            beta=float(self.beta),
            baseline=float(self.baseline),
            method=GammaRateCertificateMethod.L2_UPPER,
            lower_bound=None,
            upper_bound=bounds.preferred_upper_bound,
            moments=moments,
            bounds=bounds,
            deterministic=True,
            theorem_refs=GAMMA_RATE_THEOREM_REFS,
            arm_id=self.arm_id,
        )

    def monte_carlo_lcb_certificate(
        self,
        *,
        sample_count: int,
        delta: float,
        seed: int | None,
    ) -> GammaRateCertificate:
        mc = monte_carlo_lcb(
            self.alpha,
            self.beta,
            self.baseline,
            sample_count=sample_count,
            delta=delta,
            seed=seed,
        )
        moments = self.positive_part_moments()
        bounds = gamma_rate_bounds_from_moments(moments)
        return GammaRateCertificate(
            family=GAMMA_RATE_FAMILY,
            alpha=float(self.alpha),
            beta=float(self.beta),
            baseline=float(self.baseline),
            method=GammaRateCertificateMethod.MONTE_CARLO_LCB,
            lower_bound=mc.lower_confidence_bound,
            upper_bound=None,
            moments=moments,
            bounds=bounds,
            deterministic=False,
            confidence_delta=mc.delta,
            sample_count=mc.sample_count,
            seed=mc.seed,
            empirical_mean=mc.empirical_mean,
            confidence_radius=mc.confidence_radius,
            theorem_refs=GAMMA_RATE_THEOREM_REFS,
            arm_id=self.arm_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": GAMMA_RATE_FAMILY,
            "arm_id": self.arm_id,
            "alpha": float(self.alpha),
            "beta": float(self.beta),
            "baseline": float(self.baseline),
            "mean": self.mean,
            "variance": self.variance,
        }


@dataclass(frozen=True)
class GammaRatePositivePartMoments:
    """Closed-form positive-part moments for ``(theta - v)^+``."""

    family: str
    alpha: float
    beta: float
    baseline: float
    tail_probability: float
    tail_first_moment: float
    tail_second_moment: float
    mean_positive_part: float
    second_moment_positive_part: float
    q_positive_part: float
    shifted_threshold: float
    variance_positive_part: float
    method: GammaRateCertificateMethod = GammaRateCertificateMethod.CLOSED_FORM_POSITIVE_PART

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "method": self.method.value,
            "alpha": self.alpha,
            "beta": self.beta,
            "baseline": self.baseline,
            "tail_probability": self.tail_probability,
            "tail_first_moment": self.tail_first_moment,
            "tail_second_moment": self.tail_second_moment,
            "mean_positive_part": self.mean_positive_part,
            "second_moment_positive_part": self.second_moment_positive_part,
            "q_positive_part": self.q_positive_part,
            "shifted_threshold": self.shifted_threshold,
            "variance_positive_part": self.variance_positive_part,
        }


@dataclass(frozen=True)
class GammaRateBounds:
    """Finite L2 upper certificates for an unbounded upward Gamma-rate gap."""

    family: str
    alpha: float
    beta: float
    baseline: float
    mean_positive_part: float
    second_moment_positive_part: float
    q_positive_part: float
    variance_positive_part: float
    preferred_upper_bound: float
    fallback_upper_bound: float
    bounded_payoff_cap: str = "infinity"
    method: GammaRateCertificateMethod = GammaRateCertificateMethod.L2_UPPER

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "method": self.method.value,
            "alpha": self.alpha,
            "beta": self.beta,
            "baseline": self.baseline,
            "mean_positive_part": self.mean_positive_part,
            "second_moment_positive_part": self.second_moment_positive_part,
            "q_positive_part": self.q_positive_part,
            "variance_positive_part": self.variance_positive_part,
            "preferred_upper_bound": self.preferred_upper_bound,
            "fallback_upper_bound": self.fallback_upper_bound,
            "bounded_payoff_cap": self.bounded_payoff_cap,
        }


@dataclass(frozen=True)
class GammaRateCertificate:
    """Deterministic or probabilistic Gamma-rate Max-DE certificate payload."""

    family: str
    alpha: float
    beta: float
    baseline: float
    method: GammaRateCertificateMethod
    lower_bound: float | None
    upper_bound: float | None
    moments: GammaRatePositivePartMoments
    bounds: GammaRateBounds
    deterministic: bool
    schema_version: str = GAMMA_RATE_CERTIFICATE_SCHEMA_VERSION
    arm_id: str = ""
    confidence_delta: float | None = None
    sample_count: int | None = None
    seed: int | None = None
    empirical_mean: float | None = None
    confidence_radius: float | None = None
    theorem_refs: Sequence[str] = GAMMA_RATE_THEOREM_REFS

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "family": self.family,
            "arm_id": self.arm_id,
            "alpha": self.alpha,
            "beta": self.beta,
            "baseline": self.baseline,
            "method": self.method.value,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "deterministic": self.deterministic,
            "moments": self.moments.to_dict(),
            "bounds": self.bounds.to_dict(),
            "theorem_refs": [str(item) for item in self.theorem_refs],
        }
        for key, value in (
            ("confidence_delta", self.confidence_delta),
            ("sample_count", self.sample_count),
            ("seed", self.seed),
            ("empirical_mean", self.empirical_mean),
            ("confidence_radius", self.confidence_radius),
        ):
            if value is not None:
                payload[key] = value
        return payload

    def payload_hash(self) -> str:
        return canonical_hash_sha256(self.to_dict())


@dataclass(frozen=True)
class GammaRateMonteCarloLCB:
    """Fixed-seed Monte Carlo lower-confidence estimate for the Gamma upward gap."""

    family: str
    alpha: float
    beta: float
    baseline: float
    sample_count: int
    delta: float
    seed: int | None
    empirical_mean: float
    exact_mean: float
    exact_variance: float
    confidence_radius: float
    lower_confidence_bound: float
    method: GammaRateCertificateMethod = GammaRateCertificateMethod.MONTE_CARLO_LCB

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "method": self.method.value,
            "alpha": self.alpha,
            "beta": self.beta,
            "baseline": self.baseline,
            "sample_count": self.sample_count,
            "delta": self.delta,
            "seed": self.seed,
            "empirical_mean": self.empirical_mean,
            "exact_mean": self.exact_mean,
            "exact_variance": self.exact_variance,
            "confidence_radius": self.confidence_radius,
            "lower_confidence_bound": self.lower_confidence_bound,
        }


@dataclass(frozen=True)
class GammaRateAdmissionDecision:
    """Reserve-price comparison for an independently computed lower certificate."""

    family: str
    alpha: float
    beta: float
    baseline: float
    reserve_price: float
    comparison_policy: ReserveComparisonPolicy
    lower_bound: float
    upper_bound: float
    lower_method: GammaRateCertificateMethod
    verdict: GammaRateAdmissionVerdict
    admit: bool
    schema_version: str = GAMMA_RATE_ADMISSION_SCHEMA_VERSION
    arm_id: str = ""
    lower_certificate_hash: str | None = None
    theorem_refs: Sequence[str] = GAMMA_RATE_THEOREM_REFS

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "family": self.family,
            "arm_id": self.arm_id,
            "alpha": self.alpha,
            "beta": self.beta,
            "baseline": self.baseline,
            "reserve_price": self.reserve_price,
            "comparison_policy": self.comparison_policy,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "lower_method": self.lower_method.value,
            "verdict": self.verdict.value,
            "admit": self.admit,
            "theorem_refs": [str(item) for item in self.theorem_refs],
        }
        if self.lower_certificate_hash is not None:
            payload["lower_certificate_hash"] = self.lower_certificate_hash
        return payload

    def payload_hash(self) -> str:
        return canonical_hash_sha256(self.to_dict())


def validate_gamma_rate_family(family: str) -> None:
    _validate_family(family)


def gamma_rate_tail_probability(alpha: float, beta: float, threshold: float) -> float:
    _validate_gamma_rate_parameters(alpha, beta, threshold)
    return _regularized_upper_gamma(float(alpha), float(beta) * float(threshold))


def gamma_rate_tail_first_moment(alpha: float, beta: float, threshold: float) -> float:
    _validate_gamma_rate_parameters(alpha, beta, threshold)
    a = float(alpha)
    b = float(beta)
    x = b * float(threshold)
    return a / b * _regularized_upper_gamma(a + 1.0, x)


def gamma_rate_tail_second_moment(alpha: float, beta: float, threshold: float) -> float:
    _validate_gamma_rate_parameters(alpha, beta, threshold)
    a = float(alpha)
    b = float(beta)
    x = b * float(threshold)
    return a * (a + 1.0) / b**2 * _regularized_upper_gamma(a + 2.0, x)


def m_v_plus(alpha: float, beta: float, baseline: float) -> float:
    t0 = gamma_rate_tail_probability(alpha, beta, baseline)
    t1 = gamma_rate_tail_first_moment(alpha, beta, baseline)
    raw = t1 - float(baseline) * t0
    return _cleanup_nonnegative(raw, scale=abs(t1) + abs(float(baseline) * t0))


def s_v_plus(alpha: float, beta: float, baseline: float) -> float:
    t0 = gamma_rate_tail_probability(alpha, beta, baseline)
    t1 = gamma_rate_tail_first_moment(alpha, beta, baseline)
    t2 = gamma_rate_tail_second_moment(alpha, beta, baseline)
    v = float(baseline)
    raw = t2 - 2.0 * v * t1 + v**2 * t0
    scale = abs(t2) + abs(2.0 * v * t1) + abs(v**2 * t0)
    return _cleanup_nonnegative(raw, scale=scale)


def q_v_plus(alpha: float, beta: float, baseline: float) -> float:
    m_value = m_v_plus(alpha, beta, baseline)
    return s_v_plus(alpha, beta, float(baseline) + m_value)


def positive_part_moments(
    alpha: float,
    beta: float,
    baseline: float,
) -> GammaRatePositivePartMoments:
    _validate_gamma_rate_parameters(alpha, beta, baseline)
    a = float(alpha)
    b = float(beta)
    v = float(baseline)
    t0 = gamma_rate_tail_probability(a, b, v)
    t1 = gamma_rate_tail_first_moment(a, b, v)
    t2 = gamma_rate_tail_second_moment(a, b, v)
    m_value = _cleanup_nonnegative(t1 - v * t0, scale=abs(t1) + abs(v * t0))
    s_value = _cleanup_nonnegative(
        t2 - 2.0 * v * t1 + v**2 * t0,
        scale=abs(t2) + abs(2.0 * v * t1) + abs(v**2 * t0),
    )
    shifted = v + m_value
    q_value = s_v_plus(a, b, shifted)
    variance = _cleanup_nonnegative(
        s_value - m_value**2,
        scale=abs(s_value) + abs(m_value**2),
    )
    return GammaRatePositivePartMoments(
        family=GAMMA_RATE_FAMILY,
        alpha=a,
        beta=b,
        baseline=v,
        tail_probability=t0,
        tail_first_moment=t1,
        tail_second_moment=t2,
        mean_positive_part=m_value,
        second_moment_positive_part=s_value,
        q_positive_part=q_value,
        shifted_threshold=shifted,
        variance_positive_part=variance,
    )


def gamma_rate_bounds(alpha: float, beta: float, baseline: float) -> GammaRateBounds:
    return gamma_rate_bounds_from_moments(positive_part_moments(alpha, beta, baseline))


def gamma_rate_bounds_from_moments(moments: GammaRatePositivePartMoments) -> GammaRateBounds:
    preferred = moments.mean_positive_part + 2.0 * sqrt(moments.q_positive_part)
    fallback = moments.mean_positive_part + 2.0 * sqrt(moments.variance_positive_part)
    return GammaRateBounds(
        family=GAMMA_RATE_FAMILY,
        alpha=moments.alpha,
        beta=moments.beta,
        baseline=moments.baseline,
        mean_positive_part=moments.mean_positive_part,
        second_moment_positive_part=moments.second_moment_positive_part,
        q_positive_part=moments.q_positive_part,
        variance_positive_part=moments.variance_positive_part,
        preferred_upper_bound=preferred,
        fallback_upper_bound=fallback,
    )


def l2_upper_certificate(alpha: float, beta: float, baseline: float) -> float:
    return gamma_rate_bounds(alpha, beta, baseline).preferred_upper_bound


def l2_fallback_upper_certificate(alpha: float, beta: float, baseline: float) -> float:
    return gamma_rate_bounds(alpha, beta, baseline).fallback_upper_bound


def deterministic_one_step_lower_certificate(
    alpha: float,
    beta: float,
    baseline: float,
) -> float:
    return m_v_plus(alpha, beta, baseline)


def monte_carlo_lcb(
    alpha: float,
    beta: float,
    baseline: float,
    *,
    sample_count: int,
    delta: float,
    seed: int | None,
) -> GammaRateMonteCarloLCB:
    _validate_gamma_rate_parameters(alpha, beta, baseline)
    count = _validate_sample_count(sample_count)
    confidence_delta = _validate_delta(delta)
    a = float(alpha)
    b = float(beta)
    v = float(baseline)
    rng = np.random.default_rng(seed)
    theta = rng.gamma(shape=a, scale=1.0 / b, size=count)
    positive_gap = np.maximum(theta - v, 0.0)
    empirical_mean = float(np.mean(positive_gap, dtype=np.float64))
    moments = positive_part_moments(a, b, v)
    exact_variance = moments.variance_positive_part
    radius = sqrt(exact_variance * (1.0 - confidence_delta) / (count * confidence_delta))
    lcb = max(empirical_mean - radius, 0.0)
    return GammaRateMonteCarloLCB(
        family=GAMMA_RATE_FAMILY,
        alpha=a,
        beta=b,
        baseline=v,
        sample_count=count,
        delta=confidence_delta,
        seed=seed,
        empirical_mean=empirical_mean,
        exact_mean=moments.mean_positive_part,
        exact_variance=exact_variance,
        confidence_radius=radius,
        lower_confidence_bound=lcb,
    )


def certified_gamma_rate_candidate(
    *,
    alpha: float,
    beta: float,
    baseline: float,
    reserve_price: float,
    arm_id: str = "",
    comparison_policy: ReserveComparisonPolicy = "inclusive",
    lower_bound: float | None = None,
    lower_method: GammaRateCertificateMethod | str = (
        GammaRateCertificateMethod.DETERMINISTIC_ONE_STEP_LOWER
    ),
    sample_count: int = 10_000,
    delta: float = 0.05,
    seed: int | None = 0,
) -> GammaRateAdmissionDecision:
    """Compare a Gamma-rate lower certificate to a reserve price.

    Reserve price is an admission threshold. It is not a distinct certificate
    method, and the lower bound is computed independently of the price.
    """

    spec = GammaRatePosteriorSpec(alpha=alpha, beta=beta, baseline=baseline, arm_id=arm_id)
    price = _validate_reserve_price(reserve_price)
    policy = _validate_comparison_policy(comparison_policy)
    method = _coerce_certificate_method(lower_method)
    certificate_hash: str | None = None
    if lower_bound is None:
        if method == GammaRateCertificateMethod.DETERMINISTIC_ONE_STEP_LOWER:
            certificate = spec.deterministic_one_step_lower_certificate()
        elif method == GammaRateCertificateMethod.MONTE_CARLO_LCB:
            certificate = spec.monte_carlo_lcb_certificate(
                sample_count=sample_count,
                delta=delta,
                seed=seed,
            )
        else:
            raise ValueError(
                "lower_method must be deterministic_one_step_lower or monte_carlo_lcb"
            )
        bound = cast(float, certificate.lower_bound)
        certificate_hash = certificate.payload_hash()
    else:
        bound = _validate_lower_bound(lower_bound)

    upper = spec.bounds().preferred_upper_bound
    if _lower_clears_reserve(bound, price, policy):
        verdict = GammaRateAdmissionVerdict.INSPECT
        admit = True
    elif _upper_cannot_clear_reserve(upper, price, policy):
        verdict = GammaRateAdmissionVerdict.REJECT
        admit = False
    else:
        verdict = GammaRateAdmissionVerdict.REFINEMENT
        admit = False
    return GammaRateAdmissionDecision(
        family=GAMMA_RATE_FAMILY,
        alpha=float(alpha),
        beta=float(beta),
        baseline=float(baseline),
        reserve_price=price,
        comparison_policy=policy,
        lower_bound=bound,
        upper_bound=upper,
        lower_method=method,
        verdict=verdict,
        admit=admit,
        arm_id=arm_id,
        lower_certificate_hash=certificate_hash,
        theorem_refs=GAMMA_RATE_THEOREM_REFS,
    )


def _validate_family(family: str) -> None:
    if str(family) != GAMMA_RATE_FAMILY:
        raise ValueError("family must be 'gamma_rate'")


def _validate_gamma_rate_parameters(alpha: float, beta: float, baseline: float) -> None:
    if not isfinite(float(alpha)) or float(alpha) <= 0.0:
        raise ValueError("alpha must be positive")
    if not isfinite(float(beta)) or float(beta) <= 0.0:
        raise ValueError("beta must be positive")
    if not isfinite(float(baseline)) or float(baseline) < 0.0:
        raise ValueError("baseline must be non-negative")


def _validate_sample_count(sample_count: int) -> int:
    count = int(sample_count)
    if count <= 0:
        raise ValueError("sample_count must be positive")
    return count


def _validate_delta(delta: float) -> float:
    value = float(delta)
    if not isfinite(value) or not 0.0 < value < 1.0:
        raise ValueError("delta must be in (0, 1)")
    return value


def _validate_reserve_price(reserve_price: float) -> float:
    price = float(reserve_price)
    if not isfinite(price) or price < 0.0:
        raise ValueError("reserve_price must be non-negative")
    return price


def _validate_lower_bound(lower_bound: float) -> float:
    bound = float(lower_bound)
    if not isfinite(bound) or bound < 0.0:
        raise ValueError("lower_bound must be non-negative")
    return bound


def _validate_comparison_policy(policy: str) -> ReserveComparisonPolicy:
    if policy == "inclusive":
        return "inclusive"
    if policy == "strict":
        return "strict"
    raise ValueError("comparison_policy must be 'inclusive' or 'strict'")


def _coerce_certificate_method(
    method: GammaRateCertificateMethod | str,
) -> GammaRateCertificateMethod:
    if isinstance(method, GammaRateCertificateMethod):
        return method
    return GammaRateCertificateMethod(str(method))


def _lower_clears_reserve(
    lower_bound: float,
    reserve_price: float,
    policy: ReserveComparisonPolicy,
) -> bool:
    if policy == "inclusive":
        return lower_bound >= reserve_price
    return lower_bound > reserve_price


def _upper_cannot_clear_reserve(
    upper_bound: float,
    reserve_price: float,
    policy: ReserveComparisonPolicy,
) -> bool:
    if policy == "inclusive":
        return upper_bound < reserve_price
    return upper_bound <= reserve_price


def _regularized_upper_gamma(shape: float, x: float) -> float:
    return float(gammaincc(shape, x))


def _cleanup_nonnegative(value: float, *, scale: float) -> float:
    # Positive-part moments are nonnegative; this only cleans roundoff-scale cancellation.
    tolerance = NUMERICAL_CLEANUP_TOLERANCE * max(1.0, float(scale))
    if value < 0.0:
        if value >= -tolerance:
            return 0.0
        raise ValueError("computed Gamma-rate moment is negative beyond numerical tolerance")
    return float(value)
