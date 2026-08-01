from __future__ import annotations

from dataclasses import replace

from velvet import (
    CertificateEffect,
    CertificateEvidence,
    CertificateOutcome,
    compose_parallel_certificates,
    compose_sequential_certificates,
)
from velvet.types import certificate_effect_safe_upper_bound


def _certificate(
    arm_id: str,
    *,
    mean: float = 0.1,
    max_payoff: float = 10.0,
    variance: float = 0.01,
    dependence_kind: str = "conditional_independent",
    gamma: float | None = None,
    writes: tuple[str, ...] = (),
    filtration_index: int = 0,
    write_conflict_policy: str = "exclusive",
    commutativity_hash: str | None = None,
) -> CertificateEvidence:
    effect = CertificateEffect(
        max_payoff=max_payoff,
        mean_bound=mean,
        variance_bound=variance,
        second_moment_bound=variance + mean**2,
        resource_scope="test_scope",
        write_footprint=writes,
        dependence_kind=dependence_kind,
        covariance_reserve_gamma=gamma,
        filtration_hash=f"filtration:{filtration_index}",
        filtration_index=filtration_index,
        adapted=True,
        write_conflict_policy=write_conflict_policy,
        commutativity_certificate_hash=commutativity_hash,
    )
    safe_upper = certificate_effect_safe_upper_bound(
        mean_bound=effect.mean_bound,
        max_payoff=effect.max_payoff,
        variance_bound=effect.variance() or 0.0,
    )
    return CertificateEvidence(
        schema_version="velvet.certificate_evidence.v2",
        family="beta_bernoulli",
        arm_id=arm_id,
        baseline=0.0,
        lookback_horizon=1,
        delight_scale=1.0,
        liability_price=1.0,
        threshold=1.0,
        inspection_lower_bound=mean,
        safe_upper_bound=safe_upper,
        outcome=CertificateOutcome.LOCKOUT,
        liability_mode="posterior_certificate",
        typed_effect=effect,
    )


def test_independent_parallel_certificates_compose_with_gamma_zero() -> None:
    result = compose_parallel_certificates(
        [_certificate("a"), _certificate("b", filtration_index=1)]
    )

    assert result.certifying is True
    assert result.covariance_reserve_gamma == 0.0
    assert result.safe_upper_bound is not None


def test_dependent_parallel_certificates_require_gamma_or_fail() -> None:
    result = compose_parallel_certificates(
        [
            _certificate("a", dependence_kind="unspecified"),
            _certificate("b", dependence_kind="unspecified"),
        ]
    )

    assert result.certifying is False
    assert "Gamma" in result.reason


def test_composite_upper_increases_when_gamma_increases() -> None:
    certificates = [
        _certificate("a", dependence_kind="unspecified"),
        _certificate("b", dependence_kind="unspecified"),
    ]

    low = compose_parallel_certificates(certificates, covariance_reserve_gamma=0.0)
    high = compose_parallel_certificates(certificates, covariance_reserve_gamma=0.09)

    assert low.certifying is True
    assert high.certifying is True
    assert low.safe_upper_bound is not None
    assert high.safe_upper_bound is not None
    assert high.safe_upper_bound > low.safe_upper_bound


def test_scalar_only_certificates_cannot_compose_as_certifying() -> None:
    result = compose_parallel_certificates(
        [
            {
                "family": "beta_bernoulli",
                "lower_certificate": 0.1,
                "upper_certificate": 0.2,
                "outcome": "inspect",
            }
        ]
    )

    assert result.certifying is False
    assert "typed effect" in result.reason


def test_write_conflict_blocks_parallel_without_serialization_or_commutativity() -> None:
    left = _certificate("a", writes=("case:1",))
    right = _certificate("b", writes=("case:1",))

    blocked = compose_parallel_certificates([left, right])

    assert blocked.certifying is False
    assert "write-footprint conflict" in blocked.reason

    serialized = compose_parallel_certificates(
        [
            replace(
                left,
                typed_effect=replace(left.typed_effect, write_conflict_policy="serialized"),
            ),
            replace(
                right,
                typed_effect=replace(right.typed_effect, write_conflict_policy="serialized"),
            ),
        ]
    )

    assert serialized.certifying is True


def test_sequential_composition_preserves_filtration_order_metadata() -> None:
    first = _certificate("a", filtration_index=2)
    second = _certificate("b", filtration_index=3)

    result = compose_sequential_certificates([first, second])

    assert result.certifying is True
    assert result.typed_effect is not None
    assert result.typed_effect.filtration_index == 3
