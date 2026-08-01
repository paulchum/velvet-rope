"""Typed effect composition for Velvet certificate evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from typing import Any

from velvet.serialization import canonical_hash_sha256
from velvet.types import (
    CertificateEffect,
    CertificateEvidence,
    JsonObject,
    certificate_effect_safe_upper_bound,
)


@dataclass(frozen=True)
class CertificateComposition:
    certifying: bool
    reason: str
    composition_kind: str
    safe_upper_bound: float | None = None
    typed_effect: CertificateEffect | None = None
    source_hashes: tuple[str, ...] = ()
    covariance_reserve_gamma: float | None = None

    def to_dict(self) -> JsonObject:
        return {
            "certifying": self.certifying,
            "reason": self.reason,
            "composition_kind": self.composition_kind,
            "safe_upper_bound": self.safe_upper_bound,
            "typed_effect": self.typed_effect.to_dict()
            if self.typed_effect is not None
            else None,
            "source_hashes": list(self.source_hashes),
            "covariance_reserve_gamma": self.covariance_reserve_gamma,
        }


def composite_upper_bound(mu_star: float, b_star: float, v_star: float) -> float:
    return certificate_effect_safe_upper_bound(
        mean_bound=mu_star,
        max_payoff=b_star,
        variance_bound=v_star,
    )


def compose_sequential_certificates(
    certificates: Sequence[CertificateEvidence | Mapping[str, Any]],
) -> CertificateComposition:
    loaded = _load_effects(certificates, "sequential")
    if isinstance(loaded, CertificateComposition):
        return loaded
    effects, source_hashes = loaded
    if any(not effect.adapted for effect in effects):
        return _non_certifying("sequential", "sequential composition requires adapted effects")
    indices = [effect.filtration_index for effect in effects]
    if indices != sorted(indices):
        return _non_certifying(
            "sequential",
            "sequential composition requires nondecreasing filtration order",
        )
    return _compose_effects(
        "sequential",
        effects,
        source_hashes,
        gamma=_metadata_gamma(effects),
        reason="sequential/tower composition under adaptedness",
    )


def compose_conditional_continuation(
    certificates: Sequence[CertificateEvidence | Mapping[str, Any]],
) -> CertificateComposition:
    loaded = _load_effects(certificates, "conditional_continuation")
    if isinstance(loaded, CertificateComposition):
        return loaded
    effects, source_hashes = loaded
    sequential = compose_sequential_certificates(certificates)
    if not sequential.certifying:
        return CertificateComposition(
            certifying=False,
            reason=sequential.reason,
            composition_kind="conditional_continuation",
            source_hashes=source_hashes,
        )
    if len(effects) > 1 and any(
        effect.continuation_condition_hash is None for effect in effects[1:]
    ):
        return _non_certifying(
            "conditional_continuation",
            "conditional continuation requires explicit pasting condition metadata",
        )
    return CertificateComposition(
        certifying=True,
        reason="conditional continuation under adapted pasting metadata",
        composition_kind="conditional_continuation",
        safe_upper_bound=sequential.safe_upper_bound,
        typed_effect=sequential.typed_effect,
        source_hashes=source_hashes,
        covariance_reserve_gamma=sequential.covariance_reserve_gamma,
    )


def compose_parallel_certificates(
    certificates: Sequence[CertificateEvidence | Mapping[str, Any]],
    *,
    covariance_reserve_gamma: float | None = None,
) -> CertificateComposition:
    loaded = _load_effects(certificates, "parallel")
    if isinstance(loaded, CertificateComposition):
        return loaded
    effects, source_hashes = loaded
    write_conflict = _write_conflict_reason(effects)
    if write_conflict is not None:
        return _non_certifying("parallel", write_conflict, source_hashes=source_hashes)

    if covariance_reserve_gamma is not None:
        gamma = _finite_nonnegative_gamma(covariance_reserve_gamma)
        if gamma is None:
            return _non_certifying(
                "parallel",
                "parallel composition requires a finite non-negative Gamma reserve",
                source_hashes=source_hashes,
            )
    elif all(effect.dependence_kind == "conditional_independent" for effect in effects):
        gamma = 0.0
    else:
        gamma = _metadata_gamma(effects)
        if gamma is None:
            return _non_certifying(
                "parallel",
                "parallel composition requires certified conditional independence or Gamma",
                source_hashes=source_hashes,
            )
    return _compose_effects(
        "parallel",
        effects,
        source_hashes,
        gamma=gamma,
        reason="parallel composition with certified dependence correction",
    )


def _load_effects(
    certificates: Sequence[CertificateEvidence | Mapping[str, Any]],
    composition_kind: str,
) -> tuple[tuple[CertificateEffect, ...], tuple[str, ...]] | CertificateComposition:
    if not certificates:
        return _non_certifying(composition_kind, "composition requires at least one certificate")
    effects: list[CertificateEffect] = []
    source_hashes: list[str] = []
    for certificate in certificates:
        try:
            parsed = (
                certificate
                if isinstance(certificate, CertificateEvidence)
                else CertificateEvidence.from_dict(certificate)
            )
        except (KeyError, TypeError, ValueError) as error:
            return _non_certifying(
                composition_kind,
                f"certificate is missing typed effect metadata: {error}",
            )
        validation_error = _effect_validation_error(parsed.typed_effect)
        if validation_error is not None:
            return _non_certifying(composition_kind, validation_error)
        effects.append(parsed.typed_effect)
        source_hashes.append(canonical_hash_sha256(parsed.to_dict()))
    return tuple(effects), tuple(source_hashes)


def _effect_validation_error(effect: CertificateEffect) -> str | None:
    variance = effect.variance()
    if variance is None:
        return "certificate typed effect requires variance_bound or second_moment_bound"
    for label, value in (
        ("max_payoff", effect.max_payoff),
        ("mean_bound", effect.mean_bound),
        ("variance_bound", variance),
    ):
        if not isfinite(value):
            return f"certificate typed effect has non-finite {label}"
        if value < 0.0:
            return f"certificate typed effect has negative {label}"
    if effect.mean_bound > effect.max_payoff:
        return "certificate typed effect mean_bound exceeds max_payoff"
    if not effect.resource_scope:
        return "certificate typed effect requires resource_scope"
    if not effect.filtration_hash:
        return "certificate typed effect requires filtration_hash"
    return None


def _compose_effects(
    composition_kind: str,
    effects: Sequence[CertificateEffect],
    source_hashes: tuple[str, ...],
    *,
    gamma: float | None,
    reason: str,
) -> CertificateComposition:
    if gamma is None:
        return _non_certifying(composition_kind, "composition requires certified Gamma")
    mu_star = sum(effect.mean_bound for effect in effects)
    b_star = sum(effect.max_payoff for effect in effects)
    variance_sum = sum(effect.variance() or 0.0 for effect in effects)
    v_star = variance_sum + gamma
    try:
        upper = composite_upper_bound(mu_star, b_star, v_star)
    except ValueError as error:
        return _non_certifying(composition_kind, str(error), source_hashes=source_hashes)
    composite_effect = CertificateEffect(
        max_payoff=b_star,
        mean_bound=mu_star,
        variance_bound=v_star,
        second_moment_bound=v_star + mu_star**2,
        resource_scope=",".join(sorted({effect.resource_scope for effect in effects})),
        write_footprint=tuple(
            sorted({item for effect in effects for item in effect.write_footprint})
        ),
        declared_write_set_hash=canonical_hash_sha256(
            {
                "write_footprint": [
                    item for effect in effects for item in effect.write_footprint
                ]
            }
        ),
        dependence_group=canonical_hash_sha256({"sources": source_hashes}),
        covariance_reserve_gamma=gamma,
        dependence_kind="composite",
        filtration_hash=canonical_hash_sha256(
            {
                "composition_kind": composition_kind,
                "source_hashes": source_hashes,
                "filtration_hashes": [effect.filtration_hash for effect in effects],
            }
        ),
        filtration_index=max(effect.filtration_index for effect in effects),
        adapted=all(effect.adapted for effect in effects),
        adaptation_marker=f"{composition_kind}_typed_effect",
        write_conflict_policy="serialized"
        if composition_kind != "parallel"
        else "parallel_checked",
    )
    return CertificateComposition(
        certifying=True,
        reason=reason,
        composition_kind=composition_kind,
        safe_upper_bound=upper,
        typed_effect=composite_effect,
        source_hashes=source_hashes,
        covariance_reserve_gamma=gamma,
    )


def _metadata_gamma(effects: Sequence[CertificateEffect]) -> float | None:
    gamma_values = [
        effect.covariance_reserve_gamma
        for effect in effects
        if effect.covariance_reserve_gamma is not None
    ]
    if not gamma_values:
        independent = all(
            effect.dependence_kind == "conditional_independent" for effect in effects
        )
        return 0.0 if independent else None
    gamma = sum(gamma_values)
    return _finite_nonnegative_gamma(gamma)


def _finite_nonnegative_gamma(value: float) -> float | None:
    gamma = float(value)
    if not isfinite(gamma) or gamma < 0.0:
        return None
    return gamma


def _write_conflict_reason(effects: Sequence[CertificateEffect]) -> str | None:
    owners: dict[str, CertificateEffect] = {}
    for effect in effects:
        for write in effect.write_footprint:
            previous = owners.get(write)
            if previous is None:
                owners[write] = effect
                continue
            if _write_pair_certified(previous, effect):
                continue
            return (
                "parallel write-footprint conflict requires serialization or "
                "commutativity certificate"
            )
    return None


def _write_pair_certified(left: CertificateEffect, right: CertificateEffect) -> bool:
    policies = {left.write_conflict_policy, right.write_conflict_policy}
    if policies == {"serialized"}:
        return True
    return (
        left.write_conflict_policy == "commutative_certified"
        and right.write_conflict_policy == "commutative_certified"
        and left.commutativity_certificate_hash is not None
        and left.commutativity_certificate_hash == right.commutativity_certificate_hash
    )


def _non_certifying(
    composition_kind: str,
    reason: str,
    *,
    source_hashes: tuple[str, ...] = (),
) -> CertificateComposition:
    return CertificateComposition(
        certifying=False,
        reason=reason,
        composition_kind=composition_kind,
        source_hashes=source_hashes,
    )
