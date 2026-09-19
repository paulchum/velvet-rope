"""Platform-neutral effect evidence for ShadowPath exploration.

The search engine can observe many substrates, but a filesystem path is not a
portable unit of impact. An effect footprint identifies a resource by an
adapter-owned namespace, an extensible kind, and a stable key. It then records
what may happen separately from what an independent observer actually saw.

Kinds and effects are dotted strings rather than a closed enum. Adapters can
therefore describe filesystem entries, containers, volumes, runtimes,
processes, service objects, network endpoints, and delegated tool operations
without teaching the core their platform semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

JsonObject = dict[str, Any]

EFFECT_FOOTPRINT_SCHEMA_VERSION = "velvet.shadowpath.effect-footprint.v0.1"

EvidenceLevel = Literal["candidate", "source_supported", "adapter_declared", "observed"]

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_EVIDENCE_LEVELS: frozenset[str] = frozenset(
    {"candidate", "source_supported", "adapter_declared", "observed"}
)


class EffectFootprintError(ValueError):
    """Raised when effect evidence cannot be represented canonically."""


def _text(label: str, value: str, *, token: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise EffectFootprintError(f"{label} must be a non-empty string without NUL bytes")
    normalized = value.strip()
    if token and _TOKEN.fullmatch(normalized) is None:
        raise EffectFootprintError(f"{label} must be a dotted resource token")
    return normalized


def _resource_key(value: str) -> str:
    if not isinstance(value, str) or value == "" or "\x00" in value:
        raise EffectFootprintError("resource key must be a non-empty string without NUL bytes")
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_sha256(value: Any) -> str:
    try:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise EffectFootprintError("effect evidence must be JSON serializable") from error
    return hashlib.sha256(serialized.encode()).hexdigest()


@dataclass(frozen=True)
class ResourceRef:
    """Stable identity for one resource in an adapter-defined namespace."""

    namespace: str
    kind: str
    key: str
    facet: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "namespace", _text("resource namespace", self.namespace, token=True)
        )
        object.__setattr__(self, "kind", _text("resource kind", self.kind, token=True))
        object.__setattr__(self, "key", _resource_key(self.key))
        if self.facet is not None:
            object.__setattr__(self, "facet", _text("resource facet", self.facet, token=True))

    @property
    def resource_id(self) -> str:
        return _canonical_sha256(self.identity_json())

    def identity_json(self) -> JsonObject:
        value: JsonObject = {
            "namespace": self.namespace,
            "kind": self.kind,
            "key": self.key,
        }
        if self.facet is not None:
            value["facet"] = self.facet
        return value

    def to_json(self) -> JsonObject:
        return {**self.identity_json(), "resource_id": self.resource_id}


@dataclass(frozen=True)
class EffectRecord:
    """One candidate, derived, declared, or observed resource effect."""

    effect: str
    resource: ResourceRef
    evidence_level: EvidenceLevel
    provenance: str
    operation: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", _text("effect", self.effect, token=True))
        if self.evidence_level not in _EVIDENCE_LEVELS:
            raise EffectFootprintError(f"unknown evidence level: {self.evidence_level!r}")
        object.__setattr__(self, "provenance", _text("effect provenance", self.provenance))
        if self.operation is not None:
            object.__setattr__(self, "operation", _text("effect operation", self.operation))
        # Validate and detach now so a report cannot fail or change only when
        # it is finally written. The recursive immutable form also keeps effect
        # fingerprints stable after construction.
        try:
            normalized_details = json.loads(json.dumps(dict(self.details), allow_nan=False))
        except (TypeError, ValueError) as error:
            raise EffectFootprintError("effect evidence must be JSON serializable") from error
        object.__setattr__(self, "details", _freeze_json(normalized_details))

    def to_json(self) -> JsonObject:
        value: JsonObject = {
            "effect": self.effect,
            "resource": self.resource.to_json(),
            "evidence_level": self.evidence_level,
            "provenance": self.provenance,
            "details": _thaw_json(self.details),
        }
        if self.operation is not None:
            value["operation"] = self.operation
        return value


def merge_effects(*groups: Iterable[EffectRecord]) -> tuple[EffectRecord, ...]:
    """Return stable, exact-record deduplication across effect sequences."""

    merged: list[EffectRecord] = []
    seen: set[str] = set()
    for group in groups:
        for effect in group:
            fingerprint = _canonical_sha256(effect.to_json())
            if fingerprint not in seen:
                seen.add(fingerprint)
                merged.append(effect)
    return tuple(merged)


def effect_footprint(
    *,
    candidates: Iterable[EffectRecord] = (),
    observed: Iterable[EffectRecord] = (),
) -> JsonObject:
    """Serialize candidate and observed effects without promoting either tier."""

    candidate_records = merge_effects(candidates)
    observed_records = merge_effects(observed)
    if any(record.evidence_level == "observed" for record in candidate_records):
        raise EffectFootprintError("observed evidence cannot be serialized as a candidate effect")
    if any(record.evidence_level != "observed" for record in observed_records):
        raise EffectFootprintError(
            "non-observed evidence cannot be serialized as an observed effect"
        )
    candidate_json = [record.to_json() for record in candidate_records]
    observed_json = [record.to_json() for record in observed_records]
    candidate_resources = {
        record.resource.resource_id: record.resource for record in candidate_records
    }
    observed_resources = {
        record.resource.resource_id: record.resource for record in observed_records
    }
    candidate_effect_keys = {
        (record.resource.resource_id, record.effect, record.operation or ""): record
        for record in candidate_records
    }
    observed_effect_keys = {
        (record.resource.resource_id, record.effect, record.operation or ""): record
        for record in observed_records
    }
    return {
        "schema_version": EFFECT_FOOTPRINT_SCHEMA_VERSION,
        "candidate_effects": candidate_json,
        "observed_effects": observed_json,
        "candidate_effects_sha256": _canonical_sha256(candidate_json),
        "observed_effects_sha256": _canonical_sha256(observed_json),
        "observed_resources_not_in_candidates": [
            observed_resources[key].to_json()
            for key in sorted(observed_resources.keys() - candidate_resources.keys())
        ],
        "candidate_resources_not_observed": [
            candidate_resources[key].to_json()
            for key in sorted(candidate_resources.keys() - observed_resources.keys())
        ],
        "observed_effects_not_in_candidates": [
            observed_effect_keys[key].to_json()
            for key in sorted(observed_effect_keys.keys() - candidate_effect_keys.keys())
        ],
        "candidate_effects_not_observed": [
            candidate_effect_keys[key].to_json()
            for key in sorted(candidate_effect_keys.keys() - observed_effect_keys.keys())
        ],
    }
