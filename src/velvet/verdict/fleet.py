"""Fleet-level e-FDR aggregation for anchor-tail kill certificates.

This module composes a fixed family of same-snapshot anchor-tail e-values into
a portfolio verdict.  It is Bayesian-predictive, not fixed-mu frequentist, and
it only covers the anchor-tail subfamily; finite-horizon DP verdicts remain
single-decision claims.

Ported from the maxde-replay study (``src/replay/fleet_verdict.py``),
relicensed by the copyright owner (Coriolis Labs Inc.) under Apache-2.0; see
``src/velvet/verdict/UPSTREAM.md``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Literal

from velvet.verdict.rescue import (
    DEFAULT_GATE,
    DEFAULT_QUADRATURE_POINTS,
    ArmPosterior,
    rescue_risk_log_bound,
)

FleetStatus = Literal["anchor_tail", "refusal"]
MGFPath = Literal["quadrature"]


@dataclass(frozen=True)
class FleetCertificate:
    """One same-snapshot certificate submitted to fleet e-BH."""

    certificate_id: str
    snapshot_id: str
    status: FleetStatus
    log_e_value: float
    mgf_path: MGFPath | None
    refusal_reason: str | None = None
    metadata: Mapping[str, object] | None = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_nonempty_string("certificate_id", self.certificate_id)
        _require_nonempty_string("snapshot_id", self.snapshot_id)
        if self.status not in {"anchor_tail", "refusal"}:
            raise ValueError("status must be 'anchor_tail' or 'refusal'")
        log_e = float(self.log_e_value)
        if math.isnan(log_e):
            raise ValueError("log_e_value must not be NaN")
        object.__setattr__(self, "log_e_value", log_e)
        object.__setattr__(self, "metadata", dict(self.metadata or {}))
        if self.status == "refusal":
            if self.refusal_reason is None or not str(self.refusal_reason).strip():
                raise ValueError("refusal certificates require a refusal_reason")
            if log_e != float("-inf"):
                raise ValueError("refusal certificates must use log_e_value=-inf")
            if self.mgf_path is not None:
                raise ValueError("refusal certificates must not record an MGF path")
        else:
            if self.refusal_reason is not None:
                raise ValueError("non-refusal certificates cannot have a refusal_reason")
            if self.mgf_path != "quadrature":
                raise ValueError("anchor-tail fleet certificates must use quadrature")

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)


@dataclass(frozen=True)
class FleetDecision:
    """Fleet e-BH decision for one submitted certificate."""

    certificate_id: str
    selected: bool
    rank: int | None
    log_e_value: float
    cutoff_log_e_value: float | None
    status: FleetStatus


@dataclass(frozen=True)
class FleetVerdict:
    """Portfolio verdict over one same-snapshot certificate family."""

    snapshot_id: str | None
    target_fraction: float
    family_size: int
    selected_count: int
    cutoff_log_e_value: float | None
    selected_ids: tuple[str, ...]
    decisions: tuple[FleetDecision, ...]

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)


def anchor_tail_fleet_certificate(
    arms: Sequence[ArmPosterior],
    candidate: int,
    *,
    certificate_id: str,
    snapshot_id: str,
    gate: float = DEFAULT_GATE,
    quadrature_points: int = DEFAULT_QUADRATURE_POINTS,
    metadata: Mapping[str, object] | None = None,
) -> FleetCertificate:
    """Build a quadrature-backed anchor-tail fleet certificate.

    The e-value is the reciprocal of the anchor-tail rescue-risk upper bound,
    carried in log space as ``-log(rescue_bound)``.
    """

    log_rescue_bound = rescue_risk_log_bound(
        arms,
        candidate,
        gate,
        quadrature_points=quadrature_points,
    )
    cert_metadata = dict(metadata or {})
    cert_metadata.update(
        {
            "candidate": candidate,
            "gate": float(gate),
            "quadrature_points": int(quadrature_points),
            "log_rescue_bound": log_rescue_bound,
        }
    )
    return FleetCertificate(
        certificate_id=certificate_id,
        snapshot_id=snapshot_id,
        status="anchor_tail",
        log_e_value=-log_rescue_bound,
        mgf_path="quadrature",
        refusal_reason=None,
        metadata=cert_metadata,
    )


def refusal_fleet_certificate(
    certificate_id: str,
    snapshot_id: str,
    reason: str,
    metadata: Mapping[str, object] | None = None,
) -> FleetCertificate:
    """Build a nonselectable certificate placeholder that still counts in K."""

    return FleetCertificate(
        certificate_id=certificate_id,
        snapshot_id=snapshot_id,
        status="refusal",
        log_e_value=float("-inf"),
        mgf_path=None,
        refusal_reason=reason,
        metadata=dict(metadata or {}),
    )


def fleet_verdict(
    certificates: Sequence[FleetCertificate],
    target_fraction: float,
) -> FleetVerdict:
    """Run base e-BH over a same-snapshot fleet certificate family.

    ``target_fraction`` is the desired predictive e-FDR level ``q``.  Refusals
    count in the family size ``K`` but are never eligible for selection.
    """

    q = _require_target_fraction(target_fraction)
    certs = tuple(certificates)
    if not certs:
        return FleetVerdict(
            snapshot_id=None,
            target_fraction=q,
            family_size=0,
            selected_count=0,
            cutoff_log_e_value=None,
            selected_ids=(),
            decisions=(),
        )
    snapshot_id = _require_one_snapshot(certs)
    _require_unique_ids(certs)

    family_size = len(certs)
    ranked = sorted(
        (
            (cert.log_e_value, index, cert)
            for index, cert in enumerate(certs)
            if cert.status != "refusal"
        ),
        key=lambda item: (-item[0], item[1]),
    )
    ranks = {id(cert): rank for rank, (_, _, cert) in enumerate(ranked, start=1)}
    cutoff = _ebh_cutoff_log_e_value(
        [log_e for log_e, _, _ in ranked],
        family_size=family_size,
        target_fraction=q,
    )
    decisions: list[FleetDecision] = []
    selected_ids: list[str] = []
    for cert in certs:
        selected = (
            cutoff is not None
            and cert.status != "refusal"
            and cert.log_e_value >= cutoff
        )
        if selected:
            selected_ids.append(cert.certificate_id)
        decisions.append(
            FleetDecision(
                certificate_id=cert.certificate_id,
                selected=selected,
                rank=ranks.get(id(cert)),
                log_e_value=cert.log_e_value,
                cutoff_log_e_value=cutoff,
                status=cert.status,
            )
        )

    return FleetVerdict(
        snapshot_id=snapshot_id,
        target_fraction=q,
        family_size=family_size,
        selected_count=len(selected_ids),
        cutoff_log_e_value=cutoff,
        selected_ids=tuple(selected_ids),
        decisions=tuple(decisions),
    )


def _ebh_cutoff_log_e_value(
    descending_log_e_values: Sequence[float],
    *,
    family_size: int,
    target_fraction: float,
) -> float | None:
    cutoff: float | None = None
    log_family_size = math.log(family_size)
    log_q = math.log(target_fraction)
    for rank, log_e in enumerate(descending_log_e_values, start=1):
        threshold = log_family_size - log_q - math.log(rank)
        if log_e >= threshold:
            cutoff = threshold
    return cutoff


def _require_target_fraction(value: float) -> float:
    q = float(value)
    if not math.isfinite(q) or q <= 0.0 or q > 1.0:
        raise ValueError("target_fraction must lie in (0, 1]")
    return q


def _require_one_snapshot(certificates: Sequence[FleetCertificate]) -> str:
    snapshot_ids = {cert.snapshot_id for cert in certificates}
    if len(snapshot_ids) != 1:
        raise ValueError("fleet_verdict requires one shared snapshot_id")
    return next(iter(snapshot_ids))


def _require_unique_ids(certificates: Sequence[FleetCertificate]) -> None:
    seen: set[str] = set()
    for cert in certificates:
        if cert.certificate_id in seen:
            raise ValueError(f"duplicate certificate_id: {cert.certificate_id!r}")
        seen.add(cert.certificate_id)


def _require_nonempty_string(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


__all__ = [
    "FleetCertificate",
    "FleetDecision",
    "FleetVerdict",
    "anchor_tail_fleet_certificate",
    "fleet_verdict",
    "refusal_fleet_certificate",
]
