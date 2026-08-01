"""Verdict certificate issuance service with an append-only certificate log.

This replaces the upstream ``drift_deployment`` service surface on Velvet's
signing stack: every certificate issued here is Ed25519-signed at issue time
(closing the upstream no-op-signer gap) and appended to a JSONL certificate
log. Expiry checks and recertification produce successor certificates whose
``evidence.prior_certificate_hash`` links back to the certificate they
replace, so the full lease history of an irreversible decision is replayable.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from velvet.signing import SigningProvider
from velvet.verdict.certificate import (
    JsonObject,
    certificate_from_drift_verdict,
    certificate_from_finite_horizon,
    verdict_certificate_hash,
    verify_verdict_certificate,
)
from velvet.verdict.drift_expiry import Verdict as DriftVerdict
from velvet.verdict.drift_expiry import issue_verdict as issue_drift_verdict
from velvet.verdict.finite_horizon import finite_horizon_verdict


@dataclass(frozen=True)
class DeploymentResult:
    """One service response: the signed certificate plus the runtime answer."""

    certificate: JsonObject
    authorized: bool
    reason: str


class VerdictCertificateService:
    """Issue, log, and recertify verdict certificates for one tenant."""

    def __init__(
        self,
        store_path: str | Path,
        *,
        issuer: str = "velvet",
        tenant_id: str = "local-demo",
        environment: str = "local",
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
    ) -> None:
        self.store_path = Path(store_path)
        self.issuer = issuer
        self.tenant_id = tenant_id
        self.environment = environment
        self._signer = signer
        self._signing_key_id = signing_key_id

    # -- issuance ---------------------------------------------------------

    def issue_finite_horizon(
        self,
        arms: Sequence[tuple[int, int]],
        candidate: int,
        *,
        decision_id: str,
        decision_class: str,
        target_id_hash: str,
        inputs_hash: str,
        horizon_H: int,
        gate: float = 0.01,
        delta: float = 0.05,
        rounds_per_day: float | None = None,
        ttl_seconds: float | None = None,
        **verdict_kwargs: Any,
    ) -> DeploymentResult:
        """Run the Theorem V verdict and issue its signed certificate."""

        verdict = finite_horizon_verdict(
            arms,
            candidate,
            horizon_H=horizon_H,
            gate=gate,
            delta=delta,
            rounds_per_day=rounds_per_day,
            **verdict_kwargs,
        )
        certificate = certificate_from_finite_horizon(
            verdict,
            decision_id=decision_id,
            decision_class=decision_class,
            target_id_hash=target_id_hash,
            inputs_hash=inputs_hash,
            gate_c=gate,
            issuer=self.issuer,
            tenant_id=self.tenant_id,
            environment=self.environment,
            rounds_per_day=rounds_per_day,
            ttl_seconds=ttl_seconds,
            signer=self._signer,
            signing_key_id=self._signing_key_id,
        )
        return self._record(certificate)

    def issue_drift(
        self,
        post: Sequence[tuple[float, float]],
        candidate: int,
        *,
        decision_id: str,
        decision_class: str,
        target_id_hash: str,
        inputs_hash: str,
        gate: float,
        delta: float,
        rho: float,
        delta_tail: float | None = None,
        rounds_per_day: float | None = None,
        ttl_seconds: float | None = None,
        prior_certificate_hash: str | None = None,
    ) -> DeploymentResult:
        """Issue a windowed drift-expiry certificate for retiring ``candidate``."""

        drift = issue_drift_verdict(
            post,
            cand=candidate,
            c=gate,
            delta=delta,
            rho=rho,
            delta_tail=delta_tail,
        )
        certificate = certificate_from_drift_verdict(
            drift,
            decision_id=decision_id,
            decision_class=decision_class,
            target_id_hash=target_id_hash,
            inputs_hash=inputs_hash,
            issuer=self.issuer,
            tenant_id=self.tenant_id,
            environment=self.environment,
            rounds_per_day=rounds_per_day,
            ttl_seconds=ttl_seconds,
            prior_certificate_hash=prior_certificate_hash,
            signer=self._signer,
            signing_key_id=self._signing_key_id,
        )
        return self._record(certificate)

    def recertify_drift(
        self,
        post: Sequence[tuple[float, float]],
        prior_certificate: Mapping[str, Any],
        **kwargs: Any,
    ) -> DeploymentResult:
        """Issue a successor certificate linked to ``prior_certificate``.

        Recertification never extends the prior certificate: it evaluates the
        current posterior state from scratch and links lineage via
        ``evidence.prior_certificate_hash``.
        """

        subject = prior_certificate.get("subject")
        if not isinstance(subject, Mapping):
            raise ValueError("prior certificate missing subject")
        parameters = prior_certificate.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ValueError("prior certificate missing parameters")
        return self.issue_drift(
            post,
            _subject_candidate(kwargs),
            decision_id=str(subject["decision_id"]),
            decision_class=str(subject["decision_class"]),
            target_id_hash=str(subject["target_id_hash"]),
            inputs_hash=str(kwargs.pop("inputs_hash")),
            gate=float(parameters["gate_c"]),
            delta=float(parameters["delta"]),
            rho=float(parameters["rho"]),
            delta_tail=_optional_float(parameters.get("delta_tail")),
            prior_certificate_hash=verdict_certificate_hash(prior_certificate),
            **kwargs,
        )

    # -- checking ---------------------------------------------------------

    def check(
        self,
        certificate: Mapping[str, Any],
        *,
        public_key: str | bytes,
        now: datetime | None = None,
    ) -> DeploymentResult:
        """Verify a certificate and answer whether it licenses execution now."""

        verification = verify_verdict_certificate(
            certificate,
            public_key=public_key,
            expected_issuer=self.issuer,
            expected_tenant_id=self.tenant_id,
            now=now if now is not None else datetime.now(tz=UTC),
        )
        return DeploymentResult(
            certificate=dict(certificate),
            authorized=verification.licenses_execution,
            reason=verification.reason
            or (
                "safe_kill certificate valid"
                if verification.licenses_execution
                else f"verdict={verification.verdict}"
            ),
        )

    # -- storage ----------------------------------------------------------

    def records(self) -> Iterator[JsonObject]:
        if not self.store_path.exists():
            return iter(())
        lines = self.store_path.read_text(encoding="utf-8").splitlines()
        return (json.loads(line) for line in lines if line.strip())

    def _record(self, certificate: JsonObject) -> DeploymentResult:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(certificate, sort_keys=True) + "\n")
        verdict = str(certificate["verdict"])
        return DeploymentResult(
            certificate=certificate,
            authorized=verdict == "safe_kill",
            reason=str(certificate.get("reason_code") or f"verdict={verdict}"),
        )


def _subject_candidate(kwargs: dict[str, Any]) -> int:
    candidate = kwargs.pop("candidate", None)
    if not isinstance(candidate, int):
        raise ValueError("recertify_drift requires candidate=<arm index>")
    return candidate


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


__all__ = [
    "DeploymentResult",
    "DriftVerdict",
    "VerdictCertificateService",
]
