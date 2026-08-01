"""Signed Verdict Certificates: the wire form of a certified decision.

A verdict certificate binds one irreversible decision (retire a tool route,
agent, variant, or expert; permanent lockout) to a verdict
``{safe_kill | required_inspection | refusal}`` that is delta-bounded under
the stated hypotheses in exactly one claim currency, carries priced
alternatives, expires, and is Ed25519-signed with purpose
``velvet.verdict_certificate.v1``. Schema:
``schemas/velvet_rope/verdict_certificate.schema.json``.

An expired certificate licenses nothing: verification reports ``expired`` and
the runtime must treat the decision as ``required_inspection``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from velvet.serialization import canonical_hash_sha256
from velvet.signing import (
    PURPOSE_VERDICT_CERTIFICATE,
    SigningProvider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.verdict.drift_expiry import Verdict as DriftVerdict
from velvet.verdict.finite_horizon import FiniteHorizonVerdict

JsonObject = dict[str, Any]

VERDICT_CERTIFICATE_SCHEMA_VERSION = "velvet.verdict_certificate.v1"
VERDICT_CERTIFICATE_SCHEMA_ARTIFACT = "schemas/velvet_rope/verdict_certificate.schema.json"
CANONICALIZATION = "velvet.canonical_json.v1.sha256.unsigned_payload"
UNSIGNED_EXCLUDED_KEYS = frozenset({"signature", "certificate_hash"})

DECISION_CLASSES = (
    "retire_tool_route",
    "retire_agent",
    "retire_variant",
    "retire_expert",
    "permanent_lockout",
)

_DRIFT_STATUS_TO_VERDICT = {
    "CertifiedSafe": "safe_kill",
    "Expired": "required_inspection",
    "CertifiedNotSafe": "refusal",
    "UncertifiedNeedsRefinement": "refusal",
    "UncertifiedNeedsMoreHorizon": "required_inspection",
}

_schema_validator: Draft202012Validator | None = None


@dataclass(frozen=True)
class VerdictVerification:
    """Outcome of verifying a verdict certificate against a pinned key."""

    status: str  # accepted | expired | rejected
    verdict: str | None
    certificate_hash: str | None
    reason: str | None = None

    @property
    def licenses_execution(self) -> bool:
        """True iff the certificate currently licenses the irreversible action."""

        return self.status == "accepted" and self.verdict == "safe_kill"


def unsigned_verdict_payload(payload: Mapping[str, Any]) -> JsonObject:
    return {
        str(key): value
        for key, value in payload.items()
        if str(key) not in UNSIGNED_EXCLUDED_KEYS
    }


def verdict_certificate_hash(payload: Mapping[str, Any]) -> str:
    """Canonical hash of the certificate minus signature and stored hash."""

    return canonical_hash_sha256(unsigned_verdict_payload(payload))


def issue_verdict_certificate(
    *,
    verdict: str,
    decision_id: str,
    decision_class: str,
    target_id_hash: str,
    claim_currency: str,
    delta: float,
    gate_c: float,
    rho: float,
    method: str,
    hypotheses: Sequence[str],
    theorem_refs: Sequence[str],
    inputs_hash: str,
    expected_rounds_to_gate_crossing: float,
    tail_probability_bound: float,
    tail_crossing_probability: float,
    tail_drift_penalty: float,
    tail_posterior_expected_shortfall: float,
    horizon_rounds: float,
    rounds_remaining: float,
    issuer: str = "velvet",
    tenant_id: str = "local-demo",
    environment: str = "local",
    reason_code: str = "",
    refusal_reason: str | None = None,
    delta_tail: float | None = None,
    horizon_H: int | None = None,
    exploration_mass: float | None = None,
    posterior_state_hash: str | None = None,
    t_hat: float | None = None,
    rounds_per_day: float | None = None,
    ttl_seconds: float | None = None,
    expires_at: str | None = None,
    issued_at: str | None = None,
    fleet: Mapping[str, Any] | None = None,
    max_de_certificate_hash: str | None = None,
    prior_certificate_hash: str | None = None,
    inspection_dollars: float | None = None,
    inspection_dollars_source: str | None = None,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> JsonObject:
    """Build, validate, hash, and sign one verdict certificate.

    Wall-clock expiry is mandatory: supply ``expires_at`` directly,
    ``ttl_seconds``, or ``rounds_per_day`` (projecting ``rounds_remaining``
    onto the calendar). Rounds are the validity clock of the underlying
    verdict; the wall-clock projection is what runtimes enforce.
    """

    if verdict not in {"safe_kill", "required_inspection", "refusal"}:
        raise ValueError(f"unsupported verdict: {verdict!r}")
    if decision_class not in DECISION_CLASSES:
        raise ValueError(f"unsupported decision_class: {decision_class!r}")
    if claim_currency not in {"BP", "BP_TV", "FM"}:
        raise ValueError(f"unsupported claim_currency: {claim_currency!r}")
    if verdict == "refusal" and not (refusal_reason or reason_code):
        raise ValueError("refusal verdicts require refusal_reason or reason_code")
    if inspection_dollars is not None and not inspection_dollars_source:
        raise ValueError("dollar prices require an explicit dollars_source")

    issued = _parse_timestamp(issued_at) if issued_at else datetime.now(tz=UTC)
    expiry = _resolve_expiry(
        issued,
        expires_at=expires_at,
        ttl_seconds=ttl_seconds,
        rounds_remaining=rounds_remaining,
        rounds_per_day=rounds_per_day,
    )

    subject: JsonObject = {
        "decision_id": decision_id,
        "decision_class": decision_class,
        "target_id_hash": target_id_hash,
    }
    if posterior_state_hash is not None:
        subject["posterior_state_hash"] = posterior_state_hash

    inspection: JsonObject = {
        "expected_rounds_to_gate_crossing": float(expected_rounds_to_gate_crossing),
    }
    if inspection_dollars is not None:
        inspection["dollars"] = float(inspection_dollars)
        inspection["dollars_source"] = inspection_dollars_source

    payload: JsonObject = {
        "schema_version": VERDICT_CERTIFICATE_SCHEMA_VERSION,
        "canonicalization": CANONICALIZATION,
        "certificate_id": f"vverdict_{uuid.uuid4().hex}",
        "issuer": issuer,
        "tenant_id": tenant_id,
        "environment": environment,
        "subject": subject,
        "verdict": verdict,
        "reason_code": reason_code,
        "refusal_reason": refusal_reason,
        "claim_currency": claim_currency,
        "parameters": {
            "delta": float(delta),
            "delta_tail": None if delta_tail is None else float(delta_tail),
            "gate_c": float(gate_c),
            "rho": float(rho),
            "horizon_H": horizon_H,
            "exploration_mass": exploration_mass,
            "method": method,
            "baseline_mode": "posterior_candidate_excluded",
        },
        "hypotheses": list(hypotheses),
        "prices": {
            "inspection": inspection,
            "tail": {
                "probability_bound": float(tail_probability_bound),
                "crossing_probability": float(tail_crossing_probability),
                "drift_penalty": float(tail_drift_penalty),
                "posterior_expected_shortfall": float(tail_posterior_expected_shortfall),
            },
        },
        "validity": {
            "issued_at": _format_timestamp(issued),
            "not_before": _format_timestamp(issued),
            "expires_at": _format_timestamp(expiry),
            "horizon_rounds": float(horizon_rounds),
            "rounds_remaining": float(rounds_remaining),
            "t_hat": None if t_hat is None else float(t_hat),
            "rounds_per_day": None if rounds_per_day is None else float(rounds_per_day),
            "recertification": "required_inspection_on_expiry",
        },
        "fleet": dict(fleet) if fleet is not None else None,
        "evidence": {
            "inputs_hash": inputs_hash,
            "max_de_certificate_hash": max_de_certificate_hash,
            "prior_certificate_hash": prior_certificate_hash,
            "theorem_refs": list(theorem_refs),
        },
    }

    payload["certificate_hash"] = verdict_certificate_hash(payload)
    resolved_key_id = signing_key_id
    if resolved_key_id is None and signer is not None:
        resolved_key_id = signer_default_key_id(signer)
    payload["signature"] = sign_payload_hash(
        str(payload["certificate_hash"]),
        purpose=PURPOSE_VERDICT_CERTIFICATE,
        tenant_id=tenant_id,
        signer=signer,
        **({"key_id": resolved_key_id} if resolved_key_id is not None else {}),
    )
    validate_verdict_certificate_payload(payload)
    return payload


def certificate_from_finite_horizon(
    finite_horizon: FiniteHorizonVerdict,
    *,
    decision_id: str,
    decision_class: str,
    target_id_hash: str,
    inputs_hash: str,
    gate_c: float,
    rho: float = 0.0,
    hypotheses: Sequence[str] = (
        "host-aware rescue event (Theorem V stopping set)",
        "modeled posterior-predictive kernel, stable finite arm set",
        "baseline_mode=posterior_candidate_excluded",
    ),
    theorem_refs: Sequence[str] = ("docs/math/theorem_v_finite_horizon_verdict.txt",),
    **kwargs: Any,
) -> JsonObject:
    """Wrap a Theorem V finite-horizon verdict as a signed certificate."""

    price_inspection = finite_horizon.price_of_inspection
    price_tail = finite_horizon.price_of_tail
    kwargs.setdefault("rounds_per_day", finite_horizon.rounds_per_day)
    return issue_verdict_certificate(
        verdict=finite_horizon.verdict,
        decision_id=decision_id,
        decision_class=decision_class,
        target_id_hash=target_id_hash,
        claim_currency="BP_TV" if rho > 0.0 else "BP",
        delta=finite_horizon.delta,
        gate_c=gate_c,
        rho=rho,
        method=finite_horizon.method,
        hypotheses=hypotheses,
        theorem_refs=theorem_refs,
        inputs_hash=inputs_hash,
        expected_rounds_to_gate_crossing=(
            price_inspection.expected_rounds_to_gate_crossing
        ),
        tail_probability_bound=price_tail.probability_bound,
        tail_crossing_probability=price_tail.crossing_probability,
        tail_drift_penalty=price_tail.drift_penalty,
        tail_posterior_expected_shortfall=price_tail.posterior_expected_shortfall,
        horizon_rounds=float(finite_horizon.horizon_H),
        rounds_remaining=float(finite_horizon.rounds_remaining),
        horizon_H=finite_horizon.horizon_H,
        refusal_reason=finite_horizon.refusal_reason,
        **kwargs,
    )


def certificate_from_drift_verdict(
    drift_verdict: DriftVerdict,
    *,
    decision_id: str,
    decision_class: str,
    target_id_hash: str,
    inputs_hash: str,
    hypotheses: Sequence[str] = (
        "bounded drift D(rho) with stationary conjugate posteriors (Route A)",
        "anchor shape hypothesis min(alpha_b, beta_b) >= 1",
        "windowed validity only; nothing is claimed past expiry",
    ),
    theorem_refs: Sequence[str] = ("docs/math/drift_expiry_certificates.txt",),
    **kwargs: Any,
) -> JsonObject:
    """Wrap a drift-expiry verdict as a signed certificate."""

    verdict = _DRIFT_STATUS_TO_VERDICT.get(drift_verdict.status)
    if verdict is None:
        raise ValueError(f"unsupported drift verdict status: {drift_verdict.status!r}")
    window = drift_verdict.W
    return issue_verdict_certificate(
        verdict=verdict,
        decision_id=decision_id,
        decision_class=decision_class,
        target_id_hash=target_id_hash,
        claim_currency="BP_TV" if drift_verdict.rho > 0.0 else "BP",
        delta=drift_verdict.delta,
        delta_tail=drift_verdict.delta_tail,
        gate_c=drift_verdict.c,
        rho=drift_verdict.rho,
        method="drift_windowed",
        hypotheses=hypotheses,
        theorem_refs=theorem_refs,
        inputs_hash=inputs_hash,
        expected_rounds_to_gate_crossing=0.0,
        tail_probability_bound=(
            1.0 if drift_verdict.tail_bound is None else float(drift_verdict.tail_bound)
        ),
        tail_crossing_probability=(
            1.0 if drift_verdict.tail_bound is None else float(drift_verdict.tail_bound)
        ),
        tail_drift_penalty=0.0,
        tail_posterior_expected_shortfall=0.0,
        horizon_rounds=0.0 if window is None else float(window),
        rounds_remaining=0.0 if window is None else float(window),
        t_hat=None if drift_verdict.T_hat is None else float(drift_verdict.T_hat),
        reason_code=drift_verdict.reason_code,
        refusal_reason=drift_verdict.reason or None,
        **kwargs,
    )


def verify_verdict_certificate(
    payload: Mapping[str, Any],
    *,
    public_key: str | bytes,
    expected_issuer: str | None = None,
    expected_tenant_id: str | None = None,
    now: datetime | None = None,
) -> VerdictVerification:
    """Verify one certificate against a pinned public key.

    The embedded ``public_verification_material`` is never consulted; the
    caller supplies the trust root. Expired certificates verify their
    signatures but report ``expired`` — they license nothing.
    """

    errors = _schema_errors(payload)
    if errors:
        return VerdictVerification(
            status="rejected",
            verdict=None,
            certificate_hash=None,
            reason=f"schema: {errors[0]}",
        )
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        return VerdictVerification("rejected", None, None, "missing signature object")
    if signature.get("purpose") != PURPOSE_VERDICT_CERTIFICATE:
        return VerdictVerification("rejected", None, None, "signature purpose mismatch")
    if expected_issuer is not None and payload.get("issuer") != expected_issuer:
        return VerdictVerification("rejected", None, None, "issuer mismatch")
    if expected_tenant_id is not None and payload.get("tenant_id") != expected_tenant_id:
        return VerdictVerification("rejected", None, None, "tenant mismatch")

    recomputed = verdict_certificate_hash(payload)
    stored = payload.get("certificate_hash")
    if stored != recomputed:
        return VerdictVerification("rejected", None, None, "certificate hash mismatch")
    if not verify_signature_record(
        signature,
        recomputed,
        purpose=PURPOSE_VERDICT_CERTIFICATE,
        public_key=public_key,
    ):
        return VerdictVerification(
            "rejected", None, None, "signature verification failed"
        )

    verdict = str(payload["verdict"])
    validity = cast(Mapping[str, Any], payload["validity"])
    expires_at = _parse_timestamp(str(validity["expires_at"]))
    moment = now if now is not None else datetime.now(tz=UTC)
    if moment >= expires_at:
        return VerdictVerification(
            status="expired",
            verdict=verdict,
            certificate_hash=recomputed,
            reason="verdict_expired_recertification_required",
        )
    return VerdictVerification(
        status="accepted",
        verdict=verdict,
        certificate_hash=recomputed,
    )


def validate_verdict_certificate_payload(payload: Mapping[str, Any]) -> None:
    errors = _schema_errors(payload)
    if errors:
        raise ValueError(f"verdict certificate schema validation failed: {errors[0]}")


def _schema_errors(payload: Mapping[str, Any]) -> list[str]:
    global _schema_validator
    if _schema_validator is None:
        schema_path = Path(VERDICT_CERTIFICATE_SCHEMA_ARTIFACT)
        if not schema_path.exists():
            # Repo-relative fallback so the CLI works from any directory.
            schema_path = (
                Path(__file__).resolve().parents[3] / VERDICT_CERTIFICATE_SCHEMA_ARTIFACT
            )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        _schema_validator = Draft202012Validator(schema)
    return [
        f"{'.'.join(str(part) for part in error.path)}: {error.message}"
        for error in sorted(
            _schema_validator.iter_errors(dict(payload)),
            key=lambda item: list(item.path),
        )
    ]


def _resolve_expiry(
    issued: datetime,
    *,
    expires_at: str | None,
    ttl_seconds: float | None,
    rounds_remaining: float,
    rounds_per_day: float | None,
) -> datetime:
    if expires_at is not None:
        expiry = _parse_timestamp(expires_at)
    elif ttl_seconds is not None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        expiry = issued + timedelta(seconds=float(ttl_seconds))
    elif rounds_per_day is not None:
        if rounds_per_day <= 0:
            raise ValueError("rounds_per_day must be positive")
        expiry = issued + timedelta(days=float(rounds_remaining) / float(rounds_per_day))
    else:
        raise ValueError(
            "wall-clock expiry is mandatory: supply expires_at, ttl_seconds, "
            "or rounds_per_day"
        )
    if expiry <= issued:
        raise ValueError("expires_at must be after issued_at")
    return expiry


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must be timezone-aware: {value!r}")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
