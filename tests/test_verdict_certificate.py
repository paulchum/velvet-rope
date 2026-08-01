"""Verdict certificate issuance, verification, expiry, and lineage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from velvet.signing import load_demo_ed25519_signer
from velvet.verdict.certificate import (
    certificate_from_finite_horizon,
    issue_verdict_certificate,
    verdict_certificate_hash,
    verify_verdict_certificate,
)
from velvet.verdict.finite_horizon import finite_horizon_verdict
from velvet.verdict.service import VerdictCertificateService

PUBLIC_KEY = Path("tests/fixtures/keys/velvet_demo_ed25519.pub").read_text(encoding="utf-8")


def _service(tmp_path: Path) -> VerdictCertificateService:
    return VerdictCertificateService(
        tmp_path / "verdicts.jsonl", signer=load_demo_ed25519_signer()
    )


def _issue(tmp_path: Path) -> dict[str, object]:
    service = _service(tmp_path)
    return service.issue_finite_horizon(
        [(2, 1), (5, 45)],
        1,
        decision_id="dec-001",
        decision_class="retire_variant",
        target_id_hash="sha256:" + "ab" * 32,
        inputs_hash="sha256:" + "cd" * 32,
        horizon_H=6,
        rounds_per_day=100.0,
    ).certificate


def test_issue_and_verify_safe_kill(tmp_path: Path) -> None:
    certificate = _issue(tmp_path)
    assert certificate["verdict"] == "safe_kill"
    assert certificate["claim_currency"] == "BP"
    verification = verify_verdict_certificate(certificate, public_key=PUBLIC_KEY)
    assert verification.status == "accepted"
    assert verification.licenses_execution


def test_tampered_certificate_rejects(tmp_path: Path) -> None:
    certificate = dict(_issue(tmp_path))
    certificate["verdict"] = "refusal"
    verification = verify_verdict_certificate(certificate, public_key=PUBLIC_KEY)
    assert verification.status == "rejected"
    assert not verification.licenses_execution


def test_expired_certificate_reports_required_inspection(tmp_path: Path) -> None:
    certificate = _issue(tmp_path)
    future = datetime.now(tz=UTC) + timedelta(days=365)
    verification = verify_verdict_certificate(
        certificate, public_key=PUBLIC_KEY, now=future
    )
    assert verification.status == "expired"
    assert verification.reason == "verdict_expired_recertification_required"
    assert not verification.licenses_execution


def test_wrong_issuer_rejects(tmp_path: Path) -> None:
    certificate = _issue(tmp_path)
    verification = verify_verdict_certificate(
        certificate, public_key=PUBLIC_KEY, expected_issuer="someone-else"
    )
    assert verification.status == "rejected"
    assert verification.reason == "issuer mismatch"


def test_wall_clock_expiry_is_mandatory() -> None:
    verdict = finite_horizon_verdict([(2, 1), (5, 45)], 1, horizon_H=6)
    with pytest.raises(ValueError, match="wall-clock expiry is mandatory"):
        certificate_from_finite_horizon(
            verdict,
            decision_id="dec-002",
            decision_class="retire_variant",
            target_id_hash="sha256:" + "ab" * 32,
            inputs_hash="sha256:" + "cd" * 32,
            gate_c=0.01,
        )


def test_dollar_prices_require_a_source() -> None:
    with pytest.raises(ValueError, match="dollars_source"):
        issue_verdict_certificate(
            verdict="safe_kill",
            decision_id="dec-003",
            decision_class="retire_variant",
            target_id_hash="sha256:" + "ab" * 32,
            claim_currency="BP",
            delta=0.05,
            gate_c=0.01,
            rho=0.0,
            method="exact_dp",
            hypotheses=["modeled kernel"],
            theorem_refs=["docs/math/theorem_v_finite_horizon_verdict.txt"],
            inputs_hash="sha256:" + "cd" * 32,
            expected_rounds_to_gate_crossing=1.0,
            tail_probability_bound=0.01,
            tail_crossing_probability=0.01,
            tail_drift_penalty=0.0,
            tail_posterior_expected_shortfall=0.0,
            horizon_rounds=6.0,
            rounds_remaining=6.0,
            ttl_seconds=3600,
            inspection_dollars=125.0,
        )


def test_drift_issue_and_recertify_lineage(tmp_path: Path) -> None:
    service = _service(tmp_path)
    first = service.issue_drift(
        [(60.0, 40.0), (30.0, 70.0)],
        1,
        decision_id="dec-004",
        decision_class="retire_tool_route",
        target_id_hash="sha256:" + "ef" * 32,
        inputs_hash="sha256:" + "01" * 32,
        gate=0.01,
        delta=0.05,
        rho=0.001,
        delta_tail=0.05,
        ttl_seconds=3600,
    )
    assert first.certificate["verdict"] == "safe_kill"
    assert first.authorized
    successor = service.recertify_drift(
        [(65.0, 45.0), (30.0, 75.0)],
        first.certificate,
        candidate=1,
        inputs_hash="sha256:" + "02" * 32,
        ttl_seconds=3600,
    )
    evidence = successor.certificate["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["prior_certificate_hash"] == verdict_certificate_hash(
        first.certificate
    )
    assert len(list(service.records())) == 2


def test_service_check_answers_authorization(tmp_path: Path) -> None:
    service = _service(tmp_path)
    certificate = _issue(tmp_path)
    assert service.check(certificate, public_key=PUBLIC_KEY).authorized
    future = datetime.now(tz=UTC) + timedelta(days=365)
    assert not service.check(certificate, public_key=PUBLIC_KEY, now=future).authorized
