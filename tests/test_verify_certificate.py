"""Trust-root pinning behavior of the generic certificate verifier.

A certificate's embedded key material is never a trust root: with no pinned
key or trust-root descriptor the verifier must refuse, and the diagnostic
embedded-key path must label its result self-attested (CLI exit code 2).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from velvet.verify_certificate import main, verify_certificate

CERTIFICATE = Path("benchmarks/agent_authorization/verification/velvet_decision_certificate.json")
PUBLIC_KEY = Path("tests/fixtures/keys/velvet_demo_ed25519.pub")
PURPOSE = "velvet.agent_authorization.decision_certificate.v0.1"


def test_refuses_without_a_trust_root() -> None:
    with pytest.raises(ValueError, match="no trust root provided"):
        verify_certificate(CERTIFICATE)


def test_accepts_with_pinned_key_file() -> None:
    result = verify_certificate(CERTIFICATE, public_key_file=PUBLIC_KEY)
    assert result["status"] == "accepted"
    assert result["trust"] == "pinned_key"


def test_accepts_with_trust_root_descriptor(tmp_path: Path) -> None:
    root = tmp_path / "trust.json"
    root.write_text(
        json.dumps(
            {
                "public_key_pem": PUBLIC_KEY.read_text(encoding="utf-8"),
                "allowed_purposes": [PURPOSE],
            }
        ),
        encoding="utf-8",
    )
    result = verify_certificate(CERTIFICATE, trust_root=root)
    assert result["trust"] == "trust_root"


def test_trust_root_rejects_unlisted_purpose(tmp_path: Path) -> None:
    root = tmp_path / "trust.json"
    root.write_text(
        json.dumps(
            {
                "public_key_pem": PUBLIC_KEY.read_text(encoding="utf-8"),
                "allowed_purposes": ["velvet.verdict_certificate.v1"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not allowed by the trust root"):
        verify_certificate(CERTIFICATE, trust_root=root)


def test_expected_purpose_mismatch_rejects() -> None:
    with pytest.raises(ValueError, match="purpose mismatch"):
        verify_certificate(
            CERTIFICATE,
            public_key_file=PUBLIC_KEY,
            expected_purpose="velvet.verdict_certificate.v1",
        )


def test_embedded_key_is_labeled_self_attested() -> None:
    result = verify_certificate(CERTIFICATE, allow_embedded_key=True)
    assert result["trust"] == "self_attested_key"


def test_cli_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(CERTIFICATE), "--public-key-file", str(PUBLIC_KEY)]) == 0
    assert main([str(CERTIFICATE)]) == 1
    assert main([str(CERTIFICATE), "--allow-embedded-key"]) == 2
    captured = capsys.readouterr()
    assert "UNTRUSTED" in captured.err


def test_tampered_certificate_rejects(tmp_path: Path) -> None:
    payload = json.loads(CERTIFICATE.read_text(encoding="utf-8"))
    payload["decision"] = "tampered"
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_certificate(tampered, public_key_file=PUBLIC_KEY)
