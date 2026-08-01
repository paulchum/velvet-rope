from __future__ import annotations

import json
from pathlib import Path

from aab.serialization import canonical_hash_sha256
from aab.signing import verify_signature_record
from aab.verify_certificate import unsigned_certificate_payload, verify_certificate


def test_certificate_verifies() -> None:
    certificate_path = Path("verification/velvet_decision_certificate.json")
    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    unsigned = unsigned_certificate_payload(certificate)
    payload_hash = canonical_hash_sha256(unsigned)

    assert payload_hash == "sha256:e22cd454ac98f9de59c8e4eb4efd2920e9aaf1c6e1cb08a1055aa5924b670115"
    assert certificate["artifact_hash"] == payload_hash

    signature = certificate["signature"]
    public_key_pem = signature["public_verification_material"]["public_key_pem"]
    assert public_key_pem == Path("tests/fixtures/keys/velvet_demo_ed25519.pub").read_text(
        encoding="utf-8"
    )
    assert verify_signature_record(signature, payload_hash, public_key=public_key_pem)
    result = verify_certificate(
        certificate_path,
        public_key_file=Path("tests/fixtures/keys/velvet_demo_ed25519.pub"),
    )
    assert result["payload_hash"] == payload_hash
    assert result["trust"] == "pinned_key"
