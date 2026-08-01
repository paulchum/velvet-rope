from __future__ import annotations

import json
from pathlib import Path

from aab.serialization import canonical_hash_sha256
from aab.signing import verify_signature_record
from aab.verify_certificate import unsigned_certificate_payload


def test_tamper_detection() -> None:
    certificate = json.loads(
        Path("verification/velvet_decision_certificate.json").read_text(encoding="utf-8")
    )
    original_hash = canonical_hash_sha256(unsigned_certificate_payload(certificate))

    tampered = dict(certificate)
    tampered["decision"] = "lockout"
    tampered_hash = canonical_hash_sha256(unsigned_certificate_payload(tampered))

    signature = certificate["signature"]
    public_key_pem = signature["public_verification_material"]["public_key_pem"]
    assert tampered_hash != original_hash
    assert not verify_signature_record(signature, tampered_hash, public_key=public_key_pem)
