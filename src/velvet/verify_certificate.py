"""Verify Velvet decision and verdict certificates against a pinned trust root.

Verification requires an explicit trust root: a public key file or a trust-root
descriptor. A certificate's own embedded ``public_verification_material`` is
never a trust root — verifying against it only proves self-consistency, not
issuance. The ``--allow-embedded-key`` escape hatch exists for diagnostics; it
labels the result ``UNTRUSTED`` and the CLI exits nonzero so pipelines cannot
mistake a self-attested certificate for a verified one.

A trust-root descriptor is a JSON object:

    {
      "issuer": "velvet",                        // optional, pins payload issuer
      "public_key_pem": "...",                    // or "public_key_file": "path"
      "allowed_purposes": ["velvet.verdict_certificate.v1"],
      "allowed_schema_versions": ["velvet.verdict_certificate.v1"]
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from velvet.serialization import canonical_hash_sha256
from velvet.signing import verify_signature_record

JsonObject = dict[str, Any]

UNSIGNED_EXCLUDED_KEYS = frozenset({"signature", "artifact_hash", "certificate_hash"})

_EXIT_ACCEPTED = 0
_EXIT_REJECTED = 1
_EXIT_UNTRUSTED = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a Velvet decision or verdict certificate against a pinned "
            "trust root."
        ),
    )
    parser.add_argument("certificate")
    parser.add_argument(
        "--public-key-file",
        help="PEM or raw-base64 Ed25519 public key file (a trust root).",
    )
    parser.add_argument(
        "--trust-root",
        help=(
            "JSON trust-root descriptor pinning key material, allowed purposes, "
            "allowed schema versions, and optionally the issuer."
        ),
    )
    parser.add_argument(
        "--expected-purpose",
        help="Require signature.purpose to equal this value.",
    )
    parser.add_argument(
        "--expected-schema",
        help="Require the payload schema_version to equal this value.",
    )
    parser.add_argument(
        "--allow-embedded-key",
        action="store_true",
        help=(
            "Diagnostic only: verify against the certificate's own embedded key. "
            "The result is UNTRUSTED (self-attested) and the exit code is nonzero."
        ),
    )
    args = parser.parse_args(argv)

    try:
        result = verify_certificate(
            Path(args.certificate),
            public_key_file=Path(args.public_key_file) if args.public_key_file else None,
            trust_root=Path(args.trust_root) if args.trust_root else None,
            expected_purpose=args.expected_purpose,
            expected_schema_version=args.expected_schema,
            allow_embedded_key=args.allow_embedded_key,
        )
    except ValueError as error:
        print(f"rejected: {error}", file=sys.stderr)
        return _EXIT_REJECTED

    if result["trust"] == "self_attested_key":
        print(
            "UNTRUSTED: signature verified against the certificate's own embedded "
            "key material; this proves self-consistency, not issuance. "
            f"payload_hash={result['payload_hash']}",
            file=sys.stderr,
        )
        return _EXIT_UNTRUSTED

    print(f"accepted: payload_hash={result['payload_hash']}")
    return _EXIT_ACCEPTED


def verify_certificate(
    path: Path,
    *,
    public_key_file: Path | None = None,
    trust_root: Path | Mapping[str, Any] | None = None,
    expected_purpose: str | None = None,
    expected_schema_version: str | None = None,
    allow_embedded_key: bool = False,
) -> JsonObject:
    payload = _read_json_object(path)
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        raise ValueError("certificate missing signature object")

    root = _load_trust_root(trust_root)
    _require_purpose(signature, payload, root, expected_purpose)
    _require_schema_version(payload, root, expected_schema_version)
    _require_issuer(payload, root)

    unsigned = unsigned_certificate_payload(payload)
    payload_hash = canonical_hash_sha256(unsigned)
    stored_hash = payload.get("artifact_hash", payload.get("certificate_hash"))
    if stored_hash != payload_hash:
        raise ValueError(
            f"certificate hash mismatch: expected {payload_hash}, got {stored_hash!r}"
        )

    public_key, trust = _public_key_material(
        signature,
        public_key_file=public_key_file,
        trust_root=root,
        allow_embedded_key=allow_embedded_key,
    )
    if not verify_signature_record(
        signature,
        payload_hash,
        public_key=public_key,
    ):
        raise ValueError("signature verification failed")
    return {"status": "accepted", "payload_hash": payload_hash, "trust": trust}


def unsigned_certificate_payload(payload: Mapping[str, Any]) -> JsonObject:
    return {
        str(key): value
        for key, value in payload.items()
        if str(key) not in UNSIGNED_EXCLUDED_KEYS
    }


def _load_trust_root(
    trust_root: Path | Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    if trust_root is None:
        return None
    if isinstance(trust_root, Mapping):
        return trust_root
    descriptor = json.loads(trust_root.read_text(encoding="utf-8"))
    if not isinstance(descriptor, Mapping):
        raise ValueError("trust root must be a JSON object")
    if "public_key_file" in descriptor and "public_key_pem" not in descriptor:
        key_path = trust_root.parent / str(descriptor["public_key_file"])
        descriptor = dict(descriptor)
        descriptor["public_key_pem"] = key_path.read_text(encoding="utf-8")
    return cast(Mapping[str, Any], descriptor)


def _require_purpose(
    signature: Mapping[str, Any],
    payload: Mapping[str, Any],
    root: Mapping[str, Any] | None,
    expected_purpose: str | None,
) -> None:
    purpose = signature.get("purpose")
    if expected_purpose is not None and purpose != expected_purpose:
        raise ValueError(
            f"signature purpose mismatch: expected {expected_purpose!r}, got {purpose!r}"
        )
    if root is not None:
        allowed = root.get("allowed_purposes")
        if allowed is not None and purpose not in list(allowed):
            raise ValueError(
                f"signature purpose {purpose!r} is not allowed by the trust root"
            )


def _require_schema_version(
    payload: Mapping[str, Any],
    root: Mapping[str, Any] | None,
    expected_schema_version: str | None,
) -> None:
    schema_version = payload.get("schema_version")
    if (
        expected_schema_version is not None
        and schema_version != expected_schema_version
    ):
        raise ValueError(
            "schema_version mismatch: expected "
            f"{expected_schema_version!r}, got {schema_version!r}"
        )
    if root is not None:
        allowed = root.get("allowed_schema_versions")
        if allowed is not None and schema_version not in list(allowed):
            raise ValueError(
                f"schema_version {schema_version!r} is not allowed by the trust root"
            )


def _require_issuer(
    payload: Mapping[str, Any],
    root: Mapping[str, Any] | None,
) -> None:
    if root is None:
        return
    pinned = root.get("issuer")
    if pinned is None:
        return
    issuer = payload.get("issuer")
    if issuer != pinned:
        raise ValueError(f"issuer mismatch: trust root pins {pinned!r}, got {issuer!r}")


def _public_key_material(
    signature: Mapping[str, Any],
    *,
    public_key_file: Path | None,
    trust_root: Mapping[str, Any] | None,
    allow_embedded_key: bool,
) -> tuple[str, str]:
    if public_key_file is not None:
        return public_key_file.read_text(encoding="utf-8"), "pinned_key"
    if trust_root is not None:
        pinned = trust_root.get("public_key_pem") or trust_root.get("public_key_base64")
        if not isinstance(pinned, str) or not pinned.strip():
            raise ValueError("trust root missing public key material")
        return pinned, "trust_root"
    if not allow_embedded_key:
        raise ValueError(
            "no trust root provided: pass --public-key-file or --trust-root "
            "(or --allow-embedded-key for an UNTRUSTED self-consistency check)"
        )
    material = signature.get("public_verification_material")
    if not isinstance(material, Mapping):
        raise ValueError("signature missing public_verification_material")
    public_key = material.get("public_key_pem") or material.get("public_key_base64")
    if not isinstance(public_key, str) or not public_key.strip():
        raise ValueError("signature missing embedded public key material")
    return public_key, "self_attested_key"


def _read_json_object(path: Path) -> JsonObject:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return cast(JsonObject, payload)


if __name__ == "__main__":
    raise SystemExit(main())
