"""Signing provider boundary for Velvet proof artifacts.

LocalDevHmacSigner exists only for deterministic local demos. It is not a
production signing provider.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

from velvet.serialization import JsonObject, canonical_dumps, canonical_hash, stable_json_object

SIGNATURE_SCHEMA_VERSION_V1 = "velvet.signature.v1"
SIGNATURE_SCHEMA_VERSION_V2 = "velvet.signature.v2"
SIGNATURE_SCHEMA_VERSION = SIGNATURE_SCHEMA_VERSION_V2
SUPPORTED_SIGNATURE_SCHEMA_VERSIONS = frozenset(
    {SIGNATURE_SCHEMA_VERSION_V1, SIGNATURE_SCHEMA_VERSION_V2}
)
DEFAULT_TENANT_ID = "velvet-demo-tenant"
DEFAULT_LOCAL_DEV_HMAC_KEY_ID = "velvet-local-dev-hmac-demo-key"
DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION = "demo-v1"
DEFAULT_LOCAL_DEV_HMAC_KEY = "velvet-local-deterministic-demo-key"
DEFAULT_ED25519_KEY_ID = "velvet-production-ed25519"
DEFAULT_ED25519_KEY_VERSION = "v1"
DEMO_ED25519_KEY_ID = "demo-not-for-production"
DEMO_ED25519_KEY_VERSION = "demo-v1"
EPHEMERAL_ED25519_KEY_ID = "ephemeral-dev"
EPHEMERAL_ED25519_KEY_VERSION = "ephemeral-v1"
VELVET_SIGNING_PRIVATE_KEY_ENV = "VELVET_SIGNING_PRIVATE_KEY"
VELVET_SIGNING_PRIVATE_KEY_FILE_ENV = "VELVET_SIGNING_PRIVATE_KEY_FILE"
VELVET_SIGNING_PROFILE_ENV = "VELVET_SIGNING_PROFILE"
VELVET_ALLOW_EPHEMERAL_SIGNING_ENV = "VELVET_ALLOW_EPHEMERAL_SIGNING"
VELVET_SIGNING_KEY_ID_ENV = "VELVET_SIGNING_KEY_ID"
VELVET_SIGNING_KEY_VERSION_ENV = "VELVET_SIGNING_KEY_VERSION"
VELVET_SIGNING_PROVIDER_ENV = "VELVET_SIGNING_PROVIDER"
VELVET_KMS_KEY_ID_ENV = "VELVET_KMS_KEY_ID"
VELVET_KMS_SIGNING_ALGORITHM_ENV = "VELVET_KMS_SIGNING_ALGORITHM"
VELVET_VAULT_TRANSIT_KEY_ENV = "VELVET_VAULT_TRANSIT_KEY"
VELVET_VAULT_MOUNT_ENV = "VELVET_VAULT_MOUNT"
DEMO_ED25519_PUBLIC_KEY_BASE64 = "VAuZdqVvyBgHk+VGugmziGUxinqlCkp2jRPthPUcnYY="
DEMO_KEY_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "keys"
DEMO_ED25519_PRIVATE_KEY_PATH = DEMO_KEY_ROOT / "velvet_demo_ed25519.key"
DEMO_ED25519_PUBLIC_KEY_PATH = DEMO_KEY_ROOT / "velvet_demo_ed25519.pub"
PRODUCTION_KEY_MISSING_MESSAGE = (
    "Ed25519 signing is fail-closed: set VELVET_SIGNING_PRIVATE_KEY or "
    "VELVET_SIGNING_PRIVATE_KEY_FILE, or pass --dev-ephemeral-key for explicit "
    "non-durable local development signing."
)
LOCAL_DEMO_TENANT_ID = DEFAULT_TENANT_ID
LOCAL_DEMO_KEY_ID = DEFAULT_LOCAL_DEV_HMAC_KEY_ID
LOCAL_DEMO_KEY_VERSION = DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION
LOCAL_DEMO_SIGNATURE_KEY = DEFAULT_LOCAL_DEV_HMAC_KEY
PURPOSE_ADMISSION_EVIDENCE = "velvet.admission_evidence.v1"
PURPOSE_APPROVAL_RECEIPT = "velvet.approval_receipt.v1"
PURPOSE_APPROVAL_RECEIPT_V1 = PURPOSE_APPROVAL_RECEIPT
PURPOSE_EVIDENCE_MANIFEST = "velvet.evidence_manifest.v1"
PURPOSE_EVIDENCE_MANIFEST_V1 = PURPOSE_EVIDENCE_MANIFEST
PURPOSE_EXECUTION_PERMIT = "velvet.execution_permit.v1"
PURPOSE_EXECUTION_RECEIPT = "velvet.execution_receipt.v1"
PURPOSE_LEDGER_RECORD = "velvet.ledger.record"
PURPOSE_POLICY_COMPILE_PROVENANCE = "velvet.policy_compile.provenance.v1"
PURPOSE_PROOF_ENVELOPE = "velvet.proof_envelope.compat.v1"
PURPOSE_VERDICT_CERTIFICATE = "velvet.verdict_certificate.v1"
PURPOSE_WARRANT = "velvet.warrant"
DEFAULT_AWS_KMS_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256"
AWS_KMS_MESSAGE_TYPE_RAW = "RAW"
DEFAULT_VAULT_MOUNT_POINT = "transit"
DEFAULT_VAULT_HASH_ALGORITHM = "sha2-256"
DEFAULT_VAULT_SIGNATURE_ALGORITHM = "pss"




class SigningError(RuntimeError):
    """Base error for signing provider failures."""


class SigningProviderNotConfigured(SigningError):
    """Raised when an enterprise provider has not been configured."""


SigningConfigurationError = SigningError


def generate_ed25519_keypair() -> JsonObject:
    """Generate an Ed25519 private/public keypair for explicit operator setup."""

    private_key = _ed25519_private_key_cls().generate()
    return {
        "private_key_pem": export_ed25519_private_key_pem(private_key),
        "public_key_pem": export_ed25519_public_key_pem(private_key),
        "public_key_base64": export_ed25519_public_key_base64(private_key),
    }


def load_ed25519_private_key_from_env() -> Any:
    """Load production private key material from the approved environment surface."""

    env_value = os.environ.get(VELVET_SIGNING_PRIVATE_KEY_ENV)
    if env_value:
        private_key = load_ed25519_private_key(env_value)
        _reject_demo_private_key(private_key, source=VELVET_SIGNING_PRIVATE_KEY_ENV)
        return private_key

    file_value = os.environ.get(VELVET_SIGNING_PRIVATE_KEY_FILE_ENV)
    if file_value:
        private_key = load_ed25519_private_key_file(file_value)
        _reject_demo_private_key(private_key, source=VELVET_SIGNING_PRIVATE_KEY_FILE_ENV)
        return private_key

    raise SigningProviderNotConfigured(PRODUCTION_KEY_MISSING_MESSAGE)


def load_ed25519_private_key_file(path: str | Path) -> Any:
    """Load an Ed25519 private key from a PEM file or raw-base64 seed file."""

    return load_ed25519_private_key(Path(path).read_text(encoding="utf-8"))


def load_ed25519_private_key(material: str | bytes) -> Any:
    """Load Ed25519 private key material from PEM text or a raw base64 seed."""

    if isinstance(material, bytes):
        raw = material
        text = material.decode("utf-8", errors="ignore")
    else:
        text = material.replace("\\n", "\n").strip()
        raw = text.encode("utf-8")
    private_cls = _ed25519_private_key_cls()
    if "BEGIN" in text:
        private_key = _serialization_load_pem_private_key(raw)
        if not isinstance(private_key, private_cls):
            raise SigningConfigurationError("private key is not an Ed25519 private key")
        return private_key
    try:
        seed = base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as error:  # noqa: BLE001 - report a single actionable config error.
        raise SigningConfigurationError("Ed25519 private key must be PEM or raw base64") from error
    if len(seed) != 32:
        raise SigningConfigurationError("Ed25519 raw private key must decode to 32 bytes")
    return private_cls.from_private_bytes(seed)


def load_ed25519_public_key_file(path: str | Path) -> Any:
    """Load an Ed25519 public key from a PEM file or raw-base64 file."""

    return load_ed25519_public_key(Path(path).read_text(encoding="utf-8"))


def load_ed25519_public_key(material: str | bytes | Any) -> Any:
    """Load Ed25519 public key material from PEM text, raw base64, or key object."""

    public_cls = _ed25519_public_key_cls()
    if isinstance(material, public_cls):
        return material
    if isinstance(material, bytes):
        raw = material
        text = material.decode("utf-8", errors="ignore")
    else:
        text = str(material).replace("\\n", "\n").strip()
        raw = text.encode("utf-8")
    if "BEGIN" in text:
        public_key = _serialization_load_pem_public_key(raw)
        if not isinstance(public_key, public_cls):
            raise SigningConfigurationError("public key is not an Ed25519 public key")
        return public_key
    try:
        public_bytes = base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as error:  # noqa: BLE001 - report a single actionable config error.
        raise SigningConfigurationError("Ed25519 public key must be PEM or raw base64") from error
    if len(public_bytes) != 32:
        raise SigningConfigurationError("Ed25519 raw public key must decode to 32 bytes")
    return public_cls.from_public_bytes(public_bytes)


def export_ed25519_private_key_pem(private_key: Any) -> str:
    serialization = _serialization_module()
    return cast(
        bytes,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    ).decode("ascii")


def export_ed25519_public_key_pem(private_or_public_key: Any) -> str:
    serialization = _serialization_module()
    public_key = _public_key_from_private_or_public(private_or_public_key)
    return cast(
        bytes,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    ).decode("ascii")


def export_ed25519_public_key_base64(private_or_public_key: Any) -> str:
    serialization = _serialization_module()
    public_key = _public_key_from_private_or_public(private_or_public_key)
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(cast(bytes, raw)).decode("ascii")


def resolve_ed25519_signing_provider(
    *,
    signing_profile: str | None = None,
    dev_ephemeral_key: bool = False,
    key_id: str | None = None,
    key_version: str | None = None,
) -> Ed25519SigningProvider:
    """Resolve the fail-closed Ed25519 signing provider for warrants and ledger records."""

    allow_ephemeral = os.environ.get(VELVET_ALLOW_EPHEMERAL_SIGNING_ENV) == "1"
    if dev_ephemeral_key or allow_ephemeral:
        return Ed25519SigningProvider(
            _ed25519_private_key_cls().generate(),
            key_id=key_id or EPHEMERAL_ED25519_KEY_ID,
            key_version=key_version or EPHEMERAL_ED25519_KEY_VERSION,
            verification_tier="non-durable",
        )

    profile = signing_profile or os.environ.get(VELVET_SIGNING_PROFILE_ENV) or "production"
    normalized_profile = profile.strip().lower()
    if normalized_profile == "demo":
        return load_demo_ed25519_signer()
    if normalized_profile in {"production", "prod"}:
        return Ed25519SigningProvider(
            load_ed25519_private_key_from_env(),
            key_id=key_id or os.environ.get(VELVET_SIGNING_KEY_ID_ENV) or DEFAULT_ED25519_KEY_ID,
            key_version=(
                key_version
                or os.environ.get(VELVET_SIGNING_KEY_VERSION_ENV)
                or DEFAULT_ED25519_KEY_VERSION
            ),
            verification_tier="durable",
        )
    raise SigningProviderNotConfigured(
        f"Unsupported VELVET_SIGNING_PROFILE={profile!r}; use 'production' or 'demo'."
    )


def load_demo_ed25519_signer() -> Ed25519SigningProvider:
    """Load the committed deterministic demo keypair."""

    if not DEMO_ED25519_PRIVATE_KEY_PATH.exists():
        raise SigningProviderNotConfigured(
            f"Demo Ed25519 key not found: {DEMO_ED25519_PRIVATE_KEY_PATH}"
        )
    return Ed25519SigningProvider(
        load_ed25519_private_key_file(DEMO_ED25519_PRIVATE_KEY_PATH),
        key_id=DEMO_ED25519_KEY_ID,
        key_version=DEMO_ED25519_KEY_VERSION,
        verification_tier="demo",
    )


@runtime_checkable
class SigningProvider(Protocol):
    @property
    def provider_name(self) -> str:
        """Stable provider name included in signatures."""

    @property
    def algorithm(self) -> str:
        """Stable algorithm name included in signatures."""

    @property
    def key_version(self) -> str:
        """Provider key version included in signatures."""

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        """Sign a canonical payload hash for one purpose and tenant."""

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        """Verify a signature over a canonical payload hash."""

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        """Return public verification material when the provider exposes it."""


class AwsKmsClient(Protocol):
    """Minimal AWS KMS client surface used by AwsKmsSigner."""

    def sign(self, **kwargs: Any) -> Mapping[str, Any]:
        """Call AWS KMS Sign."""

    def verify(self, **kwargs: Any) -> Mapping[str, Any]:
        """Call AWS KMS Verify."""

    def get_public_key(self, **kwargs: Any) -> Mapping[str, Any]:
        """Call AWS KMS GetPublicKey."""


class VaultTransitMethodClient(Protocol):
    """Minimal Vault Transit method surface used by VaultTransitSigner."""

    def sign_data(self, **kwargs: Any) -> Mapping[str, Any]:
        """Call Vault Transit sign data."""

    def verify_signed_data(self, **kwargs: Any) -> Mapping[str, Any]:
        """Call Vault Transit verify signed data."""


@dataclass(frozen=True)
class SignatureBlock:
    provider_name: str
    algorithm: str
    key_id: str
    key_version: str
    purpose: str
    tenant_id: str
    payload_hash: str
    signature: str
    schema_version: str = SIGNATURE_SCHEMA_VERSION
    signed_at: str = field(default_factory=lambda: _now_iso())
    public_verification_material: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SignatureBlock:
        material = data.get("public_verification_material")
        return cls(
            schema_version=str(data.get("schema_version", SIGNATURE_SCHEMA_VERSION)),
            provider_name=str(data["provider_name"]),
            algorithm=str(data["algorithm"]),
            key_id=str(data["key_id"]),
            key_version=str(data["key_version"]),
            purpose=str(data["purpose"]),
            tenant_id=str(data["tenant_id"]),
            payload_hash=str(data["payload_hash"]),
            signature=str(data["signature"]),
            signed_at=str(data["signed_at"]),
            public_verification_material=dict(cast(Mapping[str, Any], material))
            if isinstance(material, Mapping)
            else None,
            metadata=stable_json_object(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "schema_version": self.schema_version,
            "provider_name": self.provider_name,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "purpose": self.purpose,
            "tenant_id": self.tenant_id,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
            "signed_at": self.signed_at,
            "metadata": stable_json_object(self.metadata),
        }
        if self.public_verification_material is not None:
            payload["public_verification_material"] = stable_json_object(
                self.public_verification_material
            )
        return payload


SignatureRecord = SignatureBlock


class ArtifactSigner:
    """Attach and verify SignatureBlock objects for canonical JSON artifacts."""

    def __init__(
        self,
        provider: SigningProvider | None = None,
        *,
        tenant_id: str = DEFAULT_TENANT_ID,
        key_id: str = DEFAULT_LOCAL_DEV_HMAC_KEY_ID,
    ) -> None:
        self.provider = provider or LocalDevHmacSigner()
        self.tenant_id = tenant_id
        self.key_id = key_id

    @classmethod
    def from_contract(cls, contract: object) -> ArtifactSigner:
        signature_key = str(getattr(contract, "signature_key", DEFAULT_LOCAL_DEV_HMAC_KEY))
        return cls(
            LocalDevHmacSigner(
                signature_key,
                key_version=str(
                    getattr(contract, "signing_key_version", DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION)
                ),
            ),
            tenant_id=str(getattr(contract, "tenant_id", DEFAULT_TENANT_ID)),
            key_id=str(getattr(contract, "signing_key_id", DEFAULT_LOCAL_DEV_HMAC_KEY_ID)),
        )

    @staticmethod
    def payload_hash(payload: Any) -> str:
        return canonical_hash(payload)

    @staticmethod
    def unsigned_payload(
        payload: Mapping[str, Any],
        *,
        signature_field: str = "signature",
    ) -> JsonObject:
        return {str(key): value for key, value in payload.items() if key != signature_field}

    def sign_hash(
        self,
        payload_hash: str,
        purpose: str,
        *,
        tenant_id: str | None = None,
        key_id: str | None = None,
    ) -> SignatureBlock:
        resolved_tenant_id = tenant_id or self.tenant_id
        resolved_key_id = key_id or self.key_id
        return SignatureBlock(
            provider_name=self.provider.provider_name,
            algorithm=self.provider.algorithm,
            key_id=resolved_key_id,
            key_version=self.provider.key_version,
            purpose=purpose,
            tenant_id=resolved_tenant_id,
            payload_hash=payload_hash,
            signature=self.provider.sign(
                payload_hash,
                purpose,
                resolved_tenant_id,
                resolved_key_id,
            ),
            public_verification_material=self.provider.public_verification_material(
                resolved_key_id
            ),
            schema_version=str(
                getattr(self.provider, "schema_version", SIGNATURE_SCHEMA_VERSION)
            ),
            metadata=_signature_metadata(self.provider),
        )

    def sign_payload(
        self,
        payload: Mapping[str, Any],
        purpose: str,
        *,
        tenant_id: str | None = None,
        key_id: str | None = None,
    ) -> SignatureBlock:
        return self.sign_hash(
            self.payload_hash(stable_json_object(payload)),
            purpose,
            tenant_id=tenant_id,
            key_id=key_id,
        )

    def attach_signature(
        self,
        payload: Mapping[str, Any],
        purpose: str,
        *,
        signature_field: str = "signature",
        tenant_id: str | None = None,
        key_id: str | None = None,
    ) -> JsonObject:
        unsigned = self.unsigned_payload(payload, signature_field=signature_field)
        signed = dict(unsigned)
        signed[signature_field] = self.sign_payload(
            unsigned,
            purpose,
            tenant_id=tenant_id,
            key_id=key_id,
        ).to_dict()
        return signed

    def verify_block(self, block: SignatureBlock) -> bool:
        if block.schema_version not in SUPPORTED_SIGNATURE_SCHEMA_VERSIONS:
            return False
        if block.provider_name != self.provider.provider_name:
            return False
        if block.algorithm != self.provider.algorithm:
            return False
        if block.key_version != self.provider.key_version:
            return False
        return self.provider.verify(
            block.payload_hash,
            block.signature,
            block.purpose,
            block.tenant_id,
            block.key_id,
        )

    def verify_payload(
        self,
        payload: Mapping[str, Any],
        purpose: str,
        *,
        signature_field: str = "signature",
    ) -> bool:
        raw_signature = payload.get(signature_field)
        if not isinstance(raw_signature, Mapping):
            return False
        block = SignatureBlock.from_dict(cast(Mapping[str, Any], raw_signature))
        if block.purpose != purpose:
            return False
        unsigned = self.unsigned_payload(payload, signature_field=signature_field)
        if not hmac.compare_digest(block.payload_hash, self.payload_hash(unsigned)):
            return False
        return self.verify_block(block)


class LocalDevHmacSigner:
    """Deterministic shared-secret HMAC signer for local demos only, never production."""

    def __init__(
        self,
        signing_key: str = DEFAULT_LOCAL_DEV_HMAC_KEY,
        *,
        key_version: str = DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION,
        provider_name: str = "local_dev_hmac_demo",
        schema_version: str = SIGNATURE_SCHEMA_VERSION,
    ) -> None:
        if "demo" not in provider_name:
            raise ValueError("LocalDevHmacSigner provider_name must clearly contain 'demo'")
        self._signing_key = signing_key
        self._key_version = key_version
        self._provider_name = provider_name
        self._schema_version = schema_version

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def algorithm(self) -> str:
        return "HMAC-SHA256"

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def verification_tier(self) -> str:
        return "local-dev-shared-secret"

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        return hmac.new(
            self._signing_key.encode("utf-8"),
            signing_message(
                payload_hash,
                purpose,
                tenant_id,
                key_id,
                provider_name=self.provider_name,
                algorithm=self.algorithm,
                key_version=self.key_version,
                schema_version=self.schema_version,
            ),
            hashlib.sha256,
        ).hexdigest()

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        return hmac.compare_digest(
            signature,
            self.sign(payload_hash, purpose, tenant_id, key_id),
        )

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        return None


class Ed25519SigningProvider:
    """Ed25519 signing provider backed by pyca/cryptography."""

    def __init__(
        self,
        private_key: object | None = None,
        *,
        key_id: str = DEFAULT_ED25519_KEY_ID,
        key_version: str = DEFAULT_ED25519_KEY_VERSION,
        provider_name: str = "velvet_ed25519",
        schema_version: str = SIGNATURE_SCHEMA_VERSION,
        verification_tier: str = "durable",
    ) -> None:
        private_cls = _ed25519_private_key_cls()
        if private_key is None:
            private_key = private_cls.generate()
        if not isinstance(private_key, private_cls):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._key_id = key_id
        self._key_version = key_version
        self._provider_name = provider_name
        self._schema_version = schema_version
        self._verification_tier = verification_tier

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def verification_tier(self) -> str:
        return self._verification_tier

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        signature = self._private_key.sign(
            signing_message(
                payload_hash,
                purpose,
                tenant_id,
                key_id,
                provider_name=self.provider_name,
                algorithm=self.algorithm,
                key_version=self.key_version,
                schema_version=self.schema_version,
            )
        )
        return base64.b64encode(signature).decode("ascii")

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        try:
            self._public_key.verify(
                base64.b64decode(signature.encode("ascii")),
                signing_message(
                    payload_hash,
                    purpose,
                    tenant_id,
                    key_id,
                    provider_name=self.provider_name,
                    algorithm=self.algorithm,
                    key_version=self.key_version,
                    schema_version=self.schema_version,
                ),
            )
        except Exception:  # noqa: BLE001 - crypto libraries raise provider-specific errors.
            return False
        return True

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        return {
            "key_id": key_id,
            "public_key_pem": export_ed25519_public_key_pem(self._public_key),
            "public_key_base64": export_ed25519_public_key_base64(self._public_key),
            "encoding": "pem+raw-base64",
            "verification_tier": self.verification_tier,
        }


class Ed25519PublicVerifier:
    """Public-key-only Ed25519 verifier for third-party verification."""

    def __init__(
        self,
        public_key: str | bytes | object,
        *,
        provider_name: str = "velvet_ed25519",
        key_version: str = DEFAULT_ED25519_KEY_VERSION,
        schema_version: str = SIGNATURE_SCHEMA_VERSION,
    ) -> None:
        self._public_key = load_ed25519_public_key(public_key)
        self._provider_name = provider_name
        self._key_version = key_version
        self._schema_version = schema_version

    @classmethod
    def from_block(
        cls,
        block: SignatureBlock,
        public_key: str | bytes | object,
    ) -> Ed25519PublicVerifier:
        return cls(
            public_key,
            provider_name=block.provider_name,
            key_version=block.key_version,
            schema_version=block.schema_version,
        )

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def verification_tier(self) -> str:
        return "public-key-only"

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        raise SigningProviderNotConfigured("Ed25519PublicVerifier cannot sign.")

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        try:
            self._public_key.verify(
                base64.b64decode(signature.encode("ascii")),
                signing_message(
                    payload_hash,
                    purpose,
                    tenant_id,
                    key_id,
                    provider_name=self.provider_name,
                    algorithm=self.algorithm,
                    key_version=self.key_version,
                    schema_version=self.schema_version,
                ),
            )
        except Exception:  # noqa: BLE001 - crypto libraries raise provider-specific errors.
            return False
        return True

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        del key_id
        return None


class LocalEd25519Signer(Ed25519SigningProvider):
    """Compatibility alias for Ed25519 signing experiments."""


class AwsKmsSigner:
    """AWS KMS signer backed by an explicitly supplied KMS client.

    The default signing algorithm is RSASSA_PSS_SHA_256 because it is a common
    durable asymmetric KMS choice. Operators using EC or Ed25519 KMS keys must
    pass the matching KMS SigningAlgorithm explicitly.
    """

    provider_name = "aws_kms"

    def __init__(
        self,
        *,
        key_id: str | None = None,
        client: AwsKmsClient | None = None,
        signing_algorithm: str = DEFAULT_AWS_KMS_SIGNING_ALGORITHM,
        key_version: str | None = None,
        include_public_key: bool = True,
        public_key_der: bytes | None = None,
        public_key_der_base64: str | None = None,
        schema_version: str = SIGNATURE_SCHEMA_VERSION,
    ) -> None:
        self._client = client
        self._key_id = key_id
        self._signing_algorithm = signing_algorithm
        self._key_version = key_version or key_id or "unconfigured"
        self._include_public_key = include_public_key
        self._schema_version = schema_version
        self._last_kms_key_id: str | None = None
        self._last_public_key_response: Mapping[str, Any] | None = None
        self._public_key_der: bytes | None
        if public_key_der is not None:
            self._public_key_der = public_key_der
        elif public_key_der_base64:
            self._public_key_der = base64.b64decode(
                public_key_der_base64.encode("ascii"),
                validate=True,
            )
        else:
            self._public_key_der = None

    @property
    def algorithm(self) -> str:
        return self._signing_algorithm

    @property
    def key_id(self) -> str:
        return self._key_id or ""

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def verification_tier(self) -> str:
        return "durable"

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        client = self._require_client()
        kms_key_id = self._require_key_id()
        response = client.sign(
            KeyId=kms_key_id,
            Message=self._message(payload_hash, purpose, tenant_id, key_id),
            MessageType=AWS_KMS_MESSAGE_TYPE_RAW,
            SigningAlgorithm=self.algorithm,
        )
        self._last_kms_key_id = str(response.get("KeyId") or kms_key_id)
        signature = _kms_signature_bytes(response.get("Signature"))
        return base64.b64encode(signature).decode("ascii")

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        try:
            signature_bytes = base64.b64decode(signature.encode("ascii"), validate=True)
        except Exception:  # noqa: BLE001 - invalid base64 means invalid signature.
            return False
        message = self._message(payload_hash, purpose, tenant_id, key_id)
        if self._client is not None and self._key_id:
            try:
                response = self._client.verify(
                    KeyId=self._key_id,
                    Message=message,
                    MessageType=AWS_KMS_MESSAGE_TYPE_RAW,
                    Signature=signature_bytes,
                    SigningAlgorithm=self.algorithm,
                )
            except Exception:  # noqa: BLE001 - KMS/client failures are verification failures.
                return False
            return bool(response.get("SignatureValid") is True)
        if self._public_key_der is None:
            return False
        return _verify_aws_kms_public_signature(
            self.algorithm,
            self._public_key_der,
            message,
            signature_bytes,
        )

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        if not self._include_public_key:
            return None
        if self._public_key_der is not None:
            return {
                "key_id": key_id,
                "kms_key_id": self._key_id or key_id,
                "public_key_der_base64": base64.b64encode(self._public_key_der).decode(
                    "ascii"
                ),
                "encoding": "der-base64",
                "verification_tier": self.verification_tier,
                "signing_algorithm": self.algorithm,
            }
        if self._client is None or not self._key_id:
            return None
        try:
            response = self._client.get_public_key(KeyId=self._key_id)
        except Exception:  # noqa: BLE001 - public material is optional for KMS signing.
            return None
        self._last_public_key_response = response
        public_key = _kms_public_key_bytes(response.get("PublicKey"))
        self._public_key_der = public_key
        material: JsonObject = {
            "key_id": key_id,
            "kms_key_id": str(response.get("KeyId") or self._key_id),
            "public_key_der_base64": base64.b64encode(public_key).decode("ascii"),
            "encoding": "der-base64",
            "verification_tier": self.verification_tier,
            "signing_algorithm": self.algorithm,
        }
        for source, target in (
            ("CustomerMasterKeySpec", "customer_master_key_spec"),
            ("KeySpec", "key_spec"),
            ("KeyUsage", "key_usage"),
            ("SigningAlgorithms", "signing_algorithms"),
        ):
            if source in response:
                material[target] = response[source]
        return material

    def signature_metadata(self) -> JsonObject:
        return {
            "provider_name": self.provider_name,
            "kms_key_id": self._last_kms_key_id or self._key_id or "unconfigured",
            "key_id": self._key_id or "unconfigured",
            "key_version": self.key_version,
            "signing_algorithm": self.algorithm,
            "message_type": AWS_KMS_MESSAGE_TYPE_RAW,
        }

    def _message(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> bytes:
        return signing_message(
            payload_hash,
            purpose,
            tenant_id,
            key_id,
            provider_name=self.provider_name,
            algorithm=self.algorithm,
            key_version=self.key_version,
            schema_version=self.schema_version,
        )

    def _require_client(self) -> AwsKmsClient:
        if self._client is None:
            raise SigningProviderNotConfigured(
                "AWS KMS signing requires an explicit KMS client. "
                "Use aws_kms_signer_from_boto3(...) or pass client=..."
            )
        return self._client

    def _require_key_id(self) -> str:
        if not self._key_id:
            raise SigningProviderNotConfigured(
                "AWS KMS signing requires an explicit key_id or VELVET_KMS_KEY_ID."
            )
        return self._key_id


class VaultTransitSigner:
    """HashiCorp Vault Transit signer backed by an explicitly supplied client."""

    provider_name = "vault_transit"

    def __init__(
        self,
        *,
        key_name: str | None = None,
        client: object | None = None,
        mount_point: str = DEFAULT_VAULT_MOUNT_POINT,
        key_version: str = "latest",
        hash_algorithm: str = DEFAULT_VAULT_HASH_ALGORITHM,
        signature_algorithm: str = DEFAULT_VAULT_SIGNATURE_ALGORITHM,
        prehashed: bool = False,
        schema_version: str = SIGNATURE_SCHEMA_VERSION,
    ) -> None:
        self._client = client
        self._key_name = key_name
        self._mount_point = mount_point
        self._key_version = key_version
        self._hash_algorithm = hash_algorithm
        self._signature_algorithm = signature_algorithm
        self._prehashed = prehashed
        self._schema_version = schema_version
        self._last_vault_signature_version: str | None = None

    @property
    def algorithm(self) -> str:
        return f"VaultTransit-{self._hash_algorithm}-{self._signature_algorithm}"

    @property
    def key_id(self) -> str:
        return self._key_name or ""

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def verification_tier(self) -> str:
        return "durable"

    def sign(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> str:
        transit = self._require_transit_client()
        key_name = self._require_key_name()
        response = transit.sign_data(
            **self._vault_request_kwargs(
                name=key_name,
                hash_input=base64.b64encode(
                    self._message(payload_hash, purpose, tenant_id, key_id)
                ).decode("ascii"),
            )
        )
        signature = _vault_response_value(response, "signature")
        parsed = parse_vault_transit_signature(signature)
        self._last_vault_signature_version = parsed["key_version"]
        return signature

    def verify(
        self,
        payload_hash: str,
        signature: str,
        purpose: str,
        tenant_id: str,
        key_id: str,
    ) -> bool:
        try:
            parse_vault_transit_signature(signature)
            transit = self._require_transit_client()
            key_name = self._require_key_name()
            response = transit.verify_signed_data(
                **self._vault_request_kwargs(
                    name=key_name,
                    hash_input=base64.b64encode(
                        self._message(payload_hash, purpose, tenant_id, key_id)
                    ).decode("ascii"),
                    signature=signature,
                )
            )
            return bool(_vault_response_bool(response, "valid"))
        except SigningProviderNotConfigured:
            return False
        except Exception:  # noqa: BLE001 - Vault/client failures are verification failures.
            return False

    def public_verification_material(self, key_id: str) -> JsonObject | None:
        del key_id
        return None

    def signature_metadata(self) -> JsonObject:
        return {
            "provider_name": self.provider_name,
            "key_name": self._key_name or "unconfigured",
            "key_version": self.key_version,
            "vault_signature_version": self._last_vault_signature_version,
            "mount_point": self._mount_point,
            "hash_algorithm": self._hash_algorithm,
            "signature_algorithm": self._signature_algorithm,
            "prehashed": self._prehashed,
        }

    def _message(self, payload_hash: str, purpose: str, tenant_id: str, key_id: str) -> bytes:
        return signing_message(
            payload_hash,
            purpose,
            tenant_id,
            key_id,
            provider_name=self.provider_name,
            algorithm=self.algorithm,
            key_version=self.key_version,
            schema_version=self.schema_version,
        )

    def _vault_request_kwargs(self, **kwargs: Any) -> JsonObject:
        payload: JsonObject = {
            "mount_point": self._mount_point,
            "hash_algorithm": self._hash_algorithm,
            "prehashed": self._prehashed,
            "signature_algorithm": self._signature_algorithm,
        }
        request_key_version = _vault_request_key_version(self._key_version)
        if request_key_version is not None:
            payload["key_version"] = request_key_version
        payload.update(stable_json_object(kwargs))
        return payload

    def _require_transit_client(self) -> VaultTransitMethodClient:
        if self._client is None:
            raise SigningProviderNotConfigured(
                "Vault Transit signing requires an explicit hvac client. "
                "Use vault_transit_signer_from_hvac(...) or pass client=..."
            )
        transit = _vault_transit_method_client(self._client)
        if transit is None:
            raise SigningProviderNotConfigured(
                "Vault Transit client must expose secrets.transit sign/verify methods."
            )
        return transit

    def _require_key_name(self) -> str:
        if not self._key_name:
            raise SigningProviderNotConfigured(
                "Vault Transit signing requires an explicit key_name or VELVET_VAULT_TRANSIT_KEY."
            )
        return self._key_name


def aws_kms_signer_from_boto3(
    *,
    key_id: str | None = None,
    client: AwsKmsClient | None = None,
    signing_algorithm: str | None = None,
    key_version: str | None = None,
    region_name: str | None = None,
    profile_name: str | None = None,
    include_public_key: bool = True,
) -> AwsKmsSigner:
    """Create an AwsKmsSigner through the explicit boto3 factory path."""

    resolved_key_id = key_id or os.environ.get(VELVET_KMS_KEY_ID_ENV)
    if not resolved_key_id:
        raise SigningProviderNotConfigured(
            "AWS KMS signing requires --kms-key-id or VELVET_KMS_KEY_ID."
        )
    resolved_algorithm = (
        signing_algorithm
        or os.environ.get(VELVET_KMS_SIGNING_ALGORITHM_ENV)
        or DEFAULT_AWS_KMS_SIGNING_ALGORITHM
    )
    resolved_client = client
    if resolved_client is None:
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise SigningProviderNotConfigured(
                "AWS KMS signing requires optional dependency boto3. "
                "Install velvet-rope[enterprise-kms]."
            ) from error
        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        resolved_client = cast(AwsKmsClient, session.client("kms", region_name=region_name))
    return AwsKmsSigner(
        key_id=resolved_key_id,
        client=resolved_client,
        signing_algorithm=resolved_algorithm,
        key_version=key_version or resolved_key_id,
        include_public_key=include_public_key,
    )


def vault_transit_signer_from_hvac(
    *,
    key_name: str | None = None,
    client: object | None = None,
    mount_point: str | None = None,
    key_version: str = "latest",
    hash_algorithm: str = DEFAULT_VAULT_HASH_ALGORITHM,
    signature_algorithm: str = DEFAULT_VAULT_SIGNATURE_ALGORITHM,
) -> VaultTransitSigner:
    """Create a VaultTransitSigner through the explicit hvac factory path."""

    resolved_key_name = key_name or os.environ.get(VELVET_VAULT_TRANSIT_KEY_ENV)
    if not resolved_key_name:
        raise SigningProviderNotConfigured(
            "Vault Transit signing requires --vault-transit-key or VELVET_VAULT_TRANSIT_KEY."
        )
    resolved_mount = (
        mount_point or os.environ.get(VELVET_VAULT_MOUNT_ENV) or DEFAULT_VAULT_MOUNT_POINT
    )
    resolved_client = client
    if resolved_client is None:
        try:
            hvac = importlib.import_module("hvac")
        except ImportError as error:
            raise SigningProviderNotConfigured(
                "Vault Transit signing requires optional dependency hvac. "
                "Install velvet-rope[enterprise-vault]."
            ) from error
        resolved_client = hvac.Client()
    return VaultTransitSigner(
        key_name=resolved_key_name,
        client=resolved_client,
        mount_point=resolved_mount,
        key_version=key_version,
        hash_algorithm=hash_algorithm,
        signature_algorithm=signature_algorithm,
    )


def resolve_signing_provider(
    *,
    signing_provider: str | None = None,
    signing_profile: str | None = None,
    dev_ephemeral_key: bool = False,
    key_id: str | None = None,
    key_version: str | None = None,
    kms_key_id: str | None = None,
    kms_signing_algorithm: str | None = None,
    vault_transit_key: str | None = None,
    vault_mount: str | None = None,
    aws_kms_client: AwsKmsClient | None = None,
    vault_client: object | None = None,
    create_clients: bool = False,
) -> SigningProvider:
    """Resolve a signing provider without falling back from enterprise to demo signing."""

    raw_provider = signing_provider or os.environ.get(VELVET_SIGNING_PROVIDER_ENV) or "ed25519"
    provider = raw_provider.strip().lower().replace("_", "-")
    if provider in {"ed25519", "velvet-ed25519"}:
        return resolve_ed25519_signing_provider(
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
            key_id=key_id,
            key_version=key_version,
        )
    if provider in {"aws-kms", "kms"}:
        resolved_key_id = kms_key_id or key_id or os.environ.get(VELVET_KMS_KEY_ID_ENV)
        resolved_algorithm = (
            kms_signing_algorithm
            or os.environ.get(VELVET_KMS_SIGNING_ALGORITHM_ENV)
            or DEFAULT_AWS_KMS_SIGNING_ALGORITHM
        )
        if create_clients or aws_kms_client is not None:
            return aws_kms_signer_from_boto3(
                key_id=resolved_key_id,
                client=aws_kms_client,
                signing_algorithm=resolved_algorithm,
                key_version=key_version or resolved_key_id,
            )
        return AwsKmsSigner(
            key_id=resolved_key_id,
            client=aws_kms_client,
            signing_algorithm=resolved_algorithm,
            key_version=key_version or resolved_key_id,
        )
    if provider in {"vault", "vault-transit"}:
        resolved_key_name = (
            vault_transit_key or key_id or os.environ.get(VELVET_VAULT_TRANSIT_KEY_ENV)
        )
        resolved_mount = (
            vault_mount
            or os.environ.get(VELVET_VAULT_MOUNT_ENV)
            or DEFAULT_VAULT_MOUNT_POINT
        )
        if create_clients or vault_client is not None:
            return vault_transit_signer_from_hvac(
                key_name=resolved_key_name,
                client=vault_client,
                mount_point=resolved_mount,
                key_version=key_version or "latest",
            )
        return VaultTransitSigner(
            key_name=resolved_key_name,
            client=vault_client,
            mount_point=resolved_mount,
            key_version=key_version or "latest",
        )
    raise SigningProviderNotConfigured(
        f"Unsupported signing provider {raw_provider!r}; use ed25519, aws-kms, or vault."
    )


def parse_vault_transit_signature(signature: str) -> JsonObject:
    """Parse Vault Transit signatures without assuming a fixed key version."""

    parts = signature.split(":", 2)
    if len(parts) != 3 or parts[0] != "vault" or not parts[1] or not parts[2]:
        raise ValueError("Vault Transit signature must be vault:<version>:<base64>")
    base64.b64decode(parts[2].encode("ascii"), validate=True)
    return {
        "prefix": parts[0],
        "key_version": parts[1],
        "signature_base64": parts[2],
    }


def _kms_signature_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value.encode("ascii"), validate=True)
    raise SigningConfigurationError("AWS KMS Sign response did not include signature bytes")


def _kms_public_key_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value.encode("ascii"), validate=True)
    raise SigningConfigurationError(
        "AWS KMS GetPublicKey response did not include public key bytes"
    )


def _verify_aws_kms_public_signature(
    signing_algorithm: str,
    public_key_der: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        serialization = _serialization_module()
        public_key = serialization.load_der_public_key(public_key_der)
        hash_algorithm = _aws_kms_hash_algorithm(signing_algorithm)
        if signing_algorithm.startswith("RSASSA_PSS_"):
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=hash_algorithm.digest_size,
                ),
                hash_algorithm,
            )
            return True
        if signing_algorithm.startswith("RSASSA_PKCS1_V1_5_"):
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key.verify(signature, message, padding.PKCS1v15(), hash_algorithm)
            return True
        if signing_algorithm.startswith("ECDSA_"):
            from cryptography.hazmat.primitives.asymmetric import ec

            public_key.verify(signature, message, ec.ECDSA(hash_algorithm))
            return True
        if signing_algorithm == "ED25519":
            public_key.verify(signature, message)
            return True
    except Exception:  # noqa: BLE001 - crypto verification failures return false.
        return False
    return False


def _aws_kms_hash_algorithm(signing_algorithm: str) -> Any:
    try:
        from cryptography.hazmat.primitives import hashes
    except ImportError as error:
        raise SigningProviderNotConfigured(
            "AWS KMS public verification requires the cryptography package."
        ) from error
    if signing_algorithm.endswith("_SHA_256"):
        return hashes.SHA256()
    if signing_algorithm.endswith("_SHA_384"):
        return hashes.SHA384()
    if signing_algorithm.endswith("_SHA_512"):
        return hashes.SHA512()
    raise SigningConfigurationError(f"unsupported AWS KMS signing algorithm: {signing_algorithm}")


def _kms_public_key_der_from_material(material: str | bytes | object) -> bytes:
    if isinstance(material, bytes):
        if material.startswith(b"-----BEGIN"):
            public_key = _serialization_load_pem_public_key(material)
            return _public_key_der(public_key)
        return material
    if not isinstance(material, str):
        return _public_key_der(material)
    text = material.strip().replace("\\n", "\n")
    if text.startswith("-----BEGIN"):
        public_key = _serialization_load_pem_public_key(text.encode("ascii"))
        return _public_key_der(public_key)
    return base64.b64decode(text.encode("ascii"), validate=True)


def _public_key_der(public_key: object) -> bytes:
    serialization = _serialization_module()
    typed_public_key = cast(Any, public_key)
    return cast(
        bytes,
        typed_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _vault_transit_method_client(client: object) -> VaultTransitMethodClient | None:
    if hasattr(client, "sign_data") and hasattr(client, "verify_signed_data"):
        return cast(VaultTransitMethodClient, client)
    secrets = getattr(client, "secrets", None)
    transit = getattr(secrets, "transit", None) if secrets is not None else None
    if transit is not None and hasattr(transit, "sign_data") and hasattr(
        transit,
        "verify_signed_data",
    ):
        return cast(VaultTransitMethodClient, transit)
    return None


def _vault_request_key_version(key_version: str) -> str | int | None:
    if key_version in {"", "latest"}:
        return None
    if key_version.isdecimal():
        return int(key_version)
    return key_version


def _vault_response_value(response: Mapping[str, Any], key: str) -> str:
    value = response.get(key)
    if isinstance(value, str):
        return value
    data = response.get("data")
    if isinstance(data, Mapping):
        nested = data.get(key)
        if isinstance(nested, str):
            return nested
    raise SigningConfigurationError(f"Vault Transit response did not include {key!r}")


def _vault_response_bool(response: Mapping[str, Any], key: str) -> bool:
    value = response.get(key)
    if isinstance(value, bool):
        return value
    data = response.get("data")
    if isinstance(data, Mapping):
        nested = data.get(key)
        if isinstance(nested, bool):
            return nested
    return False


def default_artifact_signer(
    *,
    tenant_id: str = DEFAULT_TENANT_ID,
    key_id: str = DEFAULT_LOCAL_DEV_HMAC_KEY_ID,
    key_version: str = DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION,
    signing_key: str = DEFAULT_LOCAL_DEV_HMAC_KEY,
    schema_version: str = SIGNATURE_SCHEMA_VERSION,
) -> ArtifactSigner:
    return ArtifactSigner(
        LocalDevHmacSigner(signing_key, key_version=key_version, schema_version=schema_version),
        tenant_id=tenant_id,
        key_id=key_id,
    )


def default_demo_signer(
    signing_key: str = DEFAULT_LOCAL_DEV_HMAC_KEY,
    *,
    key_version: str = DEFAULT_LOCAL_DEV_HMAC_KEY_VERSION,
    schema_version: str = SIGNATURE_SCHEMA_VERSION,
) -> LocalDevHmacSigner:
    return LocalDevHmacSigner(
        signing_key,
        key_version=key_version,
        schema_version=schema_version,
    )


def payload_hash(payload: Mapping[str, Any] | bytes) -> str:
    if isinstance(payload, bytes):
        return hashlib.sha256(payload).hexdigest()
    return ArtifactSigner.payload_hash(stable_json_object(payload))


def sign_payload_hash(
    signed_payload_hash: str,
    *,
    purpose: str,
    tenant_id: str | None = None,
    key_id: str = LOCAL_DEMO_KEY_ID,
    signer: SigningProvider | None = None,
    signed_at: str | None = None,
) -> JsonObject:
    active_signer = signer or default_demo_signer()
    resolved_tenant_id = tenant_id or LOCAL_DEMO_TENANT_ID
    schema_version = str(getattr(active_signer, "schema_version", SIGNATURE_SCHEMA_VERSION))
    return SignatureBlock(
        provider_name=active_signer.provider_name,
        algorithm=active_signer.algorithm,
        key_id=key_id,
        key_version=active_signer.key_version,
        purpose=purpose,
        tenant_id=resolved_tenant_id,
        payload_hash=signed_payload_hash,
        signature=active_signer.sign(
            signed_payload_hash,
            purpose,
            resolved_tenant_id,
            key_id,
        ),
        public_verification_material=active_signer.public_verification_material(key_id),
        schema_version=schema_version,
        signed_at=signed_at if signed_at is not None else _now_iso(),
        metadata=_signature_metadata(active_signer),
    ).to_dict()


def signature_record_signature(record: Mapping[str, Any]) -> str | None:
    value = record.get("signature")
    return value if isinstance(value, str) else None


_SIGNATURE_RECORD_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "provider_name",
        "algorithm",
        "key_id",
        "key_version",
        "purpose",
        "tenant_id",
        "payload_hash",
        "signature",
        "signed_at",
        "metadata",
    }
)
_SIGNATURE_RECORD_ALLOWED_KEYS = _SIGNATURE_RECORD_REQUIRED_KEYS | {
    "public_verification_material"
}


def verify_signature_record(
    record: Mapping[str, Any],
    expected_payload_hash: str,
    *,
    purpose: str | None = None,
    tenant_id: str | None = None,
    key_id: str | None = None,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
    public_key_pem: str | None = None,
    public_key_base64: str | None = None,
) -> bool:
    # Strict shape check: signature-block metadata outside the signing message
    # (signed_at, metadata, embedded key material) is not hash-covered, so a
    # renamed or injected key must fail verification rather than being
    # silently defaulted or ignored.
    record_keys = {str(item) for item in record.keys()}
    if not _SIGNATURE_RECORD_REQUIRED_KEYS <= record_keys:
        return False
    if not record_keys <= _SIGNATURE_RECORD_ALLOWED_KEYS:
        return False
    try:
        block = SignatureBlock.from_dict(record)
    except (KeyError, TypeError, ValueError):
        return False
    if block.schema_version not in SUPPORTED_SIGNATURE_SCHEMA_VERSIONS:
        return False
    if purpose is not None and block.purpose != purpose:
        return False
    if tenant_id is not None and block.tenant_id != tenant_id:
        return False
    if key_id is not None and block.key_id != key_id:
        return False
    if not hmac.compare_digest(block.payload_hash, expected_payload_hash):
        return False
    verifier_material = public_key or public_key_pem or public_key_base64
    active_signer = signer
    if active_signer is None and verifier_material is not None:
        try:
            if block.provider_name == "aws_kms":
                active_signer = AwsKmsSigner(
                    key_id=block.key_id,
                    signing_algorithm=block.algorithm,
                    key_version=block.key_version,
                    public_key_der=_kms_public_key_der_from_material(verifier_material),
                )
            else:
                active_signer = Ed25519PublicVerifier.from_block(block, verifier_material)
        except Exception:  # noqa: BLE001 - malformed public material fails closed.
            return False
    if active_signer is None:
        active_signer = _default_signer_for_block(block)
    if active_signer is None:
        return False
    return ArtifactSigner(
        active_signer,
        tenant_id=block.tenant_id,
        key_id=block.key_id,
    ).verify_block(block)


def _default_signer_for_block(block: SignatureBlock) -> SigningProvider | None:
    if block.provider_name == "local_dev_hmac_demo":
        return default_demo_signer(
            key_version=block.key_version,
            schema_version=block.schema_version,
        )
    if block.algorithm == "Ed25519":
        material = block.public_verification_material
        if isinstance(material, Mapping):
            public_key = material.get("public_key_pem") or material.get("public_key_base64")
            if isinstance(public_key, str) and public_key:
                return Ed25519PublicVerifier.from_block(block, public_key)
    if block.provider_name == "aws_kms":
        material = block.public_verification_material
        if isinstance(material, Mapping):
            public_key_der_base64 = material.get("public_key_der_base64")
            if isinstance(public_key_der_base64, str) and public_key_der_base64:
                return AwsKmsSigner(
                    key_id=block.key_id,
                    signing_algorithm=block.algorithm,
                    key_version=block.key_version,
                    public_key_der_base64=public_key_der_base64,
                )
    return None


def signing_message(
    payload_hash: str,
    purpose: str,
    tenant_id: str,
    key_id: str,
    *,
    provider_name: str,
    algorithm: str,
    key_version: str,
    schema_version: str = SIGNATURE_SCHEMA_VERSION,
) -> bytes:
    return canonical_dumps(
        {
            "schema_version": schema_version,
            "provider_name": provider_name,
            "algorithm": algorithm,
            "key_version": key_version,
            "key_id": key_id,
            "tenant_id": tenant_id,
            "purpose": purpose,
            "payload_hash": payload_hash,
        }
    ).encode("utf-8")


def signer_default_key_id(signer: SigningProvider, fallback: str = LOCAL_DEMO_KEY_ID) -> str:
    value = getattr(signer, "key_id", None)
    return value if isinstance(value, str) and value else fallback


def _signature_metadata(provider: SigningProvider) -> JsonObject:
    provider_name = provider.provider_name
    tier = getattr(provider, "verification_tier", None)
    verification_tier = str(tier) if isinstance(tier, str) and tier else "unspecified"
    metadata: JsonObject = {"verification_tier": verification_tier}
    if provider_name == "local_dev_hmac_demo":
        metadata.update(
            {
                "demo_only": True,
                "non_production": True,
                "warning": "HMAC signatures use a shared secret and are local-dev only.",
            }
        )
    elif verification_tier == "demo":
        metadata.update(
            {
                "demo_only": True,
                "non_production": True,
                "warning": "Demo Ed25519 key is committed test material, not production.",
            }
        )
    elif verification_tier == "non-durable":
        metadata.update(
            {
                "non_production": True,
                "non_durable": True,
                "warning": "Ephemeral Ed25519 key must be captured for later verification.",
            }
        )
    provider_metadata = getattr(provider, "signature_metadata", None)
    if callable(provider_metadata):
        metadata.update(stable_json_object(cast(Mapping[str, Any], provider_metadata())))
    return metadata


def _public_key_from_private_or_public(private_or_public_key: Any) -> Any:
    public_cls = _ed25519_public_key_cls()
    if isinstance(private_or_public_key, public_cls):
        return private_or_public_key
    if hasattr(private_or_public_key, "public_key"):
        return private_or_public_key.public_key()
    return load_ed25519_public_key(private_or_public_key)


def _reject_demo_private_key(private_key: Any, *, source: str) -> None:
    if export_ed25519_public_key_base64(private_key) == DEMO_ED25519_PUBLIC_KEY_BASE64:
        raise SigningProviderNotConfigured(
            f"Refusing to load tests/fixtures demo Ed25519 key from production source {source}; "
            "use VELVET_SIGNING_PROFILE=demo only for demo/test signing."
        )


def _ed25519_private_key_cls() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as error:
        raise SigningProviderNotConfigured(
            "Ed25519 signing requires the cryptography package."
        ) from error
    return Ed25519PrivateKey


def _ed25519_public_key_cls() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as error:
        raise SigningProviderNotConfigured(
            "Ed25519 verification requires the cryptography package."
        ) from error
    return Ed25519PublicKey


def _serialization_module() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as error:
        raise SigningProviderNotConfigured(
            "Ed25519 key serialization requires the cryptography package."
        ) from error
    return serialization


def _serialization_load_pem_private_key(raw: bytes) -> Any:
    serialization = _serialization_module()
    return serialization.load_pem_private_key(raw, password=None)


def _serialization_load_pem_public_key(raw: bytes) -> Any:
    serialization = _serialization_module()
    return serialization.load_pem_public_key(raw)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
