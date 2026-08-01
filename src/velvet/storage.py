"""Evidence artifact storage interfaces and local pilot implementation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import quote, urlparse

from velvet.serialization import canonical_json_v1_bytes, canonicalize
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_EVIDENCE_MANIFEST_V1,
    SigningProvider,
    default_demo_signer,
    payload_hash,
    sign_payload_hash,
    verify_signature_record,
)

JsonObject = dict[str, Any]
PathOrBytes = str | Path | bytes

EVIDENCE_MANIFEST_SCHEMA_VERSION = "velvet.evidence_manifest.v1"
LOCAL_FILESYSTEM_STORE = "local_filesystem"
S3_OBJECT_LOCK_STORE = "s3_object_lock"
EVIDENCE_ARTIFACT_TYPES = frozenset(
    {
        "ledger_segment_binary",
        "ledger_segment_manifest",
        "evidence_pack_markdown",
        "evidence_pack_json",
        "policy_bundle_snapshot",
        "signed_policy_bundle",
        "tool_inventory_snapshot",
        "approval_receipt_snapshot",
        "replay_report",
        "vault_signed_tree_head",
        "vault_public_key",
        "vault_verification_report",
        "claims_pack_result",
        "claims_pack_manifest",
        "assurance_attestation_series",
        "assurance_consistency_proofs",
        "assurance_verification_report",
        "claims_replay_verification_report",
    }
)

_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ArtifactRef:
    store: str
    uri: str
    artifact_type: str
    tenant_id: str
    sha256: str
    size_bytes: int
    created_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ArtifactRef:
        return cls(
            store=str(data["store"]),
            uri=str(data["uri"]),
            artifact_type=str(data["artifact_type"]),
            tenant_id=str(data["tenant_id"]),
            sha256=str(data["sha256"]),
            size_bytes=int(data["size_bytes"]),
            created_at=str(data["created_at"]),
            metadata=_json_object(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    def to_dict(self) -> JsonObject:
        return {
            "store": self.store,
            "uri": self.uri,
            "artifact_type": self.artifact_type,
            "tenant_id": self.tenant_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "metadata": _json_object(self.metadata),
        }


@dataclass(frozen=True)
class EvidenceManifest:
    manifest_id: str
    tenant_id: str
    generated_at: str
    artifacts: tuple[ArtifactRef, ...]
    manifest_hash: str
    signature: Mapping[str, Any]
    manifest_uri: str
    schema_version: str = EVIDENCE_MANIFEST_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceManifest:
        return cls(
            manifest_id=str(data["manifest_id"]),
            tenant_id=str(data["tenant_id"]),
            generated_at=str(data["generated_at"]),
            artifacts=tuple(
                ArtifactRef.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("artifacts", ())
            ),
            manifest_hash=str(data["manifest_hash"]),
            signature=_json_object(cast(Mapping[str, Any], data.get("signature", {}))),
            manifest_uri=str(data["manifest_uri"]),
            schema_version=str(data.get("schema_version", EVIDENCE_MANIFEST_SCHEMA_VERSION)),
        )

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "manifest_hash": self.manifest_hash,
            "signature": _json_object(self.signature),
            "manifest_uri": self.manifest_uri,
        }

    def unsigned_payload(self) -> JsonObject:
        return _manifest_unsigned_payload(
            tenant_id=self.tenant_id,
            generated_at=self.generated_at,
            artifacts=self.artifacts,
        )

    def verify_signature(self, *, signer: SigningProvider | None = None) -> bool:
        if _is_local_manifest_attestation(self.signature):
            return _verify_local_manifest_attestation(self.signature, self.manifest_hash)
        return verify_signature_record(
            self.signature,
            self.manifest_hash,
            purpose=PURPOSE_EVIDENCE_MANIFEST_V1,
            tenant_id=self.tenant_id,
            signer=signer,
        )


@dataclass(frozen=True)
class VerificationResult:
    status: str
    manifest_id: str
    checked_at: str
    artifacts_checked: int
    missing_artifacts: tuple[ArtifactRef, ...] = ()
    modified_artifacts: tuple[ArtifactRef, ...] = ()
    errors: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationResult:
        return cls(
            status=str(data["status"]),
            manifest_id=str(data["manifest_id"]),
            checked_at=str(data["checked_at"]),
            artifacts_checked=int(data["artifacts_checked"]),
            missing_artifacts=tuple(
                ArtifactRef.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("missing_artifacts", ())
            ),
            modified_artifacts=tuple(
                ArtifactRef.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("modified_artifacts", ())
            ),
            errors=tuple(str(item) for item in data.get("errors", ())),
        )

    def to_dict(self) -> JsonObject:
        return {
            "status": self.status,
            "manifest_id": self.manifest_id,
            "checked_at": self.checked_at,
            "artifacts_checked": self.artifacts_checked,
            "missing_artifacts": [artifact.to_dict() for artifact in self.missing_artifacts],
            "modified_artifacts": [artifact.to_dict() for artifact in self.modified_artifacts],
            "errors": list(self.errors),
        }


class ManifestSigner(Protocol):
    def sign(self, payload: bytes, *, tenant_id: str | None = None) -> Mapping[str, Any]:
        """Return signer-specific metadata for the canonical unsigned manifest."""
        ...


@runtime_checkable
class EvidenceStore(Protocol):
    def put_artifact(
        self,
        path_or_bytes: PathOrBytes,
        artifact_type: str,
        tenant_id: str,
        metadata: Mapping[str, Any],
    ) -> ArtifactRef:
        """Store one evidence artifact and return its content-addressed reference."""
        ...

    def get_artifact(self, ref: ArtifactRef) -> bytes:
        """Load an artifact by reference."""
        ...

    def exists(self, ref: ArtifactRef) -> bool:
        """Return whether the artifact reference is currently readable."""
        ...

    def write_manifest(
        self,
        artifacts: Sequence[ArtifactRef],
        signer: ManifestSigner,
    ) -> EvidenceManifest:
        """Persist a manifest over previously stored artifacts."""
        ...

    def verify_manifest(self, manifest: EvidenceManifest) -> VerificationResult:
        """Check referenced artifacts for presence and byte-level hash integrity."""
        ...


@dataclass(frozen=True)
class LocalManifestSigner:
    """Local development manifest signer, not a cryptographic WORM control."""

    signer_id: str = "local-dev-manifest-signer"
    signer: SigningProvider | None = None
    tenant_id: str = LOCAL_DEMO_TENANT_ID
    key_id: str = LOCAL_DEMO_KEY_ID

    def sign(self, payload: bytes, *, tenant_id: str | None = None) -> JsonObject:
        active_signer = self.signer or default_demo_signer()
        signature = sign_payload_hash(
            payload_hash(payload),
            purpose=PURPOSE_EVIDENCE_MANIFEST_V1,
            tenant_id=tenant_id or self.tenant_id,
            key_id=self.key_id,
            signer=active_signer,
        )
        metadata = dict(cast(Mapping[str, Any], signature.get("metadata", {})))
        metadata["signer_id"] = self.signer_id
        signature["metadata"] = metadata
        return signature


class LocalFilesystemEvidenceStore:
    """Content-addressed local filesystem store for pilots and development."""

    store = LOCAL_FILESYSTEM_STORE

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_artifact(
        self,
        path_or_bytes: PathOrBytes,
        artifact_type: str,
        tenant_id: str,
        metadata: Mapping[str, Any],
    ) -> ArtifactRef:
        _validate_artifact_type(artifact_type)
        _validate_safe_component("tenant_id", tenant_id)
        data, source_metadata = _read_path_or_bytes(path_or_bytes)
        digest = _sha256(data)
        destination = self.root / tenant_id / artifact_type / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            destination.write_bytes(data)

        stored_metadata = _json_object(metadata)
        for key, value in source_metadata.items():
            stored_metadata.setdefault(key, value)
        return ArtifactRef(
            store=self.store,
            uri=f"local://{tenant_id}/{artifact_type}/{digest}",
            artifact_type=artifact_type,
            tenant_id=tenant_id,
            sha256=digest,
            size_bytes=len(data),
            created_at=_now_iso(),
            metadata=stored_metadata,
        )

    def get_artifact(self, ref: ArtifactRef) -> bytes:
        return self._artifact_path(ref).read_bytes()

    def exists(self, ref: ArtifactRef) -> bool:
        try:
            return self._artifact_path(ref).is_file()
        except ValueError:
            return False

    def write_manifest(
        self,
        artifacts: Sequence[ArtifactRef],
        signer: ManifestSigner,
    ) -> EvidenceManifest:
        artifact_refs = tuple(artifacts)
        if not artifact_refs:
            raise ValueError("evidence manifest requires at least one artifact")
        tenant_ids = {artifact.tenant_id for artifact in artifact_refs}
        if len(tenant_ids) != 1:
            raise ValueError("evidence manifest artifacts must belong to one tenant")
        tenant_id = next(iter(tenant_ids))
        _validate_safe_component("tenant_id", tenant_id)
        for artifact in artifact_refs:
            self._validate_ref(artifact)

        generated_at = _now_iso()
        manifest_hash = _manifest_hash(
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
        )
        manifest_id = f"manifest_{manifest_hash[:24]}"
        unsigned_payload = _manifest_unsigned_payload(
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
        )
        signature = _json_object(
            signer.sign(canonical_json_v1_bytes(unsigned_payload), tenant_id=tenant_id)
        )
        manifest = EvidenceManifest(
            manifest_id=manifest_id,
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
            manifest_hash=manifest_hash,
            signature=signature,
            manifest_uri=f"local://{tenant_id}/manifests/{manifest_id}.json",
        )
        manifest_path = self._manifest_path(tenant_id, manifest_id)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest

    def verify_manifest(self, manifest: EvidenceManifest) -> VerificationResult:
        missing: list[ArtifactRef] = []
        modified: list[ArtifactRef] = []
        errors: list[str] = []

        expected_hash = _manifest_hash(
            tenant_id=manifest.tenant_id,
            generated_at=manifest.generated_at,
            artifacts=manifest.artifacts,
        )
        if manifest.manifest_hash != expected_hash:
            errors.append("manifest hash mismatch")
        expected_manifest_id = f"manifest_{expected_hash[:24]}"
        if manifest.manifest_id != expected_manifest_id:
            errors.append("manifest id does not match manifest hash")
        if not manifest.verify_signature():
            errors.append("manifest signature mismatch")

        for artifact in manifest.artifacts:
            try:
                self._validate_ref(artifact)
                data = self.get_artifact(artifact)
            except FileNotFoundError:
                missing.append(artifact)
                continue
            except OSError as error:
                missing.append(artifact)
                errors.append(f"{artifact.uri}: {error}")
                continue
            except ValueError as error:
                errors.append(f"{artifact.uri}: {error}")
                continue
            if _sha256(data) != artifact.sha256:
                modified.append(artifact)

        status = "pass" if not missing and not modified and not errors else "fail"
        return VerificationResult(
            status=status,
            manifest_id=manifest.manifest_id,
            checked_at=_now_iso(),
            artifacts_checked=len(manifest.artifacts),
            missing_artifacts=tuple(missing),
            modified_artifacts=tuple(modified),
            errors=tuple(errors),
        )

    def _artifact_path(self, ref: ArtifactRef) -> Path:
        self._validate_ref(ref)
        return self.root / ref.tenant_id / ref.artifact_type / ref.sha256

    def _manifest_path(self, tenant_id: str, manifest_id: str) -> Path:
        _validate_safe_component("tenant_id", tenant_id)
        _validate_safe_component("manifest_id", manifest_id)
        return self.root / tenant_id / "manifests" / f"{manifest_id}.json"

    def _validate_ref(self, ref: ArtifactRef) -> None:
        if ref.store != self.store:
            raise ValueError(f"artifact store mismatch: expected {self.store}, got {ref.store}")
        _validate_artifact_type(ref.artifact_type)
        _validate_safe_component("tenant_id", ref.tenant_id)
        if not _SHA256_RE.fullmatch(ref.sha256):
            raise ValueError(f"invalid artifact sha256: {ref.sha256}")


@dataclass(frozen=True)
class S3CompatibleEvidenceStore:
    """S3-compatible evidence store using Object Lock/WORM controls."""

    bucket: str
    prefix: str = ""
    endpoint_url: str | None = None
    object_lock_required: bool = True
    retention_mode: str = "COMPLIANCE"
    retention_days: int = 2555
    legal_hold: bool = False
    kms_key_id: str | None = None
    client: object | None = None

    store = S3_OBJECT_LOCK_STORE

    def put_artifact(
        self,
        path_or_bytes: PathOrBytes,
        artifact_type: str,
        tenant_id: str,
        metadata: Mapping[str, Any],
    ) -> ArtifactRef:
        _validate_artifact_type(artifact_type)
        _validate_safe_component("tenant_id", tenant_id)
        data, source_metadata = _read_path_or_bytes(path_or_bytes)
        digest = _sha256(data)
        key = self._artifact_key(tenant_id, artifact_type, digest)
        content_type = str(metadata.get("content_type") or "application/octet-stream")
        response = self._put_object(
            key,
            data,
            content_type=content_type,
            metadata={
                "tenant_id": tenant_id,
                "artifact_type": artifact_type,
                "sha256": digest,
            },
        )
        version_id = _optional_str(response.get("VersionId"))
        stored_metadata = _json_object(metadata)
        for source_key, value in source_metadata.items():
            stored_metadata.setdefault(source_key, value)
        stored_metadata.update(
            {
                "s3_bucket": self.bucket,
                "s3_key": key,
                "s3_version_id": version_id,
                "object_lock_required": self.object_lock_required,
                "object_lock_mode": self.retention_mode if self.object_lock_required else None,
                "retention_days": self.retention_days if self.object_lock_required else None,
                "legal_hold": self.legal_hold,
                "kms_key_id": self.kms_key_id,
                "content_type": content_type,
            }
        )
        return ArtifactRef(
            store=self.store,
            uri=self._s3_uri(key, version_id),
            artifact_type=artifact_type,
            tenant_id=tenant_id,
            sha256=digest,
            size_bytes=len(data),
            created_at=_now_iso(),
            metadata=stored_metadata,
        )

    def get_artifact(self, ref: ArtifactRef) -> bytes:
        self._validate_ref(ref)
        kwargs: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key_from_ref(ref)}
        version_id = ref.metadata.get("s3_version_id")
        if isinstance(version_id, str) and version_id:
            kwargs["VersionId"] = version_id
        response = self._client().get_object(**kwargs)
        body = response["Body"]
        return cast(bytes, body.read())

    def exists(self, ref: ArtifactRef) -> bool:
        try:
            self._validate_ref(ref)
            kwargs: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key_from_ref(ref)}
            version_id = ref.metadata.get("s3_version_id")
            if isinstance(version_id, str) and version_id:
                kwargs["VersionId"] = version_id
            self._client().head_object(**kwargs)
        except Exception:  # noqa: BLE001 - provider-specific not-found errors.
            return False
        return True

    def write_manifest(
        self,
        artifacts: Sequence[ArtifactRef],
        signer: ManifestSigner,
    ) -> EvidenceManifest:
        artifact_refs = tuple(artifacts)
        if not artifact_refs:
            raise ValueError("evidence manifest requires at least one artifact")
        tenant_ids = {artifact.tenant_id for artifact in artifact_refs}
        if len(tenant_ids) != 1:
            raise ValueError("evidence manifest artifacts must belong to one tenant")
        tenant_id = next(iter(tenant_ids))
        _validate_safe_component("tenant_id", tenant_id)
        for artifact in artifact_refs:
            self._validate_ref(artifact)

        generated_at = _now_iso()
        manifest_hash = _manifest_hash(
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
        )
        manifest_id = f"manifest_{manifest_hash[:24]}"
        unsigned_payload = _manifest_unsigned_payload(
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
        )
        signature = _json_object(
            signer.sign(canonical_json_v1_bytes(unsigned_payload), tenant_id=tenant_id)
        )
        manifest = EvidenceManifest(
            manifest_id=manifest_id,
            tenant_id=tenant_id,
            generated_at=generated_at,
            artifacts=artifact_refs,
            manifest_hash=manifest_hash,
            signature=signature,
            manifest_uri="",
        )
        manifest_bytes = (json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        key = self._manifest_key(tenant_id, manifest_id)
        response = self._put_object(
            key,
            manifest_bytes,
            content_type="application/json",
            metadata={
                "tenant_id": tenant_id,
                "artifact_type": "evidence_manifest",
                "sha256": _sha256(manifest_bytes),
                "manifest_hash": manifest_hash,
            },
        )
        return EvidenceManifest(
            manifest_id=manifest.manifest_id,
            tenant_id=manifest.tenant_id,
            generated_at=manifest.generated_at,
            artifacts=manifest.artifacts,
            manifest_hash=manifest.manifest_hash,
            signature=manifest.signature,
            manifest_uri=self._s3_uri(key, _optional_str(response.get("VersionId"))),
        )

    def verify_manifest(self, manifest: EvidenceManifest) -> VerificationResult:
        missing: list[ArtifactRef] = []
        modified: list[ArtifactRef] = []
        errors: list[str] = []

        expected_hash = _manifest_hash(
            tenant_id=manifest.tenant_id,
            generated_at=manifest.generated_at,
            artifacts=manifest.artifacts,
        )
        if manifest.manifest_hash != expected_hash:
            errors.append("manifest hash mismatch")
        expected_manifest_id = f"manifest_{expected_hash[:24]}"
        if manifest.manifest_id != expected_manifest_id:
            errors.append("manifest id does not match manifest hash")
        if not manifest.verify_signature():
            errors.append("manifest signature mismatch")

        for artifact in manifest.artifacts:
            try:
                self._validate_ref(artifact)
                data = self.get_artifact(artifact)
            except Exception as error:  # noqa: BLE001 - provider-specific not-found errors.
                missing.append(artifact)
                errors.append(f"{artifact.uri}: {error}")
                continue
            if _sha256(data) != artifact.sha256:
                modified.append(artifact)

        status = "pass" if not missing and not modified and not errors else "fail"
        return VerificationResult(
            status=status,
            manifest_id=manifest.manifest_id,
            checked_at=_now_iso(),
            artifacts_checked=len(manifest.artifacts),
            missing_artifacts=tuple(missing),
            modified_artifacts=tuple(modified),
            errors=tuple(errors),
        )

    def _client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise RuntimeError(
                "S3-compatible evidence storage requires optional dependency boto3. "
                "Install velvet-rope[enterprise-kms] or provide client=..."
            ) from error
        kwargs: dict[str, Any] = {}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return boto3.client("s3", **kwargs)

    def _put_object(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str,
        metadata: Mapping[str, str],
    ) -> Mapping[str, Any]:
        kwargs: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
            "Metadata": {key: value for key, value in metadata.items() if value},
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(data).digest()).decode("ascii"),
        }
        if self.kms_key_id:
            kwargs["ServerSideEncryption"] = "aws:kms"
            kwargs["SSEKMSKeyId"] = self.kms_key_id
        if self.object_lock_required:
            kwargs["ObjectLockMode"] = self.retention_mode
            kwargs["ObjectLockRetainUntilDate"] = datetime.now(tz=UTC) + timedelta(
                days=self.retention_days
            )
            kwargs["ObjectLockLegalHoldStatus"] = "ON" if self.legal_hold else "OFF"
        response = self._client().put_object(**kwargs)
        if self.object_lock_required and not response.get("VersionId"):
            raise RuntimeError("S3 Object Lock evidence writes require bucket versioning")
        return cast(Mapping[str, Any], response)

    def _artifact_key(self, tenant_id: str, artifact_type: str, digest: str) -> str:
        return self._join_key(tenant_id, artifact_type, digest)

    def _manifest_key(self, tenant_id: str, manifest_id: str) -> str:
        _validate_safe_component("manifest_id", manifest_id)
        return self._join_key(tenant_id, "manifests", f"{manifest_id}.json")

    def _join_key(self, *components: str) -> str:
        safe_components = [quote(component.strip("/"), safe="._-") for component in components]
        prefix = self.prefix.strip("/")
        if prefix:
            return "/".join([prefix, *safe_components])
        return "/".join(safe_components)

    def _s3_uri(self, key: str, version_id: str | None = None) -> str:
        uri = f"s3://{self.bucket}/{key}"
        if version_id:
            return f"{uri}?versionId={quote(version_id, safe='')}"
        return uri

    def _key_from_ref(self, ref: ArtifactRef) -> str:
        key = ref.metadata.get("s3_key")
        if isinstance(key, str) and key:
            return key
        parsed = urlparse(ref.uri)
        if parsed.scheme != "s3" or parsed.netloc != self.bucket:
            raise ValueError(f"artifact URI does not belong to bucket {self.bucket}")
        return parsed.path.lstrip("/")

    def _validate_ref(self, ref: ArtifactRef) -> None:
        if ref.store != self.store:
            raise ValueError(f"artifact store mismatch: expected {self.store}, got {ref.store}")
        _validate_artifact_type(ref.artifact_type)
        _validate_safe_component("tenant_id", ref.tenant_id)
        if not _SHA256_RE.fullmatch(ref.sha256):
            raise ValueError(f"invalid artifact sha256: {ref.sha256}")


def _manifest_unsigned_payload(
    *,
    tenant_id: str,
    generated_at: str,
    artifacts: Sequence[ArtifactRef],
) -> JsonObject:
    return {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": generated_at,
        "artifacts": [artifact.to_dict() for artifact in artifacts],
    }


def _local_manifest_attestation(
    payload: bytes,
    *,
    signer_id: str,
    tenant_id: str,
    key_id: str,
) -> JsonObject:
    digest = payload_hash(payload)
    return {
        "type": "local_sha256_attestation",
        "hash_algorithm": "sha256",
        "payload_hash": digest,
        "signature": digest,
        "signer_id": signer_id,
        "tenant_id": tenant_id,
        "key_id": key_id,
    }


def _is_local_manifest_attestation(signature: Mapping[str, Any]) -> bool:
    return signature.get("type") == "local_sha256_attestation"


def _verify_local_manifest_attestation(
    signature: Mapping[str, Any],
    expected_hash: str,
) -> bool:
    payload_digest = signature.get("payload_hash")
    signature_digest = signature.get("signature")
    return (
        isinstance(payload_digest, str)
        and isinstance(signature_digest, str)
        and hmac.compare_digest(payload_digest, expected_hash)
        and hmac.compare_digest(signature_digest, expected_hash)
    )


def _manifest_hash(
    *,
    tenant_id: str,
    generated_at: str,
    artifacts: Sequence[ArtifactRef],
) -> str:
    return _sha256(
        canonical_json_v1_bytes(
            _manifest_unsigned_payload(
                tenant_id=tenant_id,
                generated_at=generated_at,
                artifacts=artifacts,
            )
        )
    )


def _read_path_or_bytes(path_or_bytes: PathOrBytes) -> tuple[bytes, JsonObject]:
    if isinstance(path_or_bytes, bytes):
        return path_or_bytes, {}
    path = Path(path_or_bytes)
    return path.read_bytes(), {
        "source_path": str(path),
        "source_name": path.name,
    }


def _json_object(value: Mapping[str, Any]) -> JsonObject:
    encoded = json.dumps(canonicalize(dict(value)), sort_keys=True, default=str)
    return cast(JsonObject, json.loads(encoded))


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _validate_artifact_type(artifact_type: str) -> None:
    if artifact_type not in EVIDENCE_ARTIFACT_TYPES:
        allowed = ", ".join(sorted(EVIDENCE_ARTIFACT_TYPES))
        raise ValueError(f"unsupported evidence artifact type: {artifact_type} ({allowed})")


def _validate_safe_component(label: str, value: str) -> None:
    if not value or value in {".", ".."} or not _SAFE_COMPONENT_RE.fullmatch(value):
        raise ValueError(f"{label} must be a non-empty filesystem-safe identifier")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


__all__ = [
    "ArtifactRef",
    "EVIDENCE_ARTIFACT_TYPES",
    "EVIDENCE_MANIFEST_SCHEMA_VERSION",
    "EvidenceManifest",
    "EvidenceStore",
    "LocalFilesystemEvidenceStore",
    "LocalManifestSigner",
    "ManifestSigner",
    "S3CompatibleEvidenceStore",
    "VerificationResult",
]
