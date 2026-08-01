from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from velvet.storage import (
    ArtifactRef,
    EvidenceManifest,
    LocalFilesystemEvidenceStore,
    LocalManifestSigner,
    S3CompatibleEvidenceStore,
)


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str, str], bytes] = {}
        self.put_calls: list[dict[str, Any]] = []
        self.version = 0

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        self.version += 1
        version_id = f"v{self.version}"
        self.put_calls.append(dict(kwargs))
        self.objects[(str(kwargs["Bucket"]), str(kwargs["Key"]), version_id)] = bytes(
            kwargs["Body"]
        )
        return {"VersionId": version_id}

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]), str(kwargs.get("VersionId", "v1")))
        return {"Body": FakeBody(self.objects[key])}

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]), str(kwargs.get("VersionId", "v1")))
        if key not in self.objects:
            raise FileNotFoundError(key)
        return {}


class FakeBody:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self) -> bytes:
        return self.data


def test_local_filesystem_store_put_get_exists(tmp_path: Path) -> None:
    source = tmp_path / "ledger.vledger"
    source.write_bytes(b"binary-ledger-fixture")
    store = LocalFilesystemEvidenceStore(tmp_path / "store")

    ref = store.put_artifact(
        source,
        "ledger_segment_binary",
        "tenant-a",
        {"seal_id": "seal_123"},
    )

    assert ref.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert ref.size_bytes == len(source.read_bytes())
    assert ref.metadata["source_name"] == "ledger.vledger"
    assert store.exists(ref)
    assert store.get_artifact(ref) == source.read_bytes()
    assert ArtifactRef.from_dict(ref.to_dict()) == ref


def test_manifest_references_every_artifact_by_hash_and_verifies(tmp_path: Path) -> None:
    store = LocalFilesystemEvidenceStore(tmp_path / "store")
    refs = (
        store.put_artifact(b"binary-ledger-fixture", "ledger_segment_binary", "tenant-a", {}),
        store.put_artifact(b'{"status":"pass"}\n', "replay_report", "tenant-a", {}),
    )

    manifest = store.write_manifest(refs, LocalManifestSigner("test-signer"))
    manifest_path = tmp_path / "store" / "tenant-a" / "manifests" / f"{manifest.manifest_id}.json"
    loaded = EvidenceManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))

    assert [artifact.sha256 for artifact in manifest.artifacts] == [
        artifact.sha256 for artifact in refs
    ]
    assert manifest.manifest_hash == loaded.manifest_hash
    assert manifest.signature["provider_name"] == "local_dev_hmac_demo"
    assert manifest.signature["purpose"] == "velvet.evidence_manifest.v1"
    assert manifest.signature["payload_hash"] == manifest.manifest_hash
    assert manifest.verify_signature()
    assert store.verify_manifest(manifest).status == "pass"

    tampered = EvidenceManifest(
        manifest_id=manifest.manifest_id,
        tenant_id=manifest.tenant_id,
        generated_at=manifest.generated_at,
        artifacts=manifest.artifacts,
        manifest_hash="0" * 64,
        signature=manifest.signature,
        manifest_uri=manifest.manifest_uri,
    )
    assert not tampered.verify_signature()


def test_manifest_verification_catches_missing_artifacts(tmp_path: Path) -> None:
    store = LocalFilesystemEvidenceStore(tmp_path / "store")
    ref = store.put_artifact(b"proof", "replay_report", "tenant-a", {})
    manifest = store.write_manifest((ref,), LocalManifestSigner("test-signer"))
    (tmp_path / "store" / ref.tenant_id / ref.artifact_type / ref.sha256).unlink()

    result = store.verify_manifest(manifest)

    assert result.status == "fail"
    assert result.missing_artifacts == (ref,)
    assert result.modified_artifacts == ()


def test_manifest_verification_catches_modified_artifacts(tmp_path: Path) -> None:
    store = LocalFilesystemEvidenceStore(tmp_path / "store")
    ref = store.put_artifact(b"proof", "policy_bundle_snapshot", "tenant-a", {})
    manifest = store.write_manifest((ref,), LocalManifestSigner("test-signer"))
    (tmp_path / "store" / ref.tenant_id / ref.artifact_type / ref.sha256).write_bytes(b"changed")

    result = store.verify_manifest(manifest)

    assert result.status == "fail"
    assert result.missing_artifacts == ()
    assert result.modified_artifacts == (ref,)


def test_s3_compatible_store_writes_object_lock_artifacts() -> None:
    client = FakeS3Client()
    store = S3CompatibleEvidenceStore(
        bucket="velvet-evidence",
        prefix="prod",
        retention_mode="GOVERNANCE",
        retention_days=30,
        legal_hold=True,
        kms_key_id="alias/velvet-evidence",
        client=client,
    )

    ref = store.put_artifact(
        b'{"status":"pass"}\n',
        "replay_report",
        "tenant-a",
        {"content_type": "application/json"},
    )

    assert ref.store == "s3_object_lock"
    assert ref.uri.startswith("s3://velvet-evidence/prod/tenant-a/replay_report/")
    assert ref.metadata["s3_version_id"] == "v1"
    assert store.exists(ref)
    assert store.get_artifact(ref) == b'{"status":"pass"}\n'
    put = client.put_calls[0]
    assert put["ObjectLockMode"] == "GOVERNANCE"
    assert put["ObjectLockLegalHoldStatus"] == "ON"
    assert put["ServerSideEncryption"] == "aws:kms"


def test_s3_manifest_verifies_referenced_artifacts() -> None:
    client = FakeS3Client()
    store = S3CompatibleEvidenceStore(
        bucket="velvet-evidence",
        object_lock_required=True,
        client=client,
    )
    ref = store.put_artifact(b"proof", "claims_pack_result", "tenant-a", {})

    manifest = store.write_manifest((ref,), LocalManifestSigner("s3-test"))

    assert manifest.manifest_uri.startswith("s3://velvet-evidence/tenant-a/manifests/")
    assert store.verify_manifest(manifest).status == "pass"
