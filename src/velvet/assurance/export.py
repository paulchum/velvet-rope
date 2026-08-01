"""Outbound-only export transports for Velvet assurance attestations."""

from __future__ import annotations

import hashlib
import json
import shutil
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from velvet.serialization import JsonObject, canonical_dumps, canonical_hash_sha256

ASSURANCE_EXPORT_MANIFEST_SCHEMA_VERSION = "velvet.assurance.export_manifest.v1"
ASSURANCE_CONSISTENCY_PROOFS_SCHEMA_VERSION = "velvet.assurance.consistency_proofs.v1"


class WebhookTransport(Protocol):
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> int:
        """Post bytes and return an HTTP-like status code."""


@dataclass(frozen=True)
class WebhookExportResult:
    status: str
    attempted: int
    delivered: int
    spooled: int
    spool_paths: tuple[str, ...] = ()


class UrllibWebhookTransport:
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> int:
        _require_http_webhook_url(url)
        request = urllib.request.Request(  # noqa: S310 - caller supplies outbound webhook URL.
            url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
                return int(response.status)
        except urllib.error.HTTPError as error:
            return int(error.code)
        except OSError:
            return 0


def export_attestations_jsonl(
    attestations: Sequence[Mapping[str, Any]],
    output_path: str | Path,
) -> JsonObject:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [canonical_dumps(attestation) for attestation in attestations]
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return {
        "schema_version": ASSURANCE_EXPORT_MANIFEST_SCHEMA_VERSION,
        "export_mode": "jsonl_file",
        "attestation_count": len(attestations),
        "path": str(destination),
        "sha256": _file_sha256(destination),
        "generated_at": _now_iso(),
    }


def append_attestation_jsonl_idempotent(
    attestation: Mapping[str, Any],
    output_path: str | Path,
) -> JsonObject:
    """Append one attestation unless the same deployment period is already present."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    new_key = _attestation_period_key(attestation)
    if new_key is None:
        raise ValueError("scheduled attestation envelope is missing deployment period fields")
    existing_count = 0
    if destination.exists():
        for existing_count, existing in enumerate(_read_jsonl_objects(destination), start=1):
            existing_key = _attestation_period_key(existing)
            if existing_key != new_key:
                continue
            if existing.get("payload_hash") == attestation.get("payload_hash"):
                return {
                    "schema_version": ASSURANCE_EXPORT_MANIFEST_SCHEMA_VERSION,
                    "export_mode": "jsonl_append",
                    "status": "already_present",
                    "attestation_count": existing_count,
                    "path": str(destination),
                    "sha256": _file_sha256(destination),
                    "generated_at": _now_iso(),
                }
            raise ValueError("conflicting attestation already exists for deployment period")
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(canonical_dumps(attestation) + "\n")
    return {
        "schema_version": ASSURANCE_EXPORT_MANIFEST_SCHEMA_VERSION,
        "export_mode": "jsonl_append",
        "status": "appended",
        "attestation_count": existing_count + 1,
        "path": str(destination),
        "sha256": _file_sha256(destination),
        "generated_at": _now_iso(),
    }


def write_consistency_proofs(
    proofs: Sequence[Mapping[str, Any]],
    output_path: str | Path,
) -> JsonObject:
    payload: JsonObject = {
        "schema_version": ASSURANCE_CONSISTENCY_PROOFS_SCHEMA_VERSION,
        "proofs": [dict(proof) for proof in proofs],
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_dumps(payload) + "\n", encoding="utf-8")
    return payload


def write_manual_bundle(
    *,
    attestations: Sequence[Mapping[str, Any]],
    output_dir: str | Path,
    consistency_proofs: Sequence[Mapping[str, Any]] = (),
) -> JsonObject:
    destination = Path(output_dir)
    if destination.exists():
        for child in destination.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    destination.mkdir(parents=True, exist_ok=True)
    attestation_manifest = export_attestations_jsonl(
        attestations,
        destination / "attestations.jsonl",
    )
    write_consistency_proofs(consistency_proofs, destination / "consistency_proofs.json")
    readme = "\n".join(
        [
            "# Velvet Assurance Manual Bundle",
            "",
            "This bundle is outbound-only evidence for offline verifier use.",
            "It contains signed aggregate attestations and optional Merkle consistency proofs.",
            "",
        ]
    )
    (destination / "README.md").write_text(readme, encoding="utf-8")
    files = _hash_bundle_files(destination)
    manifest: JsonObject = {
        "schema_version": ASSURANCE_EXPORT_MANIFEST_SCHEMA_VERSION,
        "export_mode": "manual_bundle",
        "attestation_count": len(attestations),
        "consistency_proof_count": len(consistency_proofs),
        "generated_at": _now_iso(),
        "files": files,
        "attestations_jsonl_sha256": attestation_manifest["sha256"],
    }
    manifest["manifest_hash"] = canonical_hash_sha256(manifest)
    (destination / "manifest.json").write_text(canonical_dumps(manifest) + "\n", encoding="utf-8")
    return manifest


def push_attestations_webhook(
    *,
    attestations: Sequence[Mapping[str, Any]],
    url: str,
    spool_dir: str | Path,
    transport: WebhookTransport | None = None,
    timeout: float = 5.0,
    retries: int = 3,
) -> WebhookExportResult:
    _require_http_webhook_url(url)
    active_transport = transport or UrllibWebhookTransport()
    spool = Path(spool_dir)
    spool.mkdir(parents=True, exist_ok=True)
    delivered = 0
    spooled_paths: list[str] = []
    headers = {
        "content-type": "application/json",
        "user-agent": "velvet-assurance-export/1",
    }
    for index, attestation in enumerate(attestations):
        body = (canonical_dumps(attestation) + "\n").encode("utf-8")
        ok = False
        for _attempt in range(max(1, retries)):
            status_code = active_transport.post(url, body, headers, timeout)
            if 200 <= status_code < 300:
                ok = True
                delivered += 1
                break
        if not ok:
            spool_path = spool / f"attestation_{index:06d}_{_body_sha256(body)}.json"
            spool_path.write_bytes(body)
            spooled_paths.append(str(spool_path))
    return WebhookExportResult(
        status="ok" if not spooled_paths else "degraded",
        attempted=len(attestations),
        delivered=delivered,
        spooled=len(spooled_paths),
        spool_paths=tuple(spooled_paths),
    )


def drain_webhook_spool(
    *,
    url: str,
    spool_dir: str | Path,
    transport: WebhookTransport | None = None,
    timeout: float = 5.0,
    retries: int = 3,
) -> WebhookExportResult:
    """Retry outbound webhook delivery for previously spooled attestations."""

    _require_http_webhook_url(url)
    active_transport = transport or UrllibWebhookTransport()
    spool = Path(spool_dir)
    spool.mkdir(parents=True, exist_ok=True)
    delivered = 0
    remaining: list[str] = []
    files = sorted(path for path in spool.iterdir() if path.is_file())
    headers = {
        "content-type": "application/json",
        "user-agent": "velvet-assurance-export/1",
    }
    for path in files:
        body = path.read_bytes()
        ok = False
        for _attempt in range(max(1, retries)):
            status_code = active_transport.post(url, body, headers, timeout)
            if 200 <= status_code < 300:
                ok = True
                delivered += 1
                path.unlink()
                break
        if not ok:
            remaining.append(str(path))
    return WebhookExportResult(
        status="ok" if not remaining else "degraded",
        attempted=len(files),
        delivered=delivered,
        spooled=len(remaining),
        spool_paths=tuple(remaining),
    )


def _read_jsonl_objects(path: Path) -> tuple[JsonObject, ...]:
    objects: list[JsonObject] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            objects.append(payload)
    return tuple(objects)


def _attestation_period_key(attestation: Mapping[str, Any]) -> tuple[str, str, str] | None:
    payload = attestation.get("payload")
    if not isinstance(payload, Mapping):
        return None
    period = payload.get("period")
    if not isinstance(period, Mapping):
        return None
    deployment_id = payload.get("deployment_id")
    start = period.get("start")
    end = period.get("end")
    if not all(isinstance(value, str) and value for value in (deployment_id, start, end)):
        return None
    return str(deployment_id), str(start), str(end)


def _hash_bundle_files(destination: Path) -> JsonObject:
    hashes: JsonObject = {}
    for path in sorted(destination.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            relative = path.relative_to(destination).as_posix()
            hashes[relative] = {"sha256": _file_sha256(path), "size_bytes": path.stat().st_size}
    return hashes


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16]


def _require_http_webhook_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("webhook URL must use http or https and include a host")


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
