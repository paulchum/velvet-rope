"""External anchoring surfaces for signed Velvet vault tree heads."""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

from velvet.serialization import JsonObject, canonical_dumps, canonical_hash_sha256
from velvet.vault.sth import signed_tree_head_hash

ANCHOR_RECEIPT_SCHEMA_VERSION = "velvet.vault.anchor_receipt.v1"
ANCHOR_SPOOL_JOB_SCHEMA_VERSION = "velvet.vault.anchor_spool_job.v1"


@dataclass(frozen=True)
class AnchorResult:
    schema_version: str
    anchor_type: str
    status: str
    sth_hash: str
    anchored_at: str | None = None
    location: str | None = None
    error: str | None = None
    spool_path: str | None = None

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "schema_version": self.schema_version,
            "anchor_type": self.anchor_type,
            "status": self.status,
            "sth_hash": self.sth_hash,
        }
        if self.anchored_at is not None:
            payload["anchored_at"] = self.anchored_at
        if self.location is not None:
            payload["location"] = self.location
        if self.error is not None:
            payload["error"] = self.error
        if self.spool_path is not None:
            payload["spool_path"] = self.spool_path
        return payload


@runtime_checkable
class Anchor(Protocol):
    anchor_type: str

    def publish(self, sth: Mapping[str, Any]) -> AnchorResult:
        """Publish an STH outside the operator's integrity boundary."""


class FileAnchor:
    """Write-once filesystem anchor for object-lock bucket mounts."""

    anchor_type = "file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def publish(self, sth: Mapping[str, Any]) -> AnchorResult:
        sth_hash = signed_tree_head_hash(sth)
        payload = _canonical_json_bytes(sth)
        destination = self._destination(sth_hash)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as handle:
                handle.write(payload)
        except FileExistsError:
            if destination.read_bytes() == payload:
                return _success(self.anchor_type, sth_hash, str(destination))
            return _failure(
                self.anchor_type,
                sth_hash,
                f"anchor path already exists with different content: {destination}",
                location=str(destination),
            )
        return _success(self.anchor_type, sth_hash, str(destination))

    def _destination(self, sth_hash: str) -> Path:
        if self.path.suffix:
            return self.path
        return self.path / f"{sth_hash.removeprefix('sha256:')}.sth.json"


class StdoutAnchor:
    """Print canonical STH JSON for manual air-gapped export."""

    anchor_type = "stdout"

    def publish(self, sth: Mapping[str, Any]) -> AnchorResult:
        sth_hash = signed_tree_head_hash(sth)
        print(canonical_dumps(sth), file=sys.stdout, flush=True)
        return _success(self.anchor_type, sth_hash, "stdout")


class WebhookTransport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> int:
        """POST bytes and return HTTP status."""


class UrllibWebhookTransport:
    def post(self, url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> int:
        _require_http_webhook_url(url)
        request = urllib.request.Request(  # noqa: S310 - operator-supplied webhook endpoint.
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


class WebhookAnchor:
    """POST STHs to an external endpoint and spool failures for retry."""

    anchor_type = "webhook"

    def __init__(
        self,
        *,
        url: str,
        spool_dir: str | Path,
        transport: WebhookTransport | None = None,
        retries: int = 3,
        timeout: float = 5.0,
        retry_sleep_seconds: float = 0.0,
    ) -> None:
        _require_http_webhook_url(url)
        self.url = url
        self.spool_dir = Path(spool_dir)
        self.transport = transport or UrllibWebhookTransport()
        self.retries = retries
        self.timeout = timeout
        self.retry_sleep_seconds = retry_sleep_seconds

    def publish(self, sth: Mapping[str, Any]) -> AnchorResult:
        sth_hash = signed_tree_head_hash(sth)
        body = _canonical_json_bytes(sth)
        headers = {
            "Content-Type": "application/json",
            "X-Velvet-STH-Hash": sth_hash,
        }
        last_error = "not attempted"
        for attempt in range(1, self.retries + 1):
            try:
                status = self.transport.post(self.url, body, headers, self.timeout)
            except Exception as error:  # noqa: BLE001 - network failure degrades, then spools.
                last_error = str(error)
            else:
                if 200 <= status < 300:
                    return _success(self.anchor_type, sth_hash, self.url)
                last_error = f"HTTP {status}"
            if attempt < self.retries and self.retry_sleep_seconds > 0:
                time.sleep(self.retry_sleep_seconds)
        spool_path = self._spool(sth, last_error)
        return _failure(
            self.anchor_type,
            sth_hash,
            last_error,
            location=self.url,
            spool_path=str(spool_path),
        )

    def _spool(self, sth: Mapping[str, Any], error: str) -> Path:
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        sth_hash = signed_tree_head_hash(sth)
        job: JsonObject = {
            "schema_version": ANCHOR_SPOOL_JOB_SCHEMA_VERSION,
            "job_id": f"anch_{uuid.uuid4().hex}",
            "url": self.url,
            "sth_hash": sth_hash,
            "spooled_at": _now_iso(),
            "last_error": error,
            "sth": dict(sth),
        }
        path = self.spool_dir / f"{sth_hash.removeprefix('sha256:')}.{job['job_id']}.json"
        path.write_text(canonical_dumps(job) + "\n", encoding="utf-8")
        return path


def write_anchor_receipt(path: str | Path, result: AnchorResult) -> JsonObject:
    payload = result.to_dict()
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_dumps(payload) + "\n", encoding="utf-8")
    return payload


def load_anchor_receipts(path: str | Path) -> tuple[JsonObject, ...]:
    source = Path(path)
    if not source.exists():
        return ()
    if source.is_file():
        return (_load_receipt_file(source),)
    return tuple(_load_receipt_file(item) for item in sorted(source.glob("*.json")))


def anchored_success_for_sth(
    sth_hash: str,
    receipts: Mapping[str, Any] | list[Any] | tuple[Any, ...],
) -> bool:
    if isinstance(receipts, Mapping):
        candidates: tuple[Mapping[str, Any], ...] = (receipts,)
    else:
        candidates = tuple(
            cast(Mapping[str, Any], item) for item in receipts if isinstance(item, Mapping)
        )
    return any(
        item.get("schema_version") == ANCHOR_RECEIPT_SCHEMA_VERSION
        and item.get("status") == "ok"
        and item.get("sth_hash") == sth_hash
        for item in candidates
    )


def _load_receipt_file(path: Path) -> JsonObject:
    return cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (canonical_dumps(payload) + "\n").encode("utf-8")


def _require_http_webhook_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("webhook URL must use http or https and include a host")


def _success(anchor_type: str, sth_hash: str, location: str) -> AnchorResult:
    return AnchorResult(
        schema_version=ANCHOR_RECEIPT_SCHEMA_VERSION,
        anchor_type=anchor_type,
        status="ok",
        sth_hash=sth_hash,
        anchored_at=_now_iso(),
        location=location,
    )


def _failure(
    anchor_type: str,
    sth_hash: str,
    error: str,
    *,
    location: str | None = None,
    spool_path: str | None = None,
) -> AnchorResult:
    return AnchorResult(
        schema_version=ANCHOR_RECEIPT_SCHEMA_VERSION,
        anchor_type=anchor_type,
        status="degraded",
        sth_hash=sth_hash,
        location=location,
        error=error,
        spool_path=spool_path,
    )


def anchor_receipt_hash(receipt: Mapping[str, Any]) -> str:
    return canonical_hash_sha256(receipt)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
