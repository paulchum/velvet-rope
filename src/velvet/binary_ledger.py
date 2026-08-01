"""Binary tamper-evident storage primitives for Velvet audit ledgers."""

from __future__ import annotations

import json
import os
import struct
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from velvet.serialization import canonical_dumps, canonical_hash_sha256
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_TENANT_ID,
    SigningProvider,
    default_demo_signer,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)

JsonObject = dict[str, Any]

VELVET_LEDGER_MAGIC = b"VLVTLEDG"
VELVET_LEDGER_FORMAT_VERSION = 1
VELVET_LEDGER_RECORD_MAX_BYTES = 1_048_576

VELVET_LEDGER_PAYLOAD_HASH_DOMAIN = b"Velvet:Ledger:PayloadHash:v1"
VELVET_LEDGER_RECORD_HASH_DOMAIN = b"Velvet:Ledger:RecordHash:v1"
VELVET_LEDGER_RECOVERY_TAIL_DOMAIN = b"Velvet:Ledger:RecoveredTail:v1"

PURPOSE_LEDGER_RECORD_BINARY = "velvet.ledger.record.binary.v1"
PURPOSE_LEDGER_CHECKPOINT = "velvet.ledger.checkpoint.v1"

BINARY_LEDGER_FORMAT = "velvet.binary_ledger.v1"
BINARY_LEDGER_CHECKPOINT_SCHEMA_VERSION = "velvet.ledger_checkpoint.v1"
BINARY_LEDGER_GENESIS_HASH = f"sha256:{'0' * 64}"

RECORD_KIND_CANONICAL = 1
RECORD_KIND_OAP = 2

_FIXED_HEADER = struct.Struct(">8sBBQQ32s32s32sI")
_HEADER_WITH_METADATA = struct.Struct(">8sBBQQ32s32s32sI")


class BinaryLedgerError(ValueError):
    """Base error for binary ledger parse and verification failures."""


class BinaryLedgerCorruption(BinaryLedgerError):
    """Raised when strict binary ledger parsing detects corruption."""

    def __init__(
        self,
        message: str,
        *,
        offset: int,
        sequence_number: int | None = None,
        code: str = "binary_ledger_corruption",
    ) -> None:
        super().__init__(message)
        self.offset = offset
        self.sequence_number = sequence_number
        self.code = code


@dataclass(frozen=True)
class BinaryLedgerFrame:
    """Decoded binary ledger frame and its Velvet semantic payload."""

    offset: int
    end_offset: int
    version: int
    kind: int
    sequence_number: int
    payload_length: int
    metadata_length: int
    previous_frame_hash: str
    payload_hash: str
    frame_hash: str
    stored_frame_hash: str
    metadata: JsonObject
    payload: JsonObject

    @property
    def signature(self) -> Mapping[str, Any] | None:
        value = self.metadata.get("signature")
        return value if isinstance(value, Mapping) else None


@dataclass(frozen=True)
class BinaryLedgerTailState:
    record_count: int
    next_sequence_number: int
    previous_semantic_record_hash: str
    previous_frame_hash: str
    head_frame_hash: str
    valid_length: int
    frames: tuple[BinaryLedgerFrame, ...]


@dataclass(frozen=True)
class RecoveredTail:
    path: Path
    quarantine_path: Path
    start_offset: int
    byte_count: int
    recovery_hash: str


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_dumps(payload).encode("utf-8")


def payload_hash_for_bytes(payload_bytes: bytes) -> str:
    return _sha256_prefixed(VELVET_LEDGER_PAYLOAD_HASH_DOMAIN + b"\0" + payload_bytes)


def frame_hash_for_parts(
    *,
    version: int,
    kind: int,
    sequence_number: int,
    payload_length: int,
    previous_frame_hash: str,
    payload_hash: str,
    metadata_bytes: bytes,
) -> str:
    previous_digest = _hash_digest(previous_frame_hash, "previous_frame_hash")
    payload_digest = _hash_digest(payload_hash, "payload_hash")
    message = b"".join(
        (
            VELVET_LEDGER_RECORD_HASH_DOMAIN,
            b"\0",
            struct.pack(
                ">BBQQI",
                version,
                kind,
                sequence_number,
                payload_length,
                len(metadata_bytes),
            ),
            previous_digest,
            payload_digest,
            metadata_bytes,
        )
    )
    return _sha256_prefixed(message)


def encode_record(
    payload: Mapping[str, Any],
    *,
    kind: int,
    sequence_number: int,
    previous_frame_hash: str,
    signer: SigningProvider | None,
    tenant_id: str | None,
    key_id: str | None,
) -> bytes:
    payload_bytes = canonical_payload_bytes(payload)
    if len(payload_bytes) > VELVET_LEDGER_RECORD_MAX_BYTES:
        raise ValueError(
            f"ledger record payload is {len(payload_bytes)} bytes; "
            f"max is {VELVET_LEDGER_RECORD_MAX_BYTES}"
        )
    payload_hash = payload_hash_for_bytes(payload_bytes)
    active_signer = signer or default_demo_signer()
    resolved_tenant_id = tenant_id or _payload_tenant_id(payload) or LOCAL_DEMO_TENANT_ID
    resolved_key_id = key_id or signer_default_key_id(active_signer, LOCAL_DEMO_KEY_ID)
    unsigned_metadata: JsonObject = {
        "format": BINARY_LEDGER_FORMAT,
        "kind": kind,
        "payload_hash": payload_hash,
        "previous_frame_hash": previous_frame_hash,
        "sequence_number": sequence_number,
    }
    unsigned_metadata_bytes = canonical_payload_bytes(unsigned_metadata)
    frame_hash = frame_hash_for_parts(
        version=VELVET_LEDGER_FORMAT_VERSION,
        kind=kind,
        sequence_number=sequence_number,
        payload_length=len(payload_bytes),
        previous_frame_hash=previous_frame_hash,
        payload_hash=payload_hash,
        metadata_bytes=unsigned_metadata_bytes,
    )
    metadata = dict(unsigned_metadata)
    metadata["frame_hash"] = frame_hash
    metadata["signature"] = sign_payload_hash(
        frame_hash,
        purpose=PURPOSE_LEDGER_RECORD_BINARY,
        tenant_id=resolved_tenant_id,
        key_id=resolved_key_id,
        signer=active_signer,
    )
    metadata_bytes = canonical_payload_bytes(metadata)
    final_frame_hash = frame_hash_for_parts(
        version=VELVET_LEDGER_FORMAT_VERSION,
        kind=kind,
        sequence_number=sequence_number,
        payload_length=len(payload_bytes),
        previous_frame_hash=previous_frame_hash,
        payload_hash=payload_hash,
        metadata_bytes=_unsigned_metadata_bytes(metadata),
    )
    if final_frame_hash != frame_hash:
        raise AssertionError("binary ledger frame hash changed after attaching signature")
    return b"".join(
        (
            _HEADER_WITH_METADATA.pack(
                VELVET_LEDGER_MAGIC,
                VELVET_LEDGER_FORMAT_VERSION,
                kind,
                sequence_number,
                len(payload_bytes),
                _hash_digest(previous_frame_hash, "previous_frame_hash"),
                _hash_digest(payload_hash, "payload_hash"),
                _hash_digest(frame_hash, "frame_hash"),
                len(metadata_bytes),
            ),
            metadata_bytes,
            payload_bytes,
        )
    )


def append_record(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    kind: int,
    sequence_number: int,
    previous_frame_hash: str,
    signer: SigningProvider | None = None,
    tenant_id: str | None = None,
    key_id: str | None = None,
    fsync: bool = False,
) -> BinaryLedgerFrame:
    destination = Path(path)
    recover_trailing_tail(destination)
    encoded = encode_record(
        payload,
        kind=kind,
        sequence_number=sequence_number,
        previous_frame_hash=previous_frame_hash,
        signer=signer,
        tenant_id=tenant_id,
        key_id=key_id,
    )
    if destination.parent:
        destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("ab") as handle:
        offset = handle.tell()
        handle.write(encoded)
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())
    return parse_frame_at(destination.read_bytes(), offset)


def iter_frames(path: str | Path, *, verify_hashes: bool = True) -> Iterable[BinaryLedgerFrame]:
    data = Path(path).read_bytes()
    offset = 0
    while offset < len(data):
        frame = parse_frame_at(data, offset, verify_hashes=verify_hashes)
        yield frame
        offset = frame.end_offset


def read_records(path: str | Path) -> Iterable[JsonObject]:
    for frame in iter_frames(path):
        yield frame.payload


def scan_tail_state(path: str | Path) -> BinaryLedgerTailState:
    frames = tuple(iter_frames(path)) if Path(path).exists() else ()
    if not frames:
        return BinaryLedgerTailState(
            record_count=0,
            next_sequence_number=1,
            previous_semantic_record_hash="sha256:" + ("0" * 64),
            previous_frame_hash=BINARY_LEDGER_GENESIS_HASH,
            head_frame_hash=BINARY_LEDGER_GENESIS_HASH,
            valid_length=0,
            frames=(),
        )
    last = frames[-1]
    semantic_hash = last.payload.get("record_hash")
    return BinaryLedgerTailState(
        record_count=len(frames),
        next_sequence_number=int(last.payload.get("sequence_number", last.sequence_number)) + 1,
        previous_semantic_record_hash=str(semantic_hash or "sha256:" + ("0" * 64)),
        previous_frame_hash=last.frame_hash,
        head_frame_hash=last.frame_hash,
        valid_length=last.end_offset,
        frames=frames,
    )


def recover_trailing_tail(path: str | Path) -> RecoveredTail | None:
    destination = Path(path)
    if not destination.exists():
        return None
    data = destination.read_bytes()
    if not data:
        return None
    offset = 0
    try:
        while offset < len(data):
            frame = parse_frame_at(data, offset)
            offset = frame.end_offset
    except BinaryLedgerCorruption:
        if offset == 0:
            raise
        tail = data[offset:]
        if not tail:
            return None
        recovery_hash = _sha256_prefixed(
            VELVET_LEDGER_RECOVERY_TAIL_DOMAIN
            + b"\0"
            + str(offset).encode("ascii")
            + b"\0"
            + tail
        )
        quarantine_path = destination.with_name(
            f"{destination.name}.recovered-tail.{uuid.uuid4().hex}.bin"
        )
        quarantine_path.write_bytes(tail)
        destination.write_bytes(data[:offset])
        return RecoveredTail(
            path=destination,
            quarantine_path=quarantine_path,
            start_offset=offset,
            byte_count=len(tail),
            recovery_hash=recovery_hash,
        )
    return None


def parse_frame_at(
    data: bytes,
    offset: int,
    *,
    verify_hashes: bool = True,
) -> BinaryLedgerFrame:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if len(data) - offset < _FIXED_HEADER.size:
        raise BinaryLedgerCorruption(
            "ledger record is truncated before the fixed header",
            offset=offset,
            code="binary_record_truncated",
        )
    (
        magic,
        version,
        kind,
        sequence_number,
        payload_length,
        previous_frame_hash_bytes,
        payload_hash_bytes,
        frame_hash_bytes,
        metadata_length,
    ) = _FIXED_HEADER.unpack_from(data, offset)
    if magic != VELVET_LEDGER_MAGIC:
        raise BinaryLedgerCorruption(
            "ledger record magic mismatch",
            offset=offset,
            sequence_number=sequence_number,
            code="binary_magic_mismatch",
        )
    if version != VELVET_LEDGER_FORMAT_VERSION:
        raise BinaryLedgerCorruption(
            "unsupported binary ledger format version",
            offset=offset,
            sequence_number=sequence_number,
            code="binary_version_mismatch",
        )
    if payload_length > VELVET_LEDGER_RECORD_MAX_BYTES:
        raise BinaryLedgerCorruption(
            "ledger record payload exceeds max size",
            offset=offset,
            sequence_number=sequence_number,
            code="binary_payload_too_large",
        )
    metadata_start = offset + _FIXED_HEADER.size
    payload_start = metadata_start + int(metadata_length)
    end_offset = payload_start + int(payload_length)
    if payload_start > len(data):
        raise BinaryLedgerCorruption(
            "ledger record is truncated before metadata",
            offset=offset,
            sequence_number=sequence_number,
            code="binary_metadata_truncated",
        )
    if end_offset > len(data):
        raise BinaryLedgerCorruption(
            "ledger record is truncated before payload",
            offset=offset,
            sequence_number=sequence_number,
            code="binary_payload_truncated",
        )
    metadata_bytes = data[metadata_start:payload_start]
    payload_bytes = data[payload_start:end_offset]
    metadata = _decode_object(
        metadata_bytes,
        offset=metadata_start,
        code="binary_metadata_parse_error",
    )
    payload = _decode_object(payload_bytes, offset=payload_start, code="binary_payload_parse_error")
    stored_previous_hash = _format_hash(previous_frame_hash_bytes)
    stored_payload_hash = _format_hash(payload_hash_bytes)
    stored_frame_hash = _format_hash(frame_hash_bytes)
    computed_payload_hash = payload_hash_for_bytes(payload_bytes)
    computed_frame_hash = frame_hash_for_parts(
        version=version,
        kind=kind,
        sequence_number=sequence_number,
        payload_length=payload_length,
        previous_frame_hash=stored_previous_hash,
        payload_hash=computed_payload_hash,
        metadata_bytes=_unsigned_metadata_bytes(metadata),
    )
    if verify_hashes:
        if stored_payload_hash != computed_payload_hash:
            raise BinaryLedgerCorruption(
                "ledger payload hash mismatch",
                offset=offset,
                sequence_number=sequence_number,
                code="binary_payload_hash_mismatch",
            )
        if (
            stored_frame_hash != computed_frame_hash
            or metadata.get("frame_hash") != computed_frame_hash
        ):
            raise BinaryLedgerCorruption(
                "ledger frame hash mismatch",
                offset=offset,
                sequence_number=sequence_number,
                code="binary_frame_hash_mismatch",
            )
        if metadata.get("payload_hash") != computed_payload_hash:
            raise BinaryLedgerCorruption(
                "ledger metadata payload hash mismatch",
                offset=offset,
                sequence_number=sequence_number,
                code="binary_metadata_payload_hash_mismatch",
            )
        if metadata.get("previous_frame_hash") != stored_previous_hash:
            raise BinaryLedgerCorruption(
                "ledger metadata previous frame hash mismatch",
                offset=offset,
                sequence_number=sequence_number,
                code="binary_metadata_previous_hash_mismatch",
            )
        if int(metadata.get("sequence_number", -1)) != sequence_number:
            raise BinaryLedgerCorruption(
                "ledger metadata sequence number mismatch",
                offset=offset,
                sequence_number=sequence_number,
                code="binary_metadata_sequence_mismatch",
            )
    return BinaryLedgerFrame(
        offset=offset,
        end_offset=end_offset,
        version=version,
        kind=kind,
        sequence_number=sequence_number,
        payload_length=int(payload_length),
        metadata_length=int(metadata_length),
        previous_frame_hash=stored_previous_hash,
        payload_hash=computed_payload_hash,
        frame_hash=computed_frame_hash,
        stored_frame_hash=stored_frame_hash,
        metadata=metadata,
        payload=payload,
    )


def verify_frame_signature(
    frame: BinaryLedgerFrame,
    *,
    signer: SigningProvider | None = None,
    signing_key: str | None = None,
    public_key: str | bytes | object | None = None,
) -> bool:
    signature = frame.signature
    if signature is None:
        return False
    active_signer = signer or (
        default_demo_signer(signing_key) if signing_key is not None else None
    )
    return verify_signature_record(
        signature,
        frame.frame_hash,
        purpose=PURPOSE_LEDGER_RECORD_BINARY,
        signer=active_signer,
        public_key=public_key,
    )


def build_checkpoint(
    ledger_path: str | Path,
    *,
    storage_uri: str | None = None,
    signer: SigningProvider | None = None,
    signing_key: str | None = None,
    signing_key_id: str | None = None,
) -> JsonObject:
    path = Path(ledger_path)
    state = scan_tail_state(path)
    if not state.frames:
        raise ValueError("cannot build a checkpoint for a ledger with no records")
    first = state.frames[0].payload
    last = state.frames[-1].payload
    active_signer = signer or (
        default_demo_signer(signing_key) if signing_key is not None else None
    )
    if active_signer is None:
        active_signer = default_demo_signer()
    key_id = signing_key_id or signer_default_key_id(active_signer)
    checkpoint: JsonObject = {
        "schema_version": BINARY_LEDGER_CHECKPOINT_SCHEMA_VERSION,
        "ledger_format": BINARY_LEDGER_FORMAT,
        "checkpoint_id": f"chk_{state.head_frame_hash.removeprefix('sha256:')[:32]}",
        "ledger_path": str(path),
        "record_count": state.record_count,
        "next_sequence": state.next_sequence_number,
        "first_sequence": int(first.get("sequence_number", state.frames[0].sequence_number)),
        "last_sequence": int(last.get("sequence_number", state.frames[-1].sequence_number)),
        "first_record_hash": str(first.get("record_hash")),
        "last_record_hash": str(last.get("record_hash")),
        "head_frame_hash": state.head_frame_hash,
        "valid_length": state.valid_length,
        "generated_at": _now_iso(),
    }
    if storage_uri is not None:
        checkpoint["storage_uri"] = storage_uri
    checkpoint_hash = checkpoint_hash_for_payload(checkpoint)
    checkpoint["checkpoint_hash"] = checkpoint_hash
    checkpoint["signature"] = sign_payload_hash(
        checkpoint_hash,
        purpose=PURPOSE_LEDGER_CHECKPOINT,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=key_id,
        signer=active_signer,
    )
    return checkpoint


def checkpoint_hash_for_payload(checkpoint: Mapping[str, Any]) -> str:
    unsigned = {
        str(key): value
        for key, value in checkpoint.items()
        if key not in {"signature", "checkpoint_hash"}
    }
    return canonical_hash_sha256(unsigned)


def verify_checkpoint_signature(
    checkpoint: Mapping[str, Any],
    *,
    signer: SigningProvider | None = None,
    signing_key: str | None = None,
    public_key: str | bytes | object | None = None,
) -> bool:
    signature = checkpoint.get("signature")
    if not isinstance(signature, Mapping):
        return False
    active_signer = signer or (
        default_demo_signer(signing_key) if signing_key is not None else None
    )
    return verify_signature_record(
        signature,
        checkpoint_hash_for_payload(checkpoint),
        purpose=PURPOSE_LEDGER_CHECKPOINT,
        signer=active_signer,
        public_key=public_key,
    )


def _unsigned_metadata_bytes(metadata: Mapping[str, Any]) -> bytes:
    unsigned = {
        str(key): value
        for key, value in metadata.items()
        if key not in {"signature", "frame_hash"}
    }
    return canonical_payload_bytes(unsigned)


def _decode_object(data: bytes, *, offset: int, code: str) -> JsonObject:
    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BinaryLedgerCorruption(str(error), offset=offset, code=code) from error
    if not isinstance(decoded, dict):
        raise BinaryLedgerCorruption(
            "binary ledger frame section is not a JSON object",
            offset=offset,
            code=code,
        )
    return cast(JsonObject, decoded)


def _payload_tenant_id(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("tenant_id")
    return value if isinstance(value, str) and value else None


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{sha256(data).hexdigest()}"


def _format_hash(value: bytes) -> str:
    return f"sha256:{value.hex()}"


def _hash_digest(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{field} must be a sha256: hash")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64:
        raise ValueError(f"{field} must be a sha256: hash")
    try:
        return bytes.fromhex(digest)
    except ValueError as error:
        raise ValueError(f"{field} must be a sha256: hash") from error


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
