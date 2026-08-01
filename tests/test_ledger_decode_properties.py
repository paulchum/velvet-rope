from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from velvet.binary_ledger import (
    BINARY_LEDGER_GENESIS_HASH,
    BinaryLedgerCorruption,
    BinaryLedgerFrame,
    encode_record,
    parse_frame_at,
    verify_frame_signature,
)
from velvet.ledger import verify_velvet_ledger

RECORD_KIND_CANONICAL = 1
PAYLOAD_LEN_OFFSET = 18
PAYLOAD_LEN_END = 26
METADATA_LEN_OFFSET = 122
METADATA_LEN_END = 126

SURROGATE_BLACKLIST_CATEGORIES: list[Any] = ["Cs"]

json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.text(
        alphabet=st.characters(
            blacklist_categories=SURROGATE_BLACKLIST_CATEGORIES,
            blacklist_characters=("\x00",),
        ),
        max_size=48,
    ),
)
json_value = st.recursive(
    json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    blacklist_categories=SURROGATE_BLACKLIST_CATEGORIES,
                    blacklist_characters=("\x00",),
                ),
                min_size=1,
                max_size=16,
            ),
            children,
            max_size=6,
        ),
    ),
    max_leaves=32,
)


def record_payloads() -> st.SearchStrategy[list[dict[str, Any]]]:
    return st.lists(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    blacklist_categories=SURROGATE_BLACKLIST_CATEGORIES,
                    blacklist_characters=("\x00",),
                ),
                min_size=1,
                max_size=16,
            ),
            json_value,
            max_size=6,
        ),
        min_size=1,
        max_size=4,
    ).map(_with_required_fields)


def _with_required_fields(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        payload = dict(record)
        payload["contract"] = "velvet.ledger"
        payload["record_id"] = f"lr_property_{index}"
        payload["tenant_id"] = "tenant-property"
        payload["sequence_number"] = index
        payloads.append(payload)
    return payloads


def encode_ledger(records: list[dict[str, Any]]) -> bytes:
    previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    chunks: list[bytes] = []
    for record in records:
        frame_bytes = encode_record(
            record,
            kind=RECORD_KIND_CANONICAL,
            sequence_number=int(record["sequence_number"]),
            previous_frame_hash=previous_frame_hash,
            signer=None,
            tenant_id="tenant-property",
            key_id=None,
        )
        frame = parse_frame_at(frame_bytes, 0)
        previous_frame_hash = frame.frame_hash
        chunks.append(frame_bytes)
    return b"".join(chunks)


def verify_binary_bytes(data: bytes) -> list[BinaryLedgerFrame]:
    if not data:
        raise BinaryLedgerCorruption("binary ledger is empty", offset=0, code="binary_empty")
    frames: list[BinaryLedgerFrame] = []
    offset = 0
    expected_sequence = 1
    previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    while offset < len(data):
        frame = parse_frame_at(data, offset)
        if frame.sequence_number != expected_sequence:
            raise BinaryLedgerCorruption(
                "binary sequence number mismatch",
                offset=frame.offset,
                sequence_number=frame.sequence_number,
                code="binary_sequence_number_mismatch",
            )
        if frame.previous_frame_hash != previous_frame_hash:
            raise BinaryLedgerCorruption(
                "binary previous frame hash mismatch",
                offset=frame.offset,
                sequence_number=frame.sequence_number,
                code="binary_previous_hash_mismatch",
            )
        _verify_local_signature_envelope(frame)
        if not verify_frame_signature(frame):
            raise BinaryLedgerCorruption(
                "binary signature mismatch",
                offset=frame.offset,
                sequence_number=frame.sequence_number,
                code="binary_signature_mismatch",
            )
        frames.append(frame)
        expected_sequence += 1
        previous_frame_hash = frame.frame_hash
        offset = frame.end_offset
    return frames


def _verify_local_signature_envelope(frame: BinaryLedgerFrame) -> None:
    signature = frame.signature
    if signature is None:
        raise BinaryLedgerCorruption(
            "binary signature missing",
            offset=frame.offset,
            sequence_number=frame.sequence_number,
            code="binary_signature_missing",
        )
    if signature.get("schema_version") != "velvet.signature.v2":
        raise BinaryLedgerCorruption(
            "binary signature schema mismatch",
            offset=frame.offset,
            sequence_number=frame.sequence_number,
            code="binary_signature_schema_mismatch",
        )
    metadata = signature.get("metadata")
    if metadata != {
        "demo_only": True,
        "non_production": True,
        "verification_tier": "local-dev-shared-secret",
        "warning": "HMAC signatures use a shared secret and are local-dev only.",
    }:
        raise BinaryLedgerCorruption(
            "binary signature metadata mismatch",
            offset=frame.offset,
            sequence_number=frame.sequence_number,
            code="binary_signature_metadata_mismatch",
        )


def small_valid_ledger() -> bytes:
    return encode_ledger(
        [
            {
                "contract": "velvet.ledger",
                "record_id": "lr_small",
                "tenant_id": "tenant-property",
                "sequence_number": 1,
                "decision": "execute",
            }
        ]
    )


def offset_is_signature_timestamp_value(data: bytes, offset: int) -> bool:
    marker = b'"signed_at":'
    search_start = 0
    while True:
        marker_start = data.find(marker, search_start)
        if marker_start < 0:
            return False
        value_start = marker_start + len(marker)
        if value_start >= len(data) or data[value_start] != ord('"'):
            search_start = value_start
            continue
        value_start += 1
        value_end = data.find(b'"', value_start)
        if value_end < 0:
            return False
        if value_start <= offset < value_end:
            return True
        search_start = value_end + 1


def issue_codes(report: dict[str, Any]) -> set[str]:
    return {str(issue["code"]) for issue in report["issues"]}


@given(records=record_payloads())
@settings(max_examples=100, deadline=None)
def test_binary_ledger_roundtrip_preserves_generated_records(
    records: list[dict[str, Any]],
) -> None:
    encoded = encode_ledger(records)
    frames = verify_binary_bytes(encoded)
    assert [frame.payload for frame in frames] == records


@given(
    records=record_payloads(),
    mutation_index=st.integers(min_value=0),
    mutation_delta=st.integers(min_value=0, max_value=255),
)
@settings(max_examples=200, deadline=None)
def test_binary_ledger_mutations_fail_decode_or_verification(
    records: list[dict[str, Any]],
    mutation_index: int,
    mutation_delta: int,
) -> None:
    encoded = encode_ledger(records)
    index = mutation_index % len(encoded)
    assume(not offset_is_signature_timestamp_value(encoded, index))
    mutated = bytearray(encoded)
    mutated[index] ^= mutation_delta | 1
    with pytest.raises(BinaryLedgerCorruption):
        verify_binary_bytes(bytes(mutated))


def test_binary_ledger_truncations_fail_without_panic() -> None:
    encoded = small_valid_ledger()
    for offset in range(len(encoded)):
        with pytest.raises(BinaryLedgerCorruption):
            verify_binary_bytes(encoded[:offset])


def test_binary_ledger_length_prefix_lies_fail_without_panic() -> None:
    encoded = small_valid_ledger()

    declared_too_long = bytearray(encoded)
    declared_too_long[PAYLOAD_LEN_OFFSET:PAYLOAD_LEN_END] = (1024).to_bytes(8, "big")
    with pytest.raises(BinaryLedgerCorruption):
        verify_binary_bytes(bytes(declared_too_long))

    declared_zero = bytearray(encoded)
    declared_zero[PAYLOAD_LEN_OFFSET:PAYLOAD_LEN_END] = (0).to_bytes(8, "big")
    with pytest.raises(BinaryLedgerCorruption):
        verify_binary_bytes(bytes(declared_zero))

    declared_usize_max = bytearray(encoded)
    declared_usize_max[PAYLOAD_LEN_OFFSET:PAYLOAD_LEN_END] = ((2**64) - 1).to_bytes(8, "big")
    with pytest.raises(BinaryLedgerCorruption):
        verify_binary_bytes(bytes(declared_usize_max))

    metadata_zero = bytearray(encoded)
    metadata_zero[METADATA_LEN_OFFSET:METADATA_LEN_END] = (0).to_bytes(4, "big")
    with pytest.raises(BinaryLedgerCorruption):
        verify_binary_bytes(bytes(metadata_zero))


def test_ledger_verifier_reports_binary_decode_errors(tmp_path: Path) -> None:
    encoded = bytearray(small_valid_ledger())
    encoded[PAYLOAD_LEN_OFFSET:PAYLOAD_LEN_END] = (1024).to_bytes(8, "big")
    ledger_path = tmp_path / "corrupt.vledger"
    ledger_path.write_bytes(bytes(encoded))

    report = verify_velvet_ledger(ledger_path)
    assert report["status"] == "fail"
    assert "binary_payload_truncated" in issue_codes(report)
