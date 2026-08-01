from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from velvet.binary_ledger import (
    BINARY_LEDGER_GENESIS_HASH,
    BinaryLedgerCorruption,
    encode_record,
    parse_frame_at,
)

SURROGATE_BLACKLIST_CATEGORIES: list[Any] = ["Cs"]

json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    st.text(max_size=64),
)
json_object = st.dictionaries(
    st.text(
        alphabet=st.characters(
            blacklist_categories=SURROGATE_BLACKLIST_CATEGORIES,
            blacklist_characters=("\x00",),
        ),
        min_size=1,
        max_size=32,
    ),
    json_scalar,
    max_size=16,
)


@given(st.binary(max_size=512))
@settings(max_examples=200, deadline=None)
def test_binary_ledger_parser_rejects_malformed_bytes_without_crashing(data: bytes) -> None:
    try:
        parse_frame_at(data, 0)
    except BinaryLedgerCorruption:
        pass


@given(
    payload=json_object,
    kind=st.sampled_from((1, 2)),
    sequence_number=st.integers(min_value=1, max_value=10_000),
)
@settings(max_examples=100, deadline=None)
def test_binary_ledger_round_trip_preserves_payload(
    payload: dict[str, object],
    kind: int,
    sequence_number: int,
) -> None:
    encoded = encode_record(
        payload,
        kind=kind,
        sequence_number=sequence_number,
        previous_frame_hash=BINARY_LEDGER_GENESIS_HASH,
        signer=None,
        tenant_id="tenant-property",
        key_id=None,
    )

    frame = parse_frame_at(encoded, 0)
    assert frame.payload == payload
    assert frame.kind == kind
    assert frame.sequence_number == sequence_number
    assert frame.end_offset == len(encoded)
