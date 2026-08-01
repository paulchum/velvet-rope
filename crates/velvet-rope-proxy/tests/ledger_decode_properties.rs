use proptest::prelude::*;
use serde_json::{Map, Value, json};
use velvet_rope_proxy::{
    BinaryLedgerDecodeErrorKind, decode_binary_ledger_frames, encode_binary_ledger_record,
    parse_binary_ledger_frame, verify_binary_ledger_bytes,
};

const GENESIS_FRAME_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_KIND_CANONICAL: u8 = 1;
const PAYLOAD_LEN_OFFSET: usize = 18;
const PAYLOAD_LEN_END: usize = 26;
const METADATA_LEN_OFFSET: usize = 122;
const METADATA_LEN_END: usize = 126;

fn proptest_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256)
}

fn json_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-1_000_000i64..1_000_000).prop_map(|value| Value::Number(value.into())),
        "[a-zA-Z0-9 _./:-]{0,48}".prop_map(Value::String),
    ]
}

fn json_value() -> BoxedStrategy<Value> {
    json_leaf()
        .prop_recursive(3, 32, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::btree_map("[a-z][a-z0-9_]{0,12}", inner, 0..8)
                    .prop_map(|entries| Value::Object(entries.into_iter().collect::<Map<_, _>>())),
            ]
        })
        .boxed()
}

fn record_payloads() -> impl Strategy<Value = Vec<Value>> {
    proptest::collection::vec(
        proptest::collection::btree_map("[a-z][a-z0-9_]{0,12}", json_value(), 0..8),
        1..5,
    )
    .prop_map(|records| {
        records
            .into_iter()
            .enumerate()
            .map(|(index, fields)| {
                let mut object = fields.into_iter().collect::<Map<_, _>>();
                object.insert(
                    "contract".to_string(),
                    Value::String("velvet.ledger".to_string()),
                );
                object.insert(
                    "record_id".to_string(),
                    Value::String(format!("lr_property_{index}")),
                );
                object.insert(
                    "tenant_id".to_string(),
                    Value::String("tenant-property".to_string()),
                );
                object.insert(
                    "sequence_number".to_string(),
                    Value::Number(((index + 1) as u64).into()),
                );
                Value::Object(object)
            })
            .collect()
    })
}

fn encode_ledger(records: &[Value]) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    let mut previous_frame_hash = GENESIS_FRAME_HASH.to_string();
    for record in records {
        let sequence_number = record
            .get("sequence_number")
            .and_then(Value::as_u64)
            .expect("property records include sequence_number");
        let frame = encode_binary_ledger_record(
            record,
            RECORD_KIND_CANONICAL,
            sequence_number,
            &previous_frame_hash,
        )?;
        let decoded = decode_binary_ledger_frames(&frame).expect("fresh frame decodes");
        previous_frame_hash = decoded[0].frame_hash.clone();
        encoded.extend(frame);
    }
    Ok(encoded)
}

fn small_valid_ledger() -> Vec<u8> {
    encode_ledger(&[json!({
        "contract": "velvet.ledger",
        "record_id": "lr_small",
        "tenant_id": "tenant-property",
        "sequence_number": 1,
        "decision": "execute"
    })])
    .expect("small fixture encodes")
}

fn assert_decode_error(data: &[u8]) -> BinaryLedgerDecodeErrorKind {
    match verify_binary_ledger_bytes(data) {
        Ok(_) => panic!("corrupt binary ledger unexpectedly verified"),
        Err(error) => error.kind(),
    }
}

fn offset_is_signature_timestamp_value(data: &[u8], offset: usize) -> bool {
    let marker = br#""signed_at":"#;
    let mut search_start = 0usize;
    while let Some(relative_start) = data[search_start..]
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let value_start = search_start + relative_start + marker.len();
        if data.get(value_start) != Some(&b'"') {
            search_start = value_start;
            continue;
        }
        let value_start = value_start + 1;
        let Some(relative_end) = data[value_start..].iter().position(|byte| *byte == b'"') else {
            return false;
        };
        let value_end = value_start + relative_end;
        if (value_start..value_end).contains(&offset) {
            return true;
        }
        search_start = value_end + 1;
    }
    false
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn valid_records_roundtrip_through_binary_ledger(records in record_payloads()) {
        let encoded = encode_ledger(&records).expect("generated ledger encodes");
        let decoded = verify_binary_ledger_bytes(&encoded).expect("generated ledger verifies");
        let decoded_payloads = decoded
            .into_iter()
            .map(|frame| frame.payload)
            .collect::<Vec<_>>();
        prop_assert_eq!(decoded_payloads, records);
    }

    #[test]
    fn mutated_valid_ledgers_fail_decode_or_verification(
        records in record_payloads(),
        mutation_index in any::<usize>(),
        mutation_delta in any::<u8>(),
    ) {
        let encoded = encode_ledger(&records).expect("generated ledger encodes");
        prop_assume!(!encoded.is_empty());
        let mut mutated = encoded.clone();
        let index = mutation_index % mutated.len();
        prop_assume!(!offset_is_signature_timestamp_value(&encoded, index));
        mutated[index] ^= mutation_delta | 1;
        prop_assert_ne!(&mutated, &encoded);
        let kind = assert_decode_error(&mutated);
        prop_assert!(matches!(
            kind,
            BinaryLedgerDecodeErrorKind::Empty
                | BinaryLedgerDecodeErrorKind::Truncated
                | BinaryLedgerDecodeErrorKind::MagicMismatch
                | BinaryLedgerDecodeErrorKind::UnsupportedVersion
                | BinaryLedgerDecodeErrorKind::PayloadTooLarge
                | BinaryLedgerDecodeErrorKind::LengthOverflow
                | BinaryLedgerDecodeErrorKind::MetadataParse
                | BinaryLedgerDecodeErrorKind::PayloadParse
                | BinaryLedgerDecodeErrorKind::MetadataNotObject
                | BinaryLedgerDecodeErrorKind::PayloadHashMismatch
                | BinaryLedgerDecodeErrorKind::FrameHashMismatch
                | BinaryLedgerDecodeErrorKind::MetadataPayloadHashMismatch
                | BinaryLedgerDecodeErrorKind::HashFormat
                | BinaryLedgerDecodeErrorKind::SequenceMismatch
                | BinaryLedgerDecodeErrorKind::PreviousFrameHashMismatch
                | BinaryLedgerDecodeErrorKind::SignatureMismatch
        ));
    }
}

#[test]
fn truncation_at_every_prefix_offset_fails_without_panic() {
    let encoded = small_valid_ledger();
    for offset in 0..encoded.len() {
        assert_decode_error(&encoded[..offset]);
    }
}

#[test]
fn payload_length_prefix_lies_fail_without_panic() {
    let encoded = small_valid_ledger();

    let mut declared_too_long = encoded.clone();
    declared_too_long[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_END].copy_from_slice(&1024_u64.to_be_bytes());
    assert_decode_error(&declared_too_long);

    let mut declared_zero = encoded.clone();
    declared_zero[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_END].copy_from_slice(&0_u64.to_be_bytes());
    assert_decode_error(&declared_zero);

    let mut declared_usize_max = encoded.clone();
    declared_usize_max[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_END]
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert_decode_error(&declared_usize_max);
}

#[test]
fn metadata_length_prefix_lies_fail_without_panic() {
    let encoded = small_valid_ledger();

    let mut declared_too_long = encoded.clone();
    declared_too_long[METADATA_LEN_OFFSET..METADATA_LEN_END]
        .copy_from_slice(&1024_u32.to_be_bytes());
    assert_decode_error(&declared_too_long);

    let mut declared_zero = encoded.clone();
    declared_zero[METADATA_LEN_OFFSET..METADATA_LEN_END].copy_from_slice(&0_u32.to_be_bytes());
    assert_decode_error(&declared_zero);
}

#[test]
fn parse_entrypoint_rejects_length_overflow_offsets_without_panic() {
    let encoded = small_valid_ledger();
    let error = parse_binary_ledger_frame(&encoded, usize::MAX)
        .expect_err("offset beyond data must be rejected");
    assert_eq!(error.kind(), BinaryLedgerDecodeErrorKind::Truncated);
}
