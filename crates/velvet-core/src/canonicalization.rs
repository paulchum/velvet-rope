use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};

pub const VELVET_CANONICAL_JSON_V1: &str = "velvet.canonical_json.v1.sha256";
pub const VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD: &str =
    "velvet.canonical_json.v1.sha256.unsigned_payload";
const SAFE_JSON_INTEGER_MIN: i64 = -9_007_199_254_740_991;
const SAFE_JSON_INTEGER_MAX: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJson {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<CanonicalJson>),
    Object(Vec<(String, CanonicalJson)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizationError {
    message: String,
}

impl CanonicalizationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CanonicalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CanonicalizationError {}

pub fn load_canonical_json_v1(input: &[u8]) -> Result<CanonicalJson, CanonicalizationError> {
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(CanonicalizationError::new("UTF-8 BOM is not allowed"));
    }
    let source = std::str::from_utf8(input).map_err(|error| {
        CanonicalizationError::new(format!("input is not valid UTF-8: {error}"))
    })?;
    let mut deserializer = Deserializer::from_str(source);
    let value = CanonicalJson::deserialize(&mut deserializer)
        .map_err(|error| CanonicalizationError::new(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CanonicalizationError::new(error.to_string()))?;
    validate_canonical_json_v1(&value, "$", None)?;
    Ok(value)
}

pub fn canonical_json_v1_string(value: &CanonicalJson) -> Result<String, CanonicalizationError> {
    validate_canonical_json_v1(value, "$", None)?;
    Ok(serialize(value))
}

pub fn canonical_json_v1_bytes(value: &CanonicalJson) -> Result<Vec<u8>, CanonicalizationError> {
    Ok(canonical_json_v1_string(value)?.into_bytes())
}

pub fn canonical_json_v1_hash(value: &CanonicalJson) -> Result<String, CanonicalizationError> {
    let digest = Sha256::digest(canonical_json_v1_bytes(value)?);
    Ok(hex_digest(&digest))
}

pub fn proof_artifact_hash(
    artifact_type: &str,
    payload: &CanonicalJson,
) -> Result<String, CanonicalizationError> {
    let unsigned = proof_artifact_unsigned_payload(artifact_type, payload)?;
    validate_proof_artifact_v1(artifact_type, &unsigned)?;
    Ok(format!("sha256:{}", canonical_json_v1_hash(&unsigned)?))
}

pub fn proof_artifact_canonical_json(
    artifact_type: &str,
    payload: &CanonicalJson,
) -> Result<String, CanonicalizationError> {
    let unsigned = proof_artifact_unsigned_payload(artifact_type, payload)?;
    validate_proof_artifact_v1(artifact_type, &unsigned)?;
    canonical_json_v1_string(&unsigned)
}

pub fn proof_artifact_unsigned_payload(
    artifact_type: &str,
    payload: &CanonicalJson,
) -> Result<CanonicalJson, CanonicalizationError> {
    let object = match payload {
        CanonicalJson::Object(values) => values,
        _ => {
            return Err(CanonicalizationError::new(
                "proof artifact root must be a JSON object",
            ));
        }
    };
    match artifact_type {
        "evidence_manifest" => required_projection(
            object,
            &["schema_version", "tenant_id", "generated_at", "artifacts"],
        ),
        "warrant" if has_all_fields(object, WARRANT_FIELDS) => {
            required_projection(object, WARRANT_FIELDS)
        }
        "warrant" => drop_fields(object, &["warrant_hash", "signature"]),
        "ledger" => drop_fields(object, &["record_hash", "signature"]),
        "policy" => drop_fields(object, &["policy_hash", "signature"]),
        "tool_schema" => drop_fields(object, &["tool_schema_hash", "signature"]),
        "approval" => drop_fields(object, &["receipt_hash", "signature"]),
        "execution_permit" => drop_fields(object, &["permit_hash", "signature"]),
        "execution_receipt" => drop_fields(object, &["receipt_hash", "signature"]),
        "ledger_record" => drop_fields(object, &["record_hash", "artifact_hash", "signature"]),
        "proof_envelope" => drop_fields(
            object,
            &["proof_envelope_hash", "signature", "signature_record"],
        ),
        _ => Err(CanonicalizationError::new(format!(
            "unsupported proof artifact type: {artifact_type}"
        ))),
    }
}

fn validate_proof_artifact_v1(
    artifact_type: &str,
    payload: &CanonicalJson,
) -> Result<(), CanonicalizationError> {
    if !matches!(
        artifact_type,
        "warrant"
            | "ledger"
            | "policy"
            | "tool_schema"
            | "approval"
            | "evidence_manifest"
            | "execution_permit"
            | "execution_receipt"
            | "ledger_record"
            | "proof_envelope"
    ) {
        return Err(CanonicalizationError::new(format!(
            "unsupported proof artifact type: {artifact_type}"
        )));
    }
    if let CanonicalJson::Object(values) = payload
        && let Some(value) = object_get(values, "canonicalization")
    {
        match value {
            CanonicalJson::String(label)
                if label == VELVET_CANONICAL_JSON_V1
                    || label == VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD => {}
            _ => {
                return Err(CanonicalizationError::new(
                    "unsupported canonicalization label",
                ));
            }
        }
    }
    validate_canonical_json_v1(payload, "$", None)
}

fn validate_canonical_json_v1(
    value: &CanonicalJson,
    path: &str,
    field: Option<&str>,
) -> Result<(), CanonicalizationError> {
    match value {
        CanonicalJson::Null | CanonicalJson::Bool(_) => Ok(()),
        CanonicalJson::Int(value) => {
            if field.is_some_and(is_decimal_field) {
                return Err(CanonicalizationError::new(format!(
                    "{path}: decimal fields must be canonical strings"
                )));
            }
            if (SAFE_JSON_INTEGER_MIN..=SAFE_JSON_INTEGER_MAX).contains(value) {
                Ok(())
            } else {
                Err(CanonicalizationError::new(format!(
                    "{path}: integer is outside the JSON-safe range"
                )))
            }
        }
        CanonicalJson::String(value) => {
            if let Some(field) = field {
                if is_timestamp_field(field) {
                    validate_timestamp_string(value, path)?;
                }
                if is_decimal_field(field) {
                    validate_decimal_string(value, path)?;
                }
            }
            Ok(())
        }
        CanonicalJson::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                validate_canonical_json_v1(item, &format!("{path}[{index}]"), None)?;
            }
            Ok(())
        }
        CanonicalJson::Object(values) => {
            for (key, item) in values {
                validate_canonical_json_v1(item, &format!("{path}.{key}"), Some(key))?;
            }
            Ok(())
        }
    }
}

fn serialize(value: &CanonicalJson) -> String {
    match value {
        CanonicalJson::Null => "null".to_string(),
        CanonicalJson::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        CanonicalJson::Int(value) => value.to_string(),
        CanonicalJson::String(value) => quote_json_string(value),
        CanonicalJson::Array(values) => {
            let items = values.iter().map(serialize).collect::<Vec<_>>();
            format!("[{}]", items.join(","))
        }
        CanonicalJson::Object(values) => {
            let mut items = values.iter().collect::<Vec<_>>();
            items.sort_by_key(|(key, _)| utf16_sort_key(key));
            let serialized = items
                .into_iter()
                .map(|(key, value)| format!("{}:{}", quote_json_string(key), serialize(value)))
                .collect::<Vec<_>>();
            format!("{{{}}}", serialized.join(","))
        }
    }
}

fn quote_json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            character if u32::from(character) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn utf16_sort_key(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn validate_timestamp_string(value: &str, path: &str) -> Result<(), CanonicalizationError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() >= 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.last() == Some(&b'Z')
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 20
            || (bytes.get(19) == Some(&b'.')
                && (23..=29).contains(&bytes.len())
                && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)));
    if valid {
        Ok(())
    } else {
        Err(CanonicalizationError::new(format!(
            "{path}: timestamp must be RFC 3339 UTC with Z"
        )))
    }
}

fn validate_decimal_string(value: &str, path: &str) -> Result<(), CanonicalizationError> {
    if is_negative_zero_decimal(value) {
        return Err(CanonicalizationError::new(format!(
            "{path}: negative zero is not canonical"
        )));
    }
    let rest = value.strip_prefix('-').unwrap_or(value);
    let Some((whole, fraction)) = rest.split_once('.').or(Some((rest, ""))) else {
        unreachable!("split_once fallback always returns Some");
    };
    let whole_valid = whole == "0"
        || (!whole.is_empty()
            && !whole.starts_with('0')
            && whole.as_bytes().iter().all(u8::is_ascii_digit));
    let fraction_valid = fraction.is_empty() || fraction.as_bytes().iter().all(u8::is_ascii_digit);
    if whole_valid
        && fraction_valid
        && !rest.contains('e')
        && !rest.contains('E')
        && !value.starts_with('+')
        && !value.ends_with('.')
    {
        Ok(())
    } else {
        Err(CanonicalizationError::new(format!(
            "{path}: decimal string is not canonical"
        )))
    }
}

fn is_negative_zero_decimal(value: &str) -> bool {
    value == "-0"
        || value
            .strip_prefix("-0.")
            .is_some_and(|fraction| fraction.bytes().all(|byte| byte == b'0'))
}

fn is_timestamp_field(field: &str) -> bool {
    matches!(
        field,
        "timestamp"
            | "issued_at"
            | "created_at"
            | "recorded_at"
            | "generated_at"
            | "decided_at"
            | "expires_at"
            | "signed_at"
            | "proposal_timestamp"
            | "decision_timestamp"
            | "execution_timestamp"
    ) || field.ends_with("_at")
        || field.ends_with("_timestamp")
}

fn is_decimal_field(field: &str) -> bool {
    matches!(
        field,
        "admission_price"
            | "budget_pressure"
            | "clearance_score"
            | "confidence"
            | "cost_penalty"
            | "entry_price"
            | "estimated_cost"
            | "estimated_risk"
            | "expected_upside"
            | "final_lambda"
            | "hard_ceiling_usd"
            | "liability_multiplier"
            | "limit_usd"
            | "novelty"
            | "proposal_score"
            | "risk_penalty"
            | "scarcity_pressure"
            | "soft_ceiling_fraction"
            | "spend_amount"
    ) || [
        "_amount",
        "_ceiling",
        "_cost",
        "_fraction",
        "_lambda",
        "_limit",
        "_penalty",
        "_price",
        "_risk",
        "_score",
        "_usd",
        "_upside",
    ]
    .iter()
    .any(|suffix| field.ends_with(suffix))
}

fn required_projection(
    object: &[(String, CanonicalJson)],
    fields: &[&str],
) -> Result<CanonicalJson, CanonicalizationError> {
    let mut output = Vec::with_capacity(fields.len());
    for field in fields {
        let Some(value) = object_get(object, field) else {
            return Err(CanonicalizationError::new(format!(
                "missing required unsigned payload field: {field}"
            )));
        };
        output.push(((*field).to_string(), value.clone()));
    }
    Ok(CanonicalJson::Object(output))
}

fn drop_fields(
    object: &[(String, CanonicalJson)],
    fields: &[&str],
) -> Result<CanonicalJson, CanonicalizationError> {
    Ok(CanonicalJson::Object(
        object
            .iter()
            .filter(|(key, _)| !fields.contains(&key.as_str()))
            .cloned()
            .collect(),
    ))
}

fn has_all_fields(object: &[(String, CanonicalJson)], fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| object_get(object, field).is_some())
}

fn object_get<'a>(object: &'a [(String, CanonicalJson)], key: &str) -> Option<&'a CanonicalJson> {
    object
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

impl<'de> Deserialize<'de> for CanonicalJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(CanonicalJsonVisitor)
    }
}

struct CanonicalJsonVisitor;

impl<'de> Visitor<'de> for CanonicalJsonVisitor {
    type Value = CanonicalJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict Velvet canonical JSON v1")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalJson::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if (SAFE_JSON_INTEGER_MIN..=SAFE_JSON_INTEGER_MAX).contains(&value) {
            Ok(CanonicalJson::Int(value))
        } else {
            Err(E::custom("integer is outside the JSON-safe range"))
        }
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value <= SAFE_JSON_INTEGER_MAX as u64 {
            Ok(CanonicalJson::Int(value as i64))
        } else {
            Err(E::custom("integer is outside the JSON-safe range"))
        }
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("non-integer JSON numbers are not supported"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(CanonicalJson::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonicalJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalJson::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalJson::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CanonicalJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(CanonicalJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut values = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            let value = map.next_value::<CanonicalJson>()?;
            values.push((key, value));
        }
        Ok(CanonicalJson::Object(values))
    }
}

const WARRANT_FIELDS: &[&str] = &[
    "warrant_id",
    "issued_at",
    "tenant_id",
    "environment",
    "request_hash",
    "policy_hash",
    "tool_schema_hash",
    "tool_name",
    "decision",
    "reason",
    "reason_codes",
    "obligations",
    "approval_required",
    "expires_at",
    "issuer",
];
