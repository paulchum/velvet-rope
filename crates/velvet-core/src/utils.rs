use serde_json::Value;

pub fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

pub fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
    }
}

#[cfg_attr(not(feature = "legacy-heuristic-routing"), allow(dead_code))]
pub fn state_truthy(state: &Value, key: &str) -> bool {
    state.get(key).is_some_and(truthy)
}

pub fn number_value(value: Option<&Value>, default: f64) -> f64 {
    match value {
        Some(Value::Bool(value)) => f64::from(*value),
        Some(Value::Number(number)) => number.as_f64().unwrap_or(default),
        Some(Value::String(value)) => value.parse::<f64>().unwrap_or(default),
        _ => default,
    }
}

pub fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(ToString::to_string)
}

pub fn string_value<'a>(state: &'a Value, key: &str) -> Option<&'a str> {
    state.get(key).and_then(Value::as_str)
}

pub fn stable_hash_bytes(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn stable_hash_json<T: serde::Serialize>(value: &T) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    stable_hash_bytes(serialized.as_bytes())
}
