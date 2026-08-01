use serde::Serialize;

pub mod cost_ceiling;
pub mod escalation_gate;
pub mod llm_atom;
pub mod pii_guard;
pub mod prompt_injection_detector;
pub mod rate_limiter;

pub fn config_hash<T: Serialize>(value: &T) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    let mut hash = 0xcbf29ce484222325u64;
    for byte in serialized.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn action_key(action: velvet_core::ActionType) -> String {
    serde_json::to_value(action)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("{action:?}"))
}
