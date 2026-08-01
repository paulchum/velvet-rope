use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AdmissionConstraintResult, ObjectiveComponents};

pub const ADMISSION_TRACE_SCHEMA_VERSION: &str = "velvet.admission_trace.v1";
pub const ADMISSION_TRACE_HASH_DOMAIN: &str = "Velvet:AdmissionTrace:v1";
pub const CANDIDATE_HASH_DOMAIN: &str = "Velvet:AdmissionCandidate:v1";
pub const EFFECT_VECTOR_HASH_DOMAIN: &str = "Velvet:EffectVector:v1";
pub const REQUEST_HASH_DOMAIN: &str = "Velvet:AdmissionRequest:v1";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Execute,
    Block,
    Defer,
    AskApproval,
    Escalate,
    AnswerDirectly,
    RequireWarrant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionTrace {
    pub schema_version: String,
    pub candidate_hash: String,
    pub request_hash: String,
    pub policy_bundle_hash: String,
    pub tool_schema_hash: String,
    pub capability_registry_hash: String,
    pub effect_vector_hash: String,
    pub utility_model_version: String,
    pub risk_model_version: String,
    pub calibration_set_hash: String,
    pub hard_constraints: Vec<AdmissionConstraintResult>,
    pub objective_components: ObjectiveComponents,
    pub selected_decision: AdmissionDecision,
    pub selected_reason: String,
    pub deterministic_replay_inputs_hash: String,
}

impl AdmissionTrace {
    pub fn hash(&self) -> String {
        admission_trace_hash_value(
            "admission_trace",
            &serde_json::to_value(self).expect("admission trace serializes"),
        )
    }
}

pub fn admission_trace_hash_value(domain: &str, value: &Value) -> String {
    domain_hash_value(domain, value)
}

pub fn domain_hash_value(domain: &str, value: &Value) -> String {
    let canonical = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical.as_bytes());
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

pub fn domain_hash_bytes(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(&values[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
