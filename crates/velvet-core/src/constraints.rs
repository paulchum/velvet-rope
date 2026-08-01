use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AdmissionTrace, CapabilityClass, EffectVector, admission_trace_hash_value};

pub const CONSTRAINT_MODEL_VERSION: &str = "velvet.hard_constraints.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintSeverity {
    Info,
    Warning,
    Defer,
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionConstraintResult {
    pub constraint_id: String,
    pub passed: bool,
    pub severity: ConstraintSeverity,
    pub reason_code: String,
    pub evidence_hash: String,
    pub safe_public_message: String,
}

impl AdmissionConstraintResult {
    pub fn pass(
        constraint_id: impl Into<String>,
        reason_code: impl Into<String>,
        evidence: &serde_json::Value,
    ) -> Self {
        Self {
            constraint_id: constraint_id.into(),
            passed: true,
            severity: ConstraintSeverity::Info,
            reason_code: reason_code.into(),
            evidence_hash: admission_trace_hash_value("constraint_evidence", evidence),
            safe_public_message: "constraint passed".to_string(),
        }
    }

    pub fn fail(
        constraint_id: impl Into<String>,
        severity: ConstraintSeverity,
        reason_code: impl Into<String>,
        safe_public_message: impl Into<String>,
        evidence: &serde_json::Value,
    ) -> Self {
        Self {
            constraint_id: constraint_id.into(),
            passed: false,
            severity,
            reason_code: reason_code.into(),
            evidence_hash: admission_trace_hash_value("constraint_evidence", evidence),
            safe_public_message: safe_public_message.into(),
        }
    }
}

pub fn has_blocking_constraint(results: &[AdmissionConstraintResult]) -> bool {
    results
        .iter()
        .any(|result| !result.passed && result.severity == ConstraintSeverity::Block)
}

pub fn has_defer_constraint(results: &[AdmissionConstraintResult]) -> bool {
    results
        .iter()
        .any(|result| !result.passed && result.severity == ConstraintSeverity::Defer)
}

pub fn source_to_sink_constraint(effect: &EffectVector) -> AdmissionConstraintResult {
    let high_privilege_unknown_sink = effect
        .source_to_sink_flows
        .iter()
        .any(|flow| flow.sink_capability_class == CapabilityClass::Unknown);
    if high_privilege_unknown_sink {
        AdmissionConstraintResult::fail(
            "source_to_sink_allowed",
            ConstraintSeverity::Block,
            "unknown_high_privilege_sink",
            "Source-to-sink flow targets an unknown or high-privilege sink.",
            &serde_json::json!({
                "flow_count": effect.source_to_sink_flows.len(),
                "capability_class": effect.capability_class,
            }),
        )
    } else {
        AdmissionConstraintResult::pass(
            "source_to_sink_allowed",
            "no_high_privilege_unknown_sink",
            &serde_json::json!({
                "flow_count": effect.source_to_sink_flows.len(),
            }),
        )
    }
}

pub fn selected_reason_from_trace(trace: &AdmissionTrace) -> String {
    if trace
        .hard_constraints
        .iter()
        .any(|constraint| !constraint.passed && constraint.reason_code == "approval_required")
    {
        return "Valid approval is required before this action can execute.".to_string();
    }
    if let Some(constraint) = trace.hard_constraints.iter().find(|item| !item.passed) {
        return constraint.safe_public_message.clone();
    }
    format!(
        "Admission optimizer selected {:?} with objective {}.",
        trace.selected_decision, trace.objective_components.objective_bps
    )
}
