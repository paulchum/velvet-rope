use serde_json::{Value, json};

use crate::utils::{clamp01, number_value, string_value};
use crate::{DecisionType, MemoryDecision, MemoryObject};

pub fn evaluate_memory(
    content: &str,
    context: &Value,
    timestamp: Option<String>,
) -> MemoryDecision {
    let memory_value = clamp01(number_value(
        context.get("memory_candidate_value"),
        infer_value(content),
    ));
    let sensitivity = clamp01(number_value(
        context.get("sensitivity"),
        infer_sensitivity(content),
    ));
    let memory_novelty = clamp01(number_value(context.get("memory_novelty"), 0.72));
    let memory_confidence = clamp01(number_value(context.get("memory_confidence"), 0.78));
    let memory_type = string_value(context, "memory_type")
        .unwrap_or("project_preference")
        .to_string();
    let mut state = context.clone();
    let Some(state_object) = state.as_object_mut() else {
        return evaluate_memory(content, &json!({}), timestamp);
    };
    state_object.insert("memory_candidate_value".to_string(), json!(memory_value));
    state_object.insert("memory_novelty".to_string(), json!(memory_novelty));
    state_object.insert("memory_confidence".to_string(), json!(memory_confidence));
    state_object.insert("sensitivity".to_string(), json!(sensitivity));
    state_object.insert(
        "contains_sensitive_memory".to_string(),
        json!(sensitivity >= 0.70),
    );
    state_object.insert("memory_type".to_string(), json!(memory_type));
    let memory_score = clamp01(memory_value * memory_confidence);
    if sensitivity >= 0.70 {
        return MemoryDecision {
            store: false,
            decision: DecisionType::AskApproval,
            reason: "Sensitive memory candidates require explicit user approval.".to_string(),
            memory_score,
            sensitivity,
            memory_object: None,
        };
    }
    if memory_value < 0.35 {
        return MemoryDecision {
            store: false,
            decision: DecisionType::Skip,
            reason: "Memory candidate is too low-value to store.".to_string(),
            memory_score,
            sensitivity,
            memory_object: None,
        };
    }
    if memory_score < 0.35 {
        return MemoryDecision {
            store: false,
            decision: DecisionType::Skip,
            reason: "Memory candidate did not clear typed admission threshold.".to_string(),
            memory_score,
            sensitivity,
            memory_object: None,
        };
    }
    let created_at = timestamp.unwrap_or_else(crate::trace::now_iso);
    MemoryDecision {
        store: true,
        decision: DecisionType::Execute,
        reason: "Memory candidate cleared typed memory admission.".to_string(),
        memory_score,
        sensitivity,
        memory_object: Some(MemoryObject {
            content: content.to_string(),
            memory_type,
            context: context.clone(),
            confidence: memory_confidence,
            created_at,
        }),
    }
}

fn infer_value(content: &str) -> f64 {
    let lowered = content.to_lowercase();
    let durable_terms = [
        "prefers",
        "preference",
        "always",
        "project",
        "positioning",
        "remember",
    ];
    if durable_terms.iter().any(|term| lowered.contains(term)) {
        0.78
    } else if content.len() < 36 {
        0.18
    } else {
        0.44
    }
}

fn infer_sensitivity(content: &str) -> f64 {
    let lowered = content.to_lowercase();
    let sensitive_terms = [
        "password",
        "token",
        "api key",
        "secret",
        "private key",
        "ssn",
        "medical",
        "diagnosis",
    ];
    if sensitive_terms.iter().any(|term| lowered.contains(term)) {
        0.88
    } else {
        0.20
    }
}
