use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    CandidateAction, EscalationTarget, Evidence, JsonObject, Policy, PolicyContext, PolicyDecision,
    PolicyReason,
};

use crate::{action_key, config_hash};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LlmAtomConfig {
    pub rule_id: String,
    pub extraction_question: String,
    pub severity: String,
    pub default_action: String,
    pub runtime_enabled: bool,
    pub certificate_class: String,
    pub finding_keys: Vec<String>,
}

impl Default for LlmAtomConfig {
    fn default() -> Self {
        Self {
            rule_id: "llm_atom".to_string(),
            extraction_question: "Does the candidate action violate this policy atom?".to_string(),
            severity: "error".to_string(),
            default_action: "deny".to_string(),
            runtime_enabled: false,
            certificate_class: "compiled_policy_with_prebound_llm_atom".to_string(),
            finding_keys: vec![
                "llm_atom_findings".to_string(),
                "policy_findings".to_string(),
            ],
        }
    }
}

pub struct LlmAtomPolicy {
    config: LlmAtomConfig,
    config_hash: String,
}

impl Default for LlmAtomPolicy {
    fn default() -> Self {
        Self::new(LlmAtomConfig::default()).expect("default config is valid")
    }
}

impl LlmAtomPolicy {
    pub fn new(config: LlmAtomConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config_hash: config_hash(&config),
            config,
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn finding(&self, candidate: &CandidateAction, context: &PolicyContext) -> Option<Value> {
        for key in &self.config.finding_keys {
            if let Some(value) = candidate
                .metadata
                .get(key)
                .and_then(|value| find_rule_finding(value, &self.config.rule_id))
            {
                return Some(value);
            }
            if let Some(value) = candidate
                .parameters
                .get(key)
                .and_then(|value| find_rule_finding(value, &self.config.rule_id))
            {
                return Some(value);
            }
            if let Some(value) = context
                .external_observations
                .get(key)
                .and_then(|value| find_rule_finding(value, &self.config.rule_id))
            {
                return Some(value);
            }
        }
        None
    }

    fn evidence(&self, candidate: &CandidateAction, finding: &Value) -> Evidence {
        let mut details = JsonObject::new();
        details.insert("rule_id".to_string(), json!(self.config.rule_id));
        details.insert(
            "extraction_question".to_string(),
            json!(self.config.extraction_question),
        );
        details.insert(
            "runtime_grounding_enabled".to_string(),
            json!(self.config.runtime_enabled),
        );
        details.insert(
            "certificate_class".to_string(),
            json!(self.config.certificate_class),
        );
        details.insert(
            "determinism_claim_excluded".to_string(),
            json!(self.config.runtime_enabled),
        );
        details.insert(
            "action_type".to_string(),
            json!(action_key(candidate.action_type)),
        );
        details.insert("finding".to_string(), finding.clone());
        Evidence {
            rule_id: format!("llm_atom.{}", self.config.rule_id),
            evidence_type: "compiled_llm_atom_finding".to_string(),
            message: "Compiled llm_atom finding matched the candidate action.".to_string(),
            details,
        }
    }

    fn target(&self, candidate: &CandidateAction, finding: &Value) -> EscalationTarget {
        EscalationTarget {
            target_type: "compiled_policy_review".to_string(),
            target: "local://velvet-policy-review".to_string(),
            mode: "sync".to_string(),
            fallback: "deny".to_string(),
            payload: json!({
                "rule_id": self.config.rule_id,
                "extraction_question": self.config.extraction_question,
                "candidate_action": candidate,
                "finding": finding,
                "runtime_grounding_enabled": self.config.runtime_enabled,
            }),
        }
    }
}

impl LlmAtomConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.rule_id.trim().is_empty() {
            return Err("spec.config.rule_id must not be empty".to_string());
        }
        if self.extraction_question.trim().is_empty() {
            return Err("spec.config.extraction_question must not be empty".to_string());
        }
        if !["info", "warning", "error", "defer", "block"].contains(&self.severity.as_str()) {
            return Err(
                "spec.config.severity must be info, warning, error, defer, or block".to_string(),
            );
        }
        if !["deny", "defer"].contains(&self.default_action.as_str()) {
            return Err("spec.config.default_action must be deny or defer".to_string());
        }
        if self.certificate_class.trim().is_empty() {
            return Err("spec.config.certificate_class must not be empty".to_string());
        }
        if self.finding_keys.is_empty() || self.finding_keys.iter().any(|key| key.trim().is_empty())
        {
            return Err("spec.config.finding_keys must contain non-empty keys".to_string());
        }
        Ok(())
    }
}

impl Policy for LlmAtomPolicy {
    fn name(&self) -> &str {
        "llm_atom"
    }

    fn version(&self) -> &str {
        "llm_atom_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let Some(finding) = self.finding(candidate, context) else {
            return PolicyDecision::Allow;
        };
        if !finding_matches(&finding) {
            return PolicyDecision::Allow;
        }
        let evidence = self.evidence(candidate, &finding);
        let reason = PolicyReason::new(
            format!("llm_atom.{}", self.config.rule_id),
            "Compiled llm_atom policy matched a policy-visible finding.",
            self.config.severity.clone(),
        );
        if self.config.default_action == "defer" {
            PolicyDecision::Defer {
                to: self.target(candidate, &finding),
                reason,
                jurisdiction_evidence: evidence,
            }
        } else {
            PolicyDecision::Deny {
                reason,
                jurisdiction_evidence: evidence,
            }
        }
    }
}

fn find_rule_finding(value: &Value, rule_id: &str) -> Option<Value> {
    match value {
        Value::Object(object) => {
            if let Some(found) = object.get(rule_id) {
                return Some(found.clone());
            }
            if object
                .get("rule_id")
                .and_then(Value::as_str)
                .is_some_and(|value| value == rule_id)
            {
                return Some(value.clone());
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_rule_finding(item, rule_id)),
        _ => None,
    }
}

fn finding_matches(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64().is_some_and(|value| value != 0),
        Value::String(value) => string_truthy(value),
        Value::Object(object) => object
            .get("matched")
            .or_else(|| object.get("violation"))
            .or_else(|| object.get("violates"))
            .or_else(|| object.get("result"))
            .or_else(|| object.get("answer"))
            .is_some_and(finding_matches),
        _ => false,
    }
}

fn string_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "match" | "matched" | "violation" | "violates" | "violating"
    )
}
