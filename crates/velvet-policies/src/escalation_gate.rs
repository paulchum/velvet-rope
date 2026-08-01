use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    ActionType, CandidateAction, EscalationTarget, Evidence, JsonObject, Policy, PolicyContext,
    PolicyDecision, PolicyReason,
};

use crate::{action_key, config_hash};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EscalationGateConfig {
    pub cost_threshold_usd: Option<f64>,
    pub confidence_threshold: Option<f64>,
    pub novelty_threshold: Option<f64>,
    pub repeated_failure_threshold: u64,
    pub sensitive_actions: BTreeSet<String>,
    pub targets: BTreeMap<String, TargetConfig>,
    pub default_fallback: String,
}

impl Default for EscalationGateConfig {
    fn default() -> Self {
        Self {
            cost_threshold_usd: Some(25.0),
            confidence_threshold: Some(0.20),
            novelty_threshold: Some(0.98),
            repeated_failure_threshold: 3,
            sensitive_actions: [
                action_key(ActionType::ExecuteCode),
                action_key(ActionType::CallTool),
            ]
            .into_iter()
            .collect(),
            targets: BTreeMap::from([
                (
                    "concierge_review".to_string(),
                    TargetConfig {
                        target_type: "velvet_concierge_queue".to_string(),
                        target: "local://velvet-concierge".to_string(),
                        mode: "sync".to_string(),
                        fallback: "deny".to_string(),
                    },
                ),
                (
                    "model_escalation".to_string(),
                    TargetConfig {
                        target_type: "escalation_model".to_string(),
                        target: "local://model-escalation".to_string(),
                        mode: "sync".to_string(),
                        fallback: "deny".to_string(),
                    },
                ),
            ]),
            default_fallback: "deny".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TargetConfig {
    pub target_type: String,
    pub target: String,
    pub mode: String,
    pub fallback: String,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            target_type: "velvet_concierge_queue".to_string(),
            target: "local://velvet-concierge".to_string(),
            mode: "sync".to_string(),
            fallback: "deny".to_string(),
        }
    }
}

pub struct EscalationGatePolicy {
    config: EscalationGateConfig,
    config_hash: String,
}

impl Default for EscalationGatePolicy {
    fn default() -> Self {
        Self::new(EscalationGateConfig::default()).expect("default config is valid")
    }
}

impl EscalationGatePolicy {
    pub fn new(config: EscalationGateConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config_hash: config_hash(&config),
            config,
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn trigger(&self, candidate: &CandidateAction, context: &PolicyContext) -> Option<Evidence> {
        if let Some(threshold) = self.config.cost_threshold_usd
            && let Some(estimate) = usd_estimate(candidate)
            && estimate >= threshold
        {
            return Some(jurisdiction_evidence(
                "escalation_gate.cost_threshold",
                "cost_threshold",
                JsonObject::from([
                    ("usd_estimate".to_string(), json!(estimate)),
                    ("threshold".to_string(), json!(threshold)),
                ]),
            ));
        }
        if let Some(threshold) = self.config.confidence_threshold
            && let Some(confidence) = candidate.confidence
            && confidence < threshold
        {
            return Some(jurisdiction_evidence(
                "escalation_gate.low_confidence",
                "confidence_threshold",
                JsonObject::from([
                    ("confidence".to_string(), json!(confidence)),
                    ("threshold".to_string(), json!(threshold)),
                ]),
            ));
        }
        if self
            .config
            .sensitive_actions
            .contains(&action_key(candidate.action_type))
        {
            return Some(jurisdiction_evidence(
                "escalation_gate.sensitive_action",
                "sensitive_action_class",
                JsonObject::from([(
                    "action_type".to_string(),
                    json!(action_key(candidate.action_type)),
                )]),
            ));
        }
        let failures = context
            .external_observations
            .get("repeated_failures")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if failures >= self.config.repeated_failure_threshold {
            return Some(jurisdiction_evidence(
                "escalation_gate.repeated_failures",
                "repeated_failure",
                JsonObject::from([
                    ("failures".to_string(), json!(failures)),
                    (
                        "threshold".to_string(),
                        json!(self.config.repeated_failure_threshold),
                    ),
                ]),
            ));
        }
        if let Some(threshold) = self.config.novelty_threshold
            && let Some(score) = context.novelty_score.or(candidate.novelty)
            && score >= threshold
        {
            return Some(jurisdiction_evidence(
                "escalation_gate.novel_state",
                "novelty_threshold",
                JsonObject::from([
                    ("novelty_score".to_string(), json!(score)),
                    ("threshold".to_string(), json!(threshold)),
                ]),
            ));
        }
        None
    }

    fn target(
        &self,
        jurisdiction_evidence: &Evidence,
        candidate: &CandidateAction,
        context: &PolicyContext,
    ) -> EscalationTarget {
        let key = if jurisdiction_evidence.rule_id.contains("confidence") {
            "model_escalation"
        } else {
            "concierge_review"
        };
        let target = self.config.targets.get(key).cloned().unwrap_or_default();
        EscalationTarget {
            target_type: target.target_type,
            target: target.target,
            mode: target.mode,
            fallback: if target.fallback.is_empty() {
                self.config.default_fallback.clone()
            } else {
                target.fallback
            },
            payload: json!({
                "candidate_action": candidate,
                "policy_context": context,
                "thread_prefix": context.prior_thread,
                "trigger": jurisdiction_evidence,
            }),
        }
    }
}

impl EscalationGateConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .cost_threshold_usd
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err("spec.config.cost_threshold_usd must be non-negative".to_string());
        }
        for (field, value) in [
            ("confidence_threshold", self.confidence_threshold),
            ("novelty_threshold", self.novelty_threshold),
        ] {
            if value.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
                return Err(format!("spec.config.{field} must be in range [0.0, 1.0]"));
            }
        }
        if self.repeated_failure_threshold == 0 {
            return Err(
                "spec.config.repeated_failure_threshold must be greater than zero".to_string(),
            );
        }
        if !["deny", "pending_concierge"].contains(&self.default_fallback.as_str()) {
            return Err(
                "spec.config.default_fallback must be deny or pending_concierge".to_string(),
            );
        }
        for (name, target) in &self.targets {
            if !["sync", "async"].contains(&target.mode.as_str()) {
                return Err(format!(
                    "spec.config.targets.{name}.mode must be sync or async"
                ));
            }
            if !["deny", "pending_concierge"].contains(&target.fallback.as_str()) {
                return Err(format!(
                    "spec.config.targets.{name}.fallback must be deny or pending_concierge"
                ));
            }
        }
        Ok(())
    }
}

impl Policy for EscalationGatePolicy {
    fn name(&self) -> &str {
        "escalation_gate"
    }

    fn version(&self) -> &str {
        "escalation_gate_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let Some(jurisdiction_evidence) = self.trigger(candidate, context) else {
            return PolicyDecision::Allow;
        };
        PolicyDecision::Defer {
            to: self.target(&jurisdiction_evidence, candidate, context),
            reason: PolicyReason::new(
                jurisdiction_evidence.rule_id.clone(),
                "Escalation gate deferred candidate action.",
                "warning",
            ),
            jurisdiction_evidence,
        }
    }
}

fn usd_estimate(candidate: &CandidateAction) -> Option<f64> {
    candidate
        .metadata
        .get("usd_estimate")
        .or_else(|| candidate.parameters.get("usd_estimate"))
        .and_then(Value::as_f64)
}

fn jurisdiction_evidence(rule_id: &str, evidence_type: &str, details: JsonObject) -> Evidence {
    Evidence {
        rule_id: rule_id.to_string(),
        evidence_type: evidence_type.to_string(),
        message: "Escalation trigger threshold matched.".to_string(),
        details,
    }
}
