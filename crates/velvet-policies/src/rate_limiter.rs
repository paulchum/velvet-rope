use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    ActionMutation, CandidateAction, Evidence, JsonObject, Policy, PolicyContext, PolicyDecision,
    PolicyReason,
};

use crate::{action_key, config_hash};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimiterConfig {
    pub aggregate: RateLimit,
    pub per_action: BTreeMap<String, RateLimit>,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            aggregate: RateLimit {
                window_ms: 60_000,
                max_requests: 1_000_000_000,
                sustained_per_second: 1_000_000.0,
                burst_multiplier: 1.5,
            },
            per_action: BTreeMap::new(),
        }
    }
}

impl RateLimiterConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.aggregate.validate("aggregate")?;
        for (name, limit) in &self.per_action {
            limit.validate(&format!("per_action.{name}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimit {
    pub window_ms: i64,
    pub max_requests: u64,
    pub sustained_per_second: f64,
    pub burst_multiplier: f64,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            max_requests: 60,
            sustained_per_second: 1.0,
            burst_multiplier: 1.5,
        }
    }
}

impl RateLimit {
    fn effective_max(self) -> u64 {
        let sustained = (self.window_ms.max(1) as f64 / 1_000.0)
            * self.sustained_per_second.max(0.0)
            * self.burst_multiplier.max(1.0);
        self.max_requests.max(sustained.ceil() as u64)
    }

    fn validate(self, path: &str) -> Result<(), String> {
        if self.window_ms <= 0 {
            return Err(format!(
                "spec.config.{path}.window_ms must be greater than zero"
            ));
        }
        if self.max_requests == 0 {
            return Err(format!(
                "spec.config.{path}.max_requests must be greater than zero"
            ));
        }
        if !self.sustained_per_second.is_finite() || self.sustained_per_second < 0.0 {
            return Err(format!(
                "spec.config.{path}.sustained_per_second must be non-negative"
            ));
        }
        if !self.burst_multiplier.is_finite() || self.burst_multiplier < 1.0 {
            return Err(format!(
                "spec.config.{path}.burst_multiplier must be at least 1.0"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSnapshot {
    pub key: String,
    pub now_unix_ms: i64,
    pub window_start_unix_ms: i64,
    pub request_count: u64,
    pub limit: u64,
}

pub struct RateLimiterPolicy {
    config: RateLimiterConfig,
    config_hash: String,
}

impl Default for RateLimiterPolicy {
    fn default() -> Self {
        Self::new(RateLimiterConfig::default()).expect("default config is valid")
    }
}

impl RateLimiterPolicy {
    pub fn new(config: RateLimiterConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config_hash: config_hash(&config),
            config,
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn key_prefix(&self, candidate: &CandidateAction, context: &PolicyContext) -> String {
        format!(
            "{}:{}",
            context.user_id.as_deref().unwrap_or("anonymous"),
            action_key(candidate.action_type)
        )
    }

    fn snapshot_from_context(
        &self,
        context: &PolicyContext,
        snapshot_key: &str,
        default_key: String,
        limit: RateLimit,
    ) -> RateLimitSnapshot {
        context
            .external_observations
            .get("rate_limit_snapshots")
            .and_then(Value::as_object)
            .and_then(|snapshots| snapshots.get(snapshot_key))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_else(|| RateLimitSnapshot {
                key: default_key,
                now_unix_ms: context.decision_unix_ms,
                window_start_unix_ms: context.decision_unix_ms - limit.window_ms,
                request_count: 0,
                limit: limit.effective_max(),
            })
    }
}

impl Policy for RateLimiterPolicy {
    fn name(&self) -> &str {
        "rate_limiter"
    }

    fn version(&self) -> &str {
        "rate_limiter_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let action_name = action_key(candidate.action_type);
        let action_limit = self
            .config
            .per_action
            .get(&action_name)
            .copied()
            .unwrap_or(self.config.aggregate);
        let aggregate = self.config.aggregate;
        let action_snapshot = self.snapshot_from_context(
            context,
            "action",
            self.key_prefix(candidate, context),
            action_limit,
        );
        let aggregate_snapshot = self.snapshot_from_context(
            context,
            "aggregate",
            format!("{}:*", context.user_id.as_deref().unwrap_or("anonymous")),
            aggregate,
        );
        if action_snapshot.request_count >= action_snapshot.limit {
            return deny("rate_limiter.per_action", action_snapshot);
        }
        if aggregate_snapshot.request_count >= aggregate_snapshot.limit {
            return deny("rate_limiter.aggregate", aggregate_snapshot);
        }

        let mut details = JsonObject::new();
        details.insert("action_snapshot".to_string(), json!(action_snapshot));
        details.insert("aggregate_snapshot".to_string(), json!(aggregate_snapshot));
        let mutation = ActionMutation {
            jurisdiction_evidence: Some(Evidence {
                rule_id: "rate_limiter.allowed_snapshot".to_string(),
                evidence_type: "rate_limit_snapshot".to_string(),
                message: "Rate limiter allowed request from supplied deterministic snapshots."
                    .to_string(),
                details,
            }),
            ..ActionMutation::default()
        };
        PolicyDecision::Modify {
            mutation,
            reason: PolicyReason::new(
                "rate_limiter.allowed",
                "Rate limiter had capacity for this action.",
                "info",
            ),
        }
    }
}

fn deny(rule_id: &str, snapshot: RateLimitSnapshot) -> PolicyDecision {
    let mut details = JsonObject::new();
    details.insert("snapshot".to_string(), json!(snapshot));
    PolicyDecision::Deny {
        reason: PolicyReason::new(
            rule_id,
            "Rate limit exceeded for candidate action.",
            "error",
        ),
        jurisdiction_evidence: Evidence {
            rule_id: rule_id.to_string(),
            evidence_type: "rate_limit_snapshot".to_string(),
            message: "Rolling window request count met or exceeded configured limit.".to_string(),
            details,
        },
    }
}
