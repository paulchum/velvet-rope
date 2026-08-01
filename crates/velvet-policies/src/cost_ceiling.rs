use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    ActionMutation, BudgetLedger, CandidateAction, Evidence, JsonObject, Policy, PolicyContext,
    PolicyDecision, PolicyReason,
};

use crate::{action_key, config_hash};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CostCeilingConfig {
    pub per_task_usd_limit: Option<f64>,
    pub per_user_daily_usd_limit: Option<f64>,
    pub per_org_monthly_usd_limit: Option<f64>,
    pub soft_ceiling_fraction: f64,
    pub cost_model: BTreeMap<String, CostModel>,
}

impl Default for CostCeilingConfig {
    fn default() -> Self {
        Self {
            per_task_usd_limit: None,
            per_user_daily_usd_limit: None,
            per_org_monthly_usd_limit: None,
            soft_ceiling_fraction: 0.80,
            cost_model: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CostModel {
    pub token_usd: f64,
    pub call_usd: f64,
    pub volume_usd_per_unit: f64,
    pub default_usd: f64,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            token_usd: 0.0,
            call_usd: 0.0,
            volume_usd_per_unit: 0.0,
            default_usd: 0.0,
        }
    }
}

pub trait CostObserver: Send + Sync {
    /// Record the actual realized USD spend after execution.
    ///
    /// Missing realized cost is fail-closed for certified budget safety; callers
    /// must not substitute the pre-execution estimate as if it were observed spend.
    fn observe_realized_cost(
        &self,
        context: &PolicyContext,
        action: &CandidateAction,
        realized_usd: f64,
    ) -> BudgetLedger;
}

/// Soft, estimate-based compatibility policy.
///
/// This policy keeps the legacy `usd_estimate` projection behavior. It is not a
/// deterministic no-overspend guarantee; certified spend safety is enforced by
/// deterministic budget certificates in the routing core.
pub struct CostCeilingPolicy {
    config: CostCeilingConfig,
    config_hash: String,
}

impl Default for CostCeilingPolicy {
    fn default() -> Self {
        Self::new(CostCeilingConfig::default()).expect("default config is valid")
    }
}

impl CostCeilingPolicy {
    pub fn new(config: CostCeilingConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config_hash: config_hash(&config),
            config,
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn estimate_usd(&self, candidate: &CandidateAction) -> f64 {
        canonical_usd(candidate).unwrap_or_else(|| {
            self.config
                .cost_model
                .get(&action_key(candidate.action_type))
                .map(|model| {
                    let tokens = number_from(&candidate.parameters, "tokens")
                        .or_else(|| number_from(&candidate.metadata, "tokens"))
                        .unwrap_or(0.0);
                    let calls = number_from(&candidate.parameters, "calls")
                        .or_else(|| number_from(&candidate.metadata, "calls"))
                        .unwrap_or(1.0);
                    let volume = number_from(&candidate.parameters, "volume_units")
                        .or_else(|| number_from(&candidate.metadata, "volume_units"))
                        .unwrap_or(0.0);
                    model.default_usd
                        + tokens * model.token_usd
                        + calls * model.call_usd
                        + volume * model.volume_usd_per_unit
                })
                .unwrap_or_else(|| {
                    candidate
                        .cost_overrides
                        .get("money")
                        .copied()
                        .unwrap_or(0.0)
                })
        })
    }

    fn scope_checks(&self, context: &PolicyContext, estimate: f64) -> Vec<ScopeCheck> {
        [
            ("task", self.config.per_task_usd_limit, &context.task_budget),
            (
                "user_daily",
                self.config.per_user_daily_usd_limit,
                &context.user_budget,
            ),
            (
                "organization_monthly",
                self.config.per_org_monthly_usd_limit,
                &context.organization_budget,
            ),
        ]
        .into_iter()
        .filter_map(|(scope, config_limit, ledger)| {
            let limit = ledger.limit_usd.or(config_limit)?;
            let projected = ledger.spent_usd + estimate;
            Some(ScopeCheck {
                scope,
                limit,
                spent: ledger.spent_usd,
                projected,
                hard_exceeded: projected > limit,
                soft_exceeded: projected >= limit * self.config.soft_ceiling_fraction,
            })
        })
        .collect()
    }
}

impl CostCeilingConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.soft_ceiling_fraction) {
            return Err(
                "spec.config.soft_ceiling_fraction must be in range [0.0, 1.0]".to_string(),
            );
        }
        for (field, value) in [
            ("per_task_usd_limit", self.per_task_usd_limit),
            ("per_user_daily_usd_limit", self.per_user_daily_usd_limit),
            ("per_org_monthly_usd_limit", self.per_org_monthly_usd_limit),
        ] {
            if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return Err(format!(
                    "spec.config.{field} must be a non-negative finite number"
                ));
            }
        }
        for (name, model) in &self.cost_model {
            for (field, value) in [
                ("token_usd", model.token_usd),
                ("call_usd", model.call_usd),
                ("volume_usd_per_unit", model.volume_usd_per_unit),
                ("default_usd", model.default_usd),
            ] {
                if !value.is_finite() || value < 0.0 {
                    return Err(format!(
                        "spec.config.cost_model.{name}.{field} must be a non-negative finite number"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Policy for CostCeilingPolicy {
    fn name(&self) -> &str {
        "cost_ceiling"
    }

    fn version(&self) -> &str {
        "cost_ceiling_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let estimate = self.estimate_usd(candidate);
        let checks = self.scope_checks(context, estimate);
        if let Some(check) = checks.iter().find(|check| check.hard_exceeded) {
            let jurisdiction_evidence =
                check.jurisdiction_evidence(estimate, "hard_ceiling_exceeded");
            return PolicyDecision::Deny {
                reason: PolicyReason::new(
                    "cost_ceiling.hard_limit",
                    format!(
                        "Projected cost exceeds {} budget hard ceiling.",
                        check.scope
                    ),
                    "error",
                ),
                jurisdiction_evidence,
            };
        }
        if let Some(check) = checks.iter().find(|check| check.soft_exceeded) {
            let mut mutation = ActionMutation {
                jurisdiction_evidence: Some(
                    check.jurisdiction_evidence(estimate, "soft_ceiling_warning"),
                ),
                ..ActionMutation::default()
            };
            mutation.notes.push("soft cost ceiling warning".to_string());
            return PolicyDecision::Modify {
                mutation,
                reason: PolicyReason::new(
                    "cost_ceiling.soft_limit",
                    format!(
                        "Projected cost exceeds {} budget soft ceiling.",
                        check.scope
                    ),
                    "warning",
                ),
            };
        }
        PolicyDecision::Allow
    }
}

struct ScopeCheck {
    scope: &'static str,
    limit: f64,
    spent: f64,
    projected: f64,
    hard_exceeded: bool,
    soft_exceeded: bool,
}

impl ScopeCheck {
    fn jurisdiction_evidence(&self, estimate: f64, rule_id: &str) -> Evidence {
        let mut details = JsonObject::new();
        details.insert("scope".to_string(), json!(self.scope));
        details.insert("usd_estimate".to_string(), json!(estimate));
        details.insert("spent_usd".to_string(), json!(self.spent));
        details.insert("projected_spent_usd".to_string(), json!(self.projected));
        details.insert("limit_usd".to_string(), json!(self.limit));
        Evidence {
            rule_id: rule_id.to_string(),
            evidence_type: "budget_projection".to_string(),
            message: "Cost ceiling projection used canonical usd_estimate.".to_string(),
            details,
        }
    }
}

fn number_from(map: &JsonObject, key: &str) -> Option<f64> {
    map.get(key).and_then(Value::as_f64)
}

fn canonical_usd(candidate: &CandidateAction) -> Option<f64> {
    number_from(&candidate.metadata, "usd_estimate")
        .or_else(|| number_from(&candidate.parameters, "usd_estimate"))
        .or_else(|| {
            candidate
                .metadata
                .get("normalized_cost")
                .and_then(|value| value.get("usd_estimate"))
                .and_then(Value::as_f64)
        })
        .or_else(|| {
            candidate
                .parameters
                .get("normalized_cost")
                .and_then(|value| value.get("usd_estimate"))
                .and_then(Value::as_f64)
        })
}
