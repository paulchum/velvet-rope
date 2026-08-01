use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_single_dispatch() -> bool {
    true
}

fn default_max_grants() -> u64 {
    1
}

fn default_deny_reason() -> String {
    "global deny".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub name: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRule {
    pub subgoal: String,
    pub capability: String,
    pub resource: String,
    #[serde(default = "default_single_dispatch")]
    pub single_dispatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_class: Option<String>,
    #[serde(default = "default_max_grants")]
    pub max_grants: u64,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClosureKind {
    OnReceipt,
    OnSignal,
    OnDeny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClosurePredicate {
    pub subgoal: String,
    pub kind: ClosureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyRule {
    pub capability: String,
    pub resource: String,
    #[serde(default = "default_deny_reason")]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskContract {
    pub contract_id: String,
    #[serde(default)]
    pub initial_envelope: Vec<Capability>,
    #[serde(default)]
    pub grant_rules: Vec<GrantRule>,
    #[serde(default)]
    pub closure_predicates: Vec<ClosurePredicate>,
    #[serde(default)]
    pub deny_rules: Vec<DenyRule>,
}

impl TaskContract {
    pub fn deny_for(&self, capability: &str, resource: &str) -> Option<&DenyRule> {
        self.deny_rules.iter().find(|rule| {
            (rule.capability == capability || rule.capability == "*")
                && (rule.resource == resource || rule.resource == "*")
        })
    }

    pub fn grant_rule_for(
        &self,
        subgoal: &str,
        capability: &str,
        resource: &str,
    ) -> Option<&GrantRule> {
        self.grant_rules.iter().find(|rule| {
            rule.subgoal == subgoal && rule.capability == capability && rule.resource == resource
        })
    }

    pub fn closures_for_receipt(&self, subgoal: &str, capability: &str) -> Vec<&ClosurePredicate> {
        self.closure_predicates
            .iter()
            .filter(|predicate| {
                predicate.subgoal == subgoal
                    && predicate.kind == ClosureKind::OnReceipt
                    && predicate.capability.as_deref() == Some(capability)
            })
            .collect()
    }

    pub fn has_signal_closure(&self, subgoal: &str) -> bool {
        self.closure_predicates.iter().any(|predicate| {
            predicate.subgoal == subgoal && predicate.kind == ClosureKind::OnSignal
        })
    }

    pub fn has_deny_closure(&self, subgoal: &str) -> bool {
        self.closure_predicates
            .iter()
            .any(|predicate| predicate.subgoal == subgoal && predicate.kind == ClosureKind::OnDeny)
    }
}

pub fn contract_schema_json() -> Value {
    serde_json::to_value(schema_for!(TaskContract)).expect("contract schema serializes")
}

pub fn validate_contract_value(value: &Value) -> Result<()> {
    let validator =
        jsonschema::validator_for(&contract_schema_json()).context("build contract schema")?;
    if let Err(error) = validator.validate(value) {
        bail!("contract schema validation failed: {error}");
    }
    Ok(())
}

pub fn load_contract(value: Value) -> Result<TaskContract> {
    validate_contract_value(&value)?;
    let contract: TaskContract =
        serde_json::from_value(value).context("parse task contract from JSON value")?;
    validate_contract(&contract)?;
    Ok(contract)
}

pub fn load_contract_yaml(source: &str) -> Result<TaskContract> {
    let value: Value = serde_yaml::from_str(source).context("parse task contract YAML")?;
    load_contract(value)
}

pub fn load_contract_path(path: &Path) -> Result<TaskContract> {
    let source =
        fs::read_to_string(path).with_context(|| format!("read contract {}", path.display()))?;
    load_contract_yaml(&source)
}

pub fn validate_contract(contract: &TaskContract) -> Result<()> {
    if contract.contract_id.trim().is_empty() {
        bail!("contract_id is required");
    }
    for capability in &contract.initial_envelope {
        require_nonempty("initial_envelope.name", &capability.name)?;
        require_nonempty("initial_envelope.resource", &capability.resource)?;
    }
    let mut subgoals_with_closure = BTreeSet::new();
    for predicate in &contract.closure_predicates {
        require_nonempty("closure_predicates.subgoal", &predicate.subgoal)?;
        if predicate.kind == ClosureKind::OnReceipt
            && predicate
                .capability
                .as_deref()
                .is_none_or(|capability| capability.trim().is_empty())
        {
            bail!("on_receipt closure needs a capability");
        }
        subgoals_with_closure.insert(predicate.subgoal.clone());
    }
    for rule in &contract.grant_rules {
        require_nonempty("grant_rules.subgoal", &rule.subgoal)?;
        require_nonempty("grant_rules.capability", &rule.capability)?;
        require_nonempty("grant_rules.resource", &rule.resource)?;
        if rule.max_grants == 0 {
            bail!("grant_rules.max_grants must be at least 1");
        }
        if !subgoals_with_closure.contains(&rule.subgoal) {
            return Err(anyhow!(
                "grant for subgoal {:?} has no closure predicate; that is lingering authority by construction",
                rule.subgoal
            ));
        }
    }
    for deny in &contract.deny_rules {
        require_nonempty("deny_rules.capability", &deny.capability)?;
        require_nonempty("deny_rules.resource", &deny.resource)?;
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    Ok(())
}
