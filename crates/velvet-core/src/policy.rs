use std::collections::BTreeMap;
use std::sync::Arc;

use crate::utils::stable_hash_json;
use crate::{
    ActionMutation, CandidateAction, DecisionType, PolicyContext, PolicyDecision, PolicyReason,
    PolicyTraceEntry,
};

pub trait Policy: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &str {
        self.name()
    }
    fn version(&self) -> &str;
    fn config_version(&self) -> &str {
        self.version()
    }
    fn config_hash(&self) -> &str {
        "unconfigured"
    }
    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision;
}

pub struct PolicyInstance {
    name: String,
    kind: String,
    config_version: String,
    config_hash: String,
    inner: Arc<dyn Policy>,
}

impl PolicyInstance {
    pub fn new(
        name: impl Into<String>,
        kind: impl Into<String>,
        config_version: impl Into<String>,
        config_hash: impl Into<String>,
        inner: Arc<dyn Policy>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            config_version: config_version.into(),
            config_hash: config_hash.into(),
            inner,
        }
    }
}

impl Policy for PolicyInstance {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    fn version(&self) -> &str {
        self.inner.version()
    }

    fn config_version(&self) -> &str {
        &self.config_version
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        self.inner.evaluate(candidate, context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySelection {
    pub chain_name: String,
    pub chain_revision: String,
}

impl PolicySelection {
    pub fn inline() -> Self {
        Self {
            chain_name: "inline".to_string(),
            chain_revision: "inline".to_string(),
        }
    }
}

#[derive(Clone, Default)]
pub struct PolicyChain {
    policies: Vec<Arc<dyn Policy>>,
}

#[derive(Clone, Default)]
pub struct PolicyGraph {
    revision: String,
    chains: BTreeMap<String, PolicyChain>,
}

impl PolicyGraph {
    pub fn new(revision: impl Into<String>, chains: BTreeMap<String, PolicyChain>) -> Self {
        Self {
            revision: revision.into(),
            chains,
        }
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn chain(&self, name: &str) -> Option<&PolicyChain> {
        self.chains.get(name)
    }

    pub fn chain_names(&self) -> impl Iterator<Item = &str> {
        self.chains.keys().map(String::as_str)
    }
}

impl PolicyChain {
    pub fn new(policies: Vec<Arc<dyn Policy>>) -> Self {
        Self { policies }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn policies(&self) -> &[Arc<dyn Policy>] {
        &self.policies
    }

    pub fn names(&self) -> Vec<String> {
        self.policies
            .iter()
            .map(|policy| policy.name().to_string())
            .collect()
    }

    pub fn evaluate(
        &self,
        candidate: &CandidateAction,
        context: &PolicyContext,
    ) -> PolicyEvaluation {
        let mut current = candidate.clone();
        let mut entries = Vec::new();
        let mut mutations = Vec::new();
        let mut route_decision = None;
        let mut route_reason = None;
        let mut short_circuit = None;

        for (index, policy) in self.policies.iter().enumerate() {
            let input_hash = stable_hash_json(&current);
            let decision = policy.evaluate(&current, context);
            let mut output = current.clone();
            let mut mutation = None;
            let mut jurisdiction_evidence = decision.jurisdiction_evidence().cloned();
            let mut status = decision.kind().to_string();

            match &decision {
                PolicyDecision::Allow => {}
                PolicyDecision::Modify {
                    mutation: action_mutation,
                    ..
                } => {
                    jurisdiction_evidence = action_mutation.jurisdiction_evidence.clone();
                    if !action_mutation.is_empty() {
                        let mut applied = output.clone();
                        action_mutation.apply_to(&mut applied);
                        output = applied;
                        mutations.push(action_mutation.clone());
                        mutation = Some(action_mutation.clone());
                    }
                    current = output.clone();
                }
                PolicyDecision::Deny {
                    reason,
                    jurisdiction_evidence: deny_evidence,
                } => {
                    status = "deny".to_string();
                    jurisdiction_evidence = Some(deny_evidence.clone());
                    route_decision = Some(DecisionType::Block);
                    route_reason = Some(reason.message.clone());
                    short_circuit = Some(format!("deny:{}", reason.code));
                }
                PolicyDecision::Defer {
                    reason,
                    jurisdiction_evidence: defer_evidence,
                    ..
                } => {
                    status = "defer".to_string();
                    jurisdiction_evidence = Some(defer_evidence.clone());
                    route_decision = Some(DecisionType::Escalate);
                    route_reason = Some(reason.message.clone());
                    short_circuit = Some(format!("defer:{}", reason.code));
                }
            }

            let output_hash = stable_hash_json(&output);
            entries.push(PolicyTraceEntry {
                policy_name: policy.name().to_string(),
                policy_kind: policy.kind().to_string(),
                policy_version: policy.version().to_string(),
                config_version: policy.config_version().to_string(),
                config_hash: policy.config_hash().to_string(),
                status,
                decision,
                jurisdiction_evidence,
                mutation,
                input_action_hash: input_hash,
                output_action_hash: output_hash,
                elapsed_us: 0,
                short_circuit: short_circuit.clone(),
            });

            if short_circuit.is_some() {
                for skipped in self.policies.iter().skip(index + 1) {
                    let hash = stable_hash_json(&current);
                    entries.push(PolicyTraceEntry {
                        policy_name: skipped.name().to_string(),
                        policy_kind: skipped.kind().to_string(),
                        policy_version: skipped.version().to_string(),
                        config_version: skipped.config_version().to_string(),
                        config_hash: skipped.config_hash().to_string(),
                        status: "not_evaluated_due_to_short_circuit".to_string(),
                        decision: PolicyDecision::Allow,
                        jurisdiction_evidence: None,
                        mutation: None,
                        input_action_hash: hash.clone(),
                        output_action_hash: hash,
                        elapsed_us: 0,
                        short_circuit: short_circuit.clone(),
                    });
                }
                break;
            }
        }

        PolicyEvaluation {
            final_candidate: current,
            policy_trace: entries,
            mutation_ledger: mutations,
            decision: route_decision,
            reason: route_reason,
            short_circuit,
        }
    }
}

pub struct PolicyEvaluation {
    pub final_candidate: CandidateAction,
    pub policy_trace: Vec<PolicyTraceEntry>,
    pub mutation_ledger: Vec<ActionMutation>,
    pub decision: Option<DecisionType>,
    pub reason: Option<String>,
    pub short_circuit: Option<String>,
}

pub struct AllowAllPolicy;

impl Policy for AllowAllPolicy {
    fn name(&self) -> &str {
        "allow_all"
    }

    fn version(&self) -> &str {
        "allow_all_v1"
    }

    fn evaluate(&self, _candidate: &CandidateAction, _context: &PolicyContext) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

pub fn policy_reason(
    code: impl Into<String>,
    message: impl Into<String>,
    severity: impl Into<String>,
) -> PolicyReason {
    PolicyReason::new(code, message, severity)
}
