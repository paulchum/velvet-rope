use std::collections::BTreeMap;

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    ACTION_REGISTRY_VERSION, ADMISSION_ENGINE_VERSION, CandidateAction, CandidateDecision,
    ExecutionResult, PolicySelection, ROUTER_VERSION, RouteRequest, RoutingDecision,
    SCORER_VERSION, SandboxExecutionPlan, THREAD_SCHEMA_VERSION, plan_for_candidate,
    seal_material_for_candidate,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThreadCandidateAction {
    pub raw_action: CandidateAction,
    pub final_action: CandidateAction,
    #[serde(default)]
    pub certificate: Option<crate::CertificateEvidence>,
    #[serde(default)]
    pub budget_certificate: Option<crate::BudgetCertificate>,
    pub policy_trace: Vec<crate::PolicyTraceEntry>,
    pub mutation_ledger: Vec<crate::ActionMutation>,
    #[serde(default)]
    pub budget_trace: Option<crate::BudgetTrace>,
    #[serde(default)]
    pub admission_trace: Option<crate::AdmissionTrace>,
    #[serde(default)]
    pub admission_trace_hash: Option<String>,
    #[serde(default)]
    pub effect_vector: Option<crate::EffectVector>,
    pub short_circuit: Option<String>,
    pub admission_score: Option<crate::AdmissionScore>,
    pub decision: crate::DecisionType,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThreadRecord {
    pub schema_version: String,
    pub thread_id: String,
    pub timestamp: String,
    pub router_version: String,
    pub scorer_version: String,
    pub pricing_policy_name: String,
    pub pricing_policy_version: String,
    pub policy_chain_name: String,
    pub policy_chain_revision: String,
    pub action_registry_version: String,
    pub config_version: String,
    pub seal_seed: u64,
    pub seal_id: String,
    pub seal_status: String,
    pub state: Value,
    pub host_action: Option<crate::ActionType>,
    pub raw_candidates: Vec<CandidateAction>,
    pub policy_filtered_candidates: Vec<ThreadCandidateAction>,
    pub scored_candidates: Vec<ThreadCandidateAction>,
    pub selected_action: Option<crate::ActionType>,
    pub selected_candidate_index: Option<usize>,
    pub rejected_actions: Vec<ThreadCandidateAction>,
    pub budget_state: crate::BudgetState,
    #[serde(default)]
    pub sandbox_plan: Option<SandboxExecutionPlan>,
    pub execution_result: Option<ExecutionResult>,
    pub fallback_triggers: Vec<String>,
    #[serde(default)]
    pub evaluation_context: crate::EvaluationContext,
    #[serde(default)]
    pub evaluation_outcomes: Vec<crate::EvaluationOutcome>,
    #[serde(default)]
    pub provider_costs: Vec<crate::ProviderCost>,
    #[serde(default)]
    pub competitor_results: Vec<crate::CompetitorResult>,
    pub metadata: BTreeMap<String, Value>,
}

impl ThreadRecord {
    pub fn from_route_request(
        request: &RouteRequest,
        decision: &mut RoutingDecision,
        selection: &PolicySelection,
        thread_id: Option<String>,
        timestamp: Option<String>,
    ) -> Result<Self, String> {
        let thread_id = thread_id.unwrap_or_else(new_thread_id);
        decision.thread_id = Some(thread_id.clone());
        let raw_candidates = request.candidates.clone();
        let evaluated = raw_candidates
            .iter()
            .cloned()
            .zip(decision.candidate_decisions.iter().cloned())
            .map(|(candidate, evaluation)| trace_candidate(candidate, evaluation))
            .collect::<Vec<_>>();
        let policy_filtered_candidates = evaluated
            .iter()
            .filter(|candidate| candidate.short_circuit.is_none())
            .cloned()
            .collect::<Vec<_>>();
        let scored_candidates = evaluated
            .iter()
            .filter(|candidate| candidate.admission_trace.is_some())
            .cloned()
            .collect::<Vec<_>>();
        let rejected_actions = evaluated
            .iter()
            .filter(|candidate| candidate.decision != crate::DecisionType::Execute)
            .cloned()
            .collect::<Vec<_>>();
        let selected_candidate_index = evaluated.iter().position(|candidate| {
            Some(candidate.final_action.action_type) == decision.action_type
                && candidate.decision == decision.decision
        });
        let seal_id = decision
            .seal_id
            .clone()
            .unwrap_or_else(|| seal_id_for(request, decision, selection));
        let sandbox_plan = selected_candidate_for(decision)
            .map(|candidate| plan_for_candidate(&request.state, candidate))
            .transpose()?
            .flatten();
        let mut metadata = BTreeMap::new();
        metadata.insert("router".to_string(), json!("RouterV1"));
        metadata.insert(
            "admission_engine".to_string(),
            json!(ADMISSION_ENGINE_VERSION),
        );
        let evaluation_context = evaluation_context_from_state(&request.state, &thread_id);
        let evaluation_outcomes = evaluation_outcomes_from_state(
            &request.state,
            &raw_candidates,
            evaluation_context.expected_action,
        );
        let provider_costs = provider_costs_from_state(&request.state);
        let competitor_results = competitor_results_from_state(&request.state);
        Ok(Self {
            schema_version: THREAD_SCHEMA_VERSION.to_string(),
            thread_id,
            timestamp: timestamp.unwrap_or_else(now_iso),
            router_version: ROUTER_VERSION.to_string(),
            scorer_version: SCORER_VERSION.to_string(),
            pricing_policy_name: request
                .config
                .pricing_context
                .pricing_policy
                .as_str()
                .to_string(),
            pricing_policy_version: request
                .config
                .pricing_context
                .pricing_policy_version
                .clone(),
            policy_chain_name: selection.chain_name.clone(),
            policy_chain_revision: selection.chain_revision.clone(),
            action_registry_version: ACTION_REGISTRY_VERSION.to_string(),
            config_version: request.config.config_version.clone(),
            seal_seed: request.config.seal_seed,
            seal_id,
            seal_status: "decision_sealed".to_string(),
            state: request.state.clone(),
            host_action: request.host_action,
            raw_candidates,
            policy_filtered_candidates,
            scored_candidates,
            selected_action: decision.action_type,
            selected_candidate_index,
            rejected_actions,
            budget_state: request.config.pricing_context.budget_state.clone(),
            sandbox_plan,
            execution_result: None,
            fallback_triggers: Vec::new(),
            evaluation_context,
            evaluation_outcomes,
            provider_costs,
            competitor_results,
            metadata,
        })
    }
}

fn evaluation_context_from_state(state: &Value, thread_id: &str) -> crate::EvaluationContext {
    let raw = state
        .get("evaluation_context")
        .or_else(|| state.get("eval_context"))
        .and_then(Value::as_object);
    crate::EvaluationContext {
        condition_id: string_field(raw, state, "condition_id"),
        scenario_id: string_field(raw, state, "scenario_id")
            .or_else(|| string_field(raw, state, "id")),
        decision_id: string_field(raw, state, "decision_id")
            .or_else(|| Some(thread_id.to_string())),
        benchmark_suite: string_field(raw, state, "benchmark_suite"),
        arm_id: string_field(raw, state, "arm_id"),
        expected_action: action_field(raw, state, "expected_action"),
    }
}

fn evaluation_outcomes_from_state(
    state: &Value,
    candidates: &[CandidateAction],
    expected_action: Option<crate::ActionType>,
) -> Vec<crate::EvaluationOutcome> {
    if let Some(raw) = state
        .get("evaluation_outcomes")
        .or_else(|| state.get("eval_outcomes"))
    {
        if let Ok(outcomes) = serde_json::from_value::<Vec<crate::EvaluationOutcome>>(raw.clone()) {
            return outcomes;
        }
        if let Some(values) = raw.as_object() {
            let mut outcomes = Vec::new();
            for (action_type, value) in values {
                let Ok(action_type) =
                    serde_json::from_value::<crate::ActionType>(Value::String(action_type.clone()))
                else {
                    continue;
                };
                let mut outcome = value.clone();
                if let Value::Object(ref mut object) = outcome {
                    object.insert("action_type".to_string(), json!(action_type));
                }
                if let Ok(parsed) = serde_json::from_value::<crate::EvaluationOutcome>(outcome) {
                    outcomes.push(parsed);
                }
            }
            if !outcomes.is_empty() {
                outcomes.sort_by_key(|outcome| outcome.action_type);
                return outcomes;
            }
        }
    }

    let Some(expected_action) = expected_action else {
        return Vec::new();
    };
    let mut actions = candidates
        .iter()
        .map(|candidate| candidate.action_type)
        .collect::<Vec<_>>();
    actions.sort();
    actions.dedup();
    actions
        .into_iter()
        .map(|action_type| {
            let success = action_type == expected_action;
            crate::EvaluationOutcome {
                action_type,
                completed: Some(success),
                realized_reward: Some(if success { 1.0 } else { 0.0 }),
                expected_reward: Some(if success { 1.0 } else { 0.0 }),
                realized_cost: None,
                expected_cost: None,
                information_gain: None,
                content_hash: None,
                memory_unique: None,
            }
        })
        .collect()
}

fn provider_costs_from_state(state: &Value) -> Vec<crate::ProviderCost> {
    state
        .get("provider_costs")
        .or_else(|| state.get("evaluation_provider_costs"))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn competitor_results_from_state(state: &Value) -> Vec<crate::CompetitorResult> {
    state
        .get("competitor_results")
        .or_else(|| state.get("evaluation_competitor_results"))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn string_field(
    raw: Option<&serde_json::Map<String, Value>>,
    state: &Value,
    key: &str,
) -> Option<String> {
    raw.and_then(|values| values.get(key))
        .or_else(|| state.get(key))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn action_field(
    raw: Option<&serde_json::Map<String, Value>>,
    state: &Value,
    key: &str,
) -> Option<crate::ActionType> {
    raw.and_then(|values| values.get(key))
        .or_else(|| state.get(key))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn trace_candidate(
    candidate: CandidateAction,
    evaluation: CandidateDecision,
) -> ThreadCandidateAction {
    let certificate = evaluation
        .final_candidate
        .certificate
        .clone()
        .or_else(|| candidate.certificate.clone());
    let budget_certificate = evaluation
        .final_candidate
        .budget_certificate
        .clone()
        .or_else(|| candidate.budget_certificate.clone());
    ThreadCandidateAction {
        raw_action: candidate,
        final_action: evaluation.final_candidate,
        certificate,
        budget_certificate,
        policy_trace: evaluation.policy_trace,
        mutation_ledger: evaluation.mutation_ledger,
        budget_trace: evaluation.budget_trace,
        admission_trace: evaluation.admission_trace,
        admission_trace_hash: evaluation.admission_trace_hash,
        effect_vector: evaluation.effect_vector,
        short_circuit: evaluation.short_circuit,
        admission_score: evaluation.admission_score,
        decision: evaluation.decision,
        reason: evaluation.reason,
    }
}

pub fn seal_id_for(
    request: &RouteRequest,
    decision: &RoutingDecision,
    selection: &PolicySelection,
) -> String {
    let sandbox_plan = selected_candidate_for(decision)
        .map(|candidate| seal_material_for_candidate(&request.state, candidate))
        .unwrap_or(Value::Null);
    let payload = json!({
        "schema_version": THREAD_SCHEMA_VERSION,
        "router_version": ROUTER_VERSION,
        "scorer_version": SCORER_VERSION,
        "pricing_policy_name": request.config.pricing_context.pricing_policy.as_str(),
        "pricing_policy_version": request.config.pricing_context.pricing_policy_version,
        "policy_chain_name": selection.chain_name,
        "policy_chain_revision": selection.chain_revision,
        "registry_version": ACTION_REGISTRY_VERSION,
        "config": request.config,
        "state": request.state,
        "candidates": request.candidates,
        "host_action": request.host_action,
        "selected_action": decision.action_type,
        "decision": decision.decision,
        "sandbox_plan": sandbox_plan,
    });
    let serialized = serde_json::to_string(&payload).unwrap_or_default();
    format!("seal_{:016x}", fnv1a64(serialized.as_bytes()))
}

fn selected_candidate_for(decision: &RoutingDecision) -> Option<&CandidateAction> {
    decision
        .candidate_decisions
        .iter()
        .find(|candidate| {
            Some(candidate.action_type) == decision.action_type
                && candidate.decision == decision.decision
        })
        .map(|candidate| &candidate.final_candidate)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn redact_secrets(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let normalized = key.to_lowercase().replace('-', "_");
                    let redacted = if sensitive_key(&normalized) {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        redact_secrets(value)
                    };
                    (key, redacted)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_secrets).collect()),
        value => value,
    }
}

fn sensitive_key(key: &str) -> bool {
    let exact = [
        "authorization",
        "cookie",
        "password",
        "private_key",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
    ]
    .contains(&key);
    exact
        || key.ends_with("_token")
        || key.ends_with("-token")
        || key.contains("authorization")
        || key.contains("api_key")
        || key.contains("private_key")
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn new_thread_id() -> String {
    format!("thread_{}", Uuid::new_v4().simple())
}
