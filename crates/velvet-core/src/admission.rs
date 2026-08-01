use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ActionType, AdmissionConstraintResult, AdmissionDecision, AdmissionTrace, CandidateAction,
    CapabilityClass, CapabilityRegistry, ConstraintSeverity, CostBound, DataClass, DecisionType,
    EffectVector, LatencyBound, ObjectiveComponents, ObjectiveWeights, Reversibility, RiskBound,
    SideEffectClass, SourceToSinkFlow, UtilityBound, default_effect_for_action, domain_hash_bytes,
    domain_hash_value, objective_components, source_to_sink_constraint,
};

pub const NORMALIZED_CANDIDATE_SCHEMA_VERSION: &str = "velvet.normalized_candidate.v1";
pub const ADMISSION_ENGINE_VERSION: &str = "velvet.admission_engine.v1";
pub const DEFAULT_CALIBRATION_SET_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AdmissionConfig {
    pub schema_version: String,
    pub objective_weights: ObjectiveWeights,
    pub utility_confidence_bps: u16,
    pub cost_confidence_bps: u16,
    pub risk_confidence_bps: u16,
    pub direct_answer_fallback: bool,
    pub allow_legacy_heuristic_in_dev: bool,
    pub development_mode: bool,
    pub capability_registry_hash: Option<String>,
    pub policy_bundle_hash: Option<String>,
    pub calibration_set_hash: String,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            schema_version: "velvet.admission_config.v1".to_string(),
            objective_weights: ObjectiveWeights::default(),
            utility_confidence_bps: 9_500,
            cost_confidence_bps: 9_500,
            risk_confidence_bps: 9_500,
            direct_answer_fallback: true,
            allow_legacy_heuristic_in_dev: false,
            development_mode: false,
            capability_registry_hash: None,
            policy_bundle_hash: None,
            calibration_set_hash: DEFAULT_CALIBRATION_SET_HASH.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCandidate {
    pub schema_version: String,
    pub action_type: ActionType,
    pub canonical_bytes: Vec<u8>,
    pub candidate_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetConstraintStatus {
    NotRequired,
    RequiredMissing,
    Valid,
    Blocks(String),
    Invalid(String),
    NonCertifying(String),
}

#[derive(Debug, Clone)]
pub struct AdmissionEvaluationInput<'a> {
    pub candidate: &'a CandidateAction,
    pub request_state: &'a Value,
    pub config: &'a AdmissionConfig,
    pub registry: &'a CapabilityRegistry,
    pub request_hash: String,
    pub policy_bundle_hash: String,
    pub tool_schema_hash: String,
    pub policy_allowed: bool,
    pub policy_decision: Option<DecisionType>,
    pub policy_reason: Option<String>,
    pub policy_trace_hash: String,
    pub budget_status: BudgetConstraintStatus,
    pub approval_present: bool,
    pub warrant_valid: bool,
    pub permit_eligible: bool,
    pub tenant_state_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionCandidateEvaluation {
    pub normalized: NormalizedCandidatePublic,
    pub effect_vector: EffectVector,
    pub effect_vector_hash: String,
    pub trace: AdmissionTrace,
    pub trace_hash: String,
    pub decision_type: DecisionType,
    pub admission_decision: AdmissionDecision,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NormalizedCandidatePublic {
    pub schema_version: String,
    pub action_type: ActionType,
    pub candidate_hash: String,
}

pub struct AdmissionEngine;

impl AdmissionEngine {
    pub fn normalize_candidate(candidate: &CandidateAction) -> NormalizedCandidate {
        let public = normalized_candidate_value(candidate);
        let canonical = crate::admission_trace::canonical_json(&public);
        let candidate_hash =
            domain_hash_bytes("Velvet:AdmissionCandidate:v1", canonical.as_bytes());
        NormalizedCandidate {
            schema_version: NORMALIZED_CANDIDATE_SCHEMA_VERSION.to_string(),
            action_type: candidate.action_type,
            canonical_bytes: canonical.into_bytes(),
            candidate_hash,
        }
    }

    pub fn evaluate(input: AdmissionEvaluationInput<'_>) -> AdmissionCandidateEvaluation {
        let normalized = Self::normalize_candidate(input.candidate);
        let effect_vector = infer_effect_vector(
            input.candidate,
            input.request_state,
            input.registry,
            &input.budget_status,
        );
        let effect_vector_value =
            serde_json::to_value(&effect_vector).expect("effect vector serializes");
        let effect_vector_hash = domain_hash_value("Velvet:EffectVector:v1", &effect_vector_value);
        let objective = objective_components(&effect_vector, input.config.objective_weights);
        let constraints = hard_constraints(&input, &effect_vector, &normalized.candidate_hash);
        let admission_decision = selected_admission_decision(
            input.candidate.action_type,
            &constraints,
            &effect_vector,
            &input.budget_status,
        );
        let deterministic_replay_inputs_hash = deterministic_replay_inputs_hash(
            &normalized,
            &effect_vector_hash,
            &constraints,
            &objective,
            &input,
        );
        let trace = AdmissionTrace {
            schema_version: crate::ADMISSION_TRACE_SCHEMA_VERSION.to_string(),
            candidate_hash: normalized.candidate_hash.clone(),
            request_hash: input.request_hash,
            policy_bundle_hash: input.policy_bundle_hash,
            tool_schema_hash: input.tool_schema_hash,
            capability_registry_hash: input
                .config
                .capability_registry_hash
                .clone()
                .unwrap_or_else(|| {
                    domain_hash_value(
                        "Velvet:CapabilityRegistry:v1",
                        &serde_json::to_value(input.registry)
                            .expect("capability registry serializes"),
                    )
                }),
            effect_vector_hash: effect_vector_hash.clone(),
            utility_model_version: ADMISSION_ENGINE_VERSION.to_string(),
            risk_model_version: effect_vector.model_version.clone(),
            calibration_set_hash: input.config.calibration_set_hash.clone(),
            hard_constraints: constraints,
            objective_components: objective,
            selected_decision: admission_decision,
            selected_reason: selected_reason(admission_decision, &effect_vector),
            deterministic_replay_inputs_hash,
        };
        let trace_hash = trace.hash();
        AdmissionCandidateEvaluation {
            normalized: NormalizedCandidatePublic {
                schema_version: normalized.schema_version,
                action_type: normalized.action_type,
                candidate_hash: normalized.candidate_hash,
            },
            effect_vector,
            effect_vector_hash,
            decision_type: decision_type(admission_decision, input.candidate.action_type),
            admission_decision,
            trace,
            trace_hash,
        }
    }
}

fn normalized_candidate_value(candidate: &CandidateAction) -> Value {
    let mut metadata = candidate.metadata.clone();
    for volatile in [
        "timestamp",
        "timestamp_input",
        "created_at",
        "observed_at",
        "decided_at",
        "used_at",
        "approval_receipt",
        "velvet_approval_receipt",
        "decision_latency_ms",
    ] {
        metadata.remove(volatile);
    }
    let mut parameters = candidate.parameters.clone();
    for volatile in [
        "timestamp",
        "timestamp_input",
        "created_at",
        "observed_at",
        "decided_at",
        "used_at",
        "approval_receipt",
        "velvet_approval_receipt",
    ] {
        parameters.remove(volatile);
    }
    json!({
        "schema_version": NORMALIZED_CANDIDATE_SCHEMA_VERSION,
        "action_type": candidate.action_type,
        "description": candidate.description,
        "source": candidate.source,
        "cost_overrides": candidate.cost_overrides,
        "risk_overrides": candidate.risk_overrides,
        "metadata": metadata,
        "parameters": parameters,
    })
}

fn infer_effect_vector(
    candidate: &CandidateAction,
    state: &Value,
    registry: &CapabilityRegistry,
    budget_status: &BudgetConstraintStatus,
) -> EffectVector {
    let descriptor = registry.descriptor_for(candidate);
    let mut effect = default_effect_for_action(candidate.action_type);
    effect.capability_class = descriptor.capability_class;
    effect.side_effect_class = descriptor.side_effect_class;
    effect.data_classes_read = descriptor.data_classes_read;
    effect.data_classes_written = descriptor.data_classes_written;
    effect.write_footprint = descriptor.write_footprint;
    if candidate.action_type == ActionType::CallTool {
        effect.approval_required = descriptor.approval_required;
        effect.warrant_required = descriptor.warrant_required;
        effect.budget_required = descriptor.budget_required;
    } else {
        effect.approval_required |= descriptor.approval_required;
        effect.warrant_required |= descriptor.warrant_required;
        effect.budget_required |= descriptor.budget_required;
    }
    if explicit_non_budget_candidate(candidate, &effect) {
        effect.budget_required = false;
    }
    effect.utility_bound = utility_bound(candidate, state);
    effect.cost_bound = cost_bound(candidate, &effect, budget_status);
    effect.latency_bound = LatencyBound::low();
    effect.risk_bound = risk_bound(candidate, &effect);
    effect.reversibility = reversibility_for_effect(&effect);
    effect.source_to_sink_flows = source_to_sink_flows(candidate, &effect);
    effect.inference_evidence = inference_evidence(candidate, &descriptor.source, budget_status);
    effect
}

fn explicit_non_budget_candidate(candidate: &CandidateAction, effect: &EffectVector) -> bool {
    let explicitly_non_budget = candidate.metadata_truthy("non_budget_affecting")
        || candidate.parameter_truthy("non_budget_affecting")
        || candidate.metadata.get("budget_affecting") == Some(&Value::Bool(false))
        || candidate.parameters.get("budget_affecting") == Some(&Value::Bool(false));
    explicitly_non_budget
        && !candidate.metadata_truthy("budget_affecting")
        && !candidate.parameter_truthy("budget_affecting")
        && usd_estimate(candidate).is_none()
        && !candidate
            .cost_overrides
            .get("money")
            .is_some_and(|value| *value > 0.0)
        && !matches!(
            effect.capability_class,
            CapabilityClass::Unknown
                | CapabilityClass::ExternalWrite
                | CapabilityClass::FinancialTransaction
                | CapabilityClass::CredentialAccess
                | CapabilityClass::CodeExecution
                | CapabilityClass::DataExport
                | CapabilityClass::InfrastructureMutation
        )
}

fn utility_bound(candidate: &CandidateAction, state: &Value) -> UtilityBound {
    let expected = candidate.expected_improvement.unwrap_or_else(|| {
        if candidate.action_type == ActionType::AnswerDirectly {
            if state.get("freshness_required").and_then(Value::as_bool) == Some(true) {
                2_000.0 / 10_000.0
            } else {
                3_500.0 / 10_000.0
            }
        } else if matches!(
            candidate.action_type,
            ActionType::ReadFile | ActionType::InspectCode | ActionType::RetrieveContext
        ) {
            5_500.0 / 10_000.0
        } else if candidate.action_type == ActionType::SearchWeb {
            5_000.0 / 10_000.0
        } else if candidate.action_type == ActionType::AskUser {
            if state.get("ambiguous").and_then(Value::as_bool) == Some(true)
                || state.get("missing_critical_info").and_then(Value::as_bool) == Some(true)
            {
                9_000.0 / 10_000.0
            } else {
                2_000.0 / 10_000.0
            }
        } else {
            3_000.0 / 10_000.0
        }
    });
    let confidence = candidate.confidence.unwrap_or(0.75).clamp(0.0, 1.0);
    let expected_bps = (expected.clamp(0.0, 1.0) * 10_000.0).round() as i32;
    let uncertainty_bps = ((1.0 - confidence) * 2_500.0).round() as i32;
    UtilityBound {
        lower_bps: (expected_bps - uncertainty_bps).max(0),
        expected_bps,
        upper_bps: (expected_bps + uncertainty_bps).min(10_000),
        confidence_bps: (confidence * 10_000.0).round() as u16,
    }
}

fn cost_bound(
    candidate: &CandidateAction,
    effect: &EffectVector,
    budget_status: &BudgetConstraintStatus,
) -> CostBound {
    if let Some(usd_estimate) = usd_estimate(candidate) {
        let expected = usd_to_microusd_ceil(usd_estimate);
        let upper = expected.saturating_mul(2).max(expected.saturating_add(1));
        return CostBound {
            lower_microusd: 0,
            expected_microusd: expected,
            upper_microusd: upper,
            confidence_bps: 8_000,
        };
    }
    if candidate.metadata_truthy("non_budget_affecting")
        && !effect.is_high_privilege()
        && matches!(budget_status, BudgetConstraintStatus::NotRequired)
    {
        return CostBound::free();
    }
    if effect.budget_required || effect.capability_class == CapabilityClass::Unknown {
        return CostBound::conservative_unknown();
    }
    CostBound {
        lower_microusd: 0,
        expected_microusd: 1_000,
        upper_microusd: 10_000,
        confidence_bps: 8_500,
    }
}

fn risk_bound(candidate: &CandidateAction, effect: &EffectVector) -> RiskBound {
    let mut risk = if effect.capability_class == CapabilityClass::Unknown {
        RiskBound::high_unknown()
    } else {
        RiskBound::low()
    };
    if let Some(risk_class) = candidate.metadata.get("risk_class").and_then(Value::as_str) {
        match risk_class {
            "high" => {
                risk.privacy_risk_bps = risk.privacy_risk_bps.max(6_500);
                risk.integrity_risk_bps = risk.integrity_risk_bps.max(7_500);
                risk.financial_risk_bps = risk.financial_risk_bps.max(7_500);
                risk.compliance_risk_bps = risk.compliance_risk_bps.max(6_500);
            }
            "medium" => {
                risk.privacy_risk_bps = risk.privacy_risk_bps.max(3_500);
                risk.integrity_risk_bps = risk.integrity_risk_bps.max(3_500);
            }
            _ => {}
        }
    }
    if matches!(
        effect.capability_class,
        CapabilityClass::CredentialAccess | CapabilityClass::DataExport
    ) || effect.data_classes_read.iter().any(|class| {
        matches!(
            class,
            DataClass::PersonalData | DataClass::Secret | DataClass::Regulated | DataClass::Unknown
        )
    }) {
        risk.privacy_risk_bps = risk.privacy_risk_bps.max(8_000);
        risk.compliance_risk_bps = risk.compliance_risk_bps.max(7_000);
    }
    if matches!(
        effect.side_effect_class,
        SideEffectClass::Irreversible
            | SideEffectClass::ExternallyVisible
            | SideEffectClass::Regulated
    ) {
        risk.integrity_risk_bps = risk.integrity_risk_bps.max(6_500);
    }
    risk
}

fn reversibility_for_effect(effect: &EffectVector) -> Reversibility {
    match effect.side_effect_class {
        SideEffectClass::None => Reversibility::None,
        SideEffectClass::Reversible => Reversibility::Reversible,
        SideEffectClass::Compensatable | SideEffectClass::ExternallyVisible => {
            Reversibility::Partial
        }
        SideEffectClass::Irreversible | SideEffectClass::Regulated => Reversibility::Irreversible,
    }
}

fn source_to_sink_flows(
    candidate: &CandidateAction,
    effect: &EffectVector,
) -> Vec<SourceToSinkFlow> {
    if candidate.action_type != ActionType::CallTool || !effect.is_high_privilege() {
        return Vec::new();
    }
    effect
        .data_classes_read
        .iter()
        .map(|class| SourceToSinkFlow {
            source_data_class: *class,
            sink: crate::capabilities::tool_key(candidate).unwrap_or_else(|| "unknown".to_string()),
            sink_capability_class: effect.capability_class,
        })
        .collect()
}

fn inference_evidence(
    candidate: &CandidateAction,
    descriptor_source: &str,
    budget_status: &BudgetConstraintStatus,
) -> BTreeMap<String, Value> {
    let mut evidence = BTreeMap::new();
    evidence.insert("descriptor_source".to_string(), json!(descriptor_source));
    evidence.insert("action_type".to_string(), json!(candidate.action_type));
    if let Some(tool_key) = crate::capabilities::tool_key(candidate) {
        evidence.insert(
            "tool_key_hash".to_string(),
            json!(domain_hash_value("Velvet:ToolKey:v1", &json!(tool_key))),
        );
    }
    evidence.insert(
        "budget_status".to_string(),
        json!(format!("{budget_status:?}")),
    );
    if let Some(arguments) = candidate.parameters.get("arguments") {
        evidence.insert(
            "arguments_hash".to_string(),
            json!(domain_hash_value("Velvet:Arguments:v1", arguments)),
        );
    }
    evidence
}

fn hard_constraints(
    input: &AdmissionEvaluationInput<'_>,
    effect: &EffectVector,
    candidate_hash: &str,
) -> Vec<AdmissionConstraintResult> {
    let mut constraints = vec![
        AdmissionConstraintResult::pass(
            "schema_valid",
            "schema_validated_before_admission",
            &json!({"candidate_hash": candidate_hash}),
        ),
        policy_constraint(input),
        capability_constraint(effect),
        budget_constraint(&input.budget_status, effect.budget_required),
        approval_constraint(effect, input.approval_present),
        warrant_constraint(effect, input.warrant_valid),
        permit_constraint(input.permit_eligible),
        tenant_state_constraint(input.tenant_state_valid),
        source_to_sink_constraint(effect),
    ];
    constraints.sort_by(|left, right| left.constraint_id.cmp(&right.constraint_id));
    constraints
}

fn policy_constraint(input: &AdmissionEvaluationInput<'_>) -> AdmissionConstraintResult {
    if input.policy_allowed {
        AdmissionConstraintResult::pass(
            "policy_allowed",
            "policy_allowed",
            &json!({"policy_trace_hash": input.policy_trace_hash}),
        )
    } else {
        let severity = match input.policy_decision {
            Some(DecisionType::Escalate | DecisionType::AskApproval | DecisionType::Delay) => {
                ConstraintSeverity::Defer
            }
            _ => ConstraintSeverity::Block,
        };
        AdmissionConstraintResult::fail(
            "policy_allowed",
            severity,
            "policy_denied",
            input
                .policy_reason
                .clone()
                .unwrap_or_else(|| "Policy denied the candidate.".to_string()),
            &json!({"policy_trace_hash": input.policy_trace_hash}),
        )
    }
}

fn capability_constraint(effect: &EffectVector) -> AdmissionConstraintResult {
    if effect.capability_class == CapabilityClass::Unknown {
        AdmissionConstraintResult::fail(
            "capability_allowed",
            ConstraintSeverity::Defer,
            "unknown_capability",
            "Unknown capability requires approval before execution.",
            &json!({"capability_class": effect.capability_class}),
        )
    } else {
        AdmissionConstraintResult::pass(
            "capability_allowed",
            "capability_known",
            &json!({"capability_class": effect.capability_class}),
        )
    }
}

fn budget_constraint(
    status: &BudgetConstraintStatus,
    effect_budget_required: bool,
) -> AdmissionConstraintResult {
    match status {
        BudgetConstraintStatus::NotRequired if effect_budget_required => {
            AdmissionConstraintResult::fail(
                "budget_reserved",
                ConstraintSeverity::Defer,
                "budget_required",
                "Budget-affecting action requires a valid budget reservation.",
                &json!({"budget_status": "required_missing"}),
            )
        }
        BudgetConstraintStatus::NotRequired | BudgetConstraintStatus::Valid => {
            AdmissionConstraintResult::pass(
                "budget_reserved",
                "budget_valid_or_not_required",
                &json!({"budget_status": format!("{status:?}")}),
            )
        }
        BudgetConstraintStatus::RequiredMissing => AdmissionConstraintResult::fail(
            "budget_reserved",
            ConstraintSeverity::Defer,
            "budget_required",
            "Budget-affecting action requires a valid budget reservation.",
            &json!({"budget_status": "required_missing"}),
        ),
        BudgetConstraintStatus::Blocks(reason) => AdmissionConstraintResult::fail(
            "budget_reserved",
            ConstraintSeverity::Block,
            "budget_blocks",
            reason,
            &json!({"budget_status": "blocks"}),
        ),
        BudgetConstraintStatus::Invalid(reason) => AdmissionConstraintResult::fail(
            "budget_reserved",
            ConstraintSeverity::Block,
            "budget_invalid",
            reason,
            &json!({"budget_status": "invalid"}),
        ),
        BudgetConstraintStatus::NonCertifying(reason) => AdmissionConstraintResult::fail(
            "budget_reserved",
            ConstraintSeverity::Block,
            "budget_non_certifying",
            reason,
            &json!({"budget_status": "non_certifying"}),
        ),
    }
}

fn approval_constraint(effect: &EffectVector, approval_present: bool) -> AdmissionConstraintResult {
    if !effect.approval_required || approval_present {
        return AdmissionConstraintResult::pass(
            "approval_valid",
            "approval_valid_or_not_required",
            &json!({"approval_required": effect.approval_required, "approval_present": approval_present}),
        );
    }
    AdmissionConstraintResult::fail(
        "approval_valid",
        ConstraintSeverity::Defer,
        "approval_required",
        "Valid approval is required before execution.",
        &json!({"approval_required": true, "approval_present": false}),
    )
}

fn warrant_constraint(effect: &EffectVector, warrant_valid: bool) -> AdmissionConstraintResult {
    if !effect.warrant_required || warrant_valid {
        AdmissionConstraintResult::pass(
            "warrant_valid",
            "warrant_valid_or_not_required",
            &json!({"warrant_required": effect.warrant_required, "warrant_valid": warrant_valid}),
        )
    } else {
        AdmissionConstraintResult::fail(
            "warrant_valid",
            ConstraintSeverity::Defer,
            "warrant_required",
            "Execution requires a valid warrant.",
            &json!({"warrant_required": true, "warrant_valid": false}),
        )
    }
}

fn permit_constraint(permit_eligible: bool) -> AdmissionConstraintResult {
    if permit_eligible {
        AdmissionConstraintResult::pass(
            "permit_eligible",
            "permit_eligible",
            &json!({"permit_eligible": true}),
        )
    } else {
        AdmissionConstraintResult::fail(
            "permit_eligible",
            ConstraintSeverity::Block,
            "permit_ineligible",
            "Candidate is not eligible for an execution permit.",
            &json!({"permit_eligible": false}),
        )
    }
}

fn tenant_state_constraint(valid: bool) -> AdmissionConstraintResult {
    if valid {
        AdmissionConstraintResult::pass(
            "tenant_state_valid",
            "tenant_state_valid",
            &json!({"tenant_state_valid": true}),
        )
    } else {
        AdmissionConstraintResult::fail(
            "tenant_state_valid",
            ConstraintSeverity::Block,
            "tenant_state_invalid",
            "Tenant or environment state is not valid for execution.",
            &json!({"tenant_state_valid": false}),
        )
    }
}

fn selected_admission_decision(
    action_type: ActionType,
    constraints: &[AdmissionConstraintResult],
    effect: &EffectVector,
    budget_status: &BudgetConstraintStatus,
) -> AdmissionDecision {
    if constraints
        .iter()
        .any(|constraint| !constraint.passed && constraint.severity == ConstraintSeverity::Block)
    {
        return AdmissionDecision::Block;
    }
    if constraints
        .iter()
        .any(|constraint| !constraint.passed && constraint.constraint_id == "approval_valid")
    {
        return AdmissionDecision::AskApproval;
    }
    if constraints
        .iter()
        .any(|constraint| !constraint.passed && constraint.severity == ConstraintSeverity::Defer)
    {
        return AdmissionDecision::Escalate;
    }
    if matches!(
        budget_status,
        BudgetConstraintStatus::Invalid(_)
            | BudgetConstraintStatus::NonCertifying(_)
            | BudgetConstraintStatus::Blocks(_)
    ) {
        return AdmissionDecision::Block;
    }
    if constraints
        .iter()
        .any(|constraint| !constraint.passed && constraint.constraint_id == "warrant_valid")
        || effect.warrant_required && !effect.approval_required
    {
        return AdmissionDecision::RequireWarrant;
    }
    if action_type == ActionType::AnswerDirectly {
        AdmissionDecision::AnswerDirectly
    } else {
        AdmissionDecision::Execute
    }
}

fn decision_type(decision: AdmissionDecision, action_type: ActionType) -> DecisionType {
    match decision {
        AdmissionDecision::Execute | AdmissionDecision::AnswerDirectly => DecisionType::Execute,
        AdmissionDecision::Block => DecisionType::Block,
        AdmissionDecision::Defer => DecisionType::Delay,
        AdmissionDecision::AskApproval => DecisionType::AskApproval,
        AdmissionDecision::Escalate => DecisionType::Escalate,
        AdmissionDecision::RequireWarrant => {
            if action_type == ActionType::ConciergeReview {
                DecisionType::Escalate
            } else {
                DecisionType::AskApproval
            }
        }
    }
}

fn selected_reason(decision: AdmissionDecision, effect: &EffectVector) -> String {
    match decision {
        AdmissionDecision::Execute => {
            "Hard constraints passed; optimizer admitted execution.".to_string()
        }
        AdmissionDecision::AnswerDirectly => {
            "Hard constraints passed; optimizer selected direct answer/no-op.".to_string()
        }
        AdmissionDecision::AskApproval => {
            "Valid approval is required before this action can execute.".to_string()
        }
        AdmissionDecision::RequireWarrant => {
            "A valid warrant is required before this action can execute.".to_string()
        }
        AdmissionDecision::Block => {
            if effect.budget_required {
                "Hard constraint failed; candidate is blocked before execution.".to_string()
            } else {
                "Candidate is blocked before execution.".to_string()
            }
        }
        AdmissionDecision::Defer => "Admission deferred for additional evidence.".to_string(),
        AdmissionDecision::Escalate => "Admission escalated for review.".to_string(),
    }
}

fn deterministic_replay_inputs_hash(
    normalized: &NormalizedCandidate,
    effect_vector_hash: &str,
    constraints: &[AdmissionConstraintResult],
    objective: &ObjectiveComponents,
    input: &AdmissionEvaluationInput<'_>,
) -> String {
    domain_hash_value(
        "Velvet:AdmissionReplayInputs:v1",
        &json!({
            "candidate_hash": normalized.candidate_hash,
            "effect_vector_hash": effect_vector_hash,
            "constraint_hashes": constraints.iter().map(|item| &item.evidence_hash).collect::<Vec<_>>(),
            "objective": objective,
            "request_hash": input.request_hash,
            "policy_bundle_hash": input.policy_bundle_hash,
            "tool_schema_hash": input.tool_schema_hash,
            "calibration_set_hash": input.config.calibration_set_hash,
        }),
    )
}

fn usd_estimate(candidate: &CandidateAction) -> Option<f64> {
    candidate
        .metadata
        .get("usd_estimate")
        .or_else(|| candidate.parameters.get("usd_estimate"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn usd_to_microusd_ceil(value: f64) -> u64 {
    ((value * 1_000_000.0).ceil()).clamp(0.0, u64::MAX as f64) as u64
}
