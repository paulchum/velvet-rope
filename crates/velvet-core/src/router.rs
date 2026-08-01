use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admission_trace::domain_hash_value;
use crate::policy::{PolicyChain, PolicyGraph, PolicySelection};
use crate::trace::{ThreadRecord, seal_id_for};
use crate::utils::{number_value, stable_hash_json};
use crate::{
    ActionType, AdmissionEngine, AdmissionEvaluationInput, BudgetCertificate,
    BudgetCertificateKind, BudgetConstraintStatus, BudgetOutcome, BudgetSafetyLedger, BudgetScope,
    BudgetTrace, CandidateAction, CandidateDecision, CandidateSource, CapProvenance,
    CapabilityRegistry, CertificateEffect, CertificateOutcome, ConcurrencyModel, DecisionType,
    DeterministicBudgetCertificate, PolicyContext, RouteRequest, RouterConfig, RoutingDecision,
};

const CERTIFICATE_EPSILON: f64 = 1e-9;
const CERTIFICATE_SCHEMA_VERSION: &str = "velvet.certificate_evidence.v2";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteWithThread {
    pub decision: RoutingDecision,
    pub thread: ThreadRecord,
}

pub fn route(state: &Value, candidates: &[CandidateAction]) -> RoutingDecision {
    route_with_policy_chain(state, candidates, &PolicyChain::empty())
}

pub fn route_with_policy_chain(
    state: &Value,
    candidates: &[CandidateAction],
    policy_chain: &PolicyChain,
) -> RoutingDecision {
    let request = RouteRequest {
        state: state.clone(),
        candidates: candidates.to_vec(),
        host_action: host_action_from_state(state),
        config: RouterConfig::from_state(state),
    };
    route_request_with_policy_chain(&request, policy_chain)
}

pub fn route_with_policy_graph(
    state: &Value,
    candidates: &[CandidateAction],
    policy_graph: &PolicyGraph,
    chain_name: &str,
) -> Result<RoutingDecision, String> {
    let chain = policy_graph
        .chain(chain_name)
        .ok_or_else(|| format!("undefined policy chain {chain_name:?}"))?;
    let request = RouteRequest {
        state: state.clone(),
        candidates: candidates.to_vec(),
        host_action: host_action_from_state(state),
        config: RouterConfig::from_state(state),
    };
    Ok(route_request_with_policy_chain_for_selection(
        &request,
        chain,
        &PolicySelection {
            chain_name: chain_name.to_string(),
            chain_revision: policy_graph.revision().to_string(),
        },
    ))
}

pub fn route_with_thread(
    state: &Value,
    candidates: &[CandidateAction],
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    route_with_thread_and_policy_chain(
        state,
        candidates,
        &PolicyChain::empty(),
        thread_id,
        timestamp,
    )
}

pub fn route_with_thread_and_policy_chain(
    state: &Value,
    candidates: &[CandidateAction],
    policy_chain: &PolicyChain,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    let request = RouteRequest {
        state: state.clone(),
        candidates: candidates.to_vec(),
        host_action: host_action_from_state(state),
        config: RouterConfig::from_state(state),
    };
    route_request_with_policy_chain_and_thread(&request, policy_chain, thread_id, timestamp)
}

pub fn route_with_policy_graph_and_thread(
    state: &Value,
    candidates: &[CandidateAction],
    policy_graph: &PolicyGraph,
    chain_name: &str,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    let chain = policy_graph
        .chain(chain_name)
        .ok_or_else(|| format!("undefined policy chain {chain_name:?}"))?;
    let request = RouteRequest {
        state: state.clone(),
        candidates: candidates.to_vec(),
        host_action: host_action_from_state(state),
        config: RouterConfig::from_state(state),
    };
    route_request_with_policy_chain_and_thread_for_selection(
        &request,
        chain,
        &PolicySelection {
            chain_name: chain_name.to_string(),
            chain_revision: policy_graph.revision().to_string(),
        },
        thread_id,
        timestamp,
    )
}

pub fn route_request(request: &RouteRequest) -> RoutingDecision {
    route_request_with_policy_chain(request, &PolicyChain::empty())
}

pub fn route_request_with_policy_chain(
    request: &RouteRequest,
    policy_chain: &PolicyChain,
) -> RoutingDecision {
    route_request_with_policy_chain_for_selection(request, policy_chain, &PolicySelection::inline())
}

fn route_request_with_policy_chain_for_selection(
    request: &RouteRequest,
    policy_chain: &PolicyChain,
    selection: &PolicySelection,
) -> RoutingDecision {
    let context = PolicyContext::from_state(&request.state);
    let raw_candidates = generated_candidates(request);
    let registry = CapabilityRegistry::from_state(&request.state);
    let candidate_decisions = raw_candidates
        .iter()
        .map(|candidate| {
            evaluate_candidate(
                candidate,
                request,
                &context,
                policy_chain,
                selection,
                &registry,
            )
        })
        .collect::<Vec<_>>();
    let mut decision = select(request.host_action, candidate_decisions);
    decision.seal_id = Some(seal_id_for(request, &decision, selection));
    decision
}

pub fn route_request_with_thread(
    request: &RouteRequest,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    route_request_with_policy_chain_and_thread(request, &PolicyChain::empty(), thread_id, timestamp)
}

pub fn route_request_with_policy_chain_and_thread(
    request: &RouteRequest,
    policy_chain: &PolicyChain,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    route_request_with_policy_chain_and_thread_for_selection(
        request,
        policy_chain,
        &PolicySelection::inline(),
        thread_id,
        timestamp,
    )
}

fn route_request_with_policy_chain_and_thread_for_selection(
    request: &RouteRequest,
    policy_chain: &PolicyChain,
    selection: &PolicySelection,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> Result<RouteWithThread, String> {
    let mut decision =
        route_request_with_policy_chain_for_selection(request, policy_chain, selection);
    let thread =
        ThreadRecord::from_route_request(request, &mut decision, selection, thread_id, timestamp)?;
    Ok(RouteWithThread { decision, thread })
}

fn generated_candidates(request: &RouteRequest) -> Vec<CandidateAction> {
    let mut candidates = request.candidates.clone();
    if candidates.is_empty()
        && let Some(host_action) = request.host_action
    {
        candidates.push(CandidateAction {
            action_type: host_action,
            description: "Generated from host/default action.".to_string(),
            certificate: None,
            budget_certificate: None,
            expected_improvement: None,
            novelty: None,
            confidence: None,
            cost_overrides: Default::default(),
            risk_overrides: Default::default(),
            metadata: Default::default(),
            source: CandidateSource::Host,
            parameters: Default::default(),
        });
    }
    if candidates.is_empty() && request.state.get("user_request").is_some() {
        candidates.push(CandidateAction {
            action_type: ActionType::AnswerDirectly,
            description: "Generated default direct-answer candidate.".to_string(),
            certificate: None,
            budget_certificate: None,
            expected_improvement: None,
            novelty: None,
            confidence: None,
            cost_overrides: Default::default(),
            risk_overrides: Default::default(),
            metadata: Default::default(),
            source: CandidateSource::Registry,
            parameters: Default::default(),
        });
    }
    if request.config.admission_config.direct_answer_fallback
        && direct_answer_fallback_applicable(&request.state)
        && !candidates.is_empty()
        && !candidates
            .iter()
            .any(|candidate| candidate.action_type == ActionType::AnswerDirectly)
    {
        candidates.push(CandidateAction {
            action_type: ActionType::AnswerDirectly,
            description: "Generated safe direct-answer/no-op fallback candidate.".to_string(),
            certificate: None,
            budget_certificate: None,
            expected_improvement: None,
            novelty: None,
            confidence: None,
            cost_overrides: Default::default(),
            risk_overrides: Default::default(),
            metadata: [
                ("budget_affecting".to_string(), serde_json::json!(false)),
                ("non_budget_affecting".to_string(), serde_json::json!(true)),
            ]
            .into_iter()
            .collect(),
            source: CandidateSource::PolicyFallback,
            parameters: Default::default(),
        });
    }
    candidates.truncate(request.config.max_candidates);
    candidates
}

fn direct_answer_fallback_applicable(state: &Value) -> bool {
    state.get("user_request").is_some()
}

fn evaluate_candidate(
    candidate: &CandidateAction,
    request: &RouteRequest,
    context: &PolicyContext,
    policy_chain: &PolicyChain,
    selection: &PolicySelection,
    registry: &CapabilityRegistry,
) -> CandidateDecision {
    let policy_evaluation = policy_chain.evaluate(candidate, context);
    let final_candidate = policy_evaluation.final_candidate.clone();
    let budget_assessment = budget_assessment(&final_candidate, request, context);
    let budget_status = admission_budget_status(&final_candidate, &budget_assessment);
    let policy_trace_hash = domain_hash_value(
        "Velvet:PolicyTrace:v1",
        &serde_json::to_value(&policy_evaluation.policy_trace)
            .unwrap_or_else(|_| serde_json::json!({"error": "policy_trace_unserializable"})),
    );
    let policy_bundle_hash = request
        .config
        .admission_config
        .policy_bundle_hash
        .clone()
        .unwrap_or_else(|| {
            domain_hash_value(
                "Velvet:PolicyBundleRef:v1",
                &serde_json::json!({
                    "chain_name": selection.chain_name,
                    "chain_revision": selection.chain_revision,
                    "policy_names": policy_chain.names(),
                }),
            )
        });
    let tool_schema_hash = tool_schema_hash_for_candidate(&final_candidate);
    let request_hash = domain_hash_value(
        "Velvet:AdmissionRequest:v1",
        &serde_json::json!({
            "state": request.state,
            "host_action": request.host_action,
            "config_version": request.config.config_version,
        }),
    );
    let admission = AdmissionEngine::evaluate(AdmissionEvaluationInput {
        candidate: &final_candidate,
        request_state: &request.state,
        config: &request.config.admission_config,
        registry,
        request_hash,
        policy_bundle_hash,
        tool_schema_hash,
        policy_allowed: policy_evaluation.decision.is_none(),
        policy_decision: policy_evaluation.decision,
        policy_reason: policy_evaluation.reason.clone(),
        policy_trace_hash,
        budget_status,
        approval_present: approval_present(&final_candidate, &request.state),
        warrant_valid: warrant_valid(&final_candidate, &request.state),
        permit_eligible: permit_eligible(&final_candidate, &request.state),
        tenant_state_valid: tenant_state_valid(&request.state),
    });
    let mut decision = admission.decision_type;
    let mut reason = admission.trace.selected_reason.clone();
    let mut short_circuit = policy_evaluation.short_circuit.clone();

    if let Some(policy_decision) = policy_evaluation.decision {
        decision = policy_decision;
        reason = policy_evaluation
            .reason
            .unwrap_or_else(|| "Policy chain short-circuited candidate admission.".to_string());
    }

    if let Some((certificate_decision, certificate_reason, circuit)) =
        certificate_constraint_decision(&final_candidate)
    {
        decision = certificate_decision;
        reason = certificate_reason;
        short_circuit = Some(circuit);
    }

    if let Some((budget_decision, budget_reason, circuit)) =
        budget_constraint_decision(&final_candidate, &budget_assessment)
    {
        decision = budget_decision;
        reason = budget_reason;
        short_circuit = Some(circuit);
    }

    CandidateDecision {
        action_type: final_candidate.action_type,
        decision,
        reason,
        final_candidate,
        policy_trace: policy_evaluation.policy_trace,
        mutation_ledger: policy_evaluation.mutation_ledger,
        short_circuit,
        budget_trace: budget_assessment.trace,
        admission_trace: Some(admission.trace),
        admission_trace_hash: Some(admission.trace_hash),
        effect_vector: Some(admission.effect_vector),
        admission_score: None,
    }
}

fn admission_budget_status(
    candidate: &CandidateAction,
    assessment: &BudgetAssessment,
) -> BudgetConstraintStatus {
    if !is_budget_affecting(candidate) {
        return BudgetConstraintStatus::NotRequired;
    }
    match &assessment.state {
        BudgetGateState::Absent => BudgetConstraintStatus::RequiredMissing,
        BudgetGateState::ValidAdmit => BudgetConstraintStatus::Valid,
        BudgetGateState::ValidBlock => {
            BudgetConstraintStatus::Blocks(assessment.block_reason.clone())
        }
        BudgetGateState::Invalid(reason) => BudgetConstraintStatus::Invalid(reason.clone()),
        BudgetGateState::NonCertifying(reason) => {
            BudgetConstraintStatus::NonCertifying(reason.clone())
        }
    }
}

fn budget_constraint_decision(
    candidate: &CandidateAction,
    assessment: &BudgetAssessment,
) -> Option<(DecisionType, String, String)> {
    match &assessment.state {
        BudgetGateState::Invalid(reason) => Some((
            DecisionType::Block,
            reason.clone(),
            "invalid_budget_certificate".to_string(),
        )),
        BudgetGateState::ValidBlock => Some((
            DecisionType::Block,
            assessment.block_reason.clone(),
            assessment.block_short_circuit.clone(),
        )),
        BudgetGateState::NonCertifying(reason) if is_budget_affecting(candidate) => Some((
            DecisionType::Block,
            format!(
                "Budget-affecting Execute requires a valid deterministic hard-cap certificate or explicitly probabilistic budget certificate with outcome Admit. Current budget certificate downgraded: {reason}."
            ),
            "budget_authorization_required".to_string(),
        )),
        BudgetGateState::Absent
        | BudgetGateState::ValidAdmit
        | BudgetGateState::NonCertifying(_) => None,
    }
}

fn certificate_constraint_decision(
    final_candidate: &CandidateAction,
) -> Option<(DecisionType, String, String)> {
    let certificate = final_candidate.certificate.as_ref()?;
    if let Some(reason) = certificate_validation_error(certificate) {
        return Some((
            DecisionType::Block,
            reason,
            "invalid_certificate".to_string(),
        ));
    }
    match certificate.outcome {
        CertificateOutcome::Lockout => Some((
            DecisionType::Block,
            "Certified Max-DE upper certificate is below the liability price.".to_string(),
            "certified_lockout".to_string(),
        )),
        CertificateOutcome::Refinement => Some((
            DecisionType::Delay,
            "Certified Max-DE candidate remains in the refinement zone.".to_string(),
            "certified_refinement".to_string(),
        )),
        CertificateOutcome::Inspect => None,
    }
}

fn tool_schema_hash_for_candidate(candidate: &CandidateAction) -> String {
    candidate
        .metadata
        .get("tool_schema_hash")
        .or_else(|| candidate.metadata.get("approved_schema_hash"))
        .or_else(|| candidate.parameters.get("tool_schema_hash"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            domain_hash_value(
                "Velvet:ToolSchema:Unavailable:v1",
                &serde_json::json!({
                    "action_type": candidate.action_type,
                    "tool_key": crate::tool_key(candidate),
                }),
            )
        })
}

fn approval_present(candidate: &CandidateAction, state: &Value) -> bool {
    candidate.metadata_truthy("approval_valid")
        || candidate.metadata_truthy("approval_present")
        || state
            .get("approval_valid")
            .or_else(|| state.get("approval_present"))
            .is_some_and(crate::utils::truthy)
}

fn warrant_valid(candidate: &CandidateAction, state: &Value) -> bool {
    candidate.metadata_truthy("warrant_valid")
        || state.get("warrant_valid").is_some_and(crate::utils::truthy)
        || !candidate.metadata_truthy("warrant_required")
}

fn permit_eligible(candidate: &CandidateAction, state: &Value) -> bool {
    if candidate.metadata.contains_key("permit_eligible") {
        return candidate.metadata_truthy("permit_eligible");
    }
    state
        .get("permit_eligible")
        .map(crate::utils::truthy)
        .unwrap_or(true)
}

fn tenant_state_valid(state: &Value) -> bool {
    state
        .get("tenant_state_valid")
        .map(crate::utils::truthy)
        .unwrap_or(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetGateState {
    Absent,
    ValidAdmit,
    ValidBlock,
    Invalid(String),
    NonCertifying(String),
}

#[derive(Debug, Clone)]
struct BudgetAssessment {
    state: BudgetGateState,
    trace: Option<BudgetTrace>,
    block_short_circuit: String,
    block_reason: String,
}

fn budget_assessment(
    candidate: &CandidateAction,
    request: &RouteRequest,
    context: &PolicyContext,
) -> BudgetAssessment {
    let Some(certificate) = budget_certificate_for(candidate) else {
        return BudgetAssessment {
            state: BudgetGateState::Absent,
            trace: None,
            block_short_circuit: "budget_block".to_string(),
            block_reason: "Budget certificate blocks the action.".to_string(),
        };
    };
    let mut trace = budget_trace_for(&certificate);
    let validation = match &certificate {
        BudgetCertificate::Deterministic(deterministic) => {
            deterministic_budget_validation(deterministic, candidate, request, context)
        }
        BudgetCertificate::Probabilistic(probabilistic) => {
            probabilistic_budget_validation(probabilistic, candidate, request, context)
        }
    };
    let block_short_circuit = match certificate.certificate_kind() {
        BudgetCertificateKind::DeterministicHardCap => "deterministic_budget_block",
        BudgetCertificateKind::CgfVille => "cgf_ville_budget_block",
        BudgetCertificateKind::MomentCantelli => "moment_cantelli_budget_block",
    }
    .to_string();
    let block_reason = match certificate.certificate_kind() {
        BudgetCertificateKind::DeterministicHardCap => {
            "Deterministic budget certificate: admitting this action would exceed the budget."
                .to_string()
        }
        BudgetCertificateKind::CgfVille => {
            "CGF/Ville high-probability budget certificate: certified envelope exceeds the remaining budget.".to_string()
        }
        BudgetCertificateKind::MomentCantelli => {
            "Moment-only Cantelli budget certificate: certified probabilistic bound exceeds the remaining budget.".to_string()
        }
    };
    match validation {
        BudgetValidation::Valid => {
            let certifying = certificate.is_certifying();
            trace.certifying = certifying;
            let state = if certifying {
                BudgetGateState::ValidAdmit
            } else if certificate.outcome() == BudgetOutcome::Block {
                BudgetGateState::ValidBlock
            } else {
                let reason = match certificate.certificate_kind() {
                    BudgetCertificateKind::DeterministicHardCap => {
                        "deterministic budget certificate does not certify spend authorization"
                            .to_string()
                    }
                    BudgetCertificateKind::CgfVille => {
                        "CGF/Ville budget certificate does not certify probabilistic spend authorization".to_string()
                    }
                    BudgetCertificateKind::MomentCantelli => {
                        "moment-only Cantelli budget certificate does not certify probabilistic spend authorization".to_string()
                    }
                };
                trace.downgrade_reason = Some(reason.clone());
                BudgetGateState::NonCertifying(reason)
            };
            BudgetAssessment {
                state,
                trace: Some(trace),
                block_short_circuit,
                block_reason,
            }
        }
        BudgetValidation::Invalid(reason) => {
            trace.validation_error = Some(reason.clone());
            BudgetAssessment {
                state: BudgetGateState::Invalid(reason),
                trace: Some(trace),
                block_short_circuit,
                block_reason,
            }
        }
        BudgetValidation::NonCertifying(reason) => {
            trace.downgrade_reason = Some(reason.clone());
            BudgetAssessment {
                state: BudgetGateState::NonCertifying(reason),
                trace: Some(trace),
                block_short_circuit,
                block_reason,
            }
        }
    }
}

enum BudgetValidation {
    Valid,
    Invalid(String),
    NonCertifying(String),
}

fn deterministic_budget_validation(
    certificate: &DeterministicBudgetCertificate,
    candidate: &CandidateAction,
    request: &RouteRequest,
    context: &PolicyContext,
) -> BudgetValidation {
    if let Some(reason) = certificate.structural_validation_error() {
        return BudgetValidation::Invalid(reason);
    }
    let action_hash = budget_action_hash(candidate);
    if certificate.action_hash != action_hash {
        return BudgetValidation::Invalid(
            "Deterministic budget certificate action_hash does not match the candidate action."
                .to_string(),
        );
    }
    let filtration_hash = expected_filtration_hash(request, context);
    if certificate.filtration_hash != filtration_hash {
        return BudgetValidation::Invalid(
            "Deterministic budget certificate filtration_hash is stale or does not match the pre-execution history."
                .to_string(),
        );
    }
    if let Some(reason) = budget_ledger_validation_error(
        BudgetCertificateKind::DeterministicHardCap,
        LedgerBinding {
            scope: certificate.scope,
            budget_limit_microusd: certificate.budget_limit_microusd,
            observed_spend_microusd: certificate.observed_spend_microusd,
            ledger_sequence_before: certificate.ledger_sequence_before,
            pre_ledger_hash: pre_ledger_hash_for_deterministic(certificate),
        },
        request,
        context,
    ) {
        return BudgetValidation::Invalid(reason);
    }
    if certificate.cap_provenance == CapProvenance::EstimateNotACap {
        return BudgetValidation::NonCertifying(
            "estimate-only input is not a hard cost cap".to_string(),
        );
    }
    if certificate.concurrency_model == ConcurrencyModel::Unserialized {
        return BudgetValidation::NonCertifying(
            "unserialized accounting cannot certify deterministic spend safety".to_string(),
        );
    }
    BudgetValidation::Valid
}

fn probabilistic_budget_validation(
    certificate: &crate::ProbabilisticBudgetCertificate,
    candidate: &CandidateAction,
    request: &RouteRequest,
    context: &PolicyContext,
) -> BudgetValidation {
    if let Some(reason) = certificate.structural_validation_error() {
        return BudgetValidation::Invalid(reason);
    }
    let action_hash = budget_action_hash(candidate);
    if certificate.action_hash != action_hash {
        return BudgetValidation::Invalid(
            "Probabilistic budget certificate action_hash does not match the candidate action."
                .to_string(),
        );
    }
    let filtration_hash = expected_filtration_hash(request, context);
    if certificate.filtration_hash != filtration_hash {
        return BudgetValidation::Invalid(
            "Probabilistic budget certificate filtration_hash is stale or does not match the pre-execution history."
                .to_string(),
        );
    }
    if let Some(reason) = budget_ledger_validation_error(
        certificate.certificate_kind,
        LedgerBinding {
            scope: certificate.scope,
            budget_limit_microusd: certificate.budget_limit_microusd,
            observed_spend_microusd: certificate.observed_spend_microusd,
            ledger_sequence_before: certificate.ledger_sequence_before,
            pre_ledger_hash: certificate.pre_ledger_hash.clone(),
        },
        request,
        context,
    ) {
        return BudgetValidation::Invalid(reason);
    }
    BudgetValidation::Valid
}

fn budget_certificate_for(candidate: &CandidateAction) -> Option<BudgetCertificate> {
    candidate.budget_certificate.clone().or_else(|| {
        candidate
            .metadata
            .get("budget_certificate")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    })
}

fn budget_trace_for(certificate: &BudgetCertificate) -> BudgetTrace {
    match certificate {
        BudgetCertificate::Deterministic(certificate) => BudgetTrace {
            certificate_hash: Some(stable_hash_json(certificate)),
            certificate_kind: Some(BudgetCertificateKind::DeterministicHardCap),
            claim_mode: Some("deterministic".to_string()),
            pre_ledger_hash: Some(pre_ledger_hash_for_deterministic(certificate)),
            ledger_sequence: Some(certificate.ledger_sequence_before),
            scope: Some(certificate.scope),
            projected_spend_usd: Some(certificate.projected_spend_usd),
            projected_spend_microusd: certificate.projected_spend_microusd,
            high_probability_bound_usd: None,
            high_probability_bound_microusd: None,
            delta_total: None,
            cost_model_id: None,
            outcome: Some(certificate.outcome),
            certifying: false,
            downgrade_reason: None,
            validation_error: None,
        },
        BudgetCertificate::Probabilistic(certificate) => BudgetTrace {
            certificate_hash: Some(stable_hash_json(certificate)),
            certificate_kind: Some(certificate.certificate_kind),
            claim_mode: Some("probabilistic".to_string()),
            pre_ledger_hash: Some(certificate.pre_ledger_hash.clone()),
            ledger_sequence: Some(certificate.ledger_sequence_before),
            scope: Some(certificate.scope),
            projected_spend_usd: None,
            projected_spend_microusd: None,
            high_probability_bound_usd: Some(certificate.high_probability_bound),
            high_probability_bound_microusd: certificate.high_probability_bound_microusd,
            delta_total: Some(certificate.delta_total),
            cost_model_id: Some(certificate.cost_model_id.clone()),
            outcome: Some(certificate.outcome),
            certifying: false,
            downgrade_reason: None,
            validation_error: None,
        },
    }
}

fn pre_ledger_hash_for_deterministic(certificate: &DeterministicBudgetCertificate) -> String {
    crate::budget_ledger_hash(
        certificate.scope,
        certificate.budget_limit_microusd.unwrap_or_default(),
        certificate.observed_spend_microusd.unwrap_or_default(),
        certificate.ledger_sequence_before,
    )
}

struct LedgerBinding {
    scope: BudgetScope,
    budget_limit_microusd: Option<u64>,
    observed_spend_microusd: Option<u64>,
    ledger_sequence_before: u64,
    pre_ledger_hash: String,
}

fn budget_ledger_validation_error(
    certificate_kind: BudgetCertificateKind,
    binding: LedgerBinding,
    request: &RouteRequest,
    context: &PolicyContext,
) -> Option<String> {
    let ledger = expected_budget_safety_ledger(request, context)?;
    let label = match certificate_kind {
        BudgetCertificateKind::DeterministicHardCap => "Deterministic",
        BudgetCertificateKind::CgfVille | BudgetCertificateKind::MomentCantelli => "Probabilistic",
    };
    if ledger.ledger_hash != ledger.recomputed_hash() {
        return Some(format!(
            "{label} budget certificate cannot use a stale or internally inconsistent budget ledger."
        ));
    }
    if ledger.scope != binding.scope {
        return Some(format!(
            "{label} budget certificate scope does not match the current budget ledger."
        ));
    }
    if Some(ledger.budget_limit_microusd) != binding.budget_limit_microusd {
        return Some(format!(
            "{label} budget certificate budget limit does not match the current budget ledger."
        ));
    }
    if Some(ledger.observed_spend_microusd) != binding.observed_spend_microusd {
        return Some(format!(
            "{label} budget certificate observed spend is stale against the current budget ledger."
        ));
    }
    if ledger.ledger_sequence != binding.ledger_sequence_before {
        return Some(format!(
            "{label} budget certificate ledger sequence is stale against the current budget ledger."
        ));
    }
    if ledger.ledger_hash != binding.pre_ledger_hash {
        return Some(format!(
            "{label} budget certificate pre_ledger_hash does not match the current budget ledger."
        ));
    }
    None
}

fn expected_budget_safety_ledger(
    request: &RouteRequest,
    context: &PolicyContext,
) -> Option<BudgetSafetyLedger> {
    request
        .state
        .get("budget_safety_ledger")
        .or_else(|| request.state.get("budget_ledger"))
        .or_else(|| context.external_observations.get("budget_safety_ledger"))
        .or_else(|| context.external_observations.get("budget_ledger"))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn expected_filtration_hash(request: &RouteRequest, context: &PolicyContext) -> String {
    string_from_state(&request.state, "budget_filtration_hash")
        .or_else(|| string_from_state(&request.state, "filtration_hash"))
        .or_else(|| string_from_value(context.external_observations.get("budget_filtration_hash")))
        .or_else(|| string_from_value(context.external_observations.get("filtration_hash")))
        .unwrap_or_else(|| stable_hash_json(&context.prior_thread))
}

fn string_from_state(state: &Value, key: &str) -> Option<String> {
    state.get(key).and_then(Value::as_str).map(str::to_string)
}

fn string_from_value(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_string)
}

fn budget_action_hash(candidate: &CandidateAction) -> String {
    #[derive(Serialize)]
    struct ActionHashMaterial<'a> {
        action_type: ActionType,
        description: &'a str,
        cost_overrides: &'a std::collections::BTreeMap<String, f64>,
        metadata: crate::JsonObject,
        parameters: &'a crate::JsonObject,
        risk_overrides: &'a std::collections::BTreeMap<String, f64>,
    }

    let mut metadata = candidate.metadata.clone();
    metadata.remove("budget_certificate");
    metadata.remove("certificate");
    stable_hash_json(&ActionHashMaterial {
        action_type: candidate.action_type,
        description: &candidate.description,
        cost_overrides: &candidate.cost_overrides,
        metadata,
        parameters: &candidate.parameters,
        risk_overrides: &candidate.risk_overrides,
    })
}

fn is_budget_affecting(candidate: &CandidateAction) -> bool {
    let has_positive_budget_signal = candidate.metadata_truthy("budget_affecting")
        || candidate.parameter_truthy("budget_affecting")
        || budget_certificate_for(candidate).is_some()
        || candidate
            .cost_overrides
            .get("money")
            .is_some_and(|value| *value > CERTIFICATE_EPSILON)
        || usd_estimate(candidate).is_some_and(|value| value > CERTIFICATE_EPSILON);
    if has_positive_budget_signal {
        return true;
    }
    if known_paid_action_kind(candidate)
        && (explicit_false(candidate.metadata.get("budget_affecting"))
            || explicit_false(candidate.parameters.get("budget_affecting")))
    {
        return true;
    }
    if explicit_false(candidate.metadata.get("budget_affecting"))
        || explicit_false(candidate.parameters.get("budget_affecting"))
        || candidate.metadata_truthy("non_budget_affecting")
        || candidate.parameter_truthy("non_budget_affecting")
    {
        return false;
    }
    if known_paid_action_kind(candidate) {
        return true;
    }
    true
}

fn known_paid_action_kind(candidate: &CandidateAction) -> bool {
    matches!(
        candidate.action_type,
        ActionType::SearchWeb | ActionType::EscalateModel
    )
}

fn explicit_false(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(false)))
}

fn usd_estimate(candidate: &CandidateAction) -> Option<f64> {
    number_from_value(candidate.metadata.get("usd_estimate"))
        .or_else(|| number_from_value(candidate.parameters.get("usd_estimate")))
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

fn number_from_value(value: Option<&Value>) -> Option<f64> {
    value
        .map(|value| number_value(Some(value), f64::NAN))
        .filter(|value| value.is_finite())
}

fn certificate_validation_error(certificate: &crate::CertificateEvidence) -> Option<String> {
    if certificate.schema_version != CERTIFICATE_SCHEMA_VERSION {
        return Some(format!(
            "Certified Max-DE evidence schema_version {:?} is unsupported.",
            certificate.schema_version
        ));
    }
    if !matches!(
        certificate.family.as_str(),
        "beta_bernoulli" | "dirichlet_categorical"
    ) {
        return Some(format!(
            "Certified Max-DE evidence uses unsupported posterior family {:?}.",
            certificate.family
        ));
    }
    if certificate.lookback_horizon == 0 && certificate.inspection_lower_bound < 0.0 {
        return Some(
            "Certified Max-DE evidence has a negative inspection lower bound.".to_string(),
        );
    }
    for (label, value) in [
        ("baseline", certificate.baseline),
        ("delight_scale", certificate.delight_scale),
        ("liability_price", certificate.liability_price),
        ("threshold", certificate.threshold),
        ("inspection_lower_bound", certificate.inspection_lower_bound),
        ("safe_upper_bound", certificate.safe_upper_bound),
    ] {
        if !value.is_finite() {
            return Some(format!(
                "Certified Max-DE evidence has a non-finite {label} value."
            ));
        }
    }
    if let Some(reserve_price) = certificate.reserve_price {
        if !reserve_price.is_finite() {
            return Some("Certified Max-DE evidence has a non-finite reserve price.".to_string());
        }
        if reserve_price < 0.0 {
            return Some("Certified Max-DE evidence has a negative reserve price.".to_string());
        }
        let Some(upside_value_scale) = certificate.upside_value_scale else {
            return Some(
                "Certified Max-DE reserve-priced evidence requires an upside value scale."
                    .to_string(),
            );
        };
        if !upside_value_scale.is_finite() || upside_value_scale <= 0.0 {
            return Some(
                "Certified Max-DE reserve-priced evidence requires a positive upside value scale."
                    .to_string(),
            );
        }
    }
    if certificate.family == "beta_bernoulli" && !(0.0..=1.0).contains(&certificate.baseline) {
        return Some("Certified Max-DE evidence baseline is outside [0, 1].".to_string());
    }
    if certificate.delight_scale <= 0.0 {
        return Some("Certified Max-DE evidence requires a positive delight scale.".to_string());
    }
    if certificate.liability_price < 0.0 {
        return Some("Certified Max-DE evidence has a negative liability price.".to_string());
    }
    if certificate.inspection_lower_bound < -CERTIFICATE_EPSILON
        || certificate.safe_upper_bound < -CERTIFICATE_EPSILON
    {
        return Some(
            "Certified Max-DE evidence contains a negative certificate value.".to_string(),
        );
    }
    if certificate.inspection_lower_bound > certificate.safe_upper_bound + CERTIFICATE_EPSILON {
        return Some(
            "Certified Max-DE evidence has an inspection lower bound above its safe upper bound."
                .to_string(),
        );
    }
    if certificate.typed_effect.mean_bound
        > certificate.inspection_lower_bound + CERTIFICATE_EPSILON
    {
        return Some(
            "Certified Max-DE evidence has mean_bound above its inspection lower bound."
                .to_string(),
        );
    }
    if let Some(reason) = typed_effect_validation_error(&certificate.typed_effect) {
        return Some(reason);
    }
    let Some(computed_upper) = typed_effect_safe_upper_bound(&certificate.typed_effect) else {
        return Some(
            "Certified Max-DE typed effect cannot produce a safe upper bound.".to_string(),
        );
    };
    if (certificate.safe_upper_bound - computed_upper).abs() > 1e-6 {
        return Some(
            "Certified Max-DE safe upper bound does not match typed effect metadata.".to_string(),
        );
    }

    let derived_threshold = certificate
        .reserve_price
        .zip(certificate.upside_value_scale)
        .map(|(reserve_price, scale)| reserve_price / (scale * certificate.delight_scale))
        .unwrap_or(certificate.liability_price / certificate.delight_scale);
    if (certificate.threshold - derived_threshold).abs() > 1e-6 {
        return Some(
            "Certified Max-DE evidence threshold does not match the contract price scale."
                .to_string(),
        );
    }
    let implied = implied_certificate_outcome(certificate);
    if certificate.outcome != implied {
        return Some(format!(
            "Certified Max-DE evidence outcome {:?} does not match numeric bounds; expected {:?}.",
            certificate.outcome, implied
        ));
    }
    None
}

fn implied_certificate_outcome(certificate: &crate::CertificateEvidence) -> CertificateOutcome {
    let scale = certificate.upside_value_scale.unwrap_or(1.0);
    let price = certificate
        .reserve_price
        .unwrap_or(certificate.liability_price);
    let lower_delight = certificate.inspection_lower_bound * certificate.delight_scale * scale;
    let upper_delight = certificate.safe_upper_bound * certificate.delight_scale * scale;
    if lower_delight + CERTIFICATE_EPSILON >= price {
        CertificateOutcome::Inspect
    } else if upper_delight < price - CERTIFICATE_EPSILON {
        CertificateOutcome::Lockout
    } else {
        CertificateOutcome::Refinement
    }
}

fn typed_effect_validation_error(effect: &CertificateEffect) -> Option<String> {
    let Some(variance) = effect_variance_bound(effect) else {
        return Some(
            "Certified Max-DE typed effect requires variance_bound or second_moment_bound."
                .to_string(),
        );
    };
    for (label, value) in [
        ("max_payoff", effect.max_payoff),
        ("mean_bound", effect.mean_bound),
        ("variance_bound", variance),
    ] {
        if !value.is_finite() {
            return Some(format!(
                "Certified Max-DE typed effect has a non-finite {label} value."
            ));
        }
        if value < -CERTIFICATE_EPSILON {
            return Some(format!(
                "Certified Max-DE typed effect has a negative {label} value."
            ));
        }
    }
    if effect.mean_bound > effect.max_payoff + CERTIFICATE_EPSILON {
        return Some("Certified Max-DE typed effect mean_bound exceeds max_payoff.".to_string());
    }
    if effect.resource_scope.is_empty() {
        return Some("Certified Max-DE typed effect requires a resource scope.".to_string());
    }
    if effect.filtration_hash.is_empty() {
        return Some("Certified Max-DE typed effect requires a filtration hash.".to_string());
    }
    None
}

fn effect_variance_bound(effect: &CertificateEffect) -> Option<f64> {
    if let Some(variance) = effect.variance_bound {
        return Some(variance);
    }
    effect
        .second_moment_bound
        .map(|second| (second - effect.mean_bound.powi(2)).max(0.0))
}

fn typed_effect_safe_upper_bound(effect: &CertificateEffect) -> Option<f64> {
    let mean = effect.mean_bound;
    let max_payoff = effect.max_payoff;
    let variance = effect_variance_bound(effect)?;
    if !mean.is_finite() || !max_payoff.is_finite() || !variance.is_finite() {
        return None;
    }
    if mean < 0.0 || max_payoff < 0.0 || variance < 0.0 {
        return None;
    }
    if mean == 0.0 {
        return Some(0.0);
    }
    if max_payoff <= 0.0 || mean > max_payoff + CERTIFICATE_EPSILON {
        return None;
    }
    let log_envelope = mean * (1.0 + (max_payoff / mean).ln());
    let l2_envelope = mean + 2.0 * variance.sqrt();
    Some(max_payoff.min(log_envelope).min(l2_envelope).max(0.0))
}

fn select(
    host_action: Option<ActionType>,
    candidate_decisions: Vec<CandidateDecision>,
) -> RoutingDecision {
    if let Some(selected) = candidate_decisions.iter().find(|item| {
        item.decision == DecisionType::Escalate
            && matches!(
                item.action_type,
                ActionType::EscalateModel | ActionType::ConciergeReview
            )
    }) {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: DecisionType::Escalate,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    let non_fallback_has_execute = candidate_decisions.iter().any(|item| {
        item.decision == DecisionType::Execute
            && item.final_candidate.source != CandidateSource::PolicyFallback
    });
    if !non_fallback_has_execute
        && let Some(selected) = candidate_decisions.iter().find(|item| {
            item.decision == DecisionType::Block
                && item.final_candidate.source != CandidateSource::PolicyFallback
        })
    {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: DecisionType::Block,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    if !non_fallback_has_execute
        && let Some(selected) = candidate_decisions.iter().find(|item| {
            matches!(item.decision, DecisionType::Delay | DecisionType::Escalate)
                && item.final_candidate.source != CandidateSource::PolicyFallback
                && item.short_circuit.is_some()
        })
    {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: selected.decision,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    if let Some(selected) = candidate_decisions
        .iter()
        .filter(|item| item.decision == DecisionType::Execute)
        .max_by(|left, right| {
            left.admission_trace
                .as_ref()
                .map_or(i64::MIN, |trace| trace.objective_components.objective_bps)
                .partial_cmp(
                    &right
                        .admission_trace
                        .as_ref()
                        .map_or(i64::MIN, |trace| trace.objective_components.objective_bps),
                )
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: DecisionType::Execute,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    if let Some(selected) = candidate_decisions
        .iter()
        .find(|item| item.decision == DecisionType::AskApproval)
    {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: DecisionType::AskApproval,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    if let Some(selected) = candidate_decisions
        .iter()
        .find(|item| item.action_type == ActionType::AnswerDirectly)
        .or_else(|| candidate_decisions.first())
    {
        return RoutingDecision {
            action_type: Some(selected.action_type),
            decision: selected.decision,
            reason: selected.reason.clone(),
            host_action,
            candidate_decisions,
            thread_id: None,
            seal_id: None,
        };
    }
    RoutingDecision {
        action_type: None,
        decision: DecisionType::Skip,
        reason: "No candidate actions were provided or generated.".to_string(),
        host_action,
        candidate_decisions,
        thread_id: None,
        seal_id: None,
    }
}

fn host_action_from_state(state: &Value) -> Option<ActionType> {
    state
        .get("host_action")
        .or_else(|| state.get("default_action"))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn zero_cost() -> BTreeMap<String, f64> {
        crate::CostVector::WEIGHTS
            .iter()
            .map(|(key, _)| ((*key).to_string(), 0.0))
            .collect()
    }

    fn zero_risk() -> BTreeMap<String, f64> {
        crate::RiskVector::WEIGHTS
            .iter()
            .map(|(key, _)| ((*key).to_string(), 0.0))
            .collect()
    }

    fn unsigned_budget_candidate() -> CandidateAction {
        CandidateAction {
            action_type: ActionType::CallTool,
            description: "budgeted tool call".to_string(),
            certificate: None,
            budget_certificate: None,
            expected_improvement: Some(1.0),
            novelty: Some(1.0),
            confidence: Some(1.0),
            cost_overrides: zero_cost(),
            risk_overrides: zero_risk(),
            metadata: [
                ("budget_affecting".to_string(), json!(true)),
                ("capability_class".to_string(), json!("read_only")),
                ("approval_tier".to_string(), json!("auto_approve")),
                ("mcp_tool_key".to_string(), json!("test/read_budgeted")),
            ]
            .into_iter()
            .collect(),
            source: CandidateSource::Scenario,
            parameters: Default::default(),
        }
    }

    fn execute_pricing_state() -> Value {
        json!({
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.01,
                "lambda_cap": 0.01
            }
        })
    }

    fn execute_pricing_state_with_filtration() -> Value {
        json!({
            "filtration_hash": "fh",
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.01,
                "lambda_cap": 0.01
            }
        })
    }

    fn deterministic_budget_certificate(
        candidate: &CandidateAction,
        observed_spend_usd: f64,
        hard_cap_usd: f64,
    ) -> DeterministicBudgetCertificate {
        let budget_limit_microusd = 10_000_000;
        let observed_spend_microusd =
            crate::usd_to_microusd_exact_or_reject("observed_spend_usd", observed_spend_usd)
                .expect("test observed spend is integral microusd");
        let hard_cap_microusd =
            crate::usd_to_microusd_exact_or_reject("hard_cap_usd", hard_cap_usd)
                .expect("test hard cap is integral microusd");
        let projected_spend_microusd = observed_spend_microusd + hard_cap_microusd;
        let slack_microusd = budget_limit_microusd as i64 - projected_spend_microusd as i64;
        DeterministicBudgetCertificate {
            schema_version: crate::DETERMINISTIC_BUDGET_SCHEMA_VERSION.to_string(),
            certificate_kind: BudgetCertificateKind::DeterministicHardCap,
            scope: BudgetScope::Task,
            budget_limit_usd: crate::microusd_to_usd_display(budget_limit_microusd),
            observed_spend_usd: crate::microusd_to_usd_display(observed_spend_microusd),
            hard_cap_usd: crate::microusd_to_usd_display(hard_cap_microusd),
            cap_provenance: CapProvenance::ProviderEnforced,
            concurrency_model: ConcurrencyModel::SingleWriterAtomic,
            action_hash: budget_action_hash(candidate),
            filtration_hash: "fh".to_string(),
            ledger_sequence_before: 0,
            projected_spend_usd: crate::microusd_to_usd_display(projected_spend_microusd),
            slack_usd: crate::slack_microusd_to_usd_display(slack_microusd),
            outcome: if projected_spend_microusd <= budget_limit_microusd {
                BudgetOutcome::Admit
            } else {
                BudgetOutcome::Block
            },
            obligations: crate::MANDATORY_DETERMINISTIC_BUDGET_OBLIGATIONS
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            theorem_refs: vec!["docs/math/budget_safety_deterministic_theorem.txt".to_string()],
            budget_limit_microusd: Some(budget_limit_microusd),
            observed_spend_microusd: Some(observed_spend_microusd),
            hard_cap_microusd: Some(hard_cap_microusd),
            projected_spend_microusd: Some(projected_spend_microusd),
            slack_microusd: Some(slack_microusd),
        }
    }

    fn budget_certificate(
        candidate: &CandidateAction,
        observed_spend_usd: f64,
        hard_cap_usd: f64,
    ) -> BudgetCertificate {
        BudgetCertificate::Deterministic(deterministic_budget_certificate(
            candidate,
            observed_spend_usd,
            hard_cap_usd,
        ))
    }

    fn budget_ledger_value(
        budget_limit_microusd: u64,
        observed_spend_microusd: u64,
        ledger_sequence: u64,
    ) -> Value {
        let ledger = BudgetSafetyLedger {
            scope: BudgetScope::Task,
            budget_limit_usd: crate::microusd_to_usd_display(budget_limit_microusd),
            budget_limit_microusd,
            observed_spend_usd: crate::microusd_to_usd_display(observed_spend_microusd),
            observed_spend_microusd,
            ledger_hash: String::new(),
            ledger_sequence,
        }
        .with_recomputed_hash();
        serde_json::to_value(ledger).expect("ledger serializes")
    }

    fn cgf_budget_certificate(
        candidate: &CandidateAction,
        budget_limit_usd: f64,
        observed_spend_usd: f64,
    ) -> crate::ProbabilisticBudgetCertificate {
        let budget_limit_microusd =
            crate::usd_to_microusd_exact_or_reject("budget_limit_usd", budget_limit_usd)
                .expect("test budget limit is integral microusd");
        let observed_spend_microusd =
            crate::usd_to_microusd_exact_or_reject("observed_spend_usd", observed_spend_usd)
                .expect("test observed spend is integral microusd");
        let certified_mean_sum = 1.0;
        let delta_total = 0.05;
        let lambda_grid = vec![1.0];
        let mixture_weights = vec![1.0];
        let cgf_sum_by_lambda = [("1".to_string(), 0.0)].into_iter().collect();
        let high_probability_bound =
            observed_spend_usd + certified_mean_sum + (1.0_f64 / delta_total).ln();
        let high_probability_bound_microusd =
            crate::usd_to_microusd_ceil_or_reject("high_probability_bound", high_probability_bound)
                .expect("test bound is finite");
        let slack_microusd = budget_limit_microusd as i64 - high_probability_bound_microusd as i64;
        crate::ProbabilisticBudgetCertificate {
            schema_version: crate::PROBABILISTIC_BUDGET_SCHEMA_VERSION.to_string(),
            certificate_kind: BudgetCertificateKind::CgfVille,
            scope: BudgetScope::Task,
            budget_limit: crate::microusd_to_usd_display(budget_limit_microusd),
            delta_total,
            observed_spend: crate::microusd_to_usd_display(observed_spend_microusd),
            certified_mean_sum,
            cgf_sum_by_lambda,
            lambda_grid,
            mixture_weights,
            hard_cap: None,
            mean_upper: None,
            variance_upper: None,
            second_moment_upper: None,
            action_hash: budget_action_hash(candidate),
            filtration_hash: "fh".to_string(),
            ledger_sequence_before: 0,
            pre_ledger_hash: crate::budget_ledger_hash(
                BudgetScope::Task,
                budget_limit_microusd,
                observed_spend_microusd,
                0,
            ),
            cost_model_id: "unit-test-cgf".to_string(),
            high_probability_bound,
            slack: crate::slack_microusd_to_usd_display(slack_microusd),
            outcome: if high_probability_bound_microusd <= budget_limit_microusd {
                BudgetOutcome::Admit
            } else {
                BudgetOutcome::Block
            },
            obligations: crate::MANDATORY_PROBABILISTIC_BUDGET_OBLIGATIONS
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            theorem_refs: vec!["docs/math/adaptive_spend_safety_theorem.txt".to_string()],
            budget_limit_microusd: Some(budget_limit_microusd),
            observed_spend_microusd: Some(observed_spend_microusd),
            high_probability_bound_microusd: Some(high_probability_bound_microusd),
            slack_microusd: Some(slack_microusd),
        }
    }

    fn moment_budget_certificate(
        candidate: &CandidateAction,
        budget_limit_usd: f64,
    ) -> crate::ProbabilisticBudgetCertificate {
        let budget_limit_microusd =
            crate::usd_to_microusd_exact_or_reject("budget_limit_usd", budget_limit_usd)
                .expect("test budget limit is integral microusd");
        let observed_spend_microusd = 0_u64;
        let delta_total = 0.05;
        let mean_upper = 2.0_f64;
        let variance_upper = 1.0_f64;
        let high_probability_bound =
            mean_upper + ((1.0_f64 - delta_total) / delta_total).sqrt() * variance_upper.sqrt();
        let high_probability_bound_microusd =
            crate::usd_to_microusd_ceil_or_reject("high_probability_bound", high_probability_bound)
                .expect("test bound is finite");
        let slack_microusd = budget_limit_microusd as i64 - high_probability_bound_microusd as i64;
        crate::ProbabilisticBudgetCertificate {
            schema_version: crate::PROBABILISTIC_BUDGET_SCHEMA_VERSION.to_string(),
            certificate_kind: BudgetCertificateKind::MomentCantelli,
            scope: BudgetScope::Task,
            budget_limit: crate::microusd_to_usd_display(budget_limit_microusd),
            delta_total,
            observed_spend: 0.0,
            certified_mean_sum: 0.0,
            cgf_sum_by_lambda: BTreeMap::new(),
            lambda_grid: Vec::new(),
            mixture_weights: Vec::new(),
            hard_cap: None,
            mean_upper: Some(mean_upper),
            variance_upper: Some(variance_upper),
            second_moment_upper: None,
            action_hash: budget_action_hash(candidate),
            filtration_hash: "fh".to_string(),
            ledger_sequence_before: 0,
            pre_ledger_hash: crate::budget_ledger_hash(
                BudgetScope::Task,
                budget_limit_microusd,
                observed_spend_microusd,
                0,
            ),
            cost_model_id: "unit-test-moment".to_string(),
            high_probability_bound,
            slack: crate::slack_microusd_to_usd_display(slack_microusd),
            outcome: if high_probability_bound_microusd <= budget_limit_microusd {
                BudgetOutcome::Admit
            } else {
                BudgetOutcome::Block
            },
            obligations: crate::MANDATORY_PROBABILISTIC_BUDGET_OBLIGATIONS
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            theorem_refs: vec!["docs/math/adaptive_spend_safety_theorem.txt".to_string()],
            budget_limit_microusd: Some(budget_limit_microusd),
            observed_spend_microusd: Some(observed_spend_microusd),
            high_probability_bound_microusd: Some(high_probability_bound_microusd),
            slack_microusd: Some(slack_microusd),
        }
    }

    fn assert_missing_budget_authority(decision: &RoutingDecision) {
        assert!(matches!(
            decision.decision,
            DecisionType::AskApproval | DecisionType::Escalate | DecisionType::Block
        ));
        let trace = decision.candidate_decisions[0]
            .admission_trace
            .as_ref()
            .expect("admission trace");
        assert!(trace.hard_constraints.iter().any(|constraint| {
            constraint.constraint_id == "budget_reserved"
                && !constraint.passed
                && constraint.reason_code == "budget_required"
        }));
    }

    #[test]
    fn deterministic_budget_block_short_circuits_before_scoring() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(budget_certificate(&candidate, 9.6, 0.5));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("deterministic_budget_block")
        );
        assert!(decision.candidate_decisions[0].admission_score.is_none());
    }

    #[test]
    fn deterministic_budget_admit_allows_execute_scoring_path() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(budget_certificate(&candidate, 0.0, 1.0));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Execute);
        let trace = decision.candidate_decisions[0]
            .budget_trace
            .as_ref()
            .expect("budget trace");
        assert!(trace.certifying);
        assert_eq!(decision.candidate_decisions[0].short_circuit, None);
    }

    #[test]
    fn cgf_ville_budget_admits_when_envelope_clears() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(
            cgf_budget_certificate(&candidate, 10.0, 1.0),
        ));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Execute);
        let trace = decision.candidate_decisions[0]
            .budget_trace
            .as_ref()
            .expect("budget trace");
        assert!(trace.certifying);
        assert_eq!(
            trace.certificate_kind,
            Some(BudgetCertificateKind::CgfVille)
        );
        assert_eq!(trace.claim_mode.as_deref(), Some("probabilistic"));
    }

    #[test]
    fn cgf_ville_budget_blocks_when_envelope_exceeds_budget() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(
            cgf_budget_certificate(&candidate, 3.0, 1.0),
        ));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("cgf_ville_budget_block")
        );
        let trace = decision.candidate_decisions[0]
            .budget_trace
            .as_ref()
            .expect("budget trace");
        assert!(!trace.certifying);
        assert_eq!(
            trace.certificate_kind,
            Some(BudgetCertificateKind::CgfVille)
        );
    }

    #[test]
    fn stale_filtration_hash_blocks_probabilistic_certificate() {
        let mut candidate = unsigned_budget_candidate();
        let mut certificate = cgf_budget_certificate(&candidate, 10.0, 1.0);
        certificate.filtration_hash = "stale".to_string();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(certificate));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("invalid_budget_certificate")
        );
    }

    #[test]
    fn stale_budget_ledger_hash_blocks_probabilistic_certificate() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(
            cgf_budget_certificate(&candidate, 10.0, 1.0),
        ));
        let mut state = execute_pricing_state_with_filtration();
        state["budget_safety_ledger"] = budget_ledger_value(10_000_000, 2_000_000, 0);

        let decision = route(&state, &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("invalid_budget_certificate")
        );
        assert!(
            decision.candidate_decisions[0]
                .reason
                .contains("observed spend is stale")
        );
    }

    #[test]
    fn moment_cantelli_budget_is_probabilistic_and_blocks_when_bound_fails() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(
            moment_budget_certificate(&candidate, 5.0),
        ));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("moment_cantelli_budget_block")
        );
        let trace = decision.candidate_decisions[0]
            .budget_trace
            .as_ref()
            .expect("budget trace");
        assert_eq!(
            trace.certificate_kind,
            Some(BudgetCertificateKind::MomentCantelli)
        );
        assert_eq!(trace.claim_mode.as_deref(), Some("probabilistic"));
        assert!(!trace.certifying);
    }

    #[test]
    fn estimate_only_cost_model_cannot_masquerade_as_cgf_certificate() {
        let mut candidate = unsigned_budget_candidate();
        let mut certificate = cgf_budget_certificate(&candidate, 10.0, 1.0);
        certificate.lambda_grid.clear();
        certificate.cgf_sum_by_lambda.clear();
        candidate.budget_certificate = Some(BudgetCertificate::Probabilistic(certificate));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("invalid_budget_certificate")
        );
        assert!(
            decision.candidate_decisions[0]
                .reason
                .contains("lambda_grid")
        );
    }

    #[test]
    fn spend_bearing_execute_requires_passing_budget_certificate() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = None;
        candidate
            .metadata
            .insert("usd_estimate".to_string(), json!(1.0));

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_missing_budget_authority(&decision);
    }

    #[test]
    fn non_budget_affecting_cannot_bypass_usd_estimate() {
        let mut candidate = unsigned_budget_candidate();
        candidate.action_type = ActionType::AnswerDirectly;
        candidate.budget_certificate = None;
        candidate.metadata.remove("budget_affecting");
        candidate
            .metadata
            .insert("non_budget_affecting".to_string(), json!(true));
        candidate
            .metadata
            .insert("usd_estimate".to_string(), json!(1.0));

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_missing_budget_authority(&decision);
    }

    #[test]
    fn non_budget_affecting_cannot_bypass_money_cost_override() {
        let mut candidate = unsigned_budget_candidate();
        candidate.action_type = ActionType::AnswerDirectly;
        candidate.budget_certificate = None;
        candidate.metadata.remove("budget_affecting");
        candidate
            .metadata
            .insert("non_budget_affecting".to_string(), json!(true));
        candidate.cost_overrides.insert("money".to_string(), 0.01);

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_missing_budget_authority(&decision);
    }

    #[test]
    fn non_budget_affecting_cannot_bypass_explicit_budget_affecting() {
        let mut candidate = unsigned_budget_candidate();
        candidate.action_type = ActionType::AnswerDirectly;
        candidate.budget_certificate = None;
        candidate
            .metadata
            .insert("non_budget_affecting".to_string(), json!(true));

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_missing_budget_authority(&decision);
    }

    #[test]
    fn free_action_executes_only_with_no_positive_budget_signals() {
        let candidate = CandidateAction {
            action_type: ActionType::AnswerDirectly,
            description: "free answer".to_string(),
            certificate: None,
            budget_certificate: None,
            expected_improvement: Some(1.0),
            novelty: Some(1.0),
            confidence: Some(1.0),
            cost_overrides: zero_cost(),
            risk_overrides: zero_risk(),
            metadata: [("budget_affecting".to_string(), json!(false))]
                .into_iter()
                .collect(),
            source: CandidateSource::Scenario,
            parameters: Default::default(),
        };

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Execute);
        assert_eq!(decision.candidate_decisions[0].short_circuit, None);
    }

    #[test]
    fn spend_bearing_execute_rejects_non_certifying_budget_certificates() {
        let mut estimate_candidate = unsigned_budget_candidate();
        let mut estimate_certificate =
            deterministic_budget_certificate(&estimate_candidate, 0.0, 1.0);
        estimate_certificate.cap_provenance = CapProvenance::EstimateNotACap;
        estimate_candidate.budget_certificate =
            Some(BudgetCertificate::Deterministic(estimate_certificate));

        let mut unserialized_candidate = unsigned_budget_candidate();
        let mut unserialized_certificate =
            deterministic_budget_certificate(&unserialized_candidate, 0.0, 1.0);
        unserialized_certificate.concurrency_model = ConcurrencyModel::Unserialized;
        unserialized_candidate.budget_certificate =
            Some(BudgetCertificate::Deterministic(unserialized_certificate));

        let mut block_candidate = unsigned_budget_candidate();
        block_candidate.budget_certificate = Some(budget_certificate(&block_candidate, 9.6, 0.5));

        for candidate in [estimate_candidate, unserialized_candidate, block_candidate] {
            let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

            assert_eq!(decision.decision, DecisionType::Block);
        }
    }

    #[test]
    fn budget_affecting_unset_fails_closed_for_execute() {
        let mut candidate = unsigned_budget_candidate();
        candidate.budget_certificate = None;
        candidate.metadata.remove("budget_affecting");

        let decision = route(&execute_pricing_state(), &[candidate]);

        assert_missing_budget_authority(&decision);
    }

    #[test]
    fn non_certifying_budget_certificate_records_downgrade_trace() {
        let mut candidate = unsigned_budget_candidate();
        candidate
            .metadata
            .insert("non_budget_affecting".to_string(), json!(true));
        let mut certificate = deterministic_budget_certificate(&candidate, 0.0, 1.0);
        certificate.cap_provenance = CapProvenance::EstimateNotACap;
        candidate.budget_certificate = Some(BudgetCertificate::Deterministic(certificate));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        let trace = decision.candidate_decisions[0]
            .budget_trace
            .as_ref()
            .expect("budget trace");
        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("budget_authorization_required")
        );
        assert!(!trace.certifying);
        assert_eq!(
            trace.downgrade_reason.as_deref(),
            Some("estimate-only input is not a hard cost cap")
        );
    }

    #[test]
    fn invalid_budget_certificate_blocks_before_scoring() {
        let mut candidate = unsigned_budget_candidate();
        let mut certificate = deterministic_budget_certificate(&candidate, 0.0, 1.0);
        certificate.action_hash = "stale-action-hash".to_string();
        candidate.budget_certificate = Some(BudgetCertificate::Deterministic(certificate));

        let decision = route(&execute_pricing_state_with_filtration(), &[candidate]);

        assert_eq!(decision.decision, DecisionType::Block);
        assert_eq!(
            decision.candidate_decisions[0].short_circuit.as_deref(),
            Some("invalid_budget_certificate")
        );
        assert!(decision.candidate_decisions[0].admission_score.is_none());
    }

    #[test]
    fn same_snapshot_budget_commits_are_single_writer() {
        let candidate = unsigned_budget_candidate();
        let certificate = deterministic_budget_certificate(&candidate, 0.0, 1.0);
        let mut ledger = crate::BudgetSafetyLedger {
            scope: BudgetScope::Task,
            budget_limit_usd: 10.0,
            budget_limit_microusd: 10_000_000,
            observed_spend_usd: 0.0,
            observed_spend_microusd: 0,
            ledger_hash: String::new(),
            ledger_sequence: 0,
        }
        .with_recomputed_hash();

        let first = ledger.commit_authorized_realized_cost(&certificate, 500_000);
        let second = ledger.commit_authorized_realized_cost(&certificate, 500_000);

        assert!(first.is_ok());
        assert!(second.is_err());
        assert_eq!(ledger.ledger_sequence, 1);
        assert_eq!(ledger.observed_spend_microusd, 500_000);
        assert_eq!(ledger.observed_spend_usd, 0.5);
    }

    #[test]
    fn adaptive_probabilistic_sequence_reconciles_with_deterministic_seed() {
        let candidate = unsigned_budget_candidate();
        let mut ledger = BudgetSafetyLedger {
            scope: BudgetScope::Task,
            budget_limit_usd: 10.0,
            budget_limit_microusd: 10_000_000,
            observed_spend_usd: 0.0,
            observed_spend_microusd: 0,
            ledger_hash: String::new(),
            ledger_sequence: 0,
        }
        .with_recomputed_hash();
        let mut seed = 19_u64;

        for _ in 0..5 {
            let mut certificate =
                cgf_budget_certificate(&candidate, 10.0, ledger.observed_spend_usd);
            certificate.ledger_sequence_before = ledger.ledger_sequence;
            certificate.pre_ledger_hash = ledger.ledger_hash.clone();
            certificate.observed_spend_microusd = Some(ledger.observed_spend_microusd);
            certificate.observed_spend = ledger.observed_spend_usd;
            certificate.high_probability_bound =
                ledger.observed_spend_usd + certificate.certified_mean_sum + 20.0_f64.ln();
            let bound_microusd = crate::usd_to_microusd_ceil_or_reject(
                "high_probability_bound",
                certificate.high_probability_bound,
            )
            .expect("test bound is finite");
            certificate.high_probability_bound_microusd = Some(bound_microusd);
            certificate.slack_microusd =
                Some(ledger.budget_limit_microusd as i64 - bound_microusd as i64);
            certificate.slack =
                crate::slack_microusd_to_usd_display(certificate.slack_microusd.unwrap());
            certificate.outcome = BudgetOutcome::Admit;

            assert!(certificate.is_certifying());
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let realized_microusd = 100_000 + (seed % 200_000);
            ledger
                .commit_probabilistic_authorized_realized_cost(&certificate, realized_microusd)
                .expect("probabilistic realized cost records");
        }

        assert_eq!(ledger.ledger_sequence, 5);
        assert!(ledger.observed_spend_microusd > 0);
    }
}
