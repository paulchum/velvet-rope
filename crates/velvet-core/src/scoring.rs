use serde_json::Value;

use crate::pricing::{compute_entry_price, estimate_cost, estimate_risk};
use crate::utils::{clamp01, number_value, round4, state_truthy};
use crate::{
    ActionType, AdmissionScore, CandidateAction, PricingContext, PricingSignals, SCORER_VERSION,
};

pub fn score_action(action: &CandidateAction, state: &Value) -> AdmissionScore {
    let pricing_context = PricingContext::default();
    score_action_with_pricing(action, state, &pricing_context)
}

pub fn score_action_with_pricing(
    action: &CandidateAction,
    state: &Value,
    pricing_context: &PricingContext,
) -> AdmissionScore {
    let expected_upside = expected_upside(action, state);
    let surprisal = surprisal(action, state);
    let confidence = confidence(action, state);
    let cost = estimate_cost(action, state);
    let risk = estimate_risk(action, state);
    let cost_penalty = cost.penalty();
    let risk_penalty = risk.penalty();
    let clearance_score =
        round4(expected_upside * surprisal * confidence - cost_penalty - risk_penalty);
    let signals = PricingSignals {
        expected_upside,
        surprisal,
        confidence,
        clearance_score,
    };
    let pricing_breakdown =
        compute_entry_price(action, state, pricing_context, cost, risk, signals);
    AdmissionScore {
        action_type: action.action_type,
        expected_upside,
        surprisal,
        confidence,
        cost,
        risk,
        cost_penalty,
        risk_penalty,
        clearance_score,
        pricing_breakdown,
        scorer_version: SCORER_VERSION.to_string(),
    }
}

fn expected_upside(action: &CandidateAction, state: &Value) -> f64 {
    if let Some(value) = action.expected_improvement {
        return clamp01(value);
    }
    match action.action_type {
        ActionType::AnswerDirectly => {
            if state_truthy(state, "freshness_required") || state_truthy(state, "file_available") {
                0.28
            } else if state_truthy(state, "ambiguous") {
                0.34
            } else {
                0.66
            }
        }
        ActionType::SearchWeb => {
            if state_truthy(state, "freshness_required") {
                0.86
            } else if state_truthy(state, "user_requested_sources") {
                0.74
            } else {
                0.32
            }
        }
        ActionType::RetrieveContext => {
            if state_truthy(state, "retrieval_available") {
                0.72
            } else {
                0.42
            }
        }
        ActionType::ReadFile => {
            if state_truthy(state, "file_available") {
                0.90
            } else {
                0.42
            }
        }
        ActionType::InspectCode => {
            if state_truthy(state, "repo_available") || state_truthy(state, "code_available") {
                0.82
            } else {
                0.44
            }
        }
        ActionType::ExecuteCode => {
            if state_truthy(state, "execution_required") {
                0.78
            } else {
                0.40
            }
        }
        ActionType::CallTool => {
            if state_truthy(state, "tool_call_requested") {
                0.78
            } else {
                0.46
            }
        }
        ActionType::AskUser => {
            if state_truthy(state, "ambiguous") || state_truthy(state, "missing_critical_info") {
                0.78
            } else {
                0.22
            }
        }
        ActionType::StoreMemory => clamp01(number_value(state.get("memory_candidate_value"), 0.50)),
        ActionType::EscalateModel => {
            if state_truthy(state, "high_uncertainty")
                || state_truthy(state, "requires_stronger_model")
            {
                0.82
            } else {
                0.38
            }
        }
        ActionType::ConciergeReview => {
            if state_truthy(state, "safety_critical") || state_truthy(state, "blocked_by_policy") {
                0.88
            } else {
                0.30
            }
        }
    }
}

fn surprisal(action: &CandidateAction, state: &Value) -> f64 {
    if let Some(value) = action.novelty {
        return clamp01(value);
    }
    match action.action_type {
        ActionType::AnswerDirectly => 0.18,
        ActionType::SearchWeb => {
            if state_truthy(state, "freshness_required") {
                0.68
            } else {
                0.32
            }
        }
        ActionType::RetrieveContext => 0.54,
        ActionType::ReadFile => {
            if state_truthy(state, "file_available") {
                0.76
            } else {
                0.42
            }
        }
        ActionType::InspectCode => 0.64,
        ActionType::ExecuteCode => 0.70,
        ActionType::CallTool => 0.60,
        ActionType::AskUser => {
            if state_truthy(state, "ambiguous") {
                0.52
            } else {
                0.22
            }
        }
        ActionType::StoreMemory => clamp01(number_value(state.get("memory_novelty"), 0.68)),
        ActionType::EscalateModel => 0.62,
        ActionType::ConciergeReview => 0.66,
    }
}

fn confidence(action: &CandidateAction, state: &Value) -> f64 {
    if let Some(value) = action.confidence {
        return clamp01(value);
    }
    match action.action_type {
        ActionType::AnswerDirectly => {
            if state_truthy(state, "freshness_required") {
                0.42
            } else {
                0.82
            }
        }
        ActionType::SearchWeb => 0.82,
        ActionType::RetrieveContext => 0.78,
        ActionType::ReadFile => 0.86,
        ActionType::InspectCode => 0.82,
        ActionType::ExecuteCode => 0.66,
        ActionType::CallTool => 0.72,
        ActionType::AskUser => 0.78,
        ActionType::StoreMemory => clamp01(number_value(state.get("memory_confidence"), 0.74)),
        ActionType::EscalateModel => 0.72,
        ActionType::ConciergeReview => 0.82,
    }
}
