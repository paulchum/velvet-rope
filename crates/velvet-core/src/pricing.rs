use serde_json::Value;

use crate::utils::{clamp01, number_value, round4, state_truthy, string_value};
use crate::{
    ActionType, BudgetState, CandidateAction, CostVector, PricingBreakdown, PricingContext,
    PricingPolicy, PricingSignals, RiskVector,
};

pub fn compute_entry_price(
    action: &CandidateAction,
    state: &Value,
    context: &PricingContext,
    cost: CostVector,
    risk: RiskVector,
    signals: PricingSignals,
) -> PricingBreakdown {
    let base = base_entry_price(action.action_type);
    let budget = &context.budget_state;
    let fixed_baseline_price = base;
    let effective_horizon = effective_horizon(action.action_type, budget, cost);
    let horizon_multiplier = horizon_multiplier(context, effective_horizon);
    let weighted_scarcity = weighted_scarcity(cost, budget);
    let scarcity_multiplier =
        round4(1.0 + context.scarcity_strength * context.scarcity_multiplier * weighted_scarcity);
    let override_rate_multiplier = override_rate_multiplier(context);
    let action_cost_adjustment = round4(1.0 + context.cost_strength * action_cost_intensity(cost));
    let uncertainty_adjustment =
        uncertainty_credit(action.action_type, state, budget, signals, context);
    let risk_adjustment = risk_adjustment(action.action_type, state, risk, budget, context);
    let hard_budget_exhausted = hard_budget_exhausted(action.action_type, state, budget, cost);
    let fail_safe_applied = hard_budget_exhausted || !context.lambda_cap.is_finite();
    let raw_lambda = match context.pricing_policy {
        PricingPolicy::FixedPriceBaseline => base,
        PricingPolicy::LinearExhaustion => {
            base * (1.0 + budget.pressure() * context.scarcity_strength) + risk_adjustment
                - uncertainty_adjustment * 0.25
        }
        PricingPolicy::InverseHorizon => {
            base * horizon_multiplier + risk_adjustment - uncertainty_adjustment * 0.25
        }
        PricingPolicy::OverrideRateAware => {
            base * horizon_multiplier * override_rate_multiplier + risk_adjustment
                - uncertainty_adjustment * 0.25
        }
        PricingPolicy::RiskWeighted => {
            base * action_cost_adjustment + risk_adjustment - uncertainty_adjustment * 0.20
        }
        PricingPolicy::UncertaintyCompensated => {
            base * scarcity_multiplier * action_cost_adjustment + risk_adjustment
                - uncertainty_adjustment
        }
        PricingPolicy::HybridProduction => {
            base * horizon_multiplier * scarcity_multiplier * action_cost_adjustment
                + risk_adjustment
                - uncertainty_adjustment
        }
    };
    let mut fallback_triggers = budget.fallback_triggers.clone();
    let floor = context.lambda_floor.min(context.lambda_cap);
    let cap = context.lambda_cap.max(floor);
    let mut priced_lambda = if hard_budget_exhausted {
        fallback_triggers.push("required_budget_exhausted_lambda_capped".to_string());
        cap
    } else if raw_lambda.is_finite() {
        raw_lambda
    } else {
        fallback_triggers.push("lambda_non_finite_defaulted_to_cap".to_string());
        cap
    };
    let floor_applied = priced_lambda < floor;
    let cap_applied = priced_lambda > cap || hard_budget_exhausted;
    priced_lambda = priced_lambda.clamp(floor, cap);
    let final_lambda = round4(priced_lambda);
    let clears_rope = signals.clearance_score >= final_lambda;
    let fixed_clears_rope = signals.clearance_score >= fixed_baseline_price;
    PricingBreakdown {
        pricing_policy: context.pricing_policy,
        pricing_policy_name: context.pricing_policy.as_str().to_string(),
        pricing_policy_version: context.pricing_policy_version.clone(),
        base_entry_price: round4(base),
        fixed_baseline_price: round4(fixed_baseline_price),
        entry_price: final_lambda,
        final_lambda,
        budget_state: budget.clone(),
        action_cost: cost,
        horizon_multiplier,
        scarcity_multiplier,
        override_rate_multiplier,
        action_cost_adjustment,
        uncertainty_adjustment,
        risk_adjustment,
        scarcity_pressure: round4(budget.pressure()),
        weighted_scarcity,
        effective_horizon,
        override_rate: round4(context.override_rate),
        cap_applied,
        floor_applied,
        fail_safe_applied,
        hard_budget_exhausted,
        clears_rope,
        fixed_clears_rope,
        differs_from_fixed: clears_rope != fixed_clears_rope,
        fallback_triggers,
    }
}

pub fn base_entry_price(action_type: ActionType) -> f64 {
    match action_type {
        ActionType::AnswerDirectly => 0.0,
        ActionType::SearchWeb => 0.18,
        ActionType::RetrieveContext => 0.14,
        ActionType::ReadFile => 0.16,
        ActionType::InspectCode => 0.16,
        ActionType::ExecuteCode => 0.32,
        ActionType::CallTool => 0.24,
        ActionType::AskUser => 0.20,
        ActionType::StoreMemory => 0.22,
        ActionType::EscalateModel => 0.28,
        ActionType::ConciergeReview => 0.26,
    }
}

fn horizon_multiplier(context: &PricingContext, effective_horizon: f64) -> f64 {
    let denominator = effective_horizon.max(context.horizon_floor).max(0.0001);
    let horizon_price = context.surprisal_cap.max(0.0001) / denominator;
    round4(horizon_price.clamp(0.75, 3.0))
}

fn override_rate_multiplier(context: &PricingContext) -> f64 {
    if context.pricing_policy != PricingPolicy::OverrideRateAware {
        return 1.0;
    }
    let epsilon = finite_or(context.override_rate, 1.0).max(context.override_rate_floor);
    round4((1.0 / epsilon).clamp(1.0, context.override_rate_cap.max(1.0)))
}

fn effective_horizon(action_type: ActionType, budget: &BudgetState, cost: CostVector) -> f64 {
    let scarcity = weighted_scarcity(cost, budget);
    let relevant_remaining = match action_type {
        ActionType::AnswerDirectly => budget.task_horizon_remaining,
        ActionType::SearchWeb | ActionType::CallTool => average(&[
            budget.tool_calls_remaining,
            budget.dollars_remaining,
            budget.latency_ms_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::RetrieveContext => average(&[
            budget.retrievals_remaining,
            budget.tokens_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::ReadFile | ActionType::InspectCode => average(&[
            budget.tokens_remaining,
            budget.latency_ms_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::ExecuteCode => average(&[
            budget.tool_calls_remaining,
            budget.latency_ms_remaining,
            budget.model_escalations_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::AskUser | ActionType::ConciergeReview => average(&[
            budget.concierge_reviews_remaining,
            budget.latency_ms_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::StoreMemory => average(&[
            budget.memory_writes_remaining,
            budget.dollars_remaining,
            budget.task_horizon_remaining,
        ]),
        ActionType::EscalateModel => average(&[
            budget.model_escalations_remaining,
            budget.tokens_remaining,
            budget.dollars_remaining,
            budget.latency_ms_remaining,
            budget.task_horizon_remaining,
        ]),
    };
    round4((0.65 * relevant_remaining + 0.35 * (1.0 - scarcity)).clamp(0.0, 1.0))
}

fn weighted_scarcity(cost: CostVector, budget: &BudgetState) -> f64 {
    let mut weighted = 0.0;
    let mut total = 0.0;
    for (key, weight) in CostVector::WEIGHTS {
        let cost_component = cost.get(key);
        if cost_component <= 0.0 {
            continue;
        }
        let pressure = 1.0 - budget.remaining_for_cost_key(key);
        let component_weight = weight * cost_component;
        weighted += component_weight * pressure;
        total += component_weight;
    }
    if total <= 0.0 {
        return 0.0;
    }
    round4(clamp01(weighted / total))
}

fn action_cost_intensity(cost: CostVector) -> f64 {
    round4(
        CostVector::WEIGHTS
            .iter()
            .map(|(key, weight)| cost.get(key) * weight)
            .sum::<f64>()
            .clamp(0.0, 1.0),
    )
}

fn uncertainty_credit(
    action_type: ActionType,
    state: &Value,
    budget: &BudgetState,
    signals: PricingSignals,
    context: &PricingContext,
) -> f64 {
    if !is_epistemic_or_clarifying(action_type) || budget.minimum_remaining() <= 0.03 {
        return 0.0;
    }
    let explicit_deficit = budget.confidence_deficit;
    let signal_deficit = clamp01(1.0 - signals.confidence);
    let state_deficit = if state_truthy(state, "high_uncertainty")
        || state_truthy(state, "missing_critical_info")
        || state_truthy(state, "freshness_required")
    {
        0.28
    } else {
        0.0
    };
    let raw = (explicit_deficit.max(signal_deficit) + state_deficit)
        * signals.surprisal.max(0.10)
        * signals.expected_upside.max(0.10)
        * context.uncertainty_strength;
    round4(raw.min(0.08))
}

fn risk_adjustment(
    action_type: ActionType,
    state: &Value,
    risk: RiskVector,
    budget: &BudgetState,
    context: &PricingContext,
) -> f64 {
    let invasive_risk = 0.09 * risk.privacy_risk
        + 0.08 * risk.external_side_effect_risk
        + 0.07 * risk.irreversibility
        + 0.07 * risk.sensitivity
        + 0.05 * risk.future_misuse_risk
        + 0.05 * risk.compliance_risk
        + 0.04 * risk.user_trust_risk;
    let epistemic_risk = 0.05 * risk.hallucination_risk
        + 0.04 * risk.staleness_risk
        + 0.03 * risk.source_quality_risk;
    let task_importance = budget
        .task_importance
        .max(task_importance_from_state(state));
    let importance_credit =
        if is_epistemic_or_clarifying(action_type) && !is_privacy_invasive(action_type) {
            0.04 * task_importance
        } else {
            0.0
        };
    round4(
        ((invasive_risk + epistemic_risk) * context.risk_strength * context.risk_multiplier
            - importance_credit)
            .max(-0.04),
    )
}

fn hard_budget_exhausted(
    action_type: ActionType,
    state: &Value,
    budget: &BudgetState,
    cost: CostVector,
) -> bool {
    if user_blocking_fallback(action_type, state) {
        return false;
    }
    let epsilon = 0.0001;
    match action_type {
        ActionType::AnswerDirectly => false,
        ActionType::SearchWeb => {
            budget.tool_calls_remaining <= epsilon
                || budget.dollars_remaining <= epsilon && cost.money > 0.0
                || budget.latency_ms_remaining <= epsilon && cost.latency > 0.0
        }
        ActionType::RetrieveContext => budget.retrievals_remaining <= epsilon,
        ActionType::ReadFile | ActionType::InspectCode => {
            budget.tokens_remaining <= epsilon && cost.tokens > 0.0
        }
        ActionType::ExecuteCode | ActionType::CallTool => budget.tool_calls_remaining <= epsilon,
        ActionType::AskUser | ActionType::ConciergeReview => {
            budget.concierge_reviews_remaining <= epsilon && cost.user_attention > 0.0
        }
        ActionType::StoreMemory => budget.memory_writes_remaining <= epsilon,
        ActionType::EscalateModel => {
            budget.model_escalations_remaining <= epsilon
                || budget.dollars_remaining <= epsilon && cost.money > 0.0
        }
    }
}

fn user_blocking_fallback(action_type: ActionType, state: &Value) -> bool {
    match action_type {
        ActionType::AskUser => {
            state_truthy(state, "missing_critical_info")
                || state_truthy(state, "requires_user_approval")
                || state_truthy(state, "ambiguous")
        }
        ActionType::ConciergeReview => {
            state_truthy(state, "safety_critical") || state_truthy(state, "blocked_by_policy")
        }
        _ => false,
    }
}

fn is_epistemic_or_clarifying(action_type: ActionType) -> bool {
    matches!(
        action_type,
        ActionType::SearchWeb
            | ActionType::RetrieveContext
            | ActionType::ReadFile
            | ActionType::InspectCode
            | ActionType::EscalateModel
            | ActionType::AskUser
    )
}

fn is_privacy_invasive(action_type: ActionType) -> bool {
    matches!(
        action_type,
        ActionType::StoreMemory
            | ActionType::CallTool
            | ActionType::EscalateModel
            | ActionType::ConciergeReview
    )
}

fn task_importance_from_state(state: &Value) -> f64 {
    if state_truthy(state, "safety_critical") {
        1.0
    } else if state_truthy(state, "high_stakes") || state_truthy(state, "high_risk") {
        0.85
    } else {
        clamp01(number_value(state.get("task_importance"), 0.0))
    }
}

fn average(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn finite_or(value: f64, default: f64) -> f64 {
    if value.is_finite() { value } else { default }
}

pub fn estimate_cost(action: &CandidateAction, state: &Value) -> CostVector {
    let mut base = match action.action_type {
        ActionType::AnswerDirectly => CostVector {
            tokens: 0.18,
            latency: 0.05,
            context_pollution: 0.08,
            ..CostVector::default()
        },
        ActionType::SearchWeb => CostVector {
            tokens: 0.28,
            latency: 0.48,
            money: 0.10,
            api_calls: 0.45,
            context_pollution: 0.18,
            privacy_exposure: 0.18,
            ..CostVector::default()
        },
        ActionType::RetrieveContext => CostVector {
            tokens: 0.28,
            latency: 0.18,
            compute: 0.12,
            context_pollution: 0.26,
            ..CostVector::default()
        },
        ActionType::ReadFile => CostVector {
            tokens: 0.42,
            latency: 0.22,
            context_pollution: 0.40,
            privacy_exposure: 0.20,
            ..CostVector::default()
        },
        ActionType::InspectCode => CostVector {
            tokens: 0.38,
            latency: 0.25,
            compute: 0.08,
            context_pollution: 0.34,
            privacy_exposure: 0.16,
            ..CostVector::default()
        },
        ActionType::ExecuteCode => CostVector {
            tokens: 0.20,
            latency: 0.48,
            compute: 0.55,
            coordination_overhead: 0.26,
            opportunity_cost: 0.18,
            ..CostVector::default()
        },
        ActionType::CallTool => CostVector {
            tokens: 0.18,
            latency: 0.42,
            money: 0.12,
            api_calls: 0.55,
            privacy_exposure: 0.28,
            coordination_overhead: 0.20,
            ..CostVector::default()
        },
        ActionType::AskUser => CostVector {
            tokens: 0.05,
            latency: 0.60,
            user_attention: 0.85,
            coordination_overhead: 0.35,
            opportunity_cost: 0.20,
            ..CostVector::default()
        },
        ActionType::StoreMemory => CostVector {
            tokens: 0.12,
            latency: 0.10,
            memory_bloat: 0.62,
            privacy_exposure: 0.42,
            ..CostVector::default()
        },
        ActionType::EscalateModel => CostVector {
            tokens: 0.72,
            latency: 0.55,
            money: 0.72,
            api_calls: 0.35,
            compute: 0.48,
            context_pollution: 0.18,
            ..CostVector::default()
        },
        ActionType::ConciergeReview => CostVector {
            latency: 0.90,
            user_attention: 1.0,
            coordination_overhead: 0.70,
            opportunity_cost: 0.42,
            ..CostVector::default()
        },
    };
    if action.action_type == ActionType::SearchWeb && state_truthy(state, "user_requested_sources")
    {
        base.user_attention = 0.02;
    }
    if action.action_type == ActionType::ReadFile
        && string_value(state, "file_size") == Some("large")
    {
        base.tokens = 0.68;
        base.context_pollution = 0.62;
    }
    if action.action_type == ActionType::StoreMemory
        && string_value(state, "memory_type") == Some("preference")
    {
        base.memory_bloat = 0.38;
    }
    if action.action_type == ActionType::ExecuteCode {
        base.compute = base.compute.max(number_value(
            action
                .parameters
                .get("compute_estimate")
                .or_else(|| action.metadata.get("compute_estimate")),
            base.compute,
        ));
    }
    base.merge(&action.cost_overrides)
}

pub fn estimate_risk(action: &CandidateAction, state: &Value) -> RiskVector {
    let mut base = match action.action_type {
        ActionType::AnswerDirectly => RiskVector {
            hallucination_risk: 0.38,
            user_trust_risk: 0.14,
            ..RiskVector::default()
        },
        ActionType::SearchWeb => RiskVector {
            tool_risk: 0.18,
            staleness_risk: 0.12,
            source_quality_risk: 0.38,
            privacy_risk: 0.18,
            ..RiskVector::default()
        },
        ActionType::RetrieveContext => RiskVector {
            source_quality_risk: 0.22,
            hallucination_risk: 0.18,
            privacy_risk: 0.12,
            ..RiskVector::default()
        },
        ActionType::ReadFile => RiskVector {
            privacy_risk: 0.22,
            sensitivity: 0.20,
            ..RiskVector::default()
        },
        ActionType::InspectCode => RiskVector {
            privacy_risk: 0.20,
            source_quality_risk: 0.10,
            ..RiskVector::default()
        },
        ActionType::ExecuteCode => RiskVector {
            tool_risk: 0.66,
            external_side_effect_risk: 0.48,
            irreversibility: 0.30,
            compliance_risk: 0.25,
            user_trust_risk: 0.30,
            ..RiskVector::default()
        },
        ActionType::CallTool => RiskVector {
            tool_risk: 0.45,
            external_side_effect_risk: 0.32,
            privacy_risk: 0.32,
            compliance_risk: 0.20,
            ..RiskVector::default()
        },
        ActionType::AskUser => RiskVector {
            user_trust_risk: 0.22,
            ..RiskVector::default()
        },
        ActionType::StoreMemory => RiskVector {
            privacy_risk: 0.52,
            sensitivity: 0.48,
            future_misuse_risk: 0.40,
            user_trust_risk: 0.24,
            ..RiskVector::default()
        },
        ActionType::EscalateModel => RiskVector {
            privacy_risk: 0.34,
            tool_risk: 0.22,
            hallucination_risk: 0.16,
            compliance_risk: 0.18,
            ..RiskVector::default()
        },
        ActionType::ConciergeReview => RiskVector {
            user_trust_risk: 0.26,
            privacy_risk: 0.18,
            ..RiskVector::default()
        },
    };
    if matches!(
        action.action_type,
        ActionType::ReadFile | ActionType::StoreMemory | ActionType::EscalateModel
    ) && state.get("sensitivity").is_some()
    {
        let sensitivity = number_value(state.get("sensitivity"), 0.0);
        base.sensitivity = sensitivity;
        base.privacy_risk = base.privacy_risk.max(sensitivity * 0.85);
    }
    if action.action_type == ActionType::SearchWeb && !state_truthy(state, "freshness_required") {
        base.staleness_risk = 0.32;
    }
    if action.action_type == ActionType::AnswerDirectly && state_truthy(state, "freshness_required")
    {
        base.hallucination_risk = 0.74;
        base.staleness_risk = 0.72;
    }
    if action.action_type == ActionType::StoreMemory
        && state_truthy(state, "contains_sensitive_memory")
    {
        base.sensitivity = base.sensitivity.max(0.82);
        base.privacy_risk = base.privacy_risk.max(0.78);
    }
    base.merge(&action.risk_overrides)
}
