use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};
use velvet_core::{
    ActionType, CandidateAction, DecisionType, ExecutionStatus, THREAD_SCHEMA_VERSION,
    evaluate_memory, redact_secrets, route, route_with_thread,
};
#[cfg(feature = "legacy-heuristic-routing")]
use velvet_core::{BudgetState, PricingContext, PricingPolicy, score_action_with_pricing};

fn root() -> PathBuf {
    let manifest_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    if manifest_candidate.join("scenarios").is_dir() {
        return manifest_candidate;
    }
    std::env::current_dir().expect("current working directory")
}

fn candidate(action_type: ActionType) -> CandidateAction {
    CandidateAction {
        action_type,
        description: String::new(),
        certificate: None,
        budget_certificate: None,
        expected_improvement: None,
        novelty: None,
        confidence: None,
        cost_overrides: Default::default(),
        risk_overrides: Default::default(),
        metadata: [
            ("budget_affecting".to_string(), json!(false)),
            ("non_budget_affecting".to_string(), json!(true)),
        ]
        .into_iter()
        .collect(),
        source: Default::default(),
        parameters: Default::default(),
    }
}

fn zero_cost() -> Value {
    json!({
        "tokens": 0.0,
        "latency": 0.0,
        "money": 0.0,
        "compute": 0.0,
        "api_calls": 0.0,
        "context_pollution": 0.0,
        "memory_bloat": 0.0,
        "user_attention": 0.0,
        "privacy_exposure": 0.0,
        "coordination_overhead": 0.0,
        "opportunity_cost": 0.0
    })
}

fn zero_risk() -> Value {
    json!({
        "privacy_risk": 0.0,
        "tool_risk": 0.0,
        "external_side_effect_risk": 0.0,
        "hallucination_risk": 0.0,
        "staleness_risk": 0.0,
        "source_quality_risk": 0.0,
        "irreversibility": 0.0,
        "sensitivity": 0.0,
        "compliance_risk": 0.0,
        "user_trust_risk": 0.0,
        "future_misuse_risk": 0.0
    })
}

fn zero_cost_map() -> BTreeMap<String, f64> {
    serde_json::from_value(zero_cost()).expect("zero cost map")
}

fn zero_risk_map() -> BTreeMap<String, f64> {
    serde_json::from_value(zero_risk()).expect("zero risk map")
}

fn certificate_json(
    outcome: &str,
    liability_mode: &str,
    mean_bound: f64,
    inspection_lower_bound: f64,
    safe_upper_bound: f64,
    liability_price: f64,
) -> Value {
    json!({
        "schema_version": "velvet.certificate_evidence.v2",
        "family": "beta_bernoulli",
        "arm_id": "arm_2",
        "baseline": 0.55,
        "lookback_horizon": 3,
        "delight_scale": 1.0,
        "liability_price": liability_price,
        "threshold": liability_price,
        "inspection_lower_bound": inspection_lower_bound,
        "safe_upper_bound": safe_upper_bound,
        "outcome": outcome,
        "liability_mode": liability_mode,
        "typed_effect": {
            "max_payoff": 0.45,
            "mean_bound": mean_bound,
            "variance_bound": 1.0,
            "resource_scope": "posterior_option",
            "write_footprint": [],
            "dependence_kind": "unspecified",
            "filtration_hash": "test-filtration",
            "filtration_index": 0,
            "adapted": true
        },
        "compensator_step": {
            "arm": 1,
            "baseline": 0.55,
            "horizon": 3,
            "z_current": safe_upper_bound,
            "expected_z_next": safe_upper_bound,
            "increment": 0.0,
            "initial_optionality": safe_upper_bound - mean_bound,
            "cumulative_increment": 0.0
        },
        "theorem_refs": ["docs/math/certified_max_de_theorem.txt"]
    })
}

#[test]
fn scenario_decisions_remain_deterministic() {
    for scenario_path in fs::read_dir(root().join("scenarios")).expect("scenario dir") {
        let path = scenario_path.expect("scenario entry").path();
        let scenario: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("scenario should load"))
                .expect("scenario should parse");
        let candidates: Vec<CandidateAction> =
            serde_json::from_value(scenario["candidates"].clone()).expect("candidates");
        let first = route(&scenario["state"], &candidates);
        let second = route(&scenario["state"], &candidates);
        let expected = scenario["state"]
            .get("expected_action")
            .and_then(Value::as_str)
            .expect("scenario expected action");
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_value(first.action_type).expect("action"),
            json!(expected)
        );
        assert!(!first.seal_id.expect("seal").is_empty());
    }
}

#[test]
fn edge_cases_are_policy_visible() {
    let empty = route(&json!({}), &[]);
    assert_eq!(empty.action_type, None);
    assert_eq!(empty.decision, DecisionType::Skip);

    let file_decision = route(
        &json!({"available_context": []}),
        &[candidate(ActionType::ReadFile)],
    );
    assert_eq!(file_decision.action_type, Some(ActionType::ReadFile));
    assert_eq!(file_decision.candidate_decisions[0].policy_trace.len(), 0);

    let memory = evaluate_memory(
        "My API key is secret-test-value.",
        &json!({"project": "Velvet"}),
        Some("2026-05-14T00:00:00+00:00".to_string()),
    );
    assert_eq!(memory.decision, DecisionType::AskApproval);

    let redacted = redact_secrets(json!({
        "api_key": "abc",
        "nested": {"Authorization": "bearer x"},
        "safe": "ok"
    }));
    assert_eq!(
        redacted,
        json!({
            "api_key": "[REDACTED]",
            "nested": {"Authorization": "[REDACTED]"},
            "safe": "ok"
        })
    );
}

#[test]
fn thread_schema_v9_is_sealed_and_auditable() {
    let answer = CandidateAction {
        expected_improvement: Some(1.0),
        novelty: Some(1.0),
        confidence: Some(1.0),
        ..candidate(ActionType::AnswerDirectly)
    };
    let result = route_with_thread(
        &json!({"freshness_required": true, "seal_seed": 7}),
        &[answer, candidate(ActionType::SearchWeb)],
        Some("thread_fixture_v9".to_string()),
        Some("2026-05-14T00:00:00+00:00".to_string()),
    )
    .expect("thread");
    assert_eq!(result.thread.schema_version, THREAD_SCHEMA_VERSION);
    assert_eq!(result.thread.schema_version, "9.0");
    assert_eq!(result.thread.policy_chain_name, "inline");
    assert_eq!(result.thread.policy_chain_revision, "inline");
    assert_eq!(result.thread.router_version, "router_v1");
    assert_eq!(result.thread.scorer_version, "admission_optimizer_v1");
    assert_eq!(result.thread.pricing_policy_name, "hybrid_production");
    assert_eq!(result.thread.pricing_policy_version, "entry_pricing_v2");
    assert_eq!(
        result.thread.selected_action,
        Some(ActionType::AnswerDirectly)
    );
    assert_eq!(result.thread.selected_candidate_index, Some(0));
    assert_eq!(result.thread.seal_seed, 7);
    assert_eq!(result.thread.seal_status, "decision_sealed");
    assert!(!result.thread.seal_id.is_empty());
    assert_eq!(result.thread.raw_candidates.len(), 2);
    assert_eq!(result.thread.policy_filtered_candidates.len(), 2);
    assert_eq!(result.thread.scored_candidates.len(), 2);
    assert_eq!(result.thread.rejected_actions.len(), 1);
    let answer_trace = result.thread.scored_candidates[0]
        .admission_trace
        .as_ref()
        .expect("admission trace");
    assert_eq!(answer_trace.schema_version, "velvet.admission_trace.v1");
    assert!(answer_trace.objective_components.objective_bps > i64::MIN);
    assert!(
        result.thread.scored_candidates[0]
            .admission_trace_hash
            .as_ref()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_eq!(result.thread.execution_result, None);
    assert_eq!(
        result.thread.scored_candidates[0].final_action.action_type,
        ActionType::AnswerDirectly
    );
    assert!(result.thread.rejected_actions.iter().any(|candidate| {
        candidate.admission_trace.as_ref().is_some_and(|trace| {
            trace.hard_constraints.iter().any(|constraint| {
                constraint.constraint_id == "budget_reserved"
                    && !constraint.passed
                    && constraint.reason_code == "budget_required"
            })
        })
    }));
}

#[test]
fn certificate_outcomes_drive_runtime_routing() {
    let inspect: CandidateAction = serde_json::from_value(json!({
        "action_type": "RETRIEVE_CONTEXT",
        "metadata": {"budget_affecting": false, "non_budget_affecting": true},
        "certificate": certificate_json("inspect", "false_lockout", 0.030375, 0.07035201317652101, 0.11225469081352345, 0.06),
        "cost_overrides": zero_cost(),
        "risk_overrides": zero_risk()
    }))
    .expect("inspect candidate");
    let host = CandidateAction {
        expected_improvement: Some(0.02),
        novelty: Some(1.0),
        confidence: Some(1.0),
        cost_overrides: zero_cost_map(),
        risk_overrides: zero_risk_map(),
        ..candidate(ActionType::AnswerDirectly)
    };
    let result = route_with_thread(
        &json!({
            "host_action": "ANSWER_DIRECTLY",
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.06,
                "lambda_cap": 0.06
            }
        }),
        &[host, inspect],
        Some("thread_certificate_inspect".to_string()),
        Some("2026-05-24T00:00:00+00:00".to_string()),
    )
    .expect("thread");
    assert_eq!(
        result.decision.action_type,
        Some(ActionType::RetrieveContext)
    );
    let selected = result.thread.scored_candidates[1].clone();
    assert_eq!(
        selected.certificate.as_ref().expect("certificate").outcome,
        velvet_core::CertificateOutcome::Inspect
    );
    assert!(
        selected
            .admission_trace
            .as_ref()
            .expect("admission trace")
            .effect_vector_hash
            .starts_with("sha256:")
    );

    let lockout: CandidateAction = serde_json::from_value(json!({
        "action_type": "RETRIEVE_CONTEXT",
        "metadata": {"budget_affecting": false},
        "certificate": certificate_json("lockout", "certifiable_waste", 0.0102515625, 0.026906453840799847, 0.04902110044994057, 0.06)
    }))
    .expect("lockout candidate");
    let lockout_decision = route(&json!({}), &[lockout]);
    assert_eq!(lockout_decision.decision, DecisionType::Block);
    assert_eq!(
        lockout_decision.candidate_decisions[0]
            .short_circuit
            .as_deref(),
        Some("certified_lockout")
    );

    let refinement: CandidateAction = serde_json::from_value(json!({
        "action_type": "RETRIEVE_CONTEXT",
        "metadata": {"budget_affecting": false},
        "certificate": certificate_json("refinement", "false_lockout", 0.030375, 0.050, 0.11225469081352345, 0.06)
    }))
    .expect("refinement candidate");
    let refinement_decision = route(&json!({}), &[refinement]);
    assert_eq!(refinement_decision.decision, DecisionType::Delay);
    assert_eq!(
        refinement_decision.candidate_decisions[0]
            .short_circuit
            .as_deref(),
        Some("certified_refinement")
    );

    let inconsistent: CandidateAction = serde_json::from_value(json!({
        "action_type": "RETRIEVE_CONTEXT",
        "metadata": {"budget_affecting": false},
        "certificate": certificate_json("inspect", "certifiable_waste", 0.0102515625, 0.026906453840799847, 0.04902110044994057, 0.06)
    }))
    .expect("inconsistent certificate candidate");
    let inconsistent_decision = route(&json!({}), &[inconsistent]);
    assert_eq!(inconsistent_decision.decision, DecisionType::Block);
    assert_eq!(
        inconsistent_decision.candidate_decisions[0]
            .short_circuit
            .as_deref(),
        Some("invalid_certificate")
    );
}

#[test]
fn dirichlet_categorical_certificates_are_supported() {
    let candidate: CandidateAction = serde_json::from_value(json!({
        "action_type": "RETRIEVE_CONTEXT",
        "metadata": {"budget_affecting": false},
        "certificate": {
            "family": "dirichlet_categorical",
            "arm_id": "categorical_arm",
            "baseline": 1.2,
            "lookback_horizon": 2,
            "delight_scale": 1.0,
            "liability_price": 0.3,
            "threshold": 0.3,
            "inspection_lower_bound": 0.1,
            "safe_upper_bound": 0.11931471805599453,
            "outcome": "lockout",
            "liability_mode": "posterior_certificate",
            "schema_version": "velvet.certificate_evidence.v2",
            "typed_effect": {
                "max_payoff": 0.2,
                "mean_bound": 0.05,
                "variance_bound": 1.0,
                "resource_scope": "posterior_option",
                "write_footprint": [],
                "dependence_kind": "unspecified",
                "filtration_hash": "test-filtration",
                "filtration_index": 0,
                "adapted": true
            },
            "compensator_step": null,
            "theorem_refs": ["docs/math/dirichlet_categorical_max_de_certificates.txt"]
        }
    }))
    .expect("dirichlet categorical candidate");

    let decision = route(&json!({}), &[candidate]);

    assert_eq!(decision.decision, DecisionType::Block);
    assert_eq!(
        decision.candidate_decisions[0].short_circuit.as_deref(),
        Some("certified_lockout")
    );
}

#[test]
fn expanded_action_surface_has_policy_decisions() {
    let actions = [
        ActionType::AnswerDirectly,
        ActionType::SearchWeb,
        ActionType::RetrieveContext,
        ActionType::ReadFile,
        ActionType::InspectCode,
        ActionType::ExecuteCode,
        ActionType::CallTool,
        ActionType::AskUser,
        ActionType::StoreMemory,
        ActionType::EscalateModel,
        ActionType::ConciergeReview,
    ];
    for action in actions {
        let decision = route(&json!({}), &[candidate(action)]);
        assert!(
            decision
                .candidate_decisions
                .iter()
                .any(|candidate| candidate.action_type == action)
        );
        assert!(!decision.candidate_decisions.is_empty());
        assert!(
            decision
                .candidate_decisions
                .iter()
                .all(|candidate| candidate.admission_trace.is_some())
        );
    }
    assert_eq!(ExecutionStatus::NotRun, ExecutionStatus::NotRun);
}

#[test]
#[cfg(feature = "legacy-heuristic-routing")]
fn pricing_policies_have_distinct_deterministic_schedules() {
    let action = candidate(ActionType::SearchWeb);
    let state = json!({"freshness_required": true});

    let mut fixed = PricingContext {
        pricing_policy: PricingPolicy::FixedPriceBaseline,
        ..PricingContext::default()
    };
    let fixed_score = score_action_with_pricing(&action, &state, &fixed);
    assert_eq!(fixed_score.pricing_breakdown.final_lambda, 0.18);

    let linear_low = PricingContext {
        pricing_policy: PricingPolicy::LinearExhaustion,
        budget_state: BudgetState {
            tokens_remaining: 0.2,
            tool_calls_remaining: 0.2,
            dollars_remaining: 0.2,
            latency_ms_remaining: 0.2,
            task_horizon_remaining: 0.2,
            api_calls_remaining: 0.2,
            money_remaining: 0.2,
            ..BudgetState::default()
        },
        ..PricingContext::default()
    };
    assert!(
        score_action_with_pricing(&action, &state, &linear_low)
            .pricing_breakdown
            .final_lambda
            > fixed_score.pricing_breakdown.final_lambda
    );

    let inverse_full = PricingContext {
        pricing_policy: PricingPolicy::InverseHorizon,
        ..PricingContext::default()
    };
    let inverse_full_price = score_action_with_pricing(&action, &state, &inverse_full)
        .pricing_breakdown
        .final_lambda;
    fixed.budget_state.task_horizon_remaining = 0.20;
    fixed.pricing_policy = PricingPolicy::InverseHorizon;
    let inverse_low_price = score_action_with_pricing(&action, &state, &fixed)
        .pricing_breakdown
        .final_lambda;
    assert!(inverse_low_price > inverse_full_price);

    let override_high = PricingContext {
        pricing_policy: PricingPolicy::OverrideRateAware,
        override_rate: 1.0,
        ..PricingContext::default()
    };
    let override_low = PricingContext {
        pricing_policy: PricingPolicy::OverrideRateAware,
        override_rate: 0.10,
        ..PricingContext::default()
    };
    assert!(
        score_action_with_pricing(&action, &state, &override_low)
            .pricing_breakdown
            .final_lambda
            > score_action_with_pricing(&action, &state, &override_high)
                .pricing_breakdown
                .final_lambda
    );

    let hybrid = PricingContext::default();
    assert_eq!(
        score_action_with_pricing(&action, &state, &hybrid)
            .pricing_breakdown
            .pricing_policy_name,
        "hybrid_production"
    );
}

#[test]
#[cfg(feature = "legacy-heuristic-routing")]
fn uncertainty_softens_only_with_budget_headroom() {
    let action = CandidateAction {
        confidence: Some(0.80),
        ..candidate(ActionType::EscalateModel)
    };
    let context = PricingContext {
        pricing_policy: PricingPolicy::UncertaintyCompensated,
        ..PricingContext::default()
    };
    let certain = score_action_with_pricing(&action, &json!({}), &context)
        .pricing_breakdown
        .final_lambda;
    let uncertain =
        score_action_with_pricing(&action, &json!({"high_uncertainty": true}), &context)
            .pricing_breakdown
            .final_lambda;
    assert!(uncertain < certain);

    let exhausted = PricingContext {
        pricing_policy: PricingPolicy::UncertaintyCompensated,
        budget_state: BudgetState {
            model_escalations_remaining: 0.0,
            compute_remaining: 0.0,
            ..BudgetState::default()
        },
        ..PricingContext::default()
    };
    let breakdown =
        score_action_with_pricing(&action, &json!({"high_uncertainty": true}), &exhausted)
            .pricing_breakdown;
    assert!(breakdown.hard_budget_exhausted);
    assert_eq!(breakdown.final_lambda, exhausted.lambda_cap);
}

#[test]
#[cfg(feature = "legacy-heuristic-routing")]
fn entry_price_records_fixed_rope_difference() {
    let action = candidate(ActionType::SearchWeb);
    let context = PricingContext {
        budget_state: BudgetState {
            tool_calls_remaining: 0.0,
            api_calls_remaining: 0.0,
            ..BudgetState::default()
        },
        ..PricingContext::default()
    };
    let breakdown =
        score_action_with_pricing(&action, &json!({"freshness_required": true}), &context)
            .pricing_breakdown;
    assert!(breakdown.fixed_clears_rope);
    assert!(!breakdown.clears_rope);
    assert!(breakdown.differs_from_fixed);
}

#[test]
#[cfg(feature = "legacy-heuristic-routing")]
fn risk_weighting_hardens_privacy_invasive_actions() {
    let action = candidate(ActionType::StoreMemory);
    let context = PricingContext {
        pricing_policy: PricingPolicy::RiskWeighted,
        ..PricingContext::default()
    };
    let low = score_action_with_pricing(
        &action,
        &json!({"memory_candidate_value": 0.8, "memory_novelty": 0.8, "sensitivity": 0.05}),
        &context,
    )
    .pricing_breakdown
    .final_lambda;
    let high = score_action_with_pricing(
        &action,
        &json!({"memory_candidate_value": 0.8, "memory_novelty": 0.8, "sensitivity": 0.9}),
        &context,
    )
    .pricing_breakdown
    .final_lambda;
    assert!(high > low);
}

#[test]
fn malformed_budget_state_is_defaulted_and_traced() {
    let result = route_with_thread(
        &json!({
            "freshness_required": true,
            "budget_state": {
                "tokens_remaining": "NaN",
                "tool_calls_remaining": 1.0
            }
        }),
        &[candidate(ActionType::SearchWeb)],
        None,
        Some("2026-05-14T00:00:00+00:00".to_string()),
    )
    .expect("thread");
    assert!(
        result
            .thread
            .budget_state
            .fallback_triggers
            .contains(&"budget_tokens_remaining_malformed_defaulted".to_string())
    );
}

#[test]
fn seal_id_changes_with_pricing_policy() {
    let candidates = [
        candidate(ActionType::AnswerDirectly),
        candidate(ActionType::SearchWeb),
    ];
    let fixed = route(
        &json!({
            "freshness_required": true,
            "pricing_policy": "fixed_price_baseline"
        }),
        &candidates,
    );
    let hybrid = route(
        &json!({
            "freshness_required": true,
            "pricing_policy": "hybrid_production"
        }),
        &candidates,
    );
    assert_ne!(fixed.seal_id, hybrid.seal_id);
}
