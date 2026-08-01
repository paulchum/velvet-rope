use proptest::prelude::*;
use serde_json::Number;
use serde_json::{Value, json};
use velvet_core::{
    ActionType, AdmissionEngine, CandidateAction, CandidateSource, DecisionType,
    EFFECT_VECTOR_HASH_DOMAIN, route,
};

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
        metadata: Default::default(),
        source: CandidateSource::Scenario,
        parameters: Default::default(),
    }
}

#[test]
fn same_logical_candidate_has_stable_hash_and_ignores_timestamps() {
    let mut first = candidate(ActionType::CallTool);
    first
        .metadata
        .insert("mcp_tool_key".to_string(), json!("server/read"));
    first
        .metadata
        .insert("capability_class".to_string(), json!("read_only"));
    first
        .metadata
        .insert("timestamp".to_string(), json!("2026-01-01T00:00:00Z"));
    first
        .parameters
        .insert("timestamp_input".to_string(), json!("2026-01-01T00:00:00Z"));

    let mut second = first.clone();
    second
        .metadata
        .insert("timestamp".to_string(), json!("2026-02-01T00:00:00Z"));
    second
        .parameters
        .insert("timestamp_input".to_string(), json!("2026-02-01T00:00:00Z"));

    assert_eq!(
        AdmissionEngine::normalize_candidate(&first).candidate_hash,
        AdmissionEngine::normalize_candidate(&second).candidate_hash
    );
}

#[test]
fn unknown_tool_capability_fails_closed_and_unknown_cost_is_budget_affecting() {
    let mut tool = candidate(ActionType::CallTool);
    tool.metadata
        .insert("mcp_tool_key".to_string(), json!("server/unknown"));

    let decision = route(&json!({"tool_call_requested": true}), &[tool]);
    let evaluated = decision
        .candidate_decisions
        .iter()
        .find(|candidate| candidate.action_type == ActionType::CallTool)
        .expect("tool candidate");
    let effect = evaluated.effect_vector.as_ref().expect("effect vector");

    assert!(matches!(
        evaluated.decision,
        DecisionType::Block | DecisionType::AskApproval | DecisionType::Escalate
    ));
    assert!(effect.approval_required);
    assert!(effect.budget_required);
    assert!(effect.cost_bound.upper_microusd > 0);
}

#[test]
fn high_risk_external_write_loses_to_direct_answer_without_approval() {
    let mut write = candidate(ActionType::CallTool);
    write.expected_improvement = Some(1.0);
    write
        .metadata
        .insert("mcp_tool_key".to_string(), json!("server/write"));
    write
        .metadata
        .insert("capability_class".to_string(), json!("external_write"));
    write
        .metadata
        .insert("approval_tier".to_string(), json!("concierge_review"));
    write
        .metadata
        .insert("budget_affecting".to_string(), json!(false));
    write
        .metadata
        .insert("non_budget_affecting".to_string(), json!(true));

    let decision = route(
        &json!({"tool_call_requested": true, "user_request": "Can you handle this safely?"}),
        &[write],
    );

    assert_eq!(decision.action_type, Some(ActionType::AnswerDirectly));
    assert_eq!(decision.decision, DecisionType::Execute);
}

#[test]
fn approval_required_candidate_returns_ask_approval_when_fallback_disabled() {
    let mut write = candidate(ActionType::CallTool);
    write
        .metadata
        .insert("mcp_tool_key".to_string(), json!("server/write"));
    write
        .metadata
        .insert("capability_class".to_string(), json!("external_write"));
    write
        .metadata
        .insert("approval_tier".to_string(), json!("concierge_review"));
    write
        .metadata
        .insert("budget_affecting".to_string(), json!(false));
    write
        .metadata
        .insert("non_budget_affecting".to_string(), json!(true));

    let decision = route(
        &json!({"router_config": {"admission_config": {"direct_answer_fallback": false}}}),
        &[write],
    );

    assert_eq!(decision.decision, DecisionType::AskApproval);
}

#[test]
fn objective_selects_highest_safe_admissible_candidate() {
    let mut low = candidate(ActionType::ReadFile);
    low.expected_improvement = Some(0.2);
    low.metadata
        .insert("budget_affecting".to_string(), json!(false));
    low.metadata
        .insert("non_budget_affecting".to_string(), json!(true));

    let mut high = low.clone();
    high.description = "higher utility read".to_string();
    high.expected_improvement = Some(0.9);

    let decision = route(&json!({}), &[low, high]);

    assert_eq!(decision.action_type, Some(ActionType::ReadFile));
    let selected = decision
        .candidate_decisions
        .iter()
        .filter(|candidate| candidate.decision == DecisionType::Execute)
        .max_by_key(|candidate| {
            candidate
                .admission_trace
                .as_ref()
                .expect("trace")
                .objective_components
                .objective_bps
        })
        .expect("selected");
    assert_eq!(selected.final_candidate.description, "higher utility read");
}

#[test]
fn production_route_does_not_emit_legacy_admission_score_and_trace_is_deterministic() {
    let mut read = candidate(ActionType::ReadFile);
    read.expected_improvement = Some(0.9);
    read.metadata
        .insert("budget_affecting".to_string(), json!(false));
    read.metadata
        .insert("non_budget_affecting".to_string(), json!(true));

    let first = route(&json!({}), &[read.clone()]);
    let second = route(&json!({}), &[read]);
    let first_candidate = &first.candidate_decisions[0];
    let second_candidate = &second.candidate_decisions[0];

    assert!(first_candidate.admission_score.is_none());
    assert!(first_candidate.admission_trace.is_some());
    assert_eq!(
        first_candidate.admission_trace_hash,
        second_candidate.admission_trace_hash
    );
    assert!(
        first_candidate
            .admission_trace
            .as_ref()
            .expect("trace")
            .effect_vector_hash
            .starts_with("sha256:")
    );
}

proptest! {
    #[test]
    fn malformed_candidate_json_does_not_panic(value in json_value_strategy()) {
        std::panic::catch_unwind(|| {
            let parsed: Result<CandidateAction, _> = serde_json::from_value(value);
            if let Ok(candidate) = parsed {
                let _ = AdmissionEngine::normalize_candidate(&candidate);
            }
        }).expect("candidate parsing and normalization should not panic");
    }
}

fn json_value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|value| Value::Number(Number::from(value))),
        "[A-Za-z0-9_:/.-]{0,32}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map("[A-Za-z0-9_]{0,16}", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

#[test]
fn exported_hash_domain_constant_is_versioned() {
    assert_eq!(EFFECT_VECTOR_HASH_DOMAIN, "Velvet:EffectVector:v1");
}
