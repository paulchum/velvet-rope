use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::Value;
use velvet_core::{
    ActionType, CandidateAction, Policy, PolicyChain, PolicyContext, PolicyDecision,
};
use velvet_policies::pii_guard::PiiGuardPolicy;
use velvet_policies::{
    cost_ceiling::{CostCeilingConfig, CostCeilingPolicy},
    escalation_gate::{EscalationGateConfig, EscalationGatePolicy},
    llm_atom::{LlmAtomConfig, LlmAtomPolicy},
    pii_guard::PiiGuardConfig,
    prompt_injection_detector::{PromptInjectionConfig, PromptInjectionPolicy as PidPolicy},
    rate_limiter::{RateLimiterConfig, RateLimiterPolicy},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn action_with_text(text: &str) -> CandidateAction {
    CandidateAction {
        action_type: ActionType::SearchWeb,
        parameters: [("query".to_string(), Value::String(text.to_string()))]
            .into_iter()
            .collect(),
        description: String::new(),
        certificate: None,
        budget_certificate: None,
        expected_improvement: None,
        novelty: None,
        confidence: None,
        cost_overrides: Default::default(),
        risk_overrides: Default::default(),
        metadata: Default::default(),
        source: Default::default(),
    }
}

#[test]
fn pii_guard_false_positive_fixture_stays_under_two_percent() {
    let path = root().join("tests/fixtures/policies/non_pii_500.json");
    let samples: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(path).expect("fixture should load"))
            .expect("fixture should parse");
    assert_eq!(samples.len(), 500);
    let policy = PiiGuardPolicy::default();
    let false_positives = samples
        .iter()
        .filter(|sample| {
            let text = sample["text"].as_str().expect("sample text");
            !matches!(
                policy.evaluate(&action_with_text(text), &PolicyContext::default()),
                PolicyDecision::Allow
            )
        })
        .count();
    assert!(
        false_positives < 10,
        "false positive rate must stay under 2%, got {false_positives}/500"
    );
}

#[test]
fn prompt_injection_fixture_templates_are_detected() {
    let path = root().join("tests/fixtures/policies/prompt_injection_200.json");
    let samples: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(path).expect("fixture should load"))
            .expect("fixture should parse");
    assert_eq!(samples.len(), 200);
    let policy = PidPolicy::default();
    let detected = samples
        .iter()
        .filter(|sample| {
            let text = sample["text"].as_str().expect("sample text");
            matches!(
                policy.evaluate(&action_with_text(text), &PolicyContext::default()),
                PolicyDecision::Deny { .. }
            )
        })
        .count();
    assert_eq!(detected, samples.len());
}

#[test]
fn llm_atom_uses_policy_visible_prebound_findings() {
    let policy = LlmAtomPolicy::new(LlmAtomConfig {
        rule_id: "rule_001_region_boundary".to_string(),
        extraction_question: "Does the action cross an unapproved residency region?".to_string(),
        ..LlmAtomConfig::default()
    })
    .expect("config");
    let mut action = action_with_text("copy records into an unapproved residency region");
    action.metadata.insert(
        "llm_atom_findings".to_string(),
        serde_json::json!({
            "rule_001_region_boundary": {
                "matched": true,
                "answer": "violation"
            }
        }),
    );

    assert!(matches!(
        policy.evaluate(&action, &PolicyContext::default()),
        PolicyDecision::Deny { .. }
    ));
}

#[test]
fn llm_atom_allows_absent_or_negative_findings() {
    let policy = LlmAtomPolicy::new(LlmAtomConfig {
        rule_id: "rule_001_region_boundary".to_string(),
        extraction_question: "Does the action cross an unapproved residency region?".to_string(),
        ..LlmAtomConfig::default()
    })
    .expect("config");
    let mut action = action_with_text("copy records into an approved residency region");
    action.metadata.insert(
        "llm_atom_findings".to_string(),
        serde_json::json!({"rule_001_region_boundary": {"matched": false}}),
    );

    assert!(matches!(
        policy.evaluate(&action, &PolicyContext::default()),
        PolicyDecision::Allow
    ));
}

#[test]
fn default_chain_regex_only_stays_under_five_ms_p99() {
    if cfg!(debug_assertions) && std::env::var_os("VELVET_STRICT_PERF_TESTS").is_none() {
        return;
    }
    let chain = PolicyChain::new(vec![
        std::sync::Arc::new(PiiGuardPolicy::new(PiiGuardConfig::default()).unwrap()),
        std::sync::Arc::new(PidPolicy::new(PromptInjectionConfig::default()).unwrap()),
        std::sync::Arc::new(CostCeilingPolicy::new(CostCeilingConfig::default()).unwrap()),
        std::sync::Arc::new(RateLimiterPolicy::new(RateLimiterConfig::default()).unwrap()),
        std::sync::Arc::new(EscalationGatePolicy::new(EscalationGateConfig::default()).unwrap()),
    ]);
    let context = PolicyContext::default();
    let action = action_with_text("airline baggage policy without personal data");
    for _ in 0..100 {
        let result = chain.evaluate(&action, &context);
        assert!(result.decision.is_none());
    }
    let mut samples = Vec::new();
    for _ in 0..1_000 {
        let start = Instant::now();
        let result = chain.evaluate(&action, &context);
        assert!(result.decision.is_none());
        samples.push(start.elapsed());
    }
    samples.sort();
    let p99 = samples[(samples.len() as f64 * 0.99) as usize];
    assert!(
        p99 < Duration::from_millis(5),
        "default policy chain p99 exceeded 5ms: {p99:?}"
    );
}
