use criterion::{Criterion, criterion_group, criterion_main};
use std::sync::Arc;

use velvet_core::{ActionType, CandidateAction, PolicyChain, PolicyContext, PolicyDecision};
use velvet_policies::{
    cost_ceiling::{CostCeilingConfig, CostCeilingPolicy},
    escalation_gate::{EscalationGateConfig, EscalationGatePolicy},
    pii_guard::{PiiGuardConfig, PiiGuardPolicy},
    prompt_injection_detector::{PromptInjectionConfig, PromptInjectionPolicy},
    rate_limiter::{RateLimiterConfig, RateLimiterPolicy},
};

fn default_chain_decision(c: &mut Criterion) {
    let chain = PolicyChain::new(vec![
        Arc::new(PiiGuardPolicy::new(PiiGuardConfig::default()).unwrap()),
        Arc::new(PromptInjectionPolicy::new(PromptInjectionConfig::default()).unwrap()),
        Arc::new(CostCeilingPolicy::new(CostCeilingConfig::default()).unwrap()),
        Arc::new(RateLimiterPolicy::new(RateLimiterConfig::default()).unwrap()),
        Arc::new(EscalationGatePolicy::new(EscalationGateConfig::default()).unwrap()),
    ]);
    let context = PolicyContext::default();
    let action = CandidateAction {
        action_type: ActionType::SearchWeb,
        parameters: [(
            "query".to_string(),
            serde_json::json!("release notes for deterministic routing"),
        )]
        .into_iter()
        .collect(),
        ..empty_action(ActionType::SearchWeb)
    };
    c.bench_function("default_policy_chain_regex_only", |bench| {
        bench.iter(|| {
            let result = chain.evaluate(&action, &context);
            assert!(result.decision.is_none());
            for entry in result.policy_trace {
                assert!(!matches!(entry.decision, PolicyDecision::Deny { .. }));
            }
        });
    });
}

fn empty_action(action_type: ActionType) -> CandidateAction {
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
        source: Default::default(),
        parameters: Default::default(),
    }
}

criterion_group!(benches, default_chain_decision);
criterion_main!(benches);
