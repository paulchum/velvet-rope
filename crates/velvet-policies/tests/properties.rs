use std::sync::Arc;

use proptest::prelude::*;
use serde_json::json;
use velvet_core::{
    ActionMutation, ActionType, CandidateAction, Evidence, Policy, PolicyChain, PolicyContext,
    PolicyDecision, PolicyReason,
};
use velvet_policies::cost_ceiling::{CostCeilingConfig, CostCeilingPolicy};
use velvet_policies::pii_guard::{PiiGuardPolicy, ResponseMode};
use velvet_policies::rate_limiter::{RateLimit, RateLimiterConfig, RateLimiterPolicy};

fn action(action_type: ActionType) -> CandidateAction {
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

proptest! {
    #[test]
    fn pii_redaction_removes_original_email(local in "[a-z]{3,12}", domain in "[a-z]{3,12}") {
        let email = format!("{local}@{domain}.com");
        let mut candidate = action(ActionType::SearchWeb);
        candidate.parameters.insert("query".to_string(), json!(format!("find account {email}")));
        let policy = PiiGuardPolicy::default();
        let decision = policy.evaluate(&candidate, &PolicyContext::default());
        match decision {
            PolicyDecision::Modify { mutation, .. } => {
                mutation.apply_to(&mut candidate);
                let serialized = serde_json::to_string(&candidate.parameters).unwrap();
                prop_assert!(!serialized.contains(&email));
                prop_assert!(mutation.redactions.iter().any(|item| item.original_value == email));
            }
            other => prop_assert!(false, "expected redaction modify decision, got {other:?}"),
        }
    }

    #[test]
    fn cost_ceiling_denies_when_projected_spend_exceeds_limit(
        spent in 0.0f64..100.0,
        estimate in 0.01f64..100.0
    ) {
        let limit = spent + estimate / 2.0;
        let policy = CostCeilingPolicy::new(CostCeilingConfig {
            per_task_usd_limit: Some(limit),
            ..CostCeilingConfig::default()
        }).unwrap();
        let mut candidate = action(ActionType::CallTool);
        candidate.metadata.insert("usd_estimate".to_string(), json!(estimate));
        let mut context = PolicyContext::default();
        context.task_budget.spent_usd = spent;
        let decision = policy.evaluate(&candidate, &context);
        let denied = matches!(decision, PolicyDecision::Deny { .. });
        prop_assert!(denied);
    }

    #[test]
    fn rate_limiter_never_allows_more_than_configured_window_limit(limit in 1u64..20) {
        let policy = RateLimiterPolicy::new(
            RateLimiterConfig {
                aggregate: RateLimit {
                    window_ms: 10_000,
                    max_requests: limit,
                    sustained_per_second: 0.0,
                    burst_multiplier: 1.0,
                },
                ..RateLimiterConfig::default()
            },
        ).unwrap();
        let candidate = action(ActionType::SearchWeb);
        let context = PolicyContext {
            user_id: Some("property-user".to_string()),
            decision_unix_ms: 1_000,
            external_observations: [(
                "rate_limit_snapshots".to_string(),
                json!({
                    "action": {
                        "key": "property-user:SEARCH_WEB",
                        "now_unix_ms": 1000,
                        "window_start_unix_ms": -9000,
                        "request_count": limit,
                        "limit": limit,
                    }
                }),
            )]
            .into_iter()
            .collect(),
            ..PolicyContext::default()
        };
        let denied = matches!(policy.evaluate(&candidate, &context), PolicyDecision::Deny { .. });
        prop_assert!(denied);
    }
}

#[test]
fn policy_chain_short_circuit_records_skipped_policies() {
    struct DenyPolicy;
    impl Policy for DenyPolicy {
        fn name(&self) -> &str {
            "deny_policy"
        }
        fn version(&self) -> &str {
            "deny_policy_v1"
        }
        fn evaluate(
            &self,
            _candidate: &CandidateAction,
            _context: &PolicyContext,
        ) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: PolicyReason::new("deny_policy.test", "deny", "error"),
                jurisdiction_evidence: Evidence::new("deny_policy.test", "test"),
            }
        }
    }
    struct MutatePolicy;
    impl Policy for MutatePolicy {
        fn name(&self) -> &str {
            "mutate_policy"
        }
        fn version(&self) -> &str {
            "mutate_policy_v1"
        }
        fn evaluate(
            &self,
            _candidate: &CandidateAction,
            _context: &PolicyContext,
        ) -> PolicyDecision {
            PolicyDecision::Modify {
                mutation: ActionMutation::default(),
                reason: PolicyReason::new("mutate_policy.test", "mutate", "info"),
            }
        }
    }
    let chain = PolicyChain::new(vec![Arc::new(DenyPolicy), Arc::new(MutatePolicy)]);
    let result = chain.evaluate(&action(ActionType::SearchWeb), &PolicyContext::default());
    assert_eq!(result.decision, Some(velvet_core::DecisionType::Block));
    assert_eq!(result.policy_trace.len(), 2);
    assert_eq!(
        result.policy_trace[1].status,
        "not_evaluated_due_to_short_circuit"
    );
}

#[test]
fn pii_flag_mode_does_not_mutate_action() {
    let policy = PiiGuardPolicy::new(velvet_policies::pii_guard::PiiGuardConfig {
        default_mode: ResponseMode::Flag,
        ..Default::default()
    })
    .unwrap();
    let mut candidate = action(ActionType::SearchWeb);
    candidate
        .parameters
        .insert("query".to_string(), json!("email a@example.com"));
    let original = candidate.clone();
    let PolicyDecision::Modify { mutation, .. } =
        policy.evaluate(&candidate, &PolicyContext::default())
    else {
        panic!("expected flag modify decision");
    };
    mutation.apply_to(&mut candidate);
    assert_eq!(candidate, original);
    assert!(mutation.jurisdiction_evidence.is_some());
}
