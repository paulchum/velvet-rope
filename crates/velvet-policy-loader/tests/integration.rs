use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use proptest::prelude::*;
use tempfile::TempDir;
use velvet_core::{ActionType, CandidateAction, route_with_policy_graph_and_thread};
use velvet_policy_loader::{
    PolicyRuntime, load_policy_graph, migrate_legacy_document, policy_schema_json,
    run_policy_tests, schema_markdown, validate_yaml_document,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn temp_policy_dir() -> TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(
        directory.path().join("default.yaml"),
        fs::read_to_string(root().join("policies/default.yaml")).expect("default policy"),
    )
    .expect("write policy");
    directory
}

fn candidate() -> CandidateAction {
    CandidateAction {
        action_type: ActionType::SearchWeb,
        description: String::new(),
        certificate: None,
        budget_certificate: None,
        expected_improvement: Some(0.9),
        novelty: Some(0.9),
        confidence: Some(0.9),
        cost_overrides: Default::default(),
        risk_overrides: Default::default(),
        metadata: Default::default(),
        source: Default::default(),
        parameters: Default::default(),
    }
}

#[test]
fn generated_schema_accepts_all_example_documents() {
    for entry in fs::read_dir(root().join("examples/policies")).expect("examples dir") {
        let path = entry.expect("entry").path();
        let source = fs::read_to_string(&path).expect("example file");
        validate_yaml_document(&source).unwrap_or_else(|errors| panic!("{path:?}: {errors:?}"));
    }
}

#[test]
fn generated_schema_docs_are_current() {
    assert_eq!(
        schema_markdown(),
        fs::read_to_string(root().join("docs/policy-schema.md")).expect("generated docs")
    );
}

#[test]
fn published_json_schema_is_current() {
    assert_eq!(
        policy_schema_json(),
        serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(root().join("schemas/policy-v1alpha1.schema.json"))
                .expect("published schema")
        )
        .expect("published schema json")
    );
}

#[test]
fn semantic_errors_include_path_line_and_hint() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(
        directory.path().join("bad.yaml"),
        fs::read_to_string(root().join("examples/policies/default.yaml"))
            .expect("example")
            .replace("soft_ceiling_fraction: 0.8", "soft_ceiling_fraction: 1.5"),
    )
    .expect("write policy");
    let error = match load_policy_graph(directory.path()) {
        Ok(_) => panic!("invalid graph"),
        Err(mut errors) => errors.remove(0),
    };
    assert!(error.path.ends_with("bad.yaml"));
    assert!(error.line > 0);
    assert_eq!(error.field_path, "spec.config.soft_ceiling_fraction");
    assert!(error.hint.contains("fraction"));
}

#[test]
fn failed_reload_keeps_previous_graph_and_emits_one_event() {
    let directory = temp_policy_dir();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let runtime = PolicyRuntime::new_with_sink(
        directory.path(),
        false,
        Arc::new(move |event| sink_events.lock().expect("events").push(event)),
    )
    .expect("runtime");
    let before = runtime.snapshot().revision().to_string();
    fs::write(
        directory.path().join("default.yaml"),
        fs::read_to_string(root().join("policies/default.yaml"))
            .expect("default")
            .replace("soft_ceiling_fraction: 0.8", "soft_ceiling_fraction: 1.5"),
    )
    .expect("write invalid");
    assert!(!runtime.reload_now());
    assert_eq!(runtime.snapshot().revision(), before);
    let events = events.lock().expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "policy_reload_failed");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn in_flight_decisions_observe_one_policy_revision(reloads in 1usize..8) {
        let directory = temp_policy_dir();
        let runtime = Arc::new(PolicyRuntime::new(directory.path(), false).expect("runtime"));
        let source_v1 = fs::read_to_string(root().join("policies/default.yaml")).expect("default");
        let source_v2 = source_v1.replace("version: 1", "version: 2");
        let mut workers = Vec::new();
        for _ in 0..8 {
            let runtime = runtime.clone();
            workers.push(thread::spawn(move || {
                let action = candidate();
                let mut results = Vec::new();
                for _ in 0..1_250 {
                    let graph = runtime.snapshot();
                    let trace = route_with_policy_graph_and_thread(
                        &serde_json::json!({"freshness_required": true}),
                        std::slice::from_ref(&action),
                        &graph,
                        "default",
                        None,
                        None,
                    )
                    .expect("thread")
                    .thread;
                    let versions = trace
                        .scored_candidates
                        .iter()
                        .flat_map(|candidate| candidate.policy_trace.iter())
                        .map(|entry| entry.config_version.clone())
                        .collect::<std::collections::BTreeSet<_>>();
                    results.push((trace.policy_chain_revision, versions));
                }
                results
            }));
        }
        for index in 0..reloads {
            let source = if index % 2 == 0 { &source_v2 } else { &source_v1 };
            fs::write(directory.path().join("default.yaml"), source).expect("rewrite policy");
            prop_assert!(runtime.reload_now());
        }
        let results = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        prop_assert_eq!(results.len(), 10_000);
        for (_, versions) in results {
            prop_assert_eq!(versions.len(), 1);
        }
    }
}

#[test]
fn policy_test_harness_passes_examples() {
    run_policy_tests(
        &root().join("examples/policies/default.yaml"),
        &root().join("examples/policies/cost-ceiling-tests.yaml"),
    )
    .expect("policy tests pass");
}

#[test]
fn migrator_rewrites_legacy_cost_ceiling_shape() {
    let output = migrate_legacy_document(
        &PathBuf::from("small_org.yaml"),
        r#"
schema_version: cost_ceiling.v1
config_version: cost_ceiling_small_org_v1
soft_ceiling_ratio: 0.8
scopes:
  task_usd: 1.0
  user_usd: 10.0
  organization_usd: 100.0
action_costs: {}
"#,
    )
    .expect("migration")
    .expect("legacy file should migrate");
    assert!(output.contains("apiVersion: velvet.io/v1alpha1"));
    assert!(output.contains("soft_ceiling_fraction: 0.8"));
    assert!(output.contains("per_task_usd_limit: 1.0"));
    assert!(!output.contains("schema_version"));
}
