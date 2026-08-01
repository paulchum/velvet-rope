use std::fs;

use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::TempDir;
use velvet_policy_loader::{PolicyRuntime, load_policy_graph};

fn hundred_policy_dir() -> TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut yaml = String::new();
    for index in 0..100 {
        if index > 0 {
            yaml.push_str("---\n");
        }
        yaml.push_str(&format!(
            r#"apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: cost-{index}
  version: 1
spec:
  type: cost_ceiling
  config:
    per_task_usd_limit: 1.0
    per_user_daily_usd_limit: 10.0
    per_org_monthly_usd_limit: 100.0
    soft_ceiling_fraction: 0.8
    cost_model: {{}}
"#
        ));
    }
    yaml.push_str("---\n");
    yaml.push_str(
        r#"apiVersion: velvet.io/v1alpha1
kind: PolicyChain
metadata:
  name: default
  version: 1
spec:
  policies:
"#,
    );
    for index in 0..100 {
        yaml.push_str(&format!("    - cost-{index}\n"));
    }
    fs::write(directory.path().join("policies.yaml"), yaml).expect("write policies");
    directory
}

fn load_reload(c: &mut Criterion) {
    let directory = hundred_policy_dir();
    c.bench_function("policy_loader_initial_load_100", |bench| {
        bench.iter(|| load_policy_graph(directory.path()).expect("graph"))
    });

    let runtime = PolicyRuntime::new(directory.path(), false).expect("runtime");
    c.bench_function("policy_loader_reload_100", |bench| {
        bench.iter(|| {
            assert!(runtime.reload_now());
        })
    });
    c.bench_function("policy_graph_snapshot", |bench| {
        bench.iter(|| runtime.snapshot())
    });
}

criterion_group!(benches, load_reload);
criterion_main!(benches);
