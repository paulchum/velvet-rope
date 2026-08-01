use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;
use velvet_core::{CandidateAction, plan_for_candidate, route_with_thread};

fn execute_candidate() -> CandidateAction {
    serde_json::from_value(json!({
        "action_type": "EXECUTE_CODE",
        "parameters": {
            "command": ["/bin/echo", "ok"],
            "cwd": "/workspace"
        }
    }))
    .expect("candidate")
}

fn sandbox_plan_and_thread(c: &mut Criterion) {
    let candidate = execute_candidate();
    c.bench_function("sandbox_plan", |bench| {
        bench.iter(|| {
            plan_for_candidate(&json!({}), &candidate)
                .expect("plan")
                .expect("sandbox plan")
        })
    });
    c.bench_function("sandbox_thread_serialization", |bench| {
        bench.iter(|| {
            route_with_thread(
                &json!({}),
                std::slice::from_ref(&candidate),
                Some("thread_bench".to_string()),
                Some("2026-05-14T00:00:00+00:00".to_string()),
            )
            .expect("thread")
        })
    });
}

criterion_group!(benches, sandbox_plan_and_thread);
criterion_main!(benches);
