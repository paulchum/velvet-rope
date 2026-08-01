use proptest::prelude::*;
use serde_json::json;
use std::time::{Duration, Instant};
use velvet_core::{
    CandidateAction, ContainerRuntime, MountMode, MountSpec, ResourceLimits, SandboxBackendKind,
    SandboxConfig, plan_for_candidate, route_with_thread,
};

fn execute_candidate() -> CandidateAction {
    serde_json::from_value(json!({
        "action_type": "EXECUTE_CODE",
        "parameters": {
            "command": ["python3", "-c", "print('ok')"],
            "cwd": "/workspace"
        }
    }))
    .expect("candidate")
}

#[test]
fn development_defaults_to_lightweight() {
    let plan = plan_for_candidate(&json!({}), &execute_candidate())
        .expect("plan")
        .expect("sandbox plan");
    assert_eq!(plan.backend, SandboxBackendKind::Lightweight);
}

#[test]
fn production_defaults_to_digest_pinned_container() {
    let plan = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "mode": "production",
                "container_runtime": "podman",
                "container_image": format!("python@sha256:{}", "a".repeat(64))
            }
        }),
        &execute_candidate(),
    )
    .expect("plan")
    .expect("sandbox plan");
    assert_eq!(plan.backend, SandboxBackendKind::Container);
    assert_eq!(
        plan.provenance.container_runtime,
        Some(ContainerRuntime::Podman)
    );
}

#[test]
fn production_never_admits_none() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "mode": "production",
                "backend": "none",
                "allow_unsafe_exec": true
            }
        }),
        &execute_candidate(),
    )
    .expect_err("none must be rejected");
    assert!(
        error.contains("forbidden outside development") || error.contains("unavailable"),
        "{error}"
    );
}

#[test]
fn sandbox_absolute_cwd_requires_workspace_or_configured_mount_for_non_container_backend() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "lightweight"
            }
        }),
        &serde_json::from_value(json!({
            "action_type": "EXECUTE_CODE",
            "parameters": {
                "command": ["python3", "-c", "print('ok')"],
                "cwd": "/tmp/outside"
            }
        }))
        .expect("candidate"),
    )
    .expect_err("undeclared absolute cwd must be rejected");
    assert!(error.contains("cwd must be relative"));
}

#[test]
fn sandbox_absolute_cwd_under_configured_mount_is_allowed() {
    let plan = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "lightweight",
                "mounts": [{
                    "host_path": "/tmp/outside",
                    "sandbox_path": "/tmp/outside",
                    "mode": "read_only"
                }]
            }
        }),
        &serde_json::from_value(json!({
            "action_type": "EXECUTE_CODE",
            "parameters": {
                "command": ["python3", "-c", "print('ok')"],
                "cwd": "/tmp/outside/project"
            }
        }))
        .expect("candidate"),
    )
    .expect("plan")
    .expect("sandbox plan");
    assert_eq!(plan.command.cwd, "/tmp/outside/project");
}

#[test]
fn seal_identity_changes_when_sandbox_profile_changes() {
    let candidate = execute_candidate();
    let first = route_with_thread(
        &json!({}),
        std::slice::from_ref(&candidate),
        Some("thread_first".to_string()),
        Some("2026-05-14T00:00:00+00:00".to_string()),
    )
    .expect("thread");
    let second = route_with_thread(
        &json!({
            "sandbox_config": {
                "limits": {
                    "cpu_seconds": 10,
                    "memory_bytes": 536870912,
                    "wall_clock_ms": 10000,
                    "max_fs_writes_bytes": 8388608,
                    "max_stdout_bytes": 24000,
                    "max_processes": 64
                }
            }
        }),
        &[candidate],
        Some("thread_second".to_string()),
        Some("2026-05-14T00:00:00+00:00".to_string()),
    )
    .expect("thread");
    assert_ne!(first.thread.seal_id, second.thread.seal_id);
}

#[test]
fn sandbox_planning_stays_under_five_ms_p99() {
    if cfg!(debug_assertions) && std::env::var_os("VELVET_STRICT_PERF_TESTS").is_none() {
        return;
    }
    let candidate = execute_candidate();
    let state = json!({});
    for _ in 0..100 {
        let _ = plan_for_candidate(&state, &candidate)
            .expect("plan")
            .expect("sandbox plan");
    }
    let mut samples = Vec::new();
    for _ in 0..1_000 {
        let start = Instant::now();
        let plan = plan_for_candidate(&state, &candidate)
            .expect("plan")
            .expect("sandbox plan");
        assert!(!plan.provenance.profile_hash.is_empty());
        samples.push(start.elapsed());
    }
    samples.sort();
    let p99 = samples[(samples.len() as f64 * 0.99) as usize];
    assert!(
        p99 < Duration::from_millis(5),
        "sandbox planning p99 exceeded 5ms: {p99:?}"
    );
}

proptest! {
    #[test]
    fn equivalent_profiles_hash_identically(
        left_mount in "[a-z]{1,8}",
        right_mount in "[a-z]{1,8}",
    ) {
        let candidate = execute_candidate();
        let left = SandboxConfig {
            env_list: vec!["PATH".to_string(), "HOME".to_string()],
            mounts: vec![
                MountSpec {
                    host_path: format!("/{left_mount}"),
                    sandbox_path: format!("/{left_mount}"),
                    mode: MountMode::ReadOnly,
                },
                MountSpec {
                    host_path: format!("/{right_mount}"),
                    sandbox_path: format!("/{right_mount}"),
                    mode: MountMode::ReadWrite,
                },
            ],
            limits: ResourceLimits::default(),
            ..SandboxConfig::default()
        };
        let mut right = left.clone();
        right.env_list.reverse();
        right.mounts.reverse();
        let left_plan = plan_for_candidate(
            &json!({"sandbox_config": serde_json::to_value(left).unwrap()}),
            &candidate,
        ).unwrap().unwrap();
        let right_plan = plan_for_candidate(
            &json!({"sandbox_config": serde_json::to_value(right).unwrap()}),
            &candidate,
        ).unwrap().unwrap();
        prop_assert_eq!(left_plan.provenance.profile_hash, right_plan.provenance.profile_hash);
    }
}

#[cfg(feature = "sandbox-required")]
#[test]
fn sandbox_required_removes_none_backend() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "none",
                "allow_unsafe_exec": true
            }
        }),
        &execute_candidate(),
    )
    .expect_err("none must be unavailable");
    assert!(error.contains("unavailable"));
}

#[cfg(feature = "gvisor")]
#[test]
fn gvisor_feature_fails_closed_until_backend_is_registered() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "gvisor"
            }
        }),
        &execute_candidate(),
    )
    .expect_err("unknown gvisor backend must fail closed");
    assert!(error.contains("invalid sandbox_config"), "{error}");
}

#[cfg(feature = "firecracker")]
#[test]
fn firecracker_feature_fails_closed_until_backend_is_registered() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "firecracker"
            }
        }),
        &execute_candidate(),
    )
    .expect_err("unknown firecracker backend must fail closed");
    assert!(error.contains("invalid sandbox_config"), "{error}");
}

#[cfg(feature = "kubernetes")]
#[test]
fn kubernetes_feature_fails_closed_until_backend_is_registered() {
    let error = plan_for_candidate(
        &json!({
            "sandbox_config": {
                "backend": "kubernetes"
            }
        }),
        &execute_candidate(),
    )
    .expect_err("unknown kubernetes backend must fail closed");
    assert!(error.contains("invalid sandbox_config"), "{error}");
}
