use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use velvet_core::{CandidateAction, route_with_thread};

use crate::ingest::ingest;
use crate::store::{TABLES, digest_files, write_run};
use crate::{Result, message};

pub fn run_suite(workspace: &Path, root: &Path, suite: &str) -> Result<String> {
    if suite == "velvet_rope_liability" {
        return run_velvet_rope_suite(workspace, root);
    }
    let scenarios = load_scenarios(workspace, suite)?;
    let snapshot_dir = workspace.join("benchmarks").join("snapshots").join(suite);
    fs::create_dir_all(&snapshot_dir)?;
    let thread_path = snapshot_dir.join("latest.jsonl");
    let mut lines = Vec::new();
    for (index, mut scenario) in scenarios.into_iter().enumerate() {
        let id = scenario_id(&scenario, index);
        stamp_eval_context(&mut scenario, suite, &id);
        let state = scenario
            .get("state")
            .cloned()
            .ok_or_else(|| message(format!("benchmark scenario {id} has no state")))?;
        let candidates: Vec<CandidateAction> = serde_json::from_value(
            scenario
                .get("candidates")
                .cloned()
                .ok_or_else(|| message(format!("benchmark scenario {id} has no candidates")))?,
        )?;
        let result = route_with_thread(
            &state,
            &candidates,
            Some(format!("thread_{}_{}", suite, id).replace('-', "_")),
            Some("1970-01-01T00:00:00Z".to_string()),
        )
        .map_err(message)?;
        lines.push(serde_json::to_string(&result.thread)?);
    }
    fs::write(&thread_path, format!("{}\n", lines.join("\n")))?;
    let run_id = format!("bench_{suite}");
    ingest(&thread_path, &run_id, root)?;
    Ok(run_id)
}

fn load_scenarios(workspace: &Path, suite: &str) -> Result<Vec<Value>> {
    match suite {
        "tau_bench" => {
            let path = workspace.join("benchmarks/tau_bench/airline_subset.json");
            let value: Value = serde_json::from_slice(&fs::read(path)?)?;
            value
                .as_array()
                .cloned()
                .ok_or_else(|| message("tau_bench fixture must be a JSON array"))
        }
        "entry_pricing" => {
            let mut paths = fs::read_dir(workspace.join("benchmarks/entry_pricing"))?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::result::Result<Vec<PathBuf>, std::io::Error>>()?;
            paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("json"));
            paths.sort();
            paths
                .into_iter()
                .map(|path| serde_json::from_slice(&fs::read(path)?).map_err(Into::into))
                .collect()
        }
        "liability" => load_json_directory(workspace, "benchmarks/liability"),
        other => Err(message(format!(
            "unknown benchmark suite {other:?}; expected tau_bench, entry_pricing, liability, or velvet_rope_liability"
        ))),
    }
}

fn run_velvet_rope_suite(workspace: &Path, root: &Path) -> Result<String> {
    let output_dir = workspace.join("reports/liability/velvet_rope");
    run_python_arena(workspace, &output_dir)?;

    let artifact_files = [
        output_dir.join("query_traces.jsonl"),
        output_dir.join("summary.json"),
        output_dir.join("failure_cards.jsonl"),
        output_dir.join("result_failure_bindings.jsonl"),
        output_dir.join("competitor_results.json"),
        output_dir.join("competitor_research_records.jsonl"),
    ];
    let input_digest = digest_files(&artifact_files)?;
    let mut rows = empty_rows();
    let traces = read_jsonl(&artifact_files[0])?;
    let failure_cards = read_jsonl(&artifact_files[2])?;
    let bindings = read_jsonl(&artifact_files[3])?;
    let competitor_results: Value = serde_json::from_slice(&fs::read(&artifact_files[4])?)?;
    let research_records = read_jsonl(&artifact_files[5])?;

    for trace in &traces {
        let scenario_id = string_field(trace, "scenario_id", "unconditioned");
        rows.get_mut("velvet_rope_traces")
            .expect("table exists")
            .push(json!({
                "run_id": "bench_velvet_rope_liability",
                "condition_id": scenario_id,
                "scenario_id": scenario_id,
                "query_id": string_field(trace, "query_id", ""),
                "system_name": string_field(trace, "system_name", ""),
                "adapter_name": string_field(trace, "adapter_name", ""),
                "adapter_version": string_field(trace, "adapter_version", ""),
                "auditability_status": string_field(trace, "auditability_status", ""),
                "action_path_integrity": trace.get("invariant_violations").and_then(Value::as_array).is_none_or(Vec::is_empty),
                "action_executed": bool_field(trace, "action_executed"),
                "executed_without_warrant": bool_field(trace, "executed_without_warrant"),
                "hidden_tool_call": bool_field(trace, "hidden_tool_call"),
                "missing_warrant": bool_field(trace, "missing_warrant"),
                "missing_seal": bool_field(trace, "missing_seal"),
                "liability_multiplier": number_field(trace, "liability_multiplier"),
                "trace_hash": string_field(trace, "trace_hash", ""),
                "raw_trace_path": string_field(trace, "raw_trace_path", ""),
                "trace_json": serde_json::to_string(trace)?,
            }));
    }
    for card in &failure_cards {
        let scenario_id = string_field(card, "scenario_id", "unconditioned");
        rows.get_mut("velvet_failure_cards")
            .expect("table exists")
            .push(json!({
                "run_id": "bench_velvet_rope_liability",
                "condition_id": scenario_id,
                "system_name": string_field(card, "system", ""),
                "failure_card_id": string_field(card, "failure_card_id", ""),
                "failure_class": string_field(card, "failure_title", ""),
                "severity": string_field(card, "severity", ""),
                "query_id": string_field(card, "query_id", ""),
                "scenario_id": scenario_id,
                "trace_hash": string_field(card, "trace_hash", ""),
                "reproduction_command": string_field(card, "reproduction_command", ""),
                "card_json": serde_json::to_string(card)?,
            }));
    }
    for binding in &bindings {
        let scenario_id = string_field(binding, "scenario_id", "unconditioned");
        rows.get_mut("result_failure_bindings")
            .expect("table exists")
            .push(json!({
                "run_id": "bench_velvet_rope_liability",
                "condition_id": scenario_id,
                "system_name": string_field(binding, "system_name", ""),
                "adapter_name": string_field(binding, "adapter_name", ""),
                "adapter_version": string_field(binding, "adapter_version", ""),
                "result_type": string_field(binding, "result_type", ""),
                "auditability_status": string_field(binding, "auditability_status", ""),
                "scenario_id": scenario_id,
                "query_id": string_field(binding, "query_id", ""),
                "trace_hash": string_field(binding, "trace_hash", ""),
                "failure_card_id": string_field(binding, "failure_card_id", ""),
                "failure_class": string_field(binding, "failure_class", ""),
                "metric_name": string_field(binding, "metric_name", ""),
                "metric_numerator_contribution": integer_field(binding, "metric_numerator_contribution"),
                "severity": string_field(binding, "severity", ""),
                "liability_multiplier_contribution": number_field(binding, "liability_multiplier_contribution"),
                "public_report_anchor": string_field(binding, "public_report_anchor", ""),
                "reproduction_command": string_field(binding, "reproduction_command", ""),
                "binding_json": serde_json::to_string(binding)?,
            }));
    }
    for result in competitor_results
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let system_name = string_field(&result, "system_name", "unknown");
        rows.get_mut("competitor_action_results")
            .expect("table exists")
            .push(json!({
                "run_id": "bench_velvet_rope_liability",
                "condition_id": slug(&system_name),
                "system_name": system_name,
                "adapter_name": string_field(&result, "adapter_name", ""),
                "adapter_version": string_field(&result, "adapter_version", ""),
                "result_type": string_field(&result, "result_type", ""),
                "auditability_status": string_field(&result, "auditability_status", ""),
                "action_path_integrity": bool_field(&result, "action_path_integrity"),
                "task_success_rate": number_field(&result, "task_success_rate"),
                "liability_multiplier": number_field(&result, "liability_multiplier"),
                "critical_failure_count": integer_field(&result, "critical_failure_count"),
                "high_failure_count": integer_field(&result, "high_failure_count"),
                "medium_failure_count": integer_field(&result, "medium_failure_count"),
                "opportunity_failure_count": integer_field(&result, "opportunity_failure_count"),
                "cost_failure_count": integer_field(&result, "cost_failure_count"),
                "verdict": string_field(&result, "verdict", ""),
                "public_claim_status": string_field(&result, "public_claim_status", ""),
                "result_integrity_status": string_field(&result, "result_integrity_status", ""),
                "result_json": serde_json::to_string(&result)?,
            }));
    }
    for record in &research_records {
        let system_name = string_field(record, "system_name", "unknown");
        rows.get_mut("competitor_research_records")
            .expect("table exists")
            .push(json!({
                "run_id": "bench_velvet_rope_liability",
                "condition_id": slug(&system_name),
                "system_name": system_name,
                "category": string_field(record, "category", ""),
                "auditability_grade": string_field(record, "auditability_grade", ""),
                "result_type": string_field(record, "result_type", ""),
                "adapter_feasibility": string_field(record, "adapter_feasibility", ""),
                "public_claim_status": string_field(record, "public_claim_status", ""),
                "record_json": serde_json::to_string(record)?,
            }));
    }

    write_run(
        root,
        "bench_velvet_rope_liability",
        &input_digest,
        &rows,
        traces.len(),
    )?;
    Ok("bench_velvet_rope_liability".to_string())
}

fn run_python_arena(workspace: &Path, output_dir: &Path) -> Result<()> {
    let python = if workspace.join(".venv/bin/python").exists() {
        workspace.join(".venv/bin/python")
    } else {
        PathBuf::from("python3")
    };
    let mut python_path = workspace.join("src").to_string_lossy().to_string();
    if let Some(existing) = std::env::var_os("PYTHONPATH") {
        python_path.push(':');
        python_path.push_str(&existing.to_string_lossy());
    }
    let status = Command::new(python)
        .current_dir(workspace)
        .env("PYTHONPATH", python_path)
        .args([
            "-m",
            "velvet.liability_benchmark",
            "--suite",
            "velvet_rope_liability",
            "--out",
            output_dir
                .to_str()
                .ok_or_else(|| message("non-utf8 velvet rope output path"))?,
            "--json",
        ])
        .status()?;
    if !status.success() {
        return Err(message("failed to generate Velvet Rope arena artifacts"));
    }
    Ok(())
}

fn empty_rows() -> std::collections::BTreeMap<&'static str, Vec<Value>> {
    TABLES.iter().map(|table| (*table, Vec::new())).collect()
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn string_field(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn number_field(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn integer_field(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn load_json_directory(workspace: &Path, relative: &str) -> Result<Vec<Value>> {
    let mut paths = fs::read_dir(workspace.join(relative))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<PathBuf>, std::io::Error>>()?;
    paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("json"));
    paths.sort();
    paths
        .into_iter()
        .map(|path| serde_json::from_slice(&fs::read(path)?).map_err(Into::into))
        .collect()
}

fn stamp_eval_context(scenario: &mut Value, suite: &str, id: &str) {
    let Some(state) = scenario.get_mut("state").and_then(Value::as_object_mut) else {
        return;
    };
    let expected_action = state.get("expected_action").cloned();
    state
        .entry("host_action")
        .or_insert_with(|| json!("ANSWER_DIRECTLY"));
    state.insert(
        "evaluation_context".to_string(),
        json!({
            "condition_id": id,
            "scenario_id": id,
            "decision_id": id,
            "benchmark_suite": suite,
            "arm_id": "default",
            "expected_action": expected_action,
        }),
    );
}

fn scenario_id(scenario: &Value, index: usize) -> String {
    scenario
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("scenario_{index:03}"))
}
