use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use velvet_core::{ActionType, PolicyDecision, THREAD_SCHEMA_VERSION, ThreadRecord};
use walkdir::WalkDir;

use crate::store::{digest_files, write_run};
use crate::{Result, message};

pub fn ingest(thread_dir: &Path, run_id: &str, root: &Path) -> Result<()> {
    let files = thread_files(thread_dir)?;
    if files.is_empty() {
        return Err(message(format!(
            "no .json or .jsonl threads found under {}",
            thread_dir.display()
        )));
    }
    let input_digest = digest_files(&files)?;
    let validator = jsonschema::validator_for(&velvet_core::thread_schema_json())
        .map_err(|error| message(error.to_string()))?;
    let mut rows = empty_rows();
    let mut thread_count = 0;
    for file in files {
        for raw in read_thread_values(&file)? {
            let schema_version = raw
                .get("schema_version")
                .and_then(Value::as_str)
                .unwrap_or("<missing>");
            if schema_version != THREAD_SCHEMA_VERSION {
                return Err(message(format!(
                    "{} contains thread schema {schema_version}; only {THREAD_SCHEMA_VERSION} is supported. Regenerate threads from benchmarks or fixtures.",
                    file.display()
                )));
            }
            if let Some(error) = validator.iter_errors(&raw).next() {
                return Err(message(format!(
                    "{} failed thread schema validation: {} at {}",
                    file.display(),
                    error,
                    error.instance_path()
                )));
            }
            let thread: ThreadRecord = serde_json::from_value(raw)?;
            append_thread_rows(run_id, &thread, &mut rows)?;
            thread_count += 1;
        }
    }
    write_run(root, run_id, &input_digest, &rows, thread_count)
}

fn empty_rows() -> BTreeMap<&'static str, Vec<Value>> {
    [
        "threads",
        "candidates",
        "policy_events",
        "scores",
        "outcomes",
        "provider_costs",
        "execution_results",
        "certificates",
        "competitor_results",
        "coverage_gaps",
    ]
    .into_iter()
    .map(|table| (table, Vec::new()))
    .collect()
}

fn thread_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("json" | "jsonl")
            )
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn read_thread_values(path: &Path) -> Result<Vec<Value>> {
    let source = fs::read_to_string(path)?;
    if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
        return source
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect();
    }
    let value: Value = serde_json::from_str(&source)?;
    Ok(match value {
        Value::Array(values) => values,
        value => vec![value],
    })
}

fn append_thread_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
) -> Result<()> {
    let condition_id = thread
        .evaluation_context
        .condition_id
        .clone()
        .unwrap_or_else(|| "unconditioned".to_string());
    let scenario_id = thread.evaluation_context.scenario_id.clone();
    let decision_id = thread
        .evaluation_context
        .decision_id
        .clone()
        .unwrap_or_else(|| thread.thread_id.clone());
    let expected_action = thread.evaluation_context.expected_action.map(action_name);
    let selected_action = thread.selected_action.map(action_name);
    let host_action = thread.host_action.map(action_name);
    let selected_outcome = thread
        .selected_action
        .and_then(|action| outcome_for(thread, action));
    let host_expected_reward = thread
        .host_action
        .and_then(|action| outcome_for(thread, action))
        .and_then(|outcome| outcome.expected_reward);

    rows.get_mut("threads").expect("table exists").push(json!({
        "run_id": run_id,
        "condition_id": condition_id,
        "scenario_id": scenario_id,
        "decision_id": decision_id,
        "thread_id": thread.thread_id,
        "timestamp": thread.timestamp,
        "schema_version": thread.schema_version,
        "thread_json": serde_json::to_string(thread)?,
        "selected_action": selected_action,
        "host_action": host_action,
        "expected_action": expected_action,
        "policy_chain_revision": thread.policy_chain_revision,
        "seal_seed": thread.seal_seed,
        "seal_id": thread.seal_id,
        "selected_completed": selected_outcome.and_then(|outcome| outcome.completed),
        "selected_realized_reward": selected_outcome.and_then(|outcome| outcome.realized_reward),
        "selected_expected_reward": selected_outcome.and_then(|outcome| outcome.expected_reward),
        "selected_realized_cost": selected_outcome.and_then(|outcome| outcome.realized_cost),
        "host_expected_reward": host_expected_reward,
    }));

    append_candidate_rows(run_id, thread, rows, &condition_id, &decision_id);
    append_outcome_rows(run_id, thread, rows, &condition_id, &decision_id);
    append_provider_cost_rows(run_id, thread, rows, &condition_id, &decision_id);
    append_execution_result_row(run_id, thread, rows, &condition_id, &decision_id);
    append_certificate_rows(run_id, thread, rows, &condition_id, &decision_id);
    append_competitor_result_rows(run_id, thread, rows, &condition_id, &decision_id);
    append_coverage_gaps(run_id, thread, rows, &condition_id, &decision_id);
    Ok(())
}

fn append_candidate_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    for (candidate_index, candidate) in evaluated_candidates(thread).into_iter().enumerate() {
        let action = candidate.final_action.action_type;
        let action_type = action_name(action);
        let selected = thread.selected_action == Some(action)
            && candidate.decision == velvet_core::DecisionType::Execute;
        rows.get_mut("candidates")
            .expect("table exists")
            .push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "candidate_index": candidate_index as i64,
                "action_type": action_type,
                "selected": selected,
                "decision": serde_string(&candidate.decision),
                "reason": candidate.reason,
            }));
        if let Some(score) = &candidate.admission_score {
            rows.get_mut("scores").expect("table exists").push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "candidate_index": candidate_index as i64,
                "action_type": action_type,
                "expected_upside": score.expected_upside,
                "surprisal": score.surprisal,
                "confidence": score.confidence,
                "clearance_score": score.clearance_score,
                "cost_money": score.cost.money,
                "cost_tokens": score.cost.tokens,
                "cost_latency": score.cost.latency,
                "cost_api_calls": score.cost.api_calls,
                "entry_price": score.pricing_breakdown.entry_price,
                "final_lambda": score.pricing_breakdown.final_lambda,
                "clears_rope": score.pricing_breakdown.clears_rope,
            }));
        }
        for (policy_index, event) in candidate.policy_trace.iter().enumerate() {
            let evidence_json =
                event
                    .jurisdiction_evidence
                    .as_ref()
                    .and_then(|jurisdiction_evidence| {
                        serde_json::to_string(jurisdiction_evidence).ok()
                    });
            rows.get_mut("policy_events").expect("table exists").push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "candidate_index": candidate_index as i64,
                "policy_index": policy_index as i64,
                "action_type": action_type,
                "policy_name": event.policy_name,
                "policy_kind": event.policy_kind,
                "policy_version": event.policy_version,
                "config_version": event.config_version,
                "config_hash": event.config_hash,
                "status": event.status,
                "decision_kind": policy_decision_kind(&event.decision),
                "rule_id": event.jurisdiction_evidence.as_ref().map(|jurisdiction_evidence| jurisdiction_evidence.rule_id.clone()),
                "evidence_type": event.jurisdiction_evidence.as_ref().map(|jurisdiction_evidence| jurisdiction_evidence.evidence_type.clone()),
                "evidence_json": evidence_json,
            }));
        }
    }
}

fn append_outcome_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    for outcome in &thread.evaluation_outcomes {
        rows.get_mut("outcomes").expect("table exists").push(json!({
            "run_id": run_id,
            "condition_id": condition_id,
            "decision_id": decision_id,
            "thread_id": thread.thread_id,
            "action_type": action_name(outcome.action_type),
            "completed": outcome.completed,
            "realized_reward": outcome.realized_reward,
            "expected_reward": outcome.expected_reward,
            "realized_cost": outcome.realized_cost,
            "expected_cost": outcome.expected_cost,
            "information_gain": outcome.information_gain,
            "content_hash": outcome.content_hash,
            "memory_unique": outcome.memory_unique,
        }));
    }
}

fn append_provider_cost_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    for cost in &thread.provider_costs {
        rows.get_mut("provider_costs")
            .expect("table exists")
            .push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "provider": cost.provider,
                "reported_cost": cost.reported_cost,
                "billed_cost": cost.billed_cost,
                "currency": cost.currency,
                "fixture_id": cost.fixture_id,
            }));
    }
}

fn append_execution_result_row(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    if let Some(result) = &thread.execution_result {
        rows.get_mut("execution_results")
            .expect("table exists")
            .push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "action_type": action_name(result.action_type),
                "status": serde_string(&result.status),
                "provider": result.provider,
                "normalized_output_hash": result.normalized_output_hash,
            }));
    }
}

fn append_certificate_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    for (candidate_index, candidate) in evaluated_candidates(thread).into_iter().enumerate() {
        let Some(certificate) = &candidate.certificate else {
            continue;
        };
        rows.get_mut("certificates")
            .expect("table exists")
            .push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "candidate_index": candidate_index as i64,
                "action_type": action_name(candidate.final_action.action_type),
                "family": certificate.family,
                "arm_id": certificate.arm_id,
                "baseline": certificate.baseline,
                "lookback_horizon": certificate.lookback_horizon as i64,
                "delight_scale": certificate.delight_scale,
                "certificate_lambda": certificate.liability_price,
                "threshold": certificate.threshold,
                "expected_improvement": certificate.typed_effect.mean_bound,
                "lower_certificate": certificate.inspection_lower_bound,
                "upper_certificate": certificate.safe_upper_bound,
                "outcome": serde_string(&certificate.outcome),
                "liability_mode": certificate.liability_mode,
                "compensator_increment": certificate.compensator_step.as_ref().map(|step| step.increment),
                "initial_optionality": certificate.compensator_step.as_ref().map(|step| step.initial_optionality),
                "cumulative_increment": certificate.compensator_step.as_ref().map(|step| step.cumulative_increment),
            }));
    }
}

fn append_competitor_result_rows(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    for result in &thread.competitor_results {
        rows.get_mut("competitor_results")
            .expect("table exists")
            .push(json!({
                "run_id": run_id,
                "condition_id": condition_id,
                "decision_id": decision_id,
                "thread_id": thread.thread_id,
                "system": result.system,
                "system_version": result.system_version,
                "adapter_kind": result.adapter_kind,
                "case_id": result.case_id,
                "status": result.status,
                "decision": result.decision,
                "certificate_supported": result.certificate_supported,
                "certificate_outcome": result.certificate_outcome.map(|outcome| serde_string(&outcome)),
                "blocked": result.blocked,
                "skipped": result.skipped,
                "liability_cost": result.liability_cost,
                "evidence_url": result.evidence_url,
                "skip_reason": result.skip_reason,
            }));
    }
}

fn append_coverage_gaps(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
) {
    if thread.evaluation_context.condition_id.is_none() {
        push_gap(
            run_id,
            thread,
            rows,
            condition_id,
            decision_id,
            "missing_condition_id",
            "evaluation_context.condition_id is absent",
        );
    }
    if thread.evaluation_context.expected_action.is_none() {
        push_gap(
            run_id,
            thread,
            rows,
            condition_id,
            decision_id,
            "missing_expected_action",
            "evaluation_context.expected_action is absent",
        );
    }
    if thread
        .selected_action
        .and_then(|action| outcome_for(thread, action))
        .is_none()
    {
        push_gap(
            run_id,
            thread,
            rows,
            condition_id,
            decision_id,
            "missing_selected_outcome",
            "selected action has no evaluation outcome",
        );
    }
    if thread.host_action.is_some()
        && thread
            .host_action
            .and_then(|action| outcome_for(thread, action))
            .is_none()
    {
        push_gap(
            run_id,
            thread,
            rows,
            condition_id,
            decision_id,
            "missing_host_outcome",
            "host action has no expected outcome",
        );
    }
    for candidate in evaluated_candidates(thread) {
        for event in &candidate.policy_trace {
            if event.status != "allow" && event.jurisdiction_evidence.is_none() {
                push_gap(
                    run_id,
                    thread,
                    rows,
                    condition_id,
                    decision_id,
                    "missing_jurisdiction_evidence",
                    &format!(
                        "{} produced {} without jurisdiction_evidence",
                        event.policy_name, event.status
                    ),
                );
            }
        }
    }
}

fn push_gap(
    run_id: &str,
    thread: &ThreadRecord,
    rows: &mut BTreeMap<&'static str, Vec<Value>>,
    condition_id: &str,
    decision_id: &str,
    gap_kind: &str,
    detail: &str,
) {
    rows.get_mut("coverage_gaps")
        .expect("table exists")
        .push(json!({
            "run_id": run_id,
            "condition_id": condition_id,
            "decision_id": decision_id,
            "thread_id": thread.thread_id,
            "gap_kind": gap_kind,
            "detail": detail,
        }));
}

fn evaluated_candidates(thread: &ThreadRecord) -> Vec<&velvet_core::ThreadCandidateAction> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    for candidate in thread
        .scored_candidates
        .iter()
        .chain(thread.rejected_actions.iter())
    {
        let key = (
            candidate.final_action.action_type,
            serde_string(&candidate.decision),
            candidate.reason.clone(),
        );
        if seen.insert(key) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn outcome_for(
    thread: &ThreadRecord,
    action_type: ActionType,
) -> Option<&velvet_core::EvaluationOutcome> {
    thread
        .evaluation_outcomes
        .iter()
        .find(|outcome| outcome.action_type == action_type)
}

fn action_name(action_type: ActionType) -> String {
    serde_string(&action_type)
}

fn serde_string(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn policy_decision_kind(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Deny { .. } => "deny",
        PolicyDecision::Modify { .. } => "modify",
        PolicyDecision::Defer { .. } => "defer",
    }
}
