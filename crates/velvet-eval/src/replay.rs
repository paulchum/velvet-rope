use std::path::Path;

use serde::Serialize;
use velvet_core::{RouteRequest, RouterConfig, ThreadRecord, route_request};

use crate::Result;
use crate::store::execute_query;

#[derive(Debug, Clone, Serialize)]
pub struct ReplayReport {
    pub run_id: String,
    pub checked: usize,
    pub matched: usize,
    pub mismatches: Vec<ReplayMismatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayMismatch {
    pub thread_id: String,
    pub condition_id: Option<String>,
    pub expected_selected_action: Option<String>,
    pub sealed_selected_action: Option<String>,
}

pub fn seal_run(root: &Path, run_id: &str, condition_id: Option<&str>) -> Result<ReplayReport> {
    let condition_filter = condition_id
        .map(|id| format!(" AND condition_id = '{}'", id.replace('\'', "''")))
        .unwrap_or_default();
    let rows = execute_query(
        root,
        Some(run_id),
        &format!(
            "SELECT thread_json FROM threads WHERE run_id = '{}'{} ORDER BY condition_id, decision_id, thread_id",
            run_id.replace('\'', "''"),
            condition_filter
        ),
    )?;
    let mut report = ReplayReport {
        run_id: run_id.to_string(),
        checked: 0,
        matched: 0,
        mismatches: Vec::new(),
    };
    for row in rows.rows {
        let thread: ThreadRecord = serde_json::from_str(&row[0])?;
        let request = RouteRequest {
            state: thread.state.clone(),
            candidates: thread.raw_candidates.clone(),
            host_action: thread.host_action,
            config: RouterConfig::from_state(&thread.state),
        };
        let decision = route_request(&request);
        report.checked += 1;
        if decision.action_type == thread.selected_action {
            report.matched += 1;
        } else {
            report.mismatches.push(ReplayMismatch {
                thread_id: thread.thread_id,
                condition_id: thread.evaluation_context.condition_id,
                expected_selected_action: thread.selected_action.map(action_name),
                sealed_selected_action: decision.action_type.map(action_name),
            });
        }
    }
    Ok(report)
}

fn action_name(action: velvet_core::ActionType) -> String {
    serde_json::to_value(action)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "<unknown>".to_string())
}
