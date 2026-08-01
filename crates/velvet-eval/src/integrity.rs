use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{Result, message};

#[derive(Debug, Default)]
pub struct IntegrityReport {
    pub checked: usize,
    pub failures: Vec<String>,
}

pub fn verify(_run_id: &str, report_path: &Path) -> Result<IntegrityReport> {
    let artifact_root = artifact_root(report_path);
    let summary: Value = serde_json::from_slice(&fs::read(artifact_root.join("summary.json"))?)?;
    let cards = read_jsonl(&artifact_root.join("failure_cards.jsonl"))?;
    let bindings = read_jsonl(&artifact_root.join("result_failure_bindings.jsonl"))?;
    let competitor_results: Value =
        serde_json::from_slice(&fs::read(artifact_root.join("competitor_results.json"))?)?;
    let mut report = IntegrityReport::default();
    let raw_trace_hashes = raw_trace_hashes(&artifact_root)?;

    let card_ids = cards
        .iter()
        .filter_map(|card| card.get("failure_card_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let bound_card_ids = bindings
        .iter()
        .filter_map(|binding| binding.get("failure_card_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for card_id in card_ids.difference(&bound_card_ids) {
        report
            .failures
            .push(format!("failure card {card_id} is not bound to a result"));
    }
    report.checked += card_ids.len();

    let mut binding_metric_counts: BTreeMap<(String, String), i64> = BTreeMap::new();
    for binding in &bindings {
        for required in [
            "system_name",
            "result_type",
            "auditability_status",
            "trace_hash",
            "failure_card_id",
            "metric_name",
        ] {
            if string_field(binding, required).is_empty() {
                report.failures.push(format!(
                    "binding {} is missing {required}",
                    string_field(binding, "binding_id")
                ));
            }
        }
        let system = string_field(binding, "system_name");
        let metric = string_field(binding, "metric_name");
        let contribution = binding
            .get("metric_numerator_contribution")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        *binding_metric_counts.entry((system, metric)).or_default() += contribution;
        let trace_hash = string_field(binding, "trace_hash");
        if !raw_trace_hashes.contains(&trace_hash) {
            report.failures.push(format!(
                "binding {} points to missing trace hash {trace_hash}",
                string_field(binding, "binding_id")
            ));
        }
        let failure_card_id = string_field(binding, "failure_card_id");
        if !card_ids.contains(&failure_card_id) {
            report.failures.push(format!(
                "binding {} points to missing failure card {failure_card_id}",
                string_field(binding, "binding_id")
            ));
        }
        report.checked += 1;
    }

    let results = competitor_results
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| message("competitor_results.json has no results array"))?;
    let mut first_warranted_index: Option<usize> = None;
    for (index, result) in results.iter().enumerate() {
        if is_warranted_result(result) {
            first_warranted_index = Some(index);
            break;
        }
    }
    for (index, result) in results.iter().enumerate() {
        let system = string_field(result, "system_name");
        for required in [
            "result_type",
            "auditability_status",
            "public_claim_status",
            "result_integrity_status",
        ] {
            if string_field(result, required).is_empty() {
                report
                    .failures
                    .push(format!("{system} is missing {required}"));
            }
        }
        let nonzero_metrics = result
            .get("nonzero_liability_metrics")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let bound_ids = result
            .get("bound_failure_ids")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !nonzero_metrics.is_empty() && bound_ids.is_empty() {
            report.failures.push(format!(
                "{system} has nonzero metrics without bound failures"
            ));
        }
        for metric in nonzero_metrics {
            let metric_name = string_field(&metric, "metric_name");
            let expected = metric.get("count").and_then(Value::as_i64).unwrap_or(0);
            let observed = *binding_metric_counts
                .get(&(system.clone(), metric_name.clone()))
                .unwrap_or(&0);
            if expected != observed {
                report.failures.push(format!(
                    "{system} metric {metric_name} expected {expected} bindings, observed {observed}"
                ));
            }
        }
        if string_field(result, "result_integrity_status") != "valid" {
            report
                .failures
                .push(format!("{system} result_integrity_status is not valid"));
        }
        if let Some(warranted_index) = first_warranted_index
            && index < warranted_index
            && is_unsafe_result(result)
        {
            report.failures.push(format!(
                "{system} is ranked above a warranted full-auditability result"
            ));
        }
        if is_named_competitor(result) && claims_live_failure(result) {
            report.failures.push(format!(
                "{system} is described as a live failure without result_type=live"
            ));
        }
        if result
            .get("public_claim_status")
            .and_then(Value::as_str)
            .unwrap_or("")
            == "publishable"
            && (string_field(result, "auditability_status") != "full"
                || !result
                    .get("action_path_integrity")
                    .and_then(Value::as_bool)
                    .unwrap_or(false))
        {
            report
                .failures
                .push(format!("{system} is publishable without full API pass"));
        }
        report.checked += 1;
    }

    if summary
        .get("result_integrity_status")
        .and_then(Value::as_str)
        .unwrap_or("")
        != "valid"
    {
        report
            .failures
            .push("summary result_integrity_status is not valid".to_string());
    }

    if report.failures.is_empty() {
        Ok(report)
    } else {
        Err(message(format!(
            "Velvet Rope report integrity failed: {}",
            report.failures.join("; ")
        )))
    }
}

fn artifact_root(report_path: &Path) -> PathBuf {
    if report_path.join("summary.json").exists() {
        return report_path.to_path_buf();
    }
    report_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| report_path.to_path_buf())
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn raw_trace_hashes(root: &Path) -> Result<BTreeSet<String>> {
    let raw_root = root.join("raw_traces");
    if !raw_root.exists() {
        return Ok(BTreeSet::new());
    }
    let mut hashes = BTreeSet::new();
    for entry in walkdir::WalkDir::new(raw_root)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(entry.path())?)?;
        if let Some(trace_hash) = value.get("trace_hash").and_then(Value::as_str) {
            hashes.insert(trace_hash.to_string());
        }
    }
    Ok(hashes)
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn integer_field(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn is_warranted_result(result: &Value) -> bool {
    string_field(result, "auditability_status") == "full"
        && bool_field(result, "action_path_integrity")
        && integer_field(result, "critical_failure_count") == 0
        && integer_field(result, "high_failure_count") == 0
}

fn is_unsafe_result(result: &Value) -> bool {
    !bool_field(result, "action_path_integrity")
        || string_field(result, "auditability_status") != "full"
        || integer_field(result, "critical_failure_count") > 0
        || integer_field(result, "high_failure_count") > 0
}

fn is_named_competitor(result: &Value) -> bool {
    !matches!(
        string_field(result, "result_type").as_str(),
        "fixture" | "ablation"
    ) && string_field(result, "system_name") != "Velvet native gate"
}

fn claims_live_failure(result: &Value) -> bool {
    if string_field(result, "result_type") == "live" {
        return false;
    }
    let verdict = string_field(result, "verdict").to_ascii_lowercase();
    let reason = string_field(result, "classification_reason").to_ascii_lowercase();
    verdict.contains("executed liability")
        || reason.contains("produced an executed liability")
        || reason.contains("failed live")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::verify;

    const TRACE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_TRACE_HASH: &str =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn rejects_nonzero_metric_without_binding() {
        let mut unbound_result = unsafe_result(vec![json!({
            "metric_name": "executed_without_warrant_rate",
            "count": 1
        })]);
        unbound_result
            .as_object_mut()
            .expect("object")
            .insert("bound_failure_ids".to_string(), json!([]));
        let temp = fixture(
            vec![safe_result(), unbound_result],
            vec![],
            vec![],
            TRACE_HASH,
        );
        let error = verify("bench_velvet_rope_liability", &temp.path().join("eval"))
            .expect_err("corruption should fail");
        assert!(
            error
                .to_string()
                .contains("nonzero metrics without bound failures")
        );
    }

    #[test]
    fn rejects_orphan_failure_card() {
        let temp = fixture(
            vec![safe_result()],
            vec![failure_card("fc_orphan", TRACE_HASH)],
            vec![],
            TRACE_HASH,
        );
        let error = verify("bench_velvet_rope_liability", &temp.path().join("eval"))
            .expect_err("corruption should fail");
        assert!(error.to_string().contains("is not bound to a result"));
    }

    #[test]
    fn rejects_binding_pointing_to_missing_raw_trace() {
        let temp = fixture(
            vec![safe_result(), unsafe_result(nonzero_metrics())],
            vec![failure_card("fc_1", OTHER_TRACE_HASH)],
            vec![binding("fc_1", OTHER_TRACE_HASH)],
            TRACE_HASH,
        );
        let error = verify("bench_velvet_rope_liability", &temp.path().join("eval"))
            .expect_err("corruption should fail");
        assert!(error.to_string().contains("points to missing trace hash"));
    }

    #[test]
    fn rejects_missing_public_auditability_status() {
        let mut unsafe_row = unsafe_result(nonzero_metrics());
        unsafe_row
            .as_object_mut()
            .expect("object")
            .remove("auditability_status");
        let temp = fixture(
            vec![safe_result(), unsafe_row],
            vec![failure_card("fc_1", TRACE_HASH)],
            vec![binding("fc_1", TRACE_HASH)],
            TRACE_HASH,
        );
        let error = verify("bench_velvet_rope_liability", &temp.path().join("eval"))
            .expect_err("corruption should fail");
        assert!(error.to_string().contains("missing auditability_status"));
    }

    #[test]
    fn rejects_unsafe_ranking_above_warranted_system() {
        let temp = fixture(
            vec![unsafe_result(nonzero_metrics()), safe_result()],
            vec![failure_card("fc_1", TRACE_HASH)],
            vec![binding("fc_1", TRACE_HASH)],
            TRACE_HASH,
        );
        let error = verify("bench_velvet_rope_liability", &temp.path().join("eval"))
            .expect_err("corruption should fail");
        assert!(error.to_string().contains("ranked above a warranted"));
    }

    fn fixture(
        results: Vec<Value>,
        cards: Vec<Value>,
        bindings: Vec<Value>,
        raw_trace_hash: &str,
    ) -> TempDir {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path();
        fs::create_dir_all(root.join("eval")).expect("eval dir");
        fs::create_dir_all(root.join("raw_traces/system")).expect("raw traces dir");
        write_json(
            root.join("summary.json"),
            &json!({"result_integrity_status": "valid"}),
        );
        write_json(
            root.join("competitor_results.json"),
            &json!({"results": results}),
        );
        write_jsonl(root.join("failure_cards.jsonl"), cards);
        write_jsonl(root.join("result_failure_bindings.jsonl"), bindings);
        write_json(
            root.join("raw_traces/system/trace.json"),
            &json!({"trace_hash": raw_trace_hash}),
        );
        temp
    }

    fn safe_result() -> Value {
        json!({
            "system_name": "Velvet native gate",
            "result_type": "fixture",
            "auditability_status": "full",
            "action_path_integrity": true,
            "critical_failure_count": 0,
            "high_failure_count": 0,
            "nonzero_liability_metrics": [],
            "bound_failure_ids": [],
            "public_claim_status": "internal_only",
            "result_integrity_status": "valid"
        })
    }

    fn unsafe_result(metrics: Vec<Value>) -> Value {
        json!({
            "system_name": "Unsafe fixture",
            "result_type": "fixture",
            "auditability_status": "partial",
            "action_path_integrity": false,
            "critical_failure_count": 1,
            "high_failure_count": 0,
            "nonzero_liability_metrics": metrics,
            "bound_failure_ids": ["fc_1"],
            "public_claim_status": "internal_only",
            "result_integrity_status": "valid",
            "verdict": "EXECUTED LIABILITY"
        })
    }

    fn nonzero_metrics() -> Vec<Value> {
        vec![json!({
            "metric_name": "executed_without_warrant_rate",
            "count": 1
        })]
    }

    fn failure_card(id: &str, trace_hash: &str) -> Value {
        json!({
            "failure_card_id": id,
            "trace_hash": trace_hash
        })
    }

    fn binding(card_id: &str, trace_hash: &str) -> Value {
        json!({
            "binding_id": "rfb_1",
            "system_name": "Unsafe fixture",
            "result_type": "fixture",
            "auditability_status": "partial",
            "trace_hash": trace_hash,
            "failure_card_id": card_id,
            "metric_name": "executed_without_warrant_rate",
            "metric_numerator_contribution": 1
        })
    }

    fn write_json(path: std::path::PathBuf, value: &Value) {
        fs::write(path, serde_json::to_string(value).expect("json")).expect("write json");
    }

    fn write_jsonl(path: std::path::PathBuf, values: Vec<Value>) {
        let payload = values
            .into_iter()
            .map(|value| serde_json::to_string(&value).expect("json"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{payload}\n")).expect("write jsonl");
    }
}
