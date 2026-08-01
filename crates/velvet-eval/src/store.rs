use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{Result, message};

pub const TABLES: &[&str] = &[
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
    "velvet_rope_traces",
    "velvet_failure_cards",
    "result_failure_bindings",
    "competitor_action_results",
    "competitor_research_records",
];
const EVAL_STORE_SCHEMA_VERSION: &str = "eval_store_v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub run_id: String,
    pub input_digest: String,
    pub thread_count: usize,
    pub schema_version: String,
    #[serde(default)]
    pub eval_store_schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOutput {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

pub fn default_root() -> PathBuf {
    std::env::var_os("VELVET_EVAL_ROOT")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".velvet/evals")))
        .unwrap_or_else(|| PathBuf::from(".velvet/evals"))
}

pub fn run_path(root: &Path, run_id: &str) -> PathBuf {
    root.join(run_id)
}

pub fn digest_files(files: &[PathBuf]) -> Result<String> {
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(path)?);
        hasher.update([0xff]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn write_run(
    root: &Path,
    run_id: &str,
    input_digest: &str,
    rows: &BTreeMap<&'static str, Vec<Value>>,
    thread_count: usize,
) -> Result<()> {
    fs::create_dir_all(root)?;
    let final_path = run_path(root, run_id);
    let manifest_path = final_path.join("manifest.json");
    if manifest_path.exists() {
        let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        if manifest.input_digest == input_digest {
            if manifest.eval_store_schema_version == EVAL_STORE_SCHEMA_VERSION {
                return Ok(());
            }
            fs::remove_dir_all(&final_path)?;
        } else {
            return Err(message(format!(
                "run_id {run_id:?} already exists with a different input digest"
            )));
        }
    }
    if final_path.exists() {
        return Err(message(format!(
            "run_id {run_id:?} already exists without a manifest; remove it before ingesting"
        )));
    }

    let temp_path = root.join(format!(".tmp-{run_id}-{}", std::process::id()));
    if temp_path.exists() {
        fs::remove_dir_all(&temp_path)?;
    }
    fs::create_dir_all(&temp_path)?;
    let input_path = temp_path.join("_jsonl");
    fs::create_dir_all(&input_path)?;
    let mut table_payload = Vec::new();
    for table in TABLES {
        let Some(table_rows) = rows.get(table) else {
            continue;
        };
        if table_rows.is_empty() {
            continue;
        }
        let jsonl_path = input_path.join(format!("{table}.jsonl"));
        let mut file = fs::File::create(&jsonl_path)?;
        for row in table_rows {
            writeln!(file, "{}", serde_json::to_string(row)?)?;
        }
        let parquet_dir = temp_path.join(table);
        fs::create_dir_all(&parquet_dir)?;
        table_payload.push(json!({
            "table": table,
            "jsonl_path": jsonl_path,
            "parquet_dir": parquet_dir,
        }));
    }
    run_python_duckdb(INGEST_SCRIPT, &json!({ "tables": table_payload }))?;
    fs::remove_dir_all(&input_path)?;
    let manifest = Manifest {
        run_id: run_id.to_string(),
        input_digest: input_digest.to_string(),
        thread_count,
        schema_version: velvet_core::THREAD_SCHEMA_VERSION.to_string(),
        eval_store_schema_version: EVAL_STORE_SCHEMA_VERSION.to_string(),
    };
    fs::write(
        temp_path.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    fs::rename(&temp_path, &final_path)?;
    Ok(())
}

pub fn execute_query(root: &Path, run_id: Option<&str>, sql: &str) -> Result<QueryOutput> {
    let payload = json!({
        "root": root,
        "run_id": run_id,
        "tables": TABLES,
        "empty_selects": empty_selects(),
        "sql": sql,
    });
    let output = run_python_duckdb(QUERY_SCRIPT, &payload)?;
    serde_json::from_str(&output).map_err(Into::into)
}

fn empty_selects() -> BTreeMap<&'static str, &'static str> {
    TABLES
        .iter()
        .map(|table| (*table, empty_select(table)))
        .collect()
}

fn run_python_duckdb(script: &str, payload: &Value) -> Result<String> {
    let mut child = Command::new(python_executable())
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            message(format!(
                "failed to launch Python for DuckDB work: {error}. Install the Python duckdb package with `uv sync --dev`."
            ))
        })?;
    {
        let stdin = child.stdin.as_mut().expect("stdin is piped");
        stdin.write_all(serde_json::to_string(payload)?.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(message(format!(
            "DuckDB Python execution failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn python_executable() -> PathBuf {
    if let Some(value) = std::env::var_os("VELVET_EVAL_PYTHON") {
        return PathBuf::from(value);
    }
    let venv_python = PathBuf::from(".venv/bin/python");
    if venv_python.exists() {
        return venv_python;
    }
    PathBuf::from("python3")
}

fn empty_select(table: &str) -> &'static str {
    match table {
        "threads" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR scenario_id, \
             NULL::VARCHAR decision_id, NULL::VARCHAR thread_id, NULL::VARCHAR AS \"timestamp\", \
             NULL::VARCHAR schema_version, NULL::VARCHAR thread_json, NULL::VARCHAR selected_action, \
             NULL::VARCHAR host_action, NULL::VARCHAR expected_action, NULL::VARCHAR policy_chain_revision, \
             NULL::UBIGINT seal_seed, NULL::VARCHAR seal_id, NULL::BOOLEAN selected_completed, \
             NULL::DOUBLE selected_realized_reward, NULL::DOUBLE selected_expected_reward, \
             NULL::DOUBLE selected_realized_cost, NULL::DOUBLE host_expected_reward WHERE false"
        }
        "candidates" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::INTEGER candidate_index, NULL::VARCHAR action_type, \
             NULL::BOOLEAN selected, NULL::VARCHAR decision, NULL::VARCHAR reason WHERE false"
        }
        "policy_events" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::INTEGER candidate_index, NULL::INTEGER policy_index, \
             NULL::VARCHAR action_type, NULL::VARCHAR policy_name, NULL::VARCHAR policy_kind, \
             NULL::VARCHAR policy_version, NULL::VARCHAR config_version, NULL::VARCHAR config_hash, \
             NULL::VARCHAR status, NULL::VARCHAR decision_kind, NULL::VARCHAR rule_id, \
             NULL::VARCHAR evidence_type, NULL::VARCHAR evidence_json WHERE false"
        }
        "scores" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::INTEGER candidate_index, NULL::VARCHAR action_type, \
             NULL::DOUBLE expected_upside, NULL::DOUBLE surprisal, NULL::DOUBLE confidence, \
             NULL::DOUBLE clearance_score, NULL::DOUBLE cost_money, NULL::DOUBLE cost_tokens, \
             NULL::DOUBLE cost_latency, NULL::DOUBLE cost_api_calls, NULL::DOUBLE entry_price, \
             NULL::DOUBLE final_lambda, NULL::BOOLEAN clears_rope WHERE false"
        }
        "outcomes" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::VARCHAR action_type, NULL::BOOLEAN completed, \
             NULL::DOUBLE realized_reward, NULL::DOUBLE expected_reward, NULL::DOUBLE realized_cost, \
             NULL::DOUBLE expected_cost, NULL::DOUBLE information_gain, NULL::VARCHAR content_hash, \
             NULL::BOOLEAN memory_unique WHERE false"
        }
        "provider_costs" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::VARCHAR provider, NULL::DOUBLE reported_cost, \
             NULL::DOUBLE billed_cost, NULL::VARCHAR currency, NULL::VARCHAR fixture_id WHERE false"
        }
        "execution_results" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::VARCHAR action_type, NULL::VARCHAR status, \
             NULL::VARCHAR provider, NULL::VARCHAR normalized_output_hash WHERE false"
        }
        "certificates" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::INTEGER candidate_index, NULL::VARCHAR action_type, \
             NULL::VARCHAR AS family, NULL::VARCHAR arm_id, NULL::DOUBLE baseline, \
             NULL::INTEGER lookback_horizon, NULL::DOUBLE delight_scale, NULL::DOUBLE certificate_lambda, \
             NULL::DOUBLE threshold, NULL::DOUBLE expected_improvement, \
             NULL::DOUBLE lower_certificate, NULL::DOUBLE upper_certificate, NULL::VARCHAR outcome, \
             NULL::VARCHAR liability_mode, NULL::DOUBLE compensator_increment, \
             NULL::DOUBLE initial_optionality, NULL::DOUBLE cumulative_increment WHERE false"
        }
        "competitor_results" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::VARCHAR AS system, NULL::VARCHAR system_version, \
             NULL::VARCHAR adapter_kind, NULL::VARCHAR case_id, NULL::VARCHAR status, \
             NULL::VARCHAR decision, NULL::BOOLEAN certificate_supported, \
             NULL::VARCHAR certificate_outcome, NULL::BOOLEAN blocked, NULL::BOOLEAN skipped, \
             NULL::DOUBLE liability_cost, NULL::VARCHAR evidence_url, NULL::VARCHAR skip_reason \
             WHERE false"
        }
        "coverage_gaps" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR decision_id, \
             NULL::VARCHAR thread_id, NULL::VARCHAR gap_kind, NULL::VARCHAR detail WHERE false"
        }
        "velvet_rope_traces" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR scenario_id, \
             NULL::VARCHAR query_id, NULL::VARCHAR system_name, NULL::VARCHAR adapter_name, \
             NULL::VARCHAR adapter_version, NULL::VARCHAR auditability_status, \
             NULL::BOOLEAN action_path_integrity, NULL::BOOLEAN action_executed, \
             NULL::BOOLEAN executed_without_warrant, NULL::BOOLEAN hidden_tool_call, \
             NULL::BOOLEAN missing_warrant, NULL::BOOLEAN missing_seal, \
             NULL::DOUBLE liability_multiplier, NULL::VARCHAR trace_hash, \
             NULL::VARCHAR raw_trace_path, NULL::VARCHAR trace_json WHERE false"
        }
        "velvet_failure_cards" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR system_name, \
             NULL::VARCHAR failure_card_id, NULL::VARCHAR failure_class, NULL::VARCHAR severity, \
             NULL::VARCHAR query_id, NULL::VARCHAR scenario_id, NULL::VARCHAR trace_hash, \
             NULL::VARCHAR reproduction_command, NULL::VARCHAR card_json WHERE false"
        }
        "result_failure_bindings" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR system_name, \
             NULL::VARCHAR adapter_name, NULL::VARCHAR adapter_version, NULL::VARCHAR result_type, \
             NULL::VARCHAR auditability_status, NULL::VARCHAR scenario_id, NULL::VARCHAR query_id, \
             NULL::VARCHAR trace_hash, NULL::VARCHAR failure_card_id, NULL::VARCHAR failure_class, \
             NULL::VARCHAR metric_name, NULL::INTEGER metric_numerator_contribution, \
             NULL::VARCHAR severity, NULL::DOUBLE liability_multiplier_contribution, \
             NULL::VARCHAR public_report_anchor, NULL::VARCHAR reproduction_command, \
             NULL::VARCHAR binding_json WHERE false"
        }
        "competitor_action_results" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR system_name, \
             NULL::VARCHAR adapter_name, NULL::VARCHAR adapter_version, NULL::VARCHAR result_type, \
             NULL::VARCHAR auditability_status, NULL::BOOLEAN action_path_integrity, \
             NULL::DOUBLE task_success_rate, NULL::DOUBLE liability_multiplier, \
             NULL::INTEGER critical_failure_count, NULL::INTEGER high_failure_count, \
             NULL::INTEGER medium_failure_count, NULL::INTEGER opportunity_failure_count, \
             NULL::INTEGER cost_failure_count, NULL::VARCHAR verdict, \
             NULL::VARCHAR public_claim_status, NULL::VARCHAR result_integrity_status, \
             NULL::VARCHAR result_json WHERE false"
        }
        "competitor_research_records" => {
            "SELECT NULL::VARCHAR run_id, NULL::VARCHAR condition_id, NULL::VARCHAR system_name, \
             NULL::VARCHAR category, NULL::VARCHAR auditability_grade, NULL::VARCHAR result_type, \
             NULL::VARCHAR adapter_feasibility, NULL::VARCHAR public_claim_status, \
             NULL::VARCHAR record_json WHERE false"
        }
        _ => "SELECT 1 WHERE false",
    }
}

#[allow(dead_code)]
fn has_parquet(path: &Path) -> bool {
    path.exists()
        && WalkDir::new(path)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .any(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("parquet")
            })
}

const INGEST_SCRIPT: &str = r#"
import json, sys
import duckdb

payload = json.load(sys.stdin)
con = duckdb.connect()

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

for item in payload["tables"]:
    table = item["table"]
    jsonl_path = item["jsonl_path"]
    parquet_dir = item["parquet_dir"]
    con.execute(f"CREATE OR REPLACE TABLE {table} AS SELECT * FROM read_json_auto({quote(jsonl_path)}, format='newline_delimited')")
    con.execute(f"COPY {table} TO {quote(parquet_dir)} (FORMAT PARQUET, PARTITION_BY (condition_id))")
"#;

const QUERY_SCRIPT: &str = r#"
import glob, json, pathlib, sys
import duckdb

payload = json.load(sys.stdin)
root = pathlib.Path(payload["root"])
run_id = payload.get("run_id")
con = duckdb.connect()

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

for table in payload["tables"]:
    if run_id:
        pattern = root / run_id / table / "**" / "*.parquet"
    else:
        pattern = root / "*" / table / "**" / "*.parquet"
    files = glob.glob(str(pattern), recursive=True)
    if files:
        filter_sql = f" WHERE run_id = {quote(run_id)}" if run_id else ""
        con.execute(f"CREATE OR REPLACE VIEW {table} AS SELECT * FROM read_parquet({quote(pattern)}, hive_partitioning=true){filter_sql}")
    else:
        con.execute(f"CREATE OR REPLACE VIEW {table} AS {payload['empty_selects'][table]}")

result = con.execute(payload["sql"])
columns = [desc[0] for desc in result.description]
rows = [["" if value is None else str(value) for value in row] for row in result.fetchall()]
print(json.dumps({"columns": columns, "rows": rows}, sort_keys=True))
"#;
