use std::fs;
use std::io::Read;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::metrics::bca_mean_ci;
use crate::query::{OutputFormat, format_output, run_recipe, run_sql};
use crate::store::{default_root, execute_query};
use crate::{Result, bench, ingest, integrity, replay, report, schema};

#[derive(Debug, Parser)]
#[command(name = "velvet-eval")]
#[command(about = "Evaluate Velvet schema 8 threads with DuckDB and Parquet")]
struct Cli {
    #[arg(long, global = true)]
    store_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Ingest(IngestArgs),
    Query(QueryArgs),
    Replay(ReplayArgs),
    Report(ReportArgs),
    Diff(DiffArgs),
    Ab(AbArgs),
    Bench(BenchArgs),
    Schema(SchemaArgs),
    VerifyReportIntegrity(VerifyReportIntegrityArgs),
}

#[derive(Debug, Args)]
struct IngestArgs {
    thread_dir: PathBuf,
    #[arg(long)]
    run_id: String,
}

#[derive(Debug, Args)]
struct QueryArgs {
    #[arg(long)]
    recipe: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    sql_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "table")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    condition: Option<String>,
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct DiffArgs {
    #[arg(long)]
    baseline: String,
    #[arg(long)]
    candidate: String,
}

#[derive(Debug, Args)]
struct AbArgs {
    #[arg(long)]
    metric: String,
    #[arg(long, value_delimiter = ',')]
    arms: Vec<String>,
}

#[derive(Debug, Args)]
struct BenchArgs {
    #[arg(long)]
    suite: String,
}

#[derive(Debug, Args)]
struct SchemaArgs {
    #[arg(long, default_value = "schemas/thread-v8.schema.json")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyReportIntegrityArgs {
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    report: PathBuf,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let root = cli.store_root.unwrap_or_else(default_root);
    match cli.command {
        Command::Ingest(args) => {
            ingest::ingest(&args.thread_dir, &args.run_id, &root)?;
            println!("ingested run_id={} into {}", args.run_id, root.display());
        }
        Command::Query(args) => {
            let output = if let Some(recipe) = args.recipe {
                run_recipe(&root, args.run_id.as_deref(), &recipe)?
            } else if let Some(sql_file) = args.sql_file {
                run_sql(
                    &root,
                    args.run_id.as_deref(),
                    &fs::read_to_string(sql_file)?,
                )?
            } else {
                let mut sql = String::new();
                std::io::stdin().read_to_string(&mut sql)?;
                run_sql(&root, args.run_id.as_deref(), &sql)?
            };
            println!("{}", format_output(&output, args.format));
        }
        Command::Replay(args) => {
            let report = replay::seal_run(&root, &args.run_id, args.condition.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Report(args) => {
            report::generate(&root, &args.run_id, &args.output)?;
            println!("{}", args.output.join("index.html").display());
        }
        Command::Diff(args) => {
            print_diff(&root, &args.baseline, &args.candidate)?;
        }
        Command::Ab(args) => {
            print_ab(&root, &args.metric, &args.arms)?;
        }
        Command::Bench(args) => {
            let run_id = bench::run_suite(&std::env::current_dir()?, &root, &args.suite)?;
            println!("bench suite={} run_id={}", args.suite, run_id);
        }
        Command::Schema(args) => {
            schema::write_thread_schema(&args.output)?;
            println!("{}", args.output.display());
        }
        Command::VerifyReportIntegrity(args) => {
            let report = integrity::verify(&args.run_id, &args.report)?;
            println!(
                "report_integrity=valid run_id={} checked={}",
                args.run_id, report.checked
            );
        }
    }
    Ok(())
}

fn print_diff(root: &std::path::Path, baseline: &str, candidate: &str) -> Result<()> {
    let metric = execute_query(
        root,
        None,
        &format!(
            "WITH rates AS (
                SELECT run_id, avg(CASE WHEN selected_completed THEN 1.0 ELSE 0.0 END) completion_rate, count(*) n
                FROM threads WHERE run_id IN ('{}','{}') GROUP BY run_id
            )
            SELECT b.run_id baseline, c.run_id candidate, b.completion_rate baseline_completion,
                   c.completion_rate candidate_completion,
                   c.completion_rate - b.completion_rate completion_delta,
                   b.n baseline_n, c.n candidate_n
            FROM rates b, rates c WHERE b.run_id='{}' AND c.run_id='{}'",
            esc(baseline),
            esc(candidate),
            esc(baseline),
            esc(candidate)
        ),
    )?;
    println!("Metric deltas");
    println!("{}", format_output(&metric, OutputFormat::Table));
    let paired = execute_query(
        root,
        None,
        &format!(
            "WITH b AS (SELECT * FROM threads WHERE run_id='{}'),
                  c AS (SELECT * FROM threads WHERE run_id='{}')
             SELECT
                    CASE WHEN c.selected_completed THEN 1.0 ELSE 0.0 END
                  - CASE WHEN b.selected_completed THEN 1.0 ELSE 0.0 END completion_delta
             FROM b JOIN c USING (condition_id, scenario_id, decision_id)
             ORDER BY b.condition_id, b.scenario_id, b.decision_id",
            esc(baseline),
            esc(candidate)
        ),
    )?;
    let paired_deltas = paired
        .rows
        .iter()
        .filter_map(|row| row.first())
        .filter_map(|value| value.parse::<f64>().ok())
        .collect::<Vec<_>>();
    let paired_ci = bca_mean_ci(&paired_deltas, 10_000, 0xD311_6E05);
    let changed = execute_query(
        root,
        None,
        &format!(
            "WITH b AS (SELECT * FROM threads WHERE run_id='{}'),
                  c AS (SELECT * FROM threads WHERE run_id='{}')
             SELECT coalesce(b.condition_id, c.condition_id) condition_id,
                    coalesce(b.scenario_id, c.scenario_id) scenario_id,
                    coalesce(b.decision_id, c.decision_id) decision_id,
                    b.selected_action baseline_action,
                    c.selected_action candidate_action,
                    b.policy_chain_revision baseline_policy_revision,
                    c.policy_chain_revision candidate_policy_revision
             FROM b FULL OUTER JOIN c USING (condition_id, scenario_id, decision_id)
             WHERE b.selected_action IS DISTINCT FROM c.selected_action
                OR b.policy_chain_revision IS DISTINCT FROM c.policy_chain_revision
             ORDER BY condition_id, scenario_id, decision_id",
            esc(baseline),
            esc(candidate)
        ),
    )?;
    println!("\nChanged decisions");
    println!("{}", format_output(&changed, OutputFormat::Table));
    let completion_delta = metric
        .rows
        .first()
        .and_then(|row| row.get(4))
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0);
    let changed_count = changed.rows.len();
    println!("\nDiff summary");
    println!("changed_decisions={changed_count}");
    println!(
        "paired_completion_delta_ci={:.6},{:.6}",
        paired_ci.lower, paired_ci.upper
    );
    println!(
        "routing_behavior_change={}",
        changed_count > 0 || completion_delta.abs() > f64::EPSILON
    );
    Ok(())
}

fn print_ab(root: &std::path::Path, metric: &str, arms: &[String]) -> Result<()> {
    let recipe = match metric {
        "completion_rate" | "completion" => "completion_overall",
        "cost_attribution_variance" => "cost_attribution_variance",
        "brier" | "brier_score" => "brier_by_action",
        "ece" => "ece_by_action",
        other => other,
    };
    let mut all_rows = Vec::new();
    let mut columns = Vec::new();
    for arm in arms {
        let output = run_recipe(root, Some(arm), recipe)?;
        if columns.is_empty() {
            columns = output.columns;
        }
        all_rows.extend(output.rows);
    }
    println!(
        "{}",
        format_output(
            &crate::store::QueryOutput {
                columns,
                rows: all_rows
            },
            OutputFormat::Table
        )
    );
    Ok(())
}

fn esc(value: &str) -> String {
    value.replace('\'', "''")
}
