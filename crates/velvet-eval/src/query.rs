use std::path::Path;

use serde_json::json;

use crate::recipes;
use crate::store::{QueryOutput, execute_query};
use crate::{Result, message};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Csv,
    Table,
}

pub fn run_sql(root: &Path, run_id: Option<&str>, sql: &str) -> Result<QueryOutput> {
    execute_query(root, run_id, sql)
}

pub fn run_recipe(root: &Path, run_id: Option<&str>, name: &str) -> Result<QueryOutput> {
    let recipe = recipes::get(name).ok_or_else(|| {
        message(format!(
            "unknown recipe {name:?}; available recipes: {}",
            recipes::names().join(", ")
        ))
    })?;
    run_sql(root, run_id, recipe.sql)
}

pub fn format_output(output: &QueryOutput, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => format_json(output),
        OutputFormat::Csv => format_csv(output),
        OutputFormat::Table => format_table(output),
    }
}

fn format_json(output: &QueryOutput) -> String {
    let rows = output
        .rows
        .iter()
        .map(|row| {
            let mut object = serde_json::Map::new();
            for (column, value) in output.columns.iter().zip(row) {
                object.insert(column.clone(), json!(value));
            }
            serde_json::Value::Object(object)
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&rows).expect("json output serializes")
}

fn format_csv(output: &QueryOutput) -> String {
    let mut lines = Vec::new();
    lines.push(
        output
            .columns
            .iter()
            .map(|value| csv_escape(value))
            .collect::<Vec<_>>()
            .join(","),
    );
    for row in &output.rows {
        lines.push(
            row.iter()
                .map(|value| csv_escape(value))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    lines.join("\n")
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn format_table(output: &QueryOutput) -> String {
    let mut widths = output.columns.iter().map(String::len).collect::<Vec<_>>();
    for row in &output.rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.len());
        }
    }
    let mut lines = Vec::new();
    lines.push(format_row(&output.columns, &widths));
    lines.push(
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("  "),
    );
    for row in &output.rows {
        lines.push(format_row(row, &widths));
    }
    lines.join("\n")
}

fn format_row(row: &[String], widths: &[usize]) -> String {
    row.iter()
        .zip(widths)
        .map(|(value, width)| format!("{value:width$}"))
        .collect::<Vec<_>>()
        .join("  ")
}
