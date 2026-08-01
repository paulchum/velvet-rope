use std::fs;
use std::path::Path;

use askama::Template;

use crate::Result;
use crate::query::run_recipe;
use crate::recipes;
use crate::store::QueryOutput;

#[derive(Template)]
#[template(
    source = "<!doctype html><html><head><meta charset=\"utf-8\"><title>{{ title }}</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:32px;line-height:1.4;color:#172026}table{border-collapse:collapse;width:100%;margin:12px 0 28px}th,td{border:1px solid #d8dee4;padding:6px 8px;text-align:left;font-size:13px}th{background:#f6f8fa}.note{color:#57606a}.chart{border:1px solid #d8dee4;padding:12px;margin:12px 0 28px;white-space:pre-wrap;background:#fbfbfc}</style></head><body><h1>{{ title }}</h1>{{ body_html|safe }}</body></html>",
    ext = "html"
)]
struct ReportTemplate {
    title: String,
    body_html: String,
}

pub fn generate(root: &Path, run_id: &str, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    let sections = [
        ("Run Summary", "run_summary"),
        ("Completion Rate", "completion_rate"),
        ("Pareto Frontier", "pareto_frontier"),
        ("Policy Denial Rates", "policy_denial_rate"),
        ("Top Cost Denials", "highest_cost_denied"),
        ("Top Override Wins", "highest_value_overrides"),
        ("Brier Score", "brier_by_action"),
        ("Expected Calibration Error", "ece_by_action"),
        ("Cost Attribution Drift", "cost_attribution_variance"),
        ("Novelty Calibration", "novelty_calibration"),
        ("Liability Benchmark", "liability_summary"),
        ("Certificate Coverage", "certificate_coverage"),
        ("Compensator Ledger", "compensator_ledger"),
        ("Surveyed Competitors", "competitor_matrix"),
        ("Velvet Rope Verdicts", "velvet_rope_summary"),
        (
            "Velvet Rope Action Path Integrity",
            "velvet_rope_action_path_integrity",
        ),
        ("Velvet Rope Bound Failures", "velvet_rope_bound_failures"),
        (
            "Velvet Rope Nonzero Metric Drilldown",
            "velvet_rope_nonzero_metric_drilldown",
        ),
        ("Velvet Rope Research Matrix", "velvet_rope_research_matrix"),
        ("Claim Boundary", "market_claim_support"),
        ("Coverage Gaps", "coverage_gaps"),
    ];
    let mut body = String::new();
    body.push_str("<p><strong>Task success does not offset unauthorized execution.</strong></p>");
    body.push_str("<p class=\"note\">Velvet Rope classifies systems by whether they can prove the pre-execution action path. Systems that cannot emit candidate actions, admission decisions, execution contexts, warrants, and replay seals are classified as partial or non-auditable under the Velvet Rope contract.</p>");
    body.push_str("<p class=\"note\">Counterfactual metrics are one-step approximations. Every table links to the SQL recipe used to derive it.</p>");
    body.push_str("<h2>Pareto Vega-Lite Spec</h2><pre class=\"chart\">");
    body.push_str(&html_escape(&pareto_spec(run_id)));
    body.push_str("</pre>");
    for (title, recipe) in sections {
        let output = run_recipe(root, Some(run_id), recipe)?;
        body.push_str(&format!(
            "<h2>{}</h2><p><code>velvet-eval query --recipe {} --run-id {}</code></p>",
            html_escape(title),
            html_escape(recipe),
            html_escape(run_id)
        ));
        body.push_str(&table_html(&output));
    }
    body.push_str("<h2>Recipe Registry</h2><ul>");
    for recipe in recipes::all() {
        body.push_str(&format!(
            "<li><code>{}</code>: {}{}</li>",
            html_escape(recipe.name),
            html_escape(recipe.description),
            if recipe.correlational {
                " <strong>correlational</strong>"
            } else {
                ""
            }
        ));
    }
    body.push_str("</ul>");

    let html = ReportTemplate {
        title: format!("Velvet Eval Report: {run_id}"),
        body_html: body,
    }
    .render()
    .map_err(|error| crate::message(error.to_string()))?;
    fs::write(output_dir.join("index.html"), html)?;
    Ok(())
}

fn table_html(output: &QueryOutput) -> String {
    let mut html = String::from("<table><thead><tr>");
    for column in &output.columns {
        html.push_str(&format!("<th>{}</th>", html_escape(column)));
    }
    html.push_str("</tr></thead><tbody>");
    for row in &output.rows {
        html.push_str("<tr>");
        for value in row {
            html.push_str(&format!("<td>{}</td>", html_escape(value)));
        }
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table>");
    html
}

fn pareto_spec(run_id: &str) -> String {
    format!(
        "{{\"$schema\":\"https://vega.github.io/schema/vega-lite/v5.json\",\"data\":{{\"url\":\"recipes/pareto_frontier.json\"}},\"mark\":\"point\",\"encoding\":{{\"x\":{{\"field\":\"total_cost\",\"type\":\"quantitative\"}},\"y\":{{\"field\":\"completion_rate\",\"type\":\"quantitative\"}},\"color\":{{\"field\":\"condition_id\",\"type\":\"nominal\"}}}},\"title\":\"Pareto frontier for {run_id}\"}}"
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
