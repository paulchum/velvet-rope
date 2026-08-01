"""Local Starlette dashboard for thread inspection."""

from __future__ import annotations

import json
from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from velvet.ops import build_control_plane_snapshot
from velvet.thread_log import ThreadLogger
from velvet.vc_demo import build_vc_demo_payload


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach conservative browser security headers for the local dashboard."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "script-src 'self'; "
            "style-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response


def create_app(
    thread_path: str | Path | None = None,
    *,
    ledger_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
) -> Starlette:
    configured_thread_path = (
        Path(thread_path) if thread_path is not None else Path("threads/demo.jsonl")
    )
    configured_ledger_path = Path(ledger_path) if ledger_path is not None else None
    configured_registry_path = Path(registry_path) if registry_path is not None else None
    configured_approvals_path = Path(approvals_path) if approvals_path is not None else None

    def index(request: Request) -> HTMLResponse:
        _ = request
        return HTMLResponse(DASHBOARD_HTML)

    def stylesheet(request: Request) -> PlainTextResponse:
        _ = request
        return PlainTextResponse(DASHBOARD_CSS, media_type="text/css")

    def javascript(request: Request) -> PlainTextResponse:
        _ = request
        return PlainTextResponse(DASHBOARD_JS, media_type="text/javascript")

    def vc_demo(request: Request) -> HTMLResponse:
        _ = request
        return HTMLResponse(VC_DEMO_HTML)

    def vc_demo_javascript(request: Request) -> PlainTextResponse:
        _ = request
        return PlainTextResponse(VC_DEMO_JS, media_type="text/javascript")

    def thread(request: Request) -> JSONResponse:
        _ = request
        if not configured_thread_path.exists():
            raise HTTPException(status_code=404, detail="Thread file not found.")
        records = list(ThreadLogger.read(configured_thread_path))
        return JSONResponse({"thread_path": str(configured_thread_path), "records": records})

    def vc_demo_payload(request: Request) -> JSONResponse:
        _ = request
        return JSONResponse(build_vc_demo_payload())

    def control_plane_payload(request: Request) -> JSONResponse:
        _ = request
        return JSONResponse(
            build_control_plane_snapshot(
                thread_path=configured_thread_path,
                ledger_path=configured_ledger_path,
                registry_path=configured_registry_path,
                approvals_path=configured_approvals_path,
            )
        )

    app = Starlette(
        debug=False,
        routes=[
            Route("/", index),
            Route("/assets/app.css", stylesheet),
            Route("/assets/app.js", javascript),
            Route("/vc-demo", vc_demo),
            Route("/assets/vc-demo.js", vc_demo_javascript),
            Route("/api/thread", thread),
            Route("/api/vc-demo", vc_demo_payload),
            Route("/api/control-plane", control_plane_payload),
        ],
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    return app


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Velvet Thread Dashboard</title>
    <link rel="stylesheet" href="/assets/app.css">
    <script src="/assets/app.js" defer></script>
  </head>
  <body>
    <main class="shell">
      <header class="topbar">
        <div>
          <h1>Velvet</h1>
          <p>Warrant-bound action threshold for autonomous agents.</p>
        </div>
        <nav class="top-actions">
          <a class="nav-link" href="/vc-demo">VC demo</a>
          <div class="status" id="status">Loading thread</div>
        </nav>
      </header>
      <section class="grid">
        <article class="panel panel-wide">
          <div class="panel-header">
            <h2>Live Decision Thread</h2>
          </div>
          <div id="thread-list" class="thread-list"></div>
        </article>
        <article class="panel">
          <h2>Budget</h2>
          <dl id="budget-list" class="metric-list"></dl>
        </article>
        <article class="panel">
          <h2>Policy</h2>
          <dl id="policy-list" class="metric-list"></dl>
        </article>
        <article class="panel panel-wide">
          <h2>Memory Decisions</h2>
          <div id="memory-list" class="thread-list compact"></div>
        </article>
        <article class="panel">
          <h2>Evaluation</h2>
          <dl id="eval-list" class="metric-list"></dl>
        </article>
      </section>
    </main>
  </body>
</html>
"""


VC_DEMO_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Velvet VC Demo</title>
    <link rel="stylesheet" href="/assets/app.css">
    <script src="/assets/vc-demo.js" defer></script>
  </head>
  <body>
    <main class="shell vc-shell">
      <header class="topbar vc-hero">
        <div>
          <h1>Warrant-bound threshold for agent action</h1>
          <p id="thesis">Loading demo payload.</p>
        </div>
        <nav class="top-actions">
          <a class="nav-link" href="/">Thread dashboard</a>
          <div class="status" id="generated-at">Loading</div>
        </nav>
      </header>

      <section class="vc-grid">
        <article class="panel panel-wide vc-lead">
          <h2>Investor Narrative</h2>
          <p id="one-liner"></p>
          <div id="end-goals" class="goal-strip"></div>
        </article>
        <article class="panel">
          <h2>Claim Boundary</h2>
          <dl id="claim-list" class="metric-list"></dl>
        </article>
      </section>

      <section class="stage-grid">
        <article class="step-card liability-card">
          <h2>Liability Arena</h2>
          <p id="liability-line"></p>
          <div id="liability-issues" class="proof-stack"></div>
        </article>
        <article class="step-card">
          <h2>1. Rope Entry Prices</h2>
          <div id="rope-warrant" class="proof-stack"></div>
        </article>
        <article class="step-card">
          <h2>2. Velvet MCP Denials</h2>
          <div id="mcp-block" class="proof-stack"></div>
        </article>
        <article class="step-card">
          <h2>3. Sensitive Tools Escalate</h2>
          <div id="mcp-sensitive" class="proof-stack"></div>
        </article>
        <article class="step-card">
          <h2>4. Evidence Review Lane</h2>
          <p id="insurer-auditor-summary"></p>
          <div id="insurer-auditor-artifacts" class="proof-stack"></div>
        </article>
      </section>

      <section class="vc-grid">
        <article class="panel panel-wide">
          <h2>Certified Max-DE Recovery Window</h2>
          <p id="maxde-summary"></p>
          <div class="table-wrap">
            <table class="cert-table">
              <thead>
                <tr>
                  <th>Arm</th>
                  <th>Posterior</th>
                  <th>Myopic</th>
                  <th>Lower Cert</th>
                  <th>Upper Cert</th>
                  <th>Zone</th>
                </tr>
              </thead>
              <tbody id="maxde-table"></tbody>
            </table>
          </div>
        </article>
        <article class="panel">
          <h2>Max-DE Certificate Engine</h2>
          <dl id="maxde-metrics" class="metric-list"></dl>
          <dl id="maxde-ledger" class="metric-list"></dl>
        </article>
        <article class="panel">
          <h2>Pilot Offers</h2>
          <div id="pilot-list" class="thread-list compact"></div>
        </article>
      </section>

      <section class="panel source-panel">
        <h2>Research Grounding</h2>
        <div id="source-list" class="source-list"></div>
      </section>
    </main>
  </body>
</html>
"""


DASHBOARD_CSS = """
:root {
  color-scheme: light;
  --bg: #f6f8fb;
  --surface: #ffffff;
  --surface-soft: #f1f5f9;
  --text: #162033;
  --muted: #607086;
  --border: #d8e0ea;
  --accent: #2364d2;
  --execute: #126b44;
  --skip: #8a5b13;
  --block: #a22a2a;
  --shadow: 0 16px 48px rgba(21, 32, 51, 0.08);
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.shell {
  max-width: 1180px;
  margin: 0 auto;
  padding: 32px 20px 48px;
}
.topbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 24px;
}
.top-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
}
h1,
h2,
p {
  margin: 0;
}
h1 {
  font-size: 34px;
  line-height: 1.08;
  letter-spacing: 0;
}
h2 {
  font-size: 15px;
  line-height: 1.2;
  letter-spacing: 0;
}
p {
  margin-top: 8px;
  color: var(--muted);
}
.status,
.pill,
.nav-link {
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--surface);
  color: var(--muted);
  font-size: 13px;
  padding: 8px 12px;
  white-space: nowrap;
}
.nav-link {
  color: var(--accent);
  font-weight: 700;
  text-decoration: none;
}
.grid {
  display: grid;
  grid-template-columns: 1.45fr 0.8fr;
  gap: 16px;
}
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: var(--shadow);
  padding: 18px;
  min-width: 0;
}
.panel-wide {
  grid-row: span 2;
}
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.thread-list {
  display: grid;
  gap: 12px;
  margin-top: 16px;
}
.thread-item {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-soft);
  padding: 14px;
}
.thread-main {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.thread-action {
  font-weight: 700;
  font-size: 14px;
}
.thread-reason {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.45;
  margin-top: 8px;
}
.pill.execute {
  color: var(--execute);
}
.pill.skip {
  color: var(--skip);
}
.pill.block,
.pill.ask_approval {
  color: var(--block);
}
.metric-list {
  display: grid;
  grid-template-columns: minmax(120px, 1fr) auto;
  gap: 10px 14px;
  margin: 16px 0 0;
}
.metric-list dt {
  color: var(--muted);
  font-size: 13px;
}
.metric-list dd {
  margin: 0;
  font-weight: 700;
  font-size: 13px;
  text-align: right;
}
.compact .thread-item {
  background: var(--surface);
}
.vc-shell {
  max-width: 1240px;
}
.vc-hero {
  align-items: flex-start;
  padding: 30px 0 8px;
}
.vc-hero h1 {
  max-width: 850px;
  font-size: 42px;
}
.vc-hero p {
  max-width: 780px;
  font-size: 16px;
  line-height: 1.55;
}
.vc-grid {
  display: grid;
  grid-template-columns: 1.35fr 0.75fr;
  gap: 16px;
  margin-top: 16px;
}
.vc-lead p {
  color: var(--text);
  font-size: 18px;
  line-height: 1.5;
}
.goal-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
}
.goal-chip {
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--surface-soft);
  color: var(--text);
  font-size: 12px;
  font-weight: 700;
  padding: 7px 10px;
}
.stage-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin-top: 16px;
}
.step-card {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  box-shadow: var(--shadow);
  padding: 18px;
}
.liability-card {
  grid-column: 1 / -1;
}
.liability-card .proof-stack {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.liability-card .proof-row {
  border-top: 0;
  border-left: 1px solid var(--border);
  padding-top: 0;
  padding-left: 12px;
}
.proof-stack {
  display: grid;
  gap: 10px;
  margin-top: 16px;
}
.proof-row {
  display: grid;
  grid-template-columns: minmax(118px, 1fr) minmax(0, 1.15fr);
  gap: 10px;
  align-items: start;
  border-top: 1px solid var(--border);
  padding-top: 10px;
}
.proof-row:first-child {
  border-top: 0;
  padding-top: 0;
}
.proof-row dt {
  color: var(--muted);
  font-size: 12px;
}
.proof-row dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-size: 13px;
  font-weight: 700;
}
.table-wrap {
  margin-top: 16px;
  overflow-x: auto;
}
.cert-table {
  width: 100%;
  border-collapse: collapse;
  min-width: 720px;
}
.cert-table th,
.cert-table td {
  border-bottom: 1px solid var(--border);
  padding: 10px 8px;
  text-align: left;
  vertical-align: top;
  font-size: 13px;
}
.cert-table th {
  color: var(--muted);
  font-size: 12px;
}
.zone {
  display: inline-flex;
  border-radius: 999px;
  padding: 6px 9px;
  font-size: 12px;
  font-weight: 800;
}
.zone.inspect {
  background: #e7f6ef;
  color: var(--execute);
}
.zone.lockout {
  background: #fae9e9;
  color: var(--block);
}
.zone.refinement {
  background: #fff3dc;
  color: var(--skip);
}
.source-panel {
  margin-top: 16px;
}
.source-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-top: 16px;
}
.source-item {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-soft);
  padding: 12px;
}
.source-item a {
  color: var(--accent);
  font-size: 13px;
  font-weight: 800;
  text-decoration: none;
}
.source-item p {
  font-size: 13px;
  line-height: 1.4;
}
@media (max-width: 760px) {
  .topbar,
  .top-actions,
  .thread-main {
    align-items: flex-start;
    flex-direction: column;
  }
  .grid {
    grid-template-columns: 1fr;
  }
  .vc-grid,
  .stage-grid,
  .source-list {
    grid-template-columns: 1fr;
  }
  .liability-card .proof-stack {
    grid-template-columns: 1fr;
  }
  .liability-card .proof-row {
    grid-template-columns: 1fr;
    gap: 6px;
  }
  .vc-hero h1 {
    font-size: 32px;
  }
  .panel-wide {
    grid-row: span 1;
  }
}
"""


VC_DEMO_JS = """
const generatedAt = document.getElementById("generated-at");
const thesis = document.getElementById("thesis");
const oneLiner = document.getElementById("one-liner");
const endGoals = document.getElementById("end-goals");
const claimList = document.getElementById("claim-list");
const liabilityLine = document.getElementById("liability-line");
const liabilityIssues = document.getElementById("liability-issues");
const ropeWarrant = document.getElementById("rope-warrant");
const mcpBlock = document.getElementById("mcp-block");
const mcpSensitive = document.getElementById("mcp-sensitive");
const insurerAuditorSummary = document.getElementById("insurer-auditor-summary");
const insurerAuditorArtifacts = document.getElementById("insurer-auditor-artifacts");
const maxdeSummary = document.getElementById("maxde-summary");
const maxdeMetrics = document.getElementById("maxde-metrics");
const maxdeLedger = document.getElementById("maxde-ledger");
const maxdeTable = document.getElementById("maxde-table");
const pilotList = document.getElementById("pilot-list");
const sourceList = document.getElementById("source-list");

function addText(parent, tag, value, className) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  node.textContent = value;
  parent.appendChild(node);
  return node;
}

function addMetric(list, label, value) {
  addText(list, "dt", label);
  addText(list, "dd", String(value));
}

function addWarrantField(container, label, value) {
  const row = document.createElement("dl");
  row.className = "proof-row";
  addText(row, "dt", label);
  addText(row, "dd", value === undefined || value === null ? "none" : String(value));
  container.appendChild(row);
}

function fmt(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(4);
  }
  return value;
}

function renderDecision(container, demo) {
  const warrant = demo.selected_warrant || {};
  const policyReasons = (warrant.policy_reasons || [])
    .map((reason) => String(reason).replaceAll(".", " ").replaceAll("_", " "))
    .join(", ");
  addWarrantField(container, "Action", demo.action_type);
  addWarrantField(container, "Decision", demo.decision);
  addWarrantField(container, "Seal", demo.seal_id);
  if (demo.tool_key) {
  addWarrantField(container, "Tool", demo.tool_key);
  }
  addWarrantField(container, "Entry price", fmt(warrant.entry_price));
  addWarrantField(container, "Scarcity pressure", fmt(warrant.scarcity_pressure));
  addWarrantField(container, "Policy reasons", policyReasons || "none");
}

function renderMaxDe(maxde) {
  maxdeSummary.textContent = maxde.summary;
  addMetric(maxdeMetrics, "Engine", maxde.certificate_engine);
  addMetric(maxdeMetrics, "Inspect", maxde.outcome_counts.inspect);
  addMetric(maxdeMetrics, "Lockout", maxde.outcome_counts.lockout);
  addMetric(maxdeMetrics, "Refinement", maxde.outcome_counts.refinement);
  addMetric(maxdeMetrics, "Mean width", fmt(maxde.mean_unresolved_width));
  const budget = maxde.compensator_budget || {};
  addMetric(maxdeLedger, "Ledger arm", budget.arm);
  addMetric(maxdeLedger, "Consumed", fmt(budget.consumed));
  addMetric(maxdeLedger, "Initial optionality", fmt(budget.initial_optionality));
  addMetric(maxdeLedger, "Spend ratio", fmt(budget.spend_ratio));
  maxde.arms.forEach((arm) => {
    const row = document.createElement("tr");
    addText(row, "td", String(arm.arm));
    const posterior = [
      `Beta(${fmt(arm.posterior.alpha)}, ${fmt(arm.posterior.beta)})`,
      `mean ${fmt(arm.posterior.mean)}`,
    ].join(" ");
    addText(row, "td", posterior);
    addText(row, "td", arm.myopic_gate ? "open" : "skipped");
    addText(row, "td", fmt(arm.lower_certificate));
    addText(row, "td", fmt(arm.upper_certificate));
    const zoneCell = document.createElement("td");
    const zone = arm.certified_inspect
      ? "inspect"
      : arm.certified_lockout
        ? "lockout"
        : "refinement";
    addText(zoneCell, "span", zone, `zone ${zone}`);
    row.appendChild(zoneCell);
    maxdeTable.appendChild(row);
  });
}

function renderLiability(centerpiece) {
  liabilityLine.textContent = centerpiece.centerpiece_line;
  addWarrantField(liabilityIssues, "Rule", centerpiece.rule);
  addWarrantField(liabilityIssues, "Native control", centerpiece.native_control_status);
  addWarrantField(liabilityIssues, "Others", centerpiece.non_native_default_status);
  centerpiece.real_world_incidents.slice(0, 4).forEach((incident) => {
    addWarrantField(liabilityIssues, incident.title, incident.unsafe_issue);
  });
}

function renderInsurerAuditorLane(lane) {
  insurerAuditorSummary.textContent = lane.summary;
  addWarrantField(insurerAuditorArtifacts, "Audience", lane.audience);
  addWarrantField(insurerAuditorArtifacts, "Safe claims", lane.safe_claims.length);
  lane.artifacts.forEach((artifact) => {
    addWarrantField(insurerAuditorArtifacts, artifact.name, artifact.path);
  });
  addWarrantField(insurerAuditorArtifacts, "Not claimed", lane.not_claimed.length);
}

function render(payload) {
  generatedAt.textContent = new Date(payload.generated_at).toLocaleString();
  thesis.textContent = payload.thesis;
  oneLiner.textContent = payload.one_liner;
  payload.product_end_goals.forEach((goal) => addText(endGoals, "span", goal, "goal-chip"));
  addMetric(claimList, "Implemented", payload.claim_boundary.implemented_now.length);
  addMetric(claimList, "Not claimed", payload.claim_boundary.not_claimed.length);
  addMetric(claimList, "Pilot offers", payload.pilot_offers.length);
  addMetric(claimList, "Sources", payload.research_grounding.length);
  renderLiability(payload.liability_centerpiece);
  renderDecision(ropeWarrant, payload.demos.rope);
  renderDecision(mcpBlock, payload.demos.mcp_block);
  renderDecision(mcpSensitive, payload.demos.mcp_sensitive);
  renderInsurerAuditorLane(payload.insurer_auditor_lane);
  renderMaxDe(payload.demos.certified_max_de);
  payload.pilot_offers.forEach((offer) => {
    const item = document.createElement("div");
    item.className = "thread-item";
    addText(item, "div", offer.name, "thread-action");
    addText(item, "div", offer.outcome, "thread-reason");
    pilotList.appendChild(item);
  });
  payload.research_grounding.forEach((source) => {
    const item = document.createElement("div");
    item.className = "source-item";
    const link = document.createElement("a");
    link.href = source.url;
    link.textContent = source.label;
    item.appendChild(link);
    addText(item, "p", source.takeaway);
    sourceList.appendChild(item);
  });
}

fetch("/api/vc-demo", { headers: { "Accept": "application/json" } })
  .then((response) => {
    if (!response.ok) {
      throw new Error(`VC demo request failed: ${response.status}`);
    }
    return response.json();
  })
  .then((payload) => render(payload))
  .catch((error) => {
    generatedAt.textContent = "Demo unavailable";
    thesis.textContent = error.message;
  });
"""


DASHBOARD_JS = """
const statusNode = document.getElementById("status");
const threadList = document.getElementById("thread-list");
const budgetList = document.getElementById("budget-list");
const policyList = document.getElementById("policy-list");
const memoryList = document.getElementById("memory-list");
const evalList = document.getElementById("eval-list");

function addText(parent, tag, value, className) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  node.textContent = value;
  parent.appendChild(node);
  return node;
}

function addMetric(list, label, value) {
  addText(list, "dt", label);
  addText(list, "dd", String(value));
}

function renderTraceItem(parent, candidate) {
  const item = document.createElement("div");
  item.className = "thread-item";
  const action = candidate.final_action || candidate.raw_action || candidate;
  const main = document.createElement("div");
  main.className = "thread-main";
  addText(main, "div", action.action_type || "UNKNOWN", "thread-action");
  addText(main, "div", candidate.decision || "unknown", `pill ${candidate.decision || ""}`);
  item.appendChild(main);
  addText(item, "div", candidate.reason || "No reason recorded.", "thread-reason");
  parent.appendChild(item);
}

function render(records) {
  threadList.replaceChildren();
  budgetList.replaceChildren();
  policyList.replaceChildren();
  memoryList.replaceChildren();
  evalList.replaceChildren();
  const latest = records[records.length - 1];
  if (!latest) {
    statusNode.textContent = "No threads";
    return;
  }
  statusNode.textContent = `${records.length} thread record(s)`;
  const decisions = latest.scored_candidates || latest.policy_filtered_candidates || [];
  decisions.forEach((candidate) => renderTraceItem(threadList, candidate));
  const budgetState = latest.budget_state || {};
  addMetric(budgetList, "Candidates", (latest.raw_candidates || []).length || decisions.length);
  addMetric(budgetList, "Selected", latest.selected_action || "none");
  const tokenBudget = budgetState.tokens_remaining === undefined
    ? "unknown"
    : `${budgetState.tokens_remaining} token budget`;
  addMetric(budgetList, "Scarcity pressure", tokenBudget);
  addMetric(budgetList, "Threads", records.length);
  addMetric(policyList, "Policy chain", latest.policy_chain_name || "unknown");
  addMetric(policyList, "Policy revision", latest.policy_chain_revision || "unknown");
  addMetric(policyList, "Scorer", latest.scorer_version || "unknown");
  addMetric(policyList, "Pricing", latest.pricing_policy_name || "unknown");
  addMetric(policyList, "Pricing version", latest.pricing_policy_version || "unknown");
  addMetric(policyList, "Selected", latest.selected_action || "none");
  decisions
    .filter((candidate) => {
      const action = candidate.final_action || candidate.raw_action || candidate;
      return action.action_type === "STORE_MEMORY";
    })
    .forEach((candidate) => renderTraceItem(memoryList, candidate));
  if (!memoryList.hasChildNodes()) {
    addText(memoryList, "div", "No memory candidates in latest thread.", "thread-reason");
  }
  const state = latest.state || {};
  addMetric(evalList, "Expected action", state.expected_action || "not set");
  addMetric(evalList, "Freshness", state.freshness_required ? "required" : "not required");
  addMetric(evalList, "Ambiguity", state.ambiguous ? "blocking" : "clear enough");
}

fetch("/api/thread", { headers: { "Accept": "application/json" } })
  .then((response) => {
    if (!response.ok) {
      throw new Error(`Thread request failed: ${response.status}`);
    }
    return response.json();
  })
  .then((payload) => render(payload.records || []))
  .catch((error) => {
    statusNode.textContent = "Thread unavailable";
    threadList.replaceChildren();
    addText(threadList, "div", error.message, "thread-reason");
  });
"""


def traces_as_pretty_json(path: Path) -> str:
    records = list(ThreadLogger.read(path))
    return json.dumps(records, indent=2, sort_keys=True)
