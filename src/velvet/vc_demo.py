"""Reusable VC-fundraise demo payloads for Velvet.

The demo is intentionally built from current repo primitives rather than mock
objects: Agent Velvet warrants, Velvet MCP authorization, and Phase 0 Max-DE
certificates.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from velvet.research.bernoulli import BetaBernoulliPosterior
from velvet.research.policies import CertifiedMaxDEPolicy, DelightGatedPolicy
from velvet.rope import (
    AdmissionDecision,
    ToolRiskClass,
    VelvetMCP,
    VelvetRope,
    VelvetToolCall,
    VelvetToolPolicy,
)
from velvet.types import ActionType, CandidateAction
from velvet.velvet_rope_liability import (
    PUBLIC_CLAIM_SAFE_WORDING,
    REAL_WORLD_INCIDENTS,
    UNSAFE_ISSUE_EXPLANATIONS,
)

JsonObject = dict[str, Any]


PRODUCT_END_GOALS = [
    "Velvet Rope",
    "Velvet MCP",
    "Agent Spend Router",
    "Velvet Ledger",
    "Certified Max-DE Engine",
    "Agent Observability",
    "Policy Studio",
    "Agent Sandbox Broker",
    "Agent Identity & Permissions",
    "Registry Scanner",
    "Enterprise Appliance",
    "Vertical Packs",
]

DEMO_STRATEGY = {
    "investor_room": "Seed infrastructure VCs with security-aware enterprise instincts",
    "hero_scenario": "ServiceNow production change-control",
    "metaphor": (
        "Velvet is the rope outside the VIP room for agent actions. Read-only work earns entry, "
        "destructive unlisted work is turned away at the door, and sensitive production writes "
        "go to the concierge with a warrant and seal."
    ),
    "opening_line": (
        "The agent-platform race is making it easy for software to act; Velvet decides which "
        "actions have earned the right to act."
    ),
    "run_of_show": [
        "Set the market: agents now have tools, memory, files, sandboxes, and enterprise systems.",
        "Show the rope: every proposed action gets priced, checked, warranted, and sealed.",
        "Run the club-door moment: allow read-only ServiceNow lookup, block unlisted delete, "
        "escalate production change creation.",
        "Show the ledger: one record per consequential decision with policy reasons and evidence.",
        "Close with Max-DE as the flagship certificate engine inside Velvet: the path from "
        "priced action traces to certified posterior-typed thresholds.",
    ],
}

MARKET_SIGNALS = [
    {
        "signal": "Agent runtimes are becoming full action platforms.",
        "investor_read": (
            "OpenAI's Agents SDK now packages tools, memory, files, and sandbox execution; "
            "the build surface is becoming standardized and crowded."
        ),
        "demo_proof": (
            "Velvet is positioned after the agent decides to act and before execution authority "
            "is granted."
        ),
        "source": "OpenAI Agents SDK update",
        "url": "https://openai.com/index/the-next-evolution-of-the-agents-sdk",
    },
    {
        "signal": "MCP is turning tool access into shared infrastructure.",
        "investor_read": (
            "The MCP authorization spec gives the ecosystem transport-level auth primitives, "
            "but enterprises still need per-action admission, pricing, policy, and replay."
        ),
        "demo_proof": (
            "The demo blocks an unlisted MCP-shaped tool before routing and still checks listed "
            "tools through Velvet Rope."
        ),
        "source": "Model Context Protocol Authorization",
        "url": "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
    },
    {
        "signal": "Hyperscalers are bundling agent build, govern, and optimize workflows.",
        "investor_read": (
            "Google's Gemini Enterprise Agent Platform makes governance part of the platform war, "
            "which validates the control-plane category."
        ),
        "demo_proof": (
            "Velvet stays neutral: it is the warrant-bound control point around existing agent "
            "frameworks and enterprise tools."
        ),
        "source": "Google Gemini Enterprise Agent Platform",
        "url": "https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/gemini-enterprise-agent-platform/",
    },
    {
        "signal": "Enterprise agent projects are at risk without cost, value, and risk controls.",
        "investor_read": (
            "Gartner predicts over 40% of agentic AI projects will be canceled by the end of "
            "2027 because of cost, unclear value, or inadequate risk controls."
        ),
        "demo_proof": (
            "The demo makes each action's entry price, scarcity pressure, policy reason, and "
            "outcome visible before action."
        ),
        "source": "Gartner agentic AI project cancellation forecast",
        "url": "https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027",
    },
    {
        "signal": "AI VC is concentrated in infrastructure.",
        "investor_read": (
            "OECD reports that AI infrastructure and hosting attracted the most AI VC since 2023, "
            "reaching USD 109.3B in 2025."
        ),
        "demo_proof": (
            "Velvet is sold as agent-action infrastructure, not as a vertical copilot or generic "
            "agent builder."
        ),
        "source": "OECD AI VC investment report",
        "url": "https://www.oecd.org/en/publications/venture-capital-investments-in-artificial-intelligence-through-2025_a13752f5-en/full-report.html",
    },
    {
        "signal": "Security frameworks increasingly name agentic failure modes.",
        "investor_read": (
            "OWASP highlights excessive agency and agentic AI risks; buyers need controls before "
            "tools, data, and external actions are exposed."
        ),
        "demo_proof": (
            "Velvet's warrant, seal, and ledger contract turns tool misuse into a pre-execution "
            "authorization problem."
        ),
        "source": "OWASP Top 10 for LLM Applications",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications",
    },
]

PILOT_OFFERS = [
    {
        "name": "Velvet MCP for agent teams",
        "buyer": "Platform teams adopting MCP servers or internal tools",
        "outcome": "List, price, approve, block, and audit tool calls before execution.",
    },
    {
        "name": "AI agent audit pack",
        "buyer": "Security, risk, and compliance owners reviewing agent pilots",
        "outcome": (
            "Decision threads, policy jurisdiction_evidence, seals, and claim-boundary reports."
        ),
    },
    {
        "name": "Agent spend/replay assessment",
        "buyer": "Engineering leaders with rising model/tool spend",
        "outcome": "Cost attribution, routing diffs, denial rates, and replayable action records.",
    },
]

RESEARCH_GROUNDING = [
    {
        "label": "OpenAI Agents SDK update",
        "url": "https://openai.com/index/the-next-evolution-of-the-agents-sdk/",
        "takeaway": "Agent harnesses now include tools, memory, sandboxes, and durable execution.",
    },
    {
        "label": "OpenAI Frontier",
        "url": "https://openai.com/business/frontier/",
        "takeaway": "Model vendors are moving up into enterprise agent platforms.",
    },
    {
        "label": "Google Gemini Enterprise Agent Platform",
        "url": "https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/gemini-enterprise-agent-platform/",
        "takeaway": "Hyperscalers are bundling build, scale, govern, and optimize flows.",
    },
    {
        "label": "Model Context Protocol Authorization",
        "url": "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
        "takeaway": (
            "MCP standardizes tool connectivity and auth, creating demand for per-action gates."
        ),
    },
    {
        "label": "Gartner agentic AI cancellation forecast",
        "url": "https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027",
        "takeaway": (
            "Cost, unclear value, and weak risk controls are named reasons agent projects fail."
        ),
    },
    {
        "label": "OECD AI VC investment report",
        "url": "https://www.oecd.org/en/publications/venture-capital-investments-in-artificial-intelligence-through-2025_a13752f5-en/full-report.html",
        "takeaway": (
            "AI VC is concentrated in infrastructure and hosting, validating infrastructure wedges."
        ),
    },
    {
        "label": "NIST AI RMF",
        "url": "https://www.nist.gov/itl/ai-risk-management-framework",
        "takeaway": (
            "Enterprise AI buyers need governance, measurement, and risk-management artifacts."
        ),
    },
    {
        "label": "OWASP LLM Top 10",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "takeaway": (
            "Prompt injection, tool misuse, and sensitive data exposure are board-level risks."
        ),
    },
]

INSURER_AUDITOR_LANE = {
    "title": "Bounded insurer and auditor evidence lane",
    "audience": "Insurer, underwriter, auditor, and risk-review teams",
    "summary": (
        "Velvet packages review artifacts for a bounded incident window: an Article "
        "12-oriented technical record-keeping bundle, signed aggregate-only Assurance "
        "control-state attestations, and Claims Pack verification outputs."
    ),
    "safe_claims": [
        (
            "Velvet can produce a technical record-keeping bundle relevant to EU AI Act "
            "Article 12. It is not a legal conclusion, audit outcome, or substitute for "
            "counsel review."
        ),
        (
            "Velvet Assurance can emit signed, aggregate-only control-state attestations "
            "for auditor or underwriter review. The attestation omits prompts, action "
            "arguments, tool names, customer identities, and per-action records."
        ),
        "Velvet includes offline verifier packages for Assurance attestations.",
        (
            "Velvet includes a Claims Pack CLI for vault-backed incident windows when the "
            "required ledger, Signed Tree Head, public key, and signing configuration are "
            "supplied."
        ),
    ],
    "artifacts": [
        {
            "name": "Article 12 technical evidence bundle manifest",
            "path": "reports/live-demo/incident/claims_pack/manifest.json",
            "review_use": "Shows the bounded segment, manifest signature, file hashes, and notice.",
        },
        {
            "name": "Article 12 coverage report",
            "path": "reports/live-demo/incident/claims_pack/coverage_report.json",
            "review_use": (
                "Maps evidenced and not-evidenced fields without turning coverage into a "
                "legal conclusion."
            ),
        },
        {
            "name": "Aggregate Assurance attestations",
            "path": "reports/live-demo/incident/claims_pack/assurance/attestations.jsonl",
            "review_use": (
                "Provides signed aggregate control-state evidence without prompts, arguments, "
                "tool names, customer identities, or per-action records."
            ),
        },
        {
            "name": "Claims Pack verification reports",
            "path": "reports/live-demo/incident/claims_pack/verification/",
            "review_use": (
                "Carries Vault, Assurance, and replay-verification outputs for the supplied "
                "artifact window."
            ),
        },
    ],
    "not_claimed": [
        "Legal compliance, regulatory certification, or counsel review.",
        "Audit signoff or an auditor endorsement.",
        (
            "Insurance eligibility, coverage approval, coverage terms, pricing effects, "
            "or endorsement."
        ),
        "Full forensic root-cause analysis or coverage outside the supplied artifact window.",
    ],
}


def build_vc_demo_payload(*, generated_at: datetime | None = None) -> JsonObject:
    """Build a deterministic fundraise-demo payload from local Velvet primitives."""

    timestamp = generated_at or datetime.now(tz=UTC)
    admission_decision = _admission_decision()
    read_only_tool, blocked_tool, sensitive_tool, drifted_tool = _mcp_decisions()
    max_de = _max_de_demo()
    mcp_scenarios = _mcp_scenario_table(
        read_only_tool,
        sensitive_tool,
        blocked_tool,
        drifted_tool,
    )
    return {
        "generated_at": timestamp.isoformat(),
        "thesis": (
            "Velvet is the warrant-bound threshold for agent action: the velvet rope "
            "that prices, warrants, admits, denies, escalates, replays, and eventually "
            "certifies every consequential tool call, model escalation, memory write, "
            "and code execution."
        ),
        "one_liner": (
            "Velvet decides which agent actions earn entry, what price they must clear, "
            "and which warrant proves the action was justified before it happened."
        ),
        "demo_strategy": DEMO_STRATEGY,
        "market_signals": MARKET_SIGNALS,
        "liability_centerpiece": _liability_centerpiece(),
        "product_end_goals": PRODUCT_END_GOALS,
        "demos": {
            "rope": _decision_summary(admission_decision),
            "mcp_read_only": _decision_summary(read_only_tool),
            "mcp_block": _decision_summary(blocked_tool),
            "mcp_sensitive": _decision_summary(sensitive_tool),
            "mcp_schema_drift": _decision_summary(drifted_tool),
            "certified_max_de": max_de,
        },
        "mcp_scenario_table": mcp_scenarios,
        "warrant_field_checklist": _warrant_field_checklist(),
        "insurer_auditor_lane": INSURER_AUDITOR_LANE,
        "pilot_offers": PILOT_OFFERS,
        "claim_boundary": {
            "implemented_now": [
                "Deterministic Rust routing for typed actions.",
                "Policy-first filtering with jurisdiction_evidence and reasons.",
                "Entry prices, scarcity pressure, and clearance scores.",
                "Velvet warrant envelopes with seals.",
                "MCP list blocking before routing.",
                "MCP schema-hash drift denial before routing.",
                "MCP warrant pricing snapshots for routed listed tool calls.",
                "Research-level Max-DE lower and upper certificates.",
            ],
            "not_claimed": [
                "Solved agent exploration.",
                "Hard-capped total compute spend.",
                "Hosted shared-tenant service.",
                "Full MCP protocol server or remote MCP transport.",
                "Production-safe arbitrary code execution without a container backend.",
                "Runtime-integrated formal certificates for all agent decisions.",
            ],
        },
        "research_grounding": RESEARCH_GROUNDING,
    }


def write_vc_demo_artifacts(output_dir: str | Path) -> tuple[Path, Path]:
    """Write JSON and Markdown artifacts for the fundraise demo."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    payload = build_vc_demo_payload()
    json_path = destination / "vc_demo.json"
    markdown_path = destination / "vc_demo.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_vc_demo_markdown(payload), encoding="utf-8")
    return json_path, markdown_path


def render_vc_demo_markdown(payload: Mapping[str, Any]) -> str:
    """Render the payload as a diligence-friendly Markdown report."""

    demos = payload["demos"]
    rope = demos["rope"]
    read_only = demos["mcp_read_only"]
    block = demos["mcp_block"]
    sensitive = demos["mcp_sensitive"]
    schema_drift = demos["mcp_schema_drift"]
    max_de = demos["certified_max_de"]
    arm_one = max_de["arms"][1]
    lines = [
        "# Velvet VC Demo Report",
        "",
        f"Generated: `{payload['generated_at']}`",
        "",
        "## Thesis",
        "",
        str(payload["thesis"]),
        "",
        "## Investor Demo Strategy",
        "",
        f"- Investor room: {payload['demo_strategy']['investor_room']}",
        f"- Hero scenario: {payload['demo_strategy']['hero_scenario']}",
        f"- Metaphor: {payload['demo_strategy']['metaphor']}",
        f"- Opening line: {payload['demo_strategy']['opening_line']}",
        "",
        "Run of show:",
    ]
    lines.extend(f"- {item}" for item in payload["demo_strategy"]["run_of_show"])
    lines.extend(
        [
            "",
            "## Market Signals",
            "",
            "| Signal | Investor Read | Demo Proof | Source |",
            "|---|---|---|---|",
        ]
    )
    for signal in payload["market_signals"]:
        lines.append(
            "| "
            f"{signal['signal']} | "
            f"{signal['investor_read']} | "
            f"{signal['demo_proof']} | "
            f"[{signal['source']}]({signal['url']}) |"
        )
    liability = payload["liability_centerpiece"]
    lines.extend(
        [
            "",
            "## Liability Arena Centerpiece",
            "",
            liability["rule"],
            "",
            f"- Native control status: `{liability['native_control_status']}`",
            f"- Non-native default status: `{liability['non_native_default_status']}`",
            f"- Public-safe boundary: {liability['public_safe_wording']}",
            "",
            "| Real-world scenario | Unsafe issue | Implication |",
            "|---|---|---|",
        ]
    )
    for incident in liability["real_world_incidents"]:
        lines.append(
            "| "
            f"{incident['title']} | "
            f"`{incident['unsafe_issue']}` | "
            f"{incident['real_world_implication']} |"
        )
    lines.extend(
        [
            "",
            "## Demo Acceptance",
            "",
            (
                "- Velvet Warrant includes entry price, scarcity pressure, "
                "policy jurisdiction_evidence, and seal."
            ),
            f"  - Selected: `{rope['action_type']}` / `{rope['decision']}`",
            f"  - Seal: `{rope['seal_id']}`",
            f"  - Entry price: `{rope['selected_warrant'].get('entry_price')}`",
            f"  - Scarcity pressure: `{rope['selected_warrant'].get('scarcity_pressure')}`",
            "- Velvet MCP allows a read-only enterprise tool after pricing and policy.",
            f"  - Tool: `{read_only['tool_key']}`",
            f"  - Decision: `{read_only['decision']}`",
            f"  - Entry price: `{read_only['selected_warrant'].get('entry_price')}`",
            "- Velvet MCP blocks an unlisted tool before routing.",
            f"  - Tool: `{block['tool_key']}`",
            f"  - Decision: `{block['decision']}`",
            f"  - Seal: `{block['seal_id']}`",
            "- Velvet MCP blocks a listed tool whose schema hash drifted.",
            f"  - Tool: `{schema_drift['tool_key']}`",
            f"  - Decision: `{schema_drift['decision']}`",
            (
                "  - Policy reasons: "
                f"`{', '.join(schema_drift['selected_warrant'].get('policy_reasons', []))}`"
            ),
            "- Velvet MCP escalates a sensitive listed tool through the policy chain.",
            f"  - Tool: `{sensitive['tool_key']}`",
            f"  - Decision: `{sensitive['decision']}`",
            (
                "  - Policy reasons: "
                f"`{', '.join(sensitive['selected_warrant'].get('policy_reasons', []))}`"
            ),
            f"  - Entry price: `{sensitive['selected_warrant'].get('entry_price')}`",
            (
                "- Certified Max-DE keeps a one-failure arm inspectable while the "
                "myopic gate skips it."
            ),
            f"  - Myopic arm 1 gate: `{arm_one['myopic_gate']}`",
            f"  - Certified arm 1 inspect: `{arm_one['certified_inspect']}`",
            f"  - Certified arm 1 lockout: `{arm_one['certified_lockout']}`",
            f"  - Lower certificate: `{arm_one['lower_certificate']}`",
            f"  - Upper certificate: `{arm_one['upper_certificate']}`",
            "",
            "## MCP Scenario Table",
            "",
            "| Scenario | Tool Call | Risk Class | Expected Outcome | Buyer-Legible Warrant |",
            "|---|---|---:|---|---|",
        ]
    )
    for scenario in payload["mcp_scenario_table"]:
        lines.append(
            "| "
            f"{scenario['scenario']} | "
            f"`{scenario['tool_call']}` | "
            f"`{scenario['risk_class']}` | "
            f"`{scenario['expected_outcome']}` | "
            f"{scenario['buyer_legible_warrant']} |"
        )
    lines.extend(
        [
            "",
            "## Velvet Warrant Fields",
            "",
            "| Field | Present | Source |",
            "|---|---:|---|",
        ]
    )
    for item in payload["warrant_field_checklist"]:
        lines.append(f"| `{item['field']}` | `{item['present']}` | {item['source']} |")
    lane = payload["insurer_auditor_lane"]
    lines.extend(
        [
            "",
            "## Insurer And Auditor Evidence Lane",
            "",
            str(lane["summary"]),
            "",
            "Safe claims:",
        ]
    )
    lines.extend(f"- {item}" for item in lane["safe_claims"])
    lines.extend(
        [
            "",
            "| Artifact | Path | Review Use |",
            "|---|---|---|",
        ]
    )
    for artifact in lane["artifacts"]:
        lines.append(
            "| "
            f"{artifact['name']} | "
            f"`{artifact['path']}` | "
            f"{artifact['review_use']} |"
        )
    lines.extend(["", "Not claimed:"])
    lines.extend(f"- {item}" for item in lane["not_claimed"])
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "Implemented now:",
        ]
    )
    lines.extend(f"- {item}" for item in payload["claim_boundary"]["implemented_now"])
    lines.extend(["", "Not claimed:"])
    lines.extend(f"- {item}" for item in payload["claim_boundary"]["not_claimed"])
    lines.extend(["", "## Pilot Offers", ""])
    for offer in payload["pilot_offers"]:
        lines.append(f"- **{offer['name']}**: {offer['outcome']}")
    lines.extend(["", "## Research Grounding", ""])
    for source in payload["research_grounding"]:
        lines.append(f"- [{source['label']}]({source['url']}): {source['takeaway']}")
    lines.append("")
    return "\n".join(lines)


def _liability_centerpiece() -> JsonObject:
    unsafe_issues = [
        {
            "unsafe_issue": issue,
            "explanation": UNSAFE_ISSUE_EXPLANATIONS[issue],
        }
        for issue in (
            "missing_pre_execution_warrant",
            "unauthorized_destructive_action",
            "stale_policy_snapshot",
            "jurisdiction_mismatch",
            "prompt_policy_bypass",
            "missing_replay_seal",
        )
    ]
    return {
        "rule": "Task success does not cleanse unauthorized execution.",
        "centerpiece_line": (
            "The arena labels unsafe action paths by issue: what proof was missing, "
            "what authority was absent, and why the result cannot be trusted for "
            "consequential action."
        ),
        "native_control_status": "safe_for_consequential_action",
        "non_native_default_status": "unsafe_for_consequential_action",
        "public_safe_wording": PUBLIC_CLAIM_SAFE_WORDING,
        "unsafe_issues": unsafe_issues,
        "real_world_incidents": list(REAL_WORLD_INCIDENTS),
    }


def _admission_decision() -> AdmissionDecision:
    non_budget = {"non_budget_affecting": True}
    return VelvetRope().decide(
        {
            "freshness_required": True,
            "user_request": "latest agent security and governance news",
            "expected_action": "SEARCH_WEB",
        },
        [
            CandidateAction(ActionType.ANSWER_DIRECTLY, metadata=non_budget),
            CandidateAction(
                ActionType.SEARCH_WEB,
                description="Search the web for fresh agent governance jurisdiction_evidence.",
                expected_improvement=0.95,
                novelty=0.9,
                confidence=0.9,
                cost_overrides={"api_calls": 0.0, "latency": 0.0},
                risk_overrides={"source_quality_risk": 0.0},
                metadata=non_budget,
            ),
            CandidateAction(ActionType.ASK_USER, metadata=non_budget),
        ],
    )


def _mcp_decisions() -> tuple[
    AdmissionDecision,
    AdmissionDecision,
    AdmissionDecision,
    AdmissionDecision,
]:
    rope = VelvetRope(policy_dir="examples/mcp/policies", chain="mcp_demo")
    read_only = VelvetMCP(
        rope=rope,
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="search_change_requests",
                risk_class=ToolRiskClass.LOW,
                expected_improvement=0.9,
                novelty=0.52,
                confidence=0.84,
                metadata={
                    "approval_tier": "auto_approve",
                    "rationale": "Read-only change lookup used before production release triage.",
                },
            ),
        ),
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="search_change_requests",
            arguments={"query": "service=payments state=open"},
            user_request=(
                "Find open production payment-service change requests before opening anything new."
            ),
        )
    )
    blocked = VelvetMCP().authorize(
        VelvetToolCall(
            server="servicenow",
            tool="delete_change_request",
            arguments={"change_id": "CHG0042007"},
            user_request="Remove the stale production change request before the release meeting.",
        )
    )
    sensitive = VelvetMCP(
        rope=rope,
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="create_change_request",
                risk_class=ToolRiskClass.HIGH,
                expected_improvement=0.84,
                novelty=0.7,
                confidence=0.76,
                metadata={
                    "approval_tier": "concierge_review",
                    "rationale": (
                        "Creates production change-management work and can trigger release process."
                    ),
                    "usd_estimate": 75.0,
                },
            ),
        ),
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="create_change_request",
            arguments={
                "service": "payments",
                "summary": "Approve production deploy for routing fix",
                "window": "2026-05-23T22:00:00-07:00",
            },
            user_request="Open a production change request for the routing fix.",
        )
    )
    drifted = VelvetMCP(
        rope=rope,
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="search_incidents",
                risk_class=ToolRiskClass.LOW,
                expected_improvement=0.86,
                novelty=0.54,
                confidence=0.82,
                metadata={
                    "approval_tier": "auto_approve",
                    "rationale": "Read-only incident search used by support agents.",
                    "schema_status": "drifted",
                    "schema_hash": "sha256:new_incident_schema",
                    "tool_schema_hash": "sha256:new_incident_schema",
                    "approved_schema_hash": "sha256:approved_incident_schema",
                    "tool_id": "mcp:servicenow/search_incidents",
                    "owner": "platform-security",
                    "environment": "production",
                    "data_class": "operational",
                },
            ),
        ),
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="search_incidents",
            arguments={"query": "priority=1 OR assignment_group=payments"},
            user_request="Find open priority-one incidents related to payments.",
        )
    )
    return read_only, blocked, sensitive, drifted


def _max_de_demo() -> JsonObject:
    posterior = BetaBernoulliPosterior(
        alpha=np.array([1.0, 1.0], dtype=np.float64),
        beta=np.array([1.0, 2.0], dtype=np.float64),
    )
    myopic = DelightGatedPolicy(gate_price=0.08, surprisal_cap=1.0).score(posterior)
    certified = CertifiedMaxDEPolicy(
        gate_price=0.08,
        lookback_horizon=3,
        surprisal_cap=1.0,
    ).score(posterior)
    compensator = posterior.compensator_step(
        1,
        baseline=certified.baseline,
        horizon=3,
    )
    arms: list[JsonObject] = []
    for index in range(posterior.num_arms):
        unresolved_width = float(
            certified.upper_certificate[index] - certified.lower_certificate[index]
        )
        arms.append(
            {
                "arm": index,
                "posterior": {
                    "alpha": float(posterior.alpha[index]),
                    "beta": float(posterior.beta[index]),
                    "mean": float(posterior.means()[index]),
                },
                "expected_improvement": float(myopic.expected_improvement[index]),
                "myopic_delight": float(myopic.delight[index]),
                "myopic_gate": bool(myopic.gate_mask[index]),
                "lower_certificate": float(certified.lower_certificate[index]),
                "upper_certificate": float(certified.upper_certificate[index]),
                "certified_delight": float(certified.certified_delight[index]),
                "upper_delight": float(certified.upper_delight[index]),
                "certified_inspect": bool(certified.inspect_mask[index]),
                "certified_lockout": bool(certified.lockout_mask[index]),
                "certified_refinement": bool(certified.refinement_mask[index]),
                "unresolved_width": unresolved_width,
            }
        )
    outcome_counts = {
        "inspect": int(np.count_nonzero(certified.inspect_mask)),
        "lockout": int(np.count_nonzero(certified.lockout_mask)),
        "refinement": int(np.count_nonzero(certified.refinement_mask)),
    }
    return {
        "certificate_engine": "Certified Max-DE",
        "baseline": float(certified.baseline),
        "threshold": float(certified.threshold),
        "lookback_horizon": 3,
        "outcome_counts": outcome_counts,
        "mean_unresolved_width": float(
            np.mean(certified.upper_certificate - certified.lower_certificate)
        ),
        "compensator_budget": {
            "arm": compensator.arm,
            "consumed": compensator.cumulative_increment,
            "initial_optionality": compensator.initial_optionality,
            "spend_ratio": (
                compensator.cumulative_increment / compensator.initial_optionality
                if compensator.initial_optionality > 0
                else None
            ),
        },
        "summary": (
            "Arm 1 has one observed failure. The myopic gate skips it, "
            "but the finite-horizon lower certificate keeps it inspectable and "
            "the upper certificate prevents a premature permanent lockout."
        ),
        "arms": arms,
        "compensator_step": compensator.to_dict(),
    }


def _decision_summary(decision: AdmissionDecision) -> JsonObject:
    selected = decision.selected_warrant.to_dict() if decision.selected_warrant is not None else {}
    selected_candidate = decision.decision.selected_candidate
    parameters = selected_candidate.final_candidate.parameters if selected_candidate else {}
    return {
        "product_surface": decision.product_surface,
        "action_type": decision.decision.action_type.value
        if decision.decision.action_type is not None
        else None,
        "decision": decision.decision.decision.value,
        "reason": decision.decision.reason,
        "seal_id": decision.decision.seal_id,
        "thread_id": decision.decision.thread_id,
        "tool_key": parameters.get("tool_name") or _tool_key_from_selected(selected),
        "selected_warrant": selected,
        "warrants": [warrant.to_dict() for warrant in decision.warrants],
    }


def _mcp_scenario_table(
    read_only: AdmissionDecision,
    sensitive: AdmissionDecision,
    blocked: AdmissionDecision,
    drifted: AdmissionDecision,
) -> tuple[JsonObject, ...]:
    return (
        {
            "scenario": "Harmless read-only call",
            "tool_call": "servicenow/search_change_requests",
            "risk_class": _risk_class(read_only),
            "expected_outcome": read_only.decision.decision.value,
            "buyer_legible_warrant": (
                "Listed, priced, policy jurisdiction_evidence present, seal emitted."
            ),
        },
        {
            "scenario": "Sensitive write/action call",
            "tool_call": "servicenow/create_change_request",
            "risk_class": _risk_class(sensitive),
            "expected_outcome": sensitive.decision.decision.value,
            "buyer_legible_warrant": (
                "Listed, still routed through policy and pricing, "
                "ConciergeReview jurisdiction_evidence retained."
            ),
        },
        {
            "scenario": "Blocked destructive call",
            "tool_call": "servicenow/delete_change_request",
            "risk_class": _risk_class(blocked),
            "expected_outcome": blocked.decision.decision.value,
            "buyer_legible_warrant": (
                "Velvet MCP list jurisdiction_evidence, no tool execution, seal emitted."
            ),
        },
        {
            "scenario": "Schema drift on a listed tool",
            "tool_call": "servicenow/search_incidents",
            "risk_class": _risk_class(drifted),
            "expected_outcome": drifted.decision.decision.value,
            "buyer_legible_warrant": (
                "Listed tool is still denied because its current schema hash "
                "differs from the approved hash."
            ),
        },
    )


def _warrant_field_checklist() -> tuple[JsonObject, ...]:
    return (
        {"field": "admission_decision.seal_id", "present": True, "source": "AdmissionDecision"},
        {"field": "selected_warrant.reason", "present": True, "source": "VelvetWarrant"},
        {"field": "selected_warrant.policy_statuses", "present": True, "source": "policy trace"},
        {"field": "selected_warrant.policy_reasons", "present": True, "source": "policy trace"},
        {
            "field": "selected_warrant.jurisdiction_evidence",
            "present": True,
            "source": "policy jurisdiction_evidence",
        },
        {"field": "selected_warrant.risk_class", "present": True, "source": "MCP metadata"},
        {"field": "selected_warrant.entry_price", "present": True, "source": "pricing snapshot"},
        {
            "field": "selected_warrant.scarcity_pressure",
            "present": True,
            "source": "pricing snapshot",
        },
        {"field": "selected_warrant.selected", "present": True, "source": "warrant selection"},
    )


def _risk_class(decision: AdmissionDecision) -> str | None:
    if decision.selected_warrant is None:
        return None
    return decision.selected_warrant.risk_class


def _tool_key_from_selected(proof: Mapping[str, Any]) -> str | None:
    for jurisdiction_evidence in proof.get("jurisdiction_evidence", []):
        details = (
            jurisdiction_evidence.get("details", {})
            if isinstance(jurisdiction_evidence, Mapping)
            else {}
        )
        tool = details.get("tool")
        if isinstance(tool, str):
            return tool
    return None
