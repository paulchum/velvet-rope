# MCP Firewall For Agent Tool Calls

Route: `/mcp-firewall`

## Hero

MCP makes tools easier for agents to reach. Velvet makes each consequential tool
call earn authority before it executes.

Velvet Rope sits in front of MCP-shaped tool calls, checks listed tools and
policy, admits safe actions, blocks unlisted destructive actions, escalates
sensitive listed actions, and records warrant/seal/ledger evidence.

## The Problem

Platform teams are adding MCP servers faster than security teams can review tool
scope, privilege, schema drift, approval paths, and audit trails. A post-hoc log
can show that a tool was called. It does not prove the tool call had current
authority before execution.

## What Velvet Adds

- MCP tool inventory with risk classes and dispositions.
- Pre-execution `execute`, `block`, or `escalate` decisions.
- Warrant fields for schema hash, argument hash, policy version, approval state,
  budget context, and seal.
- Ledger records that can be inspected and replayed.
- A bounded pilot surface that does not require replacing the agent framework.

## Local Demo

```bash
uv run velvet mcp-firewall pilot --output-dir reports/mcp_firewall --verify-after-run
```

Additional references:

- MCP proxy overview: [`../mcp_proxy/overview.md`](../mcp_proxy/overview.md)
- MCP proxy security boundary: [`../mcp_proxy/security.md`](../mcp_proxy/security.md)
- Velvet Ledger: [`../velvet-ledger.md`](../velvet-ledger.md)

## 14-Day Pilot

Scope one workflow with MCP or tool-calling agents:

1. Inventory the MCP server/tool pairs.
2. Mark each tool as blocked, auto-approved, or escalation-required.
3. Route representative calls through Velvet.
4. Review allowed, blocked, escalated, and replayed actions.
5. Produce a short evidence report for platform and security owners.

Success criteria:

- Unlisted tool calls are blocked before routing.
- Sensitive listed tools route to approval or escalation.
- Security can inspect why a tool call was allowed, blocked, or escalated.

## CTA

Book a 14-day MCP tool-call assessment for one agent workflow.
