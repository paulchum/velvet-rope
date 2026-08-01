# Velvet MCP Proxy Overview

Velvet MCP Proxy is a fail-closed, certificate-carrying MCP tool-call
enforcement gateway for single-tenant controlled pilots. It sits between MCP
clients and upstream MCP servers, inventories upstream tools, filters
`tools/list`, enforces `tools/call`, and records proof before forwarded tool
execution.

Target MCP spec: `2025-11-25`.

The surface boundary is defined in
[`SURFACE_MATRIX.md`](SURFACE_MATRIX.md). Methods outside the enforced and
lifecycle-forwarded sets are bounded-governed, not silently forwarded.

## MCP Firewall Golden Path

For a pilot-ready local/offline walkthrough of pre-execution authorization,
signed warrants, replayable Ledger records, and evidence-pack verification, run:

```bash
uv run velvet mcp-firewall pilot --output-dir reports/mcp_firewall --verify-after-run
uv run velvet mcp-firewall verify --output-dir reports/mcp_firewall
uv run velvet mcp-firewall report --output-dir reports/mcp_firewall
```

## What It Enforces

- `tools/list`: upstream tools are canonicalized, schema-hashed, classified,
  and filtered before the downstream client sees them.
- `tools/call`: Velvet computes request, policy, argument, and tool-schema
  hashes, emits an OAP Decision plus a Velvet-signed Max-DE Certificate
  Envelope, appends a pre-execution Ledger record, then forwards only
  `execute` decisions.
- Unknown, drifted, blocked, hidden, deprecated, invalid, or unapproved
  destructive tools fail closed.
- Escalated calls are not forwarded until a bound approval receipt is supplied.
- `resources/*`, `prompts/*`, `tasks/*`, non-lifecycle notifications, and
  unknown methods resolve to explicit recorded dispositions. Strict mode blocks
  them unless the deployment opts into recorded passthrough.

## Proof Model

Each enforced tool call emits:

- OAP Decision plus Velvet-signed Max-DE Certificate Envelope.
- Hash-chained two-record Ledger entry for forwarded calls.
- `upstream_execution_status`: `forwarded`, `failed`, `not_forwarded`, or
  `pending_approval`.
- Redaction summary without raw secrets, access tokens, API keys, or sensitive
  arguments.

The Python verifier accepts Rust proxy output:

```bash
uv run velvet ledger verify --ledger reports/mcp_proxy/velvet_ledger.vledger --json
```

## Safe Defaults

Production strict mode is the default. Missing or invalid policy, schema drift,
unknown tools, invalid approval receipts, oversized requests, authorization
failures, and strict Ledger write failures fail closed.

Deferred surfaces: hosted control plane, semantic content enforcement for
resources/prompts, OpenTelemetry export wiring, and hosted key custody are not
implemented in this scoped gateway.
