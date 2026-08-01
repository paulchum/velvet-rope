# Velvet Rope Proxy Example

This directory contains a deterministic fake MCP server/client flow for the
Rust `velvet-rope-proxy` enforcement gateway.

Run from the repository root:

```bash
cargo run -p velvet-rope-proxy -- --config examples/mcp_proxy/config.yaml
uv run velvet mcp demo run --output-dir reports/mcp_proxy --json
```

The example writes:

- `reports/mcp_proxy/inventory.json`
- `reports/mcp_proxy/mcp_thread.jsonl`
- `reports/mcp_proxy/velvet_ledger_v2.jsonl`
- `reports/mcp_proxy/approval_requests.jsonl`
- `reports/mcp_proxy/evidence_pack.json`
- `reports/mcp_proxy/mcp_proxy_summary.json`

The fake flow admits a safe read, escalates a sensitive write, denies an
unapproved destructive tool, and denies an unknown tool before fake server
execution.

Verify the Ledger:

```bash
uv run velvet ledger verify --ledger reports/mcp_proxy/velvet_ledger_v2.jsonl --json
```
