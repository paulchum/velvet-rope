# MCP Proxy Operations

## Approval Workbench

Run the pilot approval workbench against a local approvals file:

```bash
export VELVET_APPROVAL_WORKBENCH_TOKEN='replace-me'
export VELVET_APPROVAL_WORKBENCH_CSRF='replace-me'
uv run velvet approvals serve \
  --approvals reports/mcp_firewall/mcp_firewall_approvals.json \
  --host 127.0.0.1 \
  --port 8765 \
  --auth-token-env VELVET_APPROVAL_WORKBENCH_TOKEN \
  --csrf-secret-env VELVET_APPROVAL_WORKBENCH_CSRF
```

Open `http://127.0.0.1:8765/approvals` to review pending requests. The
workbench lists the request id, tool key, decision reason, risk class,
requester/user/agent, request hash, arguments hash, policy hash/version, tool
schema hash, expiry, redacted request JSON, and approve/deny forms.

The workbench is intentionally no-build and server-rendered with Starlette. It
adds no npm, React, Vite, or browser-side JavaScript supply chain.

For throwaway local development only, `--local-dev-no-auth` can be used on
loopback hosts. Do not bind an unauthenticated workbench to `0.0.0.0` or expose
it through a tunnel.

Approval receipts are one-time artifacts. After a receipt is redeemed, the local
store persists `used_at`; future redemption attempts for the same receipt id fail.

## Runbooks

Policy validation failure:

1. Keep the last valid policy active.
2. Reject new invalid bundles.
3. Check bundle hash, expiry, tenant, environment, and signature.

Ledger write failure in strict mode:

1. Treat as a production incident.
2. Stop forwarding protected tool calls.
3. Check disk space, file permissions, sink availability, and segment manifest.
4. Run `uv run velvet ledger verify`.

Schema drift:

1. Confirm upstream `tools/list` changed.
2. Review the tool schema and policy disposition.
3. Update registry hash only after review.
4. Re-run conformance and demo flows.

TLS trust-store rotation:

1. Rebuild the proxy image so `ca-certificates` is current.
2. Confirm no deployment pins Google leaf or intermediate certificates.
3. If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, sync it with
   <https://pki.goog/roots.pem>.
4. Run `velvet-rope-proxy tls-check --url https://www.googleapis.com/discovery/v1/apis`
   from the deployed image or host.
5. Treat TLS check failures as a production readiness blocker before
   June 15, 2026.

## Metrics To Alert On

- policy validation failures
- OAP Decision or Max-DE envelope emission failures
- Ledger write failures
- unknown tool events
- bounded method block, escalation, and passthrough events
- schema drift events
- blocked and escalated call rates
- upstream timeout and failure rates
- TLS readiness check failures
- request size rejections
- auth failures
- p95 and p99 proxy latency

## Benchmark

```bash
uv run velvet mcp benchmark --output-dir reports/mcp_proxy/benchmark --iterations 1000 --json
```

The benchmark reports p50, p95, p99, max, throughput, cold start, registry size,
payload size, and explicit machine/configuration notes. CPU and memory are
reported as not measured unless an external profiler is used.
