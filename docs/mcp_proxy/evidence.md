# MCP Proxy Evidence

Velvet evidence is designed to prove whether a tool call was forwarded,
blocked, failed after forwarding, or held pending approval. Bounded non-tool
methods are also recorded with their explicit disposition before any forwarding
decision.

## OAP Decision And Velvet Envelope

For `tools/call`, the external MCP proxy proof artifact is an OAP Decision plus a Velvet-signed Max-DE Certificate Envelope. The envelope binds:

- hashed tenant, environment, subject, agent, session, and request identifiers;
- tool key, MCP server, MCP tool, risk class, schema hash, and argument hash;
- policy hash and policy version;
- approval request binding when escalation is required;
- Decision payload digest, signed Decision digest, Decision signature hash, Passport digest, and envelope digest.

## Ledger

The proxy appends Velvet Ledger JSONL records with:

- sequence number and previous-record hash;
- OAP Decision, OAP Passport, explicit Decision digest fields, Max-DE envelope digest, and action-binding metadata for `tools/call`;
- request hash, argument hash, tool-schema hash, and policy hash;
- `upstream_execution_status`;
- redaction summary;
- optional upstream response hash.
- bounded-method disposition records for resources, prompts, tasks,
  non-lifecycle notifications, and unknown methods.

Strict production mode fails closed if the Ledger cannot be written.

## Replay And Verification

Run:

```bash
uv run velvet mcp demo run --output-dir reports/mcp_proxy --json
uv run velvet ledger verify --ledger reports/mcp_proxy/velvet_ledger.vledger --json
```

The demo writes `evidence_pack.json`, `inventory.json`,
`approval_requests.jsonl`, `mcp_thread.jsonl`, and
`velvet_ledger.vledger`.

## Approval Workbench Trail

The local approval workbench writes approval requests and signed receipts to the
configured approvals JSON file. Evidence packs include that snapshot, summarize
pending, approved, denied, expired, redeemed, and invalid receipt counts, and
link approval request/receipt ids into the incident timeline when they can be
matched to Ledger seals.

Receipt findings flag detectable problems such as malformed signatures, binding
mismatches, duplicate receipt ids, expired receipts, and orphaned receipts. A
redeemed receipt is reported as redeemed through `used_at`; replay attempts are
rejected by the approval store/proxy rather than creating a second valid use.
