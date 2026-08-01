# MCP Proxy Security

Scope: `crates/velvet-rope-proxy`, `schemas/velvet_rope`, and the MCP proxy
CLI/demo path. Assumption: production deployments put the proxy between
agent-connected MCP clients and internal MCP servers.

## Trust Boundaries

- Downstream MCP client to Velvet: untrusted JSON-RPC over stdio or HTTP.
- Velvet to upstream MCP server: trusted only after policy, schema, and proof
  checks complete.
- Policy bundle and tool registry to Velvet: integrity-critical local inputs.
- Velvet to Ledger sink: durability-critical audit boundary.
- Approval receipt to Velvet: privileged authorization artifact.

## Assets

Policy bundles, tool registry hashes, approval receipts, access tokens,
stdio environment credentials, Decision and envelope hashes, Ledger hash chains, tool
schemas, tenant/environment identity, and upstream execution state.

## Threats And Mitigations

| Threat | Impact | Mitigation |
|---|---|---|
| Malicious MCP client calls unknown or destructive tools | Unauthorized execution | Unknown, drifted, blocked, hidden, deprecated, and destructive-unapproved tools fail closed. |
| Schema drift or compromised tool metadata | Policy bypass | `tools/list` computes stable schema hashes and marks mismatches `drifted`. |
| JSON-RPC spoofing or ID confusion | Incorrect response binding | IDs are preserved; Streamable HTTP accepts only single JSON-RPC messages, downstream response POSTs must match and consume a pending server request ID, and stdio batch compatibility omits notification responses. |
| Browser-origin cross-site request | Unauthorized HTTP call | Configured Origin allow-lists are enforced before upstream forwarding; production examples pair `0.0.0.0` bind with bearer auth. |
| Brittle upstream TLS trust assumptions | Production outage during normal CA or certificate rotation | Streamable HTTP upstreams require HTTPS by default, use platform trust stores, do not pin Google leaf/intermediate/root certificates, and allow plaintext only for explicitly configured loopback test endpoints. |
| Session fixation or replay across streams | Cross-client message leakage | `MCP-Session-Id` values must be visible ASCII, unknown sessions fail closed, and `Last-Event-ID` replay is scoped to the matching session stream. |
| Approval replay | Privilege escalation | Receipts bind request, policy, schema, subject, tenant, environment, expiry, process memory, and persisted Ledger one-time-use state. |
| Policy bundle tampering | Policy downgrade | Bundle hash verification fails closed, and production Ed25519 verification requires a configured trusted public key rather than trusting the key embedded in the manifest. |
| Ledger tampering | Audit compromise | Velvet Ledger hash chain and verifiers detect record, order, Decision, and envelope tampering. |
| Token leakage | Credential exposure | Authorization headers are redacted and not forwarded unless explicitly configured. |
| Path or command injection in stdio launch | Local execution abuse | Upstream command and args are structured config fields; no shell interpolation is used. |
| Oversized payload DoS | Availability loss | Request, response, and argument size limits are configurable and enforced. |
| Upstream crash or timeout | Ambiguous execution | Forwarding failures record `upstream_execution_status: failed`. |
| Resource, prompt, or unknown method bypass | Undefined behavior | Non-enforced methods resolve to explicit recorded dispositions; strict mode blocks them by default. |
| Compromised agent skips receipt verification or lies in the final response | Unauthorized execution or false user assurance | Velvet verifies approval receipts at the proxy boundary before forwarding. Upstream responses and UI should rely on Velvet Ledger/proof artifacts, not the agent's natural-language claim. |
| Receipt embeds attacker-chosen public verification material | Forged approval authority | The proxy ignores receipt-embedded public keys as trust roots and verifies only against configured approval-service public keys. |
| Agent or tunnel client calls private MCP directly | Complete bypass of pre-execution authorization | Production deployments give upstream MCP credentials and mTLS client identity only to Velvet, configure private MCP to require that identity, and block direct paths with network policy/security groups/service mesh/firewall rules. |

## Non-Goals

- The proxy does not sandbox upstream MCP servers.
- The proxy does not perform semantic content enforcement for `resources/*` or
  `prompts/*` in this scoped gateway.
- Legacy SSE compatibility is not a default production transport.
- The proxy does not maintain a custom Google trust store; deployments that set
  `SSL_CERT_FILE` or `SSL_CERT_DIR` own keeping those bundles current.
- Local JSONL Ledger persistence is a single-writer backend. Multi-replica
  deployments must use a transactional Ledger sink before scaling writes.

## One-Time Approval Receipts

Approval receipts are privileged artifacts. A valid receipt is bound to the
exact tenant, environment, subject/user, agent, tool key, request hash,
arguments hash, policy hash/version, and tool schema hash that were present when
the approval request was created. Changing any of those fields invalidates the
receipt.

In strict mode, the Rust MCP proxy also requires a `velvet.signature.v2`
Ed25519 signature with purpose `velvet.approval_receipt.v1`. The signature is
verified before upstream execution against a configured approval-service public
key. Public keys carried inside the receipt are evidence only; they are not
trust roots.

Receipts also carry an expiry, nonce, and `one_time_use` flag. The local Python
approval store persists redemption with `used_at`, while the Rust proxy rejects
receipts already seen in process memory or in the Ledger. A receipt marked
`used_at` is audit evidence only; it must not authorize another upstream call.

Approval receipts are evidence of human approval. Velvet is the enforcement
boundary: a receipt can only convert a current approval/escalation/delay
decision into execution, and it cannot override block, inventory denial, schema
drift denial, Max-DE/certificate failure, signer failure, Ledger failure, or
unknown-method blocking.

## No-Bypass Upstream Boundary

For private MCP servers, Velvet must be the only caller with upstream authority.
Configure `upstream.boundary` with a Velvet-only bearer token and mTLS client
identity, and configure the private MCP server to require both. The proxy fails
closed in strict OpenAI Secure MCP Tunnel mode if that upstream boundary is not
configured.

Network controls must also prevent direct agent or tunnel-client paths to the
private MCP server. Kubernetes examples use NetworkPolicy to permit
tunnel-client egress only to Velvet and private-MCP ingress only from Velvet.
Docker Compose examples keep tunnel-client off the private MCP network.

The local approval workbench requires bearer-token authentication and CSRF
protection for decision routes. Serve it with `--auth-token-env` and
`--csrf-secret-env`. The development-only `--local-dev-no-auth` flag is limited
to loopback hosts and must not be exposed on a network interface.
