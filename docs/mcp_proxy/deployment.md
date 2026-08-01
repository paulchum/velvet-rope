# MCP Proxy Deployment

## Local

```bash
cargo run -p velvet-rope-proxy -- --config examples/mcp_proxy/config.yaml
uv run velvet mcp demo run --output-dir reports/mcp_proxy --json
```

## Staging And Production

Use strict mode, explicit tenant/environment identity, bounded request and
response sizes, bearer-token auth for HTTP, TLS or mTLS at the ingress,
HTTPS to the upstream Streamable HTTP MCP server, and a durable Ledger sink.

Required production settings:

- `mode: strict`
- `ledger.strict: true`
- `ledger.fsync: true` for local file sinks
- no wildcard allow-all tools
- explicit policy bundle manifest
- `policy.require_signature: true` with exactly one trusted bundle signing
  public key, preferably `policy.trusted_signature_public_key_hex_env`
- explicit upstream server identity
- `transport: streamable_http` upstream endpoints must use `https://` in
  production
- `upstream.boundary.required: true` with both upstream bearer and mTLS for
  private MCP servers
- `http.allow_plaintext_loopback_upstream: false`
- request, response, argument, and concurrency limits
- explicit `method_dispositions` for any bounded method that should be
  recorded and passed through
- one writer for local JSONL Ledgers; run one replica unless the Ledger sink is
  replaced by a durable single-writer or transactional backend
- `auth.trust_subject_header: false` unless a trusted ingress overwrites the
  configured subject header; downstream-supplied subject headers are ignored by
  default
- no secret values in config files

Strict mode blocks `resources/*`, `prompts/*`, `tasks/*`, non-lifecycle
notifications, and unknown methods unless the deployment opts into recorded
passthrough. The full boundary is in
[`SURFACE_MATRIX.md`](SURFACE_MATRIX.md).

The sample Kubernetes deployment defaults to one replica because local JSONL
Ledger writes are serialized inside a process, not across multiple pods. Scale
out only after moving Ledger persistence to a backend with transactional
sequence allocation and one-time approval receipt replay checks.

## Streamable HTTP TLS Readiness

The proxy does not pin upstream TLS leaf, intermediate, or root certificates
and does not ship a custom Google-only trust store. It uses the platform trust
store through `reqwest`/rustls, with TLS 1.2 or newer and SNI enabled.

For local integration tests only, `http://localhost`, `http://127.0.0.1`, and
`http://[::1]` upstreams can be enabled with:

```yaml
http:
  allow_plaintext_loopback_upstream: true
```

Before June 15, 2026, rebuild production images with a current CA bundle and
run the TLS readiness check from the same image or host:

```bash
velvet-rope-proxy tls-check --url https://www.googleapis.com/discovery/v1/apis
```

If a deployment sets `SSL_CERT_FILE` or `SSL_CERT_DIR`, keep that trust store
synced with Google's published roots at <https://pki.goog/roots.pem>. Do not
pin Google leaf or intermediate certificates. Google documents that Google
certificate chains are not static and clients must handle both RSA and ECDSA
certificates: <https://pki.goog/faq/>.

## HTTP Health

- `GET /healthz`: process liveness.
- `GET /livez`: process liveness alias.
- `GET /readyz`: policy and inventory readiness summary.

## Secrets

For HTTP bearer validation, configure:

```yaml
auth:
  require_bearer: true
  bearer_token_env: VELVET_MCP_PROXY_TOKEN
  forward_authorization: false
  trust_subject_header: false
```

The proxy never writes authorization headers to signed envelopes, Ledger records, logs,
or evidence packs. For stdio upstreams, environment variables belong to the
upstream process credential boundary and must be supplied by the launcher or
secret manager.

For private MCP upstreams, configure a separate upstream-only credential and
client identity:

```yaml
upstream:
  boundary:
    required: true
    require_bearer: true
    require_mtls: true
    bearer:
      header_name: Authorization
      scheme: Bearer
      token_env: VELVET_PRIVATE_MCP_UPSTREAM_TOKEN
    mtls:
      identity_pem_env: VELVET_PRIVATE_MCP_CLIENT_IDENTITY_PEM
      ca_bundle_pem_env: VELVET_PRIVATE_MCP_CA_BUNDLE_PEM
```

This credential is injected only on Velvet's upstream leg after the proxy has
admitted the request. Do not set `auth.forward_authorization: true` with
upstream private bearer auth; downstream agent credentials must not become
private MCP authority.
