# OpenAI Secure MCP Tunnel Example

This example places Velvet between the tunnel client and the private MCP server:

```text
OpenAI product -> OpenAI-hosted tunnel -> tunnel-client -> Velvet -> private MCP server
```

The tunnel provides reachability into the customer network. Velvet remains the pre-execution authorization and proof boundary.
Velvet's upstream Streamable HTTP connection to the private MCP server uses
HTTPS by default; only loopback development endpoints may opt into plaintext.
The private MCP server must require Velvet's upstream-only bearer credential and
mTLS client identity.

Files:

- `velvet-config.yaml`: Velvet proxy config with Secure MCP Tunnel transport metadata enabled.
- `kubernetes-sidecar.yaml`: tunnel client and Velvet in one pod. Containers in
  the pod share a network namespace, so private MCP bearer+mTLS enforcement is
  required.
- `kubernetes-gateway.yaml`: tunnel client, Velvet service, private MCP service,
  and NetworkPolicies that block direct tunnel-client to private-MCP paths.
- `docker-compose.yaml`: local two-network topology for validation.
- `systemd/`: VM service units and environment template.

Set these environment variables on the Velvet process when available:

- `VELVET_OPENAI_TUNNEL_ID`
- `VELVET_OPENAI_WORKSPACE_ID`
- `VELVET_CONNECTOR_SUBJECT`
- `VELVET_PRIVATE_MCP_UPSTREAM_TOKEN`
- `VELVET_PRIVATE_MCP_CLIENT_IDENTITY_PEM`
- `VELVET_PRIVATE_MCP_CA_BUNDLE_PEM`

Velvet hashes those values before adding them to the signed Max-DE envelope or ledger.
The private MCP upstream token and client identity are not forwarded from the
agent or tunnel client; Velvet injects them only on its private upstream leg.
