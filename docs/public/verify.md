# Verify A Velvet Warrant

Route: `/verify`

## Hero

Do not trust an agent-action receipt because Velvet says so. Verify it with
public key material.

Velvet warrants and selected ledger records can be checked without the private
signing key. That is the point: a security reviewer, buyer, auditor, or
developer should be able to inspect whether an action warrant still matches the
signed payload.

## Browser Verifier

Use the local verifier command when reviewing a warrant or compatible ledger
record with published Ed25519 public key material. The verifier reports whether
the signature and artifact shape pass.

## CLI Verifier

```bash
uv run velvet verify-warrant \
  --file warrant-or-ledger-record.json \
  --public-key-file published_ed25519.pub \
  --json
```

For deterministic local demos, the committed public demo key is:

- [`../../tests/fixtures/keys/velvet_demo_ed25519.pub`](../../tests/fixtures/keys/velvet_demo_ed25519.pub)

That key is explicitly demo-only and not for production signing.

## Generate A Demo Warrant Trail

```bash
uv run velvet launch-demo --output-dir reports/launch
uv run velvet ledger \
  --ledger reports/launch/velvet_ledger.vledger \
  --thread reports/launch/mcp_thread.jsonl
```

The launch demo admits a safe read-only MCP action, blocks an unlisted
destructive MCP action before execution, and escalates a sensitive listed
production action.

## What A Warrant Binds

The public schema is:

- [`../../schemas/velvet_rope/warrant.schema.json`](../../schemas/velvet_rope/warrant.schema.json)

The warrant binds the action surface and evidence fields that matter before
execution: request hash, policy hash, tool schema hash, arguments hash, decision,
reason codes, approval state, issuer, expiration, seal/thread linkage, and
signature metadata.

## CTA

Generate a warrant, verify it locally, then try changing one field. If a
downstream reviewer cannot detect tampering, the artifact is not strong enough
for consequential agent action.
