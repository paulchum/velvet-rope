# Velvet Warrant Schema

Route: `/warrant-schema`

## Hero

A Velvet warrant is the pre-execution receipt for an agent action.

It binds the proposed action to the evidence that justified the decision:
request hash, policy hash, tool schema hash, arguments hash, approval state,
budget context, issuer, expiration, seal, ledger linkage, and signature
metadata.

## Canonical Schema

- [`../../schemas/velvet_rope/warrant.schema.json`](../../schemas/velvet_rope/warrant.schema.json)

## Minimum Mental Model

Every consequential agent action should answer:

1. What exact action was proposed?
2. Which tool schema and arguments were bound?
3. Which policy version judged it?
4. Was human approval required or attached?
5. What budget or scarcity state mattered?
6. Which seal lets the decision be replayed?
7. Can an independent reviewer verify the artifact?

## Developer CTA

Generate a warrant through the launch demo:

```bash
uv run velvet launch-demo --output-dir reports/launch
```

Then verify a warrant or ledger record:

```bash
uv run velvet verify-warrant \
  --file warrant-or-ledger-record.json \
  --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub \
  --json
```

## Badge Copy

Use these labels only when the evidence exists:

- `Warranted`: a pre-execution warrant is emitted.
- `Replayable`: the decision can be replayed to a stable seal.
- `Publicly Verifiable`: Ed25519 verification works with public key material.
- `Tamper-Evident`: field mutation is detected by verification or ledger checks.

## CTA

Add warrant emission to one consequential action path, then submit it to the
Agent Authorization Benchmark.
