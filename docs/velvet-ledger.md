# Velvet Ledger

Velvet Ledger is the hash-chained audit trail for admission decisions, Warrants,
Execution Permits, dispatch claims, and Execution Receipts. It links each
recorded action to a warrant or proof-envelope hash, request hash, policy hash,
tool schema hash, admission outcome, permit hash, dispatch-claim record hash,
execution receipt hash, upstream observation status, sequence number, previous
record hash, and canonical record hash. The ledger is tamper-evident under
checkpoint/manifest assumptions when auditors retain the segment manifest
outside the ledger segment.

Warrants and Velvet Ledger records are signed with Ed25519 signature records
(`velvet.signature.v2`) over the existing canonical payload hashes. A third
party can verify a warrant or sealed ledger record with only the published
Ed25519 public key; no shared secret is required.

Production signing is fail-closed: set `VELVET_SIGNING_PRIVATE_KEY` or
`VELVET_SIGNING_PRIVATE_KEY_FILE`. Demo runs may explicitly use the committed
throwaway key with `VELVET_SIGNING_PROFILE=demo`; HMAC is retained only for
local development and historical `velvet.signature.v1` verification, and must
not be used for production.

Run the launch workflow:

```bash
uv run velvet launch-demo --output-dir reports/launch
```

Inspect the ledger:

```bash
uv run velvet ledger \
  --ledger reports/launch/velvet_ledger.vledger \
  --thread reports/launch/mcp_thread.jsonl
```

Verify the hash chain:

```bash
uv run velvet ledger verify \
  --ledger reports/launch/velvet_ledger.vledger \
  --json
```

Verify against an externally retained segment manifest/checkpoint:

```bash
uv run velvet ledger verify \
  --ledger reports/launch/velvet_ledger.vledger \
  --manifest reports/launch/ledger_segment_manifest.json \
  --json
```

Segment manifests bind the first and last sequence numbers, first and last
record hashes, record count, and ordered segment hash. With a retained manifest,
Velvet detects modification, replacement, insertion, deletion inside the
checkpointed segment, and reordering. A local hash chain without an external
manifest does not detect tail truncation after the latest unpublished
checkpoint, and fork/equivocation detection needs a transparency log,
checkpoint gossip, remote witness, or equivalent external publication.

Ledger integrity is evidence of preservation, not a claim that the underlying
decision was correct, policy-safe, or budget-compliant.

## Execution Ordering

The execution lineage is intentionally acyclic:

1. admission decision artifact;
2. durable pre-execution decision record;
3. Execution Permit referencing the decision and pre-execution record;
4. durable dispatch-claim record referencing the permit;
5. Execution Receipt and post-execution observation referencing the claim and
   permit.

The pre-execution record does not hash the permit, because the permit has not
been created yet. If the dispatch-claim record cannot be appended or atomically
claimed, the side effect is not forwarded. If the runtime crashes after claim
but before a conclusive receipt, the ledger must expose an incomplete or
indeterminate execution state rather than treating the permit as unused.

Verify a signed warrant or ledger record with a public key:

```bash
uv run velvet verify-warrant \
  --file reports/launch/velvet_ledger.vledger \
  --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub \
  --json
```

Replay a sealed decision:

```bash
uv run velvet replay \
  --thread reports/launch/mcp_thread.jsonl \
  --seal-id <seal_id> \
  --policies-dir examples/mcp/policies \
  --chain mcp_demo
```

Validate thread shape:

```bash
uv run velvet validate-thread --thread reports/launch/mcp_thread.jsonl
```

Pre-routing Velvet MCP denials do not have Rust schema `9.0` thread records because they are denied before routing. They still have ledger records, manual seals, and list jurisdiction evidence.
