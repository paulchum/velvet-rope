# Velvet Evidence Vault

The evidence vault extends the Velvet binary ledger into a third-party-verifiable
evidence package. The claim is tamper-evident preservation under the stated
hash-chain, signature, Merkle, and external-anchor hypotheses. It is not an
impossible-to-alter storage claim.

## Artifacts

- Binary ledger segment: existing `.vledger` framed binary ledger. Each frame
  has a frame hash and provider signature. Each semantic record has
  `sequence_number`, `previous_record_hash`, `record_hash`, and a signature over
  `record_hash`.
- Merkle tree: RFC 6962-style tree over ledger `record_hash` values in append
  order. The leaf value is the raw 32-byte digest represented by
  `sha256:<hex>`. Leaf hash is `SHA256(0x00 || leaf)`. Interior hash is
  `SHA256(0x01 || left || right)`.
- Inclusion proof: `velvet.vault.merkle_inclusion_proof.v1`, with
  `tree_size`, `leaf_index`, `leaf_hash`, and `proof` as ordered
  `sha256:<hex>` sibling hashes.
- Consistency proof: `velvet.vault.merkle_consistency_proof.v1`, with old/new
  tree sizes, old/new roots, and the RFC 6962 consistency path.
- Signed Tree Head: `velvet.vault.sth.v1`, with `tree_size`, `root_hash`,
  `ledger_segment`, `timestamp`, `policy_hash`, `sth_hash`, and a Velvet
  SignatureBlock. The signature purpose is `velvet.vault.sth.v1`.
- Anchor receipt: `velvet.vault.anchor_receipt.v1`, recording anchor type,
  `sth_hash`, status, location, and successful anchor time when available.
- Retention tombstone: `velvet.vault.tombstone.v1`, appended to the live ledger
  before deleting an eligible sealed segment.

All hashed or signed JSON uses Velvet canonical serialization. Absence of a
required signature, public key, proof element, checkpoint, or anchor receipt is
a verification failure.

## Third-Party Verification

A verifier needs only:

- the ledger segment artifact,
- the STH JSON file,
- the operator public key,
- optional previous STH for consistency checking.

Run:

```bash
velvet vault verify \
  --segment 1-100 \
  --sth sth.json \
  --ledger segment.vledger \
  --public-key-file operator.pub \
  --json
```

The verifier:

- parses binary frames and recomputes frame hashes,
- verifies frame signatures with the supplied public key,
- recomputes each ledger record hash and semantic chain link,
- verifies each record signature,
- recomputes the Merkle root over ordered record hashes,
- verifies generated inclusion proofs for every record,
- verifies the STH signature,
- checks that STH segment bounds match the requested segment,
- optionally checks consistency between a previous STH and the current STH.

The browser verifier at `docs/public/velvet-verifier.html` also verifies a
single decision record against an STH and inclusion proof entirely client-side.
It makes no network calls.

## Anchoring

Anchoring publishes a signed STH outside the operator's integrity boundary.

- `FileAnchor` writes canonical STH JSON once to a configured path or directory.
  Existing identical content is accepted. Existing conflicting content fails.
- `WebhookAnchor` POSTs canonical STH JSON to a configured URL. Failures are
  retried and then durably spooled.
- `StdoutAnchor` emits canonical STH JSON for manual air-gapped export.

Admission decisions do not block on anchoring. Anchor failures mark vault status
degraded and must be surfaced in attestations as last successful anchor time.

## Retention

The named preset `eu_ai_act_minimum` retains sealed segments for 183 days.
Deletion is fail-closed:

- only sealed segments older than the horizon are eligible,
- the covering STH must verify,
- the covering STH must exactly name the segment range in v1,
- a successful anchor receipt for the STH must exist,
- a signed tombstone is appended to the live ledger before deletion.

If any check fails, the segment is not deleted.

## Recording Modes

Field recording policies apply to action arguments and tool results.

- `hash_only`: stores plaintext SHA-256 and canonical byte length only.
- `encrypted_body`: stores ciphertext returned by an injected envelope
  encryption provider, plus plaintext SHA-256 and canonical byte length.
- `plaintext`: stores plaintext only for fields explicitly opted in by policy.

The decision record always binds plaintext hashes and lengths, so replay and
drift checks are independent of the storage mode.

## Theorem Mapping

- H1, stable canonicalization: ledger records, STH payloads, proofs, anchor
  receipts, and tombstones use Velvet canonical bytes for hashing/signing.
- H2, collision-resistant hashing: record hashes, frame hashes, Merkle leaves,
  Merkle nodes, STH hashes, and anchor receipt hashes use SHA-256.
- H3, valid signatures where required: record, frame, STH, checkpoint, and
  tombstone verification fail closed on missing or invalid signatures.
- H4, external checkpoint retention: STH anchoring makes retaining checkpoints
  outside the ledger editor's integrity boundary cheap. A verifier compares the
  candidate segment against the externally anchored STH.

Limits remain the same as the theorem: an unpublished tail, unobserved fork, or
semantic policy error is outside the evidence vault's integrity claim.
