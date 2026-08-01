# Velvet Assurance Verifier

This is the offline verifier package for Velvet control-state attestations.

Inputs:

- `attestations.jsonl`: signed aggregate attestation envelopes.
- deployment public key: Ed25519 PEM or raw base64.
- optional `consistency_proofs.json`: Merkle consistency proofs supplied by the insured or by your own retained anchors.
- optional `anchor_sths.json`: tree-head summaries you retained independently.

The verifier checks signatures, schema version, period continuity, STH tree growth, Merkle consistency proofs when supplied, and whether claimed decision counts fit within tree growth. It does not need network access and does not receive customer prompts, tool names, action arguments, identities, or per-action records.

Run from a cold directory:

```bash
python verify_attestations.py /path/to/bundle --public-key-file deployment.pub --output report.json
```

Try the bundled sample:

```bash
python verifier/verify_attestations.py verifier/sample_bundle --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub
```

Or as a package:

```bash
velvet-assurance-verify --attestations attestations.jsonl --public-key-file deployment.pub --consistency-proofs consistency_proofs.json --anchor-sths anchor_sths.json --json
```

Report status is `pass` only when every fail-closed check succeeds. Unknown attestation schema versions, invalid signatures, period gaps, tree shrinkage, invalid consistency proofs, and decision counts that exceed tree growth fail the report.

The single-file JavaScript verifier exports `verifyAttestationSeries(attestations,
publicKey, { consistencyProofs, anchoredSths })` for Node or modern browsers. It
performs the same offline checks as the Python verifier and makes no network
calls.
