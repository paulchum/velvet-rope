# Reconstructability Harness

This bundle demonstrates technical record-keeping capability relevant to EU AI Act Article 12. It is not a determination of legal compliance, which depends on system classification, deployment context, and counsel review.

The launch harness is `scripts/reconstructability_test.py`. It generates three local corpora and scores whether an independent verifier can mechanically answer four questions:

1. Is the record set complete and unmodified for the selected window?
2. Can each decision be re-derived from recorded inputs?
3. Does a seeded single-field mutation get detected?
4. Can the verifier confirm the admitted action did not drift before dispatch?

## Corpora

| Corpus | Format | Purpose |
| --- | --- | --- |
| Velvet vault | Binary ledger, decision records, STH | Shows signed records, Merkle coverage, replay bindings, and action-hash evidence. |
| Plain JSONL gateway log | Structured JSONL | Represents a common gateway log with useful fields but no signed root or inclusion proof. |
| Unstructured application logs | Text log lines | Represents operational logs that humans can inspect but machines cannot reliably replay. |

## Current Reproducible Results

Run:

```bash
uv run python scripts/reconstructability_test.py --output-dir reports/compliance/reconstructability --json
```

Expected scoring pattern:

| Corpus | Complete and unmodified | Re-derive decisions | Detect mutation | No admitted-action drift | Score |
| --- | --- | --- | --- | --- | ---: |
| Velvet vault | yes | yes | yes | yes | 4/4 |
| Plain JSONL gateway log | no | yes | no | no | 1/4 |
| Unstructured application logs | no | no | no | no | 0/4 |

The table is produced by code, not hand-edited marketing copy. If the corpus or verifier changes, rerun the command and update the generated `results.json` / `results.md`.

## Interpretation

The Velvet row passes because the verifier can check signed ledger records, the STH, record hashes, and action/input bindings. The JSONL row can replay a simple policy but cannot prove completeness or detect a mutation without an external integrity mechanism. The text-log row is useful for incident narrative, but it lacks the structure needed for deterministic replay.
