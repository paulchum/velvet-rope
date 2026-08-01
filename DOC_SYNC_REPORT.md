# Velvet Documentation Sync Report

Date: 2026-06-13.

## What Changed

- Reframed `README.md` around Gate, Vault, Assurance, and Certified Actions.
- Replaced stale implementation and test summaries with current verified status.
- Added `DOC_SYNC_INVENTORY.md` as the claim-to-code evidence map.
- Updated investor one-pager, deck, claim boundaries, demo script, Ann brief, and email draft to match verified code.
- Updated diligence and investor indexes to link Vault, compliance, Assurance, and live-demo boundary docs.
- Preserved the adversarial diligence report without softening it.

## Work-Order Status

| Work order | Verified status | Notes |
| --- | --- | --- |
| Proxy decomposition | Implemented | `crates/velvet-rope-proxy/` is decomposed by config, transport, enforcement, ledger, OAP, policy bundle, inventory, and approvals. Rust proxy tests passed. |
| Evidence Vault | Implemented local evidence plane | Merkle proofs, Signed Tree Heads, anchors, retention tombstones, recording modes, and offline verifier exist. Production anchoring/storage operations remain operator work. |
| Article 12 attestation-pack generator | Implemented technical capability | `velvet attestation-pack` exists and is tested. Docs state it is relevant technical record-keeping evidence, not a legal conclusion. |
| Insurer-facing Assurance API | Partial | Aggregate signed control-state attestations, JSONL export, scheduled issuance, claims-pack integration, and offline verifier SDK exist. No hosted insurer API or carrier integration exists. |
| Live drift-rejection demo | Code present, run blocked by environment | `make live-demo` exists with Docker/Postgres target, attack scripts, incident bundle, and offline verifier. This sync could not run it because Docker daemon was unavailable. |

## Explicit Gaps

- No hosted shared-tenant platform.
- No hosted insurer API.
- No carrier integration, coverage decision workflow, or pricing-effect evidence.
- No enterprise policy authoring UI.
- No production arbitrary-code execution boundary.
- No legal compliance determination.
- Claims Pack is not invoked by `make live-demo` because the Rust proxy demo flow does not emit the Velvet Signed Tree Head required by `velvet claims-pack`.

## Captured Verification Output

| Command | Result |
| --- | --- |
| `uv run pytest` | Pass, `350 passed, 7 skipped in 53.73s`, coverage total `82%`. |
| `uv run ruff check .` | Pass, `All checks passed!`. |
| `uv run mypy src tests` | Pass, `Success: no issues found in 147 source files`. |
| `cargo test --workspace` | Pass, including `99 passed` in `velvet-rope-proxy`. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass. |
| `cargo fmt --check` | Pass, no output. |
| `uv run velvet --help` | Pass, command surface confirmed. |
| `make live-demo` | Failed before execution: Docker daemon unavailable. |

## Validation

- `scripts/check-doc-links.sh`: pass, `Markdown link check passed.`
- `scripts/check-investor-cleanliness.sh`: pass, `Investor cleanliness check passed.`
- Targeted banned-language scan over edited Markdown: pass, no matches.
- Targeted em-dash scan over edited Markdown: pass, no matches.
- `git diff --check`: pass, no output.
