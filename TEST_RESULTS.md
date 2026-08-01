# Velvet Test Results

Verification run: `2026-06-13 14:26:41 PDT`

Working directory: `<workspace>`

## Environment

- `uv run python --version`: `Python 3.12.12`
- `uv --version`: `uv 0.9.21 (0dc9556ad 2025-12-30)`
- `rustc --version`: `rustc 1.95.0 (59807616e 2026-04-14)`
- `cargo --version`: `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- `docker info --format '{{.ServerVersion}}'`: `28.5.1`

## Required Commands

| Command | Exit | Exact result line or terminal output |
| --- | ---: | --- |
| `uv run pytest tests/test_vault.py tests/test_attestation.py tests/test_assurance_attestation.py` | 0 | `26 passed in 4.78s`; coverage total line reported `TOTAL 17266 9812 43%`. |
| `cargo test -p velvet-rope-proxy` | 0 | Proxy crate reported `99 passed; 0 failed`; binary and doc tests reported `0 passed; 0 failed`. |
| `uv run velvet --help` | 0 | Help output lists `vault verify`, `attestation-pack`, `assurance issue-attestation`, `assurance issue-scheduled`, `claims-pack`, `mcp demo run`, `mcp conformance`, and `mcp benchmark`. |
| `docker info --format '{{.ServerVersion}}'` | 0 | `28.5.1` |
| `make live-demo` | 0 | Attack suite reported six passing attacks; incident summary reported `status: pass`, Claims Pack primary artifact, Vault verification `pass`, segment `1-2`, and Assurance verification `pass`. |
| `uv run pytest` | 0 | `356 passed, 7 skipped in 54.53s`; coverage total line reported `TOTAL 17266 3103 82%`. |
| `uv run ruff check .` | 0 | `All checks passed!` |
| `uv run mypy src tests` | 0 | `Success: no issues found in 148 source files` |
| `cargo test --workspace` | 0 | Workspace completed successfully; proxy crate reported `99 passed; 0 failed`; doc tests reported `0 passed; 0 failed` for each crate. |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | `Finished dev profile [unoptimized + debuginfo] target(s) in 0.53s` |
| `cargo fmt --check` | 0 | No output. |
| `scripts/check-doc-links.sh` | 0 | `Markdown link check passed.` |
| `scripts/check-investor-cleanliness.sh` | 0 | `Checking historical product-name references...`; `Checking stale canonical doc references...`; `Investor cleanliness check passed.` |
| `uv run python scripts/check-claim-language.py` | 0 | `Claim language check passed.` |
| `git diff --check` | 0 | No output. |

## Live Demo Incident Artifacts

The final `make live-demo` run wrote:

- Primary artifact: `<workspace>/reports/live-demo/incident/claims_pack`
- Claims Pack result: `<workspace>/reports/live-demo/incident/claims_pack.result.json`
- Derived Vault ledger: `<workspace>/reports/live-demo/incident/vault/argument_drift.vledger`
- Signed Tree Head: `<workspace>/reports/live-demo/incident/vault/signed_tree_head.json`
- Vault public key: `<workspace>/reports/live-demo/incident/vault/vault_public_key.pem`
- Bridge manifest: `<workspace>/reports/live-demo/incident/vault/bridge_manifest.json`
- Vault verification report: `<workspace>/reports/live-demo/incident/vault/vault_verification_report.json`
- Offline verification report: `<workspace>/reports/live-demo/incident/offline_verification_report.json`

Incident window from the final run:

- Start: `2026-06-13T21:26:30.958571Z`
- End: `2026-06-13T21:26:31.015993Z`

The derived Vault segment was `1-2`, and `reports/live-demo/incident/incident.summary.json` reported `status: pass`, `vault.verification_status: pass`, and `claims_pack.assurance_verification_status: pass`.

## Notes

- Docker was available for this run.
- The live-demo Vault ledger/STH are derived demo evidence artifacts for Vault and Claims Pack verification. The original Rust proxy ledger remains preserved separately in the live-demo reports and forensic bundle.
