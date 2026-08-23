# Velvet Documentation Sync Inventory

Generated: 2026-06-13. Incrementally updated: 2026-08-23.

This inventory is the claim source for the docs-sync pass. Capability statements in the updated docs should map to a row below. If a capability is partial, environment-dependent, or absent, docs must say so directly.

## Verification Run

| Command | Result |
| --- | --- |
| `uv run pytest` | Pass, `356 passed, 7 skipped in 54.53s`, coverage total `82%`. |
| `uv run ruff check .` | Pass, `All checks passed!`. |
| `uv run mypy src tests` | Pass, `Success: no issues found in 148 source files`. |
| `cargo test --workspace` | Pass, including `99 passed` in `velvet-rope-proxy`. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass, `Finished dev profile [unoptimized + debuginfo] target(s) in 0.53s`. |
| `cargo fmt --check` | Pass, no output. |
| `scripts/check-doc-links.sh` | Pass, `Markdown link check passed.` |
| `scripts/check-investor-cleanliness.sh` | Pass, `Investor cleanliness check passed.` |
| `uv run velvet --help` | Pass, CLI help lists Vault, attestation-pack, Assurance, and claims-pack commands. |
| `docker info --format '{{.ServerVersion}}'` | Pass, Docker Server `28.5.1`. |
| `make live-demo` | Pass; six attacks passed and the incident path completed with Vault verification `pass`, Claims Pack Assurance verification `pass`, and segment `1-2`. |

### 2026-08-23 incremental verification

| Command | Result |
| --- | --- |
| `.venv/bin/ruff check` on changed Python files | Pass. |
| `pytest tests/test_product_site.py -q --no-cov` | Pass, `3 passed`. |
| isolated ShadowPath portfolio smoke test | Pass, two projects, six routes, six deliberate fixture breaches, strict exit `3`. |
| `scripts/check-claim-language.py --extra-paths site docs/strategy ...` | Pass. |
| `scripts/check_no_npm.py` | Pass. |
| Full native-extension and Rust suite | Not run in this workspace because no Rust toolchain is installed. |

## Registered CLI Surface

Confirmed in `src/velvet/cli.py` and `uv run velvet --help`:

- `route`, `run`, `rope`
- `mcp`, including `mcp demo run`, `mcp conformance`, `mcp benchmark`
- `ledger`, including `ledger validate`, `ledger verify`, `ledger tamper-demo`
- `vault verify`
- `attestation-pack`
- `assurance issue-attestation`, `assurance issue-scheduled`
- `claims-pack`
- `verify-warrant`, `signing`, `replay`, `validate-thread`, `proof hash`
- `policy-bundle`, `registry`, `gateway`, `approvals`, `evidence`, `policy-simulate`, `ops`
- `launch-demo`, `shell-code-demo`, `mcp-firewall`, `openai-bypass-demo`, `mcp-proxy-demo`
- `liability-benchmark`, `agent-auth-benchmark`, `liability-live`, `dashboard`, `vc-demo`, `investor-demo`, `investor-video-html`, `outreach-proof`, `bernoulli`
- `shadowpath demo`, `shadowpath init`, `shadowpath run --project`, `shadowpath portfolio`, `shadowpath render`

## Artifact Naming

| Surface | Code-backed nouns | Files |
| --- | --- | --- |
| Python Gate | Warrant, Seal, Ledger record, evidence pack, approval receipt | `src/velvet/rope.py`, `src/velvet/ledger.py`, `src/velvet/evidence.py`, `src/velvet/approvals.py` |
| Rust MCP proxy | OAP Decision, OAP Passport, Velvet-signed Max-DE Certificate Envelope, OAP ledger record | `crates/velvet-rope-proxy/src/oap.rs`, `crates/velvet-rope-proxy/src/ledger.rs` |
| Vault | Signed Tree Head, inclusion proof, consistency proof, anchor receipt, retention tombstone | `src/velvet/vault/` |
| Attestation | attestation pack, coverage report, manifest | `src/velvet/attestation/` |
| Assurance | control-state attestation, attestation series, consistency proofs, claims pack | `src/velvet/assurance/`, `src/velvet/cli.py`, `assurance/verifier/` |
| Live demo | attack report, incident bundle, derived Vault ledger/STH, Claims Pack, offline verification report | `demo/attacks/`, `demo/incident/` |
| ShadowPath | effect project, route result, outcome portfolio, portfolio report, share pack | `src/velvet/shadowpath_product.py`, `docs/public/outcome-portfolios.md` |

## Component Inventory

| Component | Status | Code evidence | Test or command evidence | Claim boundary |
| --- | --- | --- | --- | --- |
| Velvet Gateway, open-core admission kernel | Implemented local | `crates/velvet-core/`, `src/velvet/rope.py`, `src/velvet/router.py`, `src/velvet/types.py` | `uv run pytest`, `cargo test --workspace` | Local deterministic admission, not hosted enterprise governance. |
| Policy and pricing path | Implemented | `crates/velvet-policies/`, `crates/velvet-policy-loader/`, `src/velvet/admission.py` | `cargo test --workspace`, `uv run pytest` | Policy and pricing are implemented for local chains and demos. |
| Python warrants, seals, ledger, replay | Implemented | `src/velvet/rope.py`, `src/velvet/ledger.py`, `src/velvet/replay.py` | `tests/test_warrant.py`, `tests/test_ledger.py`, `tests/test_replay_determinism.py`, via `uv run pytest` | Use code nouns `warrant`, `seal`, and `ledger record`. |
| Proxy decomposition | Implemented | `crates/velvet-rope-proxy/src/{config,transport,enforcement,ledger,oap,inventory,approvals}.rs` | `cargo test --workspace`, 99 proxy tests; `tests/test_mcp_proxy_cli.py` | Local Rust MCP proxy, not a hosted gateway service. |
| MCP Streamable HTTP and stdio proxy | Implemented | `crates/velvet-rope-proxy/src/transport/http.rs`, `crates/velvet-rope-proxy/src/transport/stdio.rs` | Proxy Rust tests and `tests/test_mcp_proxy_cli.py` | Docs may claim support for tested local proxy behavior. |
| OAP draft-shaped artifacts | Implemented on proxy path | `crates/velvet-rope-proxy/src/oap.rs`, `crates/velvet-rope-proxy/src/ledger.rs` | Proxy Rust tests | Say draft-shaped or pinned-shape interop, not conformance certification. |
| Vault Merkle log and proofs | Implemented | `src/velvet/vault/merkle.py` | `tests/test_vault.py` | Tamper-evident under stated hashing/canonicalization hypotheses. |
| Vault Signed Tree Heads | Implemented | `src/velvet/vault/sth.py` | `tests/test_vault.py::test_signed_tree_head_uses_canonical_hash_and_verifies` | Requires valid signatures and supplied public key. |
| Vault anchoring adapters | Implemented local adapters | `src/velvet/vault/anchor.py` | `tests/test_vault.py::test_file_anchor_is_write_once`, `tests/test_vault.py::test_webhook_anchor_spools_on_failure` | Operator must provide the external integrity boundary. |
| Vault retention tombstones | Implemented local deletion guard | `src/velvet/vault/retention.py` | `tests/test_vault.py::test_retention_refuses_without_anchor_and_deletes_with_tombstone` | Production scheduling/object lifecycle is deployment work. |
| Vault recording modes | Implemented | `src/velvet/vault/modes.py` | `tests/test_vault.py::test_recording_modes_bind_hashes_and_require_plaintext_opt_in` | Replay binds hashes and lengths; storage mode does not imply content inspection. |
| Offline vault verifier | Implemented | `src/velvet/vault/verify.py`, CLI `vault verify` | `tests/test_vault.py`, `uv run velvet --help` | Requires ledger segment, STH, and public key. |
| Browser verifier | Implemented single-file verifier | `docs/public/velvet-verifier.html` | `tests/test_verifier_html.py` via `uv run pytest` | Verifies local supplied artifacts offline. |
| Article 12 attestation pack | Implemented technical pack | `src/velvet/attestation/pack.py`, `src/velvet/attestation/mapping.py` | `tests/test_attestation.py` | Technical record-keeping capability relevant to Article 12, not a legal conclusion. |
| Compliance crosswalk docs | Implemented docs | `docs/compliance/crosswalk.md`, `docs/compliance/reconstructability.md` | Link checks after docs sync | Crosswalk is a technical map, not legal advice. |
| Assurance control-state attestation | Implemented local/offline | `src/velvet/assurance/attestation.py` | `tests/test_assurance_attestation.py` | Aggregate-only telemetry, no content, no underwriting decision. |
| Assurance scheduled issuance | Implemented local CLI | `src/velvet/cli.py`, `src/velvet/assurance/export.py` | `tests/test_assurance_attestation.py::test_scheduled_assurance_cli_appends_idempotently` | Cron-friendly local append/export path. |
| Assurance verifier SDK | Implemented offline verifier packages | `assurance/verifier/velvet_assurance_verifier/verifier.py`, `assurance/verifier/velvet-assurance-verifier.js` | `tests/test_assurance_attestation.py` Python and Node verifier tests | Independent offline verification, not a hosted service. |
| Claims Pack CLI | Implemented local CLI | `src/velvet/cli.py::claims_pack_main`, `src/velvet/attestation/pack.py` | `tests/test_assurance_attestation.py::test_assurance_and_claims_pack_cli` | Requires vault artifacts and passing Assurance verification. |
| Claims Pack and live-demo integration | Implemented local bridge | `demo/incident/vault_bridge.py`, `demo/incident/run.py`, `src/velvet/cli.py` | `make live-demo` passed locally on 2026-06-13 with Docker Server `28.5.1` | The Vault ledger/STH are derived demo evidence artifacts for Claims Pack generation; the original Rust proxy ledger remains preserved separately. |
| ShadowPath custom effect project | Implemented local runner | `src/velvet/shadowpath_product.py` | `tests/test_shadowpath_product.py` and isolated smoke test | Result covers only the user-declared effect, routes, adapter, and observer. |
| ShadowPath outcome portfolio | Implemented local aggregation | `src/velvet/shadowpath_product.py::run_shadowpath_portfolio` | portfolio tests plus isolated two-project smoke test | Does not discover missing effects/routes or imply continuous hosted assurance. |
| Static product site | Implemented buyer-facing narrative | `site/` | local asset, route-parity, JavaScript syntax, and claim-boundary checks | Portfolio panel is labelled illustrative; site does not imply customer traction or a hosted control plane. |
| Live drift-rejection demo code | Implemented, environment-dependent run | `Makefile`, `demo/live_target/`, `demo/attacks/`, `demo/incident/` | `make live-demo` passed locally on 2026-06-13 with Docker Server `28.5.1` | Docs can claim a passing local run only when Docker/Postgres are available. |
| Certified Spend | Implemented bounded helper | `src/velvet/budget_safety.py`, `crates/velvet-core/src/types.rs` | `tests/test_budget_safety_deterministic.py`, Rust router/type tests | Valid only under H1 true hard caps and H2 single-writer atomic accounting. |
| Certified Lockout | Implemented bounded Max-DE helper | `src/velvet/max_de.py`, `src/velvet/research/gamma_rate.py` | `tests/test_max_de.py`, `tests/test_gamma_rate_max_de.py`, proxy Max-DE tests | Covers posterior-typed classes only. |
| Hosted enterprise platform | Absent | No hosted service implementation found | None | Not claimed. |
| Hosted insurer API | Absent | No hosted API server or carrier integration found | None | Assurance is offline/outbound evidence only. |
| Enterprise policy UI | Absent | No product UI for policy authoring found | None | Roadmap/not claimed. |

## Existing Docs Read

- `README.md`
- `IMPLEMENTATION_STATUS.md`
- `TEST_RESULTS.md`
- `PUBLIC_READY_REPORT.md`
- `docs/investors/README.md`
- `docs/investors/VELVET_ONE_PAGER.md`
- `docs/investors/VC_DECK.md`
- `docs/public/CLAIMS.md`
- `docs/diligence/README.md`
- `docs/diligence/MARKET_TECHNICAL_DILIGENCE.md`
- `docs/vault.md`
- `docs/compliance/crosswalk.md`
- `docs/compliance/reconstructability.md`
- `docs/assurance/underwriting_profile.md`
- `demo/BOUNDARIES.md`
- `demo/DEMO_SCRIPT.md`

No `velvet-evidence-pivot.md` file was found outside generated or dependency directories during this sync.
