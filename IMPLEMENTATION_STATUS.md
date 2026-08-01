# Velvet Implementation Status

Last updated: 2026-07-04 closure-bound Execution Permit lifecycle.

## Executive Summary

Velvet is a local, deterministic pre-execution admission and evidence system for
autonomous-agent actions. The current repo has an implemented Gate layer,
proof-derived Execution Permits and Receipts, an implemented local Vault
evidence plane, Article 12-oriented technical attestation packs, an aggregate
Assurance attestation surface, and bounded certificate helpers.

The defensible current claim is a self-hosted, warrant-bound admission and evidence layer. The repo does not implement a hosted enterprise service, a legal compliance outcome, or an insurer-facing hosted API.

## Implemented

- Rust routing core for typed candidate actions.
- Policy-chain evaluation before scoring.
- Entry pricing, scarcity pressure, and clearance scoring.
- Decision outcomes including execute, block, escalate, defer, and skip.
- Schema `8.0` thread records for routed decisions.
- Python Velvet Warrant, Seal, Ledger, replay, approval, and evidence-pack helpers.
- Proof-derived Execution Permits and Execution Receipts with strict schemas,
  distinct signing purposes, external-trust verification, temporal validity,
  exact request/scope binding, and atomic claim stores.
- Closure-bound Execution Permits for local subgoal lifecycle control. Closure
  permits carry an omitted-when-absent signed `subgoal_id_hash` plus logical-step
  validity, and the proxy rejects stale subgoal epochs before dispatch while
  retaining wall-clock TTL checks.
- Ed25519-signed warrants and ledger records, with public-key verification and fail-closed production key loading.
- Dependency-injected AWS KMS and Vault Transit signing providers for warrants, ledger records, approval receipts, binary ledger frames, and evidence manifests. Default tests use fake clients.
- `velvet-rope-proxy` Rust MCP proxy, decomposed by config, policy bundle,
  inventory, approvals, enforcement, execution permits, ledger, OAP artifacts,
  stdio transport, and Streamable HTTP transport.
- MCP `2025-11-25` support for stdio and Streamable HTTP, including sessions, GET SSE listen streams, POST SSE responses, bounded same-stream replay, DELETE termination, Origin/auth checks, and pre-execution `tools/call` enforcement.
- OAP draft-shaped Passport and Decision artifacts on the proxy path, plus Velvet-signed Max-DE Certificate Envelopes when configured or required.
- Evidence Vault primitives: RFC 6962-style Merkle roots over ledger record hashes, inclusion proofs, consistency proofs, Signed Tree Heads, anchoring adapters, retention tombstones, recording modes, and offline vault verification.
- Article 12-oriented attestation-pack generation from vault artifacts.
- Assurance control-state attestations that are signed, aggregate-only, content-free, exportable to JSONL, and offline-verifiable.
- Claims Pack CLI that builds an incident-window pack from vault artifacts and Assurance verification.
- Live demo incident bridge that exports the Rust proxy argument-drift ledger into derived Vault artifacts, verifies the exported segment, and invokes `velvet claims-pack` from `make live-demo`.
- Local approval store and approval receipt verification.
- Max-DE helpers for posterior-typed Bernoulli candidates, bounded Dirichlet-categorical payoffs, and Gamma-rate positive rate/intensity posteriors.
- Deterministic budget-safety certificates for pathwise zero-overshoot spend control only when H1 real per-action hard caps and H2 single-writer atomic accounting both hold.
- Tests across routing, policy, replay determinism, ledger atomicity, demos, sandbox planning, Python/Rust parity, proxy behavior, Vault, attestation packs, Assurance, budget safety, and Max-DE helpers.

## Partial Or Local-Only

- Gate, Vault, Assurance, and Claims Pack are local/self-hosted code paths, not a shared hosted service.
- Assurance is an outbound/offline evidence surface. It does not implement a hosted insurer API, underwriting workflow, or carrier integration.
- `make live-demo` is a Docker/Postgres demo target. It passed locally on 2026-06-13 with Docker Server `28.5.1`; it remains environment-dependent on a running Docker daemon.
- Execution replay records prior results. It does not re-execute live providers.
- Provider cost accounting is not a provider-wide hard billing guarantee. Certified Spend applies only under H1/H2.
- Dashboard and approval surfaces are local inspection/workflow helpers, not hardened production observability or enterprise approval orchestration.
- Live external integrations require credentials and explicit configuration. Default tests avoid live network calls.
- External permit enforcement requires a cooperating verifier, adapter,
  credential broker, or substrate integration. Without one, Velvet enforces at
  the proxy or gateway boundary.
- Evidence vault anchoring adapters are local primitives. File anchors require operator-managed write-once or object-lock storage, and webhook anchors require an operator-managed endpoint.
- Vault retention deletion is implemented for sealed segment artifacts with exact signed STH coverage and anchor receipt checks. Production retention scheduling and object-store lifecycle integration remain deployment work.

## Not Implemented / Not Claimed

- Hosted shared-tenant enterprise platform.
- Hosted shared-tenant MCP gateway.
- Hosted insurer-facing API.
- Enterprise policy studio or rich registry management UI.
- Production arbitrary-code execution boundary.
- Legal compliance determination or audit outcome.
- External coverage approval or pricing effect.
- Formal optimality for all agent routing.
- Hard spend guarantees across all external providers.
- Formal certificates for every runtime decision.
- Impossible-to-alter storage. The supported claim is tamper-evident evidence under stated canonicalization, hashing, signature, Merkle, and external-anchor hypotheses.
- Universal exactly-once real-world effects. A crash after a side effect but
  before receipt persistence can leave an indeterminate execution state unless
  the substrate participates transactionally.

## Certified Actions Boundary

Certified Spend proves pathwise zero-overshoot spend safety only when:

- H1: the action has a true hard cap known before execution,
- H2: the scoped budget ledger admission/debit is single-writer atomic.

Estimate-only cost ceilings remain soft compatibility policy.

Certified Lockout is a Max-DE capability for posterior-typed classes only. It does not certify every action, every policy decision, or every irreversible workflow.

## Repository Map

| Area | Status | Evidence |
| --- | --- | --- |
| `crates/velvet-core/` | Implemented | Rust routing, policy, pricing, scoring, signing context, sandbox, and trace primitives. `cargo test --workspace` passed. |
| `crates/velvet-policy-loader/` | Implemented | YAML policy schema, migration, and policy-test helpers. `cargo test --workspace` passed. |
| `crates/velvet-policies/` | Implemented | Cost ceiling, PII, prompt injection, escalation, and rate-limit policy checks. `cargo test --workspace` passed. |
| `crates/velvet-py/` | Implemented | Python binding for Rust primitives. `uv run pytest` and `cargo test --workspace` passed. |
| `crates/velvet-closure/` | Implemented local lifecycle controller | Contract validation, synchronized per-subgoal epochs, closure-triggered permit invalidation, visible-surface contraction, lifecycle ledger records, and lingering-authority demo. `cargo test -p velvet-closure`, `cargo run -p velvet-closure --example lingering_authority`, and `cargo test --workspace` passed on 2026-07-04. |
| `crates/velvet-rope-proxy/` | Implemented local proxy | Decomposed MCP proxy with stdio and Streamable HTTP, Execution Permit preparation, atomic claim, and receipt observation. Targeted proxy receipt tests passed. |
| `src/velvet/execution.py` | Implemented | Python Execution Permit/Receipt issuance, verification, atomic claim, and receipt helpers. `tests/test_execution_permits.py` passed. |
| `src/velvet/rope.py` | Implemented | Python Gate warrant and MCP-shaped authorization surface. `tests/test_rope.py` passed inside `uv run pytest`. |
| `src/velvet/ledger.py` | Implemented | Local ledger records, binary ledger verification, reports, and thread validation. `tests/test_ledger.py` passed inside `uv run pytest`. |
| `src/velvet/vault/` | Implemented local evidence plane | Merkle, STH, anchors, retention, recording modes, and offline verification. `tests/test_vault.py` passed inside `uv run pytest`. |
| `src/velvet/attestation/` | Implemented technical pack generator | Article 12-oriented mapping and pack generation. `tests/test_attestation.py` passed inside `uv run pytest`. |
| `src/velvet/assurance/` | Partial venture surface | Signed aggregate attestations, export, scheduled issue, and verification helpers. `tests/test_assurance_attestation.py` passed inside `uv run pytest`. |
| `assurance/verifier/` | Implemented offline verifier SDK | Python and JS verifier packages. `tests/test_assurance_attestation.py` passed Python and Node verifier checks. |
| `src/velvet/cli.py` `claims-pack` | Implemented local CLI | Builds vault-backed incident-window packs and Assurance verification reports. `tests/test_assurance_attestation.py::test_assurance_and_claims_pack_cli` passed. |
| `demo/` | Implemented local demo, environment-dependent run | Live target, attacks, incident bundler, derived Vault bridge, Claims Pack invocation, and offline verifier exist. `make live-demo` passed locally on 2026-06-13 with Docker Server `28.5.1`. |
| `src/velvet/budget_safety.py` | Implemented bounded certificate helper | H1/H2 deterministic spend safety. `tests/test_budget_safety_deterministic.py` passed inside `uv run pytest`. |
| `src/velvet/max_de.py` and `src/velvet/research/gamma_rate.py` | Implemented bounded research engines | Posterior-typed Max-DE helpers. `tests/test_max_de.py` and `tests/test_gamma_rate_max_de.py` passed inside `uv run pytest`. |
| `src/velvet/dashboard.py` | Partial | Local inspection dashboard only. |

## Risk Register

- Open-core boundary: Gate is the open-core control point. Vault and Assurance are separate evidence and review surfaces. Docs should not imply all surfaces are packaged as the same open-core product.
- Insurance-claim discipline: Assurance produces aggregate control-state telemetry for review. It does not establish coverage, underwriting approval, or pricing impact.
- Article 12 boundary: Attestation packs demonstrate technical record-keeping capability relevant to Article 12. They are not legal compliance determinations.
- Certificate hypothesis dependence: Certified Spend depends on H1/H2. Certified Lockout depends on correctly typed posterior classes and certificate assumptions.
- `velvet-closure` Max-DE risk gating is a safe integration seam only:
  `MaxDeRiskGate` denies irreversible grants unless a real signed Max-DE envelope
  is supplied. It does not synthesize or fake a passing certificate.
- Hosted productization remains future work.
- Live-demo evidence depends on Docker and local Postgres availability; the passing run used Docker Server `28.5.1` on 2026-06-13.
- External anchoring requires an operator-managed endpoint or write-once storage boundary.
- Execution Receipts are observation artifacts. Gateway-observed receipts do
  not prove a business-level side effect completed, and signed permits are not
  self-enforcing without a verifier at the execution boundary.

## Current Positioning

Use this repo as evidence for a founder-built, local, warrant-bound pre-execution admission and evidence layer:

- Gate decides whether proposed agent actions may execute.
- Execution Permits define the exact short-lived authority that may be
  dispatched after that decision is durable.
- Execution Receipts record conservative observations after a claimed dispatch.
- Vault preserves verifiable evidence about those decisions.
- Assurance summarizes control state without exposing content.
- Certified Actions provide narrow mathematical certificates under explicit hypotheses.
