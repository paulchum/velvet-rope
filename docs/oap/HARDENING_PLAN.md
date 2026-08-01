# Velvet x OAP Hardening Plan

## Current Defects Found

- `decision_digest` is ambiguous and currently represents the signed Decision object digest.
- The Max-DE envelope binds only to Decision id, Decision digest, Passport digest, and certificate values; it does not bind policy, identity, request, arguments, tool schema, transport metadata, or raw Decision signature bytes.
- Signed Max-DE certificate verification uses `decimal_to_f64` and core `CertificateEvidence` floats.
- `max_de_certificate_required` is presence-driven (`admission.oap.max_de_envelope.is_some()`), so failed envelope generation can downgrade the ledger record.
- Pre-execution ledger persistence exists before forwarding, but persisted records are not verified with full envelope and hash-chain requirements before upstream execution.
- Public OAP docs and proxy metadata overclaim with `OAP-CONFORMANT DECISION + VELVET SIGNED BOUND ENVELOPE`.
- Public docs still use Velvet Warrant wording for externally visible proxy artifacts.
- The conformance matrix does not fully distinguish pure OAP gates from Velvet extension gates.
- OpenAI Secure MCP Tunnel topology and hashed transport metadata support are absent.

## Files To Edit

- `crates/velvet-rope-proxy/src/oap.rs`
- `crates/velvet-rope-proxy/src/lib.rs`
- `crates/velvet-rope-proxy/Cargo.toml` only if an unavoidable dependency is needed
- `examples/mcp_proxy/config.yaml`
- `examples/mcp_proxy/config.production.yaml`
- `deploy/mcp_proxy/*`
- `docs/oap/*.md`
- `docs/mcp_proxy/*.md`
- `docs/enterprise/velvet-rope-proxy.md`
- `docs/liability/VELVET_ROPE_ARENA.md`
- `docs/liability/VELVET_ROPE_DATASET_CONTRACT.md`
- `docs/investors/*`
- `scripts/check-claim-language.py`
- `tests/test_proof_contract_naming.py`
- New Secure MCP Tunnel docs/examples under `docs/deployment/` and `examples/deployment/`.

## Implementation

- Add explicit OAP digest helpers: Decision payload digest, signed Decision digest, Decision signature hash, and Passport digest.
- Build `velvet.maxde.certificate_envelope.v2` with full action binding and hashed subject/customer/session/transport identifiers.
- Replace signed Max-DE theorem checks with checked fixed-point decimal parsing and multiplication comparisons.
- Compute Max-DE certificate requirement before envelope generation from policy/config and action risk.
- Fail closed before upstream execution if signing, canonicalization, envelope generation, exact arithmetic, envelope binding, ledger persistence, or persisted-record verification fails.
- Add Velvet verification helpers for Decision signature, envelope signature, exact arithmetic, context binding, pre-execution records, and hash-chained ledgers.
- Keep OAP Passport/Decision artifacts free of Velvet extension fields.
- Retire external proxy Warrant wording in public docs while preserving internal Warrant tests for non-proxy proof coverage.

## Tests To Add

- OAP digest/signature/canonicalization tests.
- Max-DE exact arithmetic vectors for inspect, lockout, refinement, equality, just-below threshold, float/exponent rejection, and tampering.
- Envelope binding tests for policy, tool schema, arguments, request, Decision digests, signature hash, strip, swap, replay, expiry, and tunnel metadata hashing.
- Ledger tests for pre-before-forward, post success, post failure, chain tamper detection, missing required certificate, and signer/ledger/certificate fail-closed behavior.
- Identity tests for downstream subject and Passport digest mutation.
- Claim-language tests for OAP overclaims and external Warrant wording.

## Validation Commands

- `cargo fmt --check`
- `cargo test -p velvet-rope-proxy`
- `cargo test --workspace`
- `uv run pytest tests/test_proof_contract_naming.py tests/test_mcp_proxy_cli.py tests/test_public_naming.py`
- `uv run pytest`
- `uv run ruff check src tests scripts`
- `uv run mypy src tests`
- `npm --prefix third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/conformance test`

## Blocked Or Impossible Items

- Strict pinned Decision JSON Schema conformance is blocked upstream: `decision-schema.json` requires `passport_id`, `issued_at`, and `expires_at`, while omitting those properties under `additionalProperties: false`.
- The pinned OAP runner is not production crypto evidence if it still loads zero cases or verifies only signature format/length.
- VC round-trip must be marked `BLOCKED_UPSTREAM` or `UNTESTED` if pinned VC context/tooling cannot preserve Decision digests without local invention.
- Vendored OAP schemas must not be edited.
