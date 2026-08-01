# Velvet x OAP Hardening Results

## Summary

This PR hardens the Velvet MCP proxy OAP path by separating pure OAP Passport/Decision interoperability from Velvet proof obligations. The proxy now emits explicit Decision digest names, signs a v2 Velvet Max-DE Certificate Envelope with full action binding, verifies fixed-scale exact Max-DE arithmetic, computes certificate requirement from policy/config before generation, verifies the persisted pre-execution record before forwarding, and records post-execution observations after upstream success or failure.

Pure OAP ends at the pinned Passport/Decision boundary: draft object shape, passport digest, allow/deny decision fields, JCS canonicalization, Ed25519 Decision signature, kid, expiry, and whatever the pinned runner can actually verify. Velvet begins at the separately Velvet-signed Max-DE Certificate Envelope, exact theorem arithmetic, certified inspect/lockout/refinement semantics, policy-required fail-closed enforcement, pre-execution ledger persistence, and verification that the action forwarded upstream matched the action certified before execution.

## Files Changed

- `crates/velvet-rope-proxy/src/oap.rs`
- `crates/velvet-rope-proxy/src/lib.rs`
- `examples/mcp_proxy/config.yaml`
- `examples/mcp_proxy/config.production.yaml`
- `deploy/mcp_proxy/docker-compose.yaml`
- `deploy/mcp_proxy/kubernetes.yaml`
- `docs/oap/*`
- `docs/mcp_proxy/*`
- `docs/deployment/openai-secure-mcp-tunnel.md`
- `examples/deployment/openai-secure-mcp-tunnel/*`
- `docs/enterprise/velvet-rope-proxy.md`
- `docs/liability/VELVET_ROPE_ARENA.md`
- `docs/liability/VELVET_ROPE_DATASET_CONTRACT.md`
- `docs/investors/ANN_MIURA_KO_BRIEF.md`
- `docs/public/velvet-verifier.html`
- `scripts/check-claim-language.py`
- `tests/test_proof_contract_naming.py`

## Tests Added

- OAP digest tests for Decision payload digest, signed Decision digest, and raw Decision signature hash.
- Canonicalization test rejecting float JSON numbers in signed proof objects.
- Production Ed25519 tamper tests for OAP Decision signatures.
- Exact Max-DE arithmetic vectors for inspect, lockout, refinement, equality boundary, exponent/float rejection, and tampered scale/value.
- Envelope binding tests for policy, tool schema, arguments, request, Decision digests, and Decision signature hash.
- Strip, swap, replay/expiry, and tunnel metadata hashing tests.
- Ledger tests for pre-before-forward, post success, post upstream failure, chain tamper detection, re-hashed semantic binding mismatches, required certificate absence, signer failures, invalid certificate, and strict missing Max-DE config.
- Identity tests for downstream agent/subject semantics and Passport digest authority changes.
- Public claim-language tests for OAP overclaims and external proxy artifact wording.

## Validation Commands Run

```text
cargo fmt --check
cargo test -p velvet-rope-proxy
cargo test --workspace
uv run pytest tests/test_proof_contract_naming.py tests/test_mcp_proxy_cli.py tests/test_public_naming.py
uv run pytest
uv run ruff check src tests scripts
uv run mypy src tests
npm --prefix third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/conformance install --no-package-lock
npm --prefix third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/conformance test
uv run python scripts/check-claim-language.py
```

## Passing Evidence

```text
cargo test -p velvet-rope-proxy
test result: ok. 51 passed; 0 failed
```

```text
cargo test --workspace
test result: ok. 51 passed; 0 failed
Doc-tests velvet_rope_proxy
test result: ok. 0 passed; 0 failed
```

```text
uv run pytest
180 passed, 6 skipped in 30.43s
```

```text
uv run ruff check src tests scripts
All checks passed!
```

```text
uv run mypy src tests
Success: no issues found in 105 source files
```

```text
uv run python scripts/check-claim-language.py
Claim language check passed.
```

## Failing Or Blocked Evidence

Initial direct runner invocation failed before dependency install:

```text
sh: tsx: command not found
```

After installing the vendored conformance package dependencies without a package lock, the runner executed but loaded no cases:

```text
npm warn deprecated node-domexception@1.0.0: Use your platform's native DOMException instead
added 45 packages, and audited 46 packages in 3s
✔ Loaded 0 test cases
✅ Passed: 0
❌ Failed: 0
📈 Success Rate: 0.0%
```

Remaining blocked or untested items:

- Strict pinned Decision JSON Schema conformance remains `BLOCKED_UPSTREAM` because the pinned schema requires fields omitted from `properties` while `additionalProperties=false`.
- VC round-trip is `UNTESTED`; see `docs/oap/VC_ROUNDTRIP_STATUS.md`.
- The pinned OAP runner result is `STUBBED` evidence only and must not be described as production crypto verification.

## Remaining Risks

- OAP key discovery/JWKS resolution is still outside the local proxy; tests verify production Ed25519 using local verifying keys.
- The legacy internal Warrant model remains for non-proxy proof coverage and existing Python tests; public MCP proxy docs now identify the external artifact as OAP Decision plus Velvet-signed Max-DE Certificate Envelope, and the investor verifier labels Warrant evidence as legacy/internal.
- Secure MCP Tunnel examples document topology and metadata hashing but do not include a real OpenAI tunnel-client image or credentials.
