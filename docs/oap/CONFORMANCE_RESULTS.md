# OAP Conformance Results

Pinned OAP commit: `a706c64b0b7ef4bcff9756a926f9a278e577e8b0`.

## Official Runner

Setup:

```text
npm --prefix third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/conformance install --no-package-lock
```

Output:

```text
npm warn deprecated node-domexception@1.0.0: Use your platform's native DOMException instead
added 45 packages, and audited 46 packages in 3s
22 packages are looking for funding
found 0 vulnerabilities
```

Command:

```text
npm --prefix third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/conformance test
```

Output:

```text
🔍 OAP Conformance Test Runner v1.0.0

- Loading test cases...
✔ Loaded 0 test cases

📊 Conformance Test Results

✅ Passed: 0
❌ Failed: 0
📈 Success Rate: 0.0%

🎯 Conformance testing complete!
```

This runner result is not production crypto evidence. At the pinned commit it loads zero cases. Existing source review also records that the runner uses fallback validation surfaces and format/length signature checks rather than independent production Ed25519 verification.

## Local Velvet Tests

Command:

```text
cargo test -p velvet-rope-proxy
```

Output summary:

```text
running 51 tests
test oap::tests::decision_payload_and_signed_digests_are_distinct_and_stable ... ok
test oap::tests::decision_signature_hash_tracks_raw_ed25519_signature ... ok
test oap::tests::canonicalization_rejects_float_json_numbers ... ok
test oap::tests::decision_signature_tamper_checks_use_production_ed25519 ... ok
test oap::tests::maxde_exact_arithmetic_inspect_vector ... ok
test oap::tests::maxde_exact_arithmetic_lockout_vector ... ok
test oap::tests::maxde_exact_arithmetic_refinement_vector ... ok
test oap::tests::maxde_exact_arithmetic_boundary_equality_vector ... ok
test oap::tests::maxde_rejects_float_or_exponent_inputs ... ok
test oap::tests::maxde_tampered_scale_or_value_fails ... ok
test oap::tests::maxde_envelope_binds_policy_tool_schema_arguments_request_and_decision ... ok
test oap::tests::maxde_envelope_strip_swap_and_replay_are_detected ... ok
test oap::tests::maxde_envelope_expiry_is_enforced ... ok
test tests::pre_execution_record_is_persisted_before_upstream_forward ... ok
test tests::post_execution_observation_is_appended_after_success ... ok
test tests::post_execution_observation_is_appended_after_upstream_failure ... ok
test tests::ledger_chain_verifier_detects_tampering ... ok
test tests::ledger_chain_verifier_rejects_rehashed_pre_record_binding_mismatch ... ok
test tests::ledger_chain_verifier_rejects_rehashed_post_record_binding_mismatch ... ok
test tests::missing_oap_signer_blocks_before_upstream_execution ... ok
test tests::missing_velvet_signer_blocks_before_upstream_execution ... ok
test tests::required_certificate_absence_blocks_before_forward ... ok
test result: ok. 51 passed; 0 failed
```

Covered locally:

- Deterministic Passport digest and Decision payload/signed digest separation.
- Production Ed25519 verification for OAP Decisions and Velvet Max-DE envelopes.
- Fixed-scale exact Max-DE arithmetic without signed-path floats.
- Envelope binding to policy, identity hashes, request hash, arguments hash, tool schema hash, Passport digest, Decision payload digest, signed Decision digest, and raw Decision signature hash.
- Strip, swap, replay/expiry, and tamper detection.
- Policy-driven certificate-required semantics.
- Pre-execution ledger persistence before forwarding.
- Post-execution observations after upstream success and failure.
- Hash-chain tamper detection and re-hashed semantic mismatch rejection for pre/post record bindings.
- Signer and ledger fail-closed paths.

## Current Status

Strict upstream Decision schema conformance remains blocked by the pinned schema conflict described in `SPEC_CONSISTENCY.md` and `BLOCKED_SPEC_CONFLICT.md`. Velvet therefore claims only a pinned draft-compatible Passport/Decision boundary plus Velvet extension evidence, not broad OAP certification or full conformance.
