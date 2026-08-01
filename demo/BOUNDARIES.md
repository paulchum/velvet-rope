# Velvet Live Demo Boundaries

## What This Demo Proves

This demo proves that Velvet can refuse execution before a consequential local tool mutates state for five concrete attack classes, using a real proxy, a real MCP hop, real signing keys, a real dispatch guard, and real SQL against a Postgres container.

The demonstrated classes are:

1. Argument drift: the proxy admits `issue_refund(amount=20.00)`, a compromised dispatcher substitutes `amount=2000.00`, and the live executor boundary refuses before SQL inserts a refund.
2. Schema drift: the upstream server changes `update_order_status` schema after proxy inventory/admission, and dispatch refuses on tool-schema-hash mismatch.
3. Approval replay: a receipt issued for one `delete_customer_records` action is replayed against different arguments, and dispatch refuses because the receipt binds the canonical action hash.
4. Policy swap: the live control-plane policy hash changes after admission, and dispatch refuses on policy-hash mismatch.
5. Budget overshoot: rapid `issue_refund` attempts cannot commit spend above the configured refund cap; the over-cap attempt is refused and the database cap remains intact.

The demo also proves fail-closed behavior for a missing signing provider variant: the proxy refuses to issue decisions when the demo OAP/Max-DE signing keys are unavailable, and no database state changes.

Every attack script asserts both the refusal and the database state. The incident runner packages the canonical argument-drift report, proxy artifacts, public key, recording, derived Vault artifacts, and Claims Pack output. It invokes `velvet vault verify`, invokes `velvet claims-pack`, and still invokes a separate offline verifier process that replays the sealed report digest and validates the signed OAP decision metadata with the public key.

## Main Demo Artifacts

The main incident artifact is the Claims Pack under `reports/live-demo/incident/claims_pack`.

The incident path also writes:

- the original Rust proxy forensic bundle and cast recording;
- `reports/live-demo/incident/offline_verification_report.json` from `demo.incident.offline_verify`;
- derived Vault artifacts under `reports/live-demo/incident/vault/`, including `argument_drift.vledger`, `signed_tree_head.json`, `vault_public_key.pem`, `bridge_manifest.json`, and `vault_verification_report.json`.

The Vault ledger and Signed Tree Head are derived demo evidence artifacts for offline Vault and Claims Pack verification. They preserve the canonical proxy record payloads and record hashes, then replace only the top-level ledger record signature with the demo Ed25519 signer expected by the Vault verifier. They do not replace the original Rust proxy ledger, which remains in the forensic bundle and is listed in the bridge manifest.

## What This Demo Does Not Prove

This demo does not prove resistance to a compromised Velvet host.

It does not prove resistance to kernel-level interception, hypervisor compromise, database-engine compromise, or tampering below the executor boundary.

It does not prove prompt-injection prevention.

It does not prove complete coverage of every possible action class, tool schema, transport feature, policy type, or approval workflow. It covers only the five demonstrated drift/replay/race classes plus the signing-provider fail-closed variant.

It does not prove that the demo keys are production-safe. They are deterministic local demo keys.

It does not prove provider-wide hard spend control. The budget-overshoot scenario exercises the local executor refund-budget boundary and Postgres state assertions.

## Trust Boundary

For the guarantees shown here, the following must remain uncompromised:

- The Velvet proxy binary and configuration loaded by `make live-demo`.
- The executor dispatch guard in `demo/live_target/common.py`.
- The signing providers and private keys while decisions are issued.
- The single Postgres instance used as the target state store and refund budget ledger.
- The operating-system process boundary between the proxy, dispatcher, target server, and verifier.
- The verifier process and public key used for offline incident replay.

The simulated compromised component is the agent dispatch layer between proxy admission and target execution. The demo intentionally allows that layer to mutate arguments so the executor boundary can reject the drift before SQL is executed.
