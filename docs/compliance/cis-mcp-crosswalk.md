# CIS MCP Companion Guide Crosswalk

This bundle demonstrates technical record-keeping capability relevant to CIS
MCP control themes. It is not a determination of legal compliance, which
depends on system classification, deployment context, and counsel review.

This crosswalk is a technical capability map for Velvet MCP, Vault, and Claims
Pack evidence. It maps publicly documented CIS MCP Companion Guide v1.0 themes
to concrete Velvet artifacts and producer modules. It is not legal advice.

## Source Anchors

- CIS Model Context Protocol (MCP) Companion Guide v1.0, published April 20,
  2026: <https://www.cisecurity.org/insights/white-papers/controls-v8-1-model-context-protocol-companion-guide>
- Velvet compliance evidence crosswalk: [`crosswalk.md`](crosswalk.md)
- Velvet Vault artifact and verification model: [`../vault.md`](../vault.md)
- Velvet MCP proxy evidence model: [`../mcp_proxy/evidence.md`](../mcp_proxy/evidence.md)
- Velvet MCP proxy surface boundary: [`../mcp_proxy/SURFACE_MATRIX.md`](../mcp_proxy/SURFACE_MATRIX.md)
- Velvet execution permits and receipts: [`../execution-permits.md`](../execution-permits.md)

## Status Legend

- `evidenced`: Velvet vault or pack artifacts contain a concrete field or verifiable binding.
- `partial`: Evidence exists only for specific record shapes, deployments, or supplied metadata.
- `out-of-scope`: The field is not produced by Velvet vault evidence.

## CIS MCP Crosswalk

| CIS MCP control theme | Velvet artifacts and producing modules | Evidence boundary | Status |
| --- | --- | --- | --- |
| Per-capability explicit grants <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `PolicyBundleProof`, `AdmissionOutcome`, and signed `WarrantV1` scope fields produced by `crates/velvet-rope-proxy/src/enforcement.rs` and `crates/velvet-rope-proxy/src/ledger.rs`; `admission_evidence.tool`, `admission_evidence.policy`, `request_hash`, `arguments_hash`, and `tool_schema_hash` are emitted by `build_admission_evidence`. | Evidences the policy hash/version, tool key, schema hash, arguments hash, request hash, decision, reason, and warrant binding for mediated `tools/call` decisions. It does not evidence unmediated agent paths. | evidenced |
| Non-human identity governance <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `ExecutionPermit`, `SubjectBinding`, `ExecutionPermitScope`, `PermitConstraints`, `DispatchClaim`, and `ExecutionReceipt` types are defined in `crates/velvet-core/src/execution_permit.rs`; permits, atomic claims, request metadata, and receipts are produced by `crates/velvet-rope-proxy/src/execution.rs`. | Evidences identity-bound, single-use authority for executable MCP dispatches after a durable pre-execution record. Coverage is limited to configured proxy execution paths and cooperating downstream verifiers where external enforcement is required. | evidenced |
| Auditable agent interactions <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `OapLedgerRecord`, `selected_warrant`, `admission_evidence`, hash-chain fields, `forwarding_proof`, `upstream_status`, and optional `execution_receipt` are produced by `crates/velvet-rope-proxy/src/ledger.rs`; OAP decision artifacts are produced by `crates/velvet-rope-proxy/src/oap.rs`. | Evidences whether a mediated interaction was authorized, blocked, pending approval, forwarded, failed, or observed after dispatch, with sequence and predecessor hashes. It does not prove business-level side-effect completion beyond the recorded receipt semantics. | evidenced |
| Tool inventory and allowlisting <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `ToolInventory`, `InventoryEntry`, `InventoryStatus`, `approved_tools`, and `tool_schema_hash` are produced by `crates/velvet-rope-proxy/src/inventory.rs`; inventory status is consumed by `admit_tool_call` in `crates/velvet-rope-proxy/src/enforcement.rs`. | Evidences upstream tool discovery, stable schema hashes, approved-schema comparison, drift status, hidden/deprecated/destructive status, and filtered `tools/list` exposure for the configured upstream server. | evidenced |
| Session and transport controls <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `HttpSessionStore`, `McpHttpSession`, SSE replay buffers, Origin checks, bearer checks, and session validation are implemented in `crates/velvet-rope-proxy/src/transport/http.rs`; `AuthConfig`, `HttpConfig`, and `LimitConfig` are defined in `crates/velvet-rope-proxy/src/config/auth.rs`, `crates/velvet-rope-proxy/src/config/http.rs`, and `crates/velvet-rope-proxy/src/config/limits.rs`. | Evidences local Streamable HTTP session handling, known-session checks, bounded Last-Event-ID replay, Origin allow-list checks, optional bearer auth, and request/response limits. Transport security depends on deployment settings such as TLS termination and private upstream network controls. | partial |
| Non-tool MCP surface governance <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `BoundedMethodDecision` and method disposition records are produced by `bounded_method_decision` in `crates/velvet-rope-proxy/src/enforcement.rs`; `bounded_method_disposition` and `bounded_method_observation` `OapLedgerRecord` entries are produced by `crates/velvet-rope-proxy/src/ledger.rs` and called from `crates/velvet-rope-proxy/src/transport/http.rs`. | Evidences explicit allow/block/escalate dispositions for `resources/*`, `prompts/*`, `tasks/*`, non-lifecycle notifications, and unknown methods. Semantic content enforcement for resources and prompts remains outside this scoped gateway. | evidenced |
| Secrets handling and credential boundaries <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `RedactionSummary` is defined in `crates/velvet-rope-proxy/src/inventory.rs`; `redaction_summary_for_value` and secret-key detection are implemented in `crates/velvet-rope-proxy/src/enforcement.rs`; downstream/upstream bearer separation is configured through `crates/velvet-rope-proxy/src/config/auth.rs` and `crates/velvet-rope-proxy/src/config/upstream.rs`. | Evidences redacted-field summaries and a proxy boundary that can avoid forwarding downstream Authorization headers while injecting upstream-only credentials. It does not evidence enterprise secret-manager rotation, human access reviews, or every upstream server's internal credential handling. | partial |
| Logging and retention <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | `OapLedgerRecord` and binary ledger writes are produced by `crates/velvet-rope-proxy/src/ledger.rs`; Vault `SignedTreeHead` artifacts are produced by `src/velvet/vault/sth.py`; inclusion and consistency proofs are produced by `src/velvet/vault/merkle.py`; anchor receipts are produced by `src/velvet/vault/anchor.py`; retention tombstones are produced by `src/velvet/vault/retention.py`. | Evidences verifiable preservation under Velvet's ledger, Merkle, STH, anchor, and tombstone hypotheses. Retention deletion is fail-closed for sealed segments, but deployed retention duration and external anchor availability remain operator responsibilities. | evidenced |
| Incident evidence and review packs <!-- TODO(maintainer): insert section numbers from CIS MCP Companion Guide v1.0 --> | Claims Pack output is produced by `write_claims_pack` in `src/velvet/claims_pack.py` and exposed by `claims_pack_main` in `src/velvet/cli.py`; outputs include `manifest.json`, `coverage_report.json`, `assurance/attestations.jsonl`, `verification/assurance_verification_report.json`, and `verification/claims_replay_verification_report.json`. | Evidences a bounded incident window from supplied ledger, STH, public key, signing configuration, approvals, Assurance inputs, and optional replay thread. It is not full root-cause analysis outside the supplied artifact window. | evidenced |

## Notes

Velvet evidences cryptographic record integrity, replay inputs, policy bindings,
tool inventory decisions, identity-bound execution authority, approval receipts
where those receipts exist, and incident-window pack outputs. It does not
classify a customer system, decide whether a CIS control applies, determine
legal compliance, or supply organization-level governance controls outside the
MCP and vault evidence plane.
