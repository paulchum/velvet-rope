#![recursion_limit = "256"]
//! Pre-execution MCP admission proxy for Velvet Rope.
//!
//! This crate exposes the same crate-root API as the original single-file
//! implementation while organizing the proxy by configuration, policy bundle
//! verification, inventory, approvals, enforcement, ledger, and transports.

mod approvals;
mod cli;
mod config;
mod constants;
mod demo;
mod enforcement;
mod execution;
mod inventory;
mod ledger;
mod oap;
mod permit_store;
mod policy_bundle;
mod transport;
mod verdicts;

pub use approvals::*;
pub use cli::{Cli, CliCommand, run_cli, run_config};
pub use config::*;
pub use constants::*;
pub use demo::{
    EXAMPLE_POLICY, FakeMcpServer, conformance_matrix, example_tool_approvals, fake_tools,
    run_benchmark, run_demo, surface_matrix,
};
pub use enforcement::{AdmissionOutcome, admit_tool_call};
#[doc(hidden)]
pub use enforcement::{
    PermitEpochProvider, WallClockOnlyPermitEpochProvider, verify_permit_logical_step,
};
#[doc(hidden)]
pub use execution::{
    AuthorizedExecution, ExecutionReceiptObservation, LogicalPermitBinding, PreparedExecution,
    authorize_execution_with_epoch_provider, build_execution_receipt, mark_execution_complete,
    prepare_execution_with_logical_step, verify_outbound_request_matches_permit,
    verify_trusted_execution_permit, verify_trusted_execution_permit_with_epoch_provider,
};
pub use inventory::{
    InventoryEntry, InventoryStatus, RedactionSummary, ToolInventory, tool_schema_hash,
};
pub use ledger::{
    BinaryLedgerDecodeError, BinaryLedgerDecodeErrorKind, BinaryLedgerFrame, CanonicalLedgerRecord,
    LifecycleLedgerEvent, OapLedgerRecord, PostExecutionObservation, WarrantV1, canonical_json,
    decode_binary_ledger_frames, encode_binary_ledger_record, parse_binary_ledger_frame,
    record_lifecycle_ledger_event, record_post_execution_ledger, record_pre_execution_ledger,
    sha256_hex, value_hash, value_hash_hex, verify_binary_ledger_bytes, verify_oap_ledger_chain,
    verify_oap_pre_execution_record,
};
pub use oap::{
    MaxDeCertificateConfig, MaxDeDecision, OAP_DECISION_DRAFT_VALIDATION, OAP_SPEC_COMMIT,
    OAP_SPEC_REPO, OapActionContext, OapArtifacts, OapConfig, OapDecisionInput, OapReason,
    VELVET_MAXDE_ENVELOPE_TYPE, VELVET_OAP_BOUNDARY_STATEMENT, build_oap_artifacts,
    decision_payload_digest, decision_signature_hash, digest_value, hash_identifier,
    hash_optional_identifier, passport_digest, signed_decision_digest,
    validate_decision_structural, validate_passport_structural, verify_envelope_binding,
    verify_envelope_binding_against_context, verify_maxde_certificate_envelope,
    verify_maxde_exact_arithmetic, verify_oap_decision_signature, verify_required_envelope,
};
#[doc(hidden)]
pub use permit_store::PermitClaimStore;
pub use policy_bundle::{
    BundleSignature, PolicyBundleManifest, PolicyBundleProof, canonical_manifest_for_signature,
    policy_dir_hash, verify_policy_bundle,
};
pub use transport::{McpUpstream, ProxyRuntime, StdioMcpServer, run_http_proxy};
pub use verdicts::{
    PURPOSE_VERDICT_CERTIFICATE, VERDICT_CERTIFICATE_SCHEMA_VERSION, VERDICT_SAFE_KILL,
    VerdictCheck, verdict_certificate_payload_hash, verify_verdict_certificate,
    verify_verdict_certificate_with_key,
};

#[cfg(test)]
mod tests;
