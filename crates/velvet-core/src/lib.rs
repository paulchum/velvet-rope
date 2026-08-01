mod action_normalization;
mod admission;
mod admission_trace;
mod canonicalization;
mod capabilities;
mod constraints;
mod effects;
mod execution_permit;
mod memory;
mod optimization;
mod policy;
#[cfg(feature = "legacy-heuristic-routing")]
mod pricing;
mod registry;
mod router;
mod sandbox;
mod schema;
#[cfg(feature = "legacy-heuristic-routing")]
mod scoring;
mod signing;
mod trace;
mod types;
mod utils;

pub use action_normalization::{
    AuthorityClass, CANONICAL_ACTION_SCHEMA_VERSION, CanonicalActionV1, MutationKind,
    NormalizationFailure, PROPOSED_ACTION_SCHEMA_VERSION, ProposedActionV1, RedactionSummary,
    Reversibility, SurfaceKind, normalize_action_v1,
};
pub use admission::{
    ADMISSION_ENGINE_VERSION, AdmissionCandidateEvaluation, AdmissionConfig, AdmissionEngine,
    AdmissionEvaluationInput, BudgetConstraintStatus, NormalizedCandidate,
    NormalizedCandidatePublic,
};
pub use admission_trace::{
    ADMISSION_TRACE_HASH_DOMAIN, ADMISSION_TRACE_SCHEMA_VERSION, AdmissionDecision, AdmissionTrace,
    CANDIDATE_HASH_DOMAIN, EFFECT_VECTOR_HASH_DOMAIN, REQUEST_HASH_DOMAIN,
    admission_trace_hash_value, domain_hash_bytes, domain_hash_value,
};
pub use canonicalization::{
    CanonicalJson, CanonicalizationError, VELVET_CANONICAL_JSON_V1,
    VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD, canonical_json_v1_bytes, canonical_json_v1_hash,
    canonical_json_v1_string, load_canonical_json_v1, proof_artifact_canonical_json,
    proof_artifact_hash, proof_artifact_unsigned_payload,
};
pub use capabilities::{
    CAPABILITY_REGISTRY_SCHEMA_VERSION, CapabilityDescriptor, CapabilityRegistry, tool_key,
};
pub use constraints::{
    AdmissionConstraintResult, CONSTRAINT_MODEL_VERSION, ConstraintSeverity,
    has_blocking_constraint, has_defer_constraint, selected_reason_from_trace,
    source_to_sink_constraint,
};
pub use effects::{
    CapabilityClass, CostBound, DataClass, EFFECT_MODEL_VERSION, EFFECT_VECTOR_SCHEMA_VERSION,
    EffectVector, LatencyBound, RiskBound, SideEffectClass, SourceToSinkFlow, UtilityBound,
    WriteFootprint, default_effect_for_action,
};
pub use execution_permit::{
    ArtifactReference, AttestationLevel, DispatchClaim, EXECUTION_CANONICALIZATION,
    EXECUTION_PERMIT_SCHEMA_VERSION, EXECUTION_RECEIPT_SCHEMA_VERSION, ExecutionOutcome,
    ExecutionPermit, ExecutionPermitScope, ExecutionReceipt, PURPOSE_EXECUTION_PERMIT,
    PURPOSE_EXECUTION_RECEIPT, PermitConstraints, PermitLineage, PermitPolicyBinding,
    PermitValidity, ReceiptError, ReceiptExecutor, ResourceScope, SubjectBinding,
};
pub use memory::evaluate_memory;
pub use optimization::{
    OPTIMIZER_MODEL_VERSION, ObjectiveComponents, ObjectiveWeights, objective_components,
};
pub use policy::{
    AllowAllPolicy, Policy, PolicyChain, PolicyEvaluation, PolicyGraph, PolicyInstance,
    PolicySelection, policy_reason,
};
#[cfg(feature = "legacy-heuristic-routing")]
pub use pricing::{base_entry_price, compute_entry_price, estimate_cost, estimate_risk};
pub use registry::{action_registry, get_action_definition};
pub use router::{
    RouteWithThread, route, route_request, route_request_with_policy_chain,
    route_request_with_policy_chain_and_thread, route_request_with_thread, route_with_policy_chain,
    route_with_policy_graph, route_with_policy_graph_and_thread, route_with_thread,
    route_with_thread_and_policy_chain,
};
pub use sandbox::{
    ContainerBackend, ContainerRuntime, EgressRule, LightweightBackend, MountMode, MountSpec,
    NetworkPolicy, NoneBackend, OutputTransform, ResourceLimits, RuntimeMode, SandboxBackend,
    SandboxBackendKind, SandboxConfig, SandboxExecutionPlan, SandboxProvenance, SandboxViolation,
    SandboxedCommand, plan_for_candidate, seal_material_for_candidate,
};
pub use schema::thread_schema_json;
#[cfg(feature = "legacy-heuristic-routing")]
pub use scoring::{score_action, score_action_with_pricing};
pub use signing::{
    SIGNATURE_SCHEMA_VERSION, SignatureBlock, SigningContext, SigningError, SigningProvider,
    signing_message_bytes,
};
pub use trace::{ThreadCandidateAction, ThreadRecord, redact_secrets};
pub use types::*;

pub const ROUTER_VERSION: &str = "router_v1";
pub const SCORER_VERSION: &str = "admission_optimizer_v1";
pub const PRICING_POLICY_VERSION: &str = "entry_pricing_v2";
pub const ACTION_REGISTRY_VERSION: &str = "action_registry_v1";
pub const THREAD_SCHEMA_VERSION: &str = "9.0";
