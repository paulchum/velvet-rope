use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::JsonObject;

pub const EXECUTION_PERMIT_SCHEMA_VERSION: &str = "velvet.execution_permit.v1";
pub const EXECUTION_RECEIPT_SCHEMA_VERSION: &str = "velvet.execution_receipt.v1";
pub const EXECUTION_CANONICALIZATION: &str = "velvet.canonical_json.v1.sha256.unsigned_payload";
pub const PURPOSE_EXECUTION_PERMIT: &str = "velvet.execution_permit.v1";
pub const PURPOSE_EXECUTION_RECEIPT: &str = "velvet.execution_receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactReference {
    pub artifact_type: String,
    pub artifact_id: String,
    pub artifact_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SubjectBinding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceScope {
    pub kind: String,
    pub id_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionPermitScope {
    pub surface: String,
    pub method: String,
    pub tool_key: String,
    pub operation: String,
    pub request_hash: String,
    pub canonical_action_hash: String,
    pub arguments_hash: String,
    pub tool_schema_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_set_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subgoal_id_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PermitPolicyBinding {
    pub policy_hash: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PermitLineage {
    pub decision_artifact: ArtifactReference,
    pub pre_execution_record: ArtifactReference,
    pub supporting_artifacts: Vec<ArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PermitConstraints {
    pub single_use: bool,
    pub claim_before_dispatch: bool,
    pub deny_on_scope_drift: bool,
    pub receipt_required: bool,
    pub idempotency_key: String,
}

impl PermitConstraints {
    pub fn single_dispatch(idempotency_key: String) -> Self {
        Self {
            single_use: true,
            claim_before_dispatch: true,
            deny_on_scope_drift: true,
            receipt_required: true,
            idempotency_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PermitValidity {
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at_logical_step: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_logical_step: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionPermit {
    pub schema_version: String,
    pub canonicalization: String,
    pub permit_id: String,
    pub issuer: String,
    pub tenant_id: String,
    pub environment: String,
    pub audience: String,
    pub subject: SubjectBinding,
    pub scope: ExecutionPermitScope,
    pub policy: PermitPolicyBinding,
    pub lineage: PermitLineage,
    pub constraints: PermitConstraints,
    pub obligations: Vec<String>,
    pub validity: PermitValidity,
    pub permit_hash: String,
    pub signature: JsonObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DispatchClaim {
    pub claim_id: String,
    pub permit_id: String,
    pub permit_hash: String,
    pub claimed_at: String,
    pub claimant: String,
    pub pre_execution_record_hash: String,
    pub claim_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    FailedBeforeDispatch,
    Rejected,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationLevel {
    GatewayObserved,
    SubstrateAttested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptExecutor {
    pub executor_id: String,
    pub audience: String,
    pub attestation_level: AttestationLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptError {
    pub code: String,
    pub detail_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceipt {
    pub schema_version: String,
    pub canonicalization: String,
    pub receipt_id: String,
    pub permit_id: String,
    pub permit_hash: String,
    pub dispatch_claim_record_hash: String,
    pub pre_execution_record_hash: String,
    pub request_hash: String,
    pub canonical_action_hash: String,
    pub executor: ReceiptExecutor,
    pub outcome: ExecutionOutcome,
    pub dispatch_attempted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substrate_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ReceiptError>,
    pub started_at: String,
    pub completed_at: String,
    pub receipt_hash: String,
    pub signature: JsonObject,
}
