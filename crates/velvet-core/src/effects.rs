use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ActionType, Reversibility};

pub const EFFECT_VECTOR_SCHEMA_VERSION: &str = "velvet.effect_vector.v1";
pub const EFFECT_MODEL_VERSION: &str = "velvet.effect_inference.v1";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    ReadOnly,
    ExternalRead,
    InternalWrite,
    ExternalWrite,
    FinancialTransaction,
    CredentialAccess,
    CodeExecution,
    NetworkEgress,
    HumanCommunication,
    DataExport,
    InfrastructureMutation,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    None,
    Reversible,
    Compensatable,
    Irreversible,
    ExternallyVisible,
    Regulated,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    PersonalData,
    Secret,
    Regulated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WriteFootprint {
    pub resource_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_pattern: Option<String>,
    pub operation: String,
    pub blast_radius: String,
    pub rollback_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CostBound {
    pub lower_microusd: u64,
    pub expected_microusd: u64,
    pub upper_microusd: u64,
    pub confidence_bps: u16,
}

impl CostBound {
    pub fn free() -> Self {
        Self {
            lower_microusd: 0,
            expected_microusd: 0,
            upper_microusd: 0,
            confidence_bps: 10_000,
        }
    }

    pub fn conservative_unknown() -> Self {
        Self {
            lower_microusd: 1,
            expected_microusd: 5_000_000,
            upper_microusd: 100_000_000,
            confidence_bps: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LatencyBound {
    pub lower_ms: u64,
    pub expected_ms: u64,
    pub upper_ms: u64,
    pub confidence_bps: u16,
}

impl LatencyBound {
    pub fn low() -> Self {
        Self {
            lower_ms: 0,
            expected_ms: 100,
            upper_ms: 1_000,
            confidence_bps: 9_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RiskBound {
    pub privacy_risk_bps: u16,
    pub integrity_risk_bps: u16,
    pub availability_risk_bps: u16,
    pub financial_risk_bps: u16,
    pub compliance_risk_bps: u16,
    pub confidence_bps: u16,
}

impl RiskBound {
    pub fn low() -> Self {
        Self {
            privacy_risk_bps: 500,
            integrity_risk_bps: 500,
            availability_risk_bps: 500,
            financial_risk_bps: 0,
            compliance_risk_bps: 500,
            confidence_bps: 9_000,
        }
    }

    pub fn high_unknown() -> Self {
        Self {
            privacy_risk_bps: 8_500,
            integrity_risk_bps: 8_500,
            availability_risk_bps: 7_500,
            financial_risk_bps: 8_500,
            compliance_risk_bps: 8_500,
            confidence_bps: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UtilityBound {
    pub lower_bps: i32,
    pub expected_bps: i32,
    pub upper_bps: i32,
    pub confidence_bps: u16,
}

impl UtilityBound {
    pub fn neutral() -> Self {
        Self {
            lower_bps: 0,
            expected_bps: 1_000,
            upper_bps: 2_000,
            confidence_bps: 8_000,
        }
    }

    pub fn direct_answer() -> Self {
        Self {
            lower_bps: 500,
            expected_bps: 3_500,
            upper_bps: 6_000,
            confidence_bps: 8_500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceToSinkFlow {
    pub source_data_class: DataClass,
    pub sink: String,
    pub sink_capability_class: CapabilityClass,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EffectVector {
    pub schema_version: String,
    pub capability_class: CapabilityClass,
    pub side_effect_class: SideEffectClass,
    pub data_classes_read: Vec<DataClass>,
    pub data_classes_written: Vec<DataClass>,
    pub write_footprint: Vec<WriteFootprint>,
    pub cost_bound: CostBound,
    pub latency_bound: LatencyBound,
    pub risk_bound: RiskBound,
    pub utility_bound: UtilityBound,
    pub reversibility: Reversibility,
    pub approval_required: bool,
    pub warrant_required: bool,
    pub budget_required: bool,
    pub source_to_sink_flows: Vec<SourceToSinkFlow>,
    pub model_version: String,
    pub inference_evidence: BTreeMap<String, Value>,
}

impl EffectVector {
    pub fn answer_directly() -> Self {
        Self {
            schema_version: EFFECT_VECTOR_SCHEMA_VERSION.to_string(),
            capability_class: CapabilityClass::ReadOnly,
            side_effect_class: SideEffectClass::None,
            data_classes_read: vec![DataClass::Internal],
            data_classes_written: Vec::new(),
            write_footprint: Vec::new(),
            cost_bound: CostBound::free(),
            latency_bound: LatencyBound::low(),
            risk_bound: RiskBound::low(),
            utility_bound: UtilityBound::direct_answer(),
            reversibility: Reversibility::None,
            approval_required: false,
            warrant_required: false,
            budget_required: false,
            source_to_sink_flows: Vec::new(),
            model_version: EFFECT_MODEL_VERSION.to_string(),
            inference_evidence: BTreeMap::new(),
        }
    }

    pub fn is_high_privilege(&self) -> bool {
        matches!(
            self.capability_class,
            CapabilityClass::Unknown
                | CapabilityClass::ExternalWrite
                | CapabilityClass::FinancialTransaction
                | CapabilityClass::CredentialAccess
                | CapabilityClass::CodeExecution
                | CapabilityClass::DataExport
                | CapabilityClass::InfrastructureMutation
        ) || matches!(
            self.side_effect_class,
            SideEffectClass::Irreversible
                | SideEffectClass::ExternallyVisible
                | SideEffectClass::Regulated
        )
    }
}

pub fn default_effect_for_action(action_type: ActionType) -> EffectVector {
    let mut effect = EffectVector::answer_directly();
    match action_type {
        ActionType::AnswerDirectly => effect,
        ActionType::SearchWeb => {
            effect.capability_class = CapabilityClass::ExternalRead;
            effect.side_effect_class = SideEffectClass::None;
            effect.data_classes_read = vec![DataClass::Public];
            effect.cost_bound = CostBound {
                lower_microusd: 0,
                expected_microusd: 10_000,
                upper_microusd: 100_000,
                confidence_bps: 8_500,
            };
            effect.risk_bound.privacy_risk_bps = 1_500;
            effect
        }
        ActionType::RetrieveContext | ActionType::ReadFile | ActionType::InspectCode => {
            effect.capability_class = CapabilityClass::ReadOnly;
            effect.data_classes_read = vec![DataClass::Internal, DataClass::Confidential];
            effect.risk_bound.privacy_risk_bps = 1_500;
            effect
        }
        ActionType::ExecuteCode => {
            effect.capability_class = CapabilityClass::CodeExecution;
            effect.side_effect_class = SideEffectClass::Irreversible;
            effect.reversibility = Reversibility::Partial;
            effect.approval_required = true;
            effect.warrant_required = true;
            effect.budget_required = true;
            effect.cost_bound = CostBound::conservative_unknown();
            effect.risk_bound = RiskBound::high_unknown();
            effect
        }
        ActionType::CallTool => {
            effect.capability_class = CapabilityClass::Unknown;
            effect.side_effect_class = SideEffectClass::ExternallyVisible;
            effect.reversibility = Reversibility::Partial;
            effect.approval_required = true;
            effect.warrant_required = true;
            effect.budget_required = true;
            effect.cost_bound = CostBound::conservative_unknown();
            effect.risk_bound = RiskBound::high_unknown();
            effect
        }
        ActionType::AskUser => {
            effect.capability_class = CapabilityClass::HumanCommunication;
            effect.side_effect_class = SideEffectClass::ExternallyVisible;
            effect.approval_required = false;
            effect.budget_required = false;
            effect.risk_bound.privacy_risk_bps = 2_000;
            effect
        }
        ActionType::StoreMemory => {
            effect.capability_class = CapabilityClass::InternalWrite;
            effect.side_effect_class = SideEffectClass::Reversible;
            effect.data_classes_read = vec![DataClass::Internal];
            effect.data_classes_written = vec![DataClass::Internal];
            effect.write_footprint = vec![WriteFootprint {
                resource_type: "memory".to_string(),
                resource_id: None,
                resource_pattern: Some("memory:*".to_string()),
                operation: "write".to_string(),
                blast_radius: "tenant".to_string(),
                rollback_profile: "delete_memory_record".to_string(),
            }];
            effect.approval_required = true;
            effect.risk_bound.privacy_risk_bps = 5_000;
            effect
        }
        ActionType::EscalateModel => {
            effect.capability_class = CapabilityClass::ExternalRead;
            effect.side_effect_class = SideEffectClass::ExternallyVisible;
            effect.data_classes_read = vec![DataClass::Internal, DataClass::Confidential];
            effect.budget_required = true;
            effect.cost_bound = CostBound {
                lower_microusd: 1,
                expected_microusd: 50_000,
                upper_microusd: 1_000_000,
                confidence_bps: 8_000,
            };
            effect.risk_bound.privacy_risk_bps = 3_500;
            effect
        }
        ActionType::ConciergeReview => {
            effect.capability_class = CapabilityClass::HumanCommunication;
            effect.side_effect_class = SideEffectClass::ExternallyVisible;
            effect.approval_required = true;
            effect.risk_bound.privacy_risk_bps = 2_000;
            effect
        }
    }
}
