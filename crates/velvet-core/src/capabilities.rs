use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ActionType, CandidateAction, CapabilityClass, DataClass, SideEffectClass, WriteFootprint,
};

pub const CAPABILITY_REGISTRY_SCHEMA_VERSION: &str = "velvet.capability_registry.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityDescriptor {
    pub schema_version: String,
    pub capability_class: CapabilityClass,
    pub side_effect_class: SideEffectClass,
    pub data_classes_read: Vec<DataClass>,
    pub data_classes_written: Vec<DataClass>,
    pub write_footprint: Vec<WriteFootprint>,
    pub approval_required: bool,
    pub warrant_required: bool,
    pub budget_required: bool,
    pub source: String,
}

impl CapabilityDescriptor {
    pub fn unknown(source: impl Into<String>) -> Self {
        Self {
            schema_version: CAPABILITY_REGISTRY_SCHEMA_VERSION.to_string(),
            capability_class: CapabilityClass::Unknown,
            side_effect_class: SideEffectClass::ExternallyVisible,
            data_classes_read: vec![DataClass::Unknown],
            data_classes_written: vec![DataClass::Unknown],
            write_footprint: vec![WriteFootprint {
                resource_type: "unknown".to_string(),
                resource_id: None,
                resource_pattern: Some("*".to_string()),
                operation: "unknown".to_string(),
                blast_radius: "unknown".to_string(),
                rollback_profile: "unknown".to_string(),
            }],
            approval_required: true,
            warrant_required: true,
            budget_required: true,
            source: source.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityRegistry {
    pub tool_capabilities: BTreeMap<String, CapabilityDescriptor>,
}

impl CapabilityRegistry {
    pub fn from_state(state: &serde_json::Value) -> Self {
        let mut registry = Self::default();
        if let Some(values) = state
            .get("capability_registry")
            .and_then(|value| value.get("tools"))
            .and_then(serde_json::Value::as_object)
        {
            for (key, value) in values {
                if let Ok(descriptor) =
                    serde_json::from_value::<CapabilityDescriptor>(value.clone())
                {
                    registry.tool_capabilities.insert(key.clone(), descriptor);
                }
            }
        }
        registry
    }

    pub fn descriptor_for(&self, candidate: &CandidateAction) -> CapabilityDescriptor {
        if candidate.action_type == ActionType::CallTool {
            if let Some(tool_key) = tool_key(candidate) {
                if let Some(descriptor) = self.tool_capabilities.get(&tool_key) {
                    return descriptor.clone();
                }
                return descriptor_from_candidate_metadata(candidate)
                    .unwrap_or_else(|| CapabilityDescriptor::unknown(format!("mcp:{tool_key}")));
            }
            return descriptor_from_candidate_metadata(candidate)
                .unwrap_or_else(|| CapabilityDescriptor::unknown("mcp:<unknown>"));
        }
        builtin_descriptor(candidate.action_type)
    }
}

pub fn tool_key(candidate: &CandidateAction) -> Option<String> {
    candidate
        .metadata
        .get("mcp_tool_key")
        .or_else(|| candidate.parameters.get("tool_name"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            let server = candidate
                .metadata
                .get("mcp_server")
                .or_else(|| candidate.parameters.get("mcp_server"))
                .and_then(serde_json::Value::as_str)?;
            let tool = candidate
                .metadata
                .get("mcp_tool")
                .or_else(|| candidate.parameters.get("mcp_tool"))
                .and_then(serde_json::Value::as_str)?;
            Some(format!("{server}/{tool}"))
        })
}

fn descriptor_from_candidate_metadata(candidate: &CandidateAction) -> Option<CapabilityDescriptor> {
    let capability_class = parse_capability_class(
        candidate
            .metadata
            .get("capability_class")
            .and_then(serde_json::Value::as_str),
    )?;
    let destructive = candidate
        .metadata
        .get("destructive")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let approval_tier = candidate
        .metadata
        .get("approval_tier")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("concierge_review");
    let side_effect_class = if destructive {
        SideEffectClass::Irreversible
    } else if matches!(
        capability_class,
        CapabilityClass::ExternalWrite
            | CapabilityClass::FinancialTransaction
            | CapabilityClass::HumanCommunication
            | CapabilityClass::DataExport
            | CapabilityClass::InfrastructureMutation
    ) {
        SideEffectClass::ExternallyVisible
    } else {
        SideEffectClass::None
    };
    Some(CapabilityDescriptor {
        schema_version: CAPABILITY_REGISTRY_SCHEMA_VERSION.to_string(),
        capability_class,
        side_effect_class,
        data_classes_read: vec![data_class_from_metadata(candidate)],
        data_classes_written: if writes_data(capability_class) {
            vec![data_class_from_metadata(candidate)]
        } else {
            Vec::new()
        },
        write_footprint: if writes_data(capability_class) {
            vec![WriteFootprint {
                resource_type: "mcp_tool".to_string(),
                resource_id: tool_key(candidate),
                resource_pattern: None,
                operation: candidate
                    .metadata
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("call")
                    .to_string(),
                blast_radius: if destructive { "unknown" } else { "tool" }.to_string(),
                rollback_profile: if destructive {
                    "unknown".to_string()
                } else {
                    "provider_defined".to_string()
                },
            }]
        } else {
            Vec::new()
        },
        approval_required: approval_tier != "auto_approve" || destructive,
        warrant_required: destructive || capability_class != CapabilityClass::ReadOnly,
        budget_required: candidate
            .metadata
            .get("budget_affecting")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || (!candidate
                .metadata
                .get("non_budget_affecting")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                && !candidate.metadata.contains_key("usd_estimate")),
        source: "candidate_metadata".to_string(),
    })
}

fn builtin_descriptor(action_type: ActionType) -> CapabilityDescriptor {
    use CapabilityClass as C;
    use SideEffectClass as S;
    let (capability_class, side_effect_class, approval_required, warrant_required, budget_required) =
        match action_type {
            ActionType::AnswerDirectly => (C::ReadOnly, S::None, false, false, false),
            ActionType::SearchWeb => (C::ExternalRead, S::None, false, false, true),
            ActionType::RetrieveContext | ActionType::ReadFile | ActionType::InspectCode => {
                (C::ReadOnly, S::None, false, false, false)
            }
            ActionType::ExecuteCode => (C::CodeExecution, S::Irreversible, true, true, true),
            ActionType::CallTool => (C::Unknown, S::ExternallyVisible, true, true, true),
            ActionType::AskUser => (
                C::HumanCommunication,
                S::ExternallyVisible,
                false,
                false,
                false,
            ),
            ActionType::StoreMemory => (C::InternalWrite, S::Reversible, true, true, false),
            ActionType::EscalateModel => {
                (C::ExternalRead, S::ExternallyVisible, false, false, true)
            }
            ActionType::ConciergeReview => (
                C::HumanCommunication,
                S::ExternallyVisible,
                true,
                false,
                false,
            ),
        };
    CapabilityDescriptor {
        schema_version: CAPABILITY_REGISTRY_SCHEMA_VERSION.to_string(),
        capability_class,
        side_effect_class,
        data_classes_read: vec![DataClass::Internal],
        data_classes_written: if writes_data(capability_class) {
            vec![DataClass::Internal]
        } else {
            Vec::new()
        },
        write_footprint: Vec::new(),
        approval_required,
        warrant_required,
        budget_required,
        source: "builtin".to_string(),
    }
}

fn writes_data(capability_class: CapabilityClass) -> bool {
    matches!(
        capability_class,
        CapabilityClass::InternalWrite
            | CapabilityClass::ExternalWrite
            | CapabilityClass::FinancialTransaction
            | CapabilityClass::HumanCommunication
            | CapabilityClass::DataExport
            | CapabilityClass::InfrastructureMutation
            | CapabilityClass::Unknown
    )
}

fn data_class_from_metadata(candidate: &CandidateAction) -> DataClass {
    candidate
        .metadata
        .get("data_class")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_data_class)
        .unwrap_or(DataClass::Unknown)
}

fn parse_capability_class(value: Option<&str>) -> Option<CapabilityClass> {
    match value?.to_ascii_lowercase().as_str() {
        "read_only" | "readonly" => Some(CapabilityClass::ReadOnly),
        "external_read" => Some(CapabilityClass::ExternalRead),
        "internal_write" => Some(CapabilityClass::InternalWrite),
        "external_write" => Some(CapabilityClass::ExternalWrite),
        "financial_transaction" | "financial" => Some(CapabilityClass::FinancialTransaction),
        "credential_access" => Some(CapabilityClass::CredentialAccess),
        "code_execution" => Some(CapabilityClass::CodeExecution),
        "network_egress" => Some(CapabilityClass::NetworkEgress),
        "human_communication" => Some(CapabilityClass::HumanCommunication),
        "data_export" => Some(CapabilityClass::DataExport),
        "infrastructure_mutation" => Some(CapabilityClass::InfrastructureMutation),
        "unknown" => Some(CapabilityClass::Unknown),
        _ => None,
    }
}

fn parse_data_class(value: &str) -> Option<DataClass> {
    match value.to_ascii_lowercase().as_str() {
        "public" => Some(DataClass::Public),
        "internal" => Some(DataClass::Internal),
        "confidential" => Some(DataClass::Confidential),
        "personal_data" | "personal" | "pii" => Some(DataClass::PersonalData),
        "secret" => Some(DataClass::Secret),
        "regulated" => Some(DataClass::Regulated),
        "unknown" => Some(DataClass::Unknown),
        _ => None,
    }
}
