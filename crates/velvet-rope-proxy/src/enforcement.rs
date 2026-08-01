use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value, json};
use velvet_core::{
    ActionType, CandidateAction, CandidateDecision, CandidateSource, ConstraintSeverity,
    DecisionType, ExecutionPermit, JsonObject, PolicyGraph,
    SIGNATURE_SCHEMA_VERSION as CORE_SIGNATURE_SCHEMA_VERSION, SignatureBlock, normalize_action_v1,
    route_with_policy_graph_and_thread, signing_message_bytes,
};

use crate::approvals::{
    ApprovalReceipt, ApprovalRequest, ApprovalTier, RiskClass, ToolApproval,
    TrustedApprovalReceiptKey,
};
use crate::config::{
    BoundedMethodDisposition, IdentityConfig, MethodDispositionConfig, ProxyConfig,
    SchemaDriftAction,
};
use crate::constants::{
    APPROVAL_RECEIPT_SCHEMA_VERSION, INVENTORY_SCHEMA_VERSION, MCP_SPEC_TARGET,
};
use crate::inventory::{InventoryEntry, InventoryStatus, RedactionSummary, ToolInventory};
use crate::ledger::{
    OapLedgerRecord, WarrantV1, append_jsonl, approval_receipt_hash,
    approval_receipt_id_seen_in_ledger, arguments_hash_hex_from_request, canonical_json,
    decision_string, fallback_maxde_config_for_decision, hex_decode, jsonrpc_request_id,
    max_de_requirement_for_call, parse_time, policy_hash_hex, request_hash_hex, session_id,
    sha256_hex, sign_warrant_for_config, value_hash, verdict_requirement_for_call,
};
use crate::oap::{
    OapActionContext, OapArtifacts, OapDecisionInput, OapReason, VELVET_OAP_BOUNDARY_STATEMENT,
    build_oap_artifacts,
};
use crate::policy_bundle::PolicyBundleProof;
use crate::verdicts::{VERDICT_SAFE_KILL, verify_verdict_certificate};

#[derive(Debug, Clone)]
pub struct AdmissionOutcome {
    pub identity: IdentityConfig,
    pub decision: String,
    pub reason: String,
    pub inventory_status: InventoryEntry,
    pub oap: OapArtifacts,
    pub warrant: WarrantV1,
    pub max_de_certificate_required: bool,
    pub max_de_requirement_reason: String,
    pub verdict_certificate_required: bool,
    pub verdict_requirement_reason: String,
    pub verdict_status: Option<String>,
    pub verdict_certificate_hash: Option<String>,
    pub approval_request: Option<ApprovalRequest>,
    pub approval_receipt: Option<ApprovalReceipt>,
    pub redaction_summary: RedactionSummary,
    pub decision_latency_ms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundedMethodGroup {
    Resources,
    Prompts,
    Tasks,
    Notifications,
    Unknown,
}

impl BoundedMethodGroup {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::Prompts => "prompts",
            Self::Tasks => "tasks",
            Self::Notifications => "notifications",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BoundedMethodDecision {
    pub(crate) method: String,
    pub(crate) group: BoundedMethodGroup,
    pub(crate) disposition: BoundedMethodDisposition,
    pub(crate) source: String,
    pub(crate) reason: String,
    pub(crate) redaction_summary: RedactionSummary,
    pub(crate) decision_latency_ms: u128,
}

/// Integration seam for epoch-bound Execution Permits.
///
/// This is intentionally hidden from the stable public API. Closure-aware callers
/// must resolve the current epoch from the signed `subgoal_id_hash` embedded in
/// the verified permit, never from an unsigned permit-id side table.
#[doc(hidden)]
pub trait PermitEpochProvider {
    fn current_epoch_for_subgoal_hash(&self, subgoal_id_hash: &str) -> Result<i64>;
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClockOnlyPermitEpochProvider;

impl PermitEpochProvider for WallClockOnlyPermitEpochProvider {
    fn current_epoch_for_subgoal_hash(&self, _subgoal_id_hash: &str) -> Result<i64> {
        bail!("logical-step execution permit requires an epoch provider")
    }
}

#[doc(hidden)]
pub fn verify_permit_logical_step(
    permit: &ExecutionPermit,
    epoch_provider: &dyn PermitEpochProvider,
) -> Result<()> {
    match (
        permit.validity.issued_at_logical_step,
        permit.validity.expires_at_logical_step,
    ) {
        (None, None) => Ok(()),
        (Some(_), None) => bail!("execution permit has incomplete logical-step validity"),
        (None, Some(_)) => bail!("execution permit has incomplete logical-step validity"),
        (Some(issued_epoch), Some(expected_epoch)) => {
            if issued_epoch != expected_epoch {
                bail!("execution permit logical-step validity interval is malformed");
            }
            if expected_epoch < 0 {
                bail!("execution permit logical step cannot be negative");
            }
            let subgoal_id_hash = permit
                .scope
                .subgoal_id_hash
                .as_deref()
                .ok_or_else(|| anyhow!("logical-step permit missing signed subgoal binding"))?;
            let current_epoch = epoch_provider.current_epoch_for_subgoal_hash(subgoal_id_hash)?;
            if current_epoch != expected_epoch {
                bail!("execution permit logical step expired");
            }
            Ok(())
        }
    }
}

pub fn admit_tool_call(
    config: &ProxyConfig,
    bundle_proof: &PolicyBundleProof,
    policy_graph: &Arc<PolicyGraph>,
    inventory: &ToolInventory,
    request: &Value,
    used_approval_receipts: &BTreeSet<String>,
) -> Result<AdmissionOutcome> {
    let started = Instant::now();
    let (name, arguments) = call_params(request)?;
    ensure_request_within_limits(config, request, &arguments)?;
    let redaction_summary = redaction_summary_for_value(request);
    let inventory_status = inventory.entry_for_call(config, &name);
    if inventory_status.status != InventoryStatus::Approved {
        let decision = if inventory_status.status == InventoryStatus::Drifted
            && config.schema_drift_action == SchemaDriftAction::Escalate
        {
            "escalate"
        } else {
            "block"
        };
        let reason = inventory_status.status.fail_closed_reason().to_string();
        let approval_request = if decision == "escalate" {
            Some(approval_request_for(
                config,
                &inventory_status,
                request,
                bundle_proof,
                &reason,
            )?)
        } else {
            None
        };
        let mut warrant = WarrantV1::manual(
            config,
            &inventory_status,
            decision,
            &reason,
            bundle_proof,
            request,
            approval_request
                .as_ref()
                .map(|request| request.approval_request_id.clone()),
        )?;
        sign_warrant_for_config(config, &mut warrant)?;
        let (max_de_certificate_required, max_de_requirement_reason) =
            max_de_requirement_for_call(config, &inventory_status, None, decision);
        let (verdict_certificate_required, verdict_requirement_reason) =
            verdict_requirement_for_call(config, config.tool_by_name(&name));
        let max_de_config =
            max_de_certificate_required.then(|| fallback_maxde_config_for_decision(decision));
        let max_de_evidence = max_de_config
            .as_ref()
            .map(|config| config.to_core_evidence(&inventory_status.tool_key))
            .transpose()?;
        let policy_hash = policy_hash_hex(bundle_proof);
        let request_hash = request_hash_hex(request);
        let arguments_hash = arguments_hash_hex_from_request(request)?;
        let canonical_action_hash = canonical_action_hash_for_mcp_request(config, request)?;
        let tool_schema_hash = inventory_status
            .schema_hash
            .clone()
            .or_else(|| inventory_status.approved_schema_hash.clone())
            .unwrap_or_else(|| {
                value_hash(&json!({"tool_name": inventory_status.tool_key.clone()}))
            });
        let action_context = OapActionContext {
            request,
            policy_hash: &policy_hash,
            policy_version: &config.policy.chain,
            tool_key: &inventory_status.tool_key,
            tool_name: &name,
            tool_schema_hash: &tool_schema_hash,
            arguments_hash: &arguments_hash,
            request_hash: &request_hash,
            canonical_action_hash: &canonical_action_hash,
            mcp_method: "tools/call",
            max_de_certificate_required,
            max_de_requirement_reason: &max_de_requirement_reason,
        };
        let oap = build_oap_artifacts(
            &config.oap,
            OapDecisionInput {
                identity: &config.identity,
                tools: &config.tools,
                allow: false,
                reasons: oap_reasons_for_decision(decision, &reason, None),
                max_de_config: max_de_config.as_ref(),
                max_de_evidence: max_de_evidence.as_ref(),
                action_context: Some(action_context),
            },
        )?;
        return Ok(AdmissionOutcome {
            identity: config.identity.clone(),
            decision: decision.to_string(),
            reason,
            inventory_status,
            oap,
            warrant,
            max_de_certificate_required,
            max_de_requirement_reason,
            verdict_certificate_required,
            verdict_requirement_reason,
            verdict_status: None,
            verdict_certificate_hash: None,
            approval_request,
            approval_receipt: None,
            redaction_summary,
            decision_latency_ms: started.elapsed().as_millis(),
        });
    }

    let approval = config
        .tool_by_name(&name)
        .ok_or_else(|| anyhow!("approved inventory entry has no config for {name}"))?;
    ensure_subject_allowed(config, approval)?;
    validate_arguments_against_schema(inventory, &name, &arguments)?;
    let candidate = candidate_for_tool_call(approval, &arguments)?;
    let state = state_for_tool_call(approval, &arguments, request);
    let result = route_with_policy_graph_and_thread(
        &state,
        &[candidate],
        policy_graph,
        &config.policy.chain,
        None,
        None,
    )
    .map_err(anyhow::Error::msg)?;
    if let Some(path) = &config.thread_path {
        append_jsonl(path, &result.thread)?;
    }
    let selected = result
        .decision
        .candidate_decisions
        .iter()
        .find(|candidate| candidate.action_type == ActionType::CallTool)
        .or_else(|| result.decision.candidate_decisions.first())
        .ok_or_else(|| anyhow!("route decision did not evaluate the tool candidate"))?;
    let core_decision = selected.decision;
    let routed_decision = proxy_decision_for_tool(approval, selected);
    let initial_decision = decision_string(routed_decision).to_string();
    let max_de_decision = initial_decision.clone();
    let mut approval_request = if matches!(
        routed_decision,
        DecisionType::AskApproval | DecisionType::Escalate | DecisionType::Delay
    ) {
        Some(approval_request_for(
            config,
            &inventory_status,
            request,
            bundle_proof,
            &selected.reason,
        )?)
    } else {
        None
    };
    let approval_receipt = approval_receipt_from_request_or_config(config, request)?;
    let approved_receipt = if let Some(receipt) = approval_receipt {
        if !matches!(
            routed_decision,
            DecisionType::AskApproval | DecisionType::Escalate | DecisionType::Delay
        ) {
            bail!("approval receipt cannot override current routed decision");
        }
        let Some(generated_request) = approval_request.as_ref() else {
            bail!("approval receipt cannot execute without a generated approval request");
        };
        if receipt.approval_request_id != generated_request.approval_request_id {
            bail!("approval receipt approval request does not match generated request");
        }
        validate_approval_receipt(
            config,
            &receipt,
            &inventory_status,
            request,
            bundle_proof,
            used_approval_receipts,
        )?;
        Some(receipt)
    } else {
        None
    };
    let budget_failed = budget_constraint_failed(selected);
    let effective_routed_decision =
        if approved_receipt.is_some() && (core_decision == DecisionType::Block || budget_failed) {
            DecisionType::Block
        } else {
            routed_decision
        };
    let mut routed_for_tool = result.decision.clone();
    routed_for_tool.action_type = Some(selected.action_type);
    routed_for_tool.decision = effective_routed_decision;
    routed_for_tool.reason = selected.reason.clone();
    let mut warrant = WarrantV1::routed(
        config,
        approval,
        &inventory_status,
        &routed_for_tool,
        selected,
        bundle_proof,
        request,
        approval_request
            .as_ref()
            .map(|request| request.approval_request_id.clone()),
        approved_receipt.as_ref(),
    )?;
    sign_warrant_for_config(config, &mut warrant)?;
    let mut decision =
        if approved_receipt.is_some() && core_decision != DecisionType::Block && !budget_failed {
            "execute".to_string()
        } else {
            decision_string(effective_routed_decision).to_string()
        };
    let mut reason = if let Some(receipt) = &approved_receipt {
        if core_decision == DecisionType::Block {
            format!(
                "Approval receipt {} was validated, but hard admission constraints still block execution: {}",
                receipt.approval_receipt_id, selected.reason
            )
        } else {
            format!(
                "Approved by {} with receipt {}.",
                receipt.approver_id, receipt.approval_receipt_id
            )
        }
    } else {
        selected.reason.clone()
    };
    // Verdict Certificate gate: irreversible (destructive/high-risk) calls
    // that would otherwise execute must present a fresh, Velvet-signed
    // safe_kill verdict. No verdict math runs here; only signature, schema
    // consts, purpose, and expiry are checked. Missing/invalid certificates
    // fail closed; an expired certificate routes to the approval path for
    // re-certification instead of hard-denying.
    let (verdict_certificate_required, verdict_requirement_reason) =
        verdict_requirement_for_call(config, Some(approval));
    let mut verdict_status: Option<String> = None;
    let mut verdict_certificate_hash: Option<String> = None;
    if verdict_certificate_required && decision == "execute" {
        match verdict_certificate_from_request(request) {
            None => {
                decision = "block".to_string();
                reason = "verdict_certificate_missing".to_string();
                verdict_status = Some("missing".to_string());
            }
            Some(certificate) => match verify_verdict_certificate(&certificate, config, Utc::now())
            {
                Err(_) => {
                    decision = "block".to_string();
                    reason = "verdict_certificate_invalid".to_string();
                    verdict_status = Some("invalid".to_string());
                }
                Ok(check) if check.tenant_id != config.identity.tenant_id => {
                    decision = "block".to_string();
                    reason = "verdict_certificate_invalid".to_string();
                    verdict_status = Some("invalid".to_string());
                }
                Ok(check) if check.expired => {
                    decision = "escalate".to_string();
                    reason = "verdict_expired_recertification_required".to_string();
                    verdict_status = Some("expired".to_string());
                    verdict_certificate_hash = Some(check.certificate_hash);
                    if approval_request.is_none() {
                        approval_request = Some(approval_request_for(
                            config,
                            &inventory_status,
                            request,
                            bundle_proof,
                            &reason,
                        )?);
                    }
                }
                Ok(check) if check.verdict != VERDICT_SAFE_KILL => {
                    decision = "block".to_string();
                    reason = format!("verdict_not_safe_kill:{}", check.verdict);
                    verdict_status = Some(format!("not_safe_kill:{}", check.verdict));
                    verdict_certificate_hash = Some(check.certificate_hash);
                }
                Ok(check) => {
                    verdict_status = Some(VERDICT_SAFE_KILL.to_string());
                    verdict_certificate_hash = Some(check.certificate_hash);
                }
            },
        }
    }
    let (max_de_certificate_required, max_de_requirement_reason) =
        max_de_requirement_for_call(config, &inventory_status, Some(approval), &max_de_decision);
    if max_de_certificate_required
        && (approval.max_de.is_none() || selected.final_candidate.certificate.is_none())
    {
        bail!(
            "Max-DE certificate is required for {} but no valid Max-DE config was available",
            inventory_status.tool_key
        );
    }
    let policy_hash = policy_hash_hex(bundle_proof);
    let request_hash = request_hash_hex(request);
    let arguments_hash = arguments_hash_hex_from_request(request)?;
    let canonical_action_hash = canonical_action_hash_for_mcp_request(config, request)?;
    let tool_schema_hash = inventory_status
        .schema_hash
        .clone()
        .unwrap_or_else(|| approval.approved_schema_hash.clone());
    let action_context = OapActionContext {
        request,
        policy_hash: &policy_hash,
        policy_version: &config.policy.chain,
        tool_key: &inventory_status.tool_key,
        tool_name: &name,
        tool_schema_hash: &tool_schema_hash,
        arguments_hash: &arguments_hash,
        request_hash: &request_hash,
        canonical_action_hash: &canonical_action_hash,
        mcp_method: "tools/call",
        max_de_certificate_required,
        max_de_requirement_reason: &max_de_requirement_reason,
    };
    let oap = build_oap_artifacts(
        &config.oap,
        OapDecisionInput {
            identity: &config.identity,
            tools: &config.tools,
            allow: decision == "execute",
            reasons: oap_reasons_for_decision(
                &decision,
                &reason,
                selected.short_circuit.as_deref(),
            ),
            max_de_config: approval.max_de.as_ref(),
            max_de_evidence: selected.final_candidate.certificate.as_ref(),
            action_context: Some(action_context),
        },
    )?;
    Ok(AdmissionOutcome {
        identity: config.identity.clone(),
        decision,
        reason,
        inventory_status,
        oap,
        warrant,
        max_de_certificate_required,
        max_de_requirement_reason,
        verdict_certificate_required,
        verdict_requirement_reason,
        verdict_status,
        verdict_certificate_hash,
        approval_request,
        approval_receipt: approved_receipt,
        redaction_summary,
        decision_latency_ms: started.elapsed().as_millis(),
    })
}

fn proxy_decision_for_tool(approval: &ToolApproval, selected: &CandidateDecision) -> DecisionType {
    if selected.decision == DecisionType::Block && reviewable_approval_missing(approval, selected) {
        DecisionType::Escalate
    } else {
        selected.decision
    }
}

fn reviewable_approval_missing(approval: &ToolApproval, selected: &CandidateDecision) -> bool {
    if !matches!(approval.approval_tier, ApprovalTier::ConciergeReview) || approval.destructive {
        return false;
    }
    selected.admission_trace.as_ref().is_some_and(|trace| {
        trace.hard_constraints.iter().any(|constraint| {
            !constraint.passed
                && constraint.constraint_id == "approval_valid"
                && constraint.reason_code == "approval_required"
                && constraint.severity == ConstraintSeverity::Defer
        })
    })
}

#[allow(dead_code)]
fn hard_admission_block(selected: &CandidateDecision) -> bool {
    selected.admission_trace.as_ref().is_some_and(|trace| {
        trace.hard_constraints.iter().any(|constraint| {
            !constraint.passed && constraint.severity == ConstraintSeverity::Block
        })
    })
}

fn budget_constraint_failed(selected: &CandidateDecision) -> bool {
    selected.admission_trace.as_ref().is_some_and(|trace| {
        trace
            .hard_constraints
            .iter()
            .any(|constraint| !constraint.passed && constraint.constraint_id == "budget_reserved")
    })
}

pub(crate) fn is_lifecycle_method(method: &str) -> bool {
    matches!(method, "initialize" | "notifications/initialized" | "ping")
}

pub(crate) fn bounded_method_group(method: &str) -> BoundedMethodGroup {
    if method.starts_with("resources/") {
        BoundedMethodGroup::Resources
    } else if method.starts_with("prompts/") {
        BoundedMethodGroup::Prompts
    } else if method.starts_with("tasks/") {
        BoundedMethodGroup::Tasks
    } else if method.starts_with("notifications/") {
        BoundedMethodGroup::Notifications
    } else {
        BoundedMethodGroup::Unknown
    }
}

pub(crate) fn group_disposition_config(
    config: &MethodDispositionConfig,
    group: BoundedMethodGroup,
) -> Option<BoundedMethodDisposition> {
    match group {
        BoundedMethodGroup::Resources => config.resources,
        BoundedMethodGroup::Prompts => config.prompts,
        BoundedMethodGroup::Tasks => config.tasks,
        BoundedMethodGroup::Notifications => config.notifications,
        BoundedMethodGroup::Unknown => config.unknown,
    }
}

pub(crate) fn bounded_method_decision(
    config: &ProxyConfig,
    request: &Value,
) -> BoundedMethodDecision {
    let started = Instant::now();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())
        .unwrap_or("<missing>")
        .to_string();
    let group = bounded_method_group(&method);
    let (disposition, source) = if let Some(disposition) =
        config.method_dispositions.methods.get(&method).copied()
    {
        (disposition, format!("configured_method:{method}"))
    } else if let Some(disposition) = group_disposition_config(&config.method_dispositions, group) {
        (disposition, format!("configured_group:{}", group.as_str()))
    } else {
        (
            BoundedMethodDisposition::Block,
            "strict_default".to_string(),
        )
    };
    let reason = match disposition {
        BoundedMethodDisposition::AllowPassthrough => format!(
            "Bounded MCP method {method} is explicitly configured for recorded passthrough."
        ),
        BoundedMethodDisposition::Block => {
            format!("Bounded MCP method {method} is blocked by explicit surface governance.")
        }
        BoundedMethodDisposition::Escalate => {
            format!("Bounded MCP method {method} requires review by explicit surface governance.")
        }
    };
    BoundedMethodDecision {
        method,
        group,
        disposition,
        source,
        reason,
        redaction_summary: redaction_summary_for_value(request),
        decision_latency_ms: started.elapsed().as_millis(),
    }
}
pub(crate) fn candidate_for_tool_call(
    approval: &ToolApproval,
    arguments: &Value,
) -> Result<CandidateAction> {
    let mut risk_overrides = BTreeMap::new();
    risk_overrides.insert("tool_risk".to_string(), approval.risk_class.weight());
    risk_overrides.insert(
        "external_side_effect_risk".to_string(),
        approval.risk_class.weight(),
    );
    risk_overrides.insert(
        "irreversibility".to_string(),
        if approval.destructive { 0.95 } else { 0.15 },
    );
    let mut metadata = JsonObject::new();
    metadata.insert("mcp_server".to_string(), json!(approval.server));
    metadata.insert("mcp_tool".to_string(), json!(approval.name));
    metadata.insert("mcp_tool_key".to_string(), json!(approval.key()));
    metadata.insert(
        "risk_class".to_string(),
        json!(approval.risk_class.as_str()),
    );
    metadata.insert(
        "approval_tier".to_string(),
        json!(approval.approval_tier.as_str()),
    );
    metadata.insert("destructive".to_string(), json!(approval.destructive));
    metadata.insert(
        "tool_schema_hash".to_string(),
        json!(approval.approved_schema_hash),
    );
    metadata.insert(
        "capability_class".to_string(),
        json!(capability_class_for_tool_approval(approval)),
    );
    metadata.insert(
        "side_effect_class".to_string(),
        json!(side_effect_class_for_tool_approval(approval)),
    );
    if let Some(usd_estimate) = approval.usd_estimate
        && usd_estimate > 0.0
    {
        metadata.insert("usd_estimate".to_string(), json!(usd_estimate));
        metadata.insert("budget_affecting".to_string(), json!(true));
    } else {
        if explicitly_non_budget_affecting(approval) {
            metadata.insert("budget_affecting".to_string(), json!(false));
            metadata.insert("non_budget_affecting".to_string(), json!(true));
        } else {
            metadata.insert("budget_affecting".to_string(), json!(true));
            metadata.insert("cost_unknown".to_string(), json!(true));
        }
    }
    for (key, value) in &approval.metadata {
        metadata.insert(key.clone(), value.clone());
    }
    let mut parameters = JsonObject::new();
    parameters.insert("tool_name".to_string(), json!(approval.key()));
    parameters.insert("arguments".to_string(), arguments.clone());
    parameters.insert("mcp_server".to_string(), json!(approval.server));
    parameters.insert("mcp_tool".to_string(), json!(approval.name));
    let certificate = approval
        .max_de
        .as_ref()
        .map(|config| config.to_core_evidence(&approval.key()))
        .transpose()?;
    Ok(CandidateAction {
        action_type: ActionType::CallTool,
        description: format!("MCP tool call {}", approval.key()),
        certificate,
        budget_certificate: None,
        expected_improvement: Some(approval.expected_improvement),
        novelty: Some(approval.novelty),
        confidence: Some(approval.confidence),
        cost_overrides: BTreeMap::new(),
        risk_overrides,
        metadata,
        source: CandidateSource::Host,
        parameters,
    })
}

fn capability_class_for_tool_approval(approval: &ToolApproval) -> &'static str {
    if let Some(value) = approval
        .metadata
        .get("capability_class")
        .and_then(Value::as_str)
    {
        return match value {
            "read_only" => "read_only",
            "external_read" => "external_read",
            "internal_write" => "internal_write",
            "external_write" => "external_write",
            "financial_transaction" => "financial_transaction",
            "credential_access" => "credential_access",
            "code_execution" => "code_execution",
            "network_egress" => "network_egress",
            "human_communication" => "human_communication",
            "data_export" => "data_export",
            "infrastructure_mutation" => "infrastructure_mutation",
            _ => "unknown",
        };
    }
    if approval.destructive || matches!(approval.approval_tier, ApprovalTier::Blocked) {
        "infrastructure_mutation"
    } else if approval.usd_estimate.is_some_and(|value| value > 0.0) {
        "external_write"
    } else if matches!(approval.risk_class, RiskClass::Low)
        && matches!(approval.approval_tier, ApprovalTier::AutoApprove)
    {
        "read_only"
    } else {
        "unknown"
    }
}

fn side_effect_class_for_tool_approval(approval: &ToolApproval) -> &'static str {
    if approval.destructive || matches!(approval.approval_tier, ApprovalTier::Blocked) {
        "irreversible"
    } else if approval.usd_estimate.is_some_and(|value| value > 0.0) {
        "externally_visible"
    } else {
        "none"
    }
}

fn explicitly_non_budget_affecting(approval: &ToolApproval) -> bool {
    approval
        .metadata
        .get("non_budget_affecting")
        .and_then(Value::as_bool)
        .unwrap_or({
            matches!(approval.risk_class, RiskClass::Low)
                && matches!(approval.approval_tier, ApprovalTier::AutoApprove)
        })
}

pub(crate) fn state_for_tool_call(
    approval: &ToolApproval,
    arguments: &Value,
    request: &Value,
) -> Value {
    json!({
        "tool_call_requested": true,
        "user_request": request.pointer("/params/_meta/user_request").and_then(Value::as_str).unwrap_or(""),
        "mcp": {
            "server": approval.server,
            "tool": approval.name,
            "tool_key": approval.key(),
        },
        "tool_arguments": arguments,
    })
}

pub(crate) fn call_params(request: &Value) -> Result<(String, Value)> {
    let params = request
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("tools/call request requires object params"))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tools/call request requires params.name"))?
        .to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok((name, arguments))
}

pub(crate) fn canonical_action_hash_for_mcp_request(
    config: &ProxyConfig,
    request: &Value,
) -> Result<String> {
    let (name, arguments) = call_params(request)?;
    let proposal = json!({
        "surface": "mcp",
        "server": config.upstream.server,
        "tool": name,
        "arguments": arguments,
        "tenant_id": config.identity.tenant_id,
        "environment": config.identity.environment,
        "actor_id": config.identity.subject_id,
        "agent_id": config.identity.agent_id,
        "session_id": session_id(config, request),
        "request_id": jsonrpc_request_id(request),
    });
    let contract = json!({
        "contract_version": "velvet.contract.v1",
        "policy_version": config.policy.chain,
    });
    let digest = normalize_action_v1(&proposal, Some(&contract))
        .map_err(|error| anyhow!(error.to_string()))?
        .canonical_action_hash();
    Ok(format!("sha256:{digest}"))
}

pub(crate) fn ensure_request_within_limits(
    config: &ProxyConfig,
    request: &Value,
    arguments: &Value,
) -> Result<()> {
    let request_bytes = serde_json::to_vec(request)?;
    if request_bytes.len() > config.limits.max_request_bytes {
        bail!("request exceeds configured size limit");
    }
    let argument_bytes = serde_json::to_vec(arguments)?;
    if argument_bytes.len() > config.limits.max_arguments_bytes {
        bail!("arguments exceed configured size limit");
    }
    Ok(())
}

pub(crate) fn ensure_subject_allowed(config: &ProxyConfig, approval: &ToolApproval) -> Result<()> {
    if approval.allowed_subjects.is_empty() {
        return Ok(());
    }
    let subject = config
        .identity
        .subject_id
        .as_ref()
        .ok_or_else(|| anyhow!("auth context is missing for protected tool"))?;
    if approval
        .allowed_subjects
        .iter()
        .any(|allowed| allowed == subject)
    {
        Ok(())
    } else {
        bail!("subject is not authorized for tool {}", approval.key())
    }
}

pub(crate) fn validate_arguments_against_schema(
    inventory: &ToolInventory,
    name: &str,
    arguments: &Value,
) -> Result<()> {
    let Some(tool) = inventory.upstream_tools.get(name) else {
        bail!("tool schema unavailable for argument validation");
    };
    let Some(schema) = tool.get("inputSchema") else {
        return Ok(());
    };
    validate_schema_fragment(schema, arguments, "$")
}

pub(crate) fn validate_schema_fragment(schema: &Value, value: &Value, path: &str) -> Result<()> {
    for keyword in [
        "pattern",
        "format",
        "oneOf",
        "anyOf",
        "allOf",
        "not",
        "if",
        "then",
        "else",
        "contains",
        "dependentSchemas",
        "patternProperties",
        "propertyNames",
        "uniqueItems",
    ] {
        if schema.get(keyword).is_some() {
            bail!("{path} uses unsupported JSON Schema keyword {keyword}");
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|item| item == value)
    {
        bail!("{path} is not one of the allowed enum values");
    }
    if let Some(expected) = schema.get("const")
        && expected != value
    {
        bail!("{path} does not match const value");
    }
    let schema_type = schema.get("type").and_then(Value::as_str);
    match schema_type {
        Some("object") => {
            let Some(object) = value.as_object() else {
                bail!("{path} must be an object");
            };
            if let Some(min_properties) = schema.get("minProperties").and_then(Value::as_u64)
                && object.len() < min_properties as usize
            {
                bail!("{path} has fewer than minProperties");
            }
            if let Some(max_properties) = schema.get("maxProperties").and_then(Value::as_u64)
                && object.len() > max_properties as usize
            {
                bail!("{path} exceeds maxProperties");
            }
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for item in required {
                    let Some(key) = item.as_str() else {
                        continue;
                    };
                    if !object.contains_key(key) {
                        bail!("{path}.{key} is required");
                    }
                }
            }
            let properties = schema.get("properties").and_then(Value::as_object);
            if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                && let Some(properties) = properties
            {
                for key in object.keys() {
                    if !properties.contains_key(key) {
                        bail!("{path}.{key} is not allowed by schema");
                    }
                }
            }
            if let Some(properties) = properties {
                for (key, property_schema) in properties {
                    if let Some(child) = object.get(key) {
                        validate_schema_fragment(property_schema, child, &format!("{path}.{key}"))?;
                    }
                }
            }
        }
        Some("string") if !value.is_string() => bail!("{path} must be a string"),
        Some("integer") if value.as_i64().is_none() && value.as_u64().is_none() => {
            bail!("{path} must be an integer")
        }
        Some("number") if !value.is_number() => bail!("{path} must be a number"),
        Some("boolean") if !value.is_boolean() => bail!("{path} must be a boolean"),
        Some("array") => {
            let Some(items) = value.as_array() else {
                bail!("{path} must be an array");
            };
            if let Some(min_items) = schema.get("minItems").and_then(Value::as_u64)
                && items.len() < min_items as usize
            {
                bail!("{path} has fewer than minItems");
            }
            if let Some(max_items) = schema.get("maxItems").and_then(Value::as_u64)
                && items.len() > max_items as usize
            {
                bail!("{path} exceeds maxItems");
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_schema_fragment(item_schema, item, &format!("{path}[{index}]"))?;
                }
            }
        }
        _ => {}
    }
    if let Some(max_length) = schema.get("maxLength").and_then(Value::as_u64)
        && value
            .as_str()
            .is_some_and(|value| value.chars().count() > max_length as usize)
    {
        bail!("{path} exceeds maxLength");
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64)
        && value
            .as_str()
            .is_some_and(|value| value.chars().count() < min_length as usize)
    {
        bail!("{path} is shorter than minLength");
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && value.as_f64().is_some_and(|number| number < minimum)
    {
        bail!("{path} is below minimum");
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && value.as_f64().is_some_and(|number| number > maximum)
    {
        bail!("{path} exceeds maximum");
    }
    if let Some(minimum) = schema.get("exclusiveMinimum").and_then(Value::as_f64)
        && value.as_f64().is_some_and(|number| number <= minimum)
    {
        bail!("{path} is not above exclusiveMinimum");
    }
    if let Some(maximum) = schema.get("exclusiveMaximum").and_then(Value::as_f64)
        && value.as_f64().is_some_and(|number| number >= maximum)
    {
        bail!("{path} is not below exclusiveMaximum");
    }
    Ok(())
}

pub(crate) fn redaction_summary_for_value(value: &Value) -> RedactionSummary {
    let mut fields = BTreeSet::new();
    collect_redacted_fields(value, "$", &mut fields);
    RedactionSummary {
        redaction_count: fields.len(),
        redacted_fields: fields.into_iter().collect(),
    }
}

pub(crate) fn collect_redacted_fields(value: &Value, path: &str, fields: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let next = format!("{path}.{key}");
                if is_sensitive_key(key) {
                    fields.insert(next);
                } else {
                    collect_redacted_fields(child, &next, fields);
                }
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_redacted_fields(child, &format!("{path}[{index}]"), fields);
            }
        }
        _ => {}
    }
}

pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower == "authorization"
        || lower == "cookie"
        || lower == "set-cookie"
}

pub(crate) fn approval_request_for(
    config: &ProxyConfig,
    inventory_entry: &InventoryEntry,
    request: &Value,
    bundle_proof: &PolicyBundleProof,
    reason: &str,
) -> Result<ApprovalRequest> {
    let request_hash = request_hash_hex(request);
    let policy_hash = policy_hash_hex(bundle_proof);
    let arguments_hash = arguments_hash_hex_from_request(request)?;
    let tool_schema_hash = inventory_entry
        .schema_hash
        .as_deref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unavailable".to_string());
    let material = json!({
        "tenant_id": config.identity.tenant_id,
        "environment": config.identity.environment,
        "tool_key": inventory_entry.tool_key,
        "request_hash": request_hash,
        "policy_hash": policy_hash,
        "tool_schema_hash": tool_schema_hash,
    });
    Ok(ApprovalRequest {
        schema_version: "velvet.approval_request.v1".to_string(),
        approval_request_id: format!(
            "apr_{}",
            &sha256_hex(canonical_json(&material).as_bytes())[..32]
        ),
        tenant_id: config.identity.tenant_id.clone(),
        environment: config.identity.environment.clone(),
        subject_id: config.identity.subject_id.clone(),
        user_id: config.identity.subject_id.clone(),
        agent_id: None,
        tool_key: inventory_entry.tool_key.clone(),
        request_hash,
        arguments_hash,
        policy_hash,
        policy_version: config.policy.chain.clone(),
        tool_schema_hash,
        reason: reason.to_string(),
        risk_class: inventory_entry.risk_class.clone(),
        created_at: Utc::now().to_rfc3339(),
        expires_at: (Utc::now() + Duration::minutes(15)).to_rfc3339(),
    })
}

/// Extract a caller-supplied Verdict Certificate from a tools/call request.
///
/// The certificate arrives the same way approval receipts do: as a JSON object
/// under `params._meta.velvet_verdict_certificate`. It is authenticated by its
/// own Velvet SignatureBlock, so a model-controlled transport cannot forge it.
pub(crate) fn verdict_certificate_from_request(request: &Value) -> Option<Value> {
    request
        .pointer("/params/_meta/velvet_verdict_certificate")
        .filter(|value| value.is_object())
        .cloned()
}

pub(crate) fn approval_receipt_from_request_or_config(
    config: &ProxyConfig,
    request: &Value,
) -> Result<Option<ApprovalReceipt>> {
    if let Some(value) = request.pointer("/params/_meta/velvet_approval_receipt") {
        return serde_json::from_value(value.clone())
            .map(Some)
            .context("parse request approval receipt");
    }
    let request_hash = request_hash_hex(request);
    Ok(config
        .approvals
        .iter()
        .find(|receipt| receipt.request_hash == request_hash)
        .cloned())
}

pub(crate) fn validate_approval_receipt(
    config: &ProxyConfig,
    receipt: &ApprovalReceipt,
    inventory_entry: &InventoryEntry,
    request: &Value,
    bundle_proof: &PolicyBundleProof,
    used_approval_receipts: &BTreeSet<String>,
) -> Result<()> {
    if receipt.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION {
        bail!("approval receipt schema is unsupported");
    }
    if !receipt.approved {
        bail!("approval receipt is not approved");
    }
    if receipt.one_time_use
        && (used_approval_receipts.contains(receipt.receipt_id())
            || approval_receipt_id_seen_in_ledger(&config.ledger_path, receipt.receipt_id())?)
    {
        bail!("approval receipt has already been used");
    }
    if receipt.used_at.is_some() {
        bail!("approval receipt has already been used");
    }
    if parse_time(&receipt.expires_at)? <= Utc::now() {
        bail!("approval receipt is expired");
    }
    if receipt.tenant_id != config.identity.tenant_id {
        bail!("approval receipt tenant does not match");
    }
    if receipt.environment != config.identity.environment {
        bail!("approval receipt environment does not match");
    }
    if receipt.subject_id != config.identity.subject_id {
        bail!("approval receipt subject does not match");
    }
    if receipt.tool_key != inventory_entry.tool_key {
        bail!("approval receipt tool does not match");
    }
    if receipt.request_hash != request_hash_hex(request) {
        bail!("approval receipt request hash does not match");
    }
    if receipt.arguments_hash != arguments_hash_hex_from_request(request)? {
        bail!("approval receipt arguments hash does not match");
    }
    if receipt.policy_hash != policy_hash_hex(bundle_proof) {
        bail!("approval receipt policy hash does not match");
    }
    if !receipt.policy_version.is_empty() && receipt.policy_version != config.policy.chain {
        bail!("approval receipt policy version does not match");
    }
    let tool_schema_hash = inventory_entry
        .schema_hash
        .as_deref()
        .map(ToString::to_string)
        .unwrap_or_default();
    if receipt.tool_schema_hash != tool_schema_hash {
        bail!("approval receipt tool schema hash does not match");
    }
    let expected_hash = approval_receipt_hash(receipt)?;
    if receipt.receipt_hash != expected_hash {
        bail!("approval receipt hash does not match");
    }
    verify_approval_receipt_signature(config, receipt)?;
    Ok(())
}

pub(crate) fn verify_approval_receipt_signature(
    config: &ProxyConfig,
    receipt: &ApprovalReceipt,
) -> Result<()> {
    let signature_required = config.mode.is_strict() || config.approval_receipts.require_signature;
    let Some(signature) = receipt.signature.as_ref() else {
        if !signature_required && config.approval_receipts.allow_unsigned_local_demo_only {
            return Ok(());
        }
        bail!("approval receipt signature is required");
    };
    if signature.schema_version != CORE_SIGNATURE_SCHEMA_VERSION {
        bail!("approval receipt signature schema is unsupported");
    }
    if signature.purpose != APPROVAL_RECEIPT_SCHEMA_VERSION {
        bail!("approval receipt signature purpose does not match approval receipt purpose");
    }
    if signature.tenant_id != receipt.tenant_id {
        bail!("approval receipt signature tenant does not match receipt");
    }
    if signature.tenant_id != config.identity.tenant_id {
        bail!("approval receipt signature tenant does not match proxy tenant");
    }
    if signature.payload_hash != receipt.receipt_hash {
        bail!("approval receipt signature payload hash does not match receipt hash");
    }
    if signature.algorithm != "Ed25519" {
        bail!("approval receipt signature algorithm is unsupported");
    }
    let trusted_key = trusted_approval_receipt_key(config, signature)?;
    let public_key_bytes = trusted_approval_receipt_public_key_bytes(trusted_key)?;
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(signature.signature.as_bytes())
        .context("decode approval receipt signature")?
        .try_into()
        .map_err(|_| anyhow!("approval receipt Ed25519 signature must be 64 bytes"))?;
    let message = signing_message_bytes(
        &receipt.receipt_hash,
        APPROVAL_RECEIPT_SCHEMA_VERSION,
        &receipt.tenant_id,
        &signature.key_id,
        &signature.provider_name,
        &signature.algorithm,
        &signature.key_version,
    );
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&message, &signature)
        .map_err(|error| anyhow!("approval receipt signature verification failed: {error}"))
}

pub(crate) fn trusted_approval_receipt_key<'a>(
    config: &'a ProxyConfig,
    signature: &SignatureBlock,
) -> Result<&'a TrustedApprovalReceiptKey> {
    let mut matches = config.approval_receipts.trusted_keys.iter().filter(|key| {
        key.provider_name == signature.provider_name
            && key.algorithm == signature.algorithm
            && key.key_id == signature.key_id
            && key.key_version == signature.key_version
    });
    let Some(key) = matches.next() else {
        bail!("approval receipt signature key is not trusted");
    };
    if matches.next().is_some() {
        bail!("approval receipt signature key trust root is ambiguous");
    }
    Ok(key)
}

pub(crate) fn trusted_approval_receipt_public_key_bytes(
    key: &TrustedApprovalReceiptKey,
) -> Result<[u8; 32]> {
    let mut configured_sources = 0usize;
    let mut material: Option<(&'static str, String)> = None;
    add_trusted_key_material(
        &mut configured_sources,
        &mut material,
        "base64",
        key.public_key_base64.as_deref(),
    )?;
    if let Some(env_name) = non_empty_config_value(key.public_key_base64_env.as_deref()) {
        configured_sources += 1;
        let value = std::env::var(env_name)
            .with_context(|| format!("read approval receipt public key env {env_name}"))?;
        if value.trim().is_empty() {
            bail!("approval receipt public key env {env_name} is empty");
        }
        material = Some(("base64", value));
    }
    add_trusted_key_material(
        &mut configured_sources,
        &mut material,
        "hex",
        key.public_key_hex.as_deref(),
    )?;
    if let Some(env_name) = non_empty_config_value(key.public_key_hex_env.as_deref()) {
        configured_sources += 1;
        let value = std::env::var(env_name)
            .with_context(|| format!("read approval receipt public key env {env_name}"))?;
        if value.trim().is_empty() {
            bail!("approval receipt public key env {env_name} is empty");
        }
        material = Some(("hex", value));
    }
    if configured_sources == 0 {
        bail!("trusted approval receipt key has no public key material");
    }
    if configured_sources > 1 {
        bail!("trusted approval receipt key has ambiguous public key material");
    }
    let Some((encoding, value)) = material else {
        bail!("trusted approval receipt key has no resolvable public key material");
    };
    let bytes = match encoding {
        "base64" => BASE64_STANDARD
            .decode(value.trim().as_bytes())
            .context("decode approval receipt public key base64")?,
        "hex" => hex_decode(value.trim()).context("decode approval receipt public key hex")?,
        _ => unreachable!(),
    };
    bytes
        .try_into()
        .map_err(|_| anyhow!("approval receipt Ed25519 public key must be 32 bytes"))
}

pub(crate) fn add_trusted_key_material(
    configured_sources: &mut usize,
    material: &mut Option<(&'static str, String)>,
    encoding: &'static str,
    value: Option<&str>,
) -> Result<()> {
    let Some(value) = non_empty_config_value(value) else {
        return Ok(());
    };
    *configured_sources += 1;
    if material.is_some() {
        bail!("trusted approval receipt key has ambiguous public key material");
    }
    *material = Some((encoding, value.to_string()));
    Ok(())
}

pub(crate) fn non_empty_config_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn denial_response(
    request: &Value,
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
) -> Value {
    jsonrpc_error(
        request.get("id").cloned(),
        if matches!(
            admission.decision.as_str(),
            "escalate" | "ask_approval" | "delay"
        ) {
            -32072
        } else {
            -32071
        },
        &format!("Velvet Rope {}: {}", admission.decision, admission.reason),
        json!({
            "boundary": "pre_execution_authorization",
            "inventory_status": admission.inventory_status.status,
            "oap_decision_id": admission.oap.decision.get("decision_id"),
            "oap_decision": admission.oap.decision,
            "decision_payload_digest": admission.oap.decision_payload_digest,
            "signed_decision_digest": admission.oap.signed_decision_digest,
            "decision_signature_hash": admission.oap.decision_signature_hash,
            "max_de_certificate_envelope_digest": admission.oap.max_de_envelope_digest,
            "admission_evidence_hash": pre_record.admission_evidence_hash,
            "admission_evidence_ref": pre_record.admission_evidence_ref,
            "approval_request": admission.approval_request,
        }),
    )
}

pub(crate) fn bounded_method_response(request: &Value, decision: &BoundedMethodDecision) -> Value {
    let code = match decision.disposition {
        BoundedMethodDisposition::Escalate => -32072,
        BoundedMethodDisposition::Block => -32073,
        BoundedMethodDisposition::AllowPassthrough => -32074,
    };
    jsonrpc_error(
        request.get("id").cloned(),
        code,
        &format!(
            "Velvet Rope bounded method {}: {}",
            decision.disposition.as_str(),
            decision.reason
        ),
        json!({
            "boundary": "bounded_mcp_surface",
            "method": decision.method.as_str(),
            "method_group": decision.group.as_str(),
            "disposition": decision.disposition.as_str(),
            "disposition_source": decision.source.as_str(),
            "recorded": true,
        }),
    )
}

pub(crate) fn oap_reasons_for_decision(
    decision: &str,
    reason: &str,
    short_circuit: Option<&str>,
) -> Vec<OapReason> {
    let reason = match (decision, short_circuit) {
        ("execute", _) => OapReason::new("oap.allowed", "Action admitted by Velvet"),
        (_, Some("certified_lockout")) => {
            OapReason::new("velvet.certified_lockout", "Max-DE certified lockout")
        }
        (_, Some("certified_refinement"))
        | ("escalate", _)
        | ("ask_approval", _)
        | ("delay", _) => OapReason::new(
            "velvet.certificate_indeterminate",
            "Escalation required; not a silent denial",
        ),
        _ => OapReason::new("velvet.blocked", reason),
    };
    vec![reason]
}

#[allow(dead_code)]
pub(crate) fn ledger_state(decision: &str) -> &'static str {
    match decision {
        "execute" | "allow_passthrough" => "allow",
        "escalate" | "ask_approval" | "delay" => "escalate",
        _ => "block",
    }
}

pub(crate) fn bounded_ledger_state(disposition: BoundedMethodDisposition) -> &'static str {
    match disposition {
        BoundedMethodDisposition::AllowPassthrough => "allow",
        BoundedMethodDisposition::Block => "block",
        BoundedMethodDisposition::Escalate => "escalate",
    }
}

pub(crate) fn jsonrpc_error(id: Option<Value>, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
            "data": data,
        }
    })
}

pub(crate) fn attach_oap_decision(
    mut response: Value,
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
) -> Value {
    if let Some(result_object) = response.get_mut("result").and_then(Value::as_object_mut) {
        let meta = result_object
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()));
        attach_oap_meta(meta, admission, pre_record);
        return response;
    }
    if let Some(error_data) = response
        .pointer_mut("/error/data")
        .and_then(Value::as_object_mut)
    {
        let meta = error_data
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()));
        attach_oap_meta(meta, admission, pre_record);
    }
    response
}

fn attach_oap_meta(meta: &mut Value, admission: &AdmissionOutcome, pre_record: &OapLedgerRecord) {
    if let Some(meta_object) = meta.as_object_mut() {
        meta_object.insert(
            "open_agent_passport_decision".to_string(),
            admission.oap.decision.clone(),
        );
        meta_object.insert(
            "open_agent_passport_decision_digest".to_string(),
            Value::String(admission.oap.signed_decision_digest.clone()),
        );
        meta_object.insert(
            "open_agent_passport_decision_payload_digest".to_string(),
            Value::String(admission.oap.decision_payload_digest.clone()),
        );
        if let Some(digest) = &admission.oap.max_de_envelope_digest {
            meta_object.insert(
                "velvet_maxde_certificate_envelope_digest".to_string(),
                Value::String(digest.clone()),
            );
        }
        if admission.oap.max_de_envelope.is_some() && admission.oap.max_de_envelope_digest.is_some()
        {
            meta_object.insert(
                "velvet_oap_binding".to_string(),
                Value::String(VELVET_OAP_BOUNDARY_STATEMENT.to_string()),
            );
        }
        if let Some(hash) = &pre_record.admission_evidence_hash {
            meta_object.insert(
                "velvet_admission_evidence_hash".to_string(),
                Value::String(hash.clone()),
            );
        }
        if let Some(reference) = &pre_record.admission_evidence_ref {
            meta_object.insert(
                "velvet_admission_evidence_ref".to_string(),
                reference.clone(),
            );
        }
    }
}

pub(crate) fn tools_list_response(request: &Value, inventory: &ToolInventory) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": {
            "tools": inventory.approved_tools(),
            "_meta": {
                "velvet_rope_proxy": {
                    "inventory_schema_version": INVENTORY_SCHEMA_VERSION,
                    "inventory_status": "filtered_by_velvet_rope",
                    "mcp_spec_target": MCP_SPEC_TARGET
                }
            }
        }
    })
}

pub(crate) fn tools_from_list_response(response: &Value) -> Result<Vec<Value>> {
    response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| anyhow!("upstream tools/list response missing result.tools array"))
}
