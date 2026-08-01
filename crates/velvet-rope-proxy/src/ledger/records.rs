use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantV1 {
    pub warrant_id: String,
    pub issued_at: String,
    pub tenant_id: String,
    pub environment: String,
    pub request_hash: String,
    pub canonical_action_hash: String,
    pub policy_hash: String,
    pub tool_schema_hash: String,
    pub tool_name: String,
    pub reason_codes: Vec<String>,
    pub obligations: Vec<String>,
    pub expires_at: String,
    pub issuer: String,
    pub product_surface: String,
    pub actor_user_id: Option<String>,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub action_type: String,
    pub decision: String,
    pub reason: String,
    pub seal_id: Option<String>,
    pub bound_seal_id: Option<String>,
    pub thread_id: Option<String>,
    pub tool_key: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub risk_class: String,
    pub data_class: Option<String>,
    pub policy_version: Option<String>,
    pub arguments_hash: Option<String>,
    pub policy_statuses: Vec<String>,
    pub policy_reasons: Vec<String>,
    pub jurisdiction_evidence: Vec<Value>,
    pub approval_required: bool,
    pub approval_request_id: Option<String>,
    pub ledger_record_hash: Option<String>,
    #[serde(skip_serializing)]
    pub canonicalization: String,
    pub warrant_hash: String,
    pub signature: Option<Value>,
    pub signing_key_id: Option<String>,
    pub signing_provider: Option<String>,
    pub signing_algorithm: Option<String>,
    pub signing_key_version: Option<String>,
    pub selected: Option<bool>,
    pub clears_rope: Option<bool>,
    pub expected_upside: Option<f64>,
    pub surprisal: Option<f64>,
    pub confidence: Option<f64>,
    pub clearance_score: Option<f64>,
    pub final_lambda: Option<f64>,
    pub entry_price: Option<f64>,
    pub scarcity_pressure: Option<f64>,
    pub cost_penalty: Option<f64>,
    pub risk_penalty: Option<f64>,
    pub pricing_status: Option<String>,
    pub admission_trace_hash: Option<String>,
    pub effect_vector_hash: Option<String>,
    pub objective_bps: Option<i64>,
    pub utility_lcb_bps: Option<i32>,
    pub cost_ucb_microusd: Option<u64>,
    pub risk_ucb_bps: Option<u32>,
    pub certificate: Option<Value>,
}

impl WarrantV1 {
    pub(crate) fn manual(
        config: &ProxyConfig,
        inventory_entry: &InventoryEntry,
        decision: &str,
        reason: &str,
        bundle_proof: &PolicyBundleProof,
        request: &Value,
        approval_request_id: Option<String>,
    ) -> Result<Self> {
        let seal_material = json!({
            "tool_key": inventory_entry.tool_key,
            "decision": decision,
            "reason": reason,
            "request_hash": request_hash_hex(request),
        });
        let seal_id = format!(
            "seal_velvet_mcp.{}_{}",
            decision,
            &sha256_hex(canonical_json(&seal_material).as_bytes())[..16]
        );
        let (mcp_server, mcp_tool) = split_tool_key(&inventory_entry.tool_key);
        let mut warrant = Self {
            warrant_id: String::new(),
            issued_at: now_rfc3339_z(),
            tenant_id: config.identity.tenant_id.clone(),
            environment: config.identity.environment.clone(),
            request_hash: request_hash_hex(request),
            canonical_action_hash: canonical_action_hash_for_mcp_request(config, request)?,
            policy_hash: policy_hash_hex(bundle_proof),
            tool_schema_hash: inventory_entry
                .schema_hash
                .clone()
                .unwrap_or_else(|| value_hash(&json!({"tool_name": inventory_entry.tool_key}))),
            tool_name: inventory_entry.tool_key.clone(),
            reason_codes: vec![inventory_entry.status.as_str().to_string()],
            obligations: obligations_for_decision(decision),
            expires_at: "9999-12-31T23:59:59Z".to_string(),
            issuer: "velvet".to_string(),
            product_surface: config.identity.product_surface.clone(),
            actor_user_id: config.identity.subject_id.clone(),
            agent_id: config.identity.agent_id.clone(),
            session_id: session_id(config, request),
            request_id: jsonrpc_request_id(request),
            action_type: "CALL_TOOL".to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            seal_id: Some(seal_id.clone()),
            bound_seal_id: Some(seal_id),
            thread_id: None,
            tool_key: Some(inventory_entry.tool_key.clone()),
            mcp_server,
            mcp_tool,
            risk_class: inventory_entry
                .risk_class
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            data_class: None,
            policy_version: Some(config.policy.chain.clone()),
            arguments_hash: arguments_hash_hex_from_request(request).ok(),
            policy_statuses: vec![format!("velvet_rope_proxy:{}", decision)],
            policy_reasons: vec![inventory_entry.status.as_str().to_string()],
            jurisdiction_evidence: vec![json!({
                "rule_id": format!("velvet_rope_proxy.{}", inventory_entry.status.as_str()),
                "evidence_type": "velvet_mcp_proxy",
                "message": reason,
                "details": {
                    "tool_key": inventory_entry.tool_key,
                    "schema_hash": inventory_entry.schema_hash,
                    "approved_schema_hash": inventory_entry.approved_schema_hash,
                    "inventory_status": inventory_entry.status,
                    "request_hash": request_hash_hex(request),
                    "policy_hash": policy_hash_hex(bundle_proof),
                }
            })],
            approval_required: decision == "escalate" || decision == "ask_approval",
            approval_request_id,
            ledger_record_hash: None,
            canonicalization: CANONICALIZATION_UNSIGNED_PAYLOAD.to_string(),
            warrant_hash: String::new(),
            signature: None,
            signing_key_id: None,
            signing_provider: None,
            signing_algorithm: None,
            signing_key_version: None,
            selected: Some(true),
            clears_rope: Some(false),
            expected_upside: None,
            surprisal: None,
            confidence: None,
            clearance_score: None,
            final_lambda: None,
            entry_price: None,
            scarcity_pressure: None,
            cost_penalty: None,
            risk_penalty: None,
            pricing_status: Some("manual_fail_closed".to_string()),
            admission_trace_hash: None,
            effect_vector_hash: None,
            objective_bps: None,
            utility_lcb_bps: None,
            cost_ucb_microusd: None,
            risk_ucb_bps: None,
            certificate: None,
        };
        finalize_warrant(&mut warrant)?;
        Ok(warrant)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn routed(
        config: &ProxyConfig,
        approval: &ToolApproval,
        inventory_entry: &InventoryEntry,
        decision: &RoutingDecision,
        candidate: &CandidateDecision,
        bundle_proof: &PolicyBundleProof,
        request: &Value,
        approval_request_id: Option<String>,
        approval_receipt: Option<&ApprovalReceipt>,
    ) -> Result<Self> {
        let policy_statuses = candidate
            .policy_trace
            .iter()
            .map(|entry| format!("{}:{}", entry.policy_name, entry.status))
            .collect::<Vec<_>>();
        let policy_reasons = candidate
            .policy_trace
            .iter()
            .filter_map(|entry| entry.decision.reason().map(|reason| reason.code.clone()))
            .collect::<Vec<_>>();
        let jurisdiction_evidence = candidate
            .policy_trace
            .iter()
            .filter_map(|entry| entry.jurisdiction_evidence.as_ref())
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let decision_string = if approval_receipt.is_some()
            && matches!(
                decision.decision,
                DecisionType::AskApproval | DecisionType::Escalate | DecisionType::Delay
            ) {
            "execute"
        } else {
            decision_string(decision.decision)
        };
        let reason = if let Some(receipt) = approval_receipt {
            format!(
                "Approved by {} with receipt {}.",
                receipt.approver_id, receipt.approval_receipt_id
            )
        } else {
            decision.reason.clone()
        };
        let data_class = approval
            .metadata
            .get("data_class")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let seal_id = decision.seal_id.clone().or_else(|| {
            Some(format!(
                "seal_velvet_mcp.{}_{}",
                decision_string,
                &sha256_hex(
                    canonical_json(&json!({
                        "tool_key": approval.key(),
                        "decision": decision_string,
                        "request_hash": request_hash_hex(request),
                    }))
                    .as_bytes()
                )[..16]
            ))
        });
        let mut warrant = Self {
            warrant_id: String::new(),
            issued_at: now_rfc3339_z(),
            tenant_id: config.identity.tenant_id.clone(),
            environment: config.identity.environment.clone(),
            request_hash: request_hash_hex(request),
            canonical_action_hash: canonical_action_hash_for_mcp_request(config, request)?,
            policy_hash: policy_hash_hex(bundle_proof),
            tool_schema_hash: inventory_entry
                .schema_hash
                .clone()
                .unwrap_or_else(|| value_hash(&json!({"tool_name": approval.key()}))),
            tool_name: approval.key(),
            reason_codes: if policy_reasons.is_empty() {
                vec![decision_string.to_string()]
            } else {
                policy_reasons.clone()
            },
            obligations: obligations_for_decision(decision_string),
            expires_at: "9999-12-31T23:59:59Z".to_string(),
            issuer: "velvet".to_string(),
            product_surface: config.identity.product_surface.clone(),
            actor_user_id: config.identity.subject_id.clone(),
            agent_id: config.identity.agent_id.clone(),
            session_id: session_id(config, request),
            request_id: jsonrpc_request_id(request),
            action_type: "CALL_TOOL".to_string(),
            decision: decision_string.to_string(),
            reason,
            seal_id: seal_id.clone(),
            bound_seal_id: seal_id,
            thread_id: decision.thread_id.clone(),
            tool_key: Some(approval.key()),
            mcp_server: Some(approval.server.clone()),
            mcp_tool: Some(approval.name.clone()),
            risk_class: approval.risk_class.as_str().to_string(),
            data_class,
            policy_version: Some(config.policy.chain.clone()),
            arguments_hash: arguments_hash_hex_from_request(request).ok(),
            clearance_score: None,
            entry_price: None,
            expected_upside: candidate
                .effect_vector
                .as_ref()
                .map(|effect| effect.utility_bound.expected_bps as f64 / 10_000.0),
            risk_penalty: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.risk_penalty_bps as f64 / 10_000.0),
            scarcity_pressure: None,
            cost_penalty: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.cost_penalty_bps as f64 / 10_000.0),
            surprisal: None,
            confidence: Some(approval.confidence),
            final_lambda: None,
            policy_statuses,
            policy_reasons,
            jurisdiction_evidence: {
                let mut evidence = jurisdiction_evidence;
                evidence.push(json!({
                    "rule_id": "velvet_rope_proxy.pre_execution",
                    "evidence_type": "velvet_mcp_proxy",
                    "message": "Velvet decision was made before upstream execution.",
                    "details": {
                        "request_hash": request_hash_hex(request),
                        "policy_hash": policy_hash_hex(bundle_proof),
                        "tool_schema_hash": inventory_entry.schema_hash,
                        "approval_receipt_id": approval_receipt.map(|receipt| receipt.approval_receipt_id.clone()),
                    }
                }));
                evidence
            },
            approval_required: approval.approval_tier == ApprovalTier::ConciergeReview
                || matches!(
                    decision.decision,
                    DecisionType::AskApproval | DecisionType::Escalate
                ),
            approval_request_id,
            ledger_record_hash: None,
            canonicalization: CANONICALIZATION_UNSIGNED_PAYLOAD.to_string(),
            warrant_hash: String::new(),
            signature: None,
            signing_key_id: None,
            signing_provider: None,
            signing_algorithm: None,
            signing_key_version: None,
            selected: Some(true),
            clears_rope: Some(decision_string == "execute"),
            pricing_status: Some("admission_optimizer".to_string()),
            admission_trace_hash: candidate.admission_trace_hash.clone(),
            effect_vector_hash: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.effect_vector_hash.clone()),
            objective_bps: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.objective_bps),
            utility_lcb_bps: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.utility_lcb_bps),
            cost_ucb_microusd: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.cost_ucb_microusd),
            risk_ucb_bps: candidate
                .admission_trace
                .as_ref()
                .map(|trace| trace.objective_components.risk_ucb_bps),
            certificate: None,
        };
        finalize_warrant(&mut warrant)?;
        Ok(warrant)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CanonicalLedgerRecord {
    pub contract: String,
    pub contract_revision: u8,
    pub record_id: String,
    pub tenant_id: String,
    pub environment: String,
    pub sequence_number: u64,
    pub recorded_at: String,
    pub previous_record_hash: String,
    pub record_hash: String,
    pub request_hash: String,
    pub canonical_action_hash: String,
    pub warrant_hash: String,
    pub policy_hash: String,
    pub tool_schema_hash: String,
    pub decision: String,
    pub upstream_execution_status: String,
    pub selected_warrant: WarrantV1,
    pub redaction_summary: RedactionSummary,
    pub seal_id: Option<String>,
    pub thread_id: Option<String>,
    pub product_surface: String,
    pub action_type: String,
    pub reason: String,
    pub tool_key: Option<String>,
    pub policy_version: String,
    pub arguments_hash: Option<String>,
    pub upstream_response_hash: Option<String>,
    pub fail_closed_reason: Option<String>,
    pub label: String,
}

#[allow(dead_code)]
pub(crate) fn record_ledger(
    config: &ProxyConfig,
    request: &Value,
    admission: &AdmissionOutcome,
    upstream_execution_status: &str,
    upstream_response_hash: Option<String>,
    fail_closed_reason: Option<&str>,
) -> Result<CanonicalLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let mut record = CanonicalLedgerRecord {
        contract: LEDGER_CONTRACT.to_string(),
        contract_revision: LEDGER_CONTRACT_REVISION,
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: admission.identity.tenant_id.clone(),
        environment: admission.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash.clone(),
        record_hash: String::new(),
        request_hash: request_hash_hex(request),
        canonical_action_hash: admission.warrant.canonical_action_hash.clone(),
        warrant_hash: selected_warrant_hash_hex(&admission.warrant)?,
        policy_hash: admission.warrant.policy_hash.clone(),
        tool_schema_hash: admission.warrant.tool_schema_hash.clone(),
        decision: canonical_decision(&admission.decision).to_string(),
        upstream_execution_status: upstream_execution_status.to_string(),
        selected_warrant: admission.warrant.clone(),
        redaction_summary: admission.redaction_summary.clone(),
        seal_id: admission.warrant.seal_id.clone(),
        thread_id: admission.warrant.thread_id.clone(),
        product_surface: admission.identity.product_surface.clone(),
        action_type: "CALL_TOOL".to_string(),
        reason: admission.reason.clone(),
        tool_key: Some(admission.inventory_status.tool_key.clone()),
        policy_version: config.policy.chain.clone(),
        arguments_hash: arguments_hash_hex_from_request(request).ok(),
        upstream_response_hash,
        fail_closed_reason: fail_closed_reason.map(ToString::to_string),
        label: "mcp_authorization".to_string(),
    };
    record.record_hash = canonical_ledger_record_hash_hex(&record)?;
    append_canonical_ledger_record(config, &record)?;
    Ok(record)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OapLedgerRecord {
    pub oap_contract: String,
    pub record_type: String,
    pub record_id: String,
    pub tenant_id: Option<String>,
    pub environment: String,
    pub sequence_number: u64,
    pub recorded_at: String,
    pub previous_record_hash: String,
    pub record_hash: String,
    pub decision_id: String,
    pub state: String,
    pub oap_passport: Option<Value>,
    pub oap_decision: Option<Value>,
    pub oap_decision_digest: Option<String>,
    pub decision_payload_digest: Option<String>,
    pub signed_decision_digest: Option<String>,
    pub decision_signature_hash: Option<String>,
    pub admission_evidence_hash: Option<String>,
    pub admission_evidence_ref: Option<Value>,
    pub admission_evidence: Option<Value>,
    pub max_de_certificate_required: bool,
    pub max_de_requirement_reason: Option<String>,
    pub max_de_certificate_envelope: Option<Value>,
    pub max_de_certificate_envelope_digest: Option<String>,
    #[serde(default)]
    pub verdict_certificate_required: bool,
    #[serde(default)]
    pub verdict_requirement_reason: Option<String>,
    #[serde(default)]
    pub verdict_status: Option<String>,
    #[serde(default)]
    pub verdict_certificate_hash: Option<String>,
    pub passport_digest: Option<String>,
    pub standard_boundary: String,
    pub persistence_metadata: Value,
    pub thread_id: Option<String>,
    pub product_surface: String,
    pub action_type: String,
    pub decision: String,
    pub reason: String,
    pub tool_key: Option<String>,
    pub policy_hash: Option<String>,
    pub policy_version: String,
    pub tool_schema_hash: Option<String>,
    pub arguments_hash: Option<String>,
    pub request_hash: String,
    pub tenant_id_hash: Option<String>,
    pub owner_id_hash: Option<String>,
    pub subject_id_hash: Option<String>,
    pub agent_id_hash: Option<String>,
    pub client_id_hash: Option<String>,
    pub session_id_hash: Option<String>,
    pub redaction_summary: RedactionSummary,
    pub label: String,
    pub proxy: String,
    pub mcp_spec_target: String,
    pub inventory_status: InventoryStatus,
    pub upstream_request_hash: Option<String>,
    pub upstream_response_hash: Option<String>,
    pub upstream_status: Option<String>,
    pub forwarding_proof: Option<Value>,
    pub pre_execution_record_hash: Option<String>,
    pub completion_timestamp: Option<String>,
    pub error_metadata: Option<Value>,
    pub approval_request_id: Option<String>,
    pub approval_request_hash: Option<String>,
    pub approval_status: Option<String>,
    pub approval_receipt_id: Option<String>,
    pub decision_latency_ms: u128,
    pub oap_performance: Option<Value>,
}

pub(crate) fn build_admission_evidence(
    config: &ProxyConfig,
    request: &Value,
    admission: &AdmissionOutcome,
    record: &OapLedgerRecord,
    sequence_state: &LedgerSequenceState,
) -> Result<Value> {
    let raw_ref = write_raw_action_artifact(config, request)?;
    let redacted_request = redacted_public_request(request);
    let warrant_value = serde_json::to_value(&admission.warrant)?;
    let approval_request_value = admission
        .approval_request
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let approval_request_hash = approval_request_value.as_ref().map(value_hash);
    let evidence_material = json!({
        "raw_action_hash": raw_ref.get("sha256"),
        "sequence_number": sequence_state.sequence_number,
        "previous_record_hash": sequence_state.previous_record_hash,
        "decision_id": record.decision_id,
    });
    let selected_warrant_hash = value_hash(&warrant_value);
    let mut evidence = json!({
        "schema_version": ADMISSION_EVIDENCE_SCHEMA_VERSION,
        "canonicalization": CANONICALIZATION_UNSIGNED_PAYLOAD,
        "evidence_id": format!(
            "ae_{}",
            &sha256_hex(canonical_json(&evidence_material).as_bytes())[..32]
        ),
        "issued_at": record.recorded_at,
        "tenant_id": admission.identity.tenant_id,
        "environment": admission.identity.environment,
        "product_surface": admission.identity.product_surface,
        "boundary": "pre_execution_authorization",
        "request_id": admission.warrant.request_id,
        "seal_id": admission.warrant.seal_id,
        "thread_id": admission.warrant.thread_id,
        "raw_action": {
            "raw_action_hash": raw_ref.get("sha256").cloned().unwrap_or(Value::Null),
            "raw_action_ref": raw_ref,
            "redacted_action_hash": value_hash(&redacted_request),
            "redacted_action": redacted_request,
        },
        "tool": {
            "tool_key": record.tool_key,
            "tool_name": admission.warrant.tool_name,
            "mcp_server": admission.warrant.mcp_server,
            "mcp_tool": admission.warrant.mcp_tool,
            "tool_schema_hash": record.tool_schema_hash,
            "arguments_hash": record.arguments_hash,
        },
        "policy": {
            "policy_hash": record.policy_hash,
            "policy_version": record.policy_version,
            "policy_statuses": admission.warrant.policy_statuses,
            "policy_reasons": admission.warrant.policy_reasons,
        },
        "decision": {
            "decision": canonical_decision(&record.decision),
            "reason": record.reason,
            "action_type": record.action_type,
            "approval_required": admission.warrant.approval_required || admission.approval_request.is_some(),
            "approval_status": approval_status_for_admission(admission),
            "approval_request_id": record.approval_request_id,
            "approval_request_hash": approval_request_hash,
            "approval_receipt_id": record.approval_receipt_id,
            "upstream_execution_status": pre_execution_upstream_status(&record.decision),
            "obligations": admission.warrant.obligations,
        },
        "risk": {
            "risk_class": admission.inventory_status.risk_class.clone().unwrap_or_else(|| "unknown".to_string()),
            "pricing_status": admission.warrant.pricing_status.clone().unwrap_or_else(|| "not_priced".to_string()),
            "entry_price": admission.warrant.entry_price.map(decimal_string),
            "clearance_score": admission.warrant.clearance_score.map(decimal_string),
            "risk_penalty": admission.warrant.risk_penalty.map(decimal_string),
            "scarcity_pressure": admission.warrant.scarcity_pressure.map(decimal_string),
        },
        "authority": authority_snapshot(admission),
        "identity": {
            "tenant_id": admission.identity.tenant_id,
            "environment": admission.identity.environment,
            "actor_user_id": admission.warrant.actor_user_id.clone().or_else(|| admission.identity.subject_id.clone()),
            "subject_id": admission.identity.subject_id,
            "agent_id": admission.identity.agent_id,
            "session_id": admission.identity.session_id,
            "delegation": {},
        },
        "ledger_state": {
            "ledger_path": config.ledger_path.display().to_string(),
            "sequence_number": sequence_state.sequence_number,
            "previous_record_hash": sequence_state.previous_record_hash,
            "previous_frame_hash": sequence_state.previous_frame_hash,
        },
        "bindings": {
            "warrant_hash": selected_warrant_hash_hex(&admission.warrant)?,
            "selected_warrant_hash": selected_warrant_hash,
            "request_hash": record.request_hash,
        },
    });
    let evidence_hash = admission_evidence_hash_value(&evidence)?;
    evidence["admission_evidence_hash"] = Value::String(evidence_hash.clone());
    evidence["signature"] = local_signature_block(
        &evidence_hash,
        &admission.identity.tenant_id,
        PURPOSE_ADMISSION_EVIDENCE,
    )?;
    verify_admission_evidence_value(&evidence)?;
    Ok(evidence)
}

pub(crate) fn write_raw_action_artifact(config: &ProxyConfig, request: &Value) -> Result<Value> {
    let data = canonical_json(request).into_bytes();
    let digest = format!("sha256:{}", sha256_hex(&data));
    let artifact_id = format!(
        "raw_{}",
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("raw action digest missing prefix"))?
            .chars()
            .take(32)
            .collect::<String>()
    );
    let dir = raw_action_artifact_dir(&config.ledger_path);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{artifact_id}.json"));
    fs::write(&path, &data)?;
    let absolute = path.canonicalize().unwrap_or(path);
    Ok(json!({
        "artifact_id": artifact_id,
        "uri": file_uri_for_path(&absolute),
        "sha256": digest,
        "size_bytes": data.len() as u64,
        "content_type": "application/json",
    }))
}

pub(crate) fn raw_action_artifact_dir(ledger_path: &Path) -> PathBuf {
    let parent = ledger_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = ledger_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("ledger");
    parent.join(format!("{stem}_raw_actions"))
}

pub(crate) fn file_uri_for_path(path: &Path) -> String {
    format!("file://{}", path.display()).replace(' ', "%20")
}

pub(crate) fn file_uri_to_path(uri: &str) -> Result<PathBuf> {
    let Some(path) = uri.strip_prefix("file://") else {
        bail!("raw action artifact URI must use file://");
    };
    Ok(PathBuf::from(path.replace("%20", " ")))
}

pub(crate) fn admission_evidence_hash_value(evidence: &Value) -> Result<String> {
    let mut unsigned = evidence.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("admission evidence must be an object"))?;
    object.remove("admission_evidence_hash");
    object.remove("signature");
    Ok(value_hash(&unsigned))
}

pub(crate) fn approval_request_hash(request: &ApprovalRequest) -> Result<String> {
    Ok(value_hash(&serde_json::to_value(request)?))
}

pub(crate) fn approval_status_for_admission(admission: &AdmissionOutcome) -> &'static str {
    if admission.approval_receipt.is_some() {
        "approved"
    } else if admission.approval_request.is_some() {
        "pending"
    } else if admission.warrant.approval_required {
        "missing"
    } else {
        "not_required"
    }
}

pub(crate) fn pre_execution_upstream_status(decision: &str) -> &'static str {
    match canonical_decision(decision) {
        "execute" => "forward_authorized",
        "escalate" => "pending_approval",
        _ => "not_forwarded",
    }
}

pub(crate) fn decimal_string(value: f64) -> String {
    format!("{value:.6}")
}

pub(crate) fn authority_snapshot(admission: &AdmissionOutcome) -> Value {
    let pricing = json!({
        "entry_price": admission.warrant.entry_price.map(decimal_string),
        "clearance_score": admission.warrant.clearance_score.map(decimal_string),
        "scarcity_pressure": admission.warrant.scarcity_pressure.map(decimal_string),
        "risk_penalty": admission.warrant.risk_penalty.map(decimal_string),
        "expected_upside": admission.warrant.expected_upside.map(decimal_string),
        "confidence": admission.warrant.confidence.map(decimal_string),
        "usd_estimate": admission
            .inventory_status
            .approval_tier
            .as_ref()
            .map(|tier| json!({"approval_tier": tier}))
            .unwrap_or(Value::Null),
        "max_de_certificate_required": admission.max_de_certificate_required,
        "max_de_requirement_reason": admission.max_de_requirement_reason,
        "max_de_certificate_envelope_digest": admission.oap.max_de_envelope_digest,
        "admission_trace_hash": admission.warrant.admission_trace_hash.clone(),
        "effect_vector_hash": admission.warrant.effect_vector_hash.clone(),
        "objective_bps": admission.warrant.objective_bps,
        "utility_lcb_bps": admission.warrant.utility_lcb_bps,
        "cost_ucb_microusd": admission.warrant.cost_ucb_microusd,
        "risk_ucb_bps": admission.warrant.risk_ucb_bps,
    });
    let has_pricing = admission.warrant.entry_price.is_some()
        || admission.warrant.clearance_score.is_some()
        || admission.warrant.risk_penalty.is_some()
        || admission.warrant.admission_trace_hash.is_some()
        || admission.oap.max_de_envelope_digest.is_some();
    json!({
        "mode": if admission.warrant.admission_trace_hash.is_some() {
            "authority_ledger"
        } else if has_pricing {
            "router_pricing_snapshot"
        } else {
            "non_budget_affecting"
        },
        "budget_state_hash": Value::Null,
        "budget_certificate_hash": admission.oap.max_de_envelope_digest,
        "pricing": pricing,
    })
}

#[doc(hidden)]
pub fn record_pre_execution_ledger(
    config: &ProxyConfig,
    request: &Value,
    admission: &AdmissionOutcome,
) -> Result<OapLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let decision_id = admission
        .oap
        .decision
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing decision_id"))?
        .to_string();
    let mut record = OapLedgerRecord {
        oap_contract: LEDGER_SCHEMA_VERSION.to_string(),
        record_type: "pre_execution_decision".to_string(),
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: Some(admission.identity.tenant_id.clone()),
        environment: admission.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash.clone(),
        record_hash: String::new(),
        decision_id,
        state: ledger_state(&admission.decision).to_string(),
        oap_passport: Some(admission.oap.passport.clone()),
        oap_decision: Some(admission.oap.decision.clone()),
        oap_decision_digest: Some(admission.oap.decision_digest.clone()),
        decision_payload_digest: Some(admission.oap.decision_payload_digest.clone()),
        signed_decision_digest: Some(admission.oap.signed_decision_digest.clone()),
        decision_signature_hash: Some(admission.oap.decision_signature_hash.clone()),
        admission_evidence_hash: None,
        admission_evidence_ref: None,
        admission_evidence: None,
        max_de_certificate_required: admission.max_de_certificate_required,
        max_de_requirement_reason: Some(admission.max_de_requirement_reason.clone()),
        max_de_certificate_envelope: admission.oap.max_de_envelope.clone(),
        max_de_certificate_envelope_digest: admission.oap.max_de_envelope_digest.clone(),
        verdict_certificate_required: admission.verdict_certificate_required,
        verdict_requirement_reason: Some(admission.verdict_requirement_reason.clone()),
        verdict_status: admission.verdict_status.clone(),
        verdict_certificate_hash: admission.verdict_certificate_hash.clone(),
        passport_digest: Some(admission.oap.passport_digest.clone()),
        standard_boundary: VELVET_OAP_BOUNDARY_STATEMENT.to_string(),
        persistence_metadata: json!({
            "model": "two_record_pre_post",
            "boundary": "pre_execution",
            "oap_validation": admission.oap.validation,
            "oap_spec_repo": OAP_SPEC_REPO,
            "oap_spec_commit": OAP_SPEC_COMMIT,
            "standard_boundary": VELVET_OAP_BOUNDARY_STATEMENT
        }),
        thread_id: admission.warrant.thread_id.clone(),
        product_surface: admission.identity.product_surface.clone(),
        action_type: "CALL_TOOL".to_string(),
        decision: admission.decision.clone(),
        reason: admission.reason.clone(),
        tool_key: Some(admission.inventory_status.tool_key.clone()),
        policy_hash: Some(admission.warrant.policy_hash.clone()),
        policy_version: config.policy.chain.clone(),
        tool_schema_hash: admission
            .inventory_status
            .schema_hash
            .clone()
            .or_else(|| Some(admission.warrant.tool_schema_hash.clone())),
        arguments_hash: arguments_hash_hex_from_request(request).ok(),
        request_hash: request_hash_hex(request),
        tenant_id_hash: Some(hash_identifier(&admission.identity.tenant_id)),
        owner_id_hash: admission
            .oap
            .decision
            .get("owner_id")
            .and_then(Value::as_str)
            .map(hash_identifier),
        subject_id_hash: Some(hash_optional_identifier(
            admission.identity.subject_id.as_deref(),
        )),
        agent_id_hash: Some(hash_optional_identifier(
            admission.identity.agent_id.as_deref(),
        )),
        client_id_hash: Some(hash_optional_identifier(
            admission.identity.client_id.as_deref(),
        )),
        session_id_hash: Some(hash_optional_identifier(
            admission.identity.session_id.as_deref(),
        )),
        redaction_summary: admission.redaction_summary.clone(),
        label: "mcp_oap_authorization_pre_execution".to_string(),
        proxy: PROXY_NAME.to_string(),
        mcp_spec_target: MCP_SPEC_TARGET.to_string(),
        inventory_status: admission.inventory_status.status.clone(),
        upstream_request_hash: None,
        upstream_response_hash: None,
        upstream_status: None,
        forwarding_proof: None,
        pre_execution_record_hash: None,
        completion_timestamp: None,
        error_metadata: None,
        approval_request_id: admission
            .approval_request
            .as_ref()
            .map(|request| request.approval_request_id.clone()),
        approval_request_hash: admission
            .approval_request
            .as_ref()
            .map(approval_request_hash)
            .transpose()?,
        approval_status: Some(approval_status_for_admission(admission).to_string()),
        approval_receipt_id: admission
            .approval_receipt
            .as_ref()
            .map(|receipt| receipt.approval_receipt_id.clone()),
        decision_latency_ms: admission.decision_latency_ms,
        oap_performance: Some(serde_json::to_value(&admission.oap.performance)?),
    };
    let admission_evidence =
        build_admission_evidence(config, request, admission, &record, &sequence_state)?;
    record.admission_evidence_hash = admission_evidence
        .get("admission_evidence_hash")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    record.admission_evidence_ref = admission_evidence
        .pointer("/raw_action/raw_action_ref")
        .cloned();
    record.admission_evidence = Some(admission_evidence);
    record.record_hash = oap_ledger_record_hash_hex(&record)?;
    verify_required_envelope(&serde_json::to_value(&record)?)?;
    if let Some(envelope) = &record.max_de_certificate_envelope
        && let Some(decision) = &record.oap_decision
    {
        verify_envelope_binding(envelope, decision)?;
        verify_maxde_exact_arithmetic(envelope)?;
    }
    append_oap_ledger_record(config, &record)?;
    let persisted = last_binary_ledger_record(&config.ledger_path)?;
    verify_oap_pre_execution_record(&persisted)?;
    Ok(record)
}

#[doc(hidden)]
pub struct PostExecutionObservation<'a> {
    pub pre_execution_record_hash: &'a str,
    pub upstream_status: &'a str,
    pub upstream_response_hash: Option<String>,
    pub error_message: Option<&'a str>,
    pub execution_receipt: Option<&'a Value>,
}

#[doc(hidden)]
pub fn record_post_execution_ledger(
    config: &ProxyConfig,
    request: &Value,
    admission: &AdmissionOutcome,
    observation: PostExecutionObservation<'_>,
) -> Result<OapLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let decision_id = admission
        .oap
        .decision
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing decision_id"))?
        .to_string();
    let mut forwarding_proof = json!({
        "pre_execution_record_hash": observation.pre_execution_record_hash,
        "decision_id": decision_id,
        "forwarded": observation.upstream_status == "forwarded"
    });
    if let Some(receipt) = observation.execution_receipt
        && let Some(object) = forwarding_proof.as_object_mut()
    {
        object.insert(
            "dispatch_claim_record_hash".to_string(),
            receipt
                .get("dispatch_claim_record_hash")
                .cloned()
                .unwrap_or(Value::Null),
        );
        object.insert(
            "execution_receipt_hash".to_string(),
            receipt.get("receipt_hash").cloned().unwrap_or(Value::Null),
        );
        object.insert("execution_receipt".to_string(), receipt.clone());
    }
    let mut record = OapLedgerRecord {
        oap_contract: LEDGER_SCHEMA_VERSION.to_string(),
        record_type: "post_execution_observation".to_string(),
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: Some(admission.identity.tenant_id.clone()),
        environment: admission.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash,
        record_hash: String::new(),
        decision_id: decision_id.clone(),
        state: ledger_state(&admission.decision).to_string(),
        oap_passport: None,
        oap_decision: None,
        oap_decision_digest: Some(admission.oap.decision_digest.clone()),
        decision_payload_digest: Some(admission.oap.decision_payload_digest.clone()),
        signed_decision_digest: Some(admission.oap.signed_decision_digest.clone()),
        decision_signature_hash: Some(admission.oap.decision_signature_hash.clone()),
        admission_evidence_hash: None,
        admission_evidence_ref: None,
        admission_evidence: None,
        max_de_certificate_required: false,
        max_de_requirement_reason: None,
        max_de_certificate_envelope: None,
        max_de_certificate_envelope_digest: admission.oap.max_de_envelope_digest.clone(),
        verdict_certificate_required: false,
        verdict_requirement_reason: None,
        verdict_status: None,
        verdict_certificate_hash: admission.verdict_certificate_hash.clone(),
        passport_digest: Some(admission.oap.passport_digest.clone()),
        standard_boundary: VELVET_OAP_BOUNDARY_STATEMENT.to_string(),
        persistence_metadata: json!({
            "model": "two_record_pre_post",
            "boundary": "post_execution_observation",
            "oap_spec_repo": OAP_SPEC_REPO,
            "oap_spec_commit": OAP_SPEC_COMMIT
        }),
        thread_id: admission.warrant.thread_id.clone(),
        product_surface: admission.identity.product_surface.clone(),
        action_type: "CALL_TOOL".to_string(),
        decision: admission.decision.clone(),
        reason: admission.reason.clone(),
        tool_key: Some(admission.inventory_status.tool_key.clone()),
        policy_hash: Some(admission.warrant.policy_hash.clone()),
        policy_version: config.policy.chain.clone(),
        tool_schema_hash: admission
            .inventory_status
            .schema_hash
            .clone()
            .or_else(|| Some(admission.warrant.tool_schema_hash.clone())),
        arguments_hash: arguments_hash_hex_from_request(request).ok(),
        request_hash: request_hash_hex(request),
        tenant_id_hash: Some(hash_identifier(&admission.identity.tenant_id)),
        owner_id_hash: admission
            .oap
            .decision
            .get("owner_id")
            .and_then(Value::as_str)
            .map(hash_identifier),
        subject_id_hash: Some(hash_optional_identifier(
            admission.identity.subject_id.as_deref(),
        )),
        agent_id_hash: Some(hash_optional_identifier(
            admission.identity.agent_id.as_deref(),
        )),
        client_id_hash: Some(hash_optional_identifier(
            admission.identity.client_id.as_deref(),
        )),
        session_id_hash: Some(hash_optional_identifier(
            admission.identity.session_id.as_deref(),
        )),
        redaction_summary: admission.redaction_summary.clone(),
        label: "mcp_oap_authorization_post_execution".to_string(),
        proxy: PROXY_NAME.to_string(),
        mcp_spec_target: MCP_SPEC_TARGET.to_string(),
        inventory_status: admission.inventory_status.status.clone(),
        upstream_request_hash: Some(request_hash_hex(request)),
        upstream_response_hash: observation.upstream_response_hash,
        upstream_status: Some(observation.upstream_status.to_string()),
        forwarding_proof: Some(forwarding_proof),
        pre_execution_record_hash: Some(observation.pre_execution_record_hash.to_string()),
        completion_timestamp: Some(now_rfc3339_z()),
        error_metadata: observation
            .error_message
            .map(|message| json!({"message": message, "boundary": "upstream_forwarding"})),
        approval_request_id: admission
            .approval_request
            .as_ref()
            .map(|request| request.approval_request_id.clone()),
        approval_request_hash: admission
            .approval_request
            .as_ref()
            .map(approval_request_hash)
            .transpose()?,
        approval_status: Some(approval_status_for_admission(admission).to_string()),
        approval_receipt_id: admission
            .approval_receipt
            .as_ref()
            .map(|receipt| receipt.approval_receipt_id.clone()),
        decision_latency_ms: admission.decision_latency_ms,
        oap_performance: None,
    };
    record.record_hash = oap_ledger_record_hash_hex(&record)?;
    append_oap_ledger_record(config, &record)?;
    Ok(record)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[doc(hidden)]
pub struct LifecycleLedgerEvent {
    pub event: String,
    pub subgoal_id_hash: String,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub details: Value,
}

#[doc(hidden)]
pub fn record_lifecycle_ledger_event(
    config: &ProxyConfig,
    event: &LifecycleLedgerEvent,
) -> Result<OapLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let event_value = serde_json::to_value(event)?;
    let mut record = OapLedgerRecord {
        oap_contract: LEDGER_SCHEMA_VERSION.to_string(),
        record_type: "closure_lifecycle_event".to_string(),
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: Some(config.identity.tenant_id.clone()),
        environment: config.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash,
        record_hash: String::new(),
        decision_id: uuid::Uuid::new_v4().to_string(),
        state: event.event.clone(),
        oap_passport: None,
        oap_decision: None,
        oap_decision_digest: None,
        decision_payload_digest: None,
        signed_decision_digest: None,
        decision_signature_hash: None,
        admission_evidence_hash: None,
        admission_evidence_ref: None,
        admission_evidence: None,
        max_de_certificate_required: false,
        max_de_requirement_reason: None,
        max_de_certificate_envelope: None,
        max_de_certificate_envelope_digest: None,
        verdict_certificate_required: false,
        verdict_requirement_reason: None,
        verdict_status: None,
        verdict_certificate_hash: None,
        passport_digest: None,
        standard_boundary: "closure lifecycle control over signed Execution Permits".to_string(),
        persistence_metadata: json!({
            "model": "closure_lifecycle",
            "boundary": "permit_epoch_lifecycle",
            "event": event.event,
            "subgoal_id_hash": event.subgoal_id_hash,
            "epoch": event.epoch,
            "trigger": event.trigger,
            "recorded": true
        }),
        thread_id: None,
        product_surface: config.identity.product_surface.clone(),
        action_type: "CLOSURE_LIFECYCLE".to_string(),
        decision: event.event.clone(),
        reason: event
            .reason
            .clone()
            .unwrap_or_else(|| format!("closure lifecycle {}", event.event)),
        tool_key: event.capability.clone(),
        policy_hash: None,
        policy_version: config.policy.chain.clone(),
        tool_schema_hash: None,
        arguments_hash: None,
        request_hash: value_hash(&event_value),
        tenant_id_hash: Some(hash_identifier(&config.identity.tenant_id)),
        owner_id_hash: None,
        subject_id_hash: Some(hash_optional_identifier(
            config.identity.subject_id.as_deref(),
        )),
        agent_id_hash: Some(hash_optional_identifier(
            config.identity.agent_id.as_deref(),
        )),
        client_id_hash: Some(hash_optional_identifier(
            config.identity.client_id.as_deref(),
        )),
        session_id_hash: Some(hash_optional_identifier(
            config.identity.session_id.as_deref(),
        )),
        redaction_summary: RedactionSummary::default(),
        label: "permit_epoch_lifecycle".to_string(),
        proxy: PROXY_NAME.to_string(),
        mcp_spec_target: MCP_SPEC_TARGET.to_string(),
        inventory_status: InventoryStatus::Unknown,
        upstream_request_hash: None,
        upstream_response_hash: None,
        upstream_status: None,
        forwarding_proof: Some(event_value),
        pre_execution_record_hash: None,
        completion_timestamp: Some(now_rfc3339_z()),
        error_metadata: None,
        approval_request_id: None,
        approval_request_hash: None,
        approval_status: None,
        approval_receipt_id: None,
        decision_latency_ms: 0,
        oap_performance: None,
    };
    record.record_hash = oap_ledger_record_hash_hex(&record)?;
    append_oap_ledger_record(config, &record)?;
    Ok(record)
}

pub(crate) fn record_bounded_method_ledger(
    config: &ProxyConfig,
    bundle_proof: &PolicyBundleProof,
    request: &Value,
    decision: &BoundedMethodDecision,
) -> Result<OapLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let mut record = OapLedgerRecord {
        oap_contract: LEDGER_SCHEMA_VERSION.to_string(),
        record_type: "bounded_method_disposition".to_string(),
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: Some(config.identity.tenant_id.clone()),
        environment: config.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash,
        record_hash: String::new(),
        decision_id: uuid::Uuid::new_v4().to_string(),
        state: bounded_ledger_state(decision.disposition).to_string(),
        oap_passport: None,
        oap_decision: None,
        oap_decision_digest: None,
        decision_payload_digest: None,
        signed_decision_digest: None,
        decision_signature_hash: None,
        admission_evidence_hash: None,
        admission_evidence_ref: None,
        admission_evidence: None,
        max_de_certificate_required: false,
        max_de_requirement_reason: None,
        max_de_certificate_envelope: None,
        max_de_certificate_envelope_digest: None,
        verdict_certificate_required: false,
        verdict_requirement_reason: None,
        verdict_status: None,
        verdict_certificate_hash: None,
        passport_digest: None,
        standard_boundary: "bounded MCP method governance; not an OAP tools/call Decision"
            .to_string(),
        persistence_metadata: json!({
            "model": "bounded_method_governance",
            "boundary": "bounded_mcp_surface",
            "method": decision.method.as_str(),
            "method_group": decision.group.as_str(),
            "disposition": decision.disposition.as_str(),
            "disposition_source": decision.source.as_str(),
            "strict_mode": config.mode.is_strict(),
            "recorded": true
        }),
        thread_id: None,
        product_surface: config.identity.product_surface.clone(),
        action_type: "MCP_METHOD".to_string(),
        decision: decision.disposition.as_str().to_string(),
        reason: decision.reason.clone(),
        tool_key: None,
        policy_hash: Some(policy_hash_hex(bundle_proof)),
        policy_version: config.policy.chain.clone(),
        tool_schema_hash: None,
        arguments_hash: None,
        request_hash: request_hash_hex(request),
        tenant_id_hash: Some(hash_identifier(&config.identity.tenant_id)),
        owner_id_hash: None,
        subject_id_hash: Some(hash_optional_identifier(
            config.identity.subject_id.as_deref(),
        )),
        agent_id_hash: Some(hash_optional_identifier(
            config.identity.agent_id.as_deref(),
        )),
        client_id_hash: Some(hash_optional_identifier(
            config.identity.client_id.as_deref(),
        )),
        session_id_hash: Some(hash_optional_identifier(
            config.identity.session_id.as_deref(),
        )),
        redaction_summary: decision.redaction_summary.clone(),
        label: "mcp_bounded_method_disposition".to_string(),
        proxy: PROXY_NAME.to_string(),
        mcp_spec_target: MCP_SPEC_TARGET.to_string(),
        inventory_status: InventoryStatus::Unknown,
        upstream_request_hash: None,
        upstream_response_hash: None,
        upstream_status: Some(decision.disposition.upstream_status().to_string()),
        forwarding_proof: Some(json!({
            "method": decision.method.as_str(),
            "method_group": decision.group.as_str(),
            "disposition": decision.disposition.as_str(),
            "forwarded": false,
            "source": decision.source.as_str(),
        })),
        pre_execution_record_hash: None,
        completion_timestamp: None,
        error_metadata: None,
        approval_request_id: None,
        approval_request_hash: None,
        approval_status: None,
        approval_receipt_id: None,
        decision_latency_ms: decision.decision_latency_ms,
        oap_performance: None,
    };
    record.record_hash = oap_ledger_record_hash_hex(&record)?;
    append_oap_ledger_record(config, &record)?;
    Ok(record)
}

pub(crate) fn record_bounded_method_observation(
    config: &ProxyConfig,
    request: &Value,
    decision: &BoundedMethodDecision,
    pre_record_hash: &str,
    upstream_status: &str,
    upstream_response_hash: Option<String>,
    error_message: Option<&str>,
) -> Result<OapLedgerRecord> {
    let ledger_lock = ledger_append_lock(&config.ledger_path)?;
    let _ledger_guard = ledger_lock
        .lock()
        .map_err(|_| anyhow!("ledger append lock poisoned"))?;
    let sequence_state = next_ledger_sequence_state(&config.ledger_path)?;
    let mut record = OapLedgerRecord {
        oap_contract: LEDGER_SCHEMA_VERSION.to_string(),
        record_type: "bounded_method_observation".to_string(),
        record_id: format!("lr_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: Some(config.identity.tenant_id.clone()),
        environment: config.identity.environment.clone(),
        sequence_number: sequence_state.sequence_number,
        recorded_at: now_rfc3339_z(),
        previous_record_hash: sequence_state.previous_record_hash,
        record_hash: String::new(),
        decision_id: uuid::Uuid::new_v4().to_string(),
        state: bounded_ledger_state(decision.disposition).to_string(),
        oap_passport: None,
        oap_decision: None,
        oap_decision_digest: None,
        decision_payload_digest: None,
        signed_decision_digest: None,
        decision_signature_hash: None,
        admission_evidence_hash: None,
        admission_evidence_ref: None,
        admission_evidence: None,
        max_de_certificate_required: false,
        max_de_requirement_reason: None,
        max_de_certificate_envelope: None,
        max_de_certificate_envelope_digest: None,
        verdict_certificate_required: false,
        verdict_requirement_reason: None,
        verdict_status: None,
        verdict_certificate_hash: None,
        passport_digest: None,
        standard_boundary: "bounded MCP method governance; not an OAP tools/call Decision"
            .to_string(),
        persistence_metadata: json!({
            "model": "bounded_method_governance",
            "boundary": "bounded_mcp_surface_observation",
            "method": decision.method.as_str(),
            "method_group": decision.group.as_str(),
            "disposition": decision.disposition.as_str(),
            "disposition_source": decision.source.as_str(),
            "strict_mode": config.mode.is_strict(),
            "recorded": true
        }),
        thread_id: None,
        product_surface: config.identity.product_surface.clone(),
        action_type: "MCP_METHOD".to_string(),
        decision: decision.disposition.as_str().to_string(),
        reason: decision.reason.clone(),
        tool_key: None,
        policy_hash: None,
        policy_version: config.policy.chain.clone(),
        tool_schema_hash: None,
        arguments_hash: None,
        request_hash: request_hash_hex(request),
        tenant_id_hash: Some(hash_identifier(&config.identity.tenant_id)),
        owner_id_hash: None,
        subject_id_hash: Some(hash_optional_identifier(
            config.identity.subject_id.as_deref(),
        )),
        agent_id_hash: Some(hash_optional_identifier(
            config.identity.agent_id.as_deref(),
        )),
        client_id_hash: Some(hash_optional_identifier(
            config.identity.client_id.as_deref(),
        )),
        session_id_hash: Some(hash_optional_identifier(
            config.identity.session_id.as_deref(),
        )),
        redaction_summary: decision.redaction_summary.clone(),
        label: "mcp_bounded_method_observation".to_string(),
        proxy: PROXY_NAME.to_string(),
        mcp_spec_target: MCP_SPEC_TARGET.to_string(),
        inventory_status: InventoryStatus::Unknown,
        upstream_request_hash: Some(request_hash_hex(request)),
        upstream_response_hash,
        upstream_status: Some(upstream_status.to_string()),
        forwarding_proof: Some(json!({
            "pre_execution_record_hash": pre_record_hash,
            "method": decision.method.as_str(),
            "method_group": decision.group.as_str(),
            "disposition": decision.disposition.as_str(),
            "forwarded": upstream_status == "forwarded",
            "source": decision.source.as_str(),
        })),
        pre_execution_record_hash: Some(pre_record_hash.to_string()),
        completion_timestamp: Some(now_rfc3339_z()),
        error_metadata: error_message
            .map(|message| json!({"message": message, "boundary": "bounded_upstream_forwarding"})),
        approval_request_id: None,
        approval_request_hash: None,
        approval_status: None,
        approval_receipt_id: None,
        decision_latency_ms: decision.decision_latency_ms,
        oap_performance: None,
    };
    record.record_hash = oap_ledger_record_hash_hex(&record)?;
    append_oap_ledger_record(config, &record)?;
    Ok(record)
}
