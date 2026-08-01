use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{ExecutionOutcome, ExecutionPermit, ExecutionReceipt, PolicyGraph};
use velvet_rope_proxy::{
    AdmissionOutcome, ExecutionReceiptObservation, LifecycleLedgerEvent, LogicalPermitBinding,
    OapLedgerRecord, PermitClaimStore, PolicyBundleProof, PostExecutionObservation, ProxyConfig,
    ToolInventory, admit_tool_call, authorize_execution_with_epoch_provider,
    build_execution_receipt, hash_identifier, record_lifecycle_ledger_event,
    record_post_execution_ledger, record_pre_execution_ledger, value_hash,
    verify_outbound_request_matches_permit,
};

use crate::contract::TaskContract;
use crate::epoch::SynchronizedEpochTable;
use crate::risk::{AllowRiskGate, RiskGate};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit: Option<ExecutionPermit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
}

impl Decision {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            permit_id: None,
            permit: None,
            receipt: None,
            record_hash: None,
        }
    }

    fn deny(reason: impl Into<String>, record_hash: Option<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            permit_id: None,
            permit: None,
            receipt: None,
            record_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleCapability {
    pub capability: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_id: Option<String>,
    pub standing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleTools {
    pub standing: Vec<VisibleCapability>,
    pub granted: Vec<VisibleCapability>,
}

#[derive(Debug, Clone)]
struct GrantState {
    subgoal: String,
    subgoal_id_hash: String,
    epoch: u64,
    capability: String,
    resource: String,
    request: Value,
    admission: AdmissionOutcome,
    pre_record: OapLedgerRecord,
    permit: ExecutionPermit,
    spent: bool,
}

pub struct ClosureMonitor {
    contract: TaskContract,
    config: ProxyConfig,
    bundle_proof: PolicyBundleProof,
    policy_graph: Arc<PolicyGraph>,
    inventory: ToolInventory,
    claim_store: PermitClaimStore,
    epochs: SynchronizedEpochTable,
    risk_gate: Arc<dyn RiskGate>,
    grants: BTreeMap<String, GrantState>,
    grant_counts: BTreeMap<(String, u64), u64>,
    closure_fired: BTreeSet<(String, u64)>,
    used_approval_receipts: BTreeSet<String>,
    dispatch_count: u64,
}

impl ClosureMonitor {
    pub fn new(
        contract: TaskContract,
        config: ProxyConfig,
        bundle_proof: PolicyBundleProof,
        policy_graph: Arc<PolicyGraph>,
        inventory: ToolInventory,
    ) -> Self {
        let claim_store = PermitClaimStore::for_ledger_path(&config.ledger_path);
        Self {
            contract,
            config,
            bundle_proof,
            policy_graph,
            inventory,
            claim_store,
            epochs: SynchronizedEpochTable::default(),
            risk_gate: Arc::new(AllowRiskGate),
            grants: BTreeMap::new(),
            grant_counts: BTreeMap::new(),
            closure_fired: BTreeSet::new(),
            used_approval_receipts: BTreeSet::new(),
            dispatch_count: 0,
        }
    }

    pub fn with_risk_gate(mut self, risk_gate: Arc<dyn RiskGate>) -> Self {
        self.risk_gate = risk_gate;
        self
    }

    pub fn epochs(&self) -> SynchronizedEpochTable {
        self.epochs.clone()
    }

    pub fn dispatch_count(&self) -> u64 {
        self.dispatch_count
    }

    pub fn open_subgoal(&mut self, subgoal: &str) -> Result<()> {
        self.epochs.activate(subgoal)?;
        Ok(())
    }

    pub fn request(
        &mut self,
        subgoal: &str,
        capability: &str,
        resource: &str,
        arguments: Value,
    ) -> Decision {
        if let Some(deny) = self.contract.deny_for(capability, resource) {
            let deny_reason = deny.reason.clone();
            let record_hash = self
                .record_event(LifecycleLedgerEvent {
                    event: "deny".to_string(),
                    subgoal_id_hash: hash_identifier(subgoal),
                    epoch: self.epochs.current(subgoal).unwrap_or(0),
                    trigger: Some("request".to_string()),
                    capability: Some(capability.to_string()),
                    resource: Some(resource.to_string()),
                    permit_id: None,
                    permit_hash: None,
                    receipt_hash: None,
                    reason: Some(deny_reason.clone()),
                    details: json!({"stage": "request"}),
                })
                .ok();
            self.maybe_close_on_deny(subgoal);
            return Decision::deny(format!("deny: {deny_reason}"), record_hash);
        }
        match self.request_inner(subgoal, capability, resource, arguments) {
            Ok(decision) => decision,
            Err(error) => {
                let record_hash = self
                    .record_event(LifecycleLedgerEvent {
                        event: "deny".to_string(),
                        subgoal_id_hash: hash_identifier(subgoal),
                        epoch: self.epochs.current(subgoal).unwrap_or(0),
                        trigger: Some("request_error".to_string()),
                        capability: Some(capability.to_string()),
                        resource: Some(resource.to_string()),
                        permit_id: None,
                        permit_hash: None,
                        receipt_hash: None,
                        reason: Some(error.to_string()),
                        details: json!({}),
                    })
                    .ok();
                self.maybe_close_on_deny(subgoal);
                Decision::deny(error.to_string(), record_hash)
            }
        }
    }

    fn request_inner(
        &mut self,
        subgoal: &str,
        capability: &str,
        resource: &str,
        arguments: Value,
    ) -> Result<Decision> {
        if !self.epochs.is_active(subgoal)? {
            return Ok(Decision::deny("subgoal not active", None));
        }
        let rule = self
            .contract
            .grant_rule_for(subgoal, capability, resource)
            .ok_or_else(|| anyhow!("no grant rule for this expansion"))?
            .clone();
        let epoch = self.epochs.current(subgoal)?;
        let grant_key = (subgoal.to_string(), epoch);
        let count = self.grant_counts.get(&grant_key).copied().unwrap_or(0);
        if count >= rule.max_grants {
            return Ok(Decision::deny(
                "max_grants exceeded for this activation",
                None,
            ));
        }
        let risk_decision =
            self.risk_gate
                .evaluate(subgoal, capability, resource, rule.risk_class.as_deref())?;
        if !risk_decision.allow {
            return Ok(Decision::deny(
                format!("risk gate: {}", risk_decision.reason),
                None,
            ));
        }
        let request = tool_call_request(capability, arguments);
        let admission = admit_tool_call(
            &self.config,
            &self.bundle_proof,
            &self.policy_graph,
            &self.inventory,
            &request,
            &self.used_approval_receipts,
        )?;
        let pre_record = record_pre_execution_ledger(&self.config, &request, &admission)?;
        if admission.decision != "execute" {
            return Ok(Decision::deny(admission.reason.clone(), None));
        }
        let subgoal_id_hash = hash_identifier(subgoal);
        let logical_step = i64::try_from(epoch)
            .map_err(|_| anyhow!("subgoal epoch exceeds permit logical-step range"))?;
        let prepared = velvet_rope_proxy::prepare_execution_with_logical_step(
            &self.config,
            &self.bundle_proof,
            &request,
            &admission,
            &pre_record,
            &self.claim_store,
            LogicalPermitBinding {
                subgoal_id_hash: subgoal_id_hash.clone(),
                logical_step,
            },
        )?;
        let permit = prepared.permit;
        self.grant_counts.insert(grant_key, count + 1);
        let record = self.record_event(LifecycleLedgerEvent {
            event: "grant".to_string(),
            subgoal_id_hash: subgoal_id_hash.clone(),
            epoch,
            trigger: None,
            capability: Some(capability.to_string()),
            resource: Some(resource.to_string()),
            permit_id: Some(permit.permit_id.clone()),
            permit_hash: Some(permit.permit_hash.clone()),
            receipt_hash: None,
            reason: Some("granted".to_string()),
            details: json!({
                "single_dispatch": rule.single_dispatch,
                "risk": risk_decision.certificate
            }),
        })?;
        let permit_id = permit.permit_id.clone();
        self.grants.insert(
            permit_id.clone(),
            GrantState {
                subgoal: subgoal.to_string(),
                subgoal_id_hash,
                epoch,
                capability: capability.to_string(),
                resource: resource.to_string(),
                request,
                admission,
                pre_record,
                permit: permit.clone(),
                spent: false,
            },
        );
        Ok(Decision {
            allowed: true,
            reason: "granted".to_string(),
            permit_id: Some(permit_id),
            permit: Some(permit),
            receipt: None,
            record_hash: Some(record),
        })
    }

    pub fn invoke(&mut self, permit_id: &str, arguments: Value) -> Decision {
        match self.invoke_inner(permit_id, arguments) {
            Ok(decision) => decision,
            Err(error) => {
                let record_hash = self
                    .record_event(LifecycleLedgerEvent {
                        event: "deny".to_string(),
                        subgoal_id_hash: self
                            .grants
                            .get(permit_id)
                            .map(|grant| grant.subgoal_id_hash.clone())
                            .unwrap_or_else(|| "sha256:unknown".to_string()),
                        epoch: self
                            .grants
                            .get(permit_id)
                            .map(|grant| grant.epoch)
                            .unwrap_or(0),
                        trigger: Some("invoke".to_string()),
                        capability: self
                            .grants
                            .get(permit_id)
                            .map(|grant| grant.capability.clone()),
                        resource: self
                            .grants
                            .get(permit_id)
                            .map(|grant| grant.resource.clone()),
                        permit_id: Some(permit_id.to_string()),
                        permit_hash: self
                            .grants
                            .get(permit_id)
                            .map(|grant| grant.permit.permit_hash.clone()),
                        receipt_hash: None,
                        reason: Some(error.to_string()),
                        details: json!({}),
                    })
                    .ok();
                Decision::deny(error.to_string(), record_hash)
            }
        }
    }

    fn invoke_inner(&mut self, permit_id: &str, arguments: Value) -> Result<Decision> {
        let grant = self
            .grants
            .get(permit_id)
            .ok_or_else(|| anyhow!("unknown permit"))?
            .clone();
        let request = tool_call_request(&grant.capability, arguments);
        let prepared = velvet_rope_proxy::PreparedExecution {
            permit: grant.permit.clone(),
        };
        let authorized = authorize_execution_with_epoch_provider(
            &self.config,
            prepared,
            &self.claim_store,
            "velvet_closure",
            &self.epochs,
        )?;
        verify_outbound_request_matches_permit(&request, &authorized)?;
        self.dispatch_count += 1;
        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let response_hash = Some(value_hash(&json!({"ok": true, "permit_id": permit_id})));
        let receipt = build_execution_receipt(
            &self.config,
            &authorized,
            ExecutionReceiptObservation {
                outcome: ExecutionOutcome::Succeeded,
                dispatch_attempted: true,
                started_at: &started_at,
                upstream_response_hash: response_hash.clone(),
                error_code: None,
                error_detail: None,
            },
        )?;
        record_post_execution_ledger(
            &self.config,
            &grant.request,
            &grant.admission,
            PostExecutionObservation {
                pre_execution_record_hash: &grant.pre_record.record_hash,
                upstream_status: "forwarded",
                upstream_response_hash: response_hash,
                error_message: None,
                execution_receipt: Some(&serde_json::to_value(&receipt)?),
            },
        )?;
        velvet_rope_proxy::mark_execution_complete(&self.claim_store, &authorized, &receipt)?;
        if let Some(current) = self.grants.get_mut(permit_id) {
            current.spent = true;
        }
        let record_hash = self.record_event(LifecycleLedgerEvent {
            event: "invoke".to_string(),
            subgoal_id_hash: grant.subgoal_id_hash.clone(),
            epoch: grant.epoch,
            trigger: None,
            capability: Some(grant.capability.clone()),
            resource: Some(grant.resource.clone()),
            permit_id: Some(permit_id.to_string()),
            permit_hash: Some(grant.permit.permit_hash.clone()),
            receipt_hash: Some(receipt.receipt_hash.clone()),
            reason: Some("invoked".to_string()),
            details: json!({
                "arguments_hash": value_hash(
                    request
                        .pointer("/params/arguments")
                        .unwrap_or(&Value::Null)
                )
            }),
        })?;
        self.observe_receipt_for_closure(&grant, &receipt)?;
        Ok(Decision {
            allowed: true,
            reason: "invoked".to_string(),
            permit_id: Some(permit_id.to_string()),
            permit: Some(grant.permit),
            receipt: Some(receipt),
            record_hash: Some(record_hash),
        })
    }

    pub fn close_subgoal(&mut self, subgoal: &str) -> Decision {
        if !self.contract.has_signal_closure(subgoal) {
            return Decision::deny("no on_signal closure predicate for subgoal", None);
        }
        match self.close_once(subgoal, "on_signal", None, None) {
            Ok(record_hash) => Decision::allow("closed (on_signal)").with_record(record_hash),
            Err(error) => Decision::deny(error.to_string(), None),
        }
    }

    pub fn visible_tools(&self) -> VisibleTools {
        let standing = self
            .contract
            .initial_envelope
            .iter()
            .filter(|capability| {
                self.contract
                    .deny_for(&capability.name, &capability.resource)
                    .is_none()
            })
            .map(|capability| VisibleCapability {
                capability: capability.name.clone(),
                resource: capability.resource.clone(),
                permit_id: None,
                standing: true,
            })
            .collect();
        let mut granted = Vec::new();
        for grant in self.grants.values() {
            if grant.spent {
                continue;
            }
            let active = self.epochs.is_active(&grant.subgoal).unwrap_or(false);
            let current = self.epochs.current(&grant.subgoal).unwrap_or(u64::MAX);
            if active && current == grant.epoch {
                granted.push(VisibleCapability {
                    capability: grant.capability.clone(),
                    resource: grant.resource.clone(),
                    permit_id: Some(grant.permit.permit_id.clone()),
                    standing: false,
                });
            }
        }
        VisibleTools { standing, granted }
    }

    pub fn lifecycle_record_count(&self, event: &str) -> Result<usize> {
        let bytes = std::fs::read(&self.config.ledger_path)?;
        let frames = velvet_rope_proxy::verify_binary_ledger_bytes(&bytes)?;
        Ok(frames
            .iter()
            .filter(|frame| {
                frame.payload.get("record_type").and_then(Value::as_str)
                    == Some("closure_lifecycle_event")
                    && frame.payload.get("state").and_then(Value::as_str) == Some(event)
            })
            .count())
    }

    fn observe_receipt_for_closure(
        &mut self,
        grant: &GrantState,
        receipt: &ExecutionReceipt,
    ) -> Result<()> {
        if self
            .contract
            .closures_for_receipt(&grant.subgoal, &grant.capability)
            .is_empty()
        {
            return Ok(());
        }
        self.close_once(
            &grant.subgoal,
            "on_receipt",
            Some(grant.capability.clone()),
            Some(receipt.receipt_hash.clone()),
        )?;
        Ok(())
    }

    fn maybe_close_on_deny(&mut self, subgoal: &str) {
        if self.contract.has_deny_closure(subgoal)
            && self.epochs.is_active(subgoal).unwrap_or(false)
        {
            let _ = self.close_once(subgoal, "on_deny", None, None);
        }
    }

    fn close_once(
        &mut self,
        subgoal: &str,
        trigger: &str,
        capability: Option<String>,
        receipt_hash: Option<String>,
    ) -> Result<Option<String>> {
        let subgoal_id_hash = hash_identifier(subgoal);
        let epoch = self.epochs.current(subgoal)?;
        let key = (subgoal_id_hash.clone(), epoch);
        if self.closure_fired.contains(&key) {
            return Ok(None);
        }
        if !self.epochs.is_active(subgoal)? {
            return Ok(None);
        }
        self.epochs.advance(subgoal)?;
        self.closure_fired.insert(key);
        let record_hash = self.record_event(LifecycleLedgerEvent {
            event: "closure".to_string(),
            subgoal_id_hash,
            epoch,
            trigger: Some(trigger.to_string()),
            capability,
            resource: None,
            permit_id: None,
            permit_hash: None,
            receipt_hash,
            reason: Some(format!("closed ({trigger})")),
            details: json!({}),
        })?;
        Ok(Some(record_hash))
    }

    fn record_event(&self, event: LifecycleLedgerEvent) -> Result<String> {
        Ok(record_lifecycle_ledger_event(&self.config, &event)?.record_hash)
    }
}

impl Decision {
    fn with_record(mut self, record_hash: Option<String>) -> Self {
        self.record_hash = record_hash;
        self
    }
}

fn tool_call_request(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "closure-monitor",
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    })
}
