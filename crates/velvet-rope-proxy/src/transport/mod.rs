#![allow(unused_imports)]

mod http;
mod stdio;

pub use http::run_http_proxy;
pub(crate) use http::run_tls_check_command;
#[cfg(test)]
pub(crate) use http::*;
pub use stdio::StdioMcpServer;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tower::limit::ConcurrencyLimitLayer;
use velvet_core::{
    ActionType, CandidateAction, CandidateDecision, CandidateSource, DecisionType, JsonObject,
    PolicyGraph, RouteRequest, RouterConfig, RoutingDecision,
    SIGNATURE_SCHEMA_VERSION as CORE_SIGNATURE_SCHEMA_VERSION, SignatureBlock, normalize_action_v1,
    route_with_policy_graph_and_thread, signing_message_bytes,
};
use velvet_policy_loader::{PolicyLoadError, load_policy_graph};
use walkdir::WalkDir;

use crate::approvals::*;
use crate::config::*;
use crate::constants::*;
use crate::demo::*;
use crate::enforcement::*;
use crate::execution::{
    ExecutionReceiptObservation, attach_execution_metadata_to_request, authorize_execution,
    build_execution_receipt, is_executable_admission, mark_execution_complete, prepare_execution,
    strip_model_controlled_execution_metadata, verify_outbound_request_matches_permit,
};
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::permit_store::PermitClaimStore;
use crate::policy_bundle::*;

pub trait McpUpstream {
    fn send(&mut self, request: &Value) -> Result<Option<Value>>;
    fn execution_count(&self, _tool: &str) -> usize {
        0
    }
}

pub struct ProxyRuntime<U: McpUpstream> {
    pub config: ProxyConfig,
    pub bundle_proof: PolicyBundleProof,
    pub policy_graph: Arc<PolicyGraph>,
    pub inventory: ToolInventory,
    pub upstream: U,
    claim_store: PermitClaimStore,
    used_approval_receipts: BTreeSet<String>,
}

impl<U: McpUpstream> ProxyRuntime<U> {
    pub fn new(config: ProxyConfig, mut upstream: U) -> Result<Self> {
        let claim_store = PermitClaimStore::for_ledger_path(&config.ledger_path);
        let bundle_proof = verify_policy_bundle(&config.policy)?;
        let policy_graph = Arc::new(load_policy_graph_or_error(&config.policy.dir)?);
        let inventory_response = upstream
            .send(&json!({
                "jsonrpc": "2.0",
                "id": "velvet-inventory",
                "method": "tools/list",
                "params": {}
            }))?
            .ok_or_else(|| anyhow!("upstream did not respond to tools/list inventory request"))?;
        let tools = tools_from_list_response(&inventory_response)?;
        let inventory = ToolInventory::build(&config, &tools)?;
        inventory.write_if_configured(config.inventory_path.as_deref())?;
        Ok(Self {
            config,
            bundle_proof,
            policy_graph,
            inventory,
            upstream,
            claim_store,
            used_approval_receipts: BTreeSet::new(),
        })
    }

    pub fn run_fake_script(&mut self) -> Result<Value> {
        let requests = if self.config.demo_requests.is_empty() {
            default_demo_requests()
        } else {
            self.config.demo_requests.clone()
        };
        let mut transcript = Vec::new();
        for request in requests {
            let response = self.handle_message(request.clone())?;
            transcript.push(json!({
                "request": request,
                "response": response,
            }));
        }
        let summary = json!({
            "proxy": PROXY_NAME,
            "transport": "fake",
            "inventory_path": self.config.inventory_path,
            "ledger_path": self.config.ledger_path,
            "thread_path": self.config.thread_path,
            "approval_requests_path": self.config.approval_requests_path,
            "evidence_pack_path": self.config.evidence_pack_path,
            "transcript": transcript,
            "execution_counts": {
                "search_change_requests": self.upstream.execution_count("search_change_requests"),
                "create_change_request": self.upstream.execution_count("create_change_request"),
                "delete_change_request": self.upstream.execution_count("delete_change_request"),
                "drop_database": self.upstream.execution_count("drop_database"),
            },
        });
        let summary_path = self
            .config
            .ledger_path
            .parent()
            .map(|parent| parent.join("mcp_proxy_summary.json"));
        if let Some(path) = summary_path {
            fs::write(path, serde_json::to_string_pretty(&summary)? + "\n")?;
        }
        Ok(summary)
    }

    pub fn run_stdio_loop(&mut self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if line.len() > self.config.limits.max_request_bytes {
                let response = jsonrpc_error(
                    None,
                    -32080,
                    "request exceeds configured size limit",
                    json!({"boundary": "pre_execution_authorization"}),
                );
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
                continue;
            }
            if let Some(response) = self.handle_raw_message(&line)? {
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
        }
        Ok(())
    }

    pub fn handle_raw_message(&mut self, line: &str) -> Result<Option<Value>> {
        match serde_json::from_str::<Value>(line) {
            Ok(message) => self.handle_message(message),
            Err(error) => Ok(Some(jsonrpc_error(
                None,
                -32700,
                "parse error",
                json!({"detail": error.to_string()}),
            ))),
        }
    }

    pub fn handle_message(&mut self, request: Value) -> Result<Option<Value>> {
        if request.is_array() {
            let Some(items) = request.as_array() else {
                unreachable!();
            };
            if items.is_empty() {
                return Ok(Some(jsonrpc_error(
                    None,
                    -32600,
                    "invalid JSON-RPC batch",
                    json!({"boundary": "pre_execution_authorization"}),
                )));
            }
            let mut responses = Vec::new();
            for item in items {
                if let Some(response) = self.handle_message(item.clone())? {
                    responses.push(response);
                }
            }
            return Ok((!responses.is_empty()).then_some(Value::Array(responses)));
        }
        if !request.is_object() {
            return Ok(Some(jsonrpc_error(
                None,
                -32600,
                "invalid JSON-RPC request",
                json!({"boundary": "pre_execution_authorization"}),
            )));
        }
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let is_notification = request.get("id").is_none();
        if method.is_empty() {
            return self.handle_bounded_method(request, is_notification);
        }
        match method {
            method if is_lifecycle_method(method) => self.upstream.send(&request),
            "tools/list" => {
                record_inventory_event(&self.config, &self.inventory)?;
                Ok((!is_notification).then_some(tools_list_response(&request, &self.inventory)))
            }
            "tools/call" if request.pointer("/params/task").is_some() => {
                self.handle_bounded_method(request, is_notification)
            }
            "tools/call" => {
                let request = strip_model_controlled_execution_metadata(&request);
                let admission = match admit_tool_call(
                    &self.config,
                    &self.bundle_proof,
                    &self.policy_graph,
                    &self.inventory,
                    &request,
                    &self.used_approval_receipts,
                ) {
                    Ok(admission) => admission,
                    Err(error) => {
                        return Ok((!is_notification).then_some(jsonrpc_error(
                            request.get("id").cloned(),
                            -32070,
                            "Velvet Rope fail-closed before upstream execution",
                            json!({
                                "boundary": "pre_execution_authorization",
                                "detail": error.to_string(),
                            }),
                        )));
                    }
                };
                write_approval_request_if_needed(&self.config, &admission)?;
                let pre_record = record_pre_execution_ledger(&self.config, &request, &admission)?;
                if is_executable_admission(&admission) {
                    let prepared = match prepare_execution(
                        &self.config,
                        &self.bundle_proof,
                        &request,
                        &admission,
                        &pre_record,
                        &self.claim_store,
                    ) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            return Ok((!is_notification).then_some(jsonrpc_error(
                                request.get("id").cloned(),
                                -32070,
                                "Velvet Rope failed to prepare execution permit",
                                json!({
                                    "boundary": "execution_permit_preparation",
                                    "detail": error.to_string(),
                                }),
                            )));
                        }
                    };
                    let authorized = match authorize_execution(
                        &self.config,
                        prepared,
                        &self.claim_store,
                        "stdio_proxy",
                    ) {
                        Ok(authorized) => authorized,
                        Err(error) => {
                            return Ok((!is_notification).then_some(jsonrpc_error(
                                request.get("id").cloned(),
                                -32070,
                                "Velvet Rope failed to claim execution permit",
                                json!({
                                    "boundary": "execution_permit_claim",
                                    "detail": error.to_string(),
                                }),
                            )));
                        }
                    };
                    if let Some(receipt) = &admission.approval_receipt
                        && receipt.one_time_use
                    {
                        self.used_approval_receipts
                            .insert(receipt.approval_receipt_id.clone());
                    }
                    let upstream_request = if self.config.forwarding.attach_execution {
                        attach_execution_metadata_to_request(&request, &authorized)?
                    } else {
                        request.clone()
                    };
                    verify_outbound_request_matches_permit(&request, &authorized)?;
                    let started_at = now_rfc3339_z();
                    match self.upstream.send(&upstream_request) {
                        Ok(response) => {
                            let response_hash = response.as_ref().map(value_hash);
                            let receipt = build_execution_receipt(
                                &self.config,
                                &authorized,
                                ExecutionReceiptObservation {
                                    outcome: velvet_core::ExecutionOutcome::Succeeded,
                                    dispatch_attempted: true,
                                    started_at: &started_at,
                                    upstream_response_hash: response_hash.clone(),
                                    error_code: None,
                                    error_detail: None,
                                },
                            )?;
                            record_post_execution_ledger(
                                &self.config,
                                &request,
                                &admission,
                                PostExecutionObservation {
                                    pre_execution_record_hash: &pre_record.record_hash,
                                    upstream_status: "forwarded",
                                    upstream_response_hash: response_hash.clone(),
                                    error_message: None,
                                    execution_receipt: Some(&serde_json::to_value(&receipt)?),
                                },
                            )?;
                            mark_execution_complete(&self.claim_store, &authorized, &receipt)?;
                            Ok(response.map(|response| {
                                attach_oap_decision(response, &admission, &pre_record)
                            }))
                        }
                        Err(error) => {
                            let detail = error.to_string();
                            let receipt = build_execution_receipt(
                                &self.config,
                                &authorized,
                                ExecutionReceiptObservation {
                                    outcome: velvet_core::ExecutionOutcome::Indeterminate,
                                    dispatch_attempted: true,
                                    started_at: &started_at,
                                    upstream_response_hash: None,
                                    error_code: Some("upstream_error_after_dispatch_attempt"),
                                    error_detail: Some(&detail),
                                },
                            )?;
                            record_post_execution_ledger(
                                &self.config,
                                &request,
                                &admission,
                                PostExecutionObservation {
                                    pre_execution_record_hash: &pre_record.record_hash,
                                    upstream_status: "indeterminate",
                                    upstream_response_hash: None,
                                    error_message: Some(&detail),
                                    execution_receipt: Some(&serde_json::to_value(&receipt)?),
                                },
                            )?;
                            mark_execution_complete(&self.claim_store, &authorized, &receipt)?;
                            if is_notification {
                                Err(error)
                            } else {
                                Ok(Some(jsonrpc_error(
                                    request.get("id").cloned(),
                                    -32060,
                                    "upstream MCP call failed",
                                    json!({
                                        "boundary": "upstream_forwarding",
                                        "oap_decision_id": admission.oap.decision.get("decision_id"),
                                        "detail": error.to_string(),
                                    }),
                                )))
                            }
                        }
                    }
                } else {
                    Ok((!is_notification).then_some(denial_response(
                        &request,
                        &admission,
                        &pre_record,
                    )))
                }
            }
            _ => self.handle_bounded_method(request, is_notification),
        }
    }

    fn handle_bounded_method(
        &mut self,
        request: Value,
        is_notification: bool,
    ) -> Result<Option<Value>> {
        let decision = bounded_method_decision(&self.config, &request);
        let pre_record =
            record_bounded_method_ledger(&self.config, &self.bundle_proof, &request, &decision)?;
        match decision.disposition {
            BoundedMethodDisposition::AllowPassthrough => match self.upstream.send(&request) {
                Ok(response) => {
                    let response_hash = response.as_ref().map(value_hash);
                    record_bounded_method_observation(
                        &self.config,
                        &request,
                        &decision,
                        &pre_record.record_hash,
                        "forwarded",
                        response_hash,
                        None,
                    )?;
                    Ok(response)
                }
                Err(error) => {
                    let detail = error.to_string();
                    record_bounded_method_observation(
                        &self.config,
                        &request,
                        &decision,
                        &pre_record.record_hash,
                        "failed",
                        None,
                        Some(&detail),
                    )?;
                    if is_notification {
                        Err(error)
                    } else {
                        Ok(Some(jsonrpc_error(
                            request.get("id").cloned(),
                            -32060,
                            "upstream MCP bounded method failed",
                            json!({
                                "boundary": "bounded_upstream_forwarding",
                                "method": decision.method.as_str(),
                                "detail": detail,
                            }),
                        )))
                    }
                }
            },
            BoundedMethodDisposition::Block | BoundedMethodDisposition::Escalate => {
                Ok((!is_notification).then_some(bounded_method_response(&request, &decision)))
            }
        }
    }
}
