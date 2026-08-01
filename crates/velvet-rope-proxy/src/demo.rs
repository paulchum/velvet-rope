#![allow(unused_imports)]

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
use crate::enforcement::*;
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Default)]
pub struct FakeMcpServer {
    counts: BTreeMap<String, usize>,
}

impl FakeMcpServer {
    pub fn tools() -> Vec<Value> {
        fake_tools()
    }
}

impl McpUpstream for FakeMcpServer {
    fn send(&mut self, request: &Value) -> Result<Option<Value>> {
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        if request.get("id").is_none() {
            return Ok(None);
        }
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        *self.counts.entry(format!("method:{method}")).or_default() += 1;
        match method {
            "initialize" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {
                        "name": "fake-enterprise-mcp",
                        "version": "1.0.0"
                    }
                }
            }))),
            "ping" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }))),
            "resources/list" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resources": []}
            }))),
            "resources/read" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"contents": []}
            }))),
            "prompts/list" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"prompts": []}
            }))),
            "prompts/get" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"messages": []}
            }))),
            "tools/list" => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": Self::tools()}
            }))),
            "tools/call" => {
                let (name, arguments) = call_params(request)?;
                *self.counts.entry(name.clone()).or_default() += 1;
                Ok(Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": format!("fake server executed {name}")
                        }],
                        "structuredContent": {
                            "tool": name,
                            "arguments": arguments
                        },
                        "isError": false
                    }
                })))
            }
            _ => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method not found"}
            }))),
        }
    }

    fn execution_count(&self, tool: &str) -> usize {
        self.counts.get(tool).copied().unwrap_or(0)
    }
}

pub fn fake_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "search_change_requests",
            "title": "Search Change Requests",
            "description": "Read-only ServiceNow change request search.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            },
            "annotations": {"readOnlyHint": true}
        }),
        json!({
            "name": "create_change_request",
            "title": "Create Change Request",
            "description": "Create a production change request.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "summary": {"type": "string"},
                    "window": {"type": "string"}
                },
                "required": ["service", "summary"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false}
        }),
        json!({
            "name": "delete_change_request",
            "title": "Delete Change Request",
            "description": "Delete a production change request.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "change_id": {"type": "string"}
                },
                "required": ["change_id"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true}
        }),
    ]
}

pub(crate) fn default_demo_requests() -> Vec<Value> {
    vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "velvet-demo", "version": "1.0.0"}
            }
        }),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_change_requests",
                "arguments": {"query": "service=payments state=open"},
                "_meta": {"user_request": "Find open production payment-service changes."}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "create_change_request",
                "arguments": {"service": "payments", "summary": "Approve routing fix"},
                "_meta": {"user_request": "Open a production change request."}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "delete_change_request",
                "arguments": {"change_id": "CHG0042007"},
                "_meta": {"user_request": "Remove the stale production change request."}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "drop_database",
                "arguments": {"database": "prod"},
                "_meta": {"user_request": "Drop the production database."}
            }
        }),
    ]
}

pub fn example_tool_approvals(server: &str) -> Result<Vec<ToolApproval>> {
    let mut approvals = Vec::new();
    for tool in fake_tools() {
        let name = tool_name(&tool)?;
        let hash = tool_schema_hash(&tool)?;
        let (risk_class, approval_tier, destructive, usd_estimate, expected_improvement) =
            match name.as_str() {
                "search_change_requests" => {
                    (RiskClass::Low, ApprovalTier::AutoApprove, false, None, 0.90)
                }
                "create_change_request" => (
                    RiskClass::High,
                    ApprovalTier::ConciergeReview,
                    false,
                    Some(75.0),
                    0.84,
                ),
                "delete_change_request" => (
                    RiskClass::High,
                    ApprovalTier::Blocked,
                    true,
                    Some(100.0),
                    0.30,
                ),
                _ => unreachable!(),
            };
        let max_de = match (destructive, &approval_tier) {
            (true, _) | (_, ApprovalTier::Blocked) => fallback_maxde_config_for_decision("block"),
            (_, ApprovalTier::ConciergeReview) => fallback_maxde_config_for_decision("escalate"),
            _ => fallback_maxde_config_for_decision("execute"),
        };
        approvals.push(ToolApproval {
            server: server.to_string(),
            name,
            approved_schema_hash: hash,
            risk_class,
            approval_tier,
            disposition: ToolDisposition::Approved,
            destructive,
            destructive_approval: None,
            allowed_environments: vec![
                "local".to_string(),
                "staging".to_string(),
                "prod".to_string(),
            ],
            allowed_subjects: Vec::new(),
            expected_improvement,
            novelty: 0.62,
            confidence: 0.78,
            usd_estimate,
            max_de: Some(max_de),
            metadata: BTreeMap::new(),
        });
    }
    Ok(approvals)
}

pub fn run_demo(output_dir: &Path) -> Result<Value> {
    ensure_demo_signing_env();
    fs::create_dir_all(output_dir)?;
    let policy_dir = output_dir.join("policies");
    fs::create_dir_all(&policy_dir)?;
    fs::write(policy_dir.join("mcp_demo.yaml"), EXAMPLE_POLICY)?;
    let manifest_path = output_dir.join("policy-bundle.yaml");
    let bundle_hash = policy_dir_hash(&policy_dir, &manifest_path)?;
    let manifest = PolicyBundleManifest {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_hash,
        expires_at: (Utc::now() + Duration::days(7)).to_rfc3339(),
        signature: None,
    };
    fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;
    let config = ProxyConfig {
        mode: EnforcementMode::Strict,
        identity: IdentityConfig {
            tenant_id: "tenant-demo".to_string(),
            environment: "local".to_string(),
            product_surface: "velvet_inline_gateway.mcp".to_string(),
            subject_id: Some("user-demo".to_string()),
            agent_id: Some("agent-demo".to_string()),
            client_id: Some("velvet-demo-client".to_string()),
            session_id: Some("sess-demo".to_string()),
        },
        oap: OapConfig {
            passport_created_at: Some("2026-05-28T00:00:00Z".to_string()),
            passport_updated_at: Some("2026-05-28T00:00:00Z".to_string()),
            ..OapConfig::default()
        },
        transport: TransportKind::Fake,
        upstream: UpstreamConfig {
            server: "servicenow".to_string(),
            ..UpstreamConfig::default()
        },
        policy: PolicyConfig {
            dir: policy_dir,
            chain: "mcp_demo".to_string(),
            bundle_manifest: manifest_path,
            require_signature: false,
            trusted_signature_public_key_hex: None,
            trusted_signature_public_key_hex_env: None,
        },
        tools: example_tool_approvals("servicenow")?,
        approvals: Vec::new(),
        approval_receipts: ApprovalReceiptConfig::default(),
        method_dispositions: MethodDispositionConfig::default(),
        ledger_path: output_dir.join("velvet_ledger.vledger"),
        ledger: LedgerConfig::default(),
        control_plane: ControlPlaneConfig::default(),
        evidence: EvidenceConfig::default(),
        signing: SigningConfig::default(),
        gateway: GatewayConfig::default(),
        thread_path: Some(output_dir.join("mcp_thread.jsonl")),
        inventory_path: Some(output_dir.join("inventory.json")),
        approval_requests_path: Some(output_dir.join("approval_requests.jsonl")),
        evidence_pack_path: Some(output_dir.join("evidence_pack.json")),
        schema_drift_action: SchemaDriftAction::Deny,
        limits: LimitConfig::default(),
        auth: AuthConfig::default(),
        http: HttpConfig::default(),
        forwarding: ForwardingConfig::default(),
        demo_requests: default_demo_requests(),
    };
    fs::write(
        output_dir.join("config.yaml"),
        serde_yaml::to_string(&config)?,
    )?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let summary = runtime.run_fake_script()?;
    write_demo_evidence_pack(output_dir, &summary)?;
    Ok(summary)
}

pub(crate) fn write_demo_evidence_pack(output_dir: &Path, summary: &Value) -> Result<()> {
    let ledger_path = output_dir.join("velvet_ledger.vledger");
    let ledger_records = if ledger_path.exists() {
        read_binary_ledger_frames(&ledger_path)?
            .into_iter()
            .map(|frame| frame.payload)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let decisions = ledger_records
        .iter()
        .filter_map(|record| record.get("decision").and_then(Value::as_str))
        .fold(BTreeMap::<String, usize>::new(), |mut counts, decision| {
            *counts.entry(decision.to_string()).or_default() += 1;
            counts
        });
    let pack = json!({
        "schema_version": EVIDENCE_PACK_SCHEMA_VERSION,
        "generated_at": Utc::now().to_rfc3339(),
        "mcp_spec_target": MCP_SPEC_TARGET,
        "summary": summary,
        "artifacts": {
            "policy_bundle": output_dir.join("policy-bundle.yaml"),
            "tool_registry": output_dir.join("config.yaml"),
            "inventory": output_dir.join("inventory.json"),
            "oap_decisions_envelopes_and_ledger": ledger_path,
            "approval_requests": output_dir.join("approval_requests.jsonl"),
            "thread": output_dir.join("mcp_thread.jsonl")
        },
        "decision_counts": decisions,
        "blocked_calls_forwarded": summary.pointer("/execution_counts/delete_change_request").and_then(Value::as_u64).unwrap_or(0),
        "unknown_calls_forwarded": summary.pointer("/execution_counts/drop_database").and_then(Value::as_u64).unwrap_or(0),
        "verifier": {
            "ledger_records": ledger_records.len(),
            "status": "generated"
        }
    });
    fs::write(
        output_dir.join("evidence_pack.json"),
        serde_json::to_string_pretty(&pack)? + "\n",
    )?;
    Ok(())
}

pub fn surface_matrix() -> Value {
    json!({
        "schema_version": "velvet.mcp_proxy.surface_matrix.v1",
        "mcp_spec_target": MCP_SPEC_TARGET,
        "proxy": PROXY_NAME,
        "version": PROXY_VERSION,
        "rows": [
            {"method": "tools/list", "disposition": "enforced", "strict_mode_default": "filter_inventory", "recorded": "yes", "notes": "Upstream inventory is classified, schema-hashed, filtered, and written as redacted inventory evidence."},
            {"method": "tools/call", "disposition": "enforced", "strict_mode_default": "policy_decision", "recorded": "yes", "notes": "Pre-execution OAP Decision, policy-required Velvet-signed Max-DE Certificate Envelope, and two-record Ledger flow."},
            {"method": "initialize", "disposition": "lifecycle-forwarded", "strict_mode_default": "forward", "recorded": "no", "notes": "Connection lifecycle method; request and response IDs are preserved."},
            {"method": "notifications/initialized", "disposition": "lifecycle-forwarded", "strict_mode_default": "forward", "recorded": "no", "notes": "Connection lifecycle notification; no proxy response is emitted."},
            {"method": "ping", "disposition": "lifecycle-forwarded", "strict_mode_default": "forward", "recorded": "no", "notes": "Connection liveness method."},
            {"method": "resources/*", "disposition": "bounded-governed", "strict_mode_default": "block", "recorded": "yes", "notes": "No semantic resource enforcement in this pass; recorded passthrough requires explicit deployment config."},
            {"method": "prompts/*", "disposition": "bounded-governed", "strict_mode_default": "block", "recorded": "yes", "notes": "Prompt surface is default-deny; recorded passthrough requires explicit deployment config."},
            {"method": "tasks/*", "disposition": "bounded-governed", "strict_mode_default": "block", "recorded": "yes", "notes": "Task methods are outside this scoped gateway and default to a recorded block."},
            {"method": "notifications/*", "disposition": "bounded-governed", "strict_mode_default": "block", "recorded": "yes", "notes": "Only notifications/initialized is lifecycle-forwarded; other notifications use bounded governance."},
            {"method": "*", "disposition": "bounded-governed", "strict_mode_default": "block", "recorded": "yes", "notes": "Unknown methods fail closed unless explicitly configured for recorded passthrough."}
        ]
    })
}

pub fn conformance_matrix() -> Value {
    json!({
        "schema_version": PROXY_CONFORMANCE_SCHEMA_VERSION,
        "mcp_spec_target": MCP_SPEC_TARGET,
        "proxy": PROXY_NAME,
        "version": PROXY_VERSION,
        "surface_matrix": surface_matrix()["rows"].clone(),
        "methods": [
            {"method": "initialize", "behavior": "lifecycle-forwarded", "notes": "request/response IDs are preserved; proxy does not claim upstream capabilities it does not observe"},
            {"method": "notifications/initialized", "behavior": "lifecycle-forwarded", "notes": "notification forwarded without proxy response"},
            {"method": "ping", "behavior": "lifecycle-forwarded", "notes": "transparent unless upstream fails"},
            {"method": "tools/list", "behavior": "enforced", "notes": "upstream inventory is classified; only approved non-drifted tools are exposed"},
            {"method": "tools/call", "behavior": "enforced", "notes": "pre-execution OAP Decision, Velvet Max-DE envelope, Ledger, and forwarding proof"},
            {"method": "resources/*", "behavior": "bounded-governed", "notes": "strict default block; recorded passthrough requires explicit config"},
            {"method": "prompts/*", "behavior": "bounded-governed", "notes": "strict default block; recorded passthrough requires explicit config"},
            {"method": "tasks/*", "behavior": "bounded-governed", "notes": "strict default block; recorded passthrough requires explicit config"},
            {"method": "notifications/*", "behavior": "bounded-governed", "notes": "except notifications/initialized, strict default block; recorded passthrough requires explicit config"},
            {"method": "*", "behavior": "bounded-governed", "notes": "unknown methods fail closed unless explicitly configured for recorded passthrough"}
        ],
        "transports": [
            {"transport": "stdio", "status": "supported", "notes": "newline-delimited JSON-RPC with separate child stderr and bounded request handling"},
            {"transport": "streamable_http", "status": "supported", "notes": "MCP 2025-11-25 Streamable HTTP with POST JSON/SSE responses, GET SSE listen streams, sessions, DELETE termination, and bounded Last-Event-ID replay"},
            {"transport": "legacy_sse", "status": "unsupported", "notes": "not enabled by default"}
        ],
        "streamable_http_capabilities": [
            {"capability": "sessions", "status": "supported", "notes": "captures upstream MCP-Session-Id on initialize, validates visible ASCII IDs, maps downstream to upstream session IDs, and requires known sessions for stateful follow-up requests"},
            {"capability": "sse_get", "status": "supported", "notes": "GET requires Accept: text/event-stream and opens independent upstream SSE listen streams"},
            {"capability": "post_sse_responses", "status": "supported", "notes": "POST requests can return application/json or text/event-stream; terminal JSON-RPC responses retain OAP metadata for admitted tools/call"},
            {"capability": "last_event_id_replay", "status": "supported", "notes": "bounded in-memory replay is scoped to the matching session stream only"},
            {"capability": "delete_session", "status": "supported", "notes": "DELETE forwards upstream when stateful, removes local session state, and terminates replay buffers"},
            {"capability": "json_rpc_response_forwarding", "status": "supported", "notes": "client JSON-RPC responses are forwarded upstream and return HTTP 202 on acceptance"},
            {"capability": "origin_and_bearer_checks", "status": "supported", "notes": "Origin allow-list and optional bearer auth are enforced before upstream forwarding"}
        ],
        "auth": [
            {"mode": "bearer_token", "status": "supported", "notes": "optional HTTP bearer validation against an environment variable; Authorization is redacted and not forwarded unless configured"},
            {"mode": "stdio_credentials", "status": "documented_boundary", "notes": "environment variables and local credentials are treated as upstream process secrets"}
        ],
        "json_rpc": {
            "requests": "supported",
            "responses": "forwarded",
            "notifications": "supported without proxy response",
            "parse_errors": "JSON-RPC -32700",
            "invalid_requests": "JSON-RPC -32600",
            "method_not_found": "bounded-governed by Velvet before any upstream propagation",
            "batch": "supported for stdio/backwards-compatible runtime paths; rejected for MCP 2025-11-25 Streamable HTTP"
        },
        "known_limitations": [
            "resources and prompts are bounded-governed but do not receive semantic content enforcement in this scoped gateway",
            "argument validation implements the JSON Schema subset needed for MCP tool inputs; unsupported schema features fail by policy or are documented"
        ]
    })
}

pub fn run_benchmark(output_dir: &Path, iterations: usize) -> Result<Value> {
    ensure_demo_signing_env();
    fs::create_dir_all(output_dir)?;
    let setup_dir = output_dir.join("setup");
    fs::create_dir_all(&setup_dir)?;
    let config = ProxyConfig {
        mode: EnforcementMode::Strict,
        identity: IdentityConfig {
            tenant_id: "tenant-benchmark".to_string(),
            environment: "local".to_string(),
            product_surface: "velvet_inline_gateway.mcp".to_string(),
            subject_id: Some("benchmark-user".to_string()),
            agent_id: Some("benchmark-agent".to_string()),
            client_id: Some("benchmark-client".to_string()),
            session_id: Some("benchmark-session".to_string()),
        },
        oap: OapConfig {
            passport_created_at: Some("2026-05-28T00:00:00Z".to_string()),
            passport_updated_at: Some("2026-05-28T00:00:00Z".to_string()),
            ..OapConfig::default()
        },
        transport: TransportKind::Fake,
        upstream: UpstreamConfig {
            server: "servicenow".to_string(),
            ..UpstreamConfig::default()
        },
        policy: {
            let policy_dir = setup_dir.join("policies");
            fs::create_dir_all(&policy_dir)?;
            fs::write(policy_dir.join("mcp_demo.yaml"), EXAMPLE_POLICY)?;
            let manifest_path = setup_dir.join("policy-bundle.yaml");
            let manifest = PolicyBundleManifest {
                schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
                bundle_hash: policy_dir_hash(&policy_dir, &manifest_path)?,
                expires_at: (Utc::now() + Duration::days(7)).to_rfc3339(),
                signature: None,
            };
            fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;
            PolicyConfig {
                dir: policy_dir,
                chain: "mcp_demo".to_string(),
                bundle_manifest: manifest_path,
                require_signature: false,
                trusted_signature_public_key_hex: None,
                trusted_signature_public_key_hex_env: None,
            }
        },
        tools: example_tool_approvals("servicenow")?,
        approvals: Vec::new(),
        approval_receipts: ApprovalReceiptConfig::default(),
        method_dispositions: MethodDispositionConfig::default(),
        ledger_path: output_dir.join("benchmark_ledger.vledger"),
        ledger: LedgerConfig {
            strict: true,
            fsync: false,
            sink: LedgerSink::LocalFile,
            segment_manifest_path: None,
        },
        control_plane: ControlPlaneConfig::default(),
        evidence: EvidenceConfig::default(),
        signing: SigningConfig::default(),
        gateway: GatewayConfig::default(),
        thread_path: None,
        inventory_path: Some(output_dir.join("benchmark_inventory.json")),
        approval_requests_path: None,
        evidence_pack_path: None,
        schema_drift_action: SchemaDriftAction::Deny,
        limits: LimitConfig::default(),
        auth: AuthConfig::default(),
        http: HttpConfig::default(),
        forwarding: ForwardingConfig::default(),
        demo_requests: Vec::new(),
    };
    if config.ledger_path.exists() {
        fs::remove_file(&config.ledger_path)?;
    }
    let runtime_start = Instant::now();
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let cold_start_ms = runtime_start.elapsed().as_millis();
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        runtime.handle_message(json!({
            "jsonrpc": "2.0",
            "id": "bench",
            "method": "tools/call",
            "params": {
                "name": "search_change_requests",
                "arguments": {"query": "service=payments state=open"}
            }
        }))?;
        latencies.push(start.elapsed().as_micros() as u64);
    }
    latencies.sort_unstable();
    let percentile = |p: f64| -> u64 {
        if latencies.is_empty() {
            return 0;
        }
        let index = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[index]
    };
    let total_us: u64 = latencies.iter().sum();
    let summary = json!({
        "schema_version": "velvet.mcp_proxy.benchmark.v1",
        "generated_at": Utc::now().to_rfc3339(),
        "iterations": iterations,
        "benchmark_machine": std::env::consts::OS,
        "policy_complexity": "example_mcp_demo_chain",
        "registry_size": runtime.inventory.entries.len(),
        "payload_size_bytes": serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "bench",
            "method": "tools/call",
            "params": {
                "name": "search_change_requests",
                "arguments": {"query": "service=payments state=open"}
            }
        })).map(|bytes| bytes.len()).unwrap_or(0),
        "cold_start_ms": cold_start_ms,
        "tools_call_overhead_us": {
            "p50": percentile(0.50),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
            "max": latencies.last().copied().unwrap_or(0)
        },
        "throughput_per_second": if total_us == 0 { 0.0 } else { iterations as f64 / (total_us as f64 / 1_000_000.0) },
        "memory_usage": "not_measured_in_process",
        "cpu_usage": "not_measured_in_process"
    });
    fs::write(
        output_dir.join("benchmark_summary.json"),
        serde_json::to_string_pretty(&summary)? + "\n",
    )?;
    Ok(summary)
}

pub const EXAMPLE_POLICY: &str = r#"apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: pii_guard
  version: 1
spec:
  type: pii_guard
  config:
    default_mode: redact
    per_action_mode: {}
    list_context_keys:
      - own_email
      - account_email
    enabled_detectors:
      - email
      - ssn
      - phone
      - credit_card
      - iban
      - postal_code
---
apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: prompt_injection_detector
  version: 1
spec:
  type: prompt_injection_detector
  config:
    default_action: block
    source_rules:
      default:
        - id: ignore_previous_instructions
          pattern: '(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|system|developer)\b.{0,30}\b(instruction|message|prompt)s?\b'
          severity: error
    embedding_threshold: 0.86
    distance_metric: cosine
    pid_classifier_path: null
---
apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: cost_ceiling
  version: 1
spec:
  type: cost_ceiling
  config:
    per_task_usd_limit: null
    per_user_daily_usd_limit: null
    per_org_monthly_usd_limit: null
    soft_ceiling_fraction: 0.8
    cost_model: {}
---
apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: rate_limiter
  version: 1
spec:
  type: rate_limiter
  config:
    aggregate:
      window_ms: 60000
      max_requests: 1000000000
      sustained_per_second: 1000000.0
      burst_multiplier: 1.5
    per_action: {}
---
apiVersion: velvet.io/v1alpha1
kind: Policy
metadata:
  name: escalation_gate
  version: 1
spec:
  type: escalation_gate
  config:
    cost_threshold_usd: 25.0
    confidence_threshold: 0.2
    novelty_threshold: 0.98
    repeated_failure_threshold: 3
    sensitive_actions:
      - EXECUTE_CODE
    targets:
      concierge_review:
        target_type: velvet_concierge_queue
        target: local://velvet-concierge
        mode: sync
        fallback: deny
      model_escalation:
        target_type: escalation_model
        target: local://model-escalation
        mode: sync
        fallback: deny
    default_fallback: deny
---
apiVersion: velvet.io/v1alpha1
kind: PolicyChain
metadata:
  name: mcp_demo
  version: 1
spec:
  policies:
    - pii_guard
    - prompt_injection_detector
    - cost_ceiling
    - rate_limiter
    - escalation_gate
"#;
