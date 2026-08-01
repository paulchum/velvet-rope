#![allow(unused_imports)]

mod auth;
mod control_plane;
mod evidence;
mod gateway;
mod http;
mod identity;
mod limits;
mod policy;
mod signing;
mod upstream;

pub use auth::AuthConfig;
pub use control_plane::ControlPlaneConfig;
pub use evidence::{EvidenceConfig, EvidenceSink};
pub use gateway::GatewayConfig;
pub use http::HttpConfig;
pub use identity::IdentityConfig;
pub use limits::{LedgerConfig, LedgerSink, LimitConfig};
pub use policy::PolicyConfig;
pub use signing::{SigningConfig, SigningProviderKind};
pub use upstream::{
    UpstreamBoundaryBearerConfig, UpstreamBoundaryConfig, UpstreamBoundaryMtlsConfig,
    UpstreamConfig,
};

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
use crate::constants::*;
use crate::demo::*;
use crate::enforcement::*;
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Fake,
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaDriftAction {
    Deny,
    Escalate,
}

pub(crate) fn default_schema_drift_action() -> SchemaDriftAction {
    SchemaDriftAction::Deny
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    #[default]
    Strict,
    Development,
    Shadow,
}

impl EnforcementMode {
    pub(crate) fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedMethodDisposition {
    AllowPassthrough,
    Block,
    Escalate,
}

impl BoundedMethodDisposition {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AllowPassthrough => "allow_passthrough",
            Self::Block => "block",
            Self::Escalate => "escalate",
        }
    }

    pub(crate) fn upstream_status(self) -> &'static str {
        match self {
            Self::AllowPassthrough => "forwarding_allowed",
            Self::Block => "not_forwarded",
            Self::Escalate => "pending_approval",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MethodDispositionConfig {
    pub resources: Option<BoundedMethodDisposition>,
    pub prompts: Option<BoundedMethodDisposition>,
    pub tasks: Option<BoundedMethodDisposition>,
    pub notifications: Option<BoundedMethodDisposition>,
    pub unknown: Option<BoundedMethodDisposition>,
    pub methods: BTreeMap<String, BoundedMethodDisposition>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardingConfig {
    pub attach_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub mode: EnforcementMode,
    pub identity: IdentityConfig,
    pub oap: OapConfig,
    pub transport: TransportKind,
    pub upstream: UpstreamConfig,
    pub policy: PolicyConfig,
    pub tools: Vec<ToolApproval>,
    pub approvals: Vec<ApprovalReceipt>,
    pub approval_receipts: ApprovalReceiptConfig,
    pub method_dispositions: MethodDispositionConfig,
    pub ledger_path: PathBuf,
    pub ledger: LedgerConfig,
    pub control_plane: ControlPlaneConfig,
    pub evidence: EvidenceConfig,
    pub signing: SigningConfig,
    pub gateway: GatewayConfig,
    pub thread_path: Option<PathBuf>,
    pub inventory_path: Option<PathBuf>,
    pub approval_requests_path: Option<PathBuf>,
    pub evidence_pack_path: Option<PathBuf>,
    #[serde(default = "default_schema_drift_action")]
    pub schema_drift_action: SchemaDriftAction,
    pub limits: LimitConfig,
    pub auth: AuthConfig,
    pub http: HttpConfig,
    pub forwarding: ForwardingConfig,
    pub demo_requests: Vec<Value>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Strict,
            identity: IdentityConfig::default(),
            oap: OapConfig::default(),
            transport: TransportKind::Fake,
            upstream: UpstreamConfig::default(),
            policy: PolicyConfig::default(),
            tools: Vec::new(),
            approvals: Vec::new(),
            approval_receipts: ApprovalReceiptConfig::default(),
            method_dispositions: MethodDispositionConfig::default(),
            ledger_path: PathBuf::from("reports/mcp_proxy/velvet_ledger.vledger"),
            ledger: LedgerConfig::default(),
            control_plane: ControlPlaneConfig::default(),
            evidence: EvidenceConfig::default(),
            signing: SigningConfig::default(),
            gateway: GatewayConfig::default(),
            thread_path: Some(PathBuf::from("reports/mcp_proxy/mcp_thread.jsonl")),
            inventory_path: Some(PathBuf::from("reports/mcp_proxy/inventory.json")),
            approval_requests_path: Some(PathBuf::from(
                "reports/mcp_proxy/approval_requests.jsonl",
            )),
            evidence_pack_path: Some(PathBuf::from("reports/mcp_proxy/evidence_pack.json")),
            schema_drift_action: SchemaDriftAction::Deny,
            limits: LimitConfig::default(),
            auth: AuthConfig::default(),
            http: HttpConfig::default(),
            forwarding: ForwardingConfig::default(),
            demo_requests: Vec::new(),
        }
    }
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("read proxy config {}", path.display()))?;
        serde_yaml::from_str(&source)
            .with_context(|| format!("parse proxy config {}", path.display()))
    }

    pub(crate) fn tool_by_name(&self, name: &str) -> Option<&ToolApproval> {
        self.tools.iter().find(|tool| tool.name == name)
    }
}
