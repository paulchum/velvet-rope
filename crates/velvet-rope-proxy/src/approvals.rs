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

use crate::config::*;
use crate::constants::*;
use crate::demo::*;
use crate::enforcement::*;
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    #[default]
    Medium,
    High,
}

impl RiskClass {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub(crate) fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.15,
            Self::Medium => 0.45,
            Self::High => 0.85,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalTier {
    AutoApprove,
    #[default]
    ConciergeReview,
    Blocked,
}

impl ApprovalTier {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::AutoApprove => "auto_approve",
            Self::ConciergeReview => "concierge_review",
            Self::Blocked => "blocked",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalReceiptConfig {
    pub require_signature: bool,
    pub allow_unsigned_local_demo_only: bool,
    pub trusted_keys: Vec<TrustedApprovalReceiptKey>,
}

impl Default for ApprovalReceiptConfig {
    fn default() -> Self {
        Self {
            require_signature: true,
            allow_unsigned_local_demo_only: false,
            trusted_keys: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedApprovalReceiptKey {
    pub provider_name: String,
    pub algorithm: String,
    pub key_id: String,
    pub key_version: String,
    #[serde(default)]
    pub public_key_base64: Option<String>,
    #[serde(default)]
    pub public_key_base64_env: Option<String>,
    #[serde(default)]
    pub public_key_hex: Option<String>,
    #[serde(default)]
    pub public_key_hex_env: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolApproval {
    pub server: String,
    pub name: String,
    pub approved_schema_hash: String,
    pub risk_class: RiskClass,
    pub approval_tier: ApprovalTier,
    pub disposition: ToolDisposition,
    pub destructive: bool,
    pub destructive_approval: Option<DestructiveApproval>,
    pub allowed_environments: Vec<String>,
    pub allowed_subjects: Vec<String>,
    pub expected_improvement: f64,
    pub novelty: f64,
    pub confidence: f64,
    pub usd_estimate: Option<f64>,
    pub max_de: Option<MaxDeCertificateConfig>,
    pub metadata: BTreeMap<String, Value>,
}

impl Default for ToolApproval {
    fn default() -> Self {
        Self {
            server: "fake".to_string(),
            name: String::new(),
            approved_schema_hash: String::new(),
            risk_class: RiskClass::Medium,
            approval_tier: ApprovalTier::ConciergeReview,
            disposition: ToolDisposition::Approved,
            destructive: false,
            destructive_approval: None,
            allowed_environments: Vec::new(),
            allowed_subjects: Vec::new(),
            expected_improvement: 0.78,
            novelty: 0.60,
            confidence: 0.72,
            usd_estimate: None,
            max_de: None,
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDisposition {
    #[default]
    Approved,
    Blocked,
    Hidden,
    Deprecated,
}

impl ToolApproval {
    pub(crate) fn key(&self) -> String {
        mcp_tool_key(&self.server, &self.name)
    }

    pub(crate) fn destructive_approved(&self, now: DateTime<Utc>) -> bool {
        let Some(approval) = &self.destructive_approval else {
            return false;
        };
        if !approval.approved {
            return false;
        }
        parse_time(&approval.expires_at).is_ok_and(|expires_at| expires_at > now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveApproval {
    pub approved: bool,
    pub approver: String,
    pub reason: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceipt {
    pub schema_version: String,
    pub approval_receipt_id: String,
    pub approval_request_id: String,
    pub tenant_id: String,
    pub environment: String,
    pub subject_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub approver_id: String,
    pub tool_key: String,
    pub request_hash: String,
    #[serde(default)]
    pub arguments_hash: String,
    pub policy_hash: String,
    #[serde(default)]
    pub policy_version: String,
    pub tool_schema_hash: String,
    pub approved: bool,
    pub decided_at: String,
    pub expires_at: String,
    pub one_time_use: bool,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub conditions: Vec<String>,
    #[serde(default)]
    pub used_at: Option<String>,
    pub receipt_hash: String,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub schema_version: String,
    pub approval_request_id: String,
    pub tenant_id: String,
    pub environment: String,
    pub subject_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub tool_key: String,
    pub request_hash: String,
    #[serde(default)]
    pub arguments_hash: String,
    pub policy_hash: String,
    #[serde(default)]
    pub policy_version: String,
    pub tool_schema_hash: String,
    pub reason: String,
    #[serde(default)]
    pub risk_class: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

impl ApprovalReceipt {
    pub(crate) fn receipt_id(&self) -> &str {
        &self.approval_receipt_id
    }
}
