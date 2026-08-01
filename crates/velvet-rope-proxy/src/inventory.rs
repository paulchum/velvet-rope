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
use crate::demo::*;
use crate::enforcement::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Approved,
    Blocked,
    Unknown,
    Missing,
    Drifted,
    Hidden,
    Deprecated,
    DestructiveUnapproved,
}

impl InventoryStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
            Self::Missing => "missing",
            Self::Drifted => "drifted",
            Self::Hidden => "hidden",
            Self::Deprecated => "deprecated",
            Self::DestructiveUnapproved => "destructive_unapproved",
        }
    }

    pub(crate) fn fail_closed_reason(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Blocked => "blocked tool denied before execution",
            Self::Unknown => "unknown tool denied before execution",
            Self::Missing => "approved tool missing from upstream inventory",
            Self::Drifted => "drifted schema denied before execution",
            Self::Hidden => "hidden tool denied before execution",
            Self::Deprecated => "deprecated tool denied before execution",
            Self::DestructiveUnapproved => "destructive tool denied before execution",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub name: String,
    pub tool_key: String,
    pub schema_hash: Option<String>,
    pub approved_schema_hash: Option<String>,
    pub status: InventoryStatus,
    pub destructive: bool,
    pub risk_class: Option<String>,
    pub approval_tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInventory {
    pub schema_version: String,
    pub generated_at: String,
    pub upstream_server: String,
    pub entries: BTreeMap<String, InventoryEntry>,
    #[serde(default)]
    pub(crate) upstream_tools: BTreeMap<String, Value>,
}

impl ToolInventory {
    pub fn build(config: &ProxyConfig, upstream_tools: &[Value]) -> Result<Self> {
        let now = Utc::now();
        let mut entries = BTreeMap::new();
        let mut upstream_by_name = BTreeMap::new();
        for tool in upstream_tools {
            let name = tool_name(tool)?;
            let schema_hash = tool_schema_hash(tool)?;
            upstream_by_name.insert(name.clone(), tool.clone());
            let entry = if let Some(approval) = config.tool_by_name(&name) {
                let environment_disallowed = !approval.allowed_environments.is_empty()
                    && !approval
                        .allowed_environments
                        .iter()
                        .any(|environment| environment == &config.identity.environment);
                let status = if environment_disallowed
                    || matches!(approval.disposition, ToolDisposition::Blocked)
                {
                    InventoryStatus::Blocked
                } else if matches!(approval.disposition, ToolDisposition::Hidden) {
                    InventoryStatus::Hidden
                } else if matches!(approval.disposition, ToolDisposition::Deprecated) {
                    InventoryStatus::Deprecated
                } else if approval.destructive && !approval.destructive_approved(now) {
                    InventoryStatus::DestructiveUnapproved
                } else if approval.approved_schema_hash != schema_hash {
                    InventoryStatus::Drifted
                } else {
                    InventoryStatus::Approved
                };
                InventoryEntry {
                    name: name.clone(),
                    tool_key: approval.key(),
                    schema_hash: Some(schema_hash),
                    approved_schema_hash: Some(approval.approved_schema_hash.clone()),
                    status,
                    destructive: approval.destructive,
                    risk_class: Some(approval.risk_class.as_str().to_string()),
                    approval_tier: Some(approval.approval_tier.as_str().to_string()),
                }
            } else {
                InventoryEntry {
                    name: name.clone(),
                    tool_key: mcp_tool_key(&config.upstream.server, &name),
                    schema_hash: Some(schema_hash),
                    approved_schema_hash: None,
                    status: InventoryStatus::Unknown,
                    destructive: false,
                    risk_class: None,
                    approval_tier: None,
                }
            };
            entries.insert(name, entry);
        }
        for approval in &config.tools {
            if !entries.contains_key(&approval.name) {
                entries.insert(
                    approval.name.clone(),
                    InventoryEntry {
                        name: approval.name.clone(),
                        tool_key: approval.key(),
                        schema_hash: None,
                        approved_schema_hash: Some(approval.approved_schema_hash.clone()),
                        status: InventoryStatus::Missing,
                        destructive: approval.destructive,
                        risk_class: Some(approval.risk_class.as_str().to_string()),
                        approval_tier: Some(approval.approval_tier.as_str().to_string()),
                    },
                );
            }
        }
        Ok(Self {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: now.to_rfc3339(),
            upstream_server: config.upstream.server.clone(),
            entries,
            upstream_tools: upstream_by_name,
        })
    }

    pub fn entry_for_call(&self, config: &ProxyConfig, name: &str) -> InventoryEntry {
        self.entries
            .get(name)
            .cloned()
            .unwrap_or_else(|| InventoryEntry {
                name: name.to_string(),
                tool_key: mcp_tool_key(&config.upstream.server, name),
                schema_hash: None,
                approved_schema_hash: None,
                status: InventoryStatus::Unknown,
                destructive: false,
                risk_class: None,
                approval_tier: None,
            })
    }

    pub fn approved_tools(&self) -> Vec<Value> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.status == InventoryStatus::Approved)
            .filter_map(|(name, _)| self.upstream_tools.get(name).cloned())
            .collect()
    }

    pub fn write_if_configured(&self, path: Option<&Path>) -> Result<()> {
        let Some(path) = path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedactionSummary {
    pub redaction_count: usize,
    pub redacted_fields: Vec<String>,
}

pub fn tool_schema_hash(tool: &Value) -> Result<String> {
    let name = tool_name(tool)?;
    let mut canonical = Map::new();
    canonical.insert("name".to_string(), Value::String(name));
    canonical.insert(
        "inputSchema".to_string(),
        tool.get("inputSchema").cloned().unwrap_or(Value::Null),
    );
    canonical.insert(
        "outputSchema".to_string(),
        tool.get("outputSchema").cloned().unwrap_or(Value::Null),
    );
    canonical.insert(
        "annotations".to_string(),
        tool.get("annotations").cloned().unwrap_or(Value::Null),
    );
    Ok(format!(
        "sha256:{}",
        sha256_hex(canonical_json(&Value::Object(canonical)).as_bytes())
    ))
}

pub(crate) fn tool_name(tool: &Value) -> Result<String> {
    tool.get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("MCP tool is missing a string name"))
}
