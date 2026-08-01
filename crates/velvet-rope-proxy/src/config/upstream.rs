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
use crate::constants::*;
use crate::demo::*;
use crate::enforcement::*;
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    pub server: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub endpoint: Option<String>,
    pub boundary: UpstreamBoundaryConfig,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            server: "fake".to_string(),
            command: None,
            args: Vec::new(),
            endpoint: None,
            boundary: UpstreamBoundaryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamBoundaryConfig {
    pub required: bool,
    pub require_bearer: bool,
    pub require_mtls: bool,
    pub bearer: UpstreamBoundaryBearerConfig,
    pub mtls: UpstreamBoundaryMtlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamBoundaryBearerConfig {
    pub header_name: String,
    pub scheme: String,
    pub token_env: Option<String>,
    pub token_file: Option<PathBuf>,
}

impl Default for UpstreamBoundaryBearerConfig {
    fn default() -> Self {
        Self {
            header_name: header::AUTHORIZATION.as_str().to_string(),
            scheme: "Bearer".to_string(),
            token_env: None,
            token_file: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamBoundaryMtlsConfig {
    pub identity_pem_env: Option<String>,
    pub identity_pem_file: Option<PathBuf>,
    pub ca_bundle_pem_env: Option<String>,
    pub ca_bundle_pem_file: Option<PathBuf>,
}
