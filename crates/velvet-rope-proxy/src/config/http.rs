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
pub struct HttpConfig {
    pub bind: String,
    pub endpoint_path: String,
    pub allow_plaintext_loopback_upstream: bool,
    pub allowed_origins: Vec<String>,
    pub supported_protocol_versions: Vec<String>,
    pub sse_enabled: bool,
    pub sse_replay_buffer_events: usize,
    pub sse_replay_ttl_seconds: u64,
    pub sse_keepalive_seconds: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8791".to_string(),
            endpoint_path: "/mcp".to_string(),
            allow_plaintext_loopback_upstream: false,
            allowed_origins: Vec::new(),
            supported_protocol_versions: vec![
                "2025-11-25".to_string(),
                "2025-06-18".to_string(),
                "2025-03-26".to_string(),
            ],
            sse_enabled: true,
            sse_replay_buffer_events: 256,
            sse_replay_ttl_seconds: 300,
            sse_keepalive_seconds: 15,
        }
    }
}
