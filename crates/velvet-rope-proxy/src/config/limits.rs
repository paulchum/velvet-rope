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
pub struct LimitConfig {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_arguments_bytes: usize,
    pub max_concurrent_requests: usize,
    pub upstream_timeout_ms: u64,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 4 * 1024 * 1024,
            max_arguments_bytes: 256 * 1024,
            max_concurrent_requests: 128,
            upstream_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerSink {
    #[default]
    LocalFile,
    ControlPlane,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LedgerConfig {
    pub strict: bool,
    pub fsync: bool,
    pub sink: LedgerSink,
    pub segment_manifest_path: Option<PathBuf>,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            strict: true,
            fsync: true,
            sink: LedgerSink::LocalFile,
            segment_manifest_path: None,
        }
    }
}
