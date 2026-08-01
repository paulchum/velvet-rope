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

pub const LEDGER_CONTRACT: &str = "velvet.ledger";
pub const LEDGER_CONTRACT_REVISION: u8 = 1;
pub const LEDGER_SCHEMA_VERSION: &str = "velvet.oap_ledger.v1";
pub const INVENTORY_SCHEMA_VERSION: &str = "velvet.mcp_proxy.inventory.v1";
pub const POLICY_BUNDLE_SCHEMA_VERSION: &str = "velvet.policy_bundle.v1";
pub const APPROVAL_RECEIPT_SCHEMA_VERSION: &str = "velvet.approval_receipt.v1";
pub const ADMISSION_EVIDENCE_SCHEMA_VERSION: &str = "velvet.admission_evidence.v1";
pub const PROXY_CONFORMANCE_SCHEMA_VERSION: &str = "velvet.mcp_proxy.conformance.v1";
pub const EVIDENCE_PACK_SCHEMA_VERSION: &str = "velvet.mcp_proxy.evidence_pack.v1";
pub const CANONICALIZATION_UNSIGNED_PAYLOAD: &str =
    "velvet.canonical_json.v1.sha256.unsigned_payload";
pub const PROXY_NAME: &str = "velvet-rope-proxy";
pub const PROXY_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MCP_SPEC_TARGET: &str = "2025-11-25";
pub const DEFAULT_TLS_CHECK_URL: &str = "https://www.googleapis.com/discovery/v1/apis";
pub const LEDGER_GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub(crate) const VELVET_LEDGER_MAGIC: &[u8; 8] = b"VLVTLEDG";
pub(crate) const VELVET_LEDGER_FORMAT_VERSION: u8 = 1;
pub(crate) const VELVET_LEDGER_RECORD_MAX_BYTES: usize = 1_048_576;
pub(crate) const VELVET_LEDGER_PAYLOAD_HASH_DOMAIN: &[u8] = b"Velvet:Ledger:PayloadHash:v1";
pub(crate) const VELVET_LEDGER_RECORD_HASH_DOMAIN: &[u8] = b"Velvet:Ledger:RecordHash:v1";
pub(crate) const PURPOSE_LEDGER_RECORD_BINARY: &str = "velvet.ledger.record.binary.v1";
pub(crate) const PURPOSE_WARRANT: &str = "velvet.warrant.v1";
pub(crate) const PURPOSE_ADMISSION_EVIDENCE: &str = "velvet.admission_evidence.v1";
pub(crate) const BINARY_LEDGER_FORMAT: &str = "velvet.binary_ledger.v1";
pub(crate) const RECORD_KIND_CANONICAL: u8 = 1;
pub(crate) const RECORD_KIND_OAP: u8 = 2;
pub(crate) const LOCAL_DEMO_TENANT_ID: &str = "velvet-demo-tenant";
pub(crate) const LOCAL_DEMO_KEY_ID: &str = "velvet-local-dev-hmac-demo-key";
pub(crate) const LOCAL_DEMO_KEY_VERSION: &str = "demo-v1";
pub(crate) const LOCAL_DEMO_SIGNATURE_KEY: &str = "velvet-local-deterministic-demo-key";
pub(crate) const LOCAL_DEMO_PROVIDER_NAME: &str = "local_dev_hmac_demo";
pub(crate) const LOCAL_DEMO_ALGORITHM: &str = "HMAC-SHA256";
pub(crate) const SIGNATURE_SCHEMA_VERSION: &str = "velvet.signature.v2";
