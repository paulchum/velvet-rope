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
use crate::execution::{
    AuthorizedExecution, ExecutionReceiptObservation, attach_execution_metadata_to_request,
    authorize_execution, build_execution_receipt, is_executable_admission, mark_execution_complete,
    prepare_execution, strip_model_controlled_execution_metadata,
    verify_outbound_request_matches_permit,
};
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::permit_store::PermitClaimStore;
use crate::policy_bundle::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonRpcMessageKind {
    Request { method: String, id: Value },
    Notification { method: String },
    Response { id: Value },
    Batch,
    Invalid(String),
}

pub(crate) fn classify_json_rpc(value: &Value) -> JsonRpcMessageKind {
    if value.is_array() {
        return JsonRpcMessageKind::Batch;
    }
    let Some(object) = value.as_object() else {
        return JsonRpcMessageKind::Invalid("JSON-RPC message must be an object".to_string());
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return JsonRpcMessageKind::Invalid(
            "JSON-RPC message must declare jsonrpc 2.0".to_string(),
        );
    }
    let method = object.get("method").and_then(Value::as_str);
    let has_id = object.contains_key("id");
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    match (method, has_id, has_result || has_error) {
        (Some(method), true, false) if !method.is_empty() => JsonRpcMessageKind::Request {
            method: method.to_string(),
            id: object.get("id").cloned().unwrap_or(Value::Null),
        },
        (Some(method), false, false) if !method.is_empty() => JsonRpcMessageKind::Notification {
            method: method.to_string(),
        },
        (None, true, true) => JsonRpcMessageKind::Response {
            id: object.get("id").cloned().unwrap_or(Value::Null),
        },
        _ => JsonRpcMessageKind::Invalid("invalid JSON-RPC message shape".to_string()),
    }
}

impl JsonRpcMessageKind {
    fn method(&self) -> Option<&str> {
        match self {
            Self::Request { method, .. } | Self::Notification { method } => Some(method),
            Self::Response { .. } | Self::Batch | Self::Invalid(_) => None,
        }
    }

    fn is_notification(&self) -> bool {
        matches!(self, Self::Notification { .. })
    }

    fn is_response(&self) -> bool {
        matches!(self, Self::Response { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecyclePhase {
    InitializeResponded,
    Initialized,
}

#[derive(Debug, Clone)]
pub(crate) struct BufferedSseEvent {
    event: SseWireEvent,
    recorded_at: Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct SseReplayBuffer {
    events: VecDeque<BufferedSseEvent>,
    next_sequence: u64,
}

impl Default for SseReplayBuffer {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            next_sequence: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct McpHttpSession {
    upstream_session_id: Option<String>,
    protocol_version: String,
    lifecycle: LifecyclePhase,
    streams: BTreeMap<String, SseReplayBuffer>,
    pending_server_request_ids: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct StatelessHttpSession {
    protocol_version: String,
    lifecycle: LifecyclePhase,
}

#[derive(Debug, Default)]
pub(crate) struct HttpSessionStore {
    sessions: BTreeMap<String, McpHttpSession>,
    stateless: Option<StatelessHttpSession>,
    stateless_streams: BTreeMap<String, SseReplayBuffer>,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpRequestContext {
    downstream_session_id: Option<String>,
    upstream_session_id: Option<String>,
    protocol_version: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SseWireEvent {
    pub(crate) id: Option<String>,
    pub(crate) event: Option<String>,
    pub(crate) retry: Option<u64>,
    pub(crate) data: String,
}

impl SseWireEvent {
    pub(crate) fn data_json(value: Value) -> Result<Self> {
        Ok(Self {
            id: None,
            event: Some("message".to_string()),
            retry: None,
            data: serde_json::to_string(&value)?,
        })
    }

    fn to_axum_event(&self) -> Event {
        let mut event = Event::default().data(self.data.clone());
        if let Some(id) = &self.id {
            event = event.id(id.clone());
        }
        if let Some(name) = &self.event {
            event = event.event(name.clone());
        }
        if let Some(retry) = self.retry {
            event = event.retry(StdDuration::from_millis(retry));
        }
        event
    }
}

#[derive(Debug, Default)]
pub(crate) struct SseEventParser {
    buffer: String,
}

impl SseEventParser {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<SseWireEvent>> {
        let text = std::str::from_utf8(chunk).context("upstream SSE chunk is not valid UTF-8")?;
        self.buffer.push_str(text);
        self.buffer = self.buffer.replace("\r\n", "\n").replace('\r', "\n");
        let mut events = Vec::new();
        while let Some(index) = self.buffer.find("\n\n") {
            let block = self.buffer[..index].to_string();
            self.buffer.drain(..index + 2);
            if let Some(event) = parse_sse_event_block(&block)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn finish(self) -> Result<Vec<SseWireEvent>> {
        if self.buffer.trim().is_empty() {
            return Ok(Vec::new());
        }
        Ok(parse_sse_event_block(&self.buffer)?.into_iter().collect())
    }
}

pub(crate) fn parse_sse_event_block(block: &str) -> Result<Option<SseWireEvent>> {
    let mut id = None;
    let mut event = None;
    let mut retry = None;
    let mut data_lines = Vec::new();
    for raw_line in block.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line
            .split_once(':')
            .map(|(field, value)| (field, value.strip_prefix(' ').unwrap_or(value)))
            .unwrap_or((line, ""));
        match field {
            "id" => id = Some(value.to_string()),
            "event" => event = Some(value.to_string()),
            "retry" => retry = value.parse::<u64>().ok(),
            "data" => data_lines.push(value.to_string()),
            _ => {}
        }
    }
    if id.is_none() && event.is_none() && retry.is_none() && data_lines.is_empty() {
        return Ok(None);
    }
    let data = data_lines.join("\n");
    if !data.is_empty() {
        serde_json::from_str::<Value>(&data).context("SSE data field is not valid JSON")?;
    }
    Ok(Some(SseWireEvent {
        id,
        event: event.or_else(|| Some("message".to_string())),
        retry,
        data,
    }))
}

#[derive(Clone)]
pub(crate) struct HttpState {
    pub(crate) config: Arc<ProxyConfig>,
    pub(crate) bundle_proof: Arc<PolicyBundleProof>,
    pub(crate) policy_graph: Arc<PolicyGraph>,
    pub(crate) inventory: Arc<ToolInventory>,
    pub(crate) client: reqwest::Client,
    pub(crate) upstream_boundary_auth: ResolvedUpstreamBoundaryAuth,
    pub(crate) used_approval_receipts: Arc<Mutex<BTreeSet<String>>>,
    pub(crate) claim_store: Arc<PermitClaimStore>,
    pub(crate) sessions: Arc<Mutex<HttpSessionStore>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedUpstreamBoundaryAuth {
    bearer: Option<(HeaderName, HeaderValue)>,
}

pub(crate) fn default_tls_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(format!("{PROXY_NAME}/{PROXY_VERSION}"))
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .tls_sni(true)
}

pub(crate) fn build_upstream_http_client(
    config: &ProxyConfig,
    endpoint: &str,
) -> Result<reqwest::Client> {
    let endpoint_url = validate_streamable_http_upstream_endpoint(&config.http, endpoint)?;
    validate_upstream_boundary_config(config, &endpoint_url)?;
    let https_only = endpoint_url.scheme() == "https";
    let mut builder = default_tls_http_client_builder()
        .https_only(https_only)
        .timeout(StdDuration::from_millis(config.limits.upstream_timeout_ms));
    if config.upstream.boundary.require_mtls {
        let identity_pem = read_required_boundary_material(
            config.upstream.boundary.mtls.identity_pem_env.as_deref(),
            config.upstream.boundary.mtls.identity_pem_file.as_deref(),
            "upstream mTLS identity PEM",
        )?;
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .context("parse upstream mTLS identity PEM")?;
        builder = builder.identity(identity);
        if let Some(ca_bundle) = read_optional_boundary_material(
            config.upstream.boundary.mtls.ca_bundle_pem_env.as_deref(),
            config.upstream.boundary.mtls.ca_bundle_pem_file.as_deref(),
            "upstream mTLS CA bundle PEM",
        )? {
            let certificates = reqwest::Certificate::from_pem_bundle(&ca_bundle)
                .context("parse upstream mTLS CA bundle PEM")?
                .into_iter()
                .collect::<Vec<_>>();
            if certificates.is_empty() {
                bail!("parse upstream mTLS CA bundle PEM: no certificates found");
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
    }
    builder
        .build()
        .context("build streamable HTTP upstream client")
}

pub(crate) fn validate_upstream_boundary_config(
    config: &ProxyConfig,
    endpoint_url: &reqwest::Url,
) -> Result<()> {
    let boundary = &config.upstream.boundary;
    let strict_tunnel = strict_openai_secure_mcp_tunnel(config);
    if strict_tunnel {
        if endpoint_url.scheme() != "https" {
            bail!("strict OpenAI Secure MCP Tunnel mode requires an HTTPS private MCP upstream");
        }
        if !boundary.required || !boundary.require_bearer || !boundary.require_mtls {
            bail!(
                "strict OpenAI Secure MCP Tunnel mode requires upstream.boundary.required, require_bearer, and require_mtls"
            );
        }
    }
    if boundary.required && !boundary.require_bearer && !boundary.require_mtls {
        bail!("upstream.boundary.required requires bearer, mTLS, or both");
    }
    if boundary.require_bearer && config.auth.forward_authorization {
        bail!("auth.forward_authorization cannot be enabled with upstream private bearer auth");
    }
    if boundary.require_bearer {
        let _ = resolve_upstream_boundary_auth(config)?;
    }
    if boundary.require_mtls {
        let identity_pem = read_required_boundary_material(
            boundary.mtls.identity_pem_env.as_deref(),
            boundary.mtls.identity_pem_file.as_deref(),
            "upstream mTLS identity PEM",
        )?;
        reqwest::Identity::from_pem(&identity_pem).context("parse upstream mTLS identity PEM")?;
        if let Some(ca_bundle) = read_optional_boundary_material(
            boundary.mtls.ca_bundle_pem_env.as_deref(),
            boundary.mtls.ca_bundle_pem_file.as_deref(),
            "upstream mTLS CA bundle PEM",
        )? {
            let certificates = reqwest::Certificate::from_pem_bundle(&ca_bundle)
                .context("parse upstream mTLS CA bundle PEM")?;
            if certificates.is_empty() {
                bail!("parse upstream mTLS CA bundle PEM: no certificates found");
            }
        }
    }
    Ok(())
}

pub(crate) fn strict_openai_secure_mcp_tunnel(config: &ProxyConfig) -> bool {
    config.mode.is_strict()
        && config
            .oap
            .transport_context
            .openai_secure_mcp_tunnel
            .enabled
}

pub(crate) fn resolve_upstream_boundary_auth(
    config: &ProxyConfig,
) -> Result<ResolvedUpstreamBoundaryAuth> {
    let boundary = &config.upstream.boundary;
    if !boundary.require_bearer {
        return Ok(ResolvedUpstreamBoundaryAuth::default());
    }
    let header_name = HeaderName::from_bytes(boundary.bearer.header_name.trim().as_bytes())
        .context("parse upstream bearer header name")?;
    let scheme = boundary.bearer.scheme.trim();
    if scheme.is_empty() {
        bail!("upstream bearer scheme must not be empty");
    }
    let token = read_required_boundary_secret(
        boundary.bearer.token_env.as_deref(),
        boundary.bearer.token_file.as_deref(),
        "upstream bearer token",
    )?;
    let header_value = HeaderValue::from_str(&format!("{scheme} {token}"))
        .context("build upstream bearer header value")?;
    Ok(ResolvedUpstreamBoundaryAuth {
        bearer: Some((header_name, header_value)),
    })
}

pub(crate) fn read_required_boundary_secret(
    env_name: Option<&str>,
    file_path: Option<&Path>,
    label: &str,
) -> Result<String> {
    let material = read_required_boundary_material(env_name, file_path, label)?;
    let value = String::from_utf8(material).with_context(|| format!("{label} must be UTF-8"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} is empty");
    }
    Ok(trimmed.to_string())
}

pub(crate) fn read_required_boundary_material(
    env_name: Option<&str>,
    file_path: Option<&Path>,
    label: &str,
) -> Result<Vec<u8>> {
    let Some(material) = read_optional_boundary_material(env_name, file_path, label)? else {
        bail!("{label} source is required");
    };
    if material.is_empty() {
        bail!("{label} is empty");
    }
    Ok(material)
}

pub(crate) fn read_optional_boundary_material(
    env_name: Option<&str>,
    file_path: Option<&Path>,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    let env_name = non_empty_config_value(env_name);
    let file_path = file_path.filter(|path| !path.as_os_str().is_empty());
    match (env_name, file_path) {
        (Some(_), Some(_)) => bail!("{label} must configure exactly one env or file source"),
        (Some(env_name), None) => {
            let value = std::env::var(env_name)
                .with_context(|| format!("read {label} env {env_name}"))?
                .replace("\\n", "\n");
            if value.trim().is_empty() {
                bail!("{label} env {env_name} is empty");
            }
            Ok(Some(value.into_bytes()))
        }
        (None, Some(path)) => {
            let value =
                fs::read(path).with_context(|| format!("read {label} file {}", path.display()))?;
            if value.iter().all(u8::is_ascii_whitespace) {
                bail!("{label} file {} is empty", path.display());
            }
            Ok(Some(value))
        }
        (None, None) => Ok(None),
    }
}

pub(crate) fn validate_streamable_http_upstream_endpoint(
    config: &HttpConfig,
    endpoint: &str,
) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint)
        .with_context(|| format!("parse streamable_http upstream.endpoint {endpoint:?}"))?;
    if url.host_str().is_none() {
        bail!("streamable_http upstream.endpoint must include a host");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if config.allow_plaintext_loopback_upstream && is_plaintext_loopback_url(&url) => {
            Ok(url)
        }
        "http" if is_plaintext_loopback_url(&url) => bail!(
            "plaintext loopback streamable_http upstream requires http.allow_plaintext_loopback_upstream: true"
        ),
        "http" => bail!(
            "streamable_http upstream.endpoint must use https; plaintext HTTP is only allowed for localhost, 127.0.0.1, or [::1] when http.allow_plaintext_loopback_upstream is true"
        ),
        scheme => bail!("streamable_http upstream.endpoint must use https, got {scheme:?}"),
    }
}

pub(crate) fn is_plaintext_loopback_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    match url.host_str() {
        Some(host) => {
            host.eq_ignore_ascii_case("localhost") || matches!(host, "127.0.0.1" | "::1" | "[::1]")
        }
        None => false,
    }
}

pub(crate) async fn run_tls_check_command(url: &str) -> Result<()> {
    match run_tls_check(url).await {
        Ok(payload) => {
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        Err(error) => {
            let payload = json!({
                "status": "fail",
                "url": url,
                "error": error.to_string(),
                "tls": tls_check_policy_summary(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Err(error)
        }
    }
}

pub(crate) async fn run_tls_check(url: &str) -> Result<Value> {
    let url = validate_tls_check_url(url)?;
    let client = default_tls_http_client_builder()
        .https_only(true)
        .timeout(StdDuration::from_secs(15))
        .build()
        .context("build TLS readiness check client")?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("TLS readiness check request failed for {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("TLS readiness check returned HTTP status {status}");
    }
    Ok(json!({
        "status": "pass",
        "url": url.as_str(),
        "http_status": status.as_u16(),
        "tls": tls_check_policy_summary(),
    }))
}

pub(crate) fn validate_tls_check_url(url: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url).with_context(|| format!("parse TLS check URL {url:?}"))?;
    if url.scheme() != "https" {
        bail!("tls-check URL must use https");
    }
    if url.host_str().is_none() {
        bail!("tls-check URL must include a host");
    }
    Ok(url)
}

pub(crate) fn tls_check_policy_summary() -> Value {
    json!({
        "minimum_version": "TLSv1.2",
        "sni": "enabled",
        "trust_store": "platform_default",
        "certificate_pinning": "disabled",
    })
}

pub(crate) async fn fetch_http_inventory(
    client: &reqwest::Client,
    config: &ProxyConfig,
    endpoint: &str,
    upstream_boundary_auth: &ResolvedUpstreamBoundaryAuth,
) -> Result<Value> {
    let upstream_timeout = StdDuration::from_millis(config.limits.upstream_timeout_ms);
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": "velvet-inventory-init",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_SPEC_TARGET,
            "capabilities": {},
            "clientInfo": {"name": PROXY_NAME, "version": PROXY_VERSION}
        }
    });
    let init_builder = apply_upstream_boundary_auth(
        client
            .post(endpoint)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", MCP_SPEC_TARGET),
        upstream_boundary_auth,
    );
    let init_response =
        tokio::time::timeout(upstream_timeout, init_builder.json(&initialize).send())
            .await
            .map_err(|_| anyhow!("initialize HTTP MCP upstream timed out before inventory fetch"))?
            .context("initialize HTTP MCP upstream before inventory fetch")?;
    let upstream_session = response_session_header(init_response.headers())?;
    let _init_body = tokio::time::timeout(upstream_timeout, init_response.json::<Value>())
        .await
        .map_err(|_| anyhow!("parse upstream initialize response timed out"))?
        .context("parse upstream initialize response")?;

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    let mut initialized_builder = apply_upstream_boundary_auth(
        client
            .post(endpoint)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", MCP_SPEC_TARGET),
        upstream_boundary_auth,
    );
    if let Some(session) = &upstream_session {
        initialized_builder = initialized_builder.header("MCP-Session-Id", session);
    }
    let _ = tokio::time::timeout(
        upstream_timeout,
        initialized_builder.json(&initialized).send(),
    )
    .await;

    let mut list_builder = apply_upstream_boundary_auth(
        client
            .post(endpoint)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", MCP_SPEC_TARGET),
        upstream_boundary_auth,
    )
    .json(&json!({
            "jsonrpc": "2.0",
            "id": "velvet-inventory",
            "method": "tools/list",
            "params": {}
    }));
    if let Some(session) = &upstream_session {
        list_builder = list_builder.header("MCP-Session-Id", session);
    }
    let list_response = tokio::time::timeout(upstream_timeout, list_builder.send())
        .await
        .map_err(|_| anyhow!("fetch HTTP MCP upstream tools/list inventory timed out"))?
        .context("fetch HTTP MCP upstream tools/list inventory")?;
    let inventory_response = tokio::time::timeout(upstream_timeout, list_response.json::<Value>())
        .await
        .map_err(|_| anyhow!("parse upstream tools/list response timed out"))?
        .context("parse upstream tools/list response")?;

    if let Some(session) = upstream_session {
        let _ = tokio::time::timeout(
            upstream_timeout,
            apply_upstream_boundary_auth(
                client
                    .delete(endpoint)
                    .header("MCP-Session-Id", session)
                    .header("MCP-Protocol-Version", MCP_SPEC_TARGET),
                upstream_boundary_auth,
            )
            .send(),
        )
        .await;
    }
    if !config
        .http
        .supported_protocol_versions
        .iter()
        .any(|version| version == MCP_SPEC_TARGET)
    {
        bail!("unsupported MCP protocol version {MCP_SPEC_TARGET}");
    }
    Ok(inventory_response)
}

pub async fn run_http_proxy(config: ProxyConfig) -> Result<()> {
    let endpoint = config
        .upstream
        .endpoint
        .as_ref()
        .ok_or_else(|| anyhow!("streamable_http upstream requires upstream.endpoint"))?
        .clone();
    let bundle_proof = Arc::new(verify_policy_bundle(&config.policy)?);
    let policy_graph = Arc::new(load_policy_graph_or_error(&config.policy.dir)?);
    let client = build_upstream_http_client(&config, &endpoint)?;
    let upstream_boundary_auth = resolve_upstream_boundary_auth(&config)?;
    let claim_store = Arc::new(PermitClaimStore::for_ledger_path(&config.ledger_path));
    let inventory_response =
        fetch_http_inventory(&client, &config, &endpoint, &upstream_boundary_auth).await?;
    let inventory = Arc::new(ToolInventory::build(
        &config,
        &tools_from_list_response(&inventory_response)?,
    )?);
    inventory.write_if_configured(config.inventory_path.as_deref())?;

    let state = HttpState {
        config: Arc::new(config),
        bundle_proof,
        policy_graph,
        inventory,
        client,
        upstream_boundary_auth,
        used_approval_receipts: Arc::new(Mutex::new(BTreeSet::new())),
        claim_store,
        sessions: Arc::new(Mutex::new(HttpSessionStore::default())),
    };
    let path = state.config.http.endpoint_path.clone();
    let app = axum::Router::new()
        .route(&path, post(http_post).get(http_get).delete(http_delete))
        .route("/healthz", get(http_health))
        .route("/readyz", get(http_ready))
        .route("/livez", get(http_health))
        .route("/", get(|| async { "velvet-rope-proxy" }))
        .layer(DefaultBodyLimit::max(state.config.limits.max_request_bytes))
        .layer(ConcurrencyLimitLayer::new(
            state.config.limits.max_concurrent_requests.max(1),
        ))
        .with_state(state.clone());
    let bind: SocketAddr = state.config.http.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("velvet-rope-proxy listening on http://{bind}{path}");
    axum::serve(listener, app).await?;
    Ok(())
}

pub(crate) async fn http_get(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    match http_get_inner(state, headers).await {
        Ok(response) => response,
        Err(error) => http_error_response(error),
    }
}

pub(crate) async fn http_delete(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    match http_delete_inner(state, headers).await {
        Ok(response) => response,
        Err(error) => http_error_response(error),
    }
}

pub(crate) async fn http_get_inner(state: HttpState, headers: HeaderMap) -> Result<Response> {
    if !state.config.http.sse_enabled {
        bail!("SSE listen streams are disabled by configuration");
    }
    validate_http_headers(&state.config, &headers, None, HttpVerb::Get)?;
    if let Some(last_event_id) = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
    {
        let events = replay_sse_events(&state, &headers, last_event_id)?;
        let mut response = sse_response_from_events(&state.config, events);
        if let Some(session_id) = session_id_from_headers(&headers)? {
            insert_session_headers(
                response.headers_mut(),
                Some(&session_id),
                negotiated_protocol_for_session(&state, Some(&session_id))?.as_deref(),
            )?;
        }
        return Ok(response);
    }

    let context = prepare_get_context(&state, &headers)?;
    let stream_id = create_sse_stream_buffer(&state, context.downstream_session_id.as_deref())?;
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(32);
    let stream_state = state.clone();
    let stream_headers = headers.clone();
    let stream_context = context.clone();
    let stream_id_for_task = stream_id.clone();
    tokio::spawn(async move {
        stream_upstream_get_sse(
            stream_state,
            stream_headers,
            stream_context,
            stream_id_for_task,
            tx,
        )
        .await;
    });
    let mut response = Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::new().interval(StdDuration::from_secs(
            state.config.http.sse_keepalive_seconds,
        )))
        .into_response();
    insert_session_headers(
        response.headers_mut(),
        context.downstream_session_id.as_deref(),
        Some(&context.protocol_version),
    )?;
    Ok(response)
}

pub(crate) async fn http_delete_inner(state: HttpState, headers: HeaderMap) -> Result<Response> {
    validate_http_headers(&state.config, &headers, None, HttpVerb::Delete)?;
    let session_id = session_id_from_headers(&headers)?;
    let Some(session_id) = session_id else {
        let mut store = state
            .sessions
            .lock()
            .map_err(|_| anyhow!("MCP session state poisoned"))?;
        store.stateless = None;
        store.stateless_streams.clear();
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    let upstream_session_id = {
        let mut store = state
            .sessions
            .lock()
            .map_err(|_| anyhow!("MCP session state poisoned"))?;
        let Some(session) = store.sessions.remove(&session_id) else {
            bail!("unknown MCP session id");
        };
        session.upstream_session_id
    };
    if let Some(upstream_session_id) = upstream_session_id
        && let Some(endpoint) = state.config.upstream.endpoint.as_ref()
    {
        let mut builder = state
            .client
            .delete(endpoint)
            .header("MCP-Session-Id", upstream_session_id);
        if let Some(version) = headers.get("mcp-protocol-version") {
            builder = builder.header("MCP-Protocol-Version", version);
        }
        builder = apply_upstream_boundary_auth(builder, &state.upstream_boundary_auth);
        let _ = tokio::time::timeout(
            StdDuration::from_millis(state.config.limits.upstream_timeout_ms),
            builder.send(),
        )
        .await;
    }
    Ok(StatusCode::ACCEPTED.into_response())
}

pub(crate) async fn http_health() -> Response {
    axum::Json(json!({
        "status": "ok",
        "proxy": PROXY_NAME,
        "version": PROXY_VERSION,
        "mcp_spec_target": MCP_SPEC_TARGET,
    }))
    .into_response()
}

pub(crate) async fn http_ready(State(state): State<HttpState>) -> Response {
    axum::Json(json!({
        "status": "ready",
        "proxy": PROXY_NAME,
        "policy_hash": policy_hash_hex(&state.bundle_proof),
        "inventory_entries": state.inventory.entries.len(),
        "strict": state.config.mode.is_strict(),
    }))
    .into_response()
}

pub(crate) async fn http_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<Value>,
) -> Response {
    match http_post_inner(state, headers, request).await {
        Ok(response) => response,
        Err(error) => http_error_response(error),
    }
}

pub(crate) fn http_error_response(error: anyhow::Error) -> Response {
    let message = error.to_string();
    let status = if message.contains("authorization") || message.contains("bearer token") {
        StatusCode::UNAUTHORIZED
    } else if message.contains("Origin") {
        StatusCode::FORBIDDEN
    } else if message.contains("unknown MCP session")
        || message.contains("expired MCP session")
        || message.contains("Last-Event-ID")
    {
        StatusCode::NOT_FOUND
    } else if message.contains("Accept") {
        StatusCode::NOT_ACCEPTABLE
    } else if message.contains("unsupported MCP protocol")
        || message.contains("request exceeds")
        || message.contains("Mcp-")
        || message.contains("invalid JSON-RPC")
        || message.contains("initialize is required")
        || message.contains("initialization is not complete")
        || message.contains("session id")
        || message.contains("subject identity header")
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    eprintln!("velvet-rope-proxy HTTP error: {error:#}");
    let public_message = match status {
        StatusCode::UNAUTHORIZED => "authorization failed",
        StatusCode::FORBIDDEN => "request is not allowed",
        StatusCode::NOT_FOUND => "MCP session or event was not found",
        StatusCode::NOT_ACCEPTABLE => "requested media type is not acceptable",
        StatusCode::BAD_REQUEST => "invalid MCP HTTP request",
        _ => "internal proxy error",
    };
    let mut response = (
        status,
        axum::Json(json!({
            "error": {
                "message": public_message,
                "boundary": "velvet_mcp_proxy"
            }
        })),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Bearer realm="velvet-mcp-proxy""#),
        );
    }
    response
}

pub(crate) async fn http_post_inner(
    state: HttpState,
    headers: HeaderMap,
    request: Value,
) -> Result<Response> {
    validate_http_headers(&state.config, &headers, Some(&request), HttpVerb::Post)?;
    let classification = classify_json_rpc(&request);
    match &classification {
        JsonRpcMessageKind::Batch => {
            bail!("invalid JSON-RPC batch for MCP Streamable HTTP 2025-11-25")
        }
        JsonRpcMessageKind::Invalid(reason) => bail!("invalid JSON-RPC message: {reason}"),
        _ => {}
    }
    let context = prepare_http_request_context(&state, &headers, &classification, &request)?;
    let request_config = config_with_http_identity(&state.config, &headers)?;
    if let JsonRpcMessageKind::Response { id } = &classification {
        consume_pending_server_request_id(&state, context.downstream_session_id.as_deref(), id)?;
        forward_http_response_message(&state, headers, request, &context).await?;
        return Ok(StatusCode::ACCEPTED.into_response());
    }
    let method = classification.method().unwrap_or("");
    let is_notification = classification.is_notification();
    match method {
        method if is_lifecycle_method(method) => {
            let response = forward_http(&state, headers, request, &context).await?;
            if method == "notifications/initialized" {
                mark_http_session_initialized(&state, context.downstream_session_id.as_deref())?;
                return Ok(StatusCode::ACCEPTED.into_response());
            }
            Ok(response)
        }
        "tools/list" => {
            record_inventory_event(&request_config, &state.inventory)?;
            if is_notification {
                return Ok(StatusCode::ACCEPTED.into_response());
            }
            Ok(axum::Json(tools_list_response(&request, &state.inventory)).into_response())
        }
        "tools/call" => {
            if request.pointer("/params/task").is_some() {
                return handle_bounded_http(
                    state,
                    headers,
                    request,
                    &context,
                    is_notification,
                    request_config,
                )
                .await;
            }
            let request = strip_model_controlled_execution_metadata(&request);
            let (admission, pre_record, authorized) = {
                let mut used = state
                    .used_approval_receipts
                    .lock()
                    .map_err(|_| anyhow!("approval receipt state poisoned"))?;
                let admission = match admit_tool_call(
                    &request_config,
                    &state.bundle_proof,
                    &state.policy_graph,
                    &state.inventory,
                    &request,
                    &used,
                ) {
                    Ok(admission) => admission,
                    Err(error) => {
                        eprintln!("velvet-rope-proxy admission rejected request: {error:#}");
                        if is_notification {
                            return Ok(StatusCode::ACCEPTED.into_response());
                        }
                        return Ok(axum::Json(jsonrpc_error(
                            request.get("id").cloned(),
                            -32070,
                            "Velvet Rope fail-closed before upstream execution",
                            json!({
                                "boundary": "pre_execution_authorization",
                            }),
                        ))
                        .into_response());
                    }
                };
                write_approval_request_if_needed(&request_config, &admission)?;
                let pre_record =
                    record_pre_execution_ledger(&request_config, &request, &admission)?;
                let authorized = if is_executable_admission(&admission) {
                    let prepared = prepare_execution(
                        &request_config,
                        &state.bundle_proof,
                        &request,
                        &admission,
                        &pre_record,
                        &state.claim_store,
                    )?;
                    Some(authorize_execution(
                        &request_config,
                        prepared,
                        &state.claim_store,
                        "http_proxy",
                    )?)
                } else {
                    None
                };
                if let Some(receipt) = &admission.approval_receipt
                    && receipt.one_time_use
                    && authorized.is_some()
                {
                    used.insert(receipt.approval_receipt_id.clone());
                }
                (admission, pre_record, authorized)
            };
            if let Some(authorized) = authorized {
                verify_outbound_request_matches_permit(&request, &authorized)?;
                let request = if request_config.forwarding.attach_execution {
                    attach_execution_metadata_to_request(&request, &authorized)?
                } else {
                    request
                };
                let response = forward_http_json(
                    &state,
                    headers,
                    request,
                    &context,
                    Some((&admission, &pre_record, &authorized)),
                    None,
                    &request_config,
                )
                .await?;
                Ok(response)
            } else {
                if is_notification {
                    Ok(StatusCode::ACCEPTED.into_response())
                } else {
                    Ok(
                        axum::Json(denial_response(&request, &admission, &pre_record))
                            .into_response(),
                    )
                }
            }
        }
        _ => {
            handle_bounded_http(
                state,
                headers,
                request,
                &context,
                is_notification,
                request_config,
            )
            .await
        }
    }
}

pub(crate) async fn forward_http(
    state: &HttpState,
    headers: HeaderMap,
    request: Value,
    context: &HttpRequestContext,
) -> Result<Response> {
    forward_http_json(state, headers, request, context, None, None, &state.config).await
}

pub(crate) async fn handle_bounded_http(
    state: HttpState,
    headers: HeaderMap,
    request: Value,
    context: &HttpRequestContext,
    is_notification: bool,
    request_config: ProxyConfig,
) -> Result<Response> {
    let decision = bounded_method_decision(&request_config, &request);
    let pre_record =
        record_bounded_method_ledger(&request_config, &state.bundle_proof, &request, &decision)?;
    match decision.disposition {
        BoundedMethodDisposition::AllowPassthrough => {
            forward_http_json(
                &state,
                headers,
                request,
                context,
                None,
                Some((&decision, pre_record.record_hash.as_str())),
                &request_config,
            )
            .await
        }
        BoundedMethodDisposition::Block | BoundedMethodDisposition::Escalate => {
            if is_notification {
                Ok(StatusCode::ACCEPTED.into_response())
            } else {
                Ok(axum::Json(bounded_method_response(&request, &decision)).into_response())
            }
        }
    }
}

pub(crate) async fn forward_http_json(
    state: &HttpState,
    headers: HeaderMap,
    request: Value,
    context: &HttpRequestContext,
    admission: Option<(&AdmissionOutcome, &OapLedgerRecord, &AuthorizedExecution)>,
    bounded: Option<(&BoundedMethodDecision, &str)>,
    request_config: &ProxyConfig,
) -> Result<Response> {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let is_notification = request.get("id").is_none();
    let endpoint = state
        .config
        .upstream
        .endpoint
        .as_ref()
        .ok_or_else(|| anyhow!("missing HTTP upstream endpoint"))?;
    let builder = upstream_post_builder(state, endpoint, &headers, context);
    let started_at = now_rfc3339_z();
    let send_result = tokio::time::timeout(
        StdDuration::from_millis(state.config.limits.upstream_timeout_ms),
        builder.json(&request).send(),
    )
    .await;
    let upstream_response = match send_result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            if let Some((admission, pre_record, authorized)) = admission {
                let detail = error.to_string();
                let receipt = build_execution_receipt(
                    request_config,
                    authorized,
                    ExecutionReceiptObservation {
                        outcome: velvet_core::ExecutionOutcome::Indeterminate,
                        dispatch_attempted: true,
                        started_at: &started_at,
                        upstream_response_hash: None,
                        error_code: Some("http_upstream_error_after_dispatch_attempt"),
                        error_detail: Some(&detail),
                    },
                )?;
                record_post_execution_ledger(
                    request_config,
                    &request,
                    admission,
                    PostExecutionObservation {
                        pre_execution_record_hash: &pre_record.record_hash,
                        upstream_status: "indeterminate",
                        upstream_response_hash: None,
                        error_message: Some(&detail),
                        execution_receipt: Some(&serde_json::to_value(&receipt)?),
                    },
                )?;
                mark_execution_complete(&state.claim_store, authorized, &receipt)?;
                return Ok(axum::Json(jsonrpc_error(
                    request.get("id").cloned(),
                    -32060,
                    "upstream MCP call failed",
                    json!({
                        "boundary": "upstream_forwarding",
                        "oap_decision_id": admission.oap.decision.get("decision_id"),
                    }),
                ))
                .into_response());
            }
            if let Some((decision, pre_execution_record_hash)) = bounded {
                let detail = error.to_string();
                record_bounded_method_observation(
                    request_config,
                    &request,
                    decision,
                    pre_execution_record_hash,
                    "indeterminate",
                    None,
                    Some(&detail),
                )?;
                return Ok(axum::Json(jsonrpc_error(
                    request.get("id").cloned(),
                    -32060,
                    "upstream MCP bounded method failed",
                    json!({
                        "boundary": "bounded_upstream_forwarding",
                        "method": decision.method.as_str(),
                    }),
                ))
                .into_response());
            }
            return Err(error.into());
        }
        Err(_) => {
            if let Some((admission, pre_record, authorized)) = admission {
                let receipt = build_execution_receipt(
                    request_config,
                    authorized,
                    ExecutionReceiptObservation {
                        outcome: velvet_core::ExecutionOutcome::Indeterminate,
                        dispatch_attempted: true,
                        started_at: &started_at,
                        upstream_response_hash: None,
                        error_code: Some("http_upstream_timeout_after_dispatch_attempt"),
                        error_detail: Some(
                            "HTTP upstream timeout after Velvet attempted forwarding",
                        ),
                    },
                )?;
                record_post_execution_ledger(
                    request_config,
                    &request,
                    admission,
                    PostExecutionObservation {
                        pre_execution_record_hash: &pre_record.record_hash,
                        upstream_status: "indeterminate",
                        upstream_response_hash: None,
                        error_message: Some(
                            "HTTP upstream timeout after Velvet attempted forwarding",
                        ),
                        execution_receipt: Some(&serde_json::to_value(&receipt)?),
                    },
                )?;
                mark_execution_complete(&state.claim_store, authorized, &receipt)?;
                return Ok(axum::Json(jsonrpc_error(
                    request.get("id").cloned(),
                    -32060,
                    "upstream MCP call timed out",
                    json!({
                        "boundary": "upstream_forwarding",
                        "oap_decision_id": admission.oap.decision.get("decision_id"),
                    }),
                ))
                .into_response());
            }
            if let Some((decision, pre_execution_record_hash)) = bounded {
                record_bounded_method_observation(
                    request_config,
                    &request,
                    decision,
                    pre_execution_record_hash,
                    "failed",
                    None,
                    Some("HTTP upstream timeout after bounded method forwarding"),
                )?;
                return Ok(axum::Json(jsonrpc_error(
                    request.get("id").cloned(),
                    -32060,
                    "upstream MCP bounded method timed out",
                    json!({
                        "boundary": "bounded_upstream_forwarding",
                        "method": decision.method.as_str(),
                    }),
                ))
                .into_response());
            }
            bail!("HTTP upstream timeout");
        }
    };
    let status = upstream_response.status();
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    let upstream_session_id = response_session_header(upstream_response.headers())?;
    let is_sse = content_type
        .to_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("text/event-stream");
    if is_sse {
        let sse_read = tokio::time::timeout(
            StdDuration::from_millis(state.config.limits.upstream_timeout_ms),
            read_upstream_sse_response(upstream_response, state.config.limits.max_response_bytes),
        )
        .await;
        let (mut events, response_hash) = match sse_read {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                return record_forwarding_failure_response(
                    &request,
                    admission,
                    bounded,
                    &error.to_string(),
                    request_config,
                );
            }
            Err(_) => {
                return record_forwarding_failure_response(
                    &request,
                    admission,
                    bounded,
                    "HTTP upstream SSE response timed out",
                    request_config,
                );
            }
        };
        if let Some((admission, pre_record, _authorized)) = admission {
            attach_oap_to_sse_terminal_response(&mut events, admission, pre_record)?;
        }
        let negotiated_protocol = if method == "initialize" {
            sse_initialize_protocol_version(&events, &context.protocol_version)
        } else {
            context.protocol_version.clone()
        };
        let downstream_session_id = if method == "initialize" {
            mark_http_initialize_response(state, upstream_session_id, negotiated_protocol.clone())?
        } else {
            context.downstream_session_id.clone()
        };
        if let Some((admission, pre_record, authorized)) = admission {
            let receipt = build_execution_receipt(
                request_config,
                authorized,
                ExecutionReceiptObservation {
                    outcome: velvet_core::ExecutionOutcome::Succeeded,
                    dispatch_attempted: true,
                    started_at: &started_at,
                    upstream_response_hash: Some(response_hash.clone()),
                    error_code: None,
                    error_detail: None,
                },
            )?;
            record_post_execution_ledger(
                request_config,
                &request,
                admission,
                PostExecutionObservation {
                    pre_execution_record_hash: &pre_record.record_hash,
                    upstream_status: "forwarded",
                    upstream_response_hash: Some(response_hash.clone()),
                    error_message: None,
                    execution_receipt: Some(&serde_json::to_value(&receipt)?),
                },
            )?;
            mark_execution_complete(&state.claim_store, authorized, &receipt)?;
        }
        if let Some((decision, pre_execution_record_hash)) = bounded {
            record_bounded_method_observation(
                request_config,
                &request,
                decision,
                pre_execution_record_hash,
                "forwarded",
                Some(response_hash),
                None,
            )?;
        }
        if is_notification {
            return Ok(StatusCode::ACCEPTED.into_response());
        }
        let stream_id = create_sse_stream_buffer(state, downstream_session_id.as_deref())?;
        let events = assign_and_buffer_sse_events(
            state,
            downstream_session_id.as_deref(),
            &stream_id,
            events,
        )?;
        let mut response = sse_response_from_events(&state.config, events);
        insert_session_headers(
            response.headers_mut(),
            downstream_session_id.as_deref(),
            Some(&negotiated_protocol),
        )?;
        return Ok(response);
    }
    let bytes = match upstream_response
        .bytes()
        .await
        .context("read upstream HTTP MCP response")
    {
        Ok(bytes) => bytes,
        Err(error) => {
            return record_forwarding_failure_response(
                &request,
                admission,
                bounded,
                &error.to_string(),
                request_config,
            );
        }
    };
    let response_hash = format!("sha256:{}", sha256_hex(&bytes));
    if bytes.len() > state.config.limits.max_response_bytes {
        return record_forwarding_failure_response(
            &request,
            admission,
            bounded,
            "upstream response exceeds configured size limit",
            request_config,
        );
    }
    let negotiated_protocol = if method == "initialize" {
        response_protocol_version(&bytes, &context.protocol_version)
    } else {
        context.protocol_version.clone()
    };
    let downstream_session_id = if method == "initialize" {
        mark_http_initialize_response(state, upstream_session_id, negotiated_protocol.clone())?
    } else {
        context.downstream_session_id.clone()
    };
    let body_bytes = if let Some((admission, pre_record, authorized)) = admission {
        let receipt = build_execution_receipt(
            request_config,
            authorized,
            ExecutionReceiptObservation {
                outcome: velvet_core::ExecutionOutcome::Succeeded,
                dispatch_attempted: true,
                started_at: &started_at,
                upstream_response_hash: Some(response_hash.clone()),
                error_code: None,
                error_detail: None,
            },
        )?;
        record_post_execution_ledger(
            request_config,
            &request,
            admission,
            PostExecutionObservation {
                pre_execution_record_hash: &pre_record.record_hash,
                upstream_status: "forwarded",
                upstream_response_hash: Some(response_hash),
                error_message: None,
                execution_receipt: Some(&serde_json::to_value(&receipt)?),
            },
        )?;
        mark_execution_complete(&state.claim_store, authorized, &receipt)?;
        if content_type
            .to_str()
            .unwrap_or_default()
            .contains("application/json")
        {
            let value: Value = serde_json::from_slice(&bytes)?;
            serde_json::to_vec(&attach_oap_decision(value, admission, pre_record))?
        } else {
            bytes.to_vec()
        }
    } else if let Some((decision, pre_execution_record_hash)) = bounded {
        record_bounded_method_observation(
            request_config,
            &request,
            decision,
            pre_execution_record_hash,
            "forwarded",
            Some(response_hash),
            None,
        )?;
        bytes.to_vec()
    } else {
        bytes.to_vec()
    };
    if is_notification {
        return Ok(StatusCode::ACCEPTED.into_response());
    }
    let mut response = Response::builder()
        .status(StatusCode::from_u16(status.as_u16())?)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body_bytes))?;
    insert_session_headers(
        response.headers_mut(),
        downstream_session_id.as_deref(),
        Some(&negotiated_protocol),
    )?;
    Ok(response)
}

pub(crate) fn record_forwarding_failure_response(
    request: &Value,
    admission: Option<(&AdmissionOutcome, &OapLedgerRecord, &AuthorizedExecution)>,
    bounded: Option<(&BoundedMethodDecision, &str)>,
    detail: &str,
    request_config: &ProxyConfig,
) -> Result<Response> {
    eprintln!("velvet-rope-proxy upstream forwarding failed: {detail}");
    if let Some((admission, pre_record, authorized)) = admission {
        let receipt = build_execution_receipt(
            request_config,
            authorized,
            ExecutionReceiptObservation {
                outcome: velvet_core::ExecutionOutcome::Indeterminate,
                dispatch_attempted: true,
                started_at: &now_rfc3339_z(),
                upstream_response_hash: None,
                error_code: Some("http_upstream_observation_gap"),
                error_detail: Some(detail),
            },
        )?;
        record_post_execution_ledger(
            request_config,
            request,
            admission,
            PostExecutionObservation {
                pre_execution_record_hash: &pre_record.record_hash,
                upstream_status: "indeterminate",
                upstream_response_hash: None,
                error_message: Some(detail),
                execution_receipt: Some(&serde_json::to_value(&receipt)?),
            },
        )?;
        mark_execution_complete(
            &PermitClaimStore::for_ledger_path(&request_config.ledger_path),
            authorized,
            &receipt,
        )?;
        return Ok(axum::Json(jsonrpc_error(
            request.get("id").cloned(),
            -32060,
            "upstream MCP call failed",
            json!({
                "boundary": "upstream_forwarding",
                "oap_decision_id": admission.oap.decision.get("decision_id"),
            }),
        ))
        .into_response());
    }
    if let Some((decision, pre_execution_record_hash)) = bounded {
        record_bounded_method_observation(
            request_config,
            request,
            decision,
            pre_execution_record_hash,
            "failed",
            None,
            Some(detail),
        )?;
        return Ok(axum::Json(jsonrpc_error(
            request.get("id").cloned(),
            -32060,
            "upstream MCP bounded method failed",
            json!({
                "boundary": "bounded_upstream_forwarding",
                "method": decision.method.as_str(),
            }),
        ))
        .into_response());
    }
    bail!("{detail}");
}

pub(crate) async fn forward_http_response_message(
    state: &HttpState,
    headers: HeaderMap,
    response_message: Value,
    context: &HttpRequestContext,
) -> Result<()> {
    let endpoint = state
        .config
        .upstream
        .endpoint
        .as_ref()
        .ok_or_else(|| anyhow!("missing HTTP upstream endpoint"))?;
    let builder = upstream_post_builder(state, endpoint, &headers, context);
    let upstream_response = tokio::time::timeout(
        StdDuration::from_millis(state.config.limits.upstream_timeout_ms),
        builder.json(&response_message).send(),
    )
    .await
    .map_err(|_| anyhow!("HTTP upstream timeout"))??;
    if !upstream_response.status().is_success() {
        bail!(
            "upstream rejected JSON-RPC response with status {}",
            upstream_response.status()
        );
    }
    Ok(())
}

pub(crate) fn upstream_post_builder(
    state: &HttpState,
    endpoint: &str,
    headers: &HeaderMap,
    context: &HttpRequestContext,
) -> reqwest::RequestBuilder {
    let mut builder = state
        .client
        .post(endpoint)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", context.protocol_version.as_str());
    if let Some(session) = &context.upstream_session_id {
        builder = builder.header("MCP-Session-Id", session);
    }
    for header_name in ["mcp-method", "mcp-name"] {
        if let Some(value) = headers.get(header_name) {
            builder = builder.header(header_name, value);
        }
    }
    if state.config.auth.forward_authorization
        && let Some(value) = headers.get(header::AUTHORIZATION)
    {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    apply_upstream_boundary_auth(builder, &state.upstream_boundary_auth)
}

pub(crate) fn apply_upstream_boundary_auth(
    builder: reqwest::RequestBuilder,
    auth: &ResolvedUpstreamBoundaryAuth,
) -> reqwest::RequestBuilder {
    if let Some((name, value)) = &auth.bearer {
        builder.header(name, value)
    } else {
        builder
    }
}

pub(crate) fn insert_session_headers(
    headers: &mut HeaderMap,
    session_id: Option<&str>,
    protocol_version: Option<&str>,
) -> Result<()> {
    if let Some(session_id) = session_id {
        headers.insert("MCP-Session-Id", HeaderValue::from_str(session_id)?);
    }
    if let Some(protocol_version) = protocol_version {
        headers.insert(
            "MCP-Protocol-Version",
            HeaderValue::from_str(protocol_version)?,
        );
    }
    Ok(())
}

pub(crate) async fn read_upstream_sse_response(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<(Vec<SseWireEvent>, String)> {
    let mut parser = SseEventParser::default();
    let mut raw = Vec::new();
    let mut events = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read upstream SSE chunk")?;
        raw.extend_from_slice(&chunk);
        if raw.len() > max_response_bytes {
            bail!("upstream response exceeds configured size limit");
        }
        events.extend(parser.push_chunk(&chunk)?);
    }
    events.extend(parser.finish()?);
    Ok((events, format!("sha256:{}", sha256_hex(&raw))))
}

pub(crate) fn attach_oap_to_sse_terminal_response(
    events: &mut [SseWireEvent],
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
) -> Result<()> {
    for event in events.iter_mut().rev() {
        let Ok(value) = serde_json::from_str::<Value>(&event.data) else {
            continue;
        };
        if matches!(
            classify_json_rpc(&value),
            JsonRpcMessageKind::Response { .. }
        ) {
            event.data = serde_json::to_string(&attach_oap_decision(value, admission, pre_record))?;
            break;
        }
    }
    Ok(())
}

pub(crate) fn sse_initialize_protocol_version(events: &[SseWireEvent], fallback: &str) -> String {
    events
        .iter()
        .filter_map(|event| serde_json::from_str::<Value>(&event.data).ok())
        .find_map(|value| {
            value
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn create_sse_stream_buffer(
    state: &HttpState,
    session_id: Option<&str>,
) -> Result<String> {
    let stream_id = format!("sse_{}", uuid::Uuid::new_v4().simple());
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session_id) = session_id {
        let Some(session) = store.sessions.get_mut(session_id) else {
            bail!("unknown MCP session id");
        };
        session
            .streams
            .insert(stream_id.clone(), SseReplayBuffer::default());
    } else {
        store
            .stateless_streams
            .insert(stream_id.clone(), SseReplayBuffer::default());
    }
    Ok(stream_id)
}

pub(crate) fn assign_and_buffer_sse_events(
    state: &HttpState,
    session_id: Option<&str>,
    stream_id: &str,
    mut events: Vec<SseWireEvent>,
) -> Result<Vec<SseWireEvent>> {
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    let buffer = if let Some(session_id) = session_id {
        let Some(session) = store.sessions.get_mut(session_id) else {
            bail!("unknown MCP session id");
        };
        session
            .streams
            .entry(stream_id.to_string())
            .or_insert_with(SseReplayBuffer::default)
    } else {
        store
            .stateless_streams
            .entry(stream_id.to_string())
            .or_insert_with(SseReplayBuffer::default)
    };
    let now = Instant::now();
    let ttl = StdDuration::from_secs(state.config.http.sse_replay_ttl_seconds);
    let max_events = state.config.http.sse_replay_buffer_events.max(1);
    for event in &mut events {
        event.id = Some(format!("{stream_id}:{}", buffer.next_sequence));
        buffer.next_sequence += 1;
        buffer.events.push_back(BufferedSseEvent {
            event: event.clone(),
            recorded_at: now,
        });
    }
    prune_sse_buffer(buffer, now, ttl, max_events);
    Ok(events)
}

pub(crate) fn prune_sse_buffer(
    buffer: &mut SseReplayBuffer,
    now: Instant,
    ttl: StdDuration,
    max_events: usize,
) {
    while buffer
        .events
        .front()
        .is_some_and(|event| now.duration_since(event.recorded_at) > ttl)
    {
        buffer.events.pop_front();
    }
    while buffer.events.len() > max_events {
        buffer.events.pop_front();
    }
}

pub(crate) fn sse_response_from_events(
    config: &ProxyConfig,
    events: Vec<SseWireEvent>,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(events.len().max(1));
    tokio::spawn(async move {
        for event in events {
            if tx.send(Ok(event.to_axum_event())).await.is_err() {
                break;
            }
        }
    });
    Sse::new(ReceiverStream::new(rx))
        .keep_alive(
            KeepAlive::new().interval(StdDuration::from_secs(config.http.sse_keepalive_seconds)),
        )
        .into_response()
}

pub(crate) fn prepare_get_context(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<HttpRequestContext> {
    let session_id = session_id_from_headers(headers)?;
    let header_protocol = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session_id) = session_id {
        let Some(session) = store.sessions.get(&session_id) else {
            bail!("unknown MCP session id");
        };
        if let Some(protocol) = header_protocol
            && protocol != session.protocol_version
        {
            bail!("unsupported MCP protocol version {protocol} for negotiated session");
        }
        return Ok(HttpRequestContext {
            downstream_session_id: Some(session_id),
            upstream_session_id: session.upstream_session_id.clone(),
            protocol_version: session.protocol_version.clone(),
        });
    }
    if !store.sessions.is_empty() {
        bail!("MCP session id is required after stateful initialization");
    }
    let protocol_version = store
        .stateless
        .as_ref()
        .map(|session| session.protocol_version.clone())
        .or(header_protocol)
        .unwrap_or_else(|| "2025-03-26".to_string());
    Ok(HttpRequestContext {
        downstream_session_id: None,
        upstream_session_id: None,
        protocol_version,
    })
}

pub(crate) fn negotiated_protocol_for_session(
    state: &HttpState,
    session_id: Option<&str>,
) -> Result<Option<String>> {
    let store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session_id) = session_id {
        return Ok(Some(
            store
                .sessions
                .get(session_id)
                .ok_or_else(|| anyhow!("unknown MCP session id"))?
                .protocol_version
                .clone(),
        ));
    }
    Ok(store
        .stateless
        .as_ref()
        .map(|session| session.protocol_version.clone()))
}

pub(crate) fn replay_sse_events(
    state: &HttpState,
    headers: &HeaderMap,
    last_event_id: &str,
) -> Result<Vec<SseWireEvent>> {
    let (stream_id, sequence) = parse_sse_event_id(last_event_id)?;
    let session_id = session_id_from_headers(headers)?;
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    let buffer = if let Some(session_id) = session_id.as_deref() {
        let Some(session) = store.sessions.get_mut(session_id) else {
            bail!("unknown MCP session id");
        };
        session.streams.get_mut(&stream_id)
    } else {
        store.stateless_streams.get_mut(&stream_id)
    }
    .ok_or_else(|| anyhow!("Last-Event-ID is unknown or expired"))?;
    let now = Instant::now();
    prune_sse_buffer(
        buffer,
        now,
        StdDuration::from_secs(state.config.http.sse_replay_ttl_seconds),
        state.config.http.sse_replay_buffer_events.max(1),
    );
    let mut found_anchor = false;
    let events = buffer
        .events
        .iter()
        .filter_map(|event| {
            let (_, event_sequence) = parse_sse_event_id(event.event.id.as_deref()?).ok()?;
            if event_sequence == sequence {
                found_anchor = true;
            }
            (event_sequence > sequence).then_some(event.event.clone())
        })
        .collect::<Vec<_>>();
    if !found_anchor {
        bail!("Last-Event-ID is unknown or expired");
    }
    Ok(events)
}

pub(crate) fn parse_sse_event_id(event_id: &str) -> Result<(String, u64)> {
    let Some((stream_id, sequence)) = event_id.rsplit_once(':') else {
        bail!("Last-Event-ID is unknown or expired");
    };
    if stream_id.is_empty() {
        bail!("Last-Event-ID is unknown or expired");
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| anyhow!("Last-Event-ID is unknown or expired"))?;
    Ok((stream_id.to_string(), sequence))
}

pub(crate) async fn stream_upstream_get_sse(
    state: HttpState,
    headers: HeaderMap,
    context: HttpRequestContext,
    stream_id: String,
    tx: mpsc::Sender<Result<Event, Infallible>>,
) {
    let result = stream_upstream_get_sse_inner(&state, &headers, &context, &stream_id, &tx).await;
    if let Err(error) = result {
        let event = SseWireEvent::data_json(jsonrpc_error(
            None,
            -32060,
            "upstream MCP SSE stream failed",
            json!({"boundary": "upstream_sse", "detail": error.to_string()}),
        ));
        if let Ok(event) = event {
            let _ = tx.send(Ok(event.to_axum_event())).await;
        }
    }
}

pub(crate) async fn stream_upstream_get_sse_inner(
    state: &HttpState,
    headers: &HeaderMap,
    context: &HttpRequestContext,
    stream_id: &str,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
) -> Result<()> {
    let endpoint = state
        .config
        .upstream
        .endpoint
        .as_ref()
        .ok_or_else(|| anyhow!("missing HTTP upstream endpoint"))?;
    let mut builder = state
        .client
        .get(endpoint)
        .header(header::ACCEPT, "text/event-stream")
        .header("MCP-Protocol-Version", context.protocol_version.as_str());
    if let Some(session) = &context.upstream_session_id {
        builder = builder.header("MCP-Session-Id", session);
    }
    if state.config.auth.forward_authorization
        && let Some(value) = headers.get(header::AUTHORIZATION)
    {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder = apply_upstream_boundary_auth(builder, &state.upstream_boundary_auth);
    let upstream_response = tokio::time::timeout(
        StdDuration::from_millis(state.config.limits.upstream_timeout_ms),
        builder.send(),
    )
    .await
    .map_err(|_| anyhow!("HTTP upstream timeout"))??;
    if !upstream_response.status().is_success() {
        bail!("upstream GET returned {}", upstream_response.status());
    }
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .contains("text/event-stream")
    {
        bail!("upstream GET did not return text/event-stream");
    }
    let mut parser = SseEventParser::default();
    let mut streamed_bytes = 0usize;
    let mut stream = upstream_response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read upstream SSE chunk")?;
        streamed_bytes += chunk.len();
        if streamed_bytes > state.config.limits.max_response_bytes {
            bail!("upstream response exceeds configured size limit");
        }
        let events = parser.push_chunk(&chunk)?;
        forward_governed_sse_events(state, context, stream_id, events, tx).await?;
    }
    let events = parser.finish()?;
    forward_governed_sse_events(state, context, stream_id, events, tx).await?;
    Ok(())
}

pub(crate) async fn forward_governed_sse_events(
    state: &HttpState,
    context: &HttpRequestContext,
    stream_id: &str,
    events: Vec<SseWireEvent>,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
) -> Result<()> {
    let mut governed = Vec::new();
    for event in events {
        if let Some(event) = govern_server_to_client_event(state, context, event)? {
            governed.push(event);
        }
    }
    let events = assign_and_buffer_sse_events(
        state,
        context.downstream_session_id.as_deref(),
        stream_id,
        governed,
    )?;
    for event in events {
        if tx.send(Ok(event.to_axum_event())).await.is_err() {
            break;
        }
    }
    Ok(())
}

pub(crate) fn govern_server_to_client_event(
    state: &HttpState,
    context: &HttpRequestContext,
    event: SseWireEvent,
) -> Result<Option<SseWireEvent>> {
    if event.data.is_empty() {
        return Ok(Some(event));
    }
    let value: Value = serde_json::from_str(&event.data)?;
    match classify_json_rpc(&value) {
        JsonRpcMessageKind::Request { method, id } => {
            if is_safe_server_to_client_method(&method) {
                remember_server_request_id(state, context.downstream_session_id.as_deref(), &id)?;
                Ok(Some(event))
            } else {
                let decision = bounded_method_decision(&state.config, &value);
                let pre_record = record_bounded_method_ledger(
                    &state.config,
                    &state.bundle_proof,
                    &value,
                    &decision,
                )?;
                match decision.disposition {
                    BoundedMethodDisposition::AllowPassthrough => {
                        record_bounded_method_observation(
                            &state.config,
                            &value,
                            &decision,
                            &pre_record.record_hash,
                            "forwarded",
                            Some(value_hash(&value)),
                            None,
                        )?;
                        remember_server_request_id(
                            state,
                            context.downstream_session_id.as_deref(),
                            &id,
                        )?;
                        Ok(Some(event))
                    }
                    BoundedMethodDisposition::Block | BoundedMethodDisposition::Escalate => {
                        Ok(Some(SseWireEvent::data_json(bounded_method_response(
                            &value, &decision,
                        ))?))
                    }
                }
            }
        }
        JsonRpcMessageKind::Notification { method } => {
            if is_safe_server_to_client_method(&method) {
                Ok(Some(event))
            } else {
                let decision = bounded_method_decision(&state.config, &value);
                let pre_record = record_bounded_method_ledger(
                    &state.config,
                    &state.bundle_proof,
                    &value,
                    &decision,
                )?;
                match decision.disposition {
                    BoundedMethodDisposition::AllowPassthrough => {
                        record_bounded_method_observation(
                            &state.config,
                            &value,
                            &decision,
                            &pre_record.record_hash,
                            "forwarded",
                            Some(value_hash(&value)),
                            None,
                        )?;
                        Ok(Some(event))
                    }
                    BoundedMethodDisposition::Block | BoundedMethodDisposition::Escalate => {
                        Ok(None)
                    }
                }
            }
        }
        JsonRpcMessageKind::Response { .. } => Ok(Some(event)),
        JsonRpcMessageKind::Batch | JsonRpcMessageKind::Invalid(_) => Ok(None),
    }
}

pub(crate) fn is_safe_server_to_client_method(method: &str) -> bool {
    matches!(
        method,
        "ping"
            | "notifications/progress"
            | "notifications/message"
            | "notifications/logging"
            | "notifications/cancelled"
    )
}

pub(crate) fn remember_server_request_id(
    state: &HttpState,
    session_id: Option<&str>,
    id: &Value,
) -> Result<()> {
    let Some(session_id) = session_id else {
        return Ok(());
    };
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session) = store.sessions.get_mut(session_id) {
        session
            .pending_server_request_ids
            .insert(canonical_json(id));
    }
    Ok(())
}

pub(crate) fn consume_pending_server_request_id(
    state: &HttpState,
    session_id: Option<&str>,
    id: &Value,
) -> Result<()> {
    let Some(session_id) = session_id else {
        bail!("JSON-RPC response requires an MCP session id");
    };
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    let Some(session) = store.sessions.get_mut(session_id) else {
        bail!("unknown MCP session id");
    };
    let key = canonical_json(id);
    if !session.pending_server_request_ids.remove(&key) {
        bail!("JSON-RPC response id does not match a pending server request");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpVerb {
    Post,
    Get,
    Delete,
}

pub(crate) fn validate_http_headers(
    config: &ProxyConfig,
    headers: &HeaderMap,
    request: Option<&Value>,
    verb: HttpVerb,
) -> Result<()> {
    if config.auth.require_bearer {
        let token_env = config.auth.bearer_token_env.as_ref().ok_or_else(|| {
            anyhow!("authorization required but bearer_token_env is not configured")
        })?;
        let expected = std::env::var(token_env)
            .with_context(|| format!("authorization required but {token_env} is not set"))?;
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow!("authorization bearer token missing"))?;
        let Some(presented) = authorization.strip_prefix("Bearer ") else {
            bail!("authorization bearer token malformed");
        };
        if presented != expected {
            bail!("authorization bearer token rejected");
        }
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        && !config.http.allowed_origins.is_empty()
        && !config
            .http
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
    {
        bail!("invalid Origin header");
    }
    match verb {
        HttpVerb::Post => {
            let accept = headers
                .get(header::ACCEPT)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    anyhow!("Accept header must include application/json and text/event-stream")
                })?;
            if !accept_header_contains(accept, "application/json")
                || !accept_header_contains(accept, "text/event-stream")
            {
                bail!("Accept header must include application/json and text/event-stream");
            }
        }
        HttpVerb::Get => {
            let accept = headers
                .get(header::ACCEPT)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| anyhow!("Accept header must include text/event-stream"))?;
            if !accept_header_contains(accept, "text/event-stream") {
                bail!("Accept header must include text/event-stream");
            }
        }
        HttpVerb::Delete => {}
    }
    if let Some(version) = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        && !config
            .http
            .supported_protocol_versions
            .iter()
            .any(|supported| supported == version)
    {
        bail!("unsupported MCP protocol version {version}");
    }
    let Some(request) = request else {
        return Ok(());
    };
    if let Some(method_header) = headers
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
    {
        let body_method = request.get("method").and_then(Value::as_str).unwrap_or("");
        if method_header != body_method {
            bail!("Mcp-Method header does not match JSON-RPC method");
        }
    }
    if let Some(name_header) = headers
        .get("mcp-name")
        .and_then(|value| value.to_str().ok())
        && request.get("method").and_then(Value::as_str) == Some("tools/call")
    {
        let body_name = request
            .get("params")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if name_header != body_name {
            bail!("Mcp-Name header does not match tools/call params.name");
        }
    }
    Ok(())
}

pub(crate) fn accept_header_contains(header_value: &str, expected: &str) -> bool {
    header_value
        .split(',')
        .filter_map(|part| part.trim().split(';').next())
        .any(|media_type| media_type.eq_ignore_ascii_case(expected) || media_type == "*/*")
}

pub(crate) fn config_with_http_identity(
    config: &ProxyConfig,
    headers: &HeaderMap,
) -> Result<ProxyConfig> {
    let mut effective = config.clone();
    if !config.auth.trust_subject_header {
        return Ok(effective);
    }
    let subject_header = config.auth.subject_header.trim();
    if subject_header.is_empty() {
        return Ok(effective);
    }
    if let Some(value) = headers.get(subject_header) {
        let subject = value
            .to_str()
            .map_err(|_| anyhow!("subject identity header must be visible ASCII"))?
            .trim();
        ensure_visible_ascii_identity("subject identity header", subject)?;
        effective.identity.subject_id = Some(subject.to_string());
    }
    Ok(effective)
}

pub(crate) fn ensure_visible_ascii_identity(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || !value.bytes().all(|byte| matches!(byte, 0x21..=0x7e)) {
        bail!("{label} must be non-empty visible ASCII");
    }
    Ok(())
}

pub(crate) fn prepare_http_request_context(
    state: &HttpState,
    headers: &HeaderMap,
    classification: &JsonRpcMessageKind,
    request: &Value,
) -> Result<HttpRequestContext> {
    let header_session_id = session_id_from_headers(headers)?;
    let header_protocol = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let method = classification.method();
    let requested_protocol = header_protocol
        .clone()
        .or_else(|| {
            request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "2025-03-26".to_string());
    if !state
        .config
        .http
        .supported_protocol_versions
        .iter()
        .any(|version| version == &requested_protocol)
    {
        bail!("unsupported MCP protocol version {requested_protocol}");
    }

    let store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session_id) = header_session_id {
        let Some(session) = store.sessions.get(&session_id) else {
            bail!("unknown MCP session id");
        };
        if let Some(protocol) = header_protocol
            && protocol != session.protocol_version
        {
            bail!("unsupported MCP protocol version {protocol} for negotiated session");
        }
        ensure_lifecycle_allows(method, classification, session.lifecycle)?;
        return Ok(HttpRequestContext {
            downstream_session_id: Some(session_id),
            upstream_session_id: session.upstream_session_id.clone(),
            protocol_version: session.protocol_version.clone(),
        });
    }

    if method == Some("initialize") || method == Some("ping") || classification.is_response() {
        return Ok(HttpRequestContext {
            downstream_session_id: None,
            upstream_session_id: None,
            protocol_version: requested_protocol,
        });
    }

    if let Some(stateless) = &store.stateless {
        if let Some(protocol) = header_protocol
            && protocol != stateless.protocol_version
        {
            bail!("unsupported MCP protocol version {protocol} for negotiated session");
        }
        ensure_lifecycle_allows(method, classification, stateless.lifecycle)?;
        return Ok(HttpRequestContext {
            downstream_session_id: None,
            upstream_session_id: None,
            protocol_version: stateless.protocol_version.clone(),
        });
    }

    if !store.sessions.is_empty() {
        bail!("MCP session id is required after stateful initialization");
    }
    bail!("initialize is required before non-lifecycle MCP operations");
}

pub(crate) fn ensure_lifecycle_allows(
    method: Option<&str>,
    classification: &JsonRpcMessageKind,
    lifecycle: LifecyclePhase,
) -> Result<()> {
    if classification.is_response() {
        return Ok(());
    }
    match lifecycle {
        LifecyclePhase::Initialized => Ok(()),
        LifecyclePhase::InitializeResponded => match method {
            Some("notifications/initialized") | Some("ping") => Ok(()),
            _ => bail!("initialization is not complete for this MCP session"),
        },
    }
}

pub(crate) fn mark_http_initialize_response(
    state: &HttpState,
    upstream_session_id: Option<String>,
    protocol_version: String,
) -> Result<Option<String>> {
    if let Some(session_id) = upstream_session_id {
        ensure_visible_ascii_session_id(&session_id)?;
        let mut store = state
            .sessions
            .lock()
            .map_err(|_| anyhow!("MCP session state poisoned"))?;
        store.sessions.insert(
            session_id.clone(),
            McpHttpSession {
                upstream_session_id: Some(session_id.clone()),
                protocol_version,
                lifecycle: LifecyclePhase::InitializeResponded,
                streams: BTreeMap::new(),
                pending_server_request_ids: BTreeSet::new(),
            },
        );
        Ok(Some(session_id))
    } else {
        let mut store = state
            .sessions
            .lock()
            .map_err(|_| anyhow!("MCP session state poisoned"))?;
        store.stateless = Some(StatelessHttpSession {
            protocol_version,
            lifecycle: LifecyclePhase::InitializeResponded,
        });
        Ok(None)
    }
}

pub(crate) fn mark_http_session_initialized(
    state: &HttpState,
    session_id: Option<&str>,
) -> Result<()> {
    let mut store = state
        .sessions
        .lock()
        .map_err(|_| anyhow!("MCP session state poisoned"))?;
    if let Some(session_id) = session_id {
        let Some(session) = store.sessions.get_mut(session_id) else {
            bail!("unknown MCP session id");
        };
        session.lifecycle = LifecyclePhase::Initialized;
    } else if let Some(stateless) = store.stateless.as_mut() {
        stateless.lifecycle = LifecyclePhase::Initialized;
    } else {
        bail!("initialize is required before notifications/initialized");
    }
    Ok(())
}

pub(crate) fn session_id_from_headers(headers: &HeaderMap) -> Result<Option<String>> {
    let Some(value) = headers
        .get("mcp-session-id")
        .or_else(|| headers.get("MCP-Session-Id"))
    else {
        return Ok(None);
    };
    let session_id = value
        .to_str()
        .map_err(|_| anyhow!("MCP session id must be visible ASCII"))?
        .to_string();
    ensure_visible_ascii_session_id(&session_id)?;
    Ok(Some(session_id))
}

pub(crate) fn ensure_visible_ascii_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty() || !session_id.bytes().all(|byte| matches!(byte, 0x21..=0x7e)) {
        bail!("MCP session id must be visible ASCII");
    }
    Ok(())
}

pub(crate) fn response_protocol_version(body: &[u8], fallback: &str) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn response_session_header(headers: &HeaderMap) -> Result<Option<String>> {
    let Some(value) = headers.get("mcp-session-id") else {
        return Ok(None);
    };
    let session_id = value
        .to_str()
        .map_err(|_| anyhow!("MCP session id must be visible ASCII"))?
        .to_string();
    ensure_visible_ascii_session_id(&session_id)?;
    Ok(Some(session_id))
}
