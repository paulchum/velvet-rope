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
use crate::inventory::*;
use crate::ledger::*;
use crate::oap::*;
use crate::policy_bundle::*;
use crate::transport::*;

#[derive(Debug, Parser)]
#[command(name = "velvet-rope-proxy")]
#[command(about = "Pre-execution MCP proxy for Velvet Rope admission")]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    Demo {
        #[arg(long, default_value = "reports/mcp_proxy")]
        output_dir: PathBuf,
    },
    Conformance,
    Benchmark {
        #[arg(long, default_value = "reports/mcp_proxy/benchmark")]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
    TlsCheck {
        #[arg(long, default_value = DEFAULT_TLS_CHECK_URL)]
        url: String,
    },
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match (cli.command, cli.config) {
        (Some(CliCommand::Demo { output_dir }), None) => {
            let summary = run_demo(&output_dir)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        (Some(CliCommand::Conformance), None) => {
            println!("{}", serde_json::to_string_pretty(&conformance_matrix())?);
            Ok(())
        }
        (
            Some(CliCommand::Benchmark {
                output_dir,
                iterations,
            }),
            None,
        ) => {
            let summary = run_benchmark(&output_dir, iterations)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        (Some(CliCommand::TlsCheck { url }), None) => run_tls_check_command(&url).await,
        (None, Some(config)) => run_config(&config).await,
        (Some(_), Some(_)) => bail!("use either --config or a subcommand, not both"),
        (None, None) => bail!("provide --config config.yaml or run the demo subcommand"),
    }
}

pub async fn run_config(path: &Path) -> Result<()> {
    let config = ProxyConfig::load(path)?;
    match config.transport {
        TransportKind::Fake => {
            let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
            let summary = runtime.run_fake_script()?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        TransportKind::Stdio => {
            let upstream = StdioMcpServer::spawn(&config.upstream)?;
            let mut runtime = ProxyRuntime::new(config, upstream)?;
            runtime.run_stdio_loop()
        }
        TransportKind::StreamableHttp => run_http_proxy(config).await,
    }
}
