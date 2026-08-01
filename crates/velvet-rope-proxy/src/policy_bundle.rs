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
use crate::transport::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleManifest {
    pub schema_version: String,
    pub bundle_hash: String,
    pub expires_at: String,
    #[serde(default)]
    pub signature: Option<BundleSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleProof {
    pub schema_version: String,
    pub manifest_path: String,
    pub policy_dir: String,
    pub bundle_hash: String,
    pub expires_at: String,
    pub signature_verified: bool,
    pub verifier: String,
}

pub fn verify_policy_bundle(policy: &PolicyConfig) -> Result<PolicyBundleProof> {
    let manifest_path = &policy.bundle_manifest;
    let source = fs::read_to_string(manifest_path)
        .with_context(|| format!("read policy bundle manifest {}", manifest_path.display()))?;
    let manifest: PolicyBundleManifest = serde_yaml::from_str(&source)
        .with_context(|| format!("parse policy bundle manifest {}", manifest_path.display()))?;
    if manifest.schema_version != POLICY_BUNDLE_SCHEMA_VERSION {
        bail!(
            "unsupported policy bundle schema {}; expected {}",
            manifest.schema_version,
            POLICY_BUNDLE_SCHEMA_VERSION
        );
    }
    let expires_at = parse_time(&manifest.expires_at)?;
    if expires_at <= Utc::now() {
        bail!("policy bundle expired at {}", manifest.expires_at);
    }
    let actual_hash = policy_dir_hash(&policy.dir, manifest_path)?;
    if manifest.bundle_hash != actual_hash {
        bail!(
            "policy bundle hash mismatch: manifest={} actual={}",
            manifest.bundle_hash,
            actual_hash
        );
    }
    let trusted_public_key = trusted_policy_bundle_public_key(policy)?;
    if policy.require_signature && trusted_public_key.is_none() {
        bail!("policy bundle trusted signature public key is required");
    }
    let signature_verified = match &manifest.signature {
        Some(signature) => {
            if let Some(trusted_public_key) = &trusted_public_key
                && !signature
                    .public_key_hex
                    .eq_ignore_ascii_case(trusted_public_key)
            {
                bail!("policy bundle signing key does not match configured trust anchor");
            }
            verify_manifest_signature(&source, signature)?;
            true
        }
        None if policy.require_signature => bail!("policy bundle signature is required"),
        None => false,
    };
    Ok(PolicyBundleProof {
        schema_version: manifest.schema_version,
        manifest_path: manifest_path.display().to_string(),
        policy_dir: policy.dir.display().to_string(),
        bundle_hash: manifest.bundle_hash,
        expires_at: manifest.expires_at,
        signature_verified,
        verifier: if signature_verified {
            "ed25519".to_string()
        } else {
            "hash_manifest".to_string()
        },
    })
}

pub(crate) fn trusted_policy_bundle_public_key(policy: &PolicyConfig) -> Result<Option<String>> {
    let direct = policy
        .trusted_signature_public_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let from_env = match policy
        .trusted_signature_public_key_hex_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(env_name) => {
            let value = std::env::var(env_name)
                .with_context(|| format!("policy bundle trusted key env {env_name} is not set"))?;
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                bail!("policy bundle trusted key env {env_name} is empty");
            }
            Some(trimmed)
        }
        None => None,
    };
    let Some(key) = (match (direct, from_env) {
        (Some(_), Some(_)) => bail!(
            "configure exactly one of policy.trusted_signature_public_key_hex or \
             policy.trusted_signature_public_key_hex_env"
        ),
        (Some(value), None) => Some(value.to_string()),
        (None, Some(value)) => Some(value),
        (None, None) => None,
    }) else {
        return Ok(None);
    };
    let bytes = hex_decode(&key)?;
    if bytes.len() != 32 {
        bail!("policy bundle trusted ed25519 public key must be 32 bytes");
    }
    Ok(Some(key.to_ascii_lowercase()))
}

pub fn policy_dir_hash(policy_dir: &Path, manifest_path: &Path) -> Result<String> {
    let manifest_canonical = manifest_path.canonicalize().ok();
    let mut files = Vec::new();
    for entry in WalkDir::new(policy_dir).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        ) {
            continue;
        }
        if manifest_canonical
            .as_ref()
            .is_some_and(|manifest| path.canonicalize().ok().as_ref() == Some(manifest))
        {
            continue;
        }
        let relative = path.strip_prefix(policy_dir).unwrap_or(path);
        let bytes = fs::read(path).with_context(|| format!("read policy {}", path.display()))?;
        files.push(json!({
            "path": relative.to_string_lossy().replace('\\', "/"),
            "sha256": format!("sha256:{}", sha256_hex(&bytes)),
        }));
    }
    files.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["path"].as_str().unwrap_or_default())
    });
    Ok(format!(
        "sha256:{}",
        sha256_hex(canonical_json(&Value::Array(files)).as_bytes())
    ))
}

pub(crate) fn verify_manifest_signature(source: &str, signature: &BundleSignature) -> Result<()> {
    if signature.algorithm != "ed25519" {
        bail!("unsupported policy bundle signature algorithm");
    }
    let canonical = canonical_manifest_for_signature(source)?;
    let public_key_bytes: [u8; 32] = hex_decode(&signature.public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("ed25519 public key must be 32 bytes"))?;
    let signature_bytes: [u8; 64] = hex_decode(&signature.signature_hex)?
        .try_into()
        .map_err(|_| anyhow!("ed25519 signature must be 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|error| anyhow!("policy bundle signature verification failed: {error}"))
}

pub fn canonical_manifest_for_signature(source: &str) -> Result<String> {
    let mut value: Value = serde_yaml::from_str(source)?;
    let Some(object) = value.as_object_mut() else {
        bail!("policy bundle manifest must be an object");
    };
    object.remove("signature");
    Ok(canonical_json(&value))
}
