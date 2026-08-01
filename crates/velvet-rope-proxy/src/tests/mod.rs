use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use velvet_core::{
    JsonObject, SIGNATURE_SCHEMA_VERSION as CORE_SIGNATURE_SCHEMA_VERSION, SignatureBlock,
    signing_message_bytes,
};

use crate::enforcement::*;
use crate::ledger::*;
use crate::permit_store::PermitClaimStore;
use crate::transport::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use uuid::Uuid;

use super::*;

mod approvals;
mod config;
mod enforcement;
mod ledger;
mod oap;
mod permits;
mod policy_bundle;
mod support;
mod transport;
mod verdicts;

use oap::required_certificate_absence_blocks_before_forward;
use support::*;
