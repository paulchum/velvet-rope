//! Runtime enforcement of Velvet Verdict Certificates.
//!
//! A verdict certificate is a signed JSON object representing a certified
//! irreversible decision (`schemas/velvet_rope/verdict_certificate.schema.json`).
//! Verdict math NEVER runs here: the proxy only verifies schema constants, the
//! canonical payload hash, the Velvet SignatureBlock, the signing purpose, and
//! expiry — the same cost class as Execution Permit checks.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value, json};

use crate::config::ProxyConfig;
use crate::constants::{CANONICALIZATION_UNSIGNED_PAYLOAD, SIGNATURE_SCHEMA_VERSION};
use crate::execution::decode_key_material;
use crate::ledger::{canonical_json, sha256_hex};

/// `schema_version` const required on every verdict certificate.
pub const VERDICT_CERTIFICATE_SCHEMA_VERSION: &str = "velvet.verdict_certificate.v1";
/// Signing purpose required in the certificate's SignatureBlock.
pub const PURPOSE_VERDICT_CERTIFICATE: &str = "velvet.verdict_certificate.v1";
/// The only verdict that licenses an irreversible action.
pub const VERDICT_SAFE_KILL: &str = "safe_kill";

const VERDICT_VALUES: [&str; 3] = ["safe_kill", "required_inspection", "refusal"];

/// Result of verifying a verdict certificate.
///
/// `expired` distinguishes a certificate that verified in every respect but is
/// past `validity.expires_at` (callers escalate for re-certification) from an
/// invalid certificate (callers fail closed, returned as `Err`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCheck {
    pub verdict: String,
    pub certificate_hash: String,
    pub expires_at: DateTime<Utc>,
    pub decision_class: String,
    pub tenant_id: String,
    pub expired: bool,
}

/// Verify a verdict certificate against the proxy's trusted verdict key.
///
/// The trusted Ed25519 public key is read from the env var named by
/// `config.oap.verdict_trusted_public_key_env` (defaults to the same env var
/// as the Execution Permit trusted key, so single-key deployments work out of
/// the box) and the signature `key_id` is pinned to `config.oap.velvet_kid`.
///
/// Returns `Err` for any structural, hash, or signature failure; returns
/// `Ok(VerdictCheck { expired: true, .. })` when the certificate verifies but
/// `now >= validity.expires_at`.
pub fn verify_verdict_certificate(
    certificate: &Value,
    config: &ProxyConfig,
    now: DateTime<Utc>,
) -> Result<VerdictCheck> {
    let public_key_hex =
        std::env::var(&config.oap.verdict_trusted_public_key_env).with_context(|| {
            format!(
                "required Velvet verdict certificate trusted public key env var {} is not set",
                config.oap.verdict_trusted_public_key_env
            )
        })?;
    if public_key_hex.trim().is_empty() {
        bail!("Velvet verdict certificate trusted public key env var is empty");
    }
    let public_key_bytes: [u8; 32] = decode_key_material(&public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("trusted Velvet verdict certificate public key must be 32 bytes"))?;
    verify_verdict_certificate_with_key(
        certificate,
        &public_key_bytes,
        Some(&config.oap.velvet_kid),
        now,
    )
}

/// Verify a verdict certificate against a pinned 32-byte Ed25519 public key.
///
/// Used by `velvet-closure` risk gates, which hold the trusted key directly
/// instead of resolving it from proxy configuration. When `expected_key_id`
/// is `Some`, the signature's `key_id` must match it exactly.
pub fn verify_verdict_certificate_with_key(
    certificate: &Value,
    public_key_bytes: &[u8; 32],
    expected_key_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<VerdictCheck> {
    let object = certificate
        .as_object()
        .ok_or_else(|| anyhow!("verdict certificate must be an object"))?;
    if certificate_str(object, "schema_version")? != VERDICT_CERTIFICATE_SCHEMA_VERSION {
        bail!("verdict certificate schema version mismatch");
    }
    if certificate_str(object, "canonicalization")? != CANONICALIZATION_UNSIGNED_PAYLOAD {
        bail!("verdict certificate canonicalization mismatch");
    }
    let tenant_id = certificate_str(object, "tenant_id")?.to_string();
    let verdict = certificate_str(object, "verdict")?.to_string();
    if !VERDICT_VALUES.contains(&verdict.as_str()) {
        bail!("verdict certificate verdict value is not recognized");
    }
    let decision_class = certificate
        .pointer("/subject/decision_class")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verdict certificate missing subject.decision_class"))?
        .to_string();

    let payload_hash = verdict_certificate_payload_hash(certificate)?;
    if certificate_str(object, "certificate_hash")? != payload_hash {
        bail!("verdict certificate hash mismatch");
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("verdict certificate missing signature block"))?;
    verify_verdict_signature_block(
        signature,
        public_key_bytes,
        expected_key_id,
        &tenant_id,
        &payload_hash,
    )?;

    let expires_at_raw = certificate
        .pointer("/validity/expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verdict certificate missing validity.expires_at"))?;
    let expires_at = DateTime::parse_from_rfc3339(expires_at_raw)
        .context("parse verdict certificate validity.expires_at")?
        .with_timezone(&Utc);

    Ok(VerdictCheck {
        verdict,
        certificate_hash: payload_hash,
        expires_at,
        decision_class,
        tenant_id,
        expired: now >= expires_at,
    })
}

/// Canonical payload hash of a verdict certificate: `sha256:<hex>` over the
/// canonical JSON of the object with `signature` and `certificate_hash`
/// removed.
pub fn verdict_certificate_payload_hash(certificate: &Value) -> Result<String> {
    let mut unsigned = certificate.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("verdict certificate must be an object"))?;
    object.remove("signature");
    object.remove("certificate_hash");
    Ok(format!(
        "sha256:{}",
        sha256_hex(canonical_json(&unsigned).as_bytes())
    ))
}

fn verify_verdict_signature_block(
    signature: &Map<String, Value>,
    public_key_bytes: &[u8; 32],
    expected_key_id: Option<&str>,
    certificate_tenant_id: &str,
    payload_hash: &str,
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;
    let key_id = signature_str(signature, "key_id")?;
    let key_version = signature_str(signature, "key_version")?;
    let provider_name = signature_str(signature, "provider_name")?;
    let algorithm = signature_str(signature, "algorithm")?;
    let purpose = signature_str(signature, "purpose")?;
    let tenant_id = signature_str(signature, "tenant_id")?;
    let signed_payload_hash = signature_str(signature, "payload_hash")?;
    if signature_str(signature, "schema_version")? != SIGNATURE_SCHEMA_VERSION {
        bail!("verdict certificate signature schema version mismatch");
    }
    if let Some(expected_key_id) = expected_key_id
        && key_id != expected_key_id
    {
        bail!("verdict certificate signature key id is not trusted");
    }
    if provider_name != "velvet_ed25519" || algorithm != "Ed25519" {
        bail!("verdict certificate signature algorithm is not trusted");
    }
    if purpose != PURPOSE_VERDICT_CERTIFICATE {
        bail!("verdict certificate signature purpose mismatch");
    }
    if tenant_id != certificate_tenant_id {
        bail!("verdict certificate signature tenant mismatch");
    }
    if signed_payload_hash != payload_hash {
        bail!("verdict certificate signature payload hash mismatch");
    }
    if let Some(embedded_public_key) = signature
        .get("public_verification_material")
        .and_then(Value::as_object)
        .and_then(|material| material.get("public_key_base64"))
        .and_then(Value::as_str)
    {
        let embedded = BASE64_STANDARD
            .decode(embedded_public_key)
            .context("decode embedded Velvet verdict certificate public key")?;
        if embedded.as_slice() != public_key_bytes {
            bail!("verdict certificate embedded public key does not match trusted key");
        }
    }
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(signature_str(signature, "signature")?)
        .context("decode verdict certificate signature")?
        .try_into()
        .map_err(|_| anyhow!("verdict certificate signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = canonical_json(&json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": provider_name,
        "algorithm": algorithm,
        "key_version": key_version,
        "key_id": key_id,
        "tenant_id": tenant_id,
        "purpose": purpose,
        "payload_hash": payload_hash,
    }));
    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("verify verdict certificate signature")
}

fn certificate_str<'a>(certificate: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    certificate
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verdict certificate missing {key}"))
}

fn signature_str<'a>(signature: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    signature
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verdict certificate signature missing {key}"))
}
