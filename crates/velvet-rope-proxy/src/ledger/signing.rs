use super::*;

pub(crate) fn signature_block_for_config(
    config: &ProxyConfig,
    payload_hash: &str,
    tenant_id: &str,
    purpose: &str,
) -> Result<Value> {
    match config.signing.provider {
        SigningProviderKind::AwsKms => {
            hosted_signature_block(config, payload_hash, tenant_id, purpose)
        }
        SigningProviderKind::Ed25519 => local_signature_block(payload_hash, tenant_id, purpose),
    }
}

fn hosted_signature_block(
    config: &ProxyConfig,
    payload_hash: &str,
    tenant_id: &str,
    purpose: &str,
) -> Result<Value> {
    if !config.control_plane.enabled() {
        bail!("control_plane.base_url is required when signing.provider is aws_kms");
    }
    let token_env = config
        .control_plane
        .gateway_token_env
        .as_deref()
        .ok_or_else(|| anyhow!("control_plane.gateway_token_env is required"))?;
    let token = std::env::var(token_env).with_context(|| {
        format!("gateway token env var {token_env} is required for hosted signing")
    })?;
    let kms_key_id = config
        .signing
        .kms_key_id_env
        .as_deref()
        .map(|env_name| {
            std::env::var(env_name).with_context(|| {
                format!("KMS key id env var {env_name} is required for hosted signing")
            })
        })
        .transpose()?;
    let url = format!(
        "{}/internal/v1/gateway/signatures",
        config.control_plane.base_url.trim_end_matches('/'),
    );
    let mut body = json!({
        "provider": "aws_kms",
        "algorithm": config.signing.algorithm,
        "payload_hash": payload_hash,
        "purpose": purpose,
        "tenant_id": tenant_id,
    });
    if let Some(kms_key_id) = kms_key_id
        && let Some(object) = body.as_object_mut()
    {
        object.insert("key_id".to_string(), Value::String(kms_key_id.clone()));
        object.insert("kms_key_id".to_string(), Value::String(kms_key_id));
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(StdDuration::from_millis(config.control_plane.timeout_ms()))
        .build()
        .context("build hosted signing client")?
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("post hosted signature request")?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().unwrap_or_else(|_| String::new());
        bail!("hosted signer rejected request: HTTP {status}: {text}");
    }
    let payload: Value = response
        .json()
        .context("decode hosted signature response")?;
    let signature = payload
        .get("signature")
        .cloned()
        .ok_or_else(|| anyhow!("hosted signature response missing signature"))?;
    if signature.get("provider_name").and_then(Value::as_str) != Some("aws_kms") {
        bail!("hosted signature response did not use aws_kms provider");
    }
    Ok(signature)
}

#[allow(dead_code)]
pub(crate) fn binary_signature_block(payload_hash: &str, tenant_id: &str) -> Result<Value> {
    local_signature_block(payload_hash, tenant_id, PURPOSE_LEDGER_RECORD_BINARY)
}

pub(crate) fn local_signature_block(
    payload_hash: &str,
    tenant_id: &str,
    purpose: &str,
) -> Result<Value> {
    let signed_at = now_rfc3339_z()
        .split('.')
        .next()
        .map(|prefix| format!("{prefix}Z"))
        .unwrap_or_else(now_rfc3339_z);
    let message = signing_message(payload_hash, tenant_id, purpose);
    let signature = hmac_sha256_hex(LOCAL_DEMO_SIGNATURE_KEY.as_bytes(), message.as_bytes());
    Ok(json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": LOCAL_DEMO_PROVIDER_NAME,
        "algorithm": LOCAL_DEMO_ALGORITHM,
        "key_id": LOCAL_DEMO_KEY_ID,
        "key_version": LOCAL_DEMO_KEY_VERSION,
        "purpose": purpose,
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "signature": signature,
        "signed_at": signed_at,
        "metadata": {
            "verification_tier": "local-dev-shared-secret",
            "demo_only": true,
            "non_production": true,
            "warning": "HMAC signatures use a shared secret and are local-dev only."
        }
    }))
}

pub(crate) fn signing_message(payload_hash: &str, tenant_id: &str, purpose: &str) -> String {
    canonical_json(&json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": LOCAL_DEMO_PROVIDER_NAME,
        "algorithm": LOCAL_DEMO_ALGORITHM,
        "key_version": LOCAL_DEMO_KEY_VERSION,
        "key_id": LOCAL_DEMO_KEY_ID,
        "tenant_id": tenant_id,
        "purpose": purpose,
        "payload_hash": payload_hash
    }))
}

pub(crate) fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        normalized_key[..32].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    hex_encode(&outer.finalize())
}

pub(crate) fn finalize_warrant(warrant: &mut WarrantV1) -> Result<()> {
    let mut value = serde_json::to_value(&mut *warrant)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("warrant_id".to_string(), Value::Null);
        object.insert("warrant_hash".to_string(), Value::Null);
        object.insert("signature".to_string(), Value::Null);
    }
    warrant.warrant_id = format!(
        "wrnt_{}",
        &sha256_hex(canonical_json(&value).as_bytes())[..32]
    );
    warrant.warrant_hash = warrant_hash_hex(warrant)?;
    Ok(())
}

pub(crate) fn sign_warrant_for_config(config: &ProxyConfig, warrant: &mut WarrantV1) -> Result<()> {
    if config.signing.provider != SigningProviderKind::AwsKms {
        return Ok(());
    }
    warrant.signature = Some(signature_block_for_config(
        config,
        &warrant.warrant_hash,
        &warrant.tenant_id,
        PURPOSE_WARRANT,
    )?);
    Ok(())
}

pub(crate) fn warrant_hash_hex(warrant: &WarrantV1) -> Result<String> {
    let value = warrant_hash_payload(warrant)?;
    Ok(value_hash(&value))
}

pub(crate) fn warrant_hash_payload(warrant: &WarrantV1) -> Result<Value> {
    let value = serde_json::to_value(warrant)?;
    let Some(object) = value.as_object() else {
        bail!("warrant must serialize as an object");
    };
    let mut unsigned = Map::new();
    for key in [
        "warrant_id",
        "issued_at",
        "tenant_id",
        "environment",
        "request_hash",
        "policy_hash",
        "tool_schema_hash",
        "tool_name",
        "decision",
        "reason",
        "reason_codes",
        "obligations",
        "approval_required",
        "expires_at",
        "issuer",
    ] {
        let item = object
            .get(key)
            .ok_or_else(|| anyhow!("warrant missing required field {key}"))?;
        unsigned.insert(key.to_string(), item.clone());
    }
    Ok(Value::Object(unsigned))
}

pub(crate) fn selected_warrant_hash_hex(warrant: &WarrantV1) -> Result<String> {
    warrant_hash_hex(warrant)
}

pub(crate) fn canonical_ledger_record_hash_hex(record: &CanonicalLedgerRecord) -> Result<String> {
    let mut value = serde_json::to_value(record)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("record_hash");
    }
    Ok(value_hash(&value))
}

pub(crate) fn oap_ledger_record_hash_hex(record: &OapLedgerRecord) -> Result<String> {
    let mut value = serde_json::to_value(record)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("record_hash");
    }
    Ok(value_hash(&value))
}

pub(crate) fn approval_receipt_hash(receipt: &ApprovalReceipt) -> Result<String> {
    let mut value = serde_json::to_value(receipt)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("receipt_hash");
        object.remove("signature");
    }
    Ok(value_hash_hex(&value))
}
