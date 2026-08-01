use super::*;

pub(crate) fn ensure_demo_signing_env() {
    const DEMO_OAP_KEY_HEX: &str =
        "0707070707070707070707070707070707070707070707070707070707070707";
    const DEMO_MAXDE_KEY_HEX: &str =
        "0909090909090909090909090909090909090909090909090909090909090909";
    const DEMO_MAXDE_PUBLIC_KEY_HEX: &str =
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
    // Demo/test runs are local and deterministic; production configs still
    // source signing material from operator-provided environment variables.
    unsafe {
        if std::env::var_os("VELVET_OAP_ED25519_PRIVATE_KEY").is_none() {
            std::env::set_var("VELVET_OAP_ED25519_PRIVATE_KEY", DEMO_OAP_KEY_HEX);
        }
        if std::env::var_os("VELVET_MAXDE_ED25519_PRIVATE_KEY").is_none() {
            std::env::set_var("VELVET_MAXDE_ED25519_PRIVATE_KEY", DEMO_MAXDE_KEY_HEX);
        }
        if std::env::var_os("VELVET_MAXDE_ED25519_PUBLIC_KEY").is_none() {
            std::env::set_var("VELVET_MAXDE_ED25519_PUBLIC_KEY", DEMO_MAXDE_PUBLIC_KEY_HEX);
        }
    }
}

pub fn value_hash(value: &Value) -> String {
    format!("sha256:{}", sha256_hex(canonical_json(value).as_bytes()))
}

pub fn value_hash_hex(value: &Value) -> String {
    value_hash(value)
}

pub(crate) fn request_hash_hex(request: &Value) -> String {
    value_hash(&request_without_approval_receipt(request))
}

pub(crate) fn redacted_public_request(request: &Value) -> Value {
    redact_sensitive_value(&request_without_approval_receipt(request))
}

pub(crate) fn request_without_approval_receipt(request: &Value) -> Value {
    let mut value = request.clone();
    let mut remove_empty_meta = false;
    if let Some(meta) = value
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .and_then(|params| params.get_mut("_meta"))
        .and_then(Value::as_object_mut)
    {
        meta.remove("velvet_approval_receipt");
        meta.remove("velvet_execution");
        remove_empty_meta = meta.is_empty();
    }
    if remove_empty_meta
        && let Some(params) = value.get_mut("params").and_then(Value::as_object_mut)
    {
        params.remove("_meta");
    }
    value
}

pub(crate) fn arguments_hash_hex_from_request(request: &Value) -> Result<String> {
    let arguments = request
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(value_hash(&arguments))
}

pub(crate) fn redact_sensitive_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = Map::new();
            for (key, child) in object {
                if is_sensitive_key(key) {
                    redacted.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    redacted.insert(key.clone(), redact_sensitive_value(child));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_sensitive_value).collect()),
        other => other.clone(),
    }
}

pub(crate) fn policy_hash_hex(bundle_proof: &PolicyBundleProof) -> String {
    if bundle_proof.bundle_hash.starts_with("sha256:") {
        bundle_proof.bundle_hash.clone()
    } else {
        format!("sha256:{}", bundle_proof.bundle_hash)
    }
}

pub(crate) fn split_tool_key(tool_key: &str) -> (Option<String>, Option<String>) {
    let Some((server, tool)) = tool_key.split_once('/') else {
        return (None, Some(tool_key.to_string()));
    };
    (Some(server.to_string()), Some(tool.to_string()))
}

pub(crate) fn jsonrpc_request_id(request: &Value) -> Option<String> {
    request.get("id").map(|id| match id {
        Value::String(value) => value.clone(),
        other => canonical_json(other),
    })
}

pub(crate) fn session_id(config: &ProxyConfig, request: &Value) -> Option<String> {
    request
        .pointer("/params/_meta/session_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| config.identity.session_id.clone())
}

pub(crate) fn record_inventory_event(
    config: &ProxyConfig,
    inventory: &ToolInventory,
) -> Result<()> {
    if let Some(path) = config.inventory_path.as_deref() {
        inventory.write_if_configured(Some(path))?;
    }
    Ok(())
}

pub(crate) fn write_approval_request_if_needed(
    config: &ProxyConfig,
    admission: &AdmissionOutcome,
) -> Result<()> {
    let Some(request) = &admission.approval_request else {
        return Ok(());
    };
    let Some(path) = config.approval_requests_path.as_deref() else {
        return Ok(());
    };
    append_jsonl(path, request)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(&values[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

pub(crate) fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    for index in (0..input.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&input[index..index + 2], 16)?);
    }
    Ok(bytes)
}

pub(crate) fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
