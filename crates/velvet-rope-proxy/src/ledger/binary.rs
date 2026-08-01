use super::*;

pub(crate) fn append_canonical_ledger_record(
    config: &ProxyConfig,
    record: &CanonicalLedgerRecord,
) -> Result<()> {
    append_binary_ledger_record(
        config,
        &serde_json::to_value(record)?,
        RECORD_KIND_CANONICAL,
    )
}

pub(crate) fn append_oap_ledger_record(
    config: &ProxyConfig,
    record: &OapLedgerRecord,
) -> Result<()> {
    append_binary_ledger_record(config, &serde_json::to_value(record)?, RECORD_KIND_OAP)
}

pub(crate) fn next_ledger_sequence_state(path: &Path) -> Result<LedgerSequenceState> {
    if !path.exists() {
        return Ok(LedgerSequenceState {
            sequence_number: 1,
            previous_record_hash: LEDGER_GENESIS_HASH.to_string(),
            previous_frame_hash: LEDGER_GENESIS_HASH.to_string(),
        });
    }
    let frames = read_binary_ledger_frames(path)?;
    let Some(last) = frames.last() else {
        return Ok(LedgerSequenceState {
            sequence_number: 1,
            previous_record_hash: LEDGER_GENESIS_HASH.to_string(),
            previous_frame_hash: LEDGER_GENESIS_HASH.to_string(),
        });
    };
    let last_sequence = last
        .payload
        .get("sequence_number")
        .and_then(Value::as_u64)
        .unwrap_or(last.sequence_number);
    let last_hash = last
        .payload
        .get("record_hash")
        .and_then(Value::as_str)
        .unwrap_or(LEDGER_GENESIS_HASH)
        .to_string();
    Ok(LedgerSequenceState {
        sequence_number: last_sequence + 1,
        previous_record_hash: last_hash,
        previous_frame_hash: last.frame_hash.clone(),
    })
}

pub(crate) fn approval_receipt_id_seen_in_ledger(path: &Path, receipt_id: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    for frame in read_binary_ledger_frames(path)? {
        if frame
            .payload
            .get("approval_receipt_id")
            .and_then(Value::as_str)
            .is_some_and(|recorded| recorded == receipt_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn last_binary_ledger_record(path: &Path) -> Result<Value> {
    read_binary_ledger_frames(path)?
        .pop()
        .map(|frame| frame.payload)
        .ok_or_else(|| anyhow!("ledger has no persisted records"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryLedgerDecodeErrorKind {
    Empty,
    Truncated,
    MagicMismatch,
    UnsupportedVersion,
    PayloadTooLarge,
    LengthOverflow,
    MetadataParse,
    PayloadParse,
    MetadataNotObject,
    PayloadHashMismatch,
    FrameHashMismatch,
    MetadataPayloadHashMismatch,
    HashFormat,
    SequenceMismatch,
    PreviousFrameHashMismatch,
    SignatureMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryLedgerDecodeError {
    kind: BinaryLedgerDecodeErrorKind,
    offset: usize,
    message: String,
}

impl BinaryLedgerDecodeError {
    fn new(kind: BinaryLedgerDecodeErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> BinaryLedgerDecodeErrorKind {
        self.kind
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl std::fmt::Display for BinaryLedgerDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for BinaryLedgerDecodeError {}

type BinaryLedgerDecodeResult<T> = std::result::Result<T, BinaryLedgerDecodeError>;

#[derive(Debug, Clone, PartialEq)]
pub struct BinaryLedgerFrame {
    pub offset: usize,
    pub end_offset: usize,
    pub kind: u8,
    pub sequence_number: u64,
    pub previous_frame_hash: String,
    pub payload_hash: String,
    pub frame_hash: String,
    pub metadata: Value,
    pub payload: Value,
}

pub(crate) fn append_binary_ledger_record(
    config: &ProxyConfig,
    payload: &Value,
    kind: u8,
) -> Result<()> {
    if config.ledger.sink == LedgerSink::ControlPlane {
        post_hosted_ledger_record(config, payload, kind)?;
    }
    if let Some(parent) = config.ledger_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let frames = read_binary_ledger_frames(&config.ledger_path)?;
    let previous_frame_hash = frames
        .last()
        .map(|frame| frame.frame_hash.as_str())
        .unwrap_or(LEDGER_GENESIS_HASH);
    let sequence_number = payload
        .get("sequence_number")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("ledger payload missing sequence_number"))?;
    let encoded = encode_binary_ledger_record_with_signer(
        payload,
        kind,
        sequence_number,
        previous_frame_hash,
        |frame_hash, tenant_id| {
            signature_block_for_config(config, frame_hash, tenant_id, PURPOSE_LEDGER_RECORD_BINARY)
        },
    )?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.ledger_path)?;
    file.write_all(&encoded)?;
    if config.ledger.fsync {
        file.sync_all()?;
    }
    Ok(())
}

pub(crate) fn post_hosted_ledger_record(
    config: &ProxyConfig,
    payload: &Value,
    kind: u8,
) -> Result<()> {
    if !config.control_plane.enabled() {
        bail!("control_plane.base_url is required when ledger.sink is control_plane");
    }
    let token_env = config
        .control_plane
        .gateway_token_env
        .as_deref()
        .ok_or_else(|| anyhow!("control_plane.gateway_token_env is required"))?;
    let token = std::env::var(token_env).with_context(|| {
        format!("required control-plane gateway token env var {token_env} is not set")
    })?;
    let phase_path = match payload.get("record_type").and_then(Value::as_str) {
        Some("post_execution_observation") => "post-execution",
        _ => "pre-execution",
    };
    let url = format!(
        "{}/internal/v1/gateway/ledger/{}",
        config.control_plane.base_url.trim_end_matches('/'),
        phase_path
    );
    let body = json!({
        "record": payload,
        "kind": kind,
        "environment_id": payload
            .get("environment_id")
            .or_else(|| payload.get("environment"))
            .cloned()
            .unwrap_or_else(|| Value::String(config.identity.environment.clone())),
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(StdDuration::from_millis(config.control_plane.timeout_ms()))
        .build()
        .context("build hosted ledger HTTP client")?;
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("post hosted ledger record")?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().unwrap_or_else(|_| String::new());
        bail!("hosted ledger sink rejected record: HTTP {status}: {text}");
    }
    Ok(())
}

#[allow(dead_code)]
pub fn encode_binary_ledger_record(
    payload: &Value,
    kind: u8,
    sequence_number: u64,
    previous_frame_hash: &str,
) -> Result<Vec<u8>> {
    encode_binary_ledger_record_with_signer(
        payload,
        kind,
        sequence_number,
        previous_frame_hash,
        binary_signature_block,
    )
}

fn encode_binary_ledger_record_with_signer<F>(
    payload: &Value,
    kind: u8,
    sequence_number: u64,
    previous_frame_hash: &str,
    signer: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(&str, &str) -> Result<Value>,
{
    let payload_bytes = canonical_json(payload).into_bytes();
    if payload_bytes.len() > VELVET_LEDGER_RECORD_MAX_BYTES {
        bail!("ledger payload exceeds max binary record size");
    }
    let payload_hash = domain_hash(VELVET_LEDGER_PAYLOAD_HASH_DOMAIN, &payload_bytes);
    let tenant_id = payload
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or(LOCAL_DEMO_TENANT_ID);
    let unsigned_metadata = json!({
        "format": BINARY_LEDGER_FORMAT,
        "kind": kind,
        "payload_hash": payload_hash,
        "previous_frame_hash": previous_frame_hash,
        "sequence_number": sequence_number
    });
    let unsigned_metadata_bytes = canonical_json(&unsigned_metadata).into_bytes();
    let frame_hash = binary_frame_hash(
        VELVET_LEDGER_FORMAT_VERSION,
        kind,
        sequence_number,
        payload_bytes.len() as u64,
        previous_frame_hash,
        &payload_hash,
        &unsigned_metadata_bytes,
    )?;
    let signature = signer(&frame_hash, tenant_id)?;
    let mut metadata = unsigned_metadata;
    let Some(object) = metadata.as_object_mut() else {
        bail!("binary ledger metadata must be an object");
    };
    object.insert("frame_hash".to_string(), Value::String(frame_hash.clone()));
    object.insert("signature".to_string(), signature);
    let metadata_bytes = canonical_json(&metadata).into_bytes();

    let mut encoded = Vec::with_capacity(126 + metadata_bytes.len() + payload_bytes.len());
    encoded.extend_from_slice(VELVET_LEDGER_MAGIC);
    encoded.push(VELVET_LEDGER_FORMAT_VERSION);
    encoded.push(kind);
    encoded.extend_from_slice(&sequence_number.to_be_bytes());
    encoded.extend_from_slice(&(payload_bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&hash_digest(previous_frame_hash)?);
    encoded.extend_from_slice(&hash_digest(&payload_hash)?);
    encoded.extend_from_slice(&hash_digest(&frame_hash)?);
    encoded.extend_from_slice(&(metadata_bytes.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&metadata_bytes);
    encoded.extend_from_slice(&payload_bytes);
    Ok(encoded)
}

pub(crate) fn read_binary_ledger_frames(path: &Path) -> Result<Vec<BinaryLedgerFrame>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path)?;
    Ok(decode_binary_ledger_frames(&data)?)
}

pub fn decode_binary_ledger_frames(
    data: &[u8],
) -> BinaryLedgerDecodeResult<Vec<BinaryLedgerFrame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let (frame, next_offset) = parse_binary_ledger_frame(data, offset)?;
        frames.push(frame);
        offset = next_offset;
    }
    Ok(frames)
}

pub fn verify_binary_ledger_bytes(data: &[u8]) -> BinaryLedgerDecodeResult<Vec<BinaryLedgerFrame>> {
    if data.is_empty() {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::Empty,
            0,
            "binary ledger is empty",
        ));
    }
    let frames = decode_binary_ledger_frames(data)?;
    let mut previous_frame_hash = LEDGER_GENESIS_HASH.to_string();
    for (expected_sequence, frame) in (1_u64..).zip(frames.iter()) {
        if frame.sequence_number != expected_sequence {
            return Err(BinaryLedgerDecodeError::new(
                BinaryLedgerDecodeErrorKind::SequenceMismatch,
                frame.offset,
                format!(
                    "binary ledger sequence mismatch at byte offset {}",
                    frame.offset
                ),
            ));
        }
        if frame.previous_frame_hash != previous_frame_hash {
            return Err(BinaryLedgerDecodeError::new(
                BinaryLedgerDecodeErrorKind::PreviousFrameHashMismatch,
                frame.offset,
                format!(
                    "binary ledger previous frame hash mismatch at byte offset {}",
                    frame.offset
                ),
            ));
        }
        verify_binary_ledger_frame_signature(frame).map_err(|error| {
            BinaryLedgerDecodeError::new(
                BinaryLedgerDecodeErrorKind::SignatureMismatch,
                frame.offset,
                error.to_string(),
            )
        })?;
        previous_frame_hash = frame.frame_hash.clone();
    }
    Ok(frames)
}

fn verify_binary_ledger_frame_signature(frame: &BinaryLedgerFrame) -> Result<()> {
    let signature = frame
        .metadata
        .get("signature")
        .ok_or_else(|| anyhow!("binary ledger frame missing signature"))?;
    if signature.get("schema_version").and_then(Value::as_str) != Some(SIGNATURE_SCHEMA_VERSION) {
        bail!("binary ledger frame signature schema_version does not match");
    }
    let metadata = signature
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("binary ledger frame signature missing metadata"))?;
    for (field, expected) in [
        ("verification_tier", "local-dev-shared-secret"),
        (
            "warning",
            "HMAC signatures use a shared secret and are local-dev only.",
        ),
    ] {
        if metadata.get(field).and_then(Value::as_str) != Some(expected) {
            bail!("binary ledger frame signature metadata {field} does not match");
        }
    }
    for field in ["demo_only", "non_production"] {
        if metadata.get(field).and_then(Value::as_bool) != Some(true) {
            bail!("binary ledger frame signature metadata {field} does not match");
        }
    }
    let signed_at = signature
        .get("signed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("binary ledger frame signature missing signed_at"))?;
    let signed_at = parse_time(signed_at)
        .with_context(|| "binary ledger frame signature signed_at is invalid")?;
    let earliest_supported = parse_time("2026-01-01T00:00:00Z")?;
    if signed_at < earliest_supported || signed_at > Utc::now() + Duration::minutes(5) {
        bail!("binary ledger frame signature signed_at is outside the supported window");
    }
    let tenant_id = signature
        .get("tenant_id")
        .and_then(Value::as_str)
        .or_else(|| frame.payload.get("tenant_id").and_then(Value::as_str))
        .unwrap_or(LOCAL_DEMO_TENANT_ID);
    verify_local_signature(
        signature,
        &frame.frame_hash,
        tenant_id,
        PURPOSE_LEDGER_RECORD_BINARY,
    )
}

pub fn parse_binary_ledger_frame(
    data: &[u8],
    offset: usize,
) -> BinaryLedgerDecodeResult<(BinaryLedgerFrame, usize)> {
    const HEADER_LEN: usize = 126;
    if data.len().saturating_sub(offset) < HEADER_LEN {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::Truncated,
            offset,
            format!("binary ledger record truncated at byte offset {offset}"),
        ));
    }
    let header = &data[offset..offset + HEADER_LEN];
    if &header[0..8] != VELVET_LEDGER_MAGIC {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::MagicMismatch,
            offset,
            format!("binary ledger magic mismatch at byte offset {offset}"),
        ));
    }
    let version = header[8];
    if version != VELVET_LEDGER_FORMAT_VERSION {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::UnsupportedVersion,
            offset,
            format!("unsupported binary ledger version at byte offset {offset}"),
        ));
    }
    let kind = header[9];
    let sequence_number = u64::from_be_bytes(
        header[10..18]
            .try_into()
            .expect("binary ledger header sequence field has fixed length"),
    );
    let payload_len = u64::from_be_bytes(
        header[18..26]
            .try_into()
            .expect("binary ledger header payload length field has fixed length"),
    ) as usize;
    if payload_len > VELVET_LEDGER_RECORD_MAX_BYTES {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::PayloadTooLarge,
            offset,
            format!("binary ledger payload too large at byte offset {offset}"),
        ));
    }
    let previous_frame_hash = format!("sha256:{}", hex_encode(&header[26..58]));
    let stored_payload_hash = format!("sha256:{}", hex_encode(&header[58..90]));
    let stored_frame_hash = format!("sha256:{}", hex_encode(&header[90..122]));
    let metadata_len = u32::from_be_bytes(
        header[122..126]
            .try_into()
            .expect("binary ledger header metadata length field has fixed length"),
    ) as usize;
    let metadata_start = offset.checked_add(HEADER_LEN).ok_or_else(|| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::LengthOverflow,
            offset,
            format!("binary ledger record length overflow at byte offset {offset}"),
        )
    })?;
    let payload_start = metadata_start.checked_add(metadata_len).ok_or_else(|| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::LengthOverflow,
            offset,
            format!("binary ledger record length overflow at byte offset {offset}"),
        )
    })?;
    let end_offset = payload_start.checked_add(payload_len).ok_or_else(|| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::LengthOverflow,
            offset,
            format!("binary ledger record length overflow at byte offset {offset}"),
        )
    })?;
    if payload_start > data.len() || end_offset > data.len() {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::Truncated,
            offset,
            format!("binary ledger record truncated at byte offset {offset}"),
        ));
    }
    let metadata_bytes = &data[metadata_start..payload_start];
    let payload_bytes = &data[payload_start..end_offset];
    let metadata: Value = serde_json::from_slice(metadata_bytes).map_err(|error| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::MetadataParse,
            metadata_start,
            format!("parse binary ledger metadata at byte offset {metadata_start}: {error}"),
        )
    })?;
    let payload: Value = serde_json::from_slice(payload_bytes).map_err(|error| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::PayloadParse,
            payload_start,
            format!("parse binary ledger payload at byte offset {payload_start}: {error}"),
        )
    })?;
    let payload_hash = domain_hash(VELVET_LEDGER_PAYLOAD_HASH_DOMAIN, payload_bytes);
    if payload_hash != stored_payload_hash {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::PayloadHashMismatch,
            offset,
            format!("binary ledger payload hash mismatch at byte offset {offset}"),
        ));
    }
    let unsigned_metadata_bytes = unsigned_binary_metadata_bytes(&metadata).map_err(|error| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::MetadataNotObject,
            metadata_start,
            error.to_string(),
        )
    })?;
    let frame_hash = binary_frame_hash(
        version,
        kind,
        sequence_number,
        payload_len as u64,
        &previous_frame_hash,
        &payload_hash,
        &unsigned_metadata_bytes,
    )
    .map_err(|error| {
        BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::HashFormat,
            offset,
            error.to_string(),
        )
    })?;
    if frame_hash != stored_frame_hash
        || metadata.get("frame_hash").and_then(Value::as_str) != Some(frame_hash.as_str())
    {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::FrameHashMismatch,
            offset,
            format!("binary ledger frame hash mismatch at byte offset {offset}"),
        ));
    }
    if metadata.get("payload_hash").and_then(Value::as_str) != Some(payload_hash.as_str()) {
        return Err(BinaryLedgerDecodeError::new(
            BinaryLedgerDecodeErrorKind::MetadataPayloadHashMismatch,
            offset,
            format!("binary ledger metadata payload hash mismatch at byte offset {offset}"),
        ));
    }
    Ok((
        BinaryLedgerFrame {
            offset,
            end_offset,
            kind,
            sequence_number,
            previous_frame_hash,
            payload_hash,
            frame_hash,
            metadata,
            payload,
        },
        end_offset,
    ))
}

pub(crate) fn unsigned_binary_metadata_bytes(metadata: &Value) -> Result<Vec<u8>> {
    let Some(object) = metadata.as_object() else {
        bail!("binary ledger metadata must be an object");
    };
    let mut unsigned = object.clone();
    unsigned.remove("signature");
    unsigned.remove("frame_hash");
    Ok(canonical_json(&Value::Object(unsigned)).into_bytes())
}

pub(crate) fn binary_frame_hash(
    version: u8,
    kind: u8,
    sequence_number: u64,
    payload_len: u64,
    previous_frame_hash: &str,
    payload_hash: &str,
    metadata_bytes: &[u8],
) -> Result<String> {
    let mut message = Vec::new();
    message.extend_from_slice(VELVET_LEDGER_RECORD_HASH_DOMAIN);
    message.push(0);
    message.push(version);
    message.push(kind);
    message.extend_from_slice(&sequence_number.to_be_bytes());
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(&(metadata_bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(&hash_digest(previous_frame_hash)?);
    message.extend_from_slice(&hash_digest(payload_hash)?);
    message.extend_from_slice(metadata_bytes);
    Ok(format!("sha256:{}", sha256_hex(&message)))
}

pub(crate) fn domain_hash(domain: &[u8], payload: &[u8]) -> String {
    let mut message = Vec::with_capacity(domain.len() + 1 + payload.len());
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(payload);
    format!("sha256:{}", sha256_hex(&message))
}

pub(crate) fn hash_digest(value: &str) -> Result<[u8; 32]> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("hash must have sha256: prefix"))?;
    let bytes = hex_decode(digest)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("sha256 hash must decode to 32 bytes"))
}
