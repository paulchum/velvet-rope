use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value, json};
use velvet_core::{
    ArtifactReference, AttestationLevel, DispatchClaim, EXECUTION_CANONICALIZATION,
    EXECUTION_PERMIT_SCHEMA_VERSION, EXECUTION_RECEIPT_SCHEMA_VERSION, ExecutionOutcome,
    ExecutionPermit, ExecutionPermitScope, ExecutionReceipt, PURPOSE_EXECUTION_PERMIT,
    PURPOSE_EXECUTION_RECEIPT, PermitConstraints, PermitLineage, PermitPolicyBinding,
    PermitValidity, ReceiptError, ReceiptExecutor, SubjectBinding, load_canonical_json_v1,
    proof_artifact_hash,
};

use crate::config::ProxyConfig;
use crate::constants::SIGNATURE_SCHEMA_VERSION;
use crate::enforcement::{
    AdmissionOutcome, PermitEpochProvider, WallClockOnlyPermitEpochProvider, call_params,
    canonical_action_hash_for_mcp_request, verify_permit_logical_step,
};
use crate::ledger::{
    OapLedgerRecord, arguments_hash_hex_from_request, canonical_json, hex_decode, now_rfc3339_z,
    policy_hash_hex, request_hash_hex, sha256_hex, value_hash,
};
use crate::permit_store::PermitClaimStore;
use crate::policy_bundle::PolicyBundleProof;

pub(crate) const EXECUTION_METADATA_KEY: &str = "velvet_execution";
pub(crate) const LEGACY_ADMISSION_METADATA_KEY: &str = "velvet_admission";
const DEFAULT_PERMIT_TTL_SECONDS: i64 = 30;
const MAX_PERMIT_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct PreparedExecution {
    pub permit: ExecutionPermit,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct AuthorizedExecution {
    pub prepared: PreparedExecution,
    pub claim: DispatchClaim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct LogicalPermitBinding {
    pub subgoal_id_hash: String,
    pub logical_step: i64,
}

pub(crate) fn is_executable_admission(admission: &AdmissionOutcome) -> bool {
    admission.decision == "execute"
}

pub(crate) fn prepare_execution(
    config: &ProxyConfig,
    bundle_proof: &PolicyBundleProof,
    request: &Value,
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
    claim_store: &PermitClaimStore,
) -> Result<PreparedExecution> {
    prepare_execution_internal(
        config,
        bundle_proof,
        request,
        admission,
        pre_record,
        claim_store,
        None,
    )
}

#[doc(hidden)]
pub fn prepare_execution_with_logical_step(
    config: &ProxyConfig,
    bundle_proof: &PolicyBundleProof,
    request: &Value,
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
    claim_store: &PermitClaimStore,
    logical_binding: LogicalPermitBinding,
) -> Result<PreparedExecution> {
    prepare_execution_internal(
        config,
        bundle_proof,
        request,
        admission,
        pre_record,
        claim_store,
        Some(logical_binding),
    )
}

fn prepare_execution_internal(
    config: &ProxyConfig,
    bundle_proof: &PolicyBundleProof,
    request: &Value,
    admission: &AdmissionOutcome,
    pre_record: &OapLedgerRecord,
    claim_store: &PermitClaimStore,
    logical_binding: Option<LogicalPermitBinding>,
) -> Result<PreparedExecution> {
    if !is_executable_admission(admission) {
        bail!("non-executable admission decision cannot produce an Execution Permit");
    }
    let mut scope = permit_scope(config, bundle_proof, request, admission)?;
    if let Some(binding) = &logical_binding {
        if binding.logical_step < 0 {
            bail!("execution permit logical step cannot be negative");
        }
        if binding.subgoal_id_hash.trim().is_empty() {
            bail!("execution permit logical binding requires subgoal_id_hash");
        }
        scope.subgoal_id_hash = Some(binding.subgoal_id_hash.clone());
    }
    if pre_record.record_hash.is_empty() || pre_record.record_type != "pre_execution_decision" {
        bail!("pre-execution decision record is not durable");
    }
    let issued_at = now_rfc3339_z();
    let expires_at = (Utc::now() + Duration::seconds(DEFAULT_PERMIT_TTL_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let permit_id = permit_id(
        &admission.identity.tenant_id,
        &admission.identity.environment,
        &scope,
        &pre_record.record_hash,
    );
    let decision_hash = admission.oap.signed_decision_digest.clone();
    let mut supporting_artifacts = vec![ArtifactReference {
        artifact_type: "warrant".to_string(),
        artifact_id: admission.warrant.warrant_id.clone(),
        artifact_hash: admission.warrant.warrant_hash.clone(),
    }];
    if let Some(hash) = &pre_record.admission_evidence_hash {
        supporting_artifacts.push(ArtifactReference {
            artifact_type: "admission_evidence".to_string(),
            artifact_id: pre_record
                .admission_evidence
                .as_ref()
                .and_then(|value| value.get("admission_evidence_id"))
                .and_then(Value::as_str)
                .unwrap_or("admission_evidence")
                .to_string(),
            artifact_hash: hash.clone(),
        });
    }
    if let Some(hash) = &admission.oap.max_de_envelope_digest {
        supporting_artifacts.push(ArtifactReference {
            artifact_type: "max_de_certificate_envelope".to_string(),
            artifact_id: admission
                .oap
                .max_de_envelope
                .as_ref()
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("max_de_certificate_envelope")
                .to_string(),
            artifact_hash: hash.clone(),
        });
    }
    if let Some(receipt) = &admission.approval_receipt {
        supporting_artifacts.push(ArtifactReference {
            artifact_type: "approval".to_string(),
            artifact_id: receipt.approval_receipt_id.clone(),
            artifact_hash: receipt.receipt_hash.clone(),
        });
    }
    let mut permit = ExecutionPermit {
        schema_version: EXECUTION_PERMIT_SCHEMA_VERSION.to_string(),
        canonicalization: EXECUTION_CANONICALIZATION.to_string(),
        permit_id: permit_id.clone(),
        issuer: "velvet".to_string(),
        tenant_id: admission.identity.tenant_id.clone(),
        environment: admission.identity.environment.clone(),
        audience: config.upstream.server.clone(),
        subject: SubjectBinding {
            subject_id_hash: pre_record.subject_id_hash.clone(),
            agent_id_hash: pre_record.agent_id_hash.clone(),
            client_id_hash: pre_record.client_id_hash.clone(),
            session_id_hash: pre_record.session_id_hash.clone(),
        },
        scope,
        policy: PermitPolicyBinding {
            policy_hash: policy_hash_hex(bundle_proof),
            policy_version: config.policy.chain.clone(),
        },
        lineage: PermitLineage {
            decision_artifact: ArtifactReference {
                artifact_type: "oap_decision".to_string(),
                artifact_id: pre_record.decision_id.clone(),
                artifact_hash: decision_hash,
            },
            pre_execution_record: ArtifactReference {
                artifact_type: "ledger_record".to_string(),
                artifact_id: pre_record.record_id.clone(),
                artifact_hash: pre_record.record_hash.clone(),
            },
            supporting_artifacts,
        },
        constraints: PermitConstraints::single_dispatch(idempotency_key(
            &permit_id,
            &pre_record.record_hash,
            &request_hash_hex(request),
        )),
        obligations: vec![
            "verify_trusted_signature".to_string(),
            "verify_scope".to_string(),
            "verify_lineage".to_string(),
            "claim_before_dispatch".to_string(),
            "record_execution_receipt".to_string(),
        ],
        validity: PermitValidity {
            issued_at: issued_at.clone(),
            not_before: issued_at,
            expires_at,
            issued_at_logical_step: logical_binding.as_ref().map(|binding| binding.logical_step),
            expires_at_logical_step: logical_binding.as_ref().map(|binding| binding.logical_step),
        },
        permit_hash: String::new(),
        signature: BTreeMap::new(),
    };
    permit.permit_hash = artifact_hash("execution_permit", &serde_json::to_value(&permit)?)?;
    permit.signature = signature_block_for_payload_hash(
        config,
        &permit.permit_hash,
        PURPOSE_EXECUTION_PERMIT,
        &permit.tenant_id,
    )?;
    claim_store.issue(&permit)?;
    Ok(PreparedExecution { permit })
}

pub(crate) fn authorize_execution(
    config: &ProxyConfig,
    prepared: PreparedExecution,
    claim_store: &PermitClaimStore,
    claimant: &str,
) -> Result<AuthorizedExecution> {
    authorize_execution_with_epoch_provider(
        config,
        prepared,
        claim_store,
        claimant,
        &WallClockOnlyPermitEpochProvider,
    )
}

#[doc(hidden)]
pub fn authorize_execution_with_epoch_provider(
    config: &ProxyConfig,
    prepared: PreparedExecution,
    claim_store: &PermitClaimStore,
    claimant: &str,
    epoch_provider: &dyn PermitEpochProvider,
) -> Result<AuthorizedExecution> {
    verify_trusted_execution_permit_with_epoch_provider(config, &prepared.permit, epoch_provider)?;
    let claim = claim_store
        .claim(&prepared.permit, claimant, &now_rfc3339_z())?
        .ok_or_else(|| anyhow!("execution permit is already claimed"))?;
    Ok(AuthorizedExecution { prepared, claim })
}

pub(crate) fn attach_execution_metadata_to_request(
    request: &Value,
    authorized: &AuthorizedExecution,
) -> Result<Value> {
    let mut upstream_request = strip_model_controlled_execution_metadata(request);
    let params = upstream_request
        .as_object_mut()
        .ok_or_else(|| anyhow!("cannot attach execution metadata to non-object request"))?
        .entry("params".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let params = params
        .as_object_mut()
        .ok_or_else(|| anyhow!("cannot attach execution metadata to non-object params"))?;
    let meta = params
        .entry("_meta".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    let meta = meta
        .as_object_mut()
        .ok_or_else(|| anyhow!("cannot attach execution metadata to non-object params._meta"))?;
    meta.insert(
        EXECUTION_METADATA_KEY.to_string(),
        json!({
            "execution_permit": authorized.prepared.permit,
            "permit_id": authorized.prepared.permit.permit_id,
            "permit_hash": authorized.prepared.permit.permit_hash,
            "dispatch_claim_record_hash": authorized.claim.claim_hash,
            "pre_execution_record_hash": authorized.prepared.permit.lineage.pre_execution_record.artifact_hash,
            "dispatch_chain_id": authorized.prepared.permit.constraints.idempotency_key,
        }),
    );
    Ok(upstream_request)
}

pub(crate) fn strip_model_controlled_execution_metadata(request: &Value) -> Value {
    let mut sanitized = request.clone();
    let Some(params) = sanitized.get_mut("params").and_then(Value::as_object_mut) else {
        return sanitized;
    };
    let Some(meta) = params.get_mut("_meta") else {
        return sanitized;
    };
    let Some(meta_object) = meta.as_object_mut() else {
        params.remove("_meta");
        return sanitized;
    };
    meta_object.remove(EXECUTION_METADATA_KEY);
    meta_object.remove(LEGACY_ADMISSION_METADATA_KEY);
    if meta_object.is_empty() {
        params.remove("_meta");
    }
    sanitized
}

#[doc(hidden)]
pub fn verify_outbound_request_matches_permit(
    request: &Value,
    authorized: &AuthorizedExecution,
) -> Result<()> {
    let request = strip_model_controlled_execution_metadata(request);
    let expected = permit_scope_from_permit_request(
        &request,
        &authorized.prepared.permit,
        authorized.prepared.permit.scope.tool_schema_hash.clone(),
    )?;
    if expected != authorized.prepared.permit.scope {
        bail!("outbound request scope no longer matches Execution Permit");
    }
    Ok(())
}

#[doc(hidden)]
pub struct ExecutionReceiptObservation<'a> {
    pub outcome: ExecutionOutcome,
    pub dispatch_attempted: bool,
    pub started_at: &'a str,
    pub upstream_response_hash: Option<String>,
    pub error_code: Option<&'a str>,
    pub error_detail: Option<&'a str>,
}

#[doc(hidden)]
pub fn build_execution_receipt(
    config: &ProxyConfig,
    authorized: &AuthorizedExecution,
    observation: ExecutionReceiptObservation<'_>,
) -> Result<ExecutionReceipt> {
    let completed_at = now_rfc3339_z();
    let error = observation.error_code.map(|code| ReceiptError {
        code: code.to_string(),
        detail_hash: value_hash(&json!({"detail": observation.error_detail.unwrap_or(code)})),
    });
    let mut receipt = ExecutionReceipt {
        schema_version: EXECUTION_RECEIPT_SCHEMA_VERSION.to_string(),
        canonicalization: EXECUTION_CANONICALIZATION.to_string(),
        receipt_id: format!(
            "vreceipt_{}",
            &sha256_hex(
                canonical_json(&json!({
                    "permit_id": authorized.prepared.permit.permit_id,
                    "claim_hash": authorized.claim.claim_hash,
                    "completed_at": completed_at,
                }))
                .as_bytes()
            )[..32]
        ),
        permit_id: authorized.prepared.permit.permit_id.clone(),
        permit_hash: authorized.prepared.permit.permit_hash.clone(),
        dispatch_claim_record_hash: authorized.claim.claim_hash.clone(),
        pre_execution_record_hash: authorized
            .prepared
            .permit
            .lineage
            .pre_execution_record
            .artifact_hash
            .clone(),
        request_hash: authorized.prepared.permit.scope.request_hash.clone(),
        canonical_action_hash: authorized
            .prepared
            .permit
            .scope
            .canonical_action_hash
            .clone(),
        executor: ReceiptExecutor {
            executor_id: "velvet-rope-proxy".to_string(),
            audience: authorized.prepared.permit.audience.clone(),
            attestation_level: AttestationLevel::GatewayObserved,
        },
        outcome: observation.outcome,
        dispatch_attempted: observation.dispatch_attempted,
        upstream_response_hash: observation.upstream_response_hash,
        substrate_receipt_hash: None,
        error,
        started_at: observation.started_at.to_string(),
        completed_at,
        receipt_hash: String::new(),
        signature: BTreeMap::new(),
    };
    receipt.receipt_hash = artifact_hash("execution_receipt", &serde_json::to_value(&receipt)?)?;
    receipt.signature = signature_block_for_payload_hash(
        config,
        &receipt.receipt_hash,
        PURPOSE_EXECUTION_RECEIPT,
        &authorized.prepared.permit.tenant_id,
    )?;
    Ok(receipt)
}

#[doc(hidden)]
pub fn mark_execution_complete(
    claim_store: &PermitClaimStore,
    authorized: &AuthorizedExecution,
    receipt: &ExecutionReceipt,
) -> Result<()> {
    let outcome = match receipt.outcome {
        ExecutionOutcome::Succeeded => "succeeded",
        ExecutionOutcome::FailedBeforeDispatch => "failed_before_dispatch",
        ExecutionOutcome::Rejected => "failed_before_dispatch",
        ExecutionOutcome::Indeterminate => "indeterminate",
    };
    claim_store.complete(
        &authorized.prepared.permit,
        outcome,
        &receipt.receipt_hash,
        &receipt.completed_at,
    )
}

#[doc(hidden)]
pub fn verify_trusted_execution_permit(
    config: &ProxyConfig,
    permit: &ExecutionPermit,
) -> Result<()> {
    verify_trusted_execution_permit_with_epoch_provider(
        config,
        permit,
        &WallClockOnlyPermitEpochProvider,
    )
}

#[doc(hidden)]
pub fn verify_trusted_execution_permit_with_epoch_provider(
    config: &ProxyConfig,
    permit: &ExecutionPermit,
    epoch_provider: &dyn PermitEpochProvider,
) -> Result<()> {
    let expected_hash = artifact_hash("execution_permit", &serde_json::to_value(permit)?)?;
    if expected_hash != permit.permit_hash {
        bail!("execution permit hash mismatch");
    }
    verify_permit_temporal_validity(permit)?;
    verify_permit_logical_step(permit, epoch_provider)?;
    verify_permit_signature(config, permit, &expected_hash)?;
    Ok(())
}

fn verify_permit_temporal_validity(permit: &ExecutionPermit) -> Result<()> {
    let issued_at = chrono::DateTime::parse_from_rfc3339(&permit.validity.issued_at)
        .context("parse permit issued_at")?
        .with_timezone(&Utc);
    let not_before = chrono::DateTime::parse_from_rfc3339(&permit.validity.not_before)
        .context("parse permit not_before")?
        .with_timezone(&Utc);
    let expires_at = chrono::DateTime::parse_from_rfc3339(&permit.validity.expires_at)
        .context("parse permit expires_at")?
        .with_timezone(&Utc);
    if !(issued_at <= not_before && not_before <= expires_at) {
        bail!("execution permit validity interval is malformed");
    }
    if expires_at - not_before > Duration::seconds(MAX_PERMIT_TTL_SECONDS) {
        bail!("execution permit validity interval exceeds configured maximum");
    }
    let now = Utc::now();
    if now < not_before {
        bail!("execution permit is not yet valid");
    }
    if now > expires_at {
        bail!("execution permit expired");
    }
    Ok(())
}

fn verify_permit_signature(
    config: &ProxyConfig,
    permit: &ExecutionPermit,
    payload_hash: &str,
) -> Result<()> {
    let public_key_hex =
        std::env::var(&config.oap.velvet_trusted_public_key_env).with_context(|| {
            format!(
                "required Velvet execution permit trusted public key env var {} is not set",
                config.oap.velvet_trusted_public_key_env
            )
        })?;
    if public_key_hex.trim().is_empty() {
        bail!("Velvet execution permit trusted public key env var is empty");
    }
    let public_key_bytes: [u8; 32] = decode_key_material(&public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("trusted Velvet execution permit public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    let signature = &permit.signature;
    let key_id = signature_str(signature, "key_id")?;
    let key_version = signature_str(signature, "key_version")?;
    let provider_name = signature_str(signature, "provider_name")?;
    let algorithm = signature_str(signature, "algorithm")?;
    let purpose = signature_str(signature, "purpose")?;
    let tenant_id = signature_str(signature, "tenant_id")?;
    let signed_payload_hash = signature_str(signature, "payload_hash")?;
    if signature_str(signature, "schema_version")? != SIGNATURE_SCHEMA_VERSION {
        bail!("execution permit signature schema version mismatch");
    }
    if key_id != config.oap.velvet_kid {
        bail!("execution permit signature key id is not trusted");
    }
    if provider_name != "velvet_ed25519" || algorithm != "Ed25519" {
        bail!("execution permit signature algorithm is not trusted");
    }
    if purpose != PURPOSE_EXECUTION_PERMIT {
        bail!("execution permit signature purpose mismatch");
    }
    if tenant_id != permit.tenant_id {
        bail!("execution permit signature tenant mismatch");
    }
    if signed_payload_hash != payload_hash {
        bail!("execution permit signature payload hash mismatch");
    }
    if let Some(embedded_public_key) = signature
        .get("public_verification_material")
        .and_then(Value::as_object)
        .and_then(|material| material.get("public_key_base64"))
        .and_then(Value::as_str)
    {
        let embedded = BASE64_STANDARD
            .decode(embedded_public_key)
            .context("decode embedded Velvet execution permit public key")?;
        if embedded.as_slice() != public_key_bytes {
            bail!("execution permit embedded public key does not match trusted key");
        }
    }
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(signature_str(signature, "signature")?)
        .context("decode execution permit signature")?
        .try_into()
        .map_err(|_| anyhow!("execution permit signature must be 64 bytes"))?;
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
        .context("verify execution permit signature")
}

fn signature_str<'a>(signature: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str> {
    signature
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("execution permit signature missing {key}"))
}

fn permit_scope(
    config: &ProxyConfig,
    _bundle_proof: &PolicyBundleProof,
    request: &Value,
    admission: &AdmissionOutcome,
) -> Result<ExecutionPermitScope> {
    let (name, _) = call_params(request)?;
    Ok(ExecutionPermitScope {
        surface: config.identity.product_surface.clone(),
        method: "tools/call".to_string(),
        tool_key: admission.inventory_status.tool_key.clone(),
        operation: name,
        request_hash: request_hash_hex(request),
        canonical_action_hash: canonical_action_hash_for_mcp_request(config, request)?,
        arguments_hash: arguments_hash_hex_from_request(request)?,
        tool_schema_hash: admission
            .inventory_status
            .schema_hash
            .clone()
            .unwrap_or_else(|| admission.warrant.tool_schema_hash.clone()),
        read_set_hash: None,
        resource: None,
        subgoal_id_hash: None,
    })
}

fn permit_scope_from_permit_request(
    request: &Value,
    permit: &ExecutionPermit,
    tool_schema_hash: String,
) -> Result<ExecutionPermitScope> {
    let (name, _) = call_params(request)?;
    Ok(ExecutionPermitScope {
        surface: permit.scope.surface.clone(),
        method: permit.scope.method.clone(),
        tool_key: permit.scope.tool_key.clone(),
        operation: name,
        request_hash: request_hash_hex(request),
        canonical_action_hash: permit.scope.canonical_action_hash.clone(),
        arguments_hash: arguments_hash_hex_from_request(request)?,
        tool_schema_hash,
        read_set_hash: permit.scope.read_set_hash.clone(),
        resource: permit.scope.resource.clone(),
        subgoal_id_hash: permit.scope.subgoal_id_hash.clone(),
    })
}

fn permit_id(
    tenant_id: &str,
    environment: &str,
    scope: &ExecutionPermitScope,
    pre_execution_record_hash: &str,
) -> String {
    format!(
        "vpermit_{}",
        &sha256_hex(
            canonical_json(&json!({
                "tenant_id": tenant_id,
                "environment": environment,
                "scope": scope,
                "pre_execution_record_hash": pre_execution_record_hash,
            }))
            .as_bytes()
        )[..32]
    )
}

fn idempotency_key(permit_id: &str, record_hash: &str, request_hash: &str) -> String {
    format!(
        "vdispatch_{}",
        &sha256_hex(
            canonical_json(&json!({
                "permit_id": permit_id,
                "record_hash": record_hash,
                "request_hash": request_hash,
            }))
            .as_bytes()
        )[..32]
    )
}

fn artifact_hash(artifact_type: &str, value: &Value) -> Result<String> {
    let canonical = load_canonical_json_v1(canonical_json(value).as_bytes())
        .map_err(|error| anyhow!(error.to_string()))?;
    proof_artifact_hash(artifact_type, &canonical).map_err(|error| anyhow!(error.to_string()))
}

fn signature_block_for_payload_hash(
    config: &ProxyConfig,
    payload_hash: &str,
    purpose: &str,
    tenant_id: &str,
) -> Result<BTreeMap<String, Value>> {
    let key_id = config.oap.velvet_kid.clone();
    let key_version = "v1";
    let provider_name = "velvet_ed25519";
    let algorithm = "Ed25519";
    let key = signing_key_from_env(&config.oap.velvet_private_key_env)?;
    let message = canonical_json(&json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": provider_name,
        "algorithm": algorithm,
        "key_version": key_version,
        "key_id": &key_id,
        "tenant_id": tenant_id,
        "purpose": purpose,
        "payload_hash": payload_hash,
    }));
    let signature = key.sign(message.as_bytes());
    let public_key_base64 = BASE64_STANDARD.encode(key.verifying_key().as_bytes());
    let value = json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": provider_name,
        "algorithm": algorithm,
        "key_id": &key_id,
        "key_version": key_version,
        "purpose": purpose,
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        "signed_at": now_rfc3339_z(),
        "public_verification_material": {
            "key_id": &key_id,
            "public_key_base64": public_key_base64,
            "encoding": "raw-base64",
            "verification_tier": "configured-public-key-required"
        },
        "metadata": {
            "verification_tier": "durable",
            "issuer_boundary": "velvet-rope-proxy"
        }
    });
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("signature block must be an object"))?;
    Ok(object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn signing_key_from_env(env_name: &str) -> Result<SigningKey> {
    let raw = std::env::var(env_name)
        .with_context(|| format!("required Ed25519 signing key env var {env_name} is not set"))?;
    let bytes = decode_key_material(&raw)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 private key in {env_name} must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn decode_key_material(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw
        .trim()
        .strip_prefix("ed25519:")
        .unwrap_or(raw.trim())
        .strip_prefix("base64:")
        .unwrap_or_else(|| raw.trim().strip_prefix("hex:").unwrap_or(raw.trim()));
    if trimmed.len() == 64 && trimmed.chars().all(|char| char.is_ascii_hexdigit()) {
        return hex_decode(trimmed);
    }
    BASE64_STANDARD
        .decode(trimmed)
        .context("decode Ed25519 private key")
}
