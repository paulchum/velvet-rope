use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use velvet_core::{CertificateEffect, CertificateEvidence, CertificateOutcome};

use crate::{IdentityConfig, ToolApproval, ToolDisposition, canonical_json, sha256_hex};

pub const OAP_SPEC_REPO: &str = "https://github.com/aporthq/aport-spec";
pub const OAP_SPEC_COMMIT: &str = "a706c64b0b7ef4bcff9756a926f9a278e577e8b0";
pub const OAP_SPEC_VERSION: &str = "oap/1.0";
pub const OAP_DECISION_DRAFT_VALIDATION: &str =
    "oap/1.0-draft-schema-conflict-local-structural-validation";
pub const VELVET_MAXDE_ENVELOPE_TYPE: &str = "velvet.maxde.certificate.v1";
pub const VELVET_MAXDE_ENVELOPE_SCHEMA_VERSION: &str = "velvet.maxde.certificate_envelope.v2";
pub const VELVET_OAP_BOUNDARY_STATEMENT: &str = "OAP draft-compatible Decision shape at pinned commit + Velvet-signed Max-DE Certificate Envelope";
const MAXDE_CERTIFICATE_SCALE: u32 = 6;
const MAXDE_CERTIFICATE_SCALE_FACTOR: i128 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OapConfig {
    pub enabled: bool,
    pub passport_id: Option<String>,
    pub owner_id: Option<String>,
    pub owner_type: String,
    pub assurance_level: String,
    pub status: String,
    pub regions: Vec<String>,
    pub passport_version: String,
    pub passport_created_at: Option<String>,
    pub passport_updated_at: Option<String>,
    pub policy_id: String,
    pub decision_ttl_seconds: i64,
    pub oap_kid: String,
    pub oap_private_key_env: String,
    pub velvet_kid: String,
    pub velvet_private_key_env: String,
    pub velvet_trusted_public_key_env: String,
    pub debug_emit_certificate: bool,
    pub require_max_de_certificate: bool,
    pub require_max_de_for_all_tool_calls: bool,
    pub allow_missing_max_de_in_development: bool,
    /// Require a signed Verdict Certificate before admitting irreversible
    /// (destructive or high-risk) tool calls. Strict mode forces this
    /// requirement on regardless of the configured value.
    pub require_verdict_for_irreversible: bool,
    /// Env var holding the trusted Ed25519 public key for Verdict
    /// Certificates. Defaults to the same env var as the Execution Permit
    /// trusted key so single-key deployments work out of the box.
    pub verdict_trusted_public_key_env: String,
    pub transport_context: OapTransportContextConfig,
}

impl Default for OapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            passport_id: None,
            owner_id: None,
            owner_type: "org".to_string(),
            assurance_level: "L2".to_string(),
            status: "active".to_string(),
            regions: vec!["US".to_string()],
            passport_version: "1.0.0".to_string(),
            passport_created_at: None,
            passport_updated_at: None,
            policy_id: "velvet.mcp.call.v1".to_string(),
            decision_ttl_seconds: 300,
            oap_kid: "oap:registry:velvet-local".to_string(),
            oap_private_key_env: "VELVET_OAP_ED25519_PRIVATE_KEY".to_string(),
            velvet_kid: "velvet:maxde:local".to_string(),
            velvet_private_key_env: "VELVET_MAXDE_ED25519_PRIVATE_KEY".to_string(),
            velvet_trusted_public_key_env: "VELVET_MAXDE_ED25519_PUBLIC_KEY".to_string(),
            debug_emit_certificate: false,
            require_max_de_certificate: true,
            require_max_de_for_all_tool_calls: true,
            allow_missing_max_de_in_development: false,
            require_verdict_for_irreversible: false,
            verdict_trusted_public_key_env: "VELVET_MAXDE_ED25519_PUBLIC_KEY".to_string(),
            transport_context: OapTransportContextConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OapTransportContextConfig {
    pub kind: String,
    pub openai_secure_mcp_tunnel: OpenAiSecureMcpTunnelConfig,
}

impl Default for OapTransportContextConfig {
    fn default() -> Self {
        Self {
            kind: "mcp".to_string(),
            openai_secure_mcp_tunnel: OpenAiSecureMcpTunnelConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenAiSecureMcpTunnelConfig {
    pub enabled: bool,
    pub tunnel_id_env: String,
    pub workspace_id_env: String,
    pub connector_subject_env: String,
}

impl Default for OpenAiSecureMcpTunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tunnel_id_env: "VELVET_OPENAI_TUNNEL_ID".to_string(),
            workspace_id_env: "VELVET_OPENAI_WORKSPACE_ID".to_string(),
            connector_subject_env: "VELVET_CONNECTOR_SUBJECT".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaxDeDecision {
    Inspect,
    Lockout,
    Refinement,
}

impl From<CertificateOutcome> for MaxDeDecision {
    fn from(value: CertificateOutcome) -> Self {
        match value {
            CertificateOutcome::Inspect => Self::Inspect,
            CertificateOutcome::Lockout => Self::Lockout,
            CertificateOutcome::Refinement => Self::Refinement,
        }
    }
}

impl MaxDeDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Lockout => "lockout",
            Self::Refinement => "refinement",
        }
    }

    fn to_core(&self) -> CertificateOutcome {
        match self {
            Self::Inspect => CertificateOutcome::Inspect,
            Self::Lockout => CertificateOutcome::Lockout,
            Self::Refinement => CertificateOutcome::Refinement,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MaxDeCertificateConfig {
    #[serde(deserialize_with = "string_or_number")]
    pub v: String,
    #[serde(rename = "lambda", deserialize_with = "string_or_number")]
    pub lambda_value: String,
    #[serde(rename = "L", deserialize_with = "string_or_number")]
    pub delight_scale: String,
    #[serde(deserialize_with = "string_or_number")]
    pub alpha: String,
    #[serde(deserialize_with = "string_or_number")]
    pub beta: String,
    #[serde(rename = "L_cert", deserialize_with = "string_or_number")]
    pub lower_certificate: String,
    #[serde(rename = "U_cert", deserialize_with = "string_or_number")]
    pub upper_certificate: String,
    pub decision: MaxDeDecision,
    pub theorem_ref: String,
    pub maxde_version: String,
}

impl Default for MaxDeCertificateConfig {
    fn default() -> Self {
        Self {
            v: "0.0000".to_string(),
            lambda_value: "0.0000".to_string(),
            delight_scale: "1.0000".to_string(),
            alpha: "1.0000".to_string(),
            beta: "1.0000".to_string(),
            lower_certificate: "0.0000".to_string(),
            upper_certificate: "0.0000".to_string(),
            decision: MaxDeDecision::Inspect,
            theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
            maxde_version: "maxde/1.0".to_string(),
        }
    }
}

impl MaxDeCertificateConfig {
    pub fn to_core_evidence(&self, arm_id: &str) -> Result<CertificateEvidence> {
        let exact = self.exact_decision()?;
        if exact != self.decision {
            bail!(
                "Max-DE config decision {:?} does not match exact numeric certificate {:?}",
                self.decision,
                exact
            );
        }
        let baseline = compat_decimal_to_f64(&self.v, "v")?;
        let lambda = compat_decimal_to_f64(&self.lambda_value, "lambda")?;
        let delight_scale = compat_decimal_to_f64(&self.delight_scale, "L")?;
        let lower_certificate = compat_decimal_to_f64(&self.lower_certificate, "L_cert")?;
        let upper_certificate = compat_decimal_to_f64(&self.upper_certificate, "U_cert")?;
        if delight_scale <= 0.0 {
            bail!("Max-DE delight scale must be positive");
        }
        let threshold = lambda / delight_scale;
        let safe_upper_bound =
            certificate_effect_safe_upper_bound(lower_certificate, upper_certificate);
        let evidence = CertificateEvidence {
            schema_version: "velvet.certificate_evidence.v2".to_string(),
            family: "beta_bernoulli".to_string(),
            arm_id: arm_id.to_string(),
            baseline,
            lookback_horizon: 1,
            delight_scale,
            liability_price: lambda,
            threshold,
            inspection_lower_bound: lower_certificate,
            safe_upper_bound,
            outcome: self.decision.to_core(),
            liability_mode: "posterior_certificate".to_string(),
            typed_effect: CertificateEffect {
                max_payoff: upper_certificate,
                mean_bound: lower_certificate,
                variance_bound: Some(1.0),
                second_moment_bound: None,
                resource_scope: "posterior_option".to_string(),
                write_footprint: Vec::new(),
                declared_write_set_hash: None,
                dependence_group: None,
                correlation_bound: None,
                covariance_reserve_gamma: None,
                dependence_kind: "unspecified".to_string(),
                filtration_hash: "oap:maxde-config".to_string(),
                filtration_index: 0,
                adapted: true,
                adaptation_marker: Some("oap_maxde_config".to_string()),
                write_conflict_policy: "exclusive".to_string(),
                commutativity_certificate_hash: None,
                continuation_condition_hash: None,
            },
            compensator_step: None,
            theorem_refs: vec![self.theorem_ref.clone()],
            reserve_price: None,
            value_numeraire: None,
            upside_value_scale: None,
        };
        Ok(evidence)
    }

    pub fn exact_decision(&self) -> Result<MaxDeDecision> {
        exact_decision_from_decimal_strings(
            &self.delight_scale,
            &self.lambda_value,
            &self.lower_certificate,
            &self.upper_certificate,
        )
    }

    pub fn certified_lockout(&self) -> Result<bool> {
        Ok(self.exact_decision()? == MaxDeDecision::Lockout)
    }

    pub fn certified_inspect(&self) -> Result<bool> {
        Ok(self.exact_decision()? == MaxDeDecision::Inspect)
    }
}

fn certificate_effect_safe_upper_bound(mean_bound: f64, max_payoff: f64) -> f64 {
    if mean_bound == 0.0 {
        return 0.0;
    }
    let log_envelope = mean_bound * (1.0 + (max_payoff / mean_bound).ln());
    let l2_envelope = mean_bound + 2.0;
    max_payoff.min(log_envelope).min(l2_envelope).max(0.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OapArtifacts {
    pub passport: Value,
    pub passport_digest: String,
    pub decision: Value,
    pub decision_payload_digest: String,
    pub signed_decision_digest: String,
    pub decision_signature_hash: String,
    pub decision_digest: String,
    pub max_de_envelope: Option<Value>,
    pub max_de_envelope_digest: Option<String>,
    pub validation: String,
    pub performance: OapPerformance,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OapPerformance {
    pub passport_digest_us: u128,
    pub decision_build_us: u128,
    pub oap_signature_us: u128,
    pub envelope_signature_us: Option<u128>,
}

#[derive(Debug, Clone)]
pub struct OapDecisionInput<'a> {
    pub identity: &'a IdentityConfig,
    pub tools: &'a [ToolApproval],
    pub allow: bool,
    pub reasons: Vec<OapReason>,
    pub max_de_config: Option<&'a MaxDeCertificateConfig>,
    pub max_de_evidence: Option<&'a CertificateEvidence>,
    pub action_context: Option<OapActionContext<'a>>,
}

#[derive(Debug, Clone)]
pub struct OapActionContext<'a> {
    pub request: &'a Value,
    pub policy_hash: &'a str,
    pub policy_version: &'a str,
    pub tool_key: &'a str,
    pub tool_name: &'a str,
    pub tool_schema_hash: &'a str,
    pub arguments_hash: &'a str,
    pub request_hash: &'a str,
    pub canonical_action_hash: &'a str,
    pub mcp_method: &'a str,
    pub max_de_certificate_required: bool,
    pub max_de_requirement_reason: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OapReason {
    pub code: String,
    pub message: String,
}

impl OapReason {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub fn build_oap_artifacts(
    config: &OapConfig,
    input: OapDecisionInput<'_>,
) -> Result<OapArtifacts> {
    if !config.enabled {
        bail!("OAP emission is disabled");
    }
    validate_oap_config(config)?;
    let passport_started = std::time::Instant::now();
    let passport = build_passport(config, input.identity, input.tools)?;
    validate_passport_structural(&passport)?;
    let passport_digest = passport_digest(&passport)?;
    let passport_digest_us = passport_started.elapsed().as_micros();

    let decision_started = std::time::Instant::now();
    let mut performance = OapPerformance {
        passport_digest_us,
        ..OapPerformance::default()
    };
    let signing_material = SigningMaterial::from_env(&config.oap_private_key_env, &config.oap_kid)?;
    let mut decision = build_unsigned_decision(
        config,
        input.identity,
        &passport,
        &passport_digest,
        input.allow,
        input.reasons,
    )?;
    validate_decision_structural(&decision)?;
    performance.decision_build_us = decision_started.elapsed().as_micros();
    let signing_started = std::time::Instant::now();
    sign_object(&mut decision, &signing_material)?;
    performance.oap_signature_us = signing_started.elapsed().as_micros();
    verify_signed_object(&decision, &signing_material.verifying_key())?;
    let decision_payload_digest = decision_payload_digest(&decision)?;
    let signed_decision_digest = signed_decision_digest(&decision)?;
    let decision_signature_hash = decision_signature_hash(&decision)?;
    let decision_digest = signed_decision_digest.clone();

    let (max_de_envelope, max_de_envelope_digest) =
        if let (Some(max_de_config), Some(max_de_evidence)) =
            (input.max_de_config, input.max_de_evidence)
        {
            let action_context = input
                .action_context
                .as_ref()
                .ok_or_else(|| anyhow!("Max-DE envelope requires action binding context"))?;
            if MaxDeDecision::from(max_de_evidence.outcome) != max_de_config.exact_decision()? {
                bail!("Max-DE route evidence does not match exact certificate arithmetic");
            }
            let envelope_started = std::time::Instant::now();
            let velvet_material =
                SigningMaterial::from_env(&config.velvet_private_key_env, &config.velvet_kid)?;
            let mut envelope = build_unsigned_maxde_envelope(
                config,
                input.identity,
                action_context,
                &passport,
                &decision,
                &decision_payload_digest,
                &signed_decision_digest,
                &decision_signature_hash,
                &passport_digest,
                max_de_config,
            )?;
            sign_object(&mut envelope, &velvet_material)?;
            verify_signed_object(&envelope, &velvet_material.verifying_key())?;
            verify_maxde_exact_arithmetic(&envelope)?;
            verify_envelope_binding_against_context(
                &envelope,
                &decision,
                action_context.request,
                input.identity,
                action_context,
            )?;
            performance.envelope_signature_us = Some(envelope_started.elapsed().as_micros());
            let digest = digest_value(&envelope)?;
            (Some(envelope), Some(digest))
        } else {
            (None, None)
        };

    Ok(OapArtifacts {
        passport,
        passport_digest,
        decision,
        decision_payload_digest,
        signed_decision_digest,
        decision_signature_hash,
        decision_digest,
        max_de_envelope,
        max_de_envelope_digest,
        validation: OAP_DECISION_DRAFT_VALIDATION.to_string(),
        performance,
    })
}

pub fn digest_value(value: &Value) -> Result<String> {
    Ok(format!("sha256:{}", sha256_hex(&canonical_bytes(value)?)))
}

pub fn passport_digest(passport: &Value) -> Result<String> {
    digest_value(passport)
}

pub fn decision_payload_digest(decision: &Value) -> Result<String> {
    let mut payload = decision.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| anyhow!("OAP Decision must be an object"))?
        .remove("signature");
    digest_value(&payload)
}

pub fn signed_decision_digest(decision: &Value) -> Result<String> {
    digest_value(decision)
}

pub fn decision_signature_hash(decision: &Value) -> Result<String> {
    let signature = raw_signature_bytes(decision)?;
    Ok(format!("sha256:{}", sha256_hex(&signature)))
}

pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    ensure_oap_json_value(value, "$")?;
    let first = canonical_json(value);
    let reparsed: Value = serde_json::from_str(&first)?;
    let second = canonical_json(&reparsed);
    if first.as_bytes() != second.as_bytes() {
        bail!("JCS canonicalization is nondeterministic");
    }
    Ok(first.into_bytes())
}

pub fn verify_oap_decision_signature(decision: &Value, verifying_key: &VerifyingKey) -> Result<()> {
    verify_signed_object(decision, verifying_key)
}

pub fn verify_maxde_certificate_envelope(
    envelope: &Value,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    verify_signed_object(envelope, verifying_key)?;
    verify_maxde_exact_arithmetic(envelope)?;
    let expires_at = envelope
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope missing expires_at"))?;
    if parse_oap_time(expires_at)? <= Utc::now() {
        bail!("Max-DE envelope expired at {expires_at}");
    }
    Ok(())
}

pub fn verify_envelope_binding(envelope: &Value, decision: &Value) -> Result<()> {
    if envelope.get("binding").is_some() {
        let binding = envelope_binding(envelope)?;
        let envelope_decision_id = binding
            .get("oap_decision_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Max-DE envelope missing binding.oap_decision_id"))?;
        let actual_decision_id = decision
            .get("decision_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("OAP Decision missing decision_id"))?;
        if envelope_decision_id != actual_decision_id {
            bail!("Max-DE envelope decision_id does not match OAP Decision");
        }
        require_binding_digest(
            binding,
            "decision_payload_digest",
            &decision_payload_digest(decision)?,
        )?;
        require_binding_digest(
            binding,
            "signed_decision_digest",
            &signed_decision_digest(decision)?,
        )?;
        require_binding_digest(
            binding,
            "decision_signature_hash",
            &decision_signature_hash(decision)?,
        )?;
        let expected_passport_digest = decision
            .get("passport_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("OAP Decision missing passport_digest"))?;
        require_binding_digest(binding, "passport_digest", expected_passport_digest)?;
        return Ok(());
    }

    let envelope_decision_digest = envelope
        .get("oap_decision_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope missing oap_decision_digest"))?;
    let actual = digest_value(decision)?;
    if envelope_decision_digest != actual {
        bail!("Max-DE envelope is not bound to this OAP Decision");
    }
    let envelope_decision_id = envelope
        .get("oap_decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope missing oap_decision_id"))?;
    let actual_decision_id = decision
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing decision_id"))?;
    if envelope_decision_id != actual_decision_id {
        bail!("Max-DE envelope decision_id does not match OAP Decision");
    }
    Ok(())
}

pub fn verify_envelope_binding_against_context(
    envelope: &Value,
    decision: &Value,
    request: &Value,
    identity: &IdentityConfig,
    context: &OapActionContext<'_>,
) -> Result<()> {
    verify_envelope_binding(envelope, decision)?;
    let binding = envelope_binding(envelope)?;
    require_binding_str(binding, "oap_spec_repo", OAP_SPEC_REPO)?;
    require_binding_str(binding, "oap_spec_commit", OAP_SPEC_COMMIT)?;
    require_binding_str(binding, "policy_id", decision_policy_id(decision)?)?;
    require_binding_str(binding, "policy_hash", context.policy_hash)?;
    require_binding_str(binding, "policy_version", context.policy_version)?;
    require_binding_str(
        binding,
        "tenant_id_hash",
        &hash_identifier(&identity.tenant_id),
    )?;
    let owner_id = decision
        .get("owner_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing owner_id"))?;
    require_binding_str(binding, "owner_id_hash", &hash_identifier(owner_id))?;
    require_binding_str(
        binding,
        "subject_id_hash",
        &hash_optional_identifier(identity.subject_id.as_deref()),
    )?;
    require_binding_str(
        binding,
        "agent_id_hash",
        &hash_optional_identifier(identity.agent_id.as_deref()),
    )?;
    require_binding_str(
        binding,
        "client_id_hash",
        &hash_optional_identifier(identity.client_id.as_deref()),
    )?;
    require_binding_str(
        binding,
        "session_id_hash",
        &hash_optional_identifier(identity.session_id.as_deref()),
    )?;
    require_binding_str(binding, "product_surface", &identity.product_surface)?;
    require_binding_str(binding, "environment", &identity.environment)?;
    require_binding_str(binding, "mcp_method", context.mcp_method)?;
    require_binding_str(binding, "tool_key", context.tool_key)?;
    require_binding_str(binding, "tool_name", context.tool_name)?;
    require_binding_digest(binding, "tool_schema_hash", context.tool_schema_hash)?;
    require_binding_digest(binding, "arguments_hash", context.arguments_hash)?;
    require_binding_digest(binding, "request_hash", context.request_hash)?;
    require_binding_str(
        binding,
        "canonical_action_hash",
        context.canonical_action_hash,
    )?;
    if context.request_hash != digest_redaction_safe_request(request)? {
        bail!("action context request_hash does not match request");
    }
    Ok(())
}

pub fn verify_required_envelope(record: &Value) -> Result<()> {
    let requires = record
        .get("max_de_certificate_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if requires
        && record
            .get("max_de_certificate_envelope")
            .is_none_or(Value::is_null)
    {
        bail!("pre-execution record requires a Max-DE envelope but none is present");
    }
    Ok(())
}

pub fn validate_decision_structural(decision: &Value) -> Result<()> {
    let object = decision
        .as_object()
        .ok_or_else(|| anyhow!("OAP Decision must be an object"))?;
    for field in [
        "decision_id",
        "passport_id",
        "policy_id",
        "owner_id",
        "assurance_level",
        "allow",
        "reasons",
        "issued_at",
        "expires_at",
        "passport_digest",
        "kid",
    ] {
        if !object.contains_key(field) {
            bail!("OAP Decision missing required field {field}");
        }
    }
    if !is_uuid_string(object.get("decision_id")) {
        bail!("OAP Decision decision_id must be a UUID");
    }
    if !is_uuid_string(object.get("passport_id")) {
        bail!("OAP Decision passport_id must be a UUID");
    }
    if !object
        .get("policy_id")
        .and_then(Value::as_str)
        .is_some_and(valid_policy_id)
    {
        bail!("OAP Decision policy_id is invalid");
    }
    if !matches!(
        object.get("assurance_level").and_then(Value::as_str),
        Some("L0" | "L1" | "L2" | "L3" | "L4KYC" | "L4FIN")
    ) {
        bail!("OAP Decision assurance_level is invalid");
    }
    if !object.get("allow").is_some_and(Value::is_boolean) {
        bail!("OAP Decision allow must be boolean");
    }
    let reasons = object
        .get("reasons")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("OAP Decision reasons must be an array"))?;
    if reasons.is_empty() {
        bail!("OAP Decision reasons must contain at least one reason");
    }
    for reason in reasons {
        let reason = reason
            .as_object()
            .ok_or_else(|| anyhow!("OAP Decision reason must be an object"))?;
        if !reason.get("code").is_some_and(Value::is_string) {
            bail!("OAP Decision reason code is required");
        }
    }
    if !object
        .get("passport_digest")
        .and_then(Value::as_str)
        .is_some_and(valid_sha256_digest)
    {
        bail!("OAP Decision passport_digest must be sha256:<hex>");
    }
    if let Some(signature) = object.get("signature")
        && !signature.is_null()
        && !signature
            .as_str()
            .is_some_and(|value| value.starts_with("ed25519:"))
    {
        bail!("OAP Decision signature must be ed25519:<base64>");
    }
    if !object
        .get("kid")
        .and_then(Value::as_str)
        .is_some_and(valid_oap_kid)
    {
        bail!("OAP Decision kid is invalid");
    }
    for forbidden in ["certificate", "max_de", "velvet", "ext", "x-velvet"] {
        if object.contains_key(forbidden) {
            bail!("OAP Decision contains forbidden Velvet extension field {forbidden}");
        }
    }
    Ok(())
}

pub fn validate_passport_structural(passport: &Value) -> Result<()> {
    let object = passport
        .as_object()
        .ok_or_else(|| anyhow!("OAP Passport must be an object"))?;
    for field in [
        "passport_id",
        "kind",
        "spec_version",
        "owner_id",
        "owner_type",
        "status",
        "assurance_level",
        "capabilities",
        "limits",
        "regions",
        "created_at",
        "updated_at",
        "version",
    ] {
        if !object.contains_key(field) {
            bail!("OAP Passport missing required field {field}");
        }
    }
    if !is_uuid_string(object.get("passport_id")) {
        bail!("OAP Passport passport_id must be a UUID");
    }
    if object.get("spec_version").and_then(Value::as_str) != Some(OAP_SPEC_VERSION) {
        bail!("OAP Passport spec_version must be oap/1.0");
    }
    if !matches!(
        object.get("kind").and_then(Value::as_str),
        Some("template" | "instance")
    ) {
        bail!("OAP Passport kind is invalid");
    }
    if !matches!(
        object.get("owner_type").and_then(Value::as_str),
        Some("org" | "user")
    ) {
        bail!("OAP Passport owner_type is invalid");
    }
    if !matches!(
        object.get("status").and_then(Value::as_str),
        Some("draft" | "active" | "suspended" | "revoked")
    ) {
        bail!("OAP Passport status is invalid");
    }
    if !matches!(
        object.get("assurance_level").and_then(Value::as_str),
        Some("L0" | "L1" | "L2" | "L3" | "L4KYC" | "L4FIN")
    ) {
        bail!("OAP Passport assurance_level is invalid");
    }
    Ok(())
}

fn build_passport(
    config: &OapConfig,
    identity: &IdentityConfig,
    tools: &[ToolApproval],
) -> Result<Value> {
    let now = Utc::now().to_rfc3339();
    let owner_id = config
        .owner_id
        .clone()
        .unwrap_or_else(|| identity.tenant_id.clone());
    let passport_id = config.passport_id.clone().unwrap_or_else(|| {
        derived_uuid(&format!(
            "passport:{}:{}:{}",
            identity.tenant_id,
            identity.environment,
            identity.agent_id.as_deref().unwrap_or("velvet-agent")
        ))
    });
    let capabilities = tools
        .iter()
        .filter(|tool| tool.disposition == ToolDisposition::Approved)
        .map(|tool| {
            json!({
                "id": capability_id(tool),
                "params": {
                    "mcp_server": tool.server,
                    "mcp_tool": tool.name,
                    "risk_class": tool.risk_class.as_str(),
                    "destructive": tool.destructive
                }
            })
        })
        .collect::<Vec<_>>();
    let mut limits = Map::new();
    for tool in tools
        .iter()
        .filter(|tool| tool.disposition == ToolDisposition::Approved)
    {
        limits.insert(
            capability_id(tool),
            json!({
                "mcp_tool_key": tool.key(),
                "approval_tier": tool.approval_tier.as_str(),
                "allowed_environments": tool.allowed_environments,
                "max_arguments_bytes": "configured_by_proxy"
            }),
        );
    }
    Ok(json!({
        "passport_id": passport_id,
        "kind": "instance",
        "spec_version": OAP_SPEC_VERSION,
        "owner_id": owner_id,
        "owner_type": config.owner_type,
        "status": config.status,
        "assurance_level": config.assurance_level,
        "capabilities": capabilities,
        "limits": Value::Object(limits),
        "regions": config.regions,
        "metadata": {
            "agent_id": identity.agent_id,
            "subject_id": identity.subject_id,
            "client_id": identity.client_id,
            "environment": identity.environment,
            "product_surface": identity.product_surface,
            "oap_spec_repo": OAP_SPEC_REPO,
            "oap_spec_commit": OAP_SPEC_COMMIT
        },
        "created_at": config.passport_created_at.clone().unwrap_or_else(|| now.clone()),
        "updated_at": config.passport_updated_at.clone().unwrap_or(now),
        "version": config.passport_version
    }))
}

fn build_unsigned_decision(
    config: &OapConfig,
    identity: &IdentityConfig,
    passport: &Value,
    passport_digest: &str,
    allow: bool,
    reasons: Vec<OapReason>,
) -> Result<Value> {
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(config.decision_ttl_seconds);
    let owner_id = passport
        .get("owner_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Passport missing owner_id"))?;
    let passport_id = passport
        .get("passport_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Passport missing passport_id"))?;
    let agent_id = derived_uuid(&format!(
        "agent:{}:{}:{}",
        identity.tenant_id,
        identity.environment,
        identity.agent_id.as_deref().unwrap_or(passport_id)
    ));
    Ok(json!({
        "decision_id": Uuid::new_v4().to_string(),
        "passport_id": passport_id,
        "agent_id": agent_id,
        "policy_id": config.policy_id,
        "owner_id": owner_id,
        "assurance_level": config.assurance_level,
        "allow": allow,
        "reasons": reasons,
        "issued_at": issued_at.to_rfc3339(),
        "expires_at": expires_at.to_rfc3339(),
        "created_at": issued_at.to_rfc3339(),
        "expires_in": config.decision_ttl_seconds,
        "passport_digest": passport_digest,
        "signature": Value::Null,
        "kid": config.oap_kid
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_unsigned_maxde_envelope(
    config: &OapConfig,
    identity: &IdentityConfig,
    action_context: &OapActionContext<'_>,
    passport: &Value,
    decision: &Value,
    decision_payload_digest: &str,
    signed_decision_digest: &str,
    decision_signature_hash: &str,
    passport_digest: &str,
    max_de_config: &MaxDeCertificateConfig,
) -> Result<Value> {
    let decision_id = decision
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing decision_id"))?;
    let policy_id = decision_policy_id(decision)?;
    let decision_expires_at = decision
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing expires_at"))?;
    let owner_id = passport
        .get("owner_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Passport missing owner_id"))?;
    let exact_decision = max_de_config.exact_decision()?;
    Ok(json!({
        "type": VELVET_MAXDE_ENVELOPE_TYPE,
        "schema_version": VELVET_MAXDE_ENVELOPE_SCHEMA_VERSION,
        "envelope_id": format!("maxde_{}", Uuid::new_v4().simple()),
        "issued_at": Utc::now().to_rfc3339(),
        "expires_at": decision_expires_at,
        "kid": config.velvet_kid,
        "binding": {
            "oap_spec_repo": OAP_SPEC_REPO,
            "oap_spec_commit": OAP_SPEC_COMMIT,
            "oap_decision_id": decision_id,
            "decision_payload_digest": decision_payload_digest,
            "signed_decision_digest": signed_decision_digest,
            "decision_signature_hash": decision_signature_hash,
            "passport_digest": passport_digest,
            "policy_id": policy_id,
            "policy_hash": action_context.policy_hash,
            "policy_version": action_context.policy_version,
            "tenant_id_hash": hash_identifier(&identity.tenant_id),
            "owner_id_hash": hash_identifier(owner_id),
            "subject_id_hash": hash_optional_identifier(identity.subject_id.as_deref()),
            "agent_id_hash": hash_optional_identifier(identity.agent_id.as_deref()),
            "client_id_hash": hash_optional_identifier(identity.client_id.as_deref()),
            "session_id_hash": hash_optional_identifier(identity.session_id.as_deref()),
            "product_surface": identity.product_surface,
            "environment": identity.environment,
            "mcp_method": action_context.mcp_method,
            "tool_key": action_context.tool_key,
            "tool_name": action_context.tool_name,
            "tool_schema_hash": action_context.tool_schema_hash,
            "arguments_hash": action_context.arguments_hash,
            "request_hash": action_context.request_hash,
            "canonical_action_hash": action_context.canonical_action_hash,
            "transport": transport_binding(config),
            "max_de_certificate_required": action_context.max_de_certificate_required,
            "max_de_requirement_reason": action_context.max_de_requirement_reason
        },
        "certificate": {
            "v": certificate_decimal_json(&max_de_config.v, "v")?,
            "lambda": certificate_decimal_json(&max_de_config.lambda_value, "lambda")?,
            "L": certificate_decimal_json(&max_de_config.delight_scale, "L")?,
            "alpha": certificate_decimal_json(&max_de_config.alpha, "alpha")?,
            "beta": certificate_decimal_json(&max_de_config.beta, "beta")?,
            "L_cert": certificate_decimal_json(&max_de_config.lower_certificate, "L_cert")?,
            "U_cert": certificate_decimal_json(&max_de_config.upper_certificate, "U_cert")?,
            "decision": exact_decision.as_str(),
            "certified_lockout": exact_decision == MaxDeDecision::Lockout,
            "certified_inspect": exact_decision == MaxDeDecision::Inspect,
            "theorem_ref": max_de_config.theorem_ref,
            "maxde_version": max_de_config.maxde_version
        },
        "signature": Value::Null
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedDecimal {
    units: i128,
    scale: u32,
}

pub fn parse_fixed_decimal(input: &str, field: &str) -> Result<FixedDecimal> {
    parse_fixed_decimal_with_scale(input, field, None)
}

fn parse_fixed_decimal_with_scale(
    input: &str,
    field: &str,
    exact_scale: Option<u32>,
) -> Result<FixedDecimal> {
    let value = input.trim();
    if value.is_empty() {
        bail!("Max-DE {field} must not be empty");
    }
    if value.starts_with('-') || value.starts_with('+') {
        bail!("Max-DE {field} must be an unsigned decimal string");
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains('e') || lower == "nan" || lower == "inf" || lower == "infinity" {
        bail!("Max-DE {field} must not use exponent, NaN, or infinity syntax");
    }
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() {
        bail!("Max-DE {field} has multiple decimal points");
    }
    if integer.is_empty() || !integer.chars().all(|char| char.is_ascii_digit()) {
        bail!("Max-DE {field} must have decimal digits before the decimal point");
    }
    let fraction = fraction.unwrap_or("");
    if !fraction.chars().all(|char| char.is_ascii_digit()) {
        bail!("Max-DE {field} fractional part must contain only digits");
    }
    if let Some(scale) = exact_scale
        && fraction.len() != scale as usize
    {
        bail!("Max-DE {field} must use exactly {scale} fractional digits");
    }
    if fraction.len() > MAXDE_CERTIFICATE_SCALE as usize {
        bail!(
            "Max-DE {field} scale {} exceeds supported scale {}",
            fraction.len(),
            MAXDE_CERTIFICATE_SCALE
        );
    }
    if integer.trim_start_matches('0').len() > 30 {
        bail!("Max-DE {field} magnitude is too large");
    }
    let mut digits = integer.to_string();
    digits.push_str(fraction);
    for _ in fraction.len()..MAXDE_CERTIFICATE_SCALE as usize {
        digits.push('0');
    }
    let units = digits
        .parse::<i128>()
        .with_context(|| format!("Max-DE {field} magnitude is invalid"))?;
    Ok(FixedDecimal {
        units,
        scale: MAXDE_CERTIFICATE_SCALE,
    })
}

fn certificate_decimal_json(input: &str, field: &str) -> Result<Value> {
    let fixed = parse_fixed_decimal(input, field)?;
    Ok(json!({
        "value": fixed.to_canonical_string(),
        "scale": fixed.scale,
    }))
}

fn certificate_decimal_from_value(value: &Value, field: &str) -> Result<FixedDecimal> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Max-DE certificate {field} must be an object"))?;
    let raw = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE certificate {field}.value must be a string"))?;
    let scale = object
        .get("scale")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Max-DE certificate {field}.scale must be an integer"))?;
    if scale != MAXDE_CERTIFICATE_SCALE as u64 {
        bail!(
            "Max-DE certificate {field}.scale must be {}",
            MAXDE_CERTIFICATE_SCALE
        );
    }
    parse_fixed_decimal_with_scale(raw, field, Some(MAXDE_CERTIFICATE_SCALE))
}

impl FixedDecimal {
    fn to_canonical_string(&self) -> String {
        let factor = MAXDE_CERTIFICATE_SCALE_FACTOR;
        let integer = self.units / factor;
        let fraction = self.units % factor;
        format!(
            "{integer}.{:0width$}",
            fraction,
            width = MAXDE_CERTIFICATE_SCALE as usize
        )
    }
}

pub fn multiply_compare_less(a: &FixedDecimal, b: &FixedDecimal, c: &FixedDecimal) -> Result<bool> {
    compare_scaled_product(a, b, c).map(|ordering| ordering == std::cmp::Ordering::Less)
}

pub fn multiply_compare_greater_equal(
    a: &FixedDecimal,
    b: &FixedDecimal,
    c: &FixedDecimal,
) -> Result<bool> {
    compare_scaled_product(a, b, c).map(|ordering| {
        matches!(
            ordering,
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal
        )
    })
}

fn compare_scaled_product(
    a: &FixedDecimal,
    b: &FixedDecimal,
    c: &FixedDecimal,
) -> Result<std::cmp::Ordering> {
    if a.scale != MAXDE_CERTIFICATE_SCALE
        || b.scale != MAXDE_CERTIFICATE_SCALE
        || c.scale != MAXDE_CERTIFICATE_SCALE
    {
        bail!("Max-DE fixed decimals must use scale {MAXDE_CERTIFICATE_SCALE}");
    }
    let left = a
        .units
        .checked_mul(b.units)
        .ok_or_else(|| anyhow!("Max-DE multiplication overflow"))?;
    let right = c
        .units
        .checked_mul(MAXDE_CERTIFICATE_SCALE_FACTOR)
        .ok_or_else(|| anyhow!("Max-DE scale multiplication overflow"))?;
    Ok(left.cmp(&right))
}

fn exact_decision_from_decimal_strings(
    delight_scale: &str,
    lambda: &str,
    lower_certificate: &str,
    upper_certificate: &str,
) -> Result<MaxDeDecision> {
    let delight_scale = parse_fixed_decimal(delight_scale, "L")?;
    let lambda = parse_fixed_decimal(lambda, "lambda")?;
    let lower_certificate = parse_fixed_decimal(lower_certificate, "L_cert")?;
    let upper_certificate = parse_fixed_decimal(upper_certificate, "U_cert")?;
    exact_decision_from_fixed_values(
        &delight_scale,
        &lambda,
        &lower_certificate,
        &upper_certificate,
    )
}

fn exact_decision_from_fixed_values(
    delight_scale: &FixedDecimal,
    lambda: &FixedDecimal,
    lower_certificate: &FixedDecimal,
    upper_certificate: &FixedDecimal,
) -> Result<MaxDeDecision> {
    if multiply_compare_greater_equal(delight_scale, lower_certificate, lambda)? {
        Ok(MaxDeDecision::Inspect)
    } else if multiply_compare_less(delight_scale, upper_certificate, lambda)? {
        Ok(MaxDeDecision::Lockout)
    } else {
        Ok(MaxDeDecision::Refinement)
    }
}

pub fn verify_maxde_exact_arithmetic(envelope: &Value) -> Result<()> {
    if envelope.get("type").and_then(Value::as_str) != Some(VELVET_MAXDE_ENVELOPE_TYPE) {
        bail!("Max-DE envelope type is invalid");
    }
    if envelope.get("schema_version").and_then(Value::as_str)
        != Some(VELVET_MAXDE_ENVELOPE_SCHEMA_VERSION)
    {
        bail!("Max-DE envelope schema_version is invalid");
    }
    let certificate = envelope
        .get("certificate")
        .ok_or_else(|| anyhow!("Max-DE envelope missing certificate"))?;
    let _v = certificate_decimal_from_value(
        certificate
            .get("v")
            .ok_or_else(|| anyhow!("Max-DE certificate missing v"))?,
        "v",
    )?;
    let lambda = certificate_decimal_from_value(
        certificate
            .get("lambda")
            .ok_or_else(|| anyhow!("Max-DE certificate missing lambda"))?,
        "lambda",
    )?;
    let delight_scale = certificate_decimal_from_value(
        certificate
            .get("L")
            .ok_or_else(|| anyhow!("Max-DE certificate missing L"))?,
        "L",
    )?;
    let _alpha = certificate_decimal_from_value(
        certificate
            .get("alpha")
            .ok_or_else(|| anyhow!("Max-DE certificate missing alpha"))?,
        "alpha",
    )?;
    let _beta = certificate_decimal_from_value(
        certificate
            .get("beta")
            .ok_or_else(|| anyhow!("Max-DE certificate missing beta"))?,
        "beta",
    )?;
    let lower_certificate = certificate_decimal_from_value(
        certificate
            .get("L_cert")
            .ok_or_else(|| anyhow!("Max-DE certificate missing L_cert"))?,
        "L_cert",
    )?;
    let upper_certificate = certificate_decimal_from_value(
        certificate
            .get("U_cert")
            .ok_or_else(|| anyhow!("Max-DE certificate missing U_cert"))?,
        "U_cert",
    )?;
    let certified_inspect =
        multiply_compare_greater_equal(&delight_scale, &lower_certificate, &lambda)?;
    let certified_lockout = multiply_compare_less(&delight_scale, &upper_certificate, &lambda)?;
    let emitted_inspect = certificate
        .get("certified_inspect")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("Max-DE certificate missing certified_inspect"))?;
    let emitted_lockout = certificate
        .get("certified_lockout")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("Max-DE certificate missing certified_lockout"))?;
    if emitted_inspect != certified_inspect {
        bail!("Max-DE certified_inspect does not match exact arithmetic");
    }
    if emitted_lockout != certified_lockout {
        bail!("Max-DE certified_lockout does not match exact arithmetic");
    }
    let expected_decision = exact_decision_from_fixed_values(
        &delight_scale,
        &lambda,
        &lower_certificate,
        &upper_certificate,
    )?;
    let emitted_decision = certificate
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE certificate missing decision"))?;
    if emitted_decision != expected_decision.as_str() {
        bail!("Max-DE certificate decision does not match exact arithmetic");
    }
    Ok(())
}

fn sign_object(value: &mut Value, material: &SigningMaterial) -> Result<()> {
    let mut payload = value.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| anyhow!("signed payload must be an object"))?
        .remove("signature");
    let canonical = canonical_bytes(&payload)?;
    let signature = material.signing_key.sign(&canonical);
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("signed payload must be an object"))?
        .insert(
            "signature".to_string(),
            Value::String(format!(
                "ed25519:{}",
                BASE64_STANDARD.encode(signature.to_bytes())
            )),
        );
    Ok(())
}

fn verify_signed_object(value: &Value, key: &VerifyingKey) -> Result<()> {
    let signature_bytes = raw_signature_bytes(value)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let mut payload = value.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| anyhow!("signed payload must be an object"))?
        .remove("signature");
    key.verify(&canonical_bytes(&payload)?, &signature)
        .map_err(|error| anyhow!("Ed25519 signature verification failed: {error}"))
}

fn raw_signature_bytes(value: &Value) -> Result<[u8; 64]> {
    let signature = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("signed object missing signature"))?;
    let signature_bytes = BASE64_STANDARD
        .decode(signature.strip_prefix("ed25519:").unwrap_or(signature))
        .context("decode Ed25519 signature")?;
    signature_bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 signature must be 64 bytes"))
}

fn envelope_binding(envelope: &Value) -> Result<&Map<String, Value>> {
    envelope
        .get("binding")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("Max-DE envelope missing binding object"))
}

fn require_binding_digest(binding: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    if !valid_sha256_digest(expected) {
        bail!("expected digest for {field} is not sha256:<hex>");
    }
    require_binding_str(binding, field, expected)
}

fn require_binding_str(binding: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    let actual = binding
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope missing binding.{field}"))?;
    if actual != expected {
        bail!("Max-DE envelope binding.{field} does not match context");
    }
    Ok(())
}

fn decision_policy_id(decision: &Value) -> Result<&str> {
    decision
        .get("policy_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing policy_id"))
}

pub fn hash_identifier(value: &str) -> String {
    format!("sha256:{}", sha256_hex(value.as_bytes()))
}

pub fn hash_optional_identifier(value: Option<&str>) -> String {
    value
        .map(hash_identifier)
        .unwrap_or_else(|| "sha256:null".to_string())
}

fn transport_binding(config: &OapConfig) -> Value {
    let tunnel = &config.transport_context.openai_secure_mcp_tunnel;
    let tunnel_id_hash = hash_env_if_present(&tunnel.tunnel_id_env);
    let workspace_hash = hash_env_if_present(&tunnel.workspace_id_env);
    let connector_subject_hash = hash_env_if_present(&tunnel.connector_subject_env);
    json!({
        "kind": config.transport_context.kind,
        "openai_secure_mcp_tunnel": {
            "enabled": tunnel.enabled,
            "tunnel_id_hash": tunnel_id_hash,
            "workspace_hash": workspace_hash,
            "connector_subject_hash": connector_subject_hash,
        }
    })
}

fn hash_env_if_present(env_name: &str) -> Value {
    match std::env::var(env_name)
        .ok()
        .filter(|value| !value.is_empty())
    {
        Some(value) => Value::String(hash_identifier(&value)),
        None => Value::Null,
    }
}

fn digest_redaction_safe_request(request: &Value) -> Result<String> {
    let mut value = request.clone();
    let mut remove_empty_meta = false;
    if let Some(meta) = value
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .and_then(|params| params.get_mut("_meta"))
        .and_then(Value::as_object_mut)
    {
        meta.remove("velvet_approval_receipt");
        remove_empty_meta = meta.is_empty();
    }
    if remove_empty_meta
        && let Some(params) = value.get_mut("params").and_then(Value::as_object_mut)
    {
        params.remove("_meta");
    }
    Ok(format!(
        "sha256:{}",
        sha256_hex(canonical_json(&redact_sensitive_value(&value)).as_bytes())
    ))
}

fn redact_sensitive_value(value: &Value) -> Value {
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

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower == "authorization"
        || lower == "cookie"
        || lower == "set-cookie"
}

struct SigningMaterial {
    signing_key: SigningKey,
}

impl SigningMaterial {
    fn from_env(env_name: &str, kid: &str) -> Result<Self> {
        if kid.trim().is_empty() {
            bail!("signing kid must not be empty");
        }
        let raw = std::env::var(env_name).with_context(|| {
            format!("required Ed25519 signing key env var {env_name} is not set")
        })?;
        let key_bytes = decode_key_material(&raw)?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("Ed25519 private key in {env_name} must be 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&key_bytes),
        })
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

fn decode_key_material(raw: &str) -> Result<Vec<u8>> {
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
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .context("decode Ed25519 key material")
}

fn string_or_number<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(value) => Ok(value),
        Value::Number(value) => Ok(value.to_string()),
        other => Err(serde::de::Error::custom(format!(
            "expected string or number, got {other}"
        ))),
    }
}

fn compat_decimal_to_f64(value: &str, field: &str) -> Result<f64> {
    let parsed = value
        .parse::<f64>()
        .with_context(|| format!("Max-DE compatibility shim {field} must be a decimal number"))?;
    if !parsed.is_finite() {
        bail!("Max-DE compatibility shim {field} must be finite");
    }
    Ok(parsed)
}

fn parse_oap_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn validate_oap_config(config: &OapConfig) -> Result<()> {
    if !matches!(
        config.assurance_level.as_str(),
        "L0" | "L1" | "L2" | "L3" | "L4KYC" | "L4FIN"
    ) {
        bail!("OAP assurance_level is invalid");
    }
    if !valid_policy_id(&config.policy_id) {
        bail!("OAP policy_id is invalid");
    }
    if !valid_oap_kid(&config.oap_kid) {
        bail!("OAP kid is invalid");
    }
    if config.decision_ttl_seconds < 0 {
        bail!("OAP decision_ttl_seconds must be non-negative");
    }
    if config.velvet_kid.trim().is_empty() {
        bail!("Velvet Max-DE kid must not be empty");
    }
    if config.transport_context.kind != "mcp" {
        bail!("OAP transport_context.kind must be mcp");
    }
    Ok(())
}

fn ensure_oap_json_value(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if number.as_i64().is_some() || number.as_u64().is_some() {
                Ok(())
            } else {
                bail!("{path}: OAP signed payloads must not contain floating point numbers")
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                ensure_oap_json_value(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, item) in values {
                ensure_oap_json_value(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
    }
}

fn capability_id(tool: &ToolApproval) -> String {
    let raw = format!("mcp.{}.{}", tool.server, tool.name);
    let mut output = String::new();
    let mut last_dot = false;
    for char in raw.chars().flat_map(char::to_lowercase) {
        if char.is_ascii_alphanumeric() {
            output.push(char);
            last_dot = false;
        } else if !last_dot {
            output.push('.');
            last_dot = true;
        }
    }
    output.trim_matches('.').to_string()
}

fn derived_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn valid_policy_id(value: &str) -> bool {
    let Some((prefix, version)) = value.rsplit_once(".v") else {
        return false;
    };
    !prefix.is_empty()
        && !version.is_empty()
        && version.chars().all(|char| char.is_ascii_digit())
        && prefix.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|char| char.is_ascii_lowercase() || char.is_ascii_digit())
        })
}

fn valid_oap_kid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("oap:registry:") else {
        return value
            .strip_prefix("oap:owner:")
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(valid_kid_char));
    };
    !rest.is_empty() && rest.chars().all(valid_kid_char)
}

fn valid_kid_char(char: char) -> bool {
    char.is_ascii_alphanumeric() || matches!(char, '.' | '_' | '-')
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.chars().all(|char| char.is_ascii_hexdigit())
    })
}

fn is_uuid_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| Uuid::parse_str(value).is_ok())
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests;
