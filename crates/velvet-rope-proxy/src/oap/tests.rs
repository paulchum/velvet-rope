use super::*;
use crate::IdentityConfig;

fn test_identity() -> IdentityConfig {
    IdentityConfig {
        tenant_id: "tenant-oap-test".to_string(),
        environment: "local".to_string(),
        product_surface: "velvet_inline_gateway.mcp".to_string(),
        subject_id: Some("subject-oap-test".to_string()),
        agent_id: Some("agent-oap-test".to_string()),
        client_id: Some("client-oap-test".to_string()),
        session_id: Some("session-oap-test".to_string()),
    }
}

fn test_config() -> OapConfig {
    set_test_keys();
    OapConfig {
        passport_created_at: Some("2026-05-28T00:00:00Z".to_string()),
        passport_updated_at: Some("2026-05-28T00:00:00Z".to_string()),
        ..OapConfig::default()
    }
}

fn set_test_keys() {
    unsafe {
        std::env::set_var(
            "VELVET_OAP_ED25519_PRIVATE_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        );
        std::env::set_var(
            "VELVET_MAXDE_ED25519_PRIVATE_KEY",
            "0909090909090909090909090909090909090909090909090909090909090909",
        );
    }
}

fn lockout_config() -> MaxDeCertificateConfig {
    MaxDeCertificateConfig {
        v: "0.0500".to_string(),
        lambda_value: "0.2000".to_string(),
        delight_scale: "1.0000".to_string(),
        alpha: "1.0000".to_string(),
        beta: "9.0000".to_string(),
        lower_certificate: "0.0500".to_string(),
        upper_certificate: "0.1000".to_string(),
        decision: MaxDeDecision::Lockout,
        theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
        maxde_version: "maxde/1.0".to_string(),
    }
}

fn inspect_config() -> MaxDeCertificateConfig {
    MaxDeCertificateConfig {
        v: "0.900000".to_string(),
        lambda_value: "0.200000".to_string(),
        delight_scale: "1.000000".to_string(),
        alpha: "9.000000".to_string(),
        beta: "1.000000".to_string(),
        lower_certificate: "0.900000".to_string(),
        upper_certificate: "0.950000".to_string(),
        decision: MaxDeDecision::Inspect,
        theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
        maxde_version: "maxde/1.0".to_string(),
    }
}

fn refinement_config() -> MaxDeCertificateConfig {
    MaxDeCertificateConfig {
        v: "0.150000".to_string(),
        lambda_value: "0.200000".to_string(),
        delight_scale: "1.000000".to_string(),
        alpha: "3.000000".to_string(),
        beta: "7.000000".to_string(),
        lower_certificate: "0.100000".to_string(),
        upper_certificate: "0.300000".to_string(),
        decision: MaxDeDecision::Refinement,
        theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
        maxde_version: "maxde/1.0".to_string(),
    }
}

struct TestActionContext {
    request: Value,
    policy_hash: String,
    tool_schema_hash: String,
    arguments_hash: String,
    request_hash: String,
    canonical_action_hash: String,
}

impl TestActionContext {
    fn new(tool_name: &str, arguments: Value) -> Result<Self> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments}
        });
        Ok(Self {
            policy_hash: digest_value(&json!({"policy": "test"}))?,
            tool_schema_hash: digest_value(&json!({"name": tool_name}))?,
            arguments_hash: digest_value(
                request
                    .pointer("/params/arguments")
                    .ok_or_else(|| anyhow!("missing arguments"))?,
            )?,
            request_hash: digest_redaction_safe_request(&request)?,
            canonical_action_hash: digest_value(&json!({
                "surface": "mcp",
                "tool": tool_name,
                "arguments": request.pointer("/params/arguments"),
            }))?,
            request,
        })
    }

    fn as_context<'a>(&'a self, tool_key: &'a str, tool_name: &'a str) -> OapActionContext<'a> {
        OapActionContext {
            request: &self.request,
            policy_hash: &self.policy_hash,
            policy_version: "mcp_demo",
            tool_key,
            tool_name,
            tool_schema_hash: &self.tool_schema_hash,
            arguments_hash: &self.arguments_hash,
            request_hash: &self.request_hash,
            canonical_action_hash: &self.canonical_action_hash,
            mcp_method: "tools/call",
            max_de_certificate_required: true,
            max_de_requirement_reason: "test",
        }
    }
}

fn unsigned_exact_envelope(config: &MaxDeCertificateConfig) -> Result<Value> {
    let exact_decision = config.exact_decision()?;
    Ok(json!({
        "type": VELVET_MAXDE_ENVELOPE_TYPE,
        "schema_version": VELVET_MAXDE_ENVELOPE_SCHEMA_VERSION,
        "certificate": {
            "v": certificate_decimal_json(&config.v, "v")?,
            "lambda": certificate_decimal_json(&config.lambda_value, "lambda")?,
            "L": certificate_decimal_json(&config.delight_scale, "L")?,
            "alpha": certificate_decimal_json(&config.alpha, "alpha")?,
            "beta": certificate_decimal_json(&config.beta, "beta")?,
            "L_cert": certificate_decimal_json(&config.lower_certificate, "L_cert")?,
            "U_cert": certificate_decimal_json(&config.upper_certificate, "U_cert")?,
            "decision": exact_decision.as_str(),
            "certified_lockout": exact_decision == MaxDeDecision::Lockout,
            "certified_inspect": exact_decision == MaxDeDecision::Inspect,
            "theorem_ref": config.theorem_ref,
            "maxde_version": config.maxde_version
        },
        "signature": Value::Null
    }))
}

#[test]
fn pinned_decision_schema_is_unsatisfiable() {
    let schema: Value = serde_json::from_str(include_str!(
            "../../../../third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/oap/decision-schema.json"
        ))
        .unwrap();
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let properties = schema.get("properties").and_then(Value::as_object).unwrap();
    assert!(required.contains(&"passport_id"));
    assert!(!properties.contains_key("passport_id"));
    assert_eq!(
        schema.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn passport_digest_is_deterministic_and_mutation_changes_it() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let one = build_passport(&config, &identity, &[])?;
    let two = build_passport(&config, &identity, &[])?;
    assert_eq!(digest_value(&one)?, digest_value(&two)?);
    let mut mutated = one.clone();
    mutated.as_object_mut().unwrap().insert(
        "owner_id".to_string(),
        Value::String("other-owner".to_string()),
    );
    assert_ne!(digest_value(&one)?, digest_value(&mutated)?);
    validate_passport_structural(&one)?;
    Ok(())
}

#[test]
fn decision_signature_and_canonicalization_tamper_checks() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    let first = canonical_bytes(&artifacts.decision)?;
    let second = canonical_bytes(&serde_json::from_slice::<Value>(&first)?)?;
    assert_eq!(first, second);
    let material = SigningMaterial::from_env(&config.oap_private_key_env, &config.oap_kid)?;
    verify_signed_object(&artifacts.decision, &material.verifying_key())?;

    let mut tampered = artifacts.decision.clone();
    *tampered
        .pointer_mut("/reasons/0/message")
        .ok_or_else(|| anyhow!("missing reason message"))? = Value::String("tampered".to_string());
    assert!(verify_signed_object(&tampered, &material.verifying_key()).is_err());
    Ok(())
}

#[test]
fn decision_payload_and_signed_digests_are_distinct_and_stable() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    assert_ne!(
        artifacts.decision_payload_digest,
        artifacts.signed_decision_digest
    );
    assert_eq!(
        artifacts.decision_payload_digest,
        decision_payload_digest(&artifacts.decision)?
    );
    assert_eq!(
        artifacts.signed_decision_digest,
        signed_decision_digest(&artifacts.decision)?
    );
    let mut changed = artifacts.decision.clone();
    changed["allow"] = Value::Bool(false);
    assert_ne!(
        artifacts.decision_payload_digest,
        decision_payload_digest(&changed)?
    );
    Ok(())
}

#[test]
fn decision_signature_hash_tracks_raw_ed25519_signature() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let first = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    let mut second = first.decision.clone();
    second["signature"] = Value::String(format!("ed25519:{}", BASE64_STANDARD.encode([11u8; 64])));
    assert_ne!(
        first.decision_signature_hash,
        decision_signature_hash(&second)?
    );
    assert_ne!(
        signed_decision_digest(&first.decision)?,
        signed_decision_digest(&second)?
    );
    assert_eq!(
        decision_payload_digest(&first.decision)?,
        decision_payload_digest(&second)?
    );
    Ok(())
}

#[test]
fn canonicalization_rejects_float_json_numbers() {
    assert!(canonical_bytes(&json!({"value": 0.1})).is_err());
    assert!(canonical_bytes(&json!({"value": {"value": "0.100000", "scale": 6}})).is_ok());
}

#[test]
fn decision_signature_tamper_checks_use_production_ed25519() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    let material = SigningMaterial::from_env(&config.oap_private_key_env, &config.oap_kid)?;
    verify_oap_decision_signature(&artifacts.decision, &material.verifying_key())?;
    let mut tampered = artifacts.decision.clone();
    tampered["policy_id"] = Value::String("velvet.other.v1".to_string());
    assert!(verify_oap_decision_signature(&tampered, &material.verifying_key()).is_err());
    Ok(())
}

#[test]
fn maxde_exact_arithmetic_inspect_vector() -> Result<()> {
    let envelope = unsigned_exact_envelope(&inspect_config())?;
    verify_maxde_exact_arithmetic(&envelope)
}

#[test]
fn maxde_exact_arithmetic_lockout_vector() -> Result<()> {
    let envelope = unsigned_exact_envelope(&lockout_config())?;
    verify_maxde_exact_arithmetic(&envelope)
}

#[test]
fn maxde_exact_arithmetic_refinement_vector() -> Result<()> {
    let envelope = unsigned_exact_envelope(&refinement_config())?;
    verify_maxde_exact_arithmetic(&envelope)
}

#[test]
fn maxde_exact_arithmetic_boundary_equality_vector() -> Result<()> {
    let mut config = inspect_config();
    config.lambda_value = "0.200000".to_string();
    config.lower_certificate = "0.200000".to_string();
    config.upper_certificate = "0.300000".to_string();
    config.decision = MaxDeDecision::Inspect;
    let envelope = unsigned_exact_envelope(&config)?;
    verify_maxde_exact_arithmetic(&envelope)?;
    assert_eq!(
        envelope
            .pointer("/certificate/decision")
            .and_then(Value::as_str),
        Some("inspect")
    );
    Ok(())
}

#[test]
fn maxde_rejects_float_or_exponent_inputs() {
    assert!(parse_fixed_decimal("1e-6", "lambda").is_err());
    assert!(parse_fixed_decimal("NaN", "lambda").is_err());
    assert!(parse_fixed_decimal("0.1234567", "lambda").is_err());
}

#[test]
fn maxde_tampered_scale_or_value_fails() -> Result<()> {
    let envelope = unsigned_exact_envelope(&lockout_config())?;
    let mut scale = envelope.clone();
    scale["certificate"]["U_cert"]["scale"] = json!(5);
    assert!(verify_maxde_exact_arithmetic(&scale).is_err());
    let mut value = envelope;
    value["certificate"]["certified_lockout"] = Value::Bool(false);
    assert!(verify_maxde_exact_arithmetic(&value).is_err());
    Ok(())
}

#[test]
fn maxde_envelope_tamper_swap_and_strip_are_detected() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let maxde = lockout_config();
    let evidence = maxde.to_core_evidence("mcp.test.delete")?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "tools/call",
        "params": {
            "name": "delete_change_request",
            "arguments": {"change_id": "CHG0042007"}
        }
    });
    let policy_hash = digest_value(&json!({"policy": "test"}))?;
    let tool_schema_hash = digest_value(&json!({"name": "delete_change_request"}))?;
    let arguments_hash = digest_value(&json!({"change_id": "CHG0042007"}))?;
    let request_hash = digest_redaction_safe_request(&request)?;
    let canonical_action_hash = digest_value(&json!({
        "surface": "mcp",
        "tool": "delete_change_request",
        "arguments": {"change_id": "CHG0042007"},
    }))?;
    let action_context = OapActionContext {
        request: &request,
        policy_hash: &policy_hash,
        policy_version: "mcp_demo",
        tool_key: "mcp.test.delete",
        tool_name: "delete_change_request",
        tool_schema_hash: &tool_schema_hash,
        arguments_hash: &arguments_hash,
        request_hash: &request_hash,
        canonical_action_hash: &canonical_action_hash,
        mcp_method: "tools/call",
        max_de_certificate_required: true,
        max_de_requirement_reason: "test",
    };
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: false,
            reasons: vec![OapReason::new(
                "velvet.certified_lockout",
                "Max-DE certified lockout",
            )],
            max_de_config: Some(&maxde),
            max_de_evidence: Some(&evidence),
            action_context: Some(action_context),
        },
    )?;
    let envelope = artifacts
        .max_de_envelope
        .as_ref()
        .ok_or_else(|| anyhow!("missing Max-DE envelope"))?;
    let material = SigningMaterial::from_env(&config.velvet_private_key_env, &config.velvet_kid)?;
    verify_signed_object(envelope, &material.verifying_key())?;
    verify_envelope_binding(envelope, &artifacts.decision)?;

    let mut tampered = envelope.clone();
    tampered["certificate"]["U_cert"]["value"] = Value::String("0.900000".to_string());
    assert!(verify_signed_object(&tampered, &material.verifying_key()).is_err());

    let other = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    assert!(verify_envelope_binding(envelope, &other.decision).is_err());
    assert!(
        verify_required_envelope(&json!({
            "max_de_certificate_required": true
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn maxde_envelope_binds_policy_tool_schema_arguments_request_and_decision() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let maxde = lockout_config();
    let evidence = maxde.to_core_evidence("mcp.test.delete")?;
    let context_values =
        TestActionContext::new("delete_change_request", json!({"change_id": "CHG0042007"}))?;
    let action_context = context_values.as_context("mcp.test.delete", "delete_change_request");
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: false,
            reasons: vec![OapReason::new(
                "velvet.certified_lockout",
                "Max-DE certified lockout",
            )],
            max_de_config: Some(&maxde),
            max_de_evidence: Some(&evidence),
            action_context: Some(action_context.clone()),
        },
    )?;
    let envelope = artifacts
        .max_de_envelope
        .as_ref()
        .ok_or_else(|| anyhow!("missing envelope"))?;
    verify_envelope_binding_against_context(
        envelope,
        &artifacts.decision,
        &context_values.request,
        &identity,
        &action_context,
    )?;
    for pointer in [
        "/binding/policy_id",
        "/binding/arguments_hash",
        "/binding/tool_schema_hash",
        "/binding/request_hash",
        "/binding/decision_payload_digest",
        "/binding/signed_decision_digest",
        "/binding/decision_signature_hash",
    ] {
        let mut tampered = envelope.clone();
        *tampered
            .pointer_mut(pointer)
            .ok_or_else(|| anyhow!("missing pointer {pointer}"))? = Value::String(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        assert!(
            verify_envelope_binding_against_context(
                &tampered,
                &artifacts.decision,
                &context_values.request,
                &identity,
                &action_context,
            )
            .is_err(),
            "{pointer} mutation should fail"
        );
    }
    Ok(())
}

#[test]
fn maxde_envelope_strip_swap_and_replay_are_detected() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let maxde = lockout_config();
    let evidence = maxde.to_core_evidence("mcp.test.delete")?;
    let context_values =
        TestActionContext::new("delete_change_request", json!({"change_id": "CHG0042007"}))?;
    let action_context = context_values.as_context("mcp.test.delete", "delete_change_request");
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: false,
            reasons: vec![OapReason::new(
                "velvet.certified_lockout",
                "Max-DE certified lockout",
            )],
            max_de_config: Some(&maxde),
            max_de_evidence: Some(&evidence),
            action_context: Some(action_context.clone()),
        },
    )?;
    let envelope = artifacts
        .max_de_envelope
        .as_ref()
        .ok_or_else(|| anyhow!("missing envelope"))?;
    let other = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: None,
            max_de_evidence: None,
            action_context: None,
        },
    )?;
    assert!(verify_envelope_binding(envelope, &other.decision).is_err());
    assert!(
        verify_required_envelope(&json!({
            "max_de_certificate_required": true,
            "max_de_certificate_envelope": Value::Null,
        }))
        .is_err()
    );
    let mut other_context =
        TestActionContext::new("delete_change_request", json!({"change_id": "OTHER"}))?;
    other_context.policy_hash = context_values.policy_hash.clone();
    other_context.tool_schema_hash = context_values.tool_schema_hash.clone();
    let swapped_context = other_context.as_context("mcp.test.delete", "delete_change_request");
    assert!(
        verify_envelope_binding_against_context(
            envelope,
            &artifacts.decision,
            &other_context.request,
            &identity,
            &swapped_context,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn maxde_envelope_expiry_is_enforced() -> Result<()> {
    let config = test_config();
    let identity = test_identity();
    let maxde = lockout_config();
    let evidence = maxde.to_core_evidence("mcp.test.delete")?;
    let context_values =
        TestActionContext::new("delete_change_request", json!({"change_id": "CHG0042007"}))?;
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: false,
            reasons: vec![OapReason::new(
                "velvet.certified_lockout",
                "Max-DE certified lockout",
            )],
            max_de_config: Some(&maxde),
            max_de_evidence: Some(&evidence),
            action_context: Some(
                context_values.as_context("mcp.test.delete", "delete_change_request"),
            ),
        },
    )?;
    let mut envelope = artifacts
        .max_de_envelope
        .clone()
        .ok_or_else(|| anyhow!("missing envelope"))?;
    envelope["expires_at"] = Value::String("2020-01-01T00:00:00Z".to_string());
    let material = SigningMaterial::from_env(&config.velvet_private_key_env, &config.velvet_kid)?;
    sign_object(&mut envelope, &material)?;
    assert!(verify_maxde_certificate_envelope(&envelope, &material.verifying_key()).is_err());
    Ok(())
}

#[test]
fn tunnel_metadata_is_hashed_not_raw() -> Result<()> {
    unsafe {
        std::env::set_var("VELVET_OPENAI_TUNNEL_ID", "tunnel-raw");
        std::env::set_var("VELVET_OPENAI_WORKSPACE_ID", "workspace-raw");
        std::env::set_var("VELVET_CONNECTOR_SUBJECT", "connector-raw");
    }
    let mut config = test_config();
    config.transport_context.openai_secure_mcp_tunnel.enabled = true;
    let identity = test_identity();
    let maxde = inspect_config();
    let evidence = maxde.to_core_evidence("mcp.test.search")?;
    let context_values = TestActionContext::new(
        "search_change_requests",
        json!({"query": "service=payments"}),
    )?;
    let artifacts = build_oap_artifacts(
        &config,
        OapDecisionInput {
            identity: &identity,
            tools: &[],
            allow: true,
            reasons: vec![OapReason::new("oap.allowed", "Action admitted by Velvet")],
            max_de_config: Some(&maxde),
            max_de_evidence: Some(&evidence),
            action_context: Some(
                context_values.as_context("mcp.test.search", "search_change_requests"),
            ),
        },
    )?;
    let envelope = artifacts
        .max_de_envelope
        .ok_or_else(|| anyhow!("missing envelope"))?;
    let serialized = serde_json::to_string(&envelope)?;
    assert!(!serialized.contains("tunnel-raw"));
    assert!(!serialized.contains("workspace-raw"));
    assert!(!serialized.contains("connector-raw"));
    assert_eq!(
        envelope
            .pointer("/binding/transport/openai_secure_mcp_tunnel/enabled")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        envelope
            .pointer("/binding/transport/openai_secure_mcp_tunnel/tunnel_id_hash")
            .and_then(Value::as_str)
            .is_some_and(valid_sha256_digest)
    );
    Ok(())
}
