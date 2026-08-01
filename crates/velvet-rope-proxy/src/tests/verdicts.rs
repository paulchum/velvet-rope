use chrono::{DateTime, SecondsFormat};

use crate::constants::SIGNATURE_SCHEMA_VERSION;
use crate::ledger::verdict_requirement_for_call;

use super::*;

fn rfc3339_z(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The demo Max-DE signing key whose public key `ensure_demo_signing_env`
/// exports through `VELVET_MAXDE_ED25519_PUBLIC_KEY` — the default trusted
/// key env var shared by Execution Permits and Verdict Certificates.
fn demo_maxde_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn signed_verdict_certificate(
    tenant_id: &str,
    verdict: &str,
    expires_at: DateTime<Utc>,
    signing_key: &SigningKey,
    purpose: &str,
    key_id: &str,
) -> Value {
    let issued_at = rfc3339_z(expires_at - Duration::hours(2));
    let mut certificate = json!({
        "schema_version": VERDICT_CERTIFICATE_SCHEMA_VERSION,
        "canonicalization": "velvet.canonical_json.v1.sha256.unsigned_payload",
        "certificate_id": format!(
            "vverdict_{}",
            &sha256_hex(format!("{tenant_id}:{verdict}:{issued_at}").as_bytes())[..32]
        ),
        "issuer": "velvet-maxde-verdict-service",
        "tenant_id": tenant_id,
        "environment": "local",
        "subject": {
            "decision_id": "dec_replay_00042",
            "decision_class": "retire_tool_route",
            "target_id_hash": format!(
                "sha256:{}",
                sha256_hex(b"servicenow/search_change_requests")
            ),
        },
        "verdict": verdict,
        "reason_code": "delta_bounded_under_H",
        "refusal_reason": null,
        "claim_currency": "BP",
        "parameters": {
            "delta": 0.05,
            "delta_tail": null,
            "gate_c": 1.5,
            "rho": 0.2,
            "horizon_H": 128,
            "exploration_mass": null,
            "method": "exact_dp",
            "baseline_mode": "posterior_candidate_excluded"
        },
        "hypotheses": ["exchangeable_rounds_within_window"],
        "prices": {
            "inspection": {
                "expected_rounds_to_gate_crossing": 12.5,
                "dollars": null,
                "dollars_source": null
            },
            "tail": {
                "probability_bound": 0.01,
                "crossing_probability": 0.004,
                "drift_penalty": 0.0,
                "posterior_expected_shortfall": 0.02,
                "dollars": null,
                "dollars_source": null
            }
        },
        "validity": {
            "issued_at": issued_at,
            "not_before": issued_at,
            "expires_at": rfc3339_z(expires_at),
            "horizon_rounds": 128.0,
            "rounds_remaining": 64.0,
            "t_hat": null,
            "rounds_per_day": null,
            "recertification": "required_inspection_on_expiry"
        },
        "fleet": null,
        "evidence": {
            "inputs_hash": format!("sha256:{}", sha256_hex(b"verdict-inputs")),
            "max_de_certificate_hash": null,
            "prior_certificate_hash": null,
            "theorem_refs": ["velvet.maxde.kill_rule.v1"]
        },
    });
    let payload_hash = format!(
        "sha256:{}",
        sha256_hex(canonical_json(&certificate).as_bytes())
    );
    let message = canonical_json(&json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": "velvet_ed25519",
        "algorithm": "Ed25519",
        "key_version": "v1",
        "key_id": key_id,
        "tenant_id": tenant_id,
        "purpose": purpose,
        "payload_hash": payload_hash,
    }));
    let signature = signing_key.sign(message.as_bytes());
    certificate["certificate_hash"] = json!(payload_hash);
    certificate["signature"] = json!({
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "provider_name": "velvet_ed25519",
        "algorithm": "Ed25519",
        "key_id": key_id,
        "key_version": "v1",
        "purpose": purpose,
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        "signed_at": rfc3339_z(Utc::now()),
        "public_verification_material": {
            "key_id": key_id,
            "public_key_base64": BASE64_STANDARD.encode(signing_key.verifying_key().as_bytes()),
            "encoding": "raw-base64"
        },
        "metadata": {"issuer_boundary": "maxde-verdict-service"}
    });
    certificate
}

fn pinned_verdict_config(
    root: &Path,
    env_name: &str,
    signing_key: &SigningKey,
) -> Result<ProxyConfig> {
    let mut config = test_config(root)?;
    config.oap.verdict_trusted_public_key_env = env_name.to_string();
    set_test_env(
        env_name,
        &hex_encode(signing_key.verifying_key().as_bytes()),
    );
    Ok(config)
}

fn attach_verdict_certificate(request: &mut Value, certificate: &Value) -> Result<()> {
    let params = request
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("missing request params"))?;
    let meta = params
        .entry("_meta".to_string())
        .or_insert_with(|| json!({}));
    meta.as_object_mut()
        .ok_or_else(|| anyhow!("params._meta must be an object"))?
        .insert(
            "velvet_verdict_certificate".to_string(),
            certificate.clone(),
        );
    Ok(())
}

/// `search_change_requests` normally routes to execute; reclassifying it as
/// high-risk while keeping the router-admittable capability metadata
/// (read_only + non-budget-affecting, mirroring its low-risk defaults) makes
/// it an irreversible call that would execute without the verdict gate.
fn irreversible_execute_config(root: &Path) -> Result<ProxyConfig> {
    let mut config = test_config(root)?;
    for tool in &mut config.tools {
        if tool.name == "search_change_requests" {
            tool.risk_class = RiskClass::High;
            tool.metadata
                .insert("capability_class".to_string(), json!("read_only"));
            tool.metadata
                .insert("non_budget_affecting".to_string(), json!(true));
        }
    }
    Ok(config)
}

#[test]
fn valid_safe_kill_verdict_certificate_verifies() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_VALID",
        &signing_key,
    )?;
    let expires_at = Utc::now() + Duration::minutes(30);
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "safe_kill",
        expires_at,
        &signing_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let check = verify_verdict_certificate(&certificate, &config, Utc::now())?;
    assert_eq!(check.verdict, "safe_kill");
    assert!(!check.expired);
    assert_eq!(check.decision_class, "retire_tool_route");
    assert_eq!(check.tenant_id, "tenant-test");
    assert_eq!(
        Some(check.certificate_hash.as_str()),
        certificate.get("certificate_hash").and_then(Value::as_str)
    );
    Ok(())
}

#[test]
fn expired_verdict_certificate_is_distinguishable_from_invalid() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_EXPIRED",
        &signing_key,
    )?;
    let expires_at = Utc::now() - Duration::minutes(5);
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "safe_kill",
        expires_at,
        &signing_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let check = verify_verdict_certificate(&certificate, &config, Utc::now())?;
    assert!(
        check.expired,
        "expired certificate must verify with expired=true"
    );
    assert_eq!(check.verdict, "safe_kill");
    assert_eq!(rfc3339_z(check.expires_at), rfc3339_z(expires_at));
    Ok(())
}

#[test]
fn tampered_verdict_certificate_payload_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_TAMPERED",
        &signing_key,
    )?;
    let mut certificate = signed_verdict_certificate(
        "tenant-test",
        "required_inspection",
        Utc::now() + Duration::minutes(30),
        &signing_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    certificate["verdict"] = json!("safe_kill");
    let error = verify_verdict_certificate(&certificate, &config, Utc::now()).unwrap_err();
    assert!(
        error.to_string().contains("hash mismatch"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn wrong_purpose_verdict_certificate_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_PURPOSE",
        &signing_key,
    )?;
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "safe_kill",
        Utc::now() + Duration::minutes(30),
        &signing_key,
        "velvet.execution_permit.v1",
        &config.oap.velvet_kid,
    );
    let error = verify_verdict_certificate(&certificate, &config, Utc::now()).unwrap_err();
    assert!(
        error.to_string().contains("purpose mismatch"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn wrong_signing_key_verdict_certificate_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let trusted_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_WRONG_KEY",
        &trusted_key,
    )?;
    let untrusted_key = SigningKey::from_bytes(&[12u8; 32]);
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "safe_kill",
        Utc::now() + Duration::minutes(30),
        &untrusted_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let error = verify_verdict_certificate(&certificate, &config, Utc::now()).unwrap_err();
    assert!(
        error.to_string().contains("does not match trusted key"),
        "unexpected error: {error}"
    );
    let mut stripped = certificate.clone();
    stripped["signature"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("signature must be an object"))?
        .remove("public_verification_material");
    let error = verify_verdict_certificate(&stripped, &config, Utc::now()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verify verdict certificate signature"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn wrong_key_id_verdict_certificate_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_WRONG_KID",
        &signing_key,
    )?;
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "safe_kill",
        Utc::now() + Duration::minutes(30),
        &signing_key,
        PURPOSE_VERDICT_CERTIFICATE,
        "velvet:attacker:kid",
    );
    let error = verify_verdict_certificate(&certificate, &config, Utc::now()).unwrap_err();
    assert!(
        error.to_string().contains("key id is not trusted"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn required_inspection_verdict_verifies_but_is_not_safe_kill() -> Result<()> {
    let temp = TempDir::new()?;
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let config = pinned_verdict_config(
        temp.path(),
        "VELVET_TEST_VERDICT_PUBKEY_INSPECTION",
        &signing_key,
    )?;
    let certificate = signed_verdict_certificate(
        "tenant-test",
        "required_inspection",
        Utc::now() + Duration::minutes(30),
        &signing_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let check = verify_verdict_certificate(&certificate, &config, Utc::now())?;
    assert_eq!(check.verdict, "required_inspection");
    assert!(!check.expired);
    assert_ne!(check.verdict, VERDICT_SAFE_KILL);
    Ok(())
}

#[test]
fn verdict_requirement_gates_on_irreversibility_and_flag() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    let tool = |config: &ProxyConfig, name: &str| -> ToolApproval {
        config
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .expect("test tool")
            .clone()
    };
    let destructive = tool(&config, "delete_change_request");
    let high_risk = tool(&config, "create_change_request");
    let low_risk = tool(&config, "search_change_requests");

    // Strict mode forces the requirement for irreversible tools even when the
    // config flag is off.
    config.oap.require_verdict_for_irreversible = false;
    let (required, reason) = verdict_requirement_for_call(&config, Some(&destructive));
    assert!(required);
    assert_eq!(reason, "strict_mode_requires_verdict_certificate");
    assert!(verdict_requirement_for_call(&config, Some(&high_risk)).0);
    assert!(!verdict_requirement_for_call(&config, Some(&low_risk)).0);

    // Outside strict mode the requirement follows the flag.
    config.mode = EnforcementMode::Development;
    assert!(!verdict_requirement_for_call(&config, Some(&destructive)).0);
    assert!(!verdict_requirement_for_call(&config, Some(&high_risk)).0);
    config.oap.require_verdict_for_irreversible = true;
    let (required, reason) = verdict_requirement_for_call(&config, Some(&destructive));
    assert!(required);
    assert_eq!(reason, "destructive_tool");
    let (required, reason) = verdict_requirement_for_call(&config, Some(&high_risk));
    assert!(required);
    assert_eq!(reason, "high_risk_tool");
    assert!(!verdict_requirement_for_call(&config, Some(&low_risk)).0);
    assert!(!verdict_requirement_for_call(&config, None).0);
    Ok(())
}

#[test]
fn missing_verdict_certificate_blocks_irreversible_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = ProxyRuntime::new(
        irreversible_execute_config(temp.path())?,
        FakeMcpServer::default(),
    )?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert!(
        response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("verdict_certificate_missing")),
        "unexpected response: {response}"
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn invalid_verdict_certificate_blocks_irreversible_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let config = irreversible_execute_config(temp.path())?;
    let untrusted_key = SigningKey::from_bytes(&[13u8; 32]);
    let certificate = signed_verdict_certificate(
        &config.identity.tenant_id,
        "safe_kill",
        Utc::now() + Duration::hours(1),
        &untrusted_key,
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let mut request = call("search_change_requests");
    attach_verdict_certificate(&mut request, &certificate)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert!(
        response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("verdict_certificate_invalid")),
        "unexpected response: {response}"
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn safe_kill_verdict_certificate_admits_irreversible_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let config = irreversible_execute_config(temp.path())?;
    let certificate = signed_verdict_certificate(
        &config.identity.tenant_id,
        "safe_kill",
        Utc::now() + Duration::hours(1),
        &demo_maxde_signing_key(),
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let mut request = call("search_change_requests");
    attach_verdict_certificate(&mut request, &certificate)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime.handle_message(request)?.unwrap();
    assert!(response.get("result").is_some(), "unexpected: {response}");
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    let records = ledger_records(temp.path())?;
    let pre_record = records
        .iter()
        .find(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("pre_execution_decision")
        })
        .ok_or_else(|| anyhow!("missing pre-execution record"))?;
    assert_eq!(
        pre_record
            .get("verdict_certificate_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        pre_record.get("verdict_status").and_then(Value::as_str),
        Some("safe_kill")
    );
    assert_eq!(
        pre_record
            .get("verdict_certificate_hash")
            .and_then(Value::as_str),
        certificate.get("certificate_hash").and_then(Value::as_str)
    );
    assert_eq!(
        pre_record
            .get("verdict_requirement_reason")
            .and_then(Value::as_str),
        Some("strict_mode_requires_verdict_certificate")
    );
    Ok(())
}

#[test]
fn expired_verdict_certificate_escalates_for_recertification() -> Result<()> {
    let temp = TempDir::new()?;
    let config = irreversible_execute_config(temp.path())?;
    let certificate = signed_verdict_certificate(
        &config.identity.tenant_id,
        "safe_kill",
        Utc::now() - Duration::minutes(1),
        &demo_maxde_signing_key(),
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let mut request = call("search_change_requests");
    attach_verdict_certificate(&mut request, &certificate)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32072),
        "expired verdict must escalate, not hard-deny: {response}"
    );
    assert!(
        response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("verdict_expired_recertification_required")),
        "unexpected response: {response}"
    );
    assert!(
        response
            .pointer("/error/data/approval_request")
            .is_some_and(|value| !value.is_null()),
        "expired verdict must route to the approval path: {response}"
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    let records = ledger_records(temp.path())?;
    let pre_record = records
        .iter()
        .find(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("pre_execution_decision")
        })
        .ok_or_else(|| anyhow!("missing pre-execution record"))?;
    assert_eq!(
        pre_record.get("verdict_status").and_then(Value::as_str),
        Some("expired")
    );
    assert_eq!(
        pre_record.get("decision").and_then(Value::as_str),
        Some("escalate")
    );
    Ok(())
}

#[test]
fn non_safe_kill_verdict_certificate_blocks_irreversible_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let config = irreversible_execute_config(temp.path())?;
    let certificate = signed_verdict_certificate(
        &config.identity.tenant_id,
        "required_inspection",
        Utc::now() + Duration::hours(1),
        &demo_maxde_signing_key(),
        PURPOSE_VERDICT_CERTIFICATE,
        &config.oap.velvet_kid,
    );
    let mut request = call("search_change_requests");
    attach_verdict_certificate(&mut request, &certificate)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert!(
        response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("verdict_not_safe_kill:required_inspection")),
        "unexpected response: {response}"
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn reversible_tools_execute_without_verdict_certificate() -> Result<()> {
    let temp = TempDir::new()?;
    // Default test config: search_change_requests stays low-risk, so even in
    // strict mode no verdict certificate is required.
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert!(response.get("result").is_some(), "unexpected: {response}");
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    let records = ledger_records(temp.path())?;
    let pre_record = records
        .iter()
        .find(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("pre_execution_decision")
        })
        .ok_or_else(|| anyhow!("missing pre-execution record"))?;
    assert_eq!(
        pre_record
            .get("verdict_certificate_required")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(pre_record.get("verdict_status").is_some_and(Value::is_null));
    Ok(())
}
