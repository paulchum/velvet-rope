use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tempfile::TempDir;
use velvet_closure::{ClosureMonitor, MaxDeRiskGate, RiskGate, VerdictRiskGate, load_contract};
use velvet_core::ExecutionPermit;
use velvet_policy_loader::load_policy_graph;
use velvet_rope_proxy::{
    ApprovalReceiptConfig, ApprovalTier, AuthConfig, BinaryLedgerDecodeErrorKind,
    ControlPlaneConfig, EnforcementMode, EvidenceConfig, ForwardingConfig, GatewayConfig,
    HttpConfig, IdentityConfig, LedgerConfig, LimitConfig, MethodDispositionConfig, OapConfig,
    POLICY_BUNDLE_SCHEMA_VERSION, PURPOSE_VERDICT_CERTIFICATE, PolicyBundleManifest, PolicyConfig,
    ProxyConfig, RiskClass, SigningConfig, ToolApproval, ToolInventory, TransportKind,
    UpstreamConfig, VERDICT_CERTIFICATE_SCHEMA_VERSION, WallClockOnlyPermitEpochProvider,
    canonical_json, decode_binary_ledger_frames, hash_identifier, policy_dir_hash,
    record_lifecycle_ledger_event, sha256_hex, tool_schema_hash, value_hash,
    verify_binary_ledger_bytes, verify_oap_ledger_chain, verify_permit_logical_step,
    verify_policy_bundle,
};

fn base_contract() -> Value {
    json!({
        "contract_id": "test/basic",
        "initial_envelope": [{"name": "log:write", "resource": "local:run.log"}],
        "grant_rules": [{
            "subgoal": "read_once",
            "capability": "secret:read",
            "resource": "vault:/k",
            "single_dispatch": true,
            "max_grants": 1
        }],
        "closure_predicates": [{
            "subgoal": "read_once",
            "kind": "on_receipt",
            "capability": "secret:read"
        }],
        "deny_rules": [{
            "capability": "net:write",
            "resource": "external:sink",
            "reason": "exfil"
        }]
    })
}

fn monitor(temp: &TempDir, contract: Value) -> Result<ClosureMonitor> {
    let (config, bundle_proof, policy_graph, inventory) = context(temp.path(), &["secret:read"])?;
    Ok(ClosureMonitor::new(
        load_contract(contract)?,
        config,
        bundle_proof,
        Arc::new(policy_graph),
        inventory,
    ))
}

fn grant(monitor: &mut ClosureMonitor) -> velvet_closure::Decision {
    monitor.open_subgoal("read_once").unwrap();
    monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    )
}

#[test]
fn grant_then_invoke_succeeds_once() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    assert!(grant.allowed, "{}", grant.reason);
    let permit_id = grant.permit_id.as_deref().unwrap();
    let invoke = monitor.invoke(permit_id, json!({"path": "/k"}));
    assert!(invoke.allowed, "{}", invoke.reason);
    assert_eq!(
        invoke
            .receipt
            .as_ref()
            .map(|receipt| receipt.permit_id.as_str()),
        Some(permit_id)
    );
    let replay = monitor.invoke(permit_id, json!({"path": "/k"}));
    assert!(!replay.allowed);
    Ok(())
}

#[test]
fn replay_after_closure_is_rejected_before_dispatch() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    let permit_id = grant.permit_id.as_deref().unwrap();
    assert!(monitor.invoke(permit_id, json!({"path": "/k"})).allowed);
    let before = monitor.dispatch_count();
    let replay = monitor.invoke(permit_id, json!({"path": "/k"}));
    assert!(!replay.allowed);
    assert_eq!(monitor.dispatch_count(), before);
    Ok(())
}

#[test]
fn visible_surface_contracts_on_closure() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    assert!(!monitor.visible_tools().granted.is_empty());
    assert!(
        monitor
            .invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}))
            .allowed
    );
    assert!(monitor.visible_tools().granted.is_empty());
    Ok(())
}

#[test]
fn regrant_after_closure_denied_subgoal_inactive() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    assert!(
        monitor
            .invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}))
            .allowed
    );
    let regrant = monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(!regrant.allowed);
    assert!(regrant.reason.contains("not active"));
    Ok(())
}

#[test]
fn deny_rule_always_wins() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    monitor.open_subgoal("read_once")?;
    let out = monitor.request("read_once", "net:write", "external:sink", json!({}));
    assert!(!out.allowed);
    assert!(out.reason.contains("deny"));
    Ok(())
}

#[test]
fn max_grants_enforced() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let first = grant(&mut monitor);
    assert!(first.allowed, "{}", first.reason);
    let second = monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(!second.allowed);
    assert!(second.reason.contains("max_grants"));
    Ok(())
}

#[test]
fn argument_drift_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    let out = monitor.invoke(
        grant.permit_id.as_deref().unwrap(),
        json!({"path": "/OTHER"}),
    );
    assert!(!out.allowed);
    assert!(out.reason.contains("scope") || out.reason.contains("drift"));
    Ok(())
}

#[test]
fn host_signal_closure_revokes() -> Result<()> {
    let temp = TempDir::new()?;
    let mut data = base_contract();
    data["closure_predicates"] = json!([{"subgoal": "read_once", "kind": "on_signal"}]);
    let mut monitor = monitor(&temp, data)?;
    monitor.open_subgoal("read_once")?;
    let grant = monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(grant.allowed);
    assert!(!monitor.visible_tools().granted.is_empty());
    assert!(monitor.close_subgoal("read_once").allowed);
    assert!(monitor.visible_tools().granted.is_empty());
    let before = monitor.dispatch_count();
    let replay = monitor.invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}));
    assert!(!replay.allowed);
    assert_eq!(monitor.dispatch_count(), before);
    Ok(())
}

#[test]
fn contract_refuses_grant_without_closure() {
    let mut bad = base_contract();
    bad["closure_predicates"] = json!([]);
    assert!(load_contract(bad).is_err());
}

#[test]
fn ledger_verifies_and_detects_tampering() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    assert!(
        monitor
            .invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}))
            .allowed
    );
    let bytes = fs::read(temp.path().join("closure.vledger"))?;
    let frames = verify_binary_ledger_bytes(&bytes)?;
    let records = frames
        .iter()
        .map(|frame| frame.payload.clone())
        .collect::<Vec<_>>();
    verify_oap_ledger_chain(&records)?;

    let mut tampered = records.clone();
    let lifecycle = tampered
        .iter_mut()
        .find(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("closure_lifecycle_event")
        })
        .unwrap();
    lifecycle["state"] = json!("admin:everything");
    assert!(verify_oap_ledger_chain(&tampered).is_err());
    Ok(())
}

#[test]
fn logical_step_with_missing_signed_subgoal_fails_closed() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    let mut permit: ExecutionPermit = grant.permit.unwrap();
    permit.scope.subgoal_id_hash = None;
    assert!(verify_permit_logical_step(&permit, &monitor.epochs()).is_err());
    Ok(())
}

#[test]
fn legacy_no_logical_step_permit_keeps_wall_clock_behavior() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    let mut permit: ExecutionPermit = grant.permit.unwrap();
    permit.validity.issued_at_logical_step = None;
    permit.validity.expires_at_logical_step = None;
    permit.scope.subgoal_id_hash = None;
    verify_permit_logical_step(&permit, &WallClockOnlyPermitEpochProvider)?;
    Ok(())
}

#[test]
fn double_trigger_yields_one_closure_record() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    let permit_id = grant.permit_id.as_deref().unwrap();
    assert!(monitor.invoke(permit_id, json!({"path": "/k"})).allowed);
    let _ = monitor.invoke(permit_id, json!({"path": "/k"}));
    assert_eq!(monitor.lifecycle_record_count("closure")?, 1);
    Ok(())
}

#[test]
fn multi_subgoal_isolation() -> Result<()> {
    let temp = TempDir::new()?;
    let contract = json!({
        "contract_id": "test/multi",
        "initial_envelope": [],
        "grant_rules": [
            {"subgoal": "a", "capability": "secret:read", "resource": "vault:/a", "max_grants": 1},
            {"subgoal": "b", "capability": "secret:read", "resource": "vault:/b", "max_grants": 1}
        ],
        "closure_predicates": [
            {"subgoal": "a", "kind": "on_signal"},
            {"subgoal": "b", "kind": "on_signal"}
        ],
        "deny_rules": []
    });
    let mut monitor = monitor(&temp, contract)?;
    monitor.open_subgoal("a")?;
    monitor.open_subgoal("b")?;
    let a = monitor.request("a", "secret:read", "vault:/a", json!({"path": "/a"}));
    let b = monitor.request("b", "secret:read", "vault:/b", json!({"path": "/b"}));
    assert!(a.allowed);
    assert!(b.allowed);
    assert!(monitor.close_subgoal("a").allowed);
    let before = monitor.dispatch_count();
    let a_replay = monitor.invoke(a.permit_id.as_deref().unwrap(), json!({"path": "/a"}));
    assert!(!a_replay.allowed);
    assert_eq!(monitor.dispatch_count(), before);
    let b_invoke = monitor.invoke(b.permit_id.as_deref().unwrap(), json!({"path": "/b"}));
    assert!(b_invoke.allowed, "{}", b_invoke.reason);
    assert_eq!(monitor.dispatch_count(), before + 1);
    Ok(())
}

#[test]
fn max_de_risk_gate_denies_unwired_irreversible_grants() -> Result<()> {
    let gate = MaxDeRiskGate::default();
    let decision = gate.evaluate("s", "c", "r", Some("irreversible"))?;
    assert!(!decision.allow);
    assert!(decision.reason.contains("signed Max-DE"));
    Ok(())
}

const SIGNATURE_SCHEMA_VERSION: &str = "velvet.signature.v2";

fn verdict_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[21u8; 32])
}

fn verdict_verifying_key_bytes(signing_key: &SigningKey) -> [u8; 32] {
    signing_key.verifying_key().to_bytes()
}

fn rfc3339_z(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn signed_verdict_certificate(
    verdict: &str,
    expires_at: DateTime<Utc>,
    signing_key: &SigningKey,
) -> Value {
    let tenant_id = "tenant-test";
    let key_id = "velvet:maxde:local";
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
            "decision_id": "dec_closure_00007",
            "decision_class": "retire_tool_route",
            "target_id_hash": format!("sha256:{}", sha256_hex(b"vault/secret:read")),
        },
        "verdict": verdict,
        "claim_currency": "BP",
        "parameters": {
            "delta": 0.05,
            "gate_c": 1.5,
            "rho": 0.2,
            "method": "exact_dp",
            "baseline_mode": "posterior_candidate_excluded"
        },
        "hypotheses": ["exchangeable_rounds_within_window"],
        "prices": {
            "inspection": {"expected_rounds_to_gate_crossing": 12.5},
            "tail": {
                "probability_bound": 0.01,
                "crossing_probability": 0.004,
                "drift_penalty": 0.0,
                "posterior_expected_shortfall": 0.02
            }
        },
        "validity": {
            "issued_at": issued_at,
            "not_before": issued_at,
            "expires_at": rfc3339_z(expires_at),
            "horizon_rounds": 128.0,
            "rounds_remaining": 64.0,
            "recertification": "required_inspection_on_expiry"
        },
        "fleet": null,
        "evidence": {
            "inputs_hash": format!("sha256:{}", sha256_hex(b"verdict-inputs")),
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
        "purpose": PURPOSE_VERDICT_CERTIFICATE,
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
        "purpose": PURPOSE_VERDICT_CERTIFICATE,
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

fn irreversible_contract() -> Value {
    json!({
        "contract_id": "test/irreversible",
        "initial_envelope": [],
        "grant_rules": [{
            "subgoal": "read_once",
            "capability": "secret:read",
            "resource": "vault:/k",
            "single_dispatch": true,
            "risk_class": "irreversible",
            "max_grants": 3
        }],
        "closure_predicates": [{"subgoal": "read_once", "kind": "on_signal"}],
        "deny_rules": []
    })
}

#[test]
fn verdict_risk_gate_allows_fresh_safe_kill_certificate() -> Result<()> {
    let signing_key = verdict_signing_key();
    let now = Utc::now();
    let certificate =
        signed_verdict_certificate("safe_kill", now + Duration::hours(1), &signing_key);
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&signing_key))
        .with_certificate(certificate.clone())
        .with_clock(move || now);
    let decision = gate.evaluate("read_once", "secret:read", "vault:/k", Some("irreversible"))?;
    assert!(decision.allow, "{}", decision.reason);
    assert_eq!(decision.certificate, Some(certificate));
    Ok(())
}

#[test]
fn verdict_risk_gate_denies_expired_certificate_with_inspection_reason() -> Result<()> {
    let signing_key = verdict_signing_key();
    let expires_at = Utc::now() - Duration::minutes(10);
    let certificate = signed_verdict_certificate("safe_kill", expires_at, &signing_key);
    let after_expiry = expires_at + Duration::minutes(1);
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&signing_key))
        .with_certificate(certificate)
        .with_clock(move || after_expiry);
    let decision = gate.evaluate("read_once", "secret:read", "vault:/k", Some("irreversible"))?;
    assert!(!decision.allow);
    assert_eq!(decision.reason, "verdict_expired_requires_inspection");
    Ok(())
}

#[test]
fn verdict_risk_gate_denies_absent_certificate() -> Result<()> {
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&verdict_signing_key()));
    let decision = gate.evaluate("read_once", "secret:read", "vault:/k", Some("irreversible"))?;
    assert!(!decision.allow);
    assert_eq!(
        decision.reason,
        "irreversible grants require a valid verdict certificate"
    );
    Ok(())
}

#[test]
fn verdict_risk_gate_denies_non_safe_kill_certificate() -> Result<()> {
    let signing_key = verdict_signing_key();
    let now = Utc::now();
    let certificate = signed_verdict_certificate(
        "required_inspection",
        now + Duration::hours(1),
        &signing_key,
    );
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&signing_key))
        .with_certificate(certificate)
        .with_clock(move || now);
    let decision = gate.evaluate("read_once", "secret:read", "vault:/k", Some("irreversible"))?;
    assert!(!decision.allow);
    assert_eq!(decision.reason, "verdict_not_safe_kill");
    Ok(())
}

#[test]
fn verdict_risk_gate_denies_certificate_signed_by_untrusted_key() -> Result<()> {
    let trusted = verdict_signing_key();
    let untrusted = SigningKey::from_bytes(&[22u8; 32]);
    let now = Utc::now();
    let certificate = signed_verdict_certificate("safe_kill", now + Duration::hours(1), &untrusted);
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&trusted))
        .with_certificate(certificate)
        .with_clock(move || now);
    let decision = gate.evaluate("read_once", "secret:read", "vault:/k", Some("irreversible"))?;
    assert!(!decision.allow);
    assert_eq!(
        decision.reason,
        "irreversible grants require a valid verdict certificate"
    );
    Ok(())
}

#[test]
fn verdict_risk_gate_allows_non_irreversible_grants_without_certificate() -> Result<()> {
    let gate = VerdictRiskGate::new(verdict_verifying_key_bytes(&verdict_signing_key()));
    assert!(gate.evaluate("s", "c", "r", None)?.allow);
    assert!(gate.evaluate("s", "c", "r", Some("reversible"))?.allow);
    Ok(())
}

#[test]
fn irreversible_grant_lifecycle_requires_fresh_verdict_certificate() -> Result<()> {
    let signing_key = verdict_signing_key();
    let key_bytes = verdict_verifying_key_bytes(&signing_key);
    let now = Utc::now();

    // Fresh safe_kill certificate: the grant is admitted and invokable.
    let temp = TempDir::new()?;
    let fresh = signed_verdict_certificate("safe_kill", now + Duration::hours(1), &signing_key);
    let mut fresh_monitor = monitor(&temp, irreversible_contract())?.with_risk_gate(Arc::new(
        VerdictRiskGate::new(key_bytes)
            .with_certificate(fresh)
            .with_clock(move || now),
    ));
    fresh_monitor.open_subgoal("read_once")?;
    let grant = fresh_monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(grant.allowed, "{}", grant.reason);
    let invoke = fresh_monitor.invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}));
    assert!(invoke.allowed, "{}", invoke.reason);

    // Expired certificate: the grant is denied with the inspection reason.
    let temp = TempDir::new()?;
    let expired =
        signed_verdict_certificate("safe_kill", now - Duration::minutes(10), &signing_key);
    let mut expired_monitor = monitor(&temp, irreversible_contract())?.with_risk_gate(Arc::new(
        VerdictRiskGate::new(key_bytes)
            .with_certificate(expired)
            .with_clock(move || now),
    ));
    expired_monitor.open_subgoal("read_once")?;
    let denied = expired_monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(!denied.allowed);
    assert!(
        denied
            .reason
            .contains("verdict_expired_requires_inspection"),
        "{}",
        denied.reason
    );
    assert_eq!(expired_monitor.dispatch_count(), 0);

    // Absent certificate: the grant is denied outright.
    let temp = TempDir::new()?;
    let mut absent_monitor = monitor(&temp, irreversible_contract())?
        .with_risk_gate(Arc::new(VerdictRiskGate::new(key_bytes)));
    absent_monitor.open_subgoal("read_once")?;
    let denied = absent_monitor.request(
        "read_once",
        "secret:read",
        "vault:/k",
        json!({"path": "/k"}),
    );
    assert!(!denied.allowed);
    assert!(
        denied
            .reason
            .contains("irreversible grants require a valid verdict certificate"),
        "{}",
        denied.reason
    );
    assert_eq!(absent_monitor.dispatch_count(), 0);
    Ok(())
}

#[test]
fn verifier_rejects_broken_lifecycle_frame_signature() -> Result<()> {
    let temp = TempDir::new()?;
    let (config, _, _, _) = context(temp.path(), &["secret:read"])?;
    record_lifecycle_ledger_event(
        &config,
        &velvet_rope_proxy::LifecycleLedgerEvent {
            event: "grant".to_string(),
            subgoal_id_hash: hash_identifier("read_once"),
            epoch: 0,
            trigger: None,
            capability: Some("secret:read".to_string()),
            resource: Some("vault:/k".to_string()),
            permit_id: None,
            permit_hash: None,
            receipt_hash: None,
            reason: Some("test".to_string()),
            details: json!({}),
        },
    )?;
    let mut bytes = fs::read(temp.path().join("closure.vledger"))?;
    let needle = b"\"signature\":\"";
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
        + needle.len();
    bytes[start] = if bytes[start] == b'a' { b'b' } else { b'a' };
    let error = verify_binary_ledger_bytes(&bytes).unwrap_err();
    assert_eq!(error.kind(), BinaryLedgerDecodeErrorKind::SignatureMismatch);
    Ok(())
}

#[test]
fn verifier_rejects_unknown_lifecycle_record_type() -> Result<()> {
    let temp = TempDir::new()?;
    let (config, _, _, _) = context(temp.path(), &["secret:read"])?;
    record_lifecycle_ledger_event(
        &config,
        &velvet_rope_proxy::LifecycleLedgerEvent {
            event: "grant".to_string(),
            subgoal_id_hash: hash_identifier("read_once"),
            epoch: 0,
            trigger: None,
            capability: Some("secret:read".to_string()),
            resource: Some("vault:/k".to_string()),
            permit_id: None,
            permit_hash: None,
            receipt_hash: None,
            reason: Some("test".to_string()),
            details: json!({}),
        },
    )?;
    let bytes = fs::read(temp.path().join("closure.vledger"))?;
    let frames = decode_binary_ledger_frames(&bytes)?;
    let mut record = frames[0].payload.clone();
    record["record_type"] = json!("forged_lifecycle_event");
    record["record_hash"] = Value::Null;
    record["record_hash"] = json!(value_hash(&record_without_hash(&record)));
    assert!(verify_oap_ledger_chain(&[record]).is_err());
    Ok(())
}

#[test]
fn merkle_root_covers_lifecycle_records() -> Result<()> {
    let temp = TempDir::new()?;
    let mut monitor = monitor(&temp, base_contract())?;
    let grant = grant(&mut monitor);
    assert!(
        monitor
            .invoke(grant.permit_id.as_deref().unwrap(), json!({"path": "/k"}))
            .allowed
    );
    let bytes = fs::read(temp.path().join("closure.vledger"))?;
    let frames = verify_binary_ledger_bytes(&bytes)?;
    let record_hashes = frames
        .iter()
        .map(|frame| frame.payload["record_hash"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let lifecycle_index = frames
        .iter()
        .position(|frame| {
            frame.payload.get("record_type").and_then(Value::as_str)
                == Some("closure_lifecycle_event")
        })
        .unwrap();
    let root = simple_merkle_root(&record_hashes);
    assert!(verify_simple_inclusion(
        &record_hashes,
        lifecycle_index,
        &record_hashes[lifecycle_index],
        &root
    ));
    Ok(())
}

fn context(
    root: &Path,
    tool_names: &[&str],
) -> Result<(
    ProxyConfig,
    velvet_rope_proxy::PolicyBundleProof,
    velvet_core::PolicyGraph,
    ToolInventory,
)> {
    ensure_signing_env();
    let policy = write_policy_bundle(root)?;
    let tools = tool_names
        .iter()
        .map(|name| test_tool(name))
        .collect::<Vec<_>>();
    let approvals = tools
        .iter()
        .map(|tool| -> Result<ToolApproval> {
            Ok(ToolApproval {
                server: "vault".to_string(),
                name: tool["name"].as_str().unwrap().to_string(),
                approved_schema_hash: tool_schema_hash(tool)?,
                risk_class: RiskClass::Low,
                approval_tier: ApprovalTier::AutoApprove,
                ..ToolApproval::default()
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let config = ProxyConfig {
        mode: EnforcementMode::Development,
        identity: IdentityConfig {
            tenant_id: "tenant-test".to_string(),
            environment: "local".to_string(),
            product_surface: "velvet_inline_gateway.mcp".to_string(),
            subject_id: Some("user-test".to_string()),
            agent_id: Some("agent-test".to_string()),
            client_id: Some("client-test".to_string()),
            session_id: Some("session-test".to_string()),
        },
        oap: OapConfig {
            passport_created_at: Some("2026-05-28T00:00:00Z".to_string()),
            passport_updated_at: Some("2026-05-28T00:00:00Z".to_string()),
            require_max_de_certificate: false,
            require_max_de_for_all_tool_calls: false,
            allow_missing_max_de_in_development: true,
            ..OapConfig::default()
        },
        transport: TransportKind::Fake,
        upstream: UpstreamConfig {
            server: "vault".to_string(),
            ..UpstreamConfig::default()
        },
        policy,
        tools: approvals,
        approvals: Vec::new(),
        approval_receipts: ApprovalReceiptConfig {
            require_signature: false,
            allow_unsigned_local_demo_only: true,
            trusted_keys: Vec::new(),
        },
        method_dispositions: MethodDispositionConfig::default(),
        ledger_path: root.join("closure.vledger"),
        ledger: LedgerConfig::default(),
        control_plane: ControlPlaneConfig::default(),
        evidence: EvidenceConfig::default(),
        signing: SigningConfig::default(),
        gateway: GatewayConfig::default(),
        thread_path: Some(root.join("thread.jsonl")),
        inventory_path: Some(root.join("inventory.json")),
        approval_requests_path: Some(root.join("approval_requests.jsonl")),
        evidence_pack_path: Some(root.join("evidence_pack.json")),
        schema_drift_action: velvet_rope_proxy::SchemaDriftAction::Deny,
        limits: LimitConfig::default(),
        auth: AuthConfig::default(),
        http: HttpConfig::default(),
        forwarding: ForwardingConfig::default(),
        demo_requests: Vec::new(),
    };
    let inventory = ToolInventory::build(&config, &tools)?;
    let bundle_proof = verify_policy_bundle(&config.policy)?;
    let policy_graph =
        load_policy_graph(&config.policy.dir).map_err(|errors| anyhow::anyhow!("{errors:?}"))?;
    Ok((config, bundle_proof, policy_graph, inventory))
}

fn write_policy_bundle(root: &Path) -> Result<PolicyConfig> {
    let policy_dir = root.join("policies");
    fs::create_dir_all(&policy_dir)?;
    fs::write(
        policy_dir.join("mcp_demo.yaml"),
        velvet_rope_proxy::EXAMPLE_POLICY,
    )?;
    let manifest_path = root.join("policy-bundle.yaml");
    let manifest = PolicyBundleManifest {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_hash: policy_dir_hash(&policy_dir, &manifest_path)?,
        expires_at: (Utc::now() + Duration::days(2)).to_rfc3339(),
        signature: None,
    };
    fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;
    Ok(PolicyConfig {
        dir: policy_dir,
        chain: "mcp_demo".to_string(),
        bundle_manifest: manifest_path,
        require_signature: false,
        trusted_signature_public_key_hex: None,
        trusted_signature_public_key_hex_env: None,
    })
}

fn test_tool(name: &str) -> Value {
    json!({
        "name": name,
        "description": "test tool",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": false
        }
    })
}

fn ensure_signing_env() {
    unsafe {
        std::env::set_var(
            "VELVET_OAP_ED25519_PRIVATE_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        );
        std::env::set_var(
            "VELVET_MAXDE_ED25519_PRIVATE_KEY",
            "0909090909090909090909090909090909090909090909090909090909090909",
        );
        std::env::set_var(
            "VELVET_MAXDE_ED25519_PUBLIC_KEY",
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
        );
    }
}

fn record_without_hash(record: &Value) -> Value {
    let mut value = record.clone();
    value.as_object_mut().unwrap().remove("record_hash");
    value
}

fn simple_merkle_root(record_hashes: &[String]) -> String {
    value_hash(&json!({ "record_hashes": record_hashes }))
}

fn verify_simple_inclusion(record_hashes: &[String], index: usize, leaf: &str, root: &str) -> bool {
    record_hashes
        .get(index)
        .is_some_and(|actual| actual == leaf)
        && simple_merkle_root(record_hashes) == root
}
