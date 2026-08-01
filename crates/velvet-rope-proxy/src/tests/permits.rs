use super::*;

#[derive(Debug)]
struct StaticEpochProvider {
    subgoal_id_hash: String,
    epoch: i64,
}

impl PermitEpochProvider for StaticEpochProvider {
    fn current_epoch_for_subgoal_hash(&self, subgoal_id_hash: &str) -> Result<i64> {
        if subgoal_id_hash == self.subgoal_id_hash {
            Ok(self.epoch)
        } else {
            bail!("unexpected subgoal hash")
        }
    }
}

#[test]
fn missing_execution_permit_trust_anchor_blocks_before_upstream_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.oap.velvet_trusted_public_key_env =
        "VELVET_TEST_MISSING_EXECUTION_PERMIT_PUBLIC_KEY".to_string();
    unsafe {
        std::env::remove_var("VELVET_TEST_MISSING_EXECUTION_PERMIT_PUBLIC_KEY");
    }
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn model_supplied_execution_metadata_is_ignored_before_stdio_dispatch() -> Result<()> {
    let temp = TempDir::new()?;
    let request = hostile_model_execution_metadata_call("search_change_requests");
    let sanitized = crate::execution::strip_model_controlled_execution_metadata(&request);
    let mut config = test_config(temp.path())?;
    config.forwarding.attach_execution = true;
    let mut runtime = ProxyRuntime::new(config, RecordingMcpServer::default())?;

    let response = runtime.handle_message(request)?.unwrap();

    assert!(response.get("result").is_some());
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    let forwarded = runtime
        .upstream
        .requests
        .first()
        .ok_or_else(|| anyhow!("missing forwarded request"))?;
    assert_eq!(
        forwarded.pointer("/params/_meta/user_request"),
        Some(&json!("find open changes"))
    );
    assert!(
        forwarded
            .pointer("/params/_meta/velvet_admission")
            .is_none()
    );
    let permit = forwarded
        .pointer("/params/_meta/velvet_execution/execution_permit")
        .ok_or_else(|| anyhow!("missing injected execution permit"))?;
    assert_ne!(
        permit.get("permit_id").and_then(Value::as_str),
        Some("attacker-supplied-permit")
    );
    assert!(
        permit
            .get("permit_id")
            .and_then(Value::as_str)
            .is_some_and(|permit_id| permit_id.starts_with("vpermit_"))
    );
    assert_eq!(
        permit
            .pointer("/scope/request_hash")
            .and_then(Value::as_str),
        Some(request_hash_hex(&sanitized).as_str())
    );
    Ok(())
}

#[tokio::test]
async fn model_supplied_execution_metadata_is_ignored_before_http_dispatch() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let mut config = test_config(temp.path())?;
    config.transport = TransportKind::StreamableHttp;
    config.upstream.endpoint = Some(endpoint);
    config.http.allow_plaintext_loopback_upstream = true;
    config.http.sse_keepalive_seconds = 1;
    config.forwarding.attach_execution = true;
    let state = http_state_from_config(config)?;
    let session = initialize_http_session(&state).await?;
    let request = hostile_model_execution_metadata_call("search_change_requests");
    let sanitized = crate::execution::strip_model_controlled_execution_metadata(&request);

    let response = http_post_inner(state, http_headers(Some(&session)), request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = upstream.requests.lock().unwrap();
    let forwarded = requests
        .iter()
        .find(|request| request.get("method").and_then(Value::as_str) == Some("tools/call"))
        .ok_or_else(|| anyhow!("missing forwarded tools/call request"))?;
    assert_eq!(
        forwarded.pointer("/params/_meta/user_request"),
        Some(&json!("find open changes"))
    );
    assert!(
        forwarded
            .pointer("/params/_meta/velvet_admission")
            .is_none()
    );
    let permit = forwarded
        .pointer("/params/_meta/velvet_execution/execution_permit")
        .ok_or_else(|| anyhow!("missing injected execution permit"))?;
    assert_ne!(
        permit.get("permit_id").and_then(Value::as_str),
        Some("attacker-supplied-permit")
    );
    assert!(
        permit
            .get("permit_id")
            .and_then(Value::as_str)
            .is_some_and(|permit_id| permit_id.starts_with("vpermit_"))
    );
    assert_eq!(
        permit
            .pointer("/scope/request_hash")
            .and_then(Value::as_str),
        Some(request_hash_hex(&sanitized).as_str())
    );
    Ok(())
}

#[test]
fn logical_step_permit_with_matching_epoch_passes_signature_ttl_scope_and_claim() -> Result<()> {
    let temp = TempDir::new()?;
    let runtime = runtime(temp.path())?;
    let request = call("search_change_requests");
    let admission = admit_tool_call(
        &runtime.config,
        &runtime.bundle_proof,
        &runtime.policy_graph,
        &runtime.inventory,
        &request,
        &BTreeSet::new(),
    )?;
    let pre_record = record_pre_execution_ledger(&runtime.config, &request, &admission)?;
    let claim_store = PermitClaimStore::for_ledger_path(&runtime.config.ledger_path);
    let subgoal_id_hash = crate::oap::hash_identifier("read_once");
    let prepared = crate::execution::prepare_execution_with_logical_step(
        &runtime.config,
        &runtime.bundle_proof,
        &request,
        &admission,
        &pre_record,
        &claim_store,
        crate::execution::LogicalPermitBinding {
            subgoal_id_hash: subgoal_id_hash.clone(),
            logical_step: 7,
        },
    )?;
    let provider = StaticEpochProvider {
        subgoal_id_hash,
        epoch: 7,
    };
    let authorized = crate::execution::authorize_execution_with_epoch_provider(
        &runtime.config,
        prepared,
        &claim_store,
        "test",
        &provider,
    )?;
    crate::execution::verify_outbound_request_matches_permit(&request, &authorized)?;
    assert!(
        claim_store
            .claimed_record(&authorized.prepared.permit.permit_id)?
            .is_some()
    );
    assert_eq!(
        authorized.prepared.permit.validity.expires_at_logical_step,
        Some(7)
    );
    Ok(())
}

#[test]
fn stale_logical_step_rejected_before_claim() -> Result<()> {
    let temp = TempDir::new()?;
    let runtime = runtime(temp.path())?;
    let request = call("search_change_requests");
    let admission = admit_tool_call(
        &runtime.config,
        &runtime.bundle_proof,
        &runtime.policy_graph,
        &runtime.inventory,
        &request,
        &BTreeSet::new(),
    )?;
    let pre_record = record_pre_execution_ledger(&runtime.config, &request, &admission)?;
    let claim_store = PermitClaimStore::for_ledger_path(&runtime.config.ledger_path);
    let subgoal_id_hash = crate::oap::hash_identifier("read_once");
    let prepared = crate::execution::prepare_execution_with_logical_step(
        &runtime.config,
        &runtime.bundle_proof,
        &request,
        &admission,
        &pre_record,
        &claim_store,
        crate::execution::LogicalPermitBinding {
            subgoal_id_hash: subgoal_id_hash.clone(),
            logical_step: 1,
        },
    )?;
    let permit_id = prepared.permit.permit_id.clone();
    let provider = StaticEpochProvider {
        subgoal_id_hash,
        epoch: 2,
    };
    let error = crate::execution::authorize_execution_with_epoch_provider(
        &runtime.config,
        prepared,
        &claim_store,
        "test",
        &provider,
    )
    .unwrap_err();
    assert!(error.to_string().contains("logical step"));
    assert!(claim_store.claimed_record(&permit_id)?.is_none());
    Ok(())
}

#[test]
fn logical_step_without_signed_subgoal_binding_fails_closed() -> Result<()> {
    let temp = TempDir::new()?;
    let runtime = runtime(temp.path())?;
    let request = call("search_change_requests");
    let admission = admit_tool_call(
        &runtime.config,
        &runtime.bundle_proof,
        &runtime.policy_graph,
        &runtime.inventory,
        &request,
        &BTreeSet::new(),
    )?;
    let pre_record = record_pre_execution_ledger(&runtime.config, &request, &admission)?;
    let claim_store = PermitClaimStore::for_ledger_path(&runtime.config.ledger_path);
    let subgoal_id_hash = crate::oap::hash_identifier("read_once");
    let mut prepared = crate::execution::prepare_execution_with_logical_step(
        &runtime.config,
        &runtime.bundle_proof,
        &request,
        &admission,
        &pre_record,
        &claim_store,
        crate::execution::LogicalPermitBinding {
            subgoal_id_hash: subgoal_id_hash.clone(),
            logical_step: 1,
        },
    )?;
    prepared.permit.scope.subgoal_id_hash = None;
    let provider = StaticEpochProvider {
        subgoal_id_hash,
        epoch: 1,
    };
    let error = verify_permit_logical_step(&prepared.permit, &provider).unwrap_err();
    assert!(error.to_string().contains("subgoal"));
    Ok(())
}

#[test]
fn legacy_no_logical_step_permit_still_authorizes_with_wall_clock_rules() -> Result<()> {
    let temp = TempDir::new()?;
    let runtime = runtime(temp.path())?;
    let request = call("search_change_requests");
    let admission = admit_tool_call(
        &runtime.config,
        &runtime.bundle_proof,
        &runtime.policy_graph,
        &runtime.inventory,
        &request,
        &BTreeSet::new(),
    )?;
    let pre_record = record_pre_execution_ledger(&runtime.config, &request, &admission)?;
    let claim_store = PermitClaimStore::for_ledger_path(&runtime.config.ledger_path);
    let prepared = crate::execution::prepare_execution(
        &runtime.config,
        &runtime.bundle_proof,
        &request,
        &admission,
        &pre_record,
        &claim_store,
    )?;
    assert!(prepared.permit.scope.subgoal_id_hash.is_none());
    assert!(prepared.permit.validity.expires_at_logical_step.is_none());
    let authorized =
        crate::execution::authorize_execution(&runtime.config, prepared, &claim_store, "test")?;
    crate::execution::verify_outbound_request_matches_permit(&request, &authorized)?;
    Ok(())
}
