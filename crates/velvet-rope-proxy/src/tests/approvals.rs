use super::*;

#[test]
fn signed_approval_receipt_cannot_bypass_budget_requirement() -> Result<()> {
    let temp = TempDir::new()?;
    let mut first_runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = first_runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let receipt = signed_approval_receipt_for_request(&approval_request, "aprct_test_001")?;
    attach_approval_receipt(&mut request, receipt)?;
    let response = first_runtime.handle_message(request.clone())?.unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(
        first_runtime
            .upstream
            .execution_count("create_change_request"),
        0
    );
    let replay = first_runtime.handle_message(request)?.unwrap();
    assert_eq!(
        replay.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(
        first_runtime
            .upstream
            .execution_count("create_change_request"),
        0
    );
    Ok(())
}

#[test]
fn approval_receipt_with_used_at_is_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let mut receipt = signed_approval_receipt_for_request(&approval_request, "aprct_used")?;
    receipt.used_at = Some(Utc::now().to_rfc3339());
    receipt.receipt_hash = approval_receipt_hash(&receipt)?;
    attach_approval_receipt(&mut request, receipt)?;
    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn unsigned_approval_receipt_rejected_in_strict_mode() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let receipt =
        unsigned_approval_receipt_for_request(&approval_request, "aprct_unsigned_strict")?;
    attach_approval_receipt(&mut request, receipt)?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn forged_approval_receipt_hash_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let mut receipt = signed_approval_receipt_for_request(&approval_request, "aprct_forged_hash")?;
    receipt.nonce = "attacker-recomputed-hash".to_string();
    receipt.receipt_hash = approval_receipt_hash(&receipt)?;
    attach_approval_receipt(&mut request, receipt)?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn approval_receipt_signed_by_unknown_key_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let unknown_key = SigningKey::from_bytes(&[8u8; 32]);
    let receipt = signed_approval_receipt_for_request_with_key_and_purpose(
        &approval_request,
        "aprct_unknown_key",
        &unknown_key,
        APPROVAL_RECEIPT_SCHEMA_VERSION,
    )?;
    attach_approval_receipt(&mut request, receipt)?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn approval_receipt_wrong_purpose_rejected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let receipt = signed_approval_receipt_for_request_with_key_and_purpose(
        &approval_request,
        "aprct_wrong_purpose",
        &test_approval_signing_key(),
        "velvet.not_approval_receipt.v1",
    )?;
    attach_approval_receipt(&mut request, receipt)?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn approval_receipt_cannot_override_block_decision() -> Result<()> {
    let temp = TempDir::new()?;
    let config = test_config(temp.path())?;
    let mut request = call("delete_change_request");
    let approval_request = approval_request_for_test_call(&config, &request)?;
    let receipt = signed_approval_receipt_for_request(&approval_request, "aprct_block_override")?;
    attach_approval_receipt(&mut request, receipt)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(runtime.upstream.execution_count("delete_change_request"), 0);
    Ok(())
}

#[test]
fn approval_receipt_cannot_execute_without_generated_approval_request() -> Result<()> {
    let temp = TempDir::new()?;
    let config = test_config(temp.path())?;
    let mut request = call("search_change_requests");
    let approval_request = approval_request_for_test_call(&config, &request)?;
    let receipt =
        signed_approval_receipt_for_request(&approval_request, "aprct_without_generated_request")?;
    attach_approval_receipt(&mut request, receipt)?;
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;

    let rejected = runtime.handle_message(request)?.unwrap();
    assert_eq!(
        rejected.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn signed_approval_receipt_replay_fails_after_runtime_restart() -> Result<()> {
    let temp = TempDir::new()?;
    let mut first_runtime = runtime(temp.path())?;
    let mut request = call("create_change_request");
    let response = first_runtime.handle_message(request.clone())?.unwrap();
    let approval_request = approval_request_from_response(&response)?;
    let receipt = signed_approval_receipt_for_request(&approval_request, "aprct_restart_replay")?;
    attach_approval_receipt(&mut request, receipt)?;

    let first = first_runtime.handle_message(request.clone())?.unwrap();
    assert_eq!(
        first.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(
        first_runtime
            .upstream
            .execution_count("create_change_request"),
        0
    );

    let mut restarted = runtime(temp.path())?;
    let replay = restarted.handle_message(request)?.unwrap();
    assert_eq!(
        replay.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );
    assert_eq!(
        restarted.upstream.execution_count("create_change_request"),
        0
    );
    Ok(())
}
