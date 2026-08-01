use super::*;

#[test]
pub(super) fn required_certificate_absence_blocks_before_forward() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    for tool in &mut config.tools {
        if tool.name == "search_change_requests" {
            tool.max_de = None;
        }
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
fn ledger_write_failure_blocks_before_upstream_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    let blocked_parent = temp.path().join("ledger_parent_is_file");
    fs::write(&blocked_parent, "not a directory")?;
    config.ledger_path = blocked_parent.join("ledger.vledger");
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;

    let result = runtime.handle_message(call("search_change_requests"));

    assert!(result.is_err());
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0,
        "strict ledger write failure must fail before forwarding"
    );
    Ok(())
}

#[test]
fn missing_oap_signer_blocks_before_upstream_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.oap.oap_private_key_env = "VELVET_TEST_MISSING_OAP_KEY".to_string();
    unsafe {
        std::env::remove_var("VELVET_TEST_MISSING_OAP_KEY");
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
fn missing_velvet_signer_blocks_before_upstream_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.oap.velvet_private_key_env = "VELVET_TEST_MISSING_MAXDE_KEY".to_string();
    unsafe {
        std::env::remove_var("VELVET_TEST_MISSING_MAXDE_KEY");
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
fn oap_decision_subject_is_downstream_agent_not_proxy() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let records = ledger_records(temp.path())?;
    let decision = records[0]
        .get("oap_decision")
        .ok_or_else(|| anyhow!("missing decision"))?;
    let passport = records[0]
        .get("oap_passport")
        .ok_or_else(|| anyhow!("missing passport"))?;
    assert_eq!(
        passport
            .pointer("/metadata/agent_id")
            .and_then(Value::as_str),
        Some("agent-test")
    );
    assert_ne!(
        decision.get("agent_id").and_then(Value::as_str),
        Some(PROXY_NAME)
    );
    let expected_subject_hash = hash_optional_identifier(Some("user-test"));
    assert_eq!(
        records[0].get("subject_id_hash").and_then(Value::as_str),
        Some(expected_subject_hash.as_str())
    );
    Ok(())
}

#[test]
fn passport_digest_changes_when_subject_authority_changes() -> Result<()> {
    let temp = TempDir::new()?;
    let mut first = runtime(temp.path())?;
    first.handle_message(call("search_change_requests"))?;
    let first_records = ledger_records(temp.path())?;
    let first_digest = first_records[0]
        .get("passport_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing first passport digest"))?
        .to_string();

    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.identity.subject_id = Some("other-user".to_string());
    let mut second = ProxyRuntime::new(config, FakeMcpServer::default())?;
    second.handle_message(call("search_change_requests"))?;
    let second_records = ledger_records(temp.path())?;
    let second_digest = second_records[0]
        .get("passport_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing second passport digest"))?;
    assert_ne!(first_digest, second_digest);
    Ok(())
}
