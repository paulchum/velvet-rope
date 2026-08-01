use super::*;

#[test]
fn json_rpc_classifier_distinguishes_message_shapes() {
    assert!(matches!(
        classify_json_rpc(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})),
        JsonRpcMessageKind::Request { .. }
    ));
    assert!(matches!(
        classify_json_rpc(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
        JsonRpcMessageKind::Notification { .. }
    ));
    assert!(matches!(
        classify_json_rpc(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        JsonRpcMessageKind::Response { .. }
    ));
    assert!(matches!(
        classify_json_rpc(&json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])),
        JsonRpcMessageKind::Batch
    ));
    assert!(matches!(
        classify_json_rpc(&json!({"id": 1, "method": "ping"})),
        JsonRpcMessageKind::Invalid(_)
    ));
}

#[tokio::test]
async fn http_post_notification_returns_202_without_body() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;

    let response = http_post_inner(
        state,
        http_headers(Some(&session)),
        json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_body_string(response).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn http_post_json_rpc_response_requires_pending_server_request_id() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;

    let wrong_id = http_post_inner(
        state.clone(),
        http_headers(Some(&session)),
        json!({"jsonrpc": "2.0", "id": "wrong-request", "result": {"ok": true}}),
    )
    .await;
    assert!(
        wrong_id
            .unwrap_err()
            .to_string()
            .contains("does not match a pending")
    );
    remember_server_request_id(&state, Some(&session), &json!("server-request"))?;

    let response = http_post_inner(
        state,
        http_headers(Some(&session)),
        json!({"jsonrpc": "2.0", "id": "server-request", "result": {"ok": true}}),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_body_string(response).await?.is_empty());
    assert!(
        upstream
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.get("method").is_none() && request.get("result").is_some())
    );
    Ok(())
}

#[tokio::test]
async fn http_post_request_can_return_json() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;

    let response = http_post_inner(
        state,
        http_headers(Some(&session)),
        call("search_change_requests"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&response_body_string(response).await?)?;
    assert!(
        body.pointer("/result/_meta/open_agent_passport_decision")
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn http_post_request_can_proxy_upstream_sse_with_terminal_response() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;
    let mut request = call("search_change_requests");
    request
        .pointer_mut("/params/arguments")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("transport".to_string(), json!("sse"));

    let response = http_post_inner(state, http_headers(Some(&session)), request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("text/event-stream")),
        Some(true)
    );
    let body = response_body_string(response).await?;
    assert!(body.contains("id: sse_"));
    assert!(body.contains("open_agent_passport_decision"));
    Ok(())
}

#[tokio::test]
async fn http_get_requires_sse_accept() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;

    let response = http_get_inner(state, HeaderMap::new()).await;

    assert!(response.is_err());
    assert!(response.unwrap_err().to_string().contains("Accept"));
    Ok(())
}

#[tokio::test]
async fn http_get_opens_sse_stream() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert("MCP-Session-Id", HeaderValue::from_str(&session)?);
    headers.insert(
        "MCP-Protocol-Version",
        HeaderValue::from_static(MCP_SPEC_TARGET),
    );

    let response = http_get_inner(state, headers).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body_string(response).await?;
    assert!(body.contains("notifications/progress"));
    assert!(body.contains("id: sse_"));
    assert_eq!(upstream.get_count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn last_event_id_replays_only_matching_stream_events() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let stream_id = create_sse_stream_buffer(&state, None)?;
    let events = assign_and_buffer_sse_events(
        &state,
        None,
        &stream_id,
        vec![
            SseWireEvent::data_json(json!({"jsonrpc": "2.0", "id": 1, "result": {"n": 1}}))?,
            SseWireEvent::data_json(json!({"jsonrpc": "2.0", "id": 2, "result": {"n": 2}}))?,
        ],
    )?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        "Last-Event-ID",
        HeaderValue::from_str(events[0].id.as_ref().unwrap())?,
    );

    let response = http_get_inner(state, headers).await?;
    let body = response_body_string(response).await?;

    assert!(!body.contains("\"n\":1"));
    assert!(body.contains("\"n\":2"));
    Ok(())
}

#[tokio::test]
async fn multiple_sse_streams_do_not_receive_duplicate_broadcasts() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert("MCP-Session-Id", HeaderValue::from_str(&session)?);
    headers.insert(
        "MCP-Protocol-Version",
        HeaderValue::from_static(MCP_SPEC_TARGET),
    );

    let first = response_body_string(http_get_inner(state.clone(), headers.clone()).await?).await?;
    let second = response_body_string(http_get_inner(state, headers).await?).await?;

    assert_ne!(first, second);
    assert_eq!(upstream.get_count.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn initialize_captures_session_and_missing_or_unknown_session_fails() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;
    assert_eq!(session, "test-upstream-session");

    let missing = http_post_inner(
        state.clone(),
        http_headers(None),
        json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}),
    )
    .await;
    assert!(
        missing
            .unwrap_err()
            .to_string()
            .contains("session id is required")
    );

    let unknown = http_post_inner(
        state,
        http_headers(Some("missing-session")),
        json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}),
    )
    .await;
    assert!(
        unknown
            .unwrap_err()
            .to_string()
            .contains("unknown MCP session")
    );
    Ok(())
}

#[tokio::test]
async fn delete_terminates_session_and_forwards_upstream() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;

    let response = http_delete_inner(state.clone(), http_headers(Some(&session))).await?;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(upstream.delete_count.load(Ordering::SeqCst), 1);
    let unknown = http_post_inner(
        state,
        http_headers(Some(&session)),
        json!({"jsonrpc": "2.0", "id": "ping", "method": "ping"}),
    )
    .await;
    assert!(
        unknown
            .unwrap_err()
            .to_string()
            .contains("unknown MCP session")
    );
    Ok(())
}

#[tokio::test]
async fn origin_and_protocol_version_are_validated() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let mut state = http_state(temp.path(), endpoint)?;
    Arc::get_mut(&mut state.config)
        .unwrap()
        .http
        .allowed_origins = vec!["https://allowed.example".to_string()];
    let mut headers = http_headers(None);
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://blocked.example"),
    );
    let invalid_origin = http_post_inner(
        state.clone(),
        headers,
        json!({"jsonrpc": "2.0", "id": "ping", "method": "ping"}),
    )
    .await;
    assert!(invalid_origin.unwrap_err().to_string().contains("Origin"));

    let mut headers = http_headers(None);
    headers.insert(
        "MCP-Protocol-Version",
        HeaderValue::from_static("1999-01-01"),
    );
    let invalid_version = http_post_inner(
        state,
        headers,
        json!({"jsonrpc": "2.0", "id": "ping", "method": "ping"}),
    )
    .await;
    assert!(
        invalid_version
            .unwrap_err()
            .to_string()
            .contains("unsupported MCP protocol")
    );
    Ok(())
}

#[tokio::test]
async fn blocked_http_tool_call_never_reaches_upstream() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;

    let response = http_post_inner(
        state,
        http_headers(Some(&session)),
        call("delete_change_request"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&response_body_string(response).await?)?
            .pointer("/error/code")
            .and_then(Value::as_i64),
        Some(-32071)
    );
    assert!(!upstream.requests.lock().unwrap().iter().any(|request| {
        request.get("method").and_then(Value::as_str) == Some("tools/call")
            && request.pointer("/params/name").and_then(Value::as_str)
                == Some("delete_change_request")
    }));
    Ok(())
}

#[tokio::test]
async fn oversized_http_response_fails_safely_and_records_failure() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let mut state = http_state(temp.path(), endpoint)?;
    let session = initialize_http_session(&state).await?;
    Arc::get_mut(&mut state.config)
        .unwrap()
        .limits
        .max_response_bytes = 64;
    let mut request = call("search_change_requests");
    request
        .pointer_mut("/params/arguments")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("transport".to_string(), json!("huge"));

    let response = http_post_inner(state, http_headers(Some(&session)), request).await?;
    let body: Value = serde_json::from_str(&response_body_string(response).await?)?;

    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32060)
    );
    let records = ledger_records(temp.path())?;
    assert_eq!(
        records
            .last()
            .and_then(|record| record.get("upstream_status"))
            .and_then(Value::as_str),
        Some("indeterminate")
    );
    Ok(())
}

#[tokio::test]
async fn subject_header_is_ignored_by_default() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let mut config = test_config(temp.path())?;
    config.transport = TransportKind::StreamableHttp;
    config.upstream.endpoint = Some(endpoint);
    config.http.allow_plaintext_loopback_upstream = true;
    config.identity.subject_id = None;
    config
        .tools
        .iter_mut()
        .find(|tool| tool.name == "search_change_requests")
        .ok_or_else(|| anyhow!("missing test tool"))?
        .allowed_subjects = vec!["alice".to_string()];
    let state = http_state_from_config(config)?;
    let session_id = initialize_http_session(&state).await?;

    let denied = http_post_inner(
        state.clone(),
        http_headers(Some(&session_id)),
        call("search_change_requests"),
    )
    .await?;
    let denied_body: Value = serde_json::from_str(&response_body_string(denied).await?)?;
    assert_eq!(
        denied_body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32070)
    );

    let mut headers = http_headers(Some(&session_id));
    headers.insert("x-velvet-subject-id", HeaderValue::from_static("alice"));
    let still_denied = http_post_inner(state, headers, call("search_change_requests")).await?;
    let still_denied_body: Value =
        serde_json::from_str(&response_body_string(still_denied).await?)?;
    assert_eq!(
        still_denied_body
            .pointer("/error/code")
            .and_then(Value::as_i64),
        Some(-32070)
    );
    Ok(())
}

#[tokio::test]
async fn subject_header_opt_in_drives_http_authorization_and_ledger_identity() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let mut config = test_config(temp.path())?;
    config.transport = TransportKind::StreamableHttp;
    config.upstream.endpoint = Some(endpoint);
    config.http.allow_plaintext_loopback_upstream = true;
    config.identity.subject_id = None;
    config.auth.trust_subject_header = true;
    config
        .tools
        .iter_mut()
        .find(|tool| tool.name == "search_change_requests")
        .ok_or_else(|| anyhow!("missing test tool"))?
        .allowed_subjects = vec!["alice".to_string()];
    let state = http_state_from_config(config)?;
    let session_id = initialize_http_session(&state).await?;

    let mut headers = http_headers(Some(&session_id));
    headers.insert("x-velvet-subject-id", HeaderValue::from_static("alice"));
    let allowed = http_post_inner(state, headers, call("search_change_requests")).await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    let allowed_body: Value = serde_json::from_str(&response_body_string(allowed).await?)?;
    assert!(allowed_body.get("result").is_some());

    let records = ledger_records(temp.path())?;
    let pre_record = records
        .iter()
        .find(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("pre_execution_decision")
        })
        .ok_or_else(|| anyhow!("missing pre-execution record"))?;
    assert_eq!(
        pre_record.get("subject_id_hash").and_then(Value::as_str),
        Some(hash_optional_identifier(Some("alice")).as_str())
    );
    assert_eq!(
        pre_record
            .pointer("/oap_passport/metadata/subject_id")
            .and_then(Value::as_str),
        Some("alice")
    );
    Ok(())
}

#[tokio::test]
async fn upstream_private_bearer_is_injected_without_reusing_downstream_authorization() -> Result<()>
{
    let temp = TempDir::new()?;
    let token_env = "VELVET_TEST_PRIVATE_MCP_INJECT_TOKEN";
    set_test_env(token_env, "private-upstream-token");
    let (endpoint, upstream) = spawn_test_http_upstream().await?;
    let mut config = test_config(temp.path())?;
    config.transport = TransportKind::StreamableHttp;
    config.upstream.endpoint = Some(endpoint);
    config.http.allow_plaintext_loopback_upstream = true;
    config.upstream.boundary = private_mcp_boundary_config(token_env);
    let state = http_state_from_config(config)?;
    let mut headers = http_headers(None);
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer downstream-agent-token"),
    );
    let response = http_post_inner(
        state,
        headers,
        json!({
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_SPEC_TARGET,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = upstream.headers.lock().unwrap();
    let upstream_authorization = headers
        .first()
        .and_then(|headers| headers.get("authorization"))
        .ok_or_else(|| anyhow!("missing upstream authorization header"))?;
    assert_eq!(upstream_authorization, "Bearer private-upstream-token");
    assert_ne!(upstream_authorization, "Bearer downstream-agent-token");
    remove_test_env(token_env);
    Ok(())
}

#[tokio::test]
async fn http_error_response_omits_internal_error_details() -> Result<()> {
    let temp = TempDir::new()?;
    let (endpoint, _upstream) = spawn_test_http_upstream().await?;
    let state = http_state(temp.path(), endpoint)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "MCP-Session-Id",
        HeaderValue::from_static("missing-session"),
    );

    let response = http_delete(State(state), headers).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_body_string(response).await?;
    assert!(!body.contains("unknown MCP session"));
    assert!(body.contains("MCP session or event was not found"));
    Ok(())
}

#[test]
fn json_rpc_batch_omits_notification_responses_and_parse_errors_are_protocol_errors() -> Result<()>
{
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(json!([
            {"jsonrpc": "2.0", "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
        ]))?
        .unwrap();
    assert_eq!(response.as_array().map(Vec::len), Some(1));
    let parse_error = runtime.handle_raw_message("{not-json")?.unwrap();
    assert_eq!(
        parse_error.pointer("/error/code").and_then(Value::as_i64),
        Some(-32700)
    );
    Ok(())
}
