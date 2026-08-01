use super::*;

#[test]
fn canonical_mcp_action_hash_uses_sha256_wire_format() -> Result<()> {
    let temp = TempDir::new()?;
    let config = test_config(temp.path())?;
    let hash = canonical_action_hash_for_mcp_request(&config, &call("search_change_requests"))?;
    let digest = hash
        .strip_prefix("sha256:")
        .expect("canonical action hash must identify its algorithm");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    Ok(())
}

#[test]
fn safe_read_admitted_and_reaches_fake_server() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert!(response.get("result").is_some());
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    Ok(())
}

#[test]
fn sensitive_write_escalated_and_never_reaches_fake_server() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(call("create_change_request"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32072)
    );
    assert_eq!(runtime.upstream.execution_count("create_change_request"), 0);
    Ok(())
}

#[test]
fn unknown_tool_denied_before_server_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime.handle_message(call("drop_database"))?.unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(runtime.upstream.execution_count("drop_database"), 0);
    Ok(())
}

#[test]
fn drifted_schema_denied_before_server_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    for tool in &mut config.tools {
        if tool.name == "search_change_requests" {
            tool.approved_schema_hash = "sha256:0000".to_string();
        }
    }
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn destructive_tool_denied_before_server_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(call("delete_change_request"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32071)
    );
    assert_eq!(runtime.upstream.execution_count("delete_change_request"), 0);
    Ok(())
}

#[test]
fn tools_list_only_returns_approved_tools() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))?
        .unwrap();
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap();
    let names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    assert!(names.contains("search_change_requests"));
    assert!(!names.contains("delete_change_request"));
    Ok(())
}

#[test]
fn invalid_maxde_certificate_blocks_before_upstream_execution() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    for tool in &mut config.tools {
        if tool.name == "search_change_requests"
            && let Some(max_de) = &mut tool.max_de
        {
            max_de.decision = MaxDeDecision::Lockout;
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
fn strict_missing_maxde_config_blocks_before_upstream_execution() -> Result<()> {
    required_certificate_absence_blocks_before_forward()
}

#[test]
fn task_methods_and_task_augmented_tool_calls_are_not_forwarded() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(json!({
            "jsonrpc": "2.0",
            "id": "task-method",
            "method": "tasks/get",
            "params": {"id": "task_1"}
        }))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32073)
    );

    let response = runtime
        .handle_message(json!({
            "jsonrpc": "2.0",
            "id": "task-call",
            "method": "tools/call",
            "params": {
                "name": "search_change_requests",
                "arguments": {"query": "service=payments"},
                "task": {"ttl": 60000}
            }
        }))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32073)
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        0
    );
    Ok(())
}

#[test]
fn strict_unknown_method_is_blocked_ledgered_and_not_forwarded() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let response = runtime
        .handle_message(json!({
            "jsonrpc": "2.0",
            "id": "unknown-method",
            "method": "vendor/unknown",
            "params": {"x": 1}
        }))?
        .unwrap();

    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32073)
    );
    assert_eq!(runtime.upstream.execution_count("method:vendor/unknown"), 0);

    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("record_type").and_then(Value::as_str),
        Some("bounded_method_disposition")
    );
    assert_eq!(
        records[0].get("decision").and_then(Value::as_str),
        Some("block")
    );
    assert_eq!(
        records[0]
            .pointer("/persistence_metadata/method")
            .and_then(Value::as_str),
        Some("vendor/unknown")
    );
    assert_eq!(
        records[0]
            .pointer("/persistence_metadata/disposition_source")
            .and_then(Value::as_str),
        Some("strict_default")
    );
    Ok(())
}

#[test]
fn resources_prompts_and_unknown_default_to_recorded_block() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    for method in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "notifications/progress",
        "unknown/method",
    ] {
        let response = runtime
            .handle_message(json!({"jsonrpc": "2.0", "id": method, "method": method}))?
            .unwrap();
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_i64),
            Some(-32073),
            "{method} should be blocked by default"
        );
        assert_eq!(
            runtime
                .upstream
                .execution_count(&format!("method:{method}")),
            0
        );
    }

    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 6);
    assert!(records.iter().all(|record| {
        record.get("record_type").and_then(Value::as_str) == Some("bounded_method_disposition")
            && record.get("decision").and_then(Value::as_str) == Some("block")
            && record
                .get("upstream_status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "not_forwarded")
    }));
    Ok(())
}

#[test]
fn explicit_bounded_passthrough_forwards_and_records_observation() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.method_dispositions.resources = Some(BoundedMethodDisposition::AllowPassthrough);
    config.method_dispositions.prompts = Some(BoundedMethodDisposition::AllowPassthrough);
    config.method_dispositions.unknown = Some(BoundedMethodDisposition::AllowPassthrough);
    let mut runtime = ProxyRuntime::new(config, FakeMcpServer::default())?;

    for method in ["resources/list", "prompts/list", "vendor/unknown"] {
        let response = runtime
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": method,
                "method": method
            }))?
            .unwrap();
        assert!(
            response.get("result").is_some() || response.get("error").is_some(),
            "{method} should be forwarded to upstream"
        );
        assert_eq!(
            runtime
                .upstream
                .execution_count(&format!("method:{method}")),
            1
        );
    }
    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 6);
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.get("record_type").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![
            "bounded_method_disposition",
            "bounded_method_observation",
            "bounded_method_disposition",
            "bounded_method_observation",
            "bounded_method_disposition",
            "bounded_method_observation"
        ]
    );
    assert!(
        records
            .iter()
            .all(|record| record.get("decision").and_then(Value::as_str)
                == Some("allow_passthrough"))
    );
    assert_eq!(
        records[1]
            .get("pre_execution_record_hash")
            .and_then(Value::as_str),
        records[0].get("record_hash").and_then(Value::as_str)
    );
    assert_eq!(
        records[1].get("upstream_status").and_then(Value::as_str),
        Some("forwarded")
    );
    Ok(())
}

#[test]
fn lifecycle_methods_forward_without_bounded_ledger_records() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    let initialize = runtime
        .handle_message(json!({"jsonrpc": "2.0", "id": "init", "method": "initialize"}))?
        .unwrap();
    let ping = runtime
        .handle_message(json!({"jsonrpc": "2.0", "id": "ping", "method": "ping"}))?
        .unwrap();
    let initialized = runtime.handle_message(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))?;

    assert!(initialize.get("result").is_some());
    assert!(ping.get("result").is_some());
    assert!(initialized.is_none());
    assert_eq!(runtime.upstream.execution_count("method:initialize"), 1);
    assert_eq!(runtime.upstream.execution_count("method:ping"), 1);
    assert!(!temp.path().join("ledger.vledger").exists());
    Ok(())
}

#[test]
fn surface_matrix_doc_matches_runtime_dispositions() -> Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("crate path has no repo root"))?;
    let doc = fs::read_to_string(repo_root.join("docs/mcp_proxy/SURFACE_MATRIX.md"))?;
    let matrix = surface_matrix();
    let rows = matrix
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("surface matrix rows missing"))?;

    for row in rows {
        let method = row
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("surface matrix method missing"))?;
        let disposition = row
            .get("disposition")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("surface matrix disposition missing"))?;
        assert!(
            doc.contains(&format!("`{method}`")),
            "SURFACE_MATRIX.md must document {method}"
        );
        assert!(
            doc.contains(disposition),
            "SURFACE_MATRIX.md must document {method} as {disposition}"
        );
    }
    for method in ["resources/*", "prompts/*", "tasks/*", "*"] {
        let row = rows
            .iter()
            .find(|row| row.get("method").and_then(Value::as_str) == Some(method))
            .ok_or_else(|| anyhow!("missing surface matrix row for {method}"))?;
        assert_eq!(
            row.get("strict_mode_default").and_then(Value::as_str),
            Some("block")
        );
        assert_eq!(row.get("recorded").and_then(Value::as_str), Some("yes"));
    }
    Ok(())
}

#[test]
fn secret_values_are_exact_for_hashing_but_redacted_for_evidence() -> Result<()> {
    let mut first = call("search_change_requests");
    first
        .pointer_mut("/params/arguments")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("missing arguments"))?
        .insert("api_key".to_string(), json!("secret-one"));
    let mut second = first.clone();
    second
        .pointer_mut("/params/arguments/api_key")
        .ok_or_else(|| anyhow!("missing api_key"))?
        .clone_from(&json!("secret-two"));

    assert_ne!(request_hash_hex(&first), request_hash_hex(&second));
    assert_ne!(
        arguments_hash_hex_from_request(&first)?,
        arguments_hash_hex_from_request(&second)?
    );
    let summary = redaction_summary_for_value(&first);
    assert!(
        summary
            .redacted_fields
            .contains(&"$.params.arguments.api_key".to_string())
    );
    Ok(())
}

#[test]
fn schema_fragment_enforces_constraints_and_fails_closed() -> Result<()> {
    let schema = json!({
        "type": "object",
        "required": ["mode", "count", "tags"],
        "additionalProperties": false,
        "properties": {
            "mode": {"type": "string", "enum": ["safe"], "minLength": 2, "maxLength": 8},
            "count": {"type": "integer", "minimum": 1, "maximum": 3},
            "tags": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "string"}},
            "fixed": {"const": true}
        }
    });
    validate_schema_fragment(
        &schema,
        &json!({"mode": "safe", "count": 2, "tags": ["a"], "fixed": true}),
        "$",
    )?;
    assert!(
        validate_schema_fragment(
            &schema,
            &json!({"mode": "unsafe", "count": 2, "tags": ["a"], "fixed": true}),
            "$",
        )
        .is_err()
    );
    assert!(
        validate_schema_fragment(
            &schema,
            &json!({"mode": "safe", "count": 4, "tags": ["a"], "fixed": true}),
            "$",
        )
        .is_err()
    );
    assert!(
        validate_schema_fragment(
            &schema,
            &json!({"mode": "safe", "count": 2, "tags": ["a", "b", "c"], "fixed": true}),
            "$",
        )
        .is_err()
    );
    assert!(
        validate_schema_fragment(
            &json!({"type": "string", "pattern": "^safe$"}),
            &json!("safe"),
            "$",
        )
        .is_err()
    );
    Ok(())
}
