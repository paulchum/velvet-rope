use super::*;

#[test]
fn rust_decodes_python_binary_ledger_fixture() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_dir = root.join("tests/fixtures/binary_ledger/v1");
    let frames = read_binary_ledger_frames(&fixture_dir.join("python_canonical.vledger"))?;
    let expected_record_id =
        fs::read_to_string(fixture_dir.join("python_canonical_record_id.txt"))?;

    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].payload.get("record_id").and_then(Value::as_str),
        Some(expected_record_id.trim())
    );
    assert_eq!(
        frames[0].payload.get("contract").and_then(Value::as_str),
        Some(LEDGER_CONTRACT)
    );
    assert_eq!(
        frames[0].payload.get("label").and_then(Value::as_str),
        Some("python_binary_fixture")
    );
    Ok(())
}

#[test]
fn ledger_records_forwarding_truth_for_execute_escalate_and_block() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    runtime.handle_message(call("create_change_request"))?;
    runtime.handle_message(call("delete_change_request"))?;
    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 4);
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.get("record_type").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![
            "pre_execution_decision",
            "post_execution_observation",
            "pre_execution_decision",
            "pre_execution_decision"
        ]
    );
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.get("decision").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec!["execute", "execute", "delay", "block"]
    );
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.get("state").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec!["allow", "allow", "escalate", "block"]
    );
    assert!(records[0].get("selected_warrant").is_none());
    assert!(records[0].get("oap_decision").is_some());
    assert!(records[0].get("oap_passport").is_some());
    assert!(
        records[0]
            .get("upstream_response_hash")
            .is_none_or(Value::is_null)
    );
    assert!(records[1].get("pre_execution_record_hash").is_some());
    assert_eq!(
        records[1]
            .get("pre_execution_record_hash")
            .and_then(Value::as_str),
        records[0].get("record_hash").and_then(Value::as_str)
    );
    assert_eq!(
        runtime.upstream.execution_count("delete_change_request"),
        0,
        "blocked destructive tools must never be forwarded"
    );
    Ok(())
}

#[test]
fn admission_evidence_emitted_for_execute_escalate_and_block() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    runtime.handle_message(call("create_change_request"))?;
    runtime.handle_message(call("delete_change_request"))?;
    let records = ledger_records(temp.path())?;
    let pre_records = records
        .iter()
        .filter(|record| {
            record.get("record_type").and_then(Value::as_str) == Some("pre_execution_decision")
        })
        .collect::<Vec<_>>();
    assert_eq!(pre_records.len(), 3);
    assert_eq!(
        pre_records
            .iter()
            .filter_map(|record| record.get("decision").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec!["execute", "delay", "block"]
    );
    for record in pre_records {
        verify_admission_evidence_for_record(record)?;
        let evidence = record
            .get("admission_evidence")
            .ok_or_else(|| anyhow!("missing evidence"))?;
        assert_eq!(
            evidence.get("schema_version").and_then(Value::as_str),
            Some(ADMISSION_EVIDENCE_SCHEMA_VERSION)
        );
        assert_eq!(
            evidence
                .pointer("/signature/purpose")
                .and_then(Value::as_str),
            Some(PURPOSE_ADMISSION_EVIDENCE)
        );
        assert_eq!(
            record
                .get("admission_evidence_hash")
                .and_then(Value::as_str),
            evidence
                .get("admission_evidence_hash")
                .and_then(Value::as_str)
        );
        let raw_uri = evidence
            .pointer("/raw_action/raw_action_ref/uri")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing raw URI"))?;
        assert!(file_uri_to_path(raw_uri)?.exists());
    }
    Ok(())
}

#[test]
fn admission_evidence_raw_artifact_tamper_is_detected() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let records = ledger_records(temp.path())?;
    verify_oap_ledger_chain(&records)?;
    let raw_uri = records[0]
        .pointer("/admission_evidence/raw_action/raw_action_ref/uri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing raw URI"))?;
    fs::write(file_uri_to_path(raw_uri)?, b"{\"tampered\":true}")?;
    assert!(
        verify_oap_ledger_chain(&records).is_err(),
        "raw artifact tampering must fail evidence verification"
    );
    Ok(())
}

#[test]
fn admission_evidence_binds_pending_approval_request() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("create_change_request"))?;
    let records = ledger_records(temp.path())?;
    let record = &records[0];
    verify_admission_evidence_for_record(record)?;
    let evidence = record
        .get("admission_evidence")
        .ok_or_else(|| anyhow!("missing evidence"))?;
    assert_eq!(
        record.get("approval_status").and_then(Value::as_str),
        Some("pending")
    );
    assert_eq!(
        evidence
            .pointer("/decision/approval_status")
            .and_then(Value::as_str),
        Some("pending")
    );
    assert_eq!(
        evidence
            .pointer("/decision/approval_request_id")
            .and_then(Value::as_str),
        record.get("approval_request_id").and_then(Value::as_str)
    );
    let approval_line = fs::read_to_string(temp.path().join("approval_requests.jsonl"))?;
    let approval_request: Value = serde_json::from_str(
        approval_line
            .lines()
            .next()
            .ok_or_else(|| anyhow!("missing approval request"))?,
    )?;
    assert_eq!(
        approval_request
            .get("approval_request_id")
            .and_then(Value::as_str),
        record.get("approval_request_id").and_then(Value::as_str)
    );
    let expected_approval_hash = value_hash(&approval_request);
    assert_eq!(
        Some(expected_approval_hash.as_str()),
        record.get("approval_request_hash").and_then(Value::as_str)
    );
    assert_eq!(
        evidence
            .pointer("/decision/approval_request_hash")
            .and_then(Value::as_str),
        record.get("approval_request_hash").and_then(Value::as_str)
    );
    Ok(())
}

#[test]
fn admission_evidence_rejects_rehashed_bound_field_tampering() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let mut records = ledger_records(temp.path())?;
    verify_oap_ledger_chain(&records)?;

    records[0]["approval_status"] = Value::String("approved".to_string());
    rehash_oap_record(&mut records[0]);
    let new_pre_hash = records[0]
        .get("record_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing pre hash"))?
        .to_string();
    records[1]["previous_record_hash"] = Value::String(new_pre_hash.clone());
    records[1]["pre_execution_record_hash"] = Value::String(new_pre_hash.clone());
    records[1]["forwarding_proof"]["pre_execution_record_hash"] = Value::String(new_pre_hash);
    rehash_oap_record(&mut records[1]);

    assert!(
        verify_oap_ledger_chain(&records).is_err(),
        "admission evidence binding must fail even after ledger hashes are recomputed"
    );
    Ok(())
}

#[test]
fn pre_execution_record_is_persisted_before_upstream_forward() -> Result<()> {
    let temp = TempDir::new()?;
    let config = test_config(temp.path())?;
    let ledger_path = config.ledger_path.clone();
    let mut runtime = ProxyRuntime::new(
        config,
        PreLedgerAssertingServer {
            ledger_path,
            inner: FakeMcpServer::default(),
        },
    )?;
    runtime.handle_message(call("search_change_requests"))?;
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    Ok(())
}

#[test]
fn post_execution_observation_is_appended_after_success() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].get("record_type").and_then(Value::as_str),
        Some("post_execution_observation")
    );
    assert_eq!(
        records[1].get("upstream_status").and_then(Value::as_str),
        Some("forwarded")
    );
    let receipt = records[1]
        .pointer("/forwarding_proof/execution_receipt")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("post-execution record missing execution receipt"))?;
    assert_eq!(
        receipt
            .get("permit_id")
            .and_then(Value::as_str)
            .map(|value| &value[..8]),
        Some("vpermit_")
    );
    assert_eq!(
        records[1]
            .pointer("/forwarding_proof/execution_receipt_hash")
            .and_then(Value::as_str),
        receipt.get("receipt_hash").and_then(Value::as_str)
    );
    verify_oap_ledger_chain(&records)?;
    Ok(())
}

#[test]
fn post_execution_observation_is_appended_after_upstream_failure() -> Result<()> {
    let temp = TempDir::new()?;
    let config = test_config(temp.path())?;
    let mut runtime = ProxyRuntime::new(config, FailingCallServer::default())?;
    let response = runtime
        .handle_message(call("search_change_requests"))?
        .unwrap();
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32060)
    );
    assert_eq!(
        runtime.upstream.execution_count("search_change_requests"),
        1
    );
    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].get("record_type").and_then(Value::as_str),
        Some("post_execution_observation")
    );
    assert_eq!(
        records[1].get("upstream_status").and_then(Value::as_str),
        Some("indeterminate")
    );
    assert!(records[1].get("error_metadata").is_some());
    verify_oap_ledger_chain(&records)?;
    Ok(())
}

#[test]
fn ledger_chain_verifier_detects_tampering() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let records = ledger_records(temp.path())?;
    verify_oap_ledger_chain(&records)?;
    let mut tampered = records.clone();
    tampered[1]["upstream_status"] = Value::String("forwarded_but_tampered".to_string());
    assert!(verify_oap_ledger_chain(&tampered).is_err());
    let mut tampered = records;
    tampered[1]["previous_record_hash"] = Value::String(LEDGER_GENESIS_HASH.to_string());
    assert!(verify_oap_ledger_chain(&tampered).is_err());
    Ok(())
}

#[test]
fn ledger_chain_verifier_rejects_rehashed_pre_record_binding_mismatch() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let mut records = ledger_records(temp.path())?;

    records[0]["request_hash"] = Value::String(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
    );
    rehash_oap_record(&mut records[0]);
    let new_pre_hash = records[0]
        .get("record_hash")
        .and_then(Value::as_str)
        .expect("pre record hash")
        .to_string();
    records[1]["previous_record_hash"] = Value::String(new_pre_hash.clone());
    records[1]["pre_execution_record_hash"] = Value::String(new_pre_hash.clone());
    records[1]["forwarding_proof"]["pre_execution_record_hash"] = Value::String(new_pre_hash);
    rehash_oap_record(&mut records[1]);

    assert!(
        verify_oap_ledger_chain(&records).is_err(),
        "semantic envelope/request mismatch must fail even after record hashes are recomputed"
    );
    Ok(())
}

#[test]
fn ledger_chain_verifier_rejects_rehashed_post_record_binding_mismatch() -> Result<()> {
    let temp = TempDir::new()?;
    let mut runtime = runtime(temp.path())?;
    runtime.handle_message(call("search_change_requests"))?;
    let mut records = ledger_records(temp.path())?;

    records[1]["signed_decision_digest"] = Value::String(
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string(),
    );
    rehash_oap_record(&mut records[1]);

    assert!(
        verify_oap_ledger_chain(&records).is_err(),
        "post-execution observation must stay semantically bound to the pre-execution record"
    );
    Ok(())
}

#[test]
fn concurrent_ledger_writes_keep_sequence_and_hash_chain_linear() -> Result<()> {
    let temp = TempDir::new()?;
    let config = Arc::new(test_config(temp.path())?);
    let bundle_proof = Arc::new(verify_policy_bundle(&config.policy)?);
    let mut handles = Vec::new();
    for index in 0..16 {
        let config = Arc::clone(&config);
        let bundle_proof = Arc::clone(&bundle_proof);
        handles.push(std::thread::spawn(move || -> Result<()> {
            let request = json!({
                "jsonrpc": "2.0",
                "id": format!("bounded-{index}"),
                "method": format!("vendor/method_{index}"),
                "params": {"index": index}
            });
            let decision = bounded_method_decision(&config, &request);
            record_bounded_method_ledger(&config, &bundle_proof, &request, &decision)?;
            Ok(())
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| anyhow!("ledger writer thread panicked"))??;
    }

    let records = ledger_records(temp.path())?;
    assert_eq!(records.len(), 16);
    let mut sequences = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let sequence = record
            .get("sequence_number")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("missing sequence"))?;
        sequences.insert(sequence);
        if index == 0 {
            assert_eq!(
                record.get("previous_record_hash").and_then(Value::as_str),
                Some(LEDGER_GENESIS_HASH)
            );
        } else {
            assert_eq!(
                record.get("previous_record_hash").and_then(Value::as_str),
                records[index - 1]
                    .get("record_hash")
                    .and_then(Value::as_str)
            );
        }
    }
    assert_eq!(sequences, (1..=16).collect::<BTreeSet<_>>());
    Ok(())
}
