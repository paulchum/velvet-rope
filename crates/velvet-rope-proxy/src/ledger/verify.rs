use super::*;

pub(crate) fn verify_admission_evidence_for_record(record: &Value) -> Result<()> {
    let evidence = record
        .get("admission_evidence")
        .ok_or_else(|| anyhow!("pre-execution record missing admission_evidence"))?;
    verify_admission_evidence_value(evidence)?;
    let evidence_hash = evidence
        .get("admission_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing admission_evidence_hash"))?;
    require_record_digest(record, "admission_evidence_hash", evidence_hash)?;
    let record_ref = record
        .get("admission_evidence_ref")
        .ok_or_else(|| anyhow!("pre-execution record missing admission_evidence_ref"))?;
    let evidence_ref = evidence
        .pointer("/raw_action/raw_action_ref")
        .ok_or_else(|| anyhow!("admission evidence missing raw action ref"))?;
    if record_ref != evidence_ref {
        bail!("ledger admission_evidence_ref does not match admission evidence raw action ref");
    }
    require_evidence_u64(
        evidence,
        "/ledger_state/sequence_number",
        record,
        "sequence_number",
    )?;
    require_evidence_str(
        evidence,
        "/ledger_state/previous_record_hash",
        record,
        "previous_record_hash",
    )?;
    require_evidence_str(evidence, "/bindings/request_hash", record, "request_hash")?;
    require_evidence_str(evidence, "/policy/policy_hash", record, "policy_hash")?;
    require_evidence_str(
        evidence,
        "/tool/tool_schema_hash",
        record,
        "tool_schema_hash",
    )?;
    require_evidence_str(evidence, "/tool/arguments_hash", record, "arguments_hash")?;
    require_evidence_str(evidence, "/decision/action_type", record, "action_type")?;
    require_evidence_str(
        evidence,
        "/decision/approval_status",
        record,
        "approval_status",
    )?;
    require_optional_evidence_str(
        evidence,
        "/decision/approval_request_id",
        record,
        "approval_request_id",
    )?;
    require_optional_evidence_str(
        evidence,
        "/decision/approval_request_hash",
        record,
        "approval_request_hash",
    )?;
    require_optional_evidence_str(
        evidence,
        "/decision/approval_receipt_id",
        record,
        "approval_receipt_id",
    )?;
    let record_decision = record
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pre-execution record missing decision"))?;
    let evidence_decision = evidence
        .pointer("/decision/decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing decision"))?;
    if evidence_decision != canonical_decision(record_decision) {
        bail!("admission evidence decision does not match pre-execution record");
    }
    let raw_action_hash = evidence
        .pointer("/raw_action/raw_action_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing raw_action_hash"))?;
    let raw_ref_hash = evidence
        .pointer("/raw_action/raw_action_ref/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence raw action ref missing sha256"))?;
    if raw_action_hash != raw_ref_hash {
        bail!("admission evidence raw_action_hash does not match raw_action_ref");
    }
    let redacted_hash = evidence
        .pointer("/raw_action/redacted_action_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing redacted_action_hash"))?;
    if redacted_hash
        != record
            .get("request_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
    {
        bail!("admission evidence redacted action hash does not match request_hash");
    }
    Ok(())
}

pub(crate) fn verify_admission_evidence_value(evidence: &Value) -> Result<()> {
    if evidence
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing schema_version"))?
        != ADMISSION_EVIDENCE_SCHEMA_VERSION
    {
        bail!("unsupported admission evidence schema_version");
    }
    if evidence
        .get("boundary")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing boundary"))?
        != "pre_execution_authorization"
    {
        bail!("admission evidence boundary is not pre_execution_authorization");
    }
    let expected_hash = admission_evidence_hash_value(evidence)?;
    let actual_hash = evidence
        .get("admission_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing admission_evidence_hash"))?;
    if actual_hash != expected_hash {
        bail!("admission evidence hash does not match canonical unsigned payload");
    }
    let tenant_id = evidence
        .get("tenant_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing tenant_id"))?;
    verify_local_signature(
        evidence
            .get("signature")
            .ok_or_else(|| anyhow!("admission evidence missing signature"))?,
        actual_hash,
        tenant_id,
        PURPOSE_ADMISSION_EVIDENCE,
    )?;
    verify_raw_action_ref(evidence)?;
    Ok(())
}

pub(crate) fn verify_raw_action_ref(evidence: &Value) -> Result<()> {
    let raw_ref = evidence
        .pointer("/raw_action/raw_action_ref")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("admission evidence raw_action_ref must be an object"))?;
    let uri = raw_ref
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("raw action ref missing uri"))?;
    let expected_hash = raw_ref
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("raw action ref missing sha256"))?;
    let expected_size = raw_ref
        .get("size_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("raw action ref missing size_bytes"))?;
    let path = file_uri_to_path(uri)?;
    let data = fs::read(&path).with_context(|| format!("read raw action artifact {uri}"))?;
    let actual_hash = format!("sha256:{}", sha256_hex(&data));
    if actual_hash != expected_hash {
        bail!("raw action artifact hash does not match admission evidence");
    }
    if data.len() as u64 != expected_size {
        bail!("raw action artifact size does not match admission evidence");
    }
    Ok(())
}

pub(crate) fn verify_local_signature(
    signature: &Value,
    payload_hash: &str,
    tenant_id: &str,
    purpose: &str,
) -> Result<()> {
    let object = signature
        .as_object()
        .ok_or_else(|| anyhow!("signature must be an object"))?;
    for (field, expected) in [
        ("provider_name", LOCAL_DEMO_PROVIDER_NAME),
        ("algorithm", LOCAL_DEMO_ALGORITHM),
        ("key_id", LOCAL_DEMO_KEY_ID),
        ("key_version", LOCAL_DEMO_KEY_VERSION),
        ("purpose", purpose),
        ("tenant_id", tenant_id),
        ("payload_hash", payload_hash),
    ] {
        let actual = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("signature missing {field}"))?;
        if actual != expected {
            bail!("signature {field} does not match admission evidence");
        }
    }
    let actual_signature = object
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("signature missing signature value"))?;
    let expected_signature = hmac_sha256_hex(
        LOCAL_DEMO_SIGNATURE_KEY.as_bytes(),
        signing_message(payload_hash, tenant_id, purpose).as_bytes(),
    );
    if actual_signature != expected_signature {
        bail!("admission evidence signature does not verify");
    }
    Ok(())
}

pub(crate) fn require_evidence_str(
    evidence: &Value,
    evidence_pointer: &str,
    record: &Value,
    record_field: &str,
) -> Result<()> {
    let actual = evidence
        .pointer(evidence_pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("admission evidence missing {evidence_pointer}"))?;
    let expected = record
        .get(record_field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pre-execution record missing {record_field}"))?;
    if actual != expected {
        bail!("admission evidence {evidence_pointer} does not match record {record_field}");
    }
    Ok(())
}

pub(crate) fn require_optional_evidence_str(
    evidence: &Value,
    evidence_pointer: &str,
    record: &Value,
    record_field: &str,
) -> Result<()> {
    let actual = evidence.pointer(evidence_pointer).and_then(Value::as_str);
    let expected = record.get(record_field).and_then(Value::as_str);
    if actual != expected {
        bail!("admission evidence {evidence_pointer} does not match record {record_field}");
    }
    Ok(())
}

pub(crate) fn require_evidence_u64(
    evidence: &Value,
    evidence_pointer: &str,
    record: &Value,
    record_field: &str,
) -> Result<()> {
    let actual = evidence
        .pointer(evidence_pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("admission evidence missing {evidence_pointer}"))?;
    let expected = record
        .get(record_field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("pre-execution record missing {record_field}"))?;
    if actual != expected {
        bail!("admission evidence {evidence_pointer} does not match record {record_field}");
    }
    Ok(())
}

pub fn verify_oap_pre_execution_record(record: &Value) -> Result<()> {
    if record.get("record_type").and_then(Value::as_str) != Some("pre_execution_decision") {
        bail!("record is not a pre_execution_decision");
    }
    verify_record_hash_value(record)?;
    verify_admission_evidence_for_record(record)?;
    verify_required_envelope(record)?;
    let decision = record
        .get("oap_decision")
        .ok_or_else(|| anyhow!("pre-execution record missing OAP Decision"))?;
    let passport = record
        .get("oap_passport")
        .ok_or_else(|| anyhow!("pre-execution record missing OAP Passport"))?;
    validate_decision_structural(decision)?;
    validate_passport_structural(passport)?;
    require_record_digest(record, "passport_digest", &passport_digest(passport)?)?;
    let decision_passport_digest = decision
        .get("passport_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing passport_digest"))?;
    require_record_digest(record, "passport_digest", decision_passport_digest)?;
    require_record_digest(
        record,
        "decision_payload_digest",
        &decision_payload_digest(decision)?,
    )?;
    require_record_digest(
        record,
        "signed_decision_digest",
        &signed_decision_digest(decision)?,
    )?;
    require_record_digest(
        record,
        "oap_decision_digest",
        &signed_decision_digest(decision)?,
    )?;
    require_record_digest(
        record,
        "decision_signature_hash",
        &decision_signature_hash(decision)?,
    )?;
    if let Some(envelope) = record
        .get("max_de_certificate_envelope")
        .filter(|value| !value.is_null())
    {
        verify_envelope_binding(envelope, decision)?;
        verify_envelope_binding_against_pre_execution_record(envelope, decision, record)?;
        verify_maxde_exact_arithmetic(envelope)?;
        require_record_digest(
            record,
            "max_de_certificate_envelope_digest",
            &digest_value(envelope)?,
        )?;
    }
    Ok(())
}

pub fn verify_oap_ledger_chain(records: &[Value]) -> Result<()> {
    let mut previous = LEDGER_GENESIS_HASH.to_string();
    let mut expected_sequence = 1_u64;
    let mut pre_records = BTreeMap::new();
    for record in records {
        if record.get("oap_contract").and_then(Value::as_str) != Some(LEDGER_SCHEMA_VERSION) {
            continue;
        }
        let sequence = record
            .get("sequence_number")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("ledger record missing sequence_number"))?;
        if sequence != expected_sequence {
            bail!("ledger sequence_number is not append-only");
        }
        let previous_record_hash = record
            .get("previous_record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ledger record missing previous_record_hash"))?;
        if previous_record_hash != previous {
            bail!("ledger previous_record_hash does not match hash chain");
        }
        verify_record_hash_value(record)?;
        let record_hash = record
            .get("record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ledger record missing record_hash"))?
            .to_string();
        match record.get("record_type").and_then(Value::as_str) {
            Some("pre_execution_decision") => {
                verify_oap_pre_execution_record(record)?;
                pre_records.insert(record_hash.clone(), record.clone());
            }
            Some("post_execution_observation") => {
                verify_post_execution_observation_record(record, &pre_records)?;
            }
            Some("bounded_method_disposition" | "bounded_method_observation") => {}
            Some("closure_lifecycle_event") => verify_closure_lifecycle_record(record)?,
            Some(other) => bail!("unknown OAP ledger record_type {other}"),
            None => bail!("ledger record missing record_type"),
        }
        previous = record_hash;
        expected_sequence += 1;
    }
    Ok(())
}

fn verify_closure_lifecycle_record(record: &Value) -> Result<()> {
    if record
        .get("action_type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("closure lifecycle record missing action_type"))?
        != "CLOSURE_LIFECYCLE"
    {
        bail!("closure lifecycle record action_type mismatch");
    }
    if record
        .get("oap_passport")
        .is_some_and(|value| !value.is_null())
        || record
            .get("oap_decision")
            .is_some_and(|value| !value.is_null())
    {
        bail!("closure lifecycle record must not masquerade as an OAP decision");
    }
    let metadata = record
        .get("persistence_metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("closure lifecycle record missing persistence_metadata"))?;
    if metadata.get("model").and_then(Value::as_str) != Some("closure_lifecycle") {
        bail!("closure lifecycle record model mismatch");
    }
    if metadata.get("boundary").and_then(Value::as_str) != Some("permit_epoch_lifecycle") {
        bail!("closure lifecycle record boundary mismatch");
    }
    let event = metadata
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("closure lifecycle record missing event"))?;
    if !matches!(event, "request" | "grant" | "invoke" | "closure" | "deny") {
        bail!("closure lifecycle record event is not recognized");
    }
    let state = record
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("closure lifecycle record missing state"))?;
    if state != event {
        bail!("closure lifecycle record state does not match event");
    }
    let subgoal_id_hash = metadata
        .get("subgoal_id_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("closure lifecycle record missing subgoal_id_hash"))?;
    if !subgoal_id_hash.starts_with("sha256:") {
        bail!("closure lifecycle record subgoal_id_hash must be a sha256 hash");
    }
    metadata
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("closure lifecycle record missing epoch"))?;
    let proof = record
        .get("forwarding_proof")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("closure lifecycle record missing lifecycle payload"))?;
    if proof.get("event").and_then(Value::as_str) != Some(event) {
        bail!("closure lifecycle payload event mismatch");
    }
    if proof.get("subgoal_id_hash").and_then(Value::as_str) != Some(subgoal_id_hash) {
        bail!("closure lifecycle payload subgoal mismatch");
    }
    Ok(())
}

pub(crate) fn verify_post_execution_observation_record(
    record: &Value,
    pre_records: &BTreeMap<String, Value>,
) -> Result<()> {
    let pre_hash = record
        .get("pre_execution_record_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("post-execution record missing pre_execution_record_hash"))?;
    let pre_record = pre_records.get(pre_hash).ok_or_else(|| {
        anyhow!("post-execution observation is not bound to a known pre-execution record")
    })?;
    let proof_hash = record
        .pointer("/forwarding_proof/pre_execution_record_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("post-execution record missing forwarding proof pre hash"))?;
    if proof_hash != pre_hash {
        bail!("post-execution forwarding proof does not bind the pre-execution record");
    }
    if record
        .get("upstream_status")
        .and_then(Value::as_str)
        .is_none()
    {
        bail!("post-execution record missing upstream_status");
    }
    for field in [
        "decision_id",
        "signed_decision_digest",
        "max_de_certificate_envelope_digest",
        "request_hash",
        "arguments_hash",
        "tool_schema_hash",
    ] {
        if pre_record.get(field) != record.get(field) {
            bail!("post-execution record {field} does not match bound pre-execution record");
        }
    }
    let proof_decision_id = record
        .pointer("/forwarding_proof/decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("post-execution record missing forwarding proof decision_id"))?;
    let pre_decision_id = pre_record
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pre-execution record missing decision_id"))?;
    if proof_decision_id != pre_decision_id {
        bail!("post-execution forwarding proof decision_id does not match pre-execution record");
    }
    Ok(())
}

pub(crate) fn verify_envelope_binding_against_pre_execution_record(
    envelope: &Value,
    decision: &Value,
    record: &Value,
) -> Result<()> {
    let binding = envelope
        .get("binding")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("Max-DE envelope missing binding"))?;
    require_binding_record_str(binding, "policy_hash", record, "policy_hash")?;
    require_binding_record_str(binding, "policy_version", record, "policy_version")?;
    require_binding_record_str(binding, "tenant_id_hash", record, "tenant_id_hash")?;
    require_binding_record_str(binding, "owner_id_hash", record, "owner_id_hash")?;
    require_binding_record_str(binding, "subject_id_hash", record, "subject_id_hash")?;
    require_binding_record_str(binding, "agent_id_hash", record, "agent_id_hash")?;
    require_binding_record_str(binding, "client_id_hash", record, "client_id_hash")?;
    require_binding_record_str(binding, "session_id_hash", record, "session_id_hash")?;
    require_binding_record_str(binding, "product_surface", record, "product_surface")?;
    require_binding_record_str(binding, "environment", record, "environment")?;
    require_binding_record_str(binding, "tool_key", record, "tool_key")?;
    require_binding_record_str(binding, "tool_schema_hash", record, "tool_schema_hash")?;
    require_binding_record_str(binding, "arguments_hash", record, "arguments_hash")?;
    require_binding_record_str(binding, "request_hash", record, "request_hash")?;
    require_binding_literal(binding, "mcp_method", "tools/call")?;
    require_binding_literal(
        binding,
        "policy_id",
        decision_policy_id_for_record(decision)?,
    )?;

    let binding_required = binding
        .get("max_de_certificate_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("Max-DE envelope missing binding.max_de_certificate_required"))?;
    let record_required = record
        .get("max_de_certificate_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("pre-execution record missing max_de_certificate_required"))?;
    if binding_required != record_required {
        bail!("Max-DE envelope requirement flag does not match pre-execution record");
    }
    require_binding_record_str(
        binding,
        "max_de_requirement_reason",
        record,
        "max_de_requirement_reason",
    )?;
    Ok(())
}

pub(crate) fn decision_policy_id_for_record(decision: &Value) -> Result<&str> {
    decision
        .get("policy_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("OAP Decision missing policy_id"))
}

pub(crate) fn require_binding_literal(
    binding: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<()> {
    let actual = binding
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope binding missing {field}"))?;
    if actual != expected {
        bail!("Max-DE envelope binding {field} does not match expected value");
    }
    Ok(())
}

pub(crate) fn require_binding_record_str(
    binding: &Map<String, Value>,
    binding_field: &str,
    record: &Value,
    record_field: &str,
) -> Result<()> {
    let actual = binding
        .get(binding_field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Max-DE envelope binding missing {binding_field}"))?;
    let expected = record
        .get(record_field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pre-execution record missing {record_field}"))?;
    if actual != expected {
        bail!(
            "Max-DE envelope binding {binding_field} does not match pre-execution record {record_field}"
        );
    }
    Ok(())
}

pub(crate) fn verify_record_hash_value(record: &Value) -> Result<()> {
    let actual = record
        .get("record_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("ledger record missing record_hash"))?;
    let mut payload = record.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| anyhow!("ledger record must be an object"))?
        .remove("record_hash");
    let expected = value_hash(&payload);
    if actual != expected {
        bail!("ledger record_hash does not match canonical record payload");
    }
    Ok(())
}

pub(crate) fn require_record_digest(record: &Value, field: &str, expected: &str) -> Result<()> {
    let actual = record
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("ledger record missing {field}"))?;
    if actual != expected {
        bail!("ledger record {field} does not match computed digest");
    }
    Ok(())
}
