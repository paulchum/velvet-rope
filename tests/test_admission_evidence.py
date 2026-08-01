from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

from velvet.admission_evidence import verify_admission_evidence
from velvet.mcp_firewall import run_mcp_firewall_pilot, verify_mcp_firewall_pilot
from velvet.serialization import canonical_hash_sha256


def test_mcp_firewall_emits_signed_admission_evidence_for_all_outcomes(
    tmp_path: Path,
) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)
    ledger_path = Path(payload["artifacts"]["ledger_path"])
    records = _read_inline_records(ledger_path)

    assert [decision["decision"] for decision in payload["decisions"]] == [
        "execute",
        "block",
        "escalate",
    ]
    assert len(records) == 3
    assert verify_mcp_firewall_pilot(tmp_path)["status"] == "pass"

    for record in records:
        evidence = record["admission_evidence"]
        assert verify_admission_evidence(evidence)
        assert record["admission_evidence_hash"] == evidence["admission_evidence_hash"]
        assert record["sequence_number"] == evidence["ledger_state"]["sequence_number"]
        assert record["previous_record_hash"] == evidence["ledger_state"]["previous_record_hash"]
        assert evidence["bindings"]["request_hash"]
        assert evidence["policy"]["policy_hash"]
        assert record["request_id"]
        assert (
            record["canonical_action_hash"]
            == record["canonical_action"]["canonical_action_hash"]
        )
        assert evidence["tool"]["tool_schema_hash"]
        assert evidence["tool"]["arguments_hash"]
        expected_decision = (
            "execute"
            if record["decision"] == "ADMITTED"
            else "escalate"
            if record["decision"] == "ESCALATED"
            else "block"
        )
        assert expected_decision == evidence["decision"]["decision"]

        raw_ref = evidence["raw_action"]["raw_action_ref"]
        assert raw_ref["sha256"] == evidence["raw_action"]["raw_action_hash"]
        assert raw_ref["artifact_id"]
        assert raw_ref["uri"].startswith("file://")
        assert raw_ref["size_bytes"] > 0
        assert raw_ref["content_type"] == "application/json"

    escalated = next(record for record in records if record["decision"] == "ESCALATED")
    escalated_evidence = escalated["admission_evidence"]
    assert escalated_evidence["decision"]["approval_status"] == "pending"
    assert escalated_evidence["decision"]["approval_request_id"]
    assert escalated_evidence["decision"]["approval_request_hash"]
    assert escalated_evidence["risk"]["risk_class"] == "BIND_EXTERNAL"
    assert escalated_evidence["identity"]["actor_user_id"] == "platform-lead@example.com"
    assert escalated_evidence["identity"]["agent_id"] == "release-agent"


def test_admission_evidence_detects_raw_artifact_tamper(tmp_path: Path) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)
    ledger_path = Path(payload["artifacts"]["ledger_path"])
    record = _read_inline_records(ledger_path)[0]
    raw_ref = record["admission_evidence"]["raw_action"]["raw_action_ref"]
    raw_path = Path(url2pathname(urlparse(raw_ref["uri"]).path))

    raw_path.write_text('{"tampered":true}', encoding="utf-8")

    verification = verify_mcp_firewall_pilot(tmp_path)
    assert verification["status"] == "fail"
    checks = {check["name"]: check for check in verification["checks"]}
    issues = checks["inline_ledger_records_verify"]["details"]["issues"]
    assert any(
        issue["code"] == "admission_evidence_signature_mismatch"
        for issue in issues
    )


def test_admission_evidence_binding_survives_recomputed_ledger_hash(
    tmp_path: Path,
) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)
    ledger_path = Path(payload["artifacts"]["ledger_path"])
    records = _read_inline_records(ledger_path)
    records[1]["decision"] = "ADMITTED"
    records[1]["inline_record_hash"] = canonical_hash_sha256(
        {str(key): value for key, value in records[1].items() if key != "inline_record_hash"}
    )
    _write_inline_records(ledger_path, records)

    verification = verify_mcp_firewall_pilot(tmp_path)
    assert verification["status"] == "fail"
    checks = {check["name"]: check for check in verification["checks"]}
    issues = checks["inline_ledger_records_verify"]["details"]["issues"]
    assert any(
        issue["code"] == "admission_evidence_binding_mismatch"
        and issue.get("field") == "decision"
        for issue in issues
    )


def _read_inline_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_inline_records(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
