from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from velvet.cli import main
from velvet.mcp_firewall import (
    MCP_FIREWALL_REQUEST_SCHEMA_VERSION,
    MCP_FIREWALL_RESPONSE_SCHEMA_VERSION,
    MCPFirewallRequest,
    run_mcp_firewall_pilot,
    verify_mcp_firewall_pilot,
)

FORBIDDEN_INVESTOR_TERMS = (
    "investor_target",
    "Investor To Reach",
    "Ann Miura-Ko",
    "Floodgate",
    "Sarah Guo",
    "Conviction",
)


def test_mcp_firewall_pilot_writes_product_clean_allow_block_escalate_pack(
    tmp_path: Path,
) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)

    assert payload["schema_version"] == "velvet.mcp_firewall.pilot.v1"
    assert payload["product"] == "Velvet MCP Firewall"
    assert payload["boundary"] == "pre_execution_authorization"
    assert payload["summary"]["decision_counts"] == {
        "block": 1,
        "escalate": 1,
        "execute": 1,
    }
    assert payload["summary"]["total_requests"] == 3
    assert payload["summary"]["pending_approvals"] == 1
    assert payload["summary"]["approval_pending"] == 1
    assert payload["summary"]["ledger_verification_status"] == "pass"
    assert payload["velvet_ledger_report"]["summary"]["records"] == 3
    assert payload["velvet_ledger_report"]["summary"]["canonical_action_hashes"] == 3
    assert payload["evidence_pack"]["summary"]["controls_attention"] == 0
    assert all(
        control["status"] == "pass"
        for control in payload["evidence_pack"]["controls"].values()
    )
    assert "investor_target" not in payload
    assert payload["replay_report"]["status"] == "pass"

    decisions = payload["decisions"]
    assert [decision["decision"] for decision in decisions] == [
        "execute",
        "block",
        "escalate",
    ]
    for decision in decisions:
        assert decision["schema_version"] == MCP_FIREWALL_RESPONSE_SCHEMA_VERSION
        assert decision["request"]["schema_version"] == MCP_FIREWALL_REQUEST_SCHEMA_VERSION
        assert decision["boundary"] == "pre_execution_authorization"
        assert decision["agent_id"] == "release-agent"
        assert decision["user_id"] == "platform-lead@example.com"
        assert decision["seal_id"]
        assert decision["canonical_action_hash"]
        assert decision["canonical_action"]["surface"] == "mcp"
        assert decision["warrant"]["canonical_action_hash"] == decision["canonical_action_hash"]
        assert decision["ledger_record_id"]
        assert decision["ledger_record_hash"]

    assert decisions[0]["approval_request_id"] is None
    assert decisions[1]["decision"] == "block"
    assert decisions[1]["upstream_execution_status"] == "not_forwarded"
    assert decisions[2]["approval_request_id"]
    assert decisions[2]["upstream_execution_status"] == "pending_approval"

    artifacts = payload["artifacts"]
    assert Path(artifacts["pilot_markdown_path"]).exists()
    assert Path(artifacts["evidence_pack_markdown_path"]).exists()
    pilot_json = Path(artifacts["pilot_json_path"]).read_text(encoding="utf-8")
    pilot_markdown = Path(artifacts["pilot_markdown_path"]).read_text(encoding="utf-8")
    for forbidden in FORBIDDEN_INVESTOR_TERMS:
        assert forbidden not in pilot_json
        assert forbidden not in pilot_markdown

    verification = verify_mcp_firewall_pilot(tmp_path)
    assert verification["status"] == "pass"


def test_cli_mcp_firewall_pilot_outputs_json(tmp_path: Path, capsys: object) -> None:
    assert main(["mcp-firewall", "--output-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]

    assert payload["product"] == "Velvet MCP Firewall"
    assert payload["boundary"] == "pre_execution_authorization"
    assert payload["summary"]["decision_counts"]["block"] == 1
    assert Path(payload["artifacts"]["ledger_path"]).exists()


def test_cli_mcp_firewall_verify_and_report(tmp_path: Path, capsys: object) -> None:
    assert main(["mcp-firewall", "pilot", "--output-dir", str(tmp_path), "--json"]) == 0
    capsys.readouterr()  # type: ignore[attr-defined]

    assert main(["mcp-firewall", "verify", "--output-dir", str(tmp_path), "--json"]) == 0
    verification = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert verification["schema_version"] == "velvet.mcp_firewall.verify.v1"
    assert verification["status"] == "pass"
    assert {check["name"]: check["status"] for check in verification["checks"]}[
        "decision_coverage"
    ] == "pass"

    assert main(["mcp-firewall", "report", "--output-dir", str(tmp_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert report["status"] == "pass"
    markdown = Path(report["pilot_markdown_path"]).read_text(encoding="utf-8")
    assert "Velvet MCP Firewall Pilot" in markdown
    for forbidden in FORBIDDEN_INVESTOR_TERMS:
        assert forbidden not in markdown


def test_mcp_firewall_verify_fails_for_missing_artifact(
    tmp_path: Path,
    capsys: object,
) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)
    Path(payload["artifacts"]["evidence_pack_json_path"]).unlink()

    assert main(["mcp-firewall", "verify", "--output-dir", str(tmp_path), "--json"]) == 1
    verification = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert verification["status"] == "fail"
    checks = {check["name"]: check for check in verification["checks"]}
    assert checks["artifact_evidence_pack_json_path_exists"]["status"] == "fail"


def test_mcp_firewall_verify_fails_for_tampered_ledger(
    tmp_path: Path,
    capsys: object,
) -> None:
    payload = run_mcp_firewall_pilot(tmp_path)
    ledger_path = Path(payload["artifacts"]["ledger_path"])
    records = _read_inline_records(ledger_path)
    records[1]["decision"] = "tampered after pilot"
    _write_inline_records(ledger_path, records)

    assert main(["mcp-firewall", "verify", "--output-dir", str(tmp_path), "--json"]) == 1
    verification = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    checks = {check["name"]: check for check in verification["checks"]}
    assert checks["inline_ledger_records_verify"]["status"] == "fail"
    issues = checks["inline_ledger_records_verify"]["details"]["issues"]
    assert any(issue["code"] == "record_hash_mismatch" for issue in issues)


def test_mcp_firewall_request_builds_inline_gateway_request() -> None:
    request = MCPFirewallRequest.from_dict(
        {
            "agent_id": "ops-agent",
            "user_id": "operator@example.com",
            "mcp_server": "linear",
            "mcp_tool": "list_issues",
            "arguments": {"team": "platform"},
            "risk_class": "low",
        }
    )

    gateway_request = request.to_inline_gateway_request()
    assert request.tool_key == "linear/list_issues"
    assert gateway_request.proposed_action["surface"] == "mcp"
    assert gateway_request.proposed_action["server"] == "linear"
    assert gateway_request.proposed_action["tool"] == "list_issues"
    assert gateway_request.context["user_id"] == "operator@example.com"


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
