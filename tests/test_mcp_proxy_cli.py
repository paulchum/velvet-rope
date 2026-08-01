from __future__ import annotations

import json
from pathlib import Path

from velvet.cli import main
from velvet.ledger import read_ledger_records, verify_velvet_ledger


def test_cli_mcp_proxy_demo_writes_artifacts(tmp_path: Path, capsys: object) -> None:
    assert main(["mcp-proxy-demo", "--output-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]

    assert payload["execution_counts"]["search_change_requests"] == 1
    assert payload["execution_counts"]["create_change_request"] == 0
    assert payload["execution_counts"]["delete_change_request"] == 0
    assert Path(payload["inventory_path"]).exists()
    assert Path(payload["ledger_path"]).exists()
    assert Path(payload["thread_path"]).exists()
    verification = verify_velvet_ledger(payload["ledger_path"])
    assert verification["status"] == "pass"
    assert verification["canonical_records"] == 5

    records = list(read_ledger_records(payload["ledger_path"]))
    assert [record["oap_contract"] for record in records] == ["velvet.oap_ledger.v1"] * 5
    assert [record["record_type"] for record in records] == [
        "pre_execution_decision",
        "post_execution_observation",
        "pre_execution_decision",
        "pre_execution_decision",
        "pre_execution_decision",
    ]
    assert [record["decision"] for record in records] == [
        "execute",
        "execute",
        "delay",
        "block",
        "block",
    ]
    assert records[0]["oap_decision"] is not None
    assert records[0]["oap_passport"] is not None
    assert records[0].get("selected_warrant") is None
    assert records[1]["pre_execution_record_hash"] == records[0]["record_hash"]
    assert records[1]["upstream_status"] == "forwarded"
    for previous, current in zip(records[:-1], records[1:], strict=True):
        assert current["previous_record_hash"] == previous["record_hash"]


def test_cli_mcp_proxy_nested_commands(tmp_path: Path, capsys: object) -> None:
    assert main(["mcp", "demo", "run", "--output-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["execution_counts"]["delete_change_request"] == 0

    assert main(["mcp", "conformance", "--json"]) == 0
    conformance = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert conformance["mcp_spec_target"] == "2025-11-25"
    assert any(row["method"] == "tools/call" for row in conformance["methods"])
    streamable_http = next(
        row for row in conformance["transports"] if row["transport"] == "streamable_http"
    )
    assert streamable_http["status"] == "supported"
    capabilities = {
        row["capability"]: row["status"]
        for row in conformance["streamable_http_capabilities"]
    }
    assert capabilities["sse_get"] == "supported"
    assert capabilities["last_event_id_replay"] == "supported"
    resources = next(row for row in conformance["methods"] if row["method"] == "resources/*")
    prompts = next(row for row in conformance["methods"] if row["method"] == "prompts/*")
    assert resources["behavior"] == "bounded-governed"
    assert prompts["behavior"] == "bounded-governed"
    surface_rows = {row["method"]: row for row in conformance["surface_matrix"]}
    assert surface_rows["resources/*"]["strict_mode_default"] == "block"
    assert surface_rows["prompts/*"]["recorded"] == "yes"


def test_cli_demo_runs_proxy_demo_and_verifies_ledger(tmp_path: Path, capsys: object) -> None:
    assert main(["demo", "--output-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]

    assert payload["status"] == "pass"
    assert payload["demo"]["execution_counts"]["search_change_requests"] == 1
    assert payload["ledger_verification"]["status"] == "pass"
    assert Path(payload["demo"]["ledger_path"]).exists()
