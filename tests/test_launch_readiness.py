from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from velvet.cli import main
from velvet.launch import run_launch_demo
from velvet.ledger import (
    LEDGER_CONTRACT,
    build_velvet_ledger_report,
    read_ledger_records,
    seal_thread_decision,
)
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.storage import EvidenceManifest, LocalFilesystemEvidenceStore

ROOT = Path(__file__).resolve().parents[1]


def test_direct_mcp_records_allow_block_escalate(tmp_path: Path) -> None:
    thread_path = tmp_path / "mcp_thread.jsonl"
    ledger_path = tmp_path / "velvet_ledger.vledger"
    adapter = DirectVelvetMCPAdapter.from_list_file(ROOT / "examples" / "mcp" / "list.json")

    outputs = [
        adapter.authorize(request, thread_path=thread_path, ledger_path=ledger_path)
        for request in load_requests(ROOT / "examples" / "mcp" / "workflow.json")
    ]

    decisions = [output["admission_decision"]["decision"]["decision"] for output in outputs]
    assert decisions == ["execute", "block", "escalate"]
    assert [output["tool_key"] for output in outputs] == [
        "servicenow/search_change_requests",
        "servicenow/delete_change_request",
        "servicenow/create_change_request",
    ]
    for output in outputs:
        warrant = output["admission_decision"]["selected_warrant"]
        assert output["boundary"] == "pre_execution_authorization"
        assert "execution_result" not in output
        assert warrant["reason"]
        assert warrant["risk_class"] in {"low", "high", "unlisted"}
        assert warrant["policy_reasons"]
        assert warrant["jurisdiction_evidence"]

    assert outputs[0]["admission_decision"]["selected_warrant"]["entry_price"] > 0.0
    assert (
        outputs[0]["admission_decision"]["selected_warrant"]["pricing_status"]
        == "admission_optimizer"
    )
    assert outputs[1]["admission_decision"]["selected_warrant"]["pricing_status"] == (
        "denied_at_rope"
    )
    assert outputs[2]["admission_decision"]["selected_warrant"]["entry_price"] > 0.0
    assert outputs[2]["admission_decision"]["selected_warrant"]["pricing_status"] == (
        "admission_optimizer"
    )

    report = build_velvet_ledger_report(ledger_path, thread_path=thread_path)
    records = list(read_ledger_records(ledger_path))
    assert {record["contract"] for record in records} == {LEDGER_CONTRACT}
    assert {record["contract_revision"] for record in records} == {1}
    assert report["summary"]["decision_counts"] == {
        "block": 1,
        "escalate": 1,
        "execute": 1,
    }
    assert report["summary"]["ledger_verification_status"] == "pass"
    assert report["summary"]["with_thread"] == 3
    assert report["thread_validation"]["status"] == "pass"

    seal_id = outputs[0]["admission_decision"]["seal_id"]
    replay = seal_thread_decision(
        thread_path,
        seal_id,
        policy_dir=str(ROOT / "examples" / "mcp" / "policies"),
        chain="mcp_demo",
    )
    assert replay["status"] == "pass"
    assert replay["sealed_selected_action"] == "CALL_TOOL"

    block_seal_id = outputs[1]["admission_decision"]["seal_id"]
    block_replay = seal_thread_decision(
        thread_path,
        block_seal_id,
        policy_dir=str(ROOT / "examples" / "mcp" / "policies"),
        chain="mcp_demo",
    )
    assert block_replay["status"] == "pass"
    assert block_replay["decision"] == "block"


def test_cli_launch_demo_and_replay(tmp_path: Path, capsys: object) -> None:
    output_dir = tmp_path / "launch"
    assert main(["launch-demo", "--output-dir", str(output_dir), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["velvet_ledger_report"]["summary"]["decision_counts"]["block"] == 1
    assert payload["velvet_ledger_report"]["thread_validation"]["status"] == "pass"
    assert payload["incident_window"]["segment"] == "1-3"
    assert payload["vault"]["verification_status"] == "pass"
    assert payload["claims_pack"]["assurance_verification_status"] == "pass"
    assert payload["claims_pack"]["replay_verification_status"] == "pass"
    assert (output_dir / "vault" / "signed_tree_head.json").exists()
    assert (output_dir / "vault" / "vault_public_key.pem").exists()
    assert (output_dir / "vault" / "vault_verification_report.json").exists()
    assert (output_dir / "claims_pack" / "manifest.json").exists()
    assert (output_dir / "claims_pack.result.json").exists()

    seal_id = payload["decisions"][0]["admission_decision"]["seal_id"]
    assert (
        main(
            [
                "replay",
                "--thread",
                str(output_dir / "mcp_thread.jsonl"),
                "--seal-id",
                seal_id,
                "--policies-dir",
                str(ROOT / "examples" / "mcp" / "policies"),
                "--chain",
                "mcp_demo",
                "--json",
            ]
        )
        == 0
    )
    replay = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert replay["status"] == "pass"


def test_launch_demo_writes_velvet_ledger_artifacts(tmp_path: Path) -> None:
    payload = run_launch_demo(tmp_path)

    assert Path(payload["thread_path"]).exists()
    assert Path(payload["ledger_path"]).exists()
    assert (tmp_path / "velvet_ledger_report.md").exists()
    assert payload["single_thing_not_cut"].startswith("Velvet Warrant")
    manifest = EvidenceManifest.from_dict(
        cast(Mapping[str, Any], payload["evidence_manifest"])
    )
    assert manifest.artifacts
    assert all(len(artifact.sha256) == 64 for artifact in manifest.artifacts)
    assert {artifact.artifact_type for artifact in manifest.artifacts} >= {
        "ledger_segment_binary",
        "ledger_segment_manifest",
        "evidence_pack_markdown",
        "evidence_pack_json",
        "policy_bundle_snapshot",
        "tool_inventory_snapshot",
        "replay_report",
        "vault_signed_tree_head",
        "vault_public_key",
        "vault_verification_report",
        "claims_pack_result",
        "claims_pack_manifest",
        "assurance_attestation_series",
        "assurance_consistency_proofs",
        "assurance_verification_report",
        "claims_replay_verification_report",
    }
    assert payload["vault"]["verification_status"] == "pass"
    assert payload["claims_pack"]["assurance_verification_status"] == "pass"
    assert payload["claims_pack"]["replay_verification_status"] == "pass"
    store = LocalFilesystemEvidenceStore(cast(str, payload["evidence_store_root"]))
    assert store.verify_manifest(manifest).status == "pass"
