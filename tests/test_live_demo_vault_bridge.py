from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from velvet.binary_ledger import (
    BINARY_LEDGER_GENESIS_HASH,
    RECORD_KIND_OAP,
    append_record,
    iter_frames,
)
from velvet.cli import main
from velvet.ledger import LEDGER_GENESIS_HASH, ledger_record_hash
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_LEDGER_RECORD,
    default_demo_signer,
    sign_payload_hash,
)
from velvet.vault.verify import verify_vault_segment

ROOT = Path(__file__).resolve().parents[1]

POLICY_HASH = "sha256:7a33625810215c508b2bed21e5e79842771b1cc6867ae038b5ffef7b2a5f2234"
TOOL_SCHEMA_HASH = "sha256:8a33625810215c508b2bed21e5e79842771b1cc6867ae038b5ffef7b2a5f2234"
REQUEST_HASH = "sha256:9a33625810215c508b2bed21e5e79842771b1cc6867ae038b5ffef7b2a5f2234"
ARGUMENTS_HASH = "sha256:aa33625810215c508b2bed21e5e79842771b1cc6867ae038b5ffef7b2a5f2234"


def _load_bridge_module() -> ModuleType:
    module_name = "velvet_live_demo_vault_bridge_test"
    module_path = ROOT / "demo" / "incident" / "vault_bridge.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


BRIDGE = _load_bridge_module()
LiveDemoVaultBridgeError = BRIDGE.LiveDemoVaultBridgeError
export_argument_drift_vault_artifacts = BRIDGE.export_argument_drift_vault_artifacts


def test_live_demo_bridge_exports_vault_compatible_segment(tmp_path: Path) -> None:
    source_ledger = tmp_path / "proxy-ledger.vledger"
    _write_proxy_style_ledger(source_ledger)

    artifacts = export_argument_drift_vault_artifacts(
        proxy_ledger_path=source_ledger,
        output_dir=tmp_path / "vault",
        policy_hash=POLICY_HASH,
    )

    assert artifacts.segment_range == "1-2"
    assert artifacts.incident_window_start == "2026-06-13T12:00:01.000000Z"
    assert artifacts.incident_window_end == "2026-06-13T12:00:02.000001Z"
    report = verify_vault_segment(
        segment_range=artifacts.segment_range,
        sth_path=artifacts.sth_path,
        public_key=artifacts.public_key_path.read_text(encoding="utf-8"),
        ledger_path=artifacts.ledger_path,
    )
    assert report["status"] == "pass"

    exported_frames = list(iter_frames(artifacts.ledger_path))
    assert exported_frames[0].payload["signature"]["algorithm"] == "Ed25519"
    assert exported_frames[0].metadata["signature"]["algorithm"] == "Ed25519"
    manifest = json.loads(artifacts.manifest_path.read_text(encoding="utf-8"))
    assert manifest["source"]["proxy_ledger"] == str(source_ledger)
    assert manifest["export"]["ledger"] == str(artifacts.ledger_path)


def test_live_demo_bridge_artifacts_feed_claims_pack(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_ledger = tmp_path / "proxy-ledger.vledger"
    _write_proxy_style_ledger(source_ledger)
    artifacts = export_argument_drift_vault_artifacts(
        proxy_ledger_path=source_ledger,
        output_dir=tmp_path / "vault",
        policy_hash=POLICY_HASH,
    )
    output_dir = tmp_path / "claims_pack"

    assert (
        main(
            [
                "claims-pack",
                "--incident-window",
                artifacts.incident_window_start,
                artifacts.incident_window_end,
                "--ledger",
                str(artifacts.ledger_path),
                "--sth",
                str(artifacts.sth_path),
                "--public-key-file",
                str(artifacts.public_key_path),
                "--output-dir",
                str(output_dir),
                "--system-name",
                "Velvet live drift-rejection demo",
                "--intended-purpose",
                "Pre-execution action admission for the local live-demo target",
                "--deployer-legal-entity",
                "Velvet Demo Ltd.",
                "--eu-exposure",
                "false",
                "--deployment-id-source",
                "velvet-live-demo/local",
                "--deployment-salt",
                "velvet-live-demo-demo-salt",
                "--signing-profile",
                "demo",
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["assurance_verification"]["status"] == "pass"
    assert payload["attestation_pack_manifest"]["segment"]["range"] == "1-2"
    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "records" / "ledger_segment.vledger").exists()


def test_live_demo_bridge_refuses_tampered_source_record_hash(tmp_path: Path) -> None:
    source_ledger = tmp_path / "proxy-ledger.vledger"
    _write_proxy_style_ledger(source_ledger, tamper_first_record_hash=True)

    with pytest.raises(LiveDemoVaultBridgeError, match="record_hash"):
        export_argument_drift_vault_artifacts(
            proxy_ledger_path=source_ledger,
            output_dir=tmp_path / "vault",
            policy_hash=POLICY_HASH,
        )


def test_live_demo_bridge_refuses_missing_policy_hash(tmp_path: Path) -> None:
    source_ledger = tmp_path / "proxy-ledger.vledger"
    _write_proxy_style_ledger(source_ledger, policy_hash=None)

    with pytest.raises(LiveDemoVaultBridgeError, match="policy_hash"):
        export_argument_drift_vault_artifacts(
            proxy_ledger_path=source_ledger,
            output_dir=tmp_path / "vault",
        )


def _write_proxy_style_ledger(
    path: Path,
    *,
    policy_hash: str | None = POLICY_HASH,
    tamper_first_record_hash: bool = False,
) -> None:
    signer = default_demo_signer()
    previous_record_hash = LEDGER_GENESIS_HASH
    previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    for sequence in (1, 2):
        record = _proxy_style_record(
            sequence=sequence,
            previous_record_hash=previous_record_hash,
            policy_hash=policy_hash,
        )
        if tamper_first_record_hash and sequence == 1:
            record["record_hash"] = f"sha256:{'f' * 64}"
        frame = append_record(
            path,
            record,
            kind=RECORD_KIND_OAP,
            sequence_number=sequence,
            previous_frame_hash=previous_frame_hash,
            signer=signer,
            tenant_id=LOCAL_DEMO_TENANT_ID,
            key_id=LOCAL_DEMO_KEY_ID,
        )
        previous_record_hash = str(record["record_hash"])
        previous_frame_hash = frame.frame_hash


def _proxy_style_record(
    *,
    sequence: int,
    previous_record_hash: str,
    policy_hash: str | None,
) -> dict[str, Any]:
    reason = "canonical action hash mismatch at executor dispatch validation"
    record: dict[str, Any] = {
        "oap_contract": "velvet.oap_ledger.v1",
        "record_type": "pre_execution_decision",
        "record_id": f"lr_argument_drift_{sequence}",
        "tenant_id": LOCAL_DEMO_TENANT_ID,
        "environment": "local",
        "sequence_number": sequence,
        "recorded_at": f"2026-06-13T12:00:0{sequence}.000000Z",
        "previous_record_hash": previous_record_hash,
        "record_hash": "",
        "decision_id": "dec_argument_drift",
        "state": "block",
        "oap_passport": {"passport_id": "pass_argument_drift"},
        "oap_decision": {"decision_id": "dec_argument_drift", "decision": "deny"},
        "oap_decision_digest": f"sha256:{'1' * 64}",
        "decision_payload_digest": f"sha256:{'2' * 64}",
        "signed_decision_digest": f"sha256:{'3' * 64}",
        "decision_signature_hash": f"sha256:{'4' * 64}",
        "admission_evidence_hash": f"sha256:{'5' * 64}",
        "admission_evidence_ref": None,
        "admission_evidence": {
            "decision": {"decision": "block", "reason": reason},
            "risk": {"risk_class": "spend"},
        },
        "max_de_certificate_required": False,
        "max_de_requirement_reason": None,
        "max_de_certificate_envelope": None,
        "max_de_certificate_envelope_digest": None,
        "passport_digest": f"sha256:{'6' * 64}",
        "standard_boundary": "local live-demo proxy boundary",
        "persistence_metadata": {"boundary": "pre_execution"},
        "thread_id": "thread_argument_drift",
        "product_surface": "mcp_proxy",
        "action_type": "CALL_TOOL",
        "decision": "block",
        "reason": reason,
        "tool_key": "velvet-live-target/issue_refund",
        "policy_hash": policy_hash,
        "policy_version": "mcp_demo",
        "tool_schema_hash": TOOL_SCHEMA_HASH,
        "arguments_hash": ARGUMENTS_HASH,
        "request_hash": REQUEST_HASH,
        "tenant_id_hash": f"sha256:{'7' * 64}",
        "owner_id_hash": None,
        "subject_id_hash": None,
        "agent_id_hash": None,
        "client_id_hash": None,
        "session_id_hash": None,
        "redaction_summary": {"mode": "hash_only"},
        "label": "mcp_oap_authorization_pre_execution",
        "proxy": "velvet-rope-proxy",
        "mcp_spec_target": "2025-11-25",
        "inventory_status": "approved",
        "upstream_request_hash": None,
        "upstream_response_hash": None,
        "upstream_status": None,
        "forwarding_proof": None,
        "pre_execution_record_hash": None,
        "completion_timestamp": None,
        "error_metadata": None,
        "approval_request_id": None,
        "approval_request_hash": None,
        "approval_status": "not_required",
        "approval_receipt_id": None,
        "decision_latency_ms": 1,
        "oap_performance": None,
    }
    record["record_hash"] = ledger_record_hash(record)
    record["signature"] = sign_payload_hash(
        str(record["record_hash"]),
        purpose=PURPOSE_LEDGER_RECORD,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=LOCAL_DEMO_KEY_ID,
        signer=default_demo_signer(),
    )
    return record
