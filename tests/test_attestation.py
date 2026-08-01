from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.attestation.mapping import build_coverage_report
from velvet.attestation.pack import AttestationPackError, write_attestation_pack
from velvet.cli import main
from velvet.ledger import VelvetLedger, read_ledger_records
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import VelvetToolCall
from velvet.signing import DEMO_ED25519_PUBLIC_KEY_BASE64, load_demo_ed25519_signer
from velvet.vault.merkle import verify_consistency_proof_artifact
from velvet.vault.sth import build_signed_tree_head

ROOT = Path(__file__).resolve().parents[1]


def test_coverage_report_prominently_lists_unmapped_fields() -> None:
    report = build_coverage_report(
        records=[],
        sth={},
        verification_report={"status": "pass"},
        deployment_metadata={"system_name": "Velvet"},
        approval_receipts=(),
    )

    unmapped = {
        item["field_id"]
        for item in cast(list[Mapping[str, Any]], report["not_evidenced_by_velvet"])
    }
    assert "biometric.reference_database" in unmapped
    assert "verification.natural_person_identity" in unmapped
    fields = {item["field_id"]: item for item in cast(list[Mapping[str, Any]], report["fields"])}
    assert fields["biometric.reference_database"]["not_evidenced_by_velvet"] is True


def test_attestation_pack_cli_writes_bundle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger_path, sth_path, public_key_path = _write_demo_vault(tmp_path)
    output_dir = tmp_path / "pack"

    assert (
        main(
            [
                "attestation-pack",
                "--ledger",
                str(ledger_path),
                "--sth",
                str(sth_path),
                "--segment",
                "1-3",
                "--public-key-file",
                str(public_key_path),
                "--output-dir",
                str(output_dir),
                "--system-name",
                "Velvet demo admission system",
                "--intended-purpose",
                "Pre-execution action admission for release operations",
                "--deployer-legal-entity",
                "Velvet Demo Ltd.",
                "--eu-exposure",
                "true",
                "--signing-profile",
                "demo",
                "--json",
            ]
        )
        == 0
    )
    manifest = json.loads(capsys.readouterr().out)

    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "coverage_report.json").exists()
    assert (output_dir / "records" / "ledger_segment.vledger").exists()
    assert (output_dir / "sth" / "signed_tree_head.json").exists()
    assert (output_dir / "sth" / "latest_signed_tree_head.json").exists()
    assert (output_dir / "verification" / "vault_verification_report.json").exists()
    assert (output_dir / "verification" / "browser_verifier.html").exists()
    assert (output_dir / "README.html").exists()
    assert manifest["deployment_metadata"]["eu_exposure"] is True
    assert manifest["file_hashes"]["coverage_report.json"]["sha256"].startswith("sha256:")
    coverage = json.loads((output_dir / "coverage_report.json").read_text(encoding="utf-8"))
    assert coverage["not_evidenced_by_velvet"]
    record = json.loads(
        (output_dir / "records" / "decision_record_000001.json").read_text(encoding="utf-8")
    )
    assert record["pack_recording_mode"] == "hash_only"
    readme = (output_dir / "README.html").read_text(encoding="utf-8")
    assert "verification/browser_verifier.html" in readme


def test_attestation_pack_writes_latest_sth_consistency_proof(tmp_path: Path) -> None:
    ledger_path, latest_sth_path, public_key_path = _write_demo_vault(tmp_path)
    records = list(read_ledger_records(ledger_path))
    signer = load_demo_ed25519_signer()
    covering_sth = build_signed_tree_head(
        record_hashes=[str(record["record_hash"]) for record in records[:2]],
        first_sequence=1,
        policy_hash=str(records[1]["policy_hash"]),
        signer=signer,
    )
    covering_sth_path = tmp_path / "covering_sth.json"
    covering_sth_path.write_text(json.dumps(covering_sth, sort_keys=True) + "\n", encoding="utf-8")
    output_dir = tmp_path / "pack"

    write_attestation_pack(
        ledger_path=ledger_path,
        sth_path=covering_sth_path,
        public_key=public_key_path.read_text(encoding="utf-8"),
        output_dir=output_dir,
        system_name="Velvet demo admission system",
        intended_purpose="Pre-execution action admission for release operations",
        deployer_legal_entity="Velvet Demo Ltd.",
        eu_exposure=True,
        signer=signer,
        signing_key_id="demo-not-for-production",
        segment_range="1-2",
        latest_sth_path=latest_sth_path,
    )

    proof = json.loads(
        (output_dir / "sth" / "consistency_to_latest.json").read_text(encoding="utf-8")
    )
    latest = json.loads(
        (output_dir / "sth" / "latest_signed_tree_head.json").read_text(encoding="utf-8")
    )
    assert proof["old_tree_size"] == 2
    assert proof["new_tree_size"] == 3
    assert proof["latest_anchor_status"] == "latest_sth_supplied"
    assert proof["latest_root_hash"] == latest["root_hash"]
    assert verify_consistency_proof_artifact(proof)


def test_attestation_pack_refuses_tampered_sth(tmp_path: Path) -> None:
    ledger_path, sth_path, _public_key_path = _write_demo_vault(tmp_path)
    signer = load_demo_ed25519_signer()
    tampered = json.loads(sth_path.read_text(encoding="utf-8"))
    tampered["root_hash"] = f"sha256:{'f' * 64}"
    tampered_path = tmp_path / "tampered_sth.json"
    tampered_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(AttestationPackError):
        write_attestation_pack(
            ledger_path=ledger_path,
            sth_path=tampered_path,
            public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
            output_dir=tmp_path / "tampered_pack",
            system_name="Velvet demo admission system",
            intended_purpose="Pre-execution action admission for release operations",
            deployer_legal_entity="Velvet Demo Ltd.",
            eu_exposure=True,
            signer=signer,
            signing_key_id="demo-not-for-production",
            segment_range="1-3",
        )


def _write_demo_vault(tmp_path: Path) -> tuple[Path, Path, Path]:
    signer = load_demo_ed25519_signer()
    adapter = DirectVelvetMCPAdapter.from_list_file(
        ROOT / "examples" / "mcp" / "list.json",
        signing_profile="demo",
    )
    ledger_path = tmp_path / "ledger.vledger"
    ledger = VelvetLedger(
        ledger_path,
        signer=signer,
        signing_key_id="demo-not-for-production",
    )
    for request in list(load_requests(ROOT / "examples" / "mcp" / "workflow.json"))[:3]:
        decision = adapter.firewall.authorize(
            VelvetToolCall(
                server=str(request["server"]),
                tool=str(request["tool"]),
                arguments=cast(Mapping[str, Any], request.get("arguments", {})),
                user_request=str(request.get("user_request", "")),
                untrusted_content=cast(str | None, request.get("untrusted_content")),
            ),
            state=cast(Mapping[str, object] | None, request.get("state")),
        )
        ledger.write_admission_decision(decision, request=request, label="attestation_test")
    records = list(read_ledger_records(ledger_path))
    sth = build_signed_tree_head(
        record_hashes=[str(record["record_hash"]) for record in records],
        first_sequence=1,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=signer,
    )
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth, sort_keys=True) + "\n", encoding="utf-8")
    public_key_path = tmp_path / "demo.pub"
    material = signer.public_verification_material("demo-not-for-production")
    assert material is not None
    public_key_path.write_text(str(material["public_key_pem"]), encoding="utf-8")
    return ledger_path, sth_path, public_key_path
