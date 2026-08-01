from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.assurance import (
    issue_control_state_attestation,
    load_ledger_records,
    verify_control_state_attestation,
)
from velvet.assurance.attestation import (
    CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA,
    AssuranceAttestationError,
    validate_payload_schema_content_free,
)
from velvet.assurance.export import (
    drain_webhook_spool,
    push_attestations_webhook,
    write_manual_bundle,
)
from velvet.cli import main
from velvet.ledger import VelvetLedger, read_ledger_records
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import VelvetToolCall
from velvet.serialization import canonical_dumps
from velvet.signing import DEMO_ED25519_PUBLIC_KEY_BASE64, load_demo_ed25519_signer
from velvet.vault.merkle import build_consistency_proof
from velvet.vault.sth import build_signed_tree_head

ROOT = Path(__file__).resolve().parents[1]
JsonObject = dict[str, Any]


def test_control_state_payload_is_deterministic_and_content_free(tmp_path: Path) -> None:
    ledger_path, sth_path, _public_key_path = _write_demo_vault(tmp_path)
    records = load_ledger_records(ledger_path)
    sth = json.loads(sth_path.read_text(encoding="utf-8"))
    signer = load_demo_ed25519_signer()

    first = issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start="2000-01-01T00:00:00Z",
        period_end="2100-01-01T00:00:00Z",
        deployment_id_source="tenant-a/prod",
        deployment_salt="salt-a",
        signer=signer,
        signed_at="2026-06-12T00:00:00.000000Z",
        retention_preset="eu_ai_act_minimum",
    )
    second = issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start="2000-01-01T00:00:00Z",
        period_end="2100-01-01T00:00:00Z",
        deployment_id_source="tenant-a/prod",
        deployment_salt="salt-a",
        signer=signer,
        signed_at="2026-06-12T00:00:00.000000Z",
        retention_preset="eu_ai_act_minimum",
    )

    assert canonical_dumps(first["payload"]) == canonical_dumps(second["payload"])
    assert first["payload_hash"] == second["payload_hash"]
    assert first["payload"]["gateway_liveness"]["decisions_observed"] == 3
    assert first["payload"]["evidence_plane"]["retention_preset"] == "eu_ai_act_minimum"
    assert "tool_key" not in canonical_dumps(first["payload"])
    validate_payload_schema_content_free()


def test_attestation_signature_tampering_is_detected(tmp_path: Path) -> None:
    ledger_path, sth_path, _public_key_path = _write_demo_vault(tmp_path)
    records = load_ledger_records(ledger_path)
    sth = json.loads(sth_path.read_text(encoding="utf-8"))
    signer = load_demo_ed25519_signer()
    attestation = issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start="2000-01-01T00:00:00Z",
        period_end="2100-01-01T00:00:00Z",
        deployment_id_source="tenant-a/prod",
        deployment_salt="salt-a",
        signer=signer,
    )

    assert verify_control_state_attestation(
        attestation,
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
    )
    tampered = copy.deepcopy(attestation)
    tampered["payload"]["gateway_liveness"]["decisions_observed"] = 99

    assert not verify_control_state_attestation(
        tampered,
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
    )


def test_denylist_rejects_free_text_schema_field() -> None:
    schema_path = ROOT / "schemas" / "velvet_rope" / "control_state_attestation.v1.schema.json"
    checked_in_schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert checked_in_schema == CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA
    validate_payload_schema_content_free(checked_in_schema)
    schema = copy.deepcopy(CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA)
    cast(dict[str, Any], schema["properties"])["prompt_text"] = {"type": "string"}

    with pytest.raises(AssuranceAttestationError):
        validate_payload_schema_content_free(schema)

    schema = copy.deepcopy(CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA)
    cast(dict[str, Any], schema["properties"])["opaque_status"] = {"type": "string"}

    with pytest.raises(AssuranceAttestationError):
        validate_payload_schema_content_free(schema)

    schema = copy.deepcopy(CONTROL_STATE_ATTESTATION_PAYLOAD_SCHEMA)
    cast(dict[str, Any], schema["properties"])["open_counts"] = {
        "type": "object",
        "additionalProperties": True,
    }

    with pytest.raises(AssuranceAttestationError):
        validate_payload_schema_content_free(schema)


def test_offline_verifier_detects_gap_and_tampering_from_cold_bundle(tmp_path: Path) -> None:
    ledger_path, sth_path, public_key_path = _write_demo_vault(tmp_path)
    records = load_ledger_records(ledger_path)
    sth = json.loads(sth_path.read_text(encoding="utf-8"))
    signer = load_demo_ed25519_signer()
    first = issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start="2200-01-01T00:00:00Z",
        period_end="2200-01-02T00:00:00Z",
        deployment_id_source="tenant-a/prod",
        deployment_salt="salt-a",
        signer=signer,
    )
    second = issue_control_state_attestation(
        records=records,
        sth=sth,
        period_start="2200-01-03T00:00:00Z",
        period_end="2200-01-04T00:00:00Z",
        deployment_id_source="tenant-a/prod",
        deployment_salt="salt-a",
        signer=signer,
    )
    bundle = tmp_path / "bundle"
    write_manual_bundle(attestations=[first, second], output_dir=bundle)
    verifier = _load_verifier()

    report = verifier.verify_attestation_series(
        verifier.load_attestations_jsonl(bundle / "attestations.jsonl"),
        public_key=public_key_path.read_text(encoding="utf-8"),
        consistency_proofs=verifier.load_consistency_proofs(bundle / "consistency_proofs.json"),
    )

    assert report["status"] == "fail"
    assert "period_gap" in {issue["code"] for issue in report["issues"]}

    tampered = copy.deepcopy(first)
    tampered["payload"]["period"]["end"] = "2200-01-02T00:00:01.000000Z"
    report = verifier.verify_attestation_series(
        [tampered],
        public_key=public_key_path.read_text(encoding="utf-8"),
    )
    assert report["status"] == "fail"
    assert "payload_hash_mismatch" in {issue["code"] for issue in report["issues"]}


def test_offline_verifier_accepts_consistent_growing_series() -> None:
    attestations, proof = _growing_attestation_series()
    verifier = _load_verifier()

    report = verifier.verify_attestation_series(
        attestations,
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
        consistency_proofs=[proof],
    )

    assert report["status"] == "pass"


def test_js_verifier_matches_python_fail_closed_checks() -> None:
    attestations, proof = _growing_attestation_series()

    report = _run_js_verifier(attestations=attestations, consistency_proofs=[proof])
    assert report["status"] == "pass"

    tampered = copy.deepcopy(attestations)
    tampered[0]["payload"]["gateway_liveness"]["decisions_observed"] = 99
    report = _run_js_verifier(attestations=tampered, consistency_proofs=[proof])
    assert report["status"] == "fail"
    assert "payload_hash_mismatch" in {issue["code"] for issue in report["issues"]}

    gapped, gapped_proof = _growing_attestation_series(gapped=True)
    report = _run_js_verifier(attestations=gapped, consistency_proofs=[gapped_proof])
    assert report["status"] == "fail"
    assert "period_gap" in {issue["code"] for issue in report["issues"]}

    report = _run_js_verifier(attestations=attestations, consistency_proofs=[])
    assert report["status"] == "fail"
    assert "sth_consistency_proof_missing" in {issue["code"] for issue in report["issues"]}

    invalid_proof = dict(copy.deepcopy(proof))
    invalid_proof["proof"] = [f"sha256:{'0' * 64}"]
    report = _run_js_verifier(attestations=attestations, consistency_proofs=[invalid_proof])
    assert report["status"] == "fail"
    assert "sth_consistency_proof_invalid" in {issue["code"] for issue in report["issues"]}

    count_mismatch = copy.deepcopy(attestations)
    count_mismatch[0]["payload"]["decision_counts"]["admit"]["low"] = 2
    report = _run_js_verifier(attestations=count_mismatch, consistency_proofs=[proof])
    assert report["status"] == "fail"
    assert "decision_counts_exceed_tree_growth" in {issue["code"] for issue in report["issues"]}


def test_webhook_export_spools_on_failure(tmp_path: Path) -> None:
    class FailingTransport:
        def post(
            self,
            url: str,
            body: bytes,
            headers: Mapping[str, str],
            timeout: float,
        ) -> int:
            del url, body, headers, timeout
            return 503

    result = push_attestations_webhook(
        attestations=[{"schema_version": "example"}],
        url="https://carrier.example.invalid/ingest",
        spool_dir=tmp_path / "spool",
        transport=FailingTransport(),
        retries=1,
    )

    assert result.status == "degraded"
    assert result.spooled == 1
    assert Path(result.spool_paths[0]).exists()


def test_webhook_export_rejects_non_http_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="webhook URL must use http or https"):
        push_attestations_webhook(
            attestations=[{"schema_version": "example"}],
            url="file:///tmp/attestations",
            spool_dir=tmp_path / "spool",
        )


def test_webhook_spool_drain_retries_and_removes_delivered_files(tmp_path: Path) -> None:
    class SucceedingTransport:
        def post(
            self,
            url: str,
            body: bytes,
            headers: Mapping[str, str],
            timeout: float,
        ) -> int:
            del url, body, headers, timeout
            return 204

    spool = tmp_path / "spool"
    push_attestations_webhook(
        attestations=[{"schema_version": "example"}],
        url="https://carrier.example.invalid/ingest",
        spool_dir=spool,
        transport=SucceedingTransport(),
        retries=1,
    )
    assert not list(spool.iterdir())

    (spool / "attestation_000000_deadbeef.json").write_text(
        '{"schema_version":"example"}\n',
        encoding="utf-8",
    )
    result = drain_webhook_spool(
        url="https://carrier.example.invalid/ingest",
        spool_dir=spool,
        transport=SucceedingTransport(),
        retries=1,
    )

    assert result.status == "ok"
    assert result.delivered == 1
    assert not list(spool.iterdir())


def test_scheduled_assurance_cli_appends_idempotently(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger_path, sth_path, _public_key_path = _write_demo_vault(tmp_path)
    attestations_path = tmp_path / "scheduled.jsonl"
    command = [
        "assurance",
        "issue-scheduled",
        "--cadence",
        "daily",
        "--now",
        "2026-01-03T12:34:56Z",
        "--ledger",
        str(ledger_path),
        "--sth",
        str(sth_path),
        "--deployment-id-source",
        "tenant-a/prod",
        "--deployment-salt",
        "salt-a",
        "--output",
        str(attestations_path),
        "--signing-profile",
        "demo",
        "--json",
    ]

    assert main(command) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["export"]["status"] == "appended"
    assert first["period"]["start"] == "2026-01-02T00:00:00.000000Z"
    assert first["period"]["end"] == "2026-01-03T00:00:00.000000Z"

    assert main(command) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["export"]["status"] == "already_present"
    assert len(attestations_path.read_text(encoding="utf-8").splitlines()) == 1


def test_assurance_and_claims_pack_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ledger_path, sth_path, public_key_path = _write_demo_vault(tmp_path)
    attestations_path = tmp_path / "attestations.jsonl"

    assert (
        main(
            [
                "assurance",
                "issue-attestation",
                "--ledger",
                str(ledger_path),
                "--sth",
                str(sth_path),
                "--period-start",
                "2000-01-01T00:00:00Z",
                "--period-end",
                "2100-01-01T00:00:00Z",
                "--deployment-id-source",
                "tenant-a/prod",
                "--deployment-salt",
                "salt-a",
                "--output",
                str(attestations_path),
                "--signing-profile",
                "demo",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["export"]["attestation_count"] == 1
    assert attestations_path.exists()

    output_dir = tmp_path / "claims"
    assert (
        main(
            [
                "claims-pack",
                "--incident-window",
                "2000-01-01T00:00:00Z",
                "2100-01-01T00:00:00Z",
                "--ledger",
                str(ledger_path),
                "--sth",
                str(sth_path),
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
                "--deployment-id-source",
                "tenant-a/prod",
                "--deployment-salt",
                "salt-a",
                "--signing-profile",
                "demo",
                "--json",
            ]
        )
        == 0
    )
    claims_payload = json.loads(capsys.readouterr().out)
    assert claims_payload["assurance_export"]["attestation_count"] == 1
    assert claims_payload["assurance_verification"]["status"] == "pass"
    assert (output_dir / "assurance" / "attestations.jsonl").exists()
    assert (output_dir / "assurance" / "consistency_proofs.json").exists()
    assert (output_dir / "verification" / "assurance_verification_report.json").exists()
    assert (output_dir / "verification" / "claims_replay_verification_report.json").exists()


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
        ledger.write_admission_decision(decision, request=request, label="assurance_test")
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


def _growing_attestation_series(
    *,
    gapped: bool = False,
) -> tuple[list[Mapping[str, Any]], Mapping[str, Any]]:
    signer = load_demo_ed25519_signer()
    policy_hash = f"sha256:{'a' * 64}"
    record_hashes = [f"sha256:{index:064x}" for index in range(1, 3)]
    records: list[Mapping[str, Any]] = [
        {
            "recorded_at": "2026-01-01T00:00:00.000000Z",
            "record_hash": record_hashes[0],
            "policy_hash": policy_hash,
            "decision": "execute",
            "selected_warrant": {"risk_class": "low", "decision": "execute"},
        },
        {
            "recorded_at": "2026-01-02T00:00:00.000000Z",
            "record_hash": record_hashes[1],
            "policy_hash": policy_hash,
            "decision": "block",
            "selected_warrant": {"risk_class": "high", "decision": "block"},
        },
    ]
    first_sth = build_signed_tree_head(
        record_hashes=record_hashes[:1],
        first_sequence=1,
        policy_hash=policy_hash,
        signer=signer,
    )
    second_sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=policy_hash,
        signer=signer,
    )
    second_start = "2026-01-02T00:00:01Z" if gapped else "2026-01-02T00:00:00Z"
    attestations: list[Mapping[str, Any]] = [
        issue_control_state_attestation(
            records=records,
            sth=first_sth,
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-01-02T00:00:00Z",
            deployment_id_source="tenant-a/prod",
            deployment_salt="salt-a",
            signer=signer,
        ),
        issue_control_state_attestation(
            records=records,
            sth=second_sth,
            period_start=second_start,
            period_end="2026-01-03T00:00:00Z",
            deployment_id_source="tenant-a/prod",
            deployment_salt="salt-a",
            signer=signer,
        ),
    ]
    return attestations, build_consistency_proof(record_hashes[:1], record_hashes)


def _run_js_verifier(
    *,
    attestations: Sequence[Mapping[str, Any]],
    consistency_proofs: Sequence[Mapping[str, Any]],
) -> JsonObject:
    node = shutil.which("node")
    assert node is not None
    runner = """
const verifier = require(process.argv[1]);
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", async () => {
  const payload = JSON.parse(input);
  const report = await verifier.verifyAttestationSeries(
    payload.attestations,
    payload.publicKey,
    { consistencyProofs: payload.consistencyProofs },
  );
  process.stdout.write(JSON.stringify(report));
});
""".strip()
    completed = subprocess.run(  # noqa: S603 - node path is resolved locally for verifier tests.
        [node, "-e", runner, str(ROOT / "assurance" / "verifier" / "velvet-assurance-verifier.js")],
        input=json.dumps(
            {
                "attestations": attestations,
                "consistencyProofs": consistency_proofs,
                "publicKey": DEMO_ED25519_PUBLIC_KEY_BASE64,
            }
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    return cast(JsonObject, json.loads(completed.stdout))


def _load_verifier() -> Any:
    verifier_path = ROOT / "assurance" / "verifier" / "velvet_assurance_verifier" / "verifier.py"
    spec = importlib.util.spec_from_file_location("standalone_assurance_verifier", verifier_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module
