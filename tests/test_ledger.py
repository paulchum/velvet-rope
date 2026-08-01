from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.cli import main
from velvet.ledger import (
    LEDGER_CONTRACT,
    VelvetLedger,
    _write_binary_records,
    build_ledger_segment_manifest,
    build_velvet_ledger_report,
    read_ledger_records,
    verify_velvet_ledger,
)
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import AdmissionDecision, VelvetToolCall

ROOT = Path(__file__).resolve().parents[1]


def _demo_requests() -> tuple[dict[str, Any], ...]:
    return tuple(dict(item) for item in load_requests(ROOT / "examples" / "mcp" / "workflow.json"))


def _adapter() -> DirectVelvetMCPAdapter:
    return DirectVelvetMCPAdapter.from_list_file(ROOT / "examples" / "mcp" / "list.json")


def _decision_for_request(
    adapter: DirectVelvetMCPAdapter,
    request: Mapping[str, Any],
) -> AdmissionDecision:
    return adapter.firewall.authorize(
        VelvetToolCall(
            server=str(request["server"]),
            tool=str(request["tool"]),
            arguments=cast(Mapping[str, Any], request.get("arguments", {})),
            user_request=str(request.get("user_request", "")),
            untrusted_content=cast(str | None, request.get("untrusted_content")),
        ),
        state=cast(Mapping[str, object] | None, request.get("state")),
    )


def _write_demo_ledger(
    tmp_path: Path,
    *,
    signing_key: str | None = None,
) -> Path:
    ledger_path = tmp_path / "ledger.vledger"
    adapter = _adapter()
    ledger = VelvetLedger(ledger_path, signing_key=signing_key, signing_key_id="test-key")
    for request in _demo_requests():
        ledger.write_admission_decision(
            _decision_for_request(adapter, request),
            request=request,
            label="test_ledger",
        )
    return ledger_path


def _read_records(path: Path) -> list[dict[str, Any]]:
    return list(read_ledger_records(path))


def _write_records(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    _write_binary_records(path, records)


def _issue_codes(report: Mapping[str, Any]) -> set[str]:
    return {str(issue["code"]) for issue in cast(list[Mapping[str, Any]], report["issues"])}


def _modify_reason(records: list[dict[str, Any]]) -> None:
    records[0]["reason"] = "modified after write"


def _delete_middle(records: list[dict[str, Any]]) -> None:
    records.pop(1)


def _reverse_records(records: list[dict[str, Any]]) -> None:
    records.reverse()


def _change_warrant(records: list[dict[str, Any]]) -> None:
    cast(dict[str, Any], records[0]["selected_warrant"])["reason_codes"] = ["changed_warrant"]


def _change_decision(records: list[dict[str, Any]]) -> None:
    records[0]["decision"] = "block"


def _break_previous_hash(records: list[dict[str, Any]]) -> None:
    records[1]["previous_record_hash"] = f"sha256:{'1' * 64}"


def test_writer_hash_chain_verifies_and_reports(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path)

    records = _read_records(ledger_path)
    assert [record["sequence_number"] for record in records] == [1, 2, 3]
    assert all(record["contract"] == LEDGER_CONTRACT for record in records)
    assert all("request" not in record and "warrants" not in record for record in records)
    assert records[1]["previous_record_hash"] == records[0]["record_hash"]
    assert all(record["record_hash"].startswith("sha256:") for record in records)

    verification = verify_velvet_ledger(ledger_path)
    assert verification["status"] == "pass"
    assert verification["canonical_records"] == 3

    report = build_velvet_ledger_report(ledger_path)
    assert report["summary"]["decision_counts"] == {
        "block": 1,
        "escalate": 1,
        "execute": 1,
    }
    assert report["summary"]["ledger_verification_status"] == "pass"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (_modify_reason, "record_hash_mismatch"),
        (_delete_middle, "sequence_number_mismatch"),
        (_reverse_records, "previous_hash_mismatch"),
        (_change_warrant, "warrant_hash_mismatch"),
        (_change_decision, "decision_warrant_mismatch"),
        (_break_previous_hash, "previous_hash_mismatch"),
    ],
)
def test_verifier_detects_tampering(
    tmp_path: Path,
    mutate: Callable[[list[dict[str, Any]]], object],
    expected_code: str,
) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    records = _read_records(ledger_path)
    mutate(records)
    tampered_path = tmp_path / "tampered.vledger"
    _write_records(tampered_path, records)

    verification = verify_velvet_ledger(tampered_path)
    assert verification["status"] == "fail"
    assert expected_code in _issue_codes(verification)


def test_verifier_detects_bad_signature_when_enforced(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path, signing_key="correct-key")

    assert (
        verify_velvet_ledger(
            ledger_path,
            enforce_signatures=True,
            signing_key="correct-key",
        )["status"]
        == "pass"
    )
    verification = verify_velvet_ledger(
        ledger_path,
        enforce_signatures=True,
        signing_key="wrong-key",
    )
    assert verification["status"] == "fail"
    assert "signature_mismatch" in _issue_codes(verification)


def test_segment_manifest_detects_tail_deletion_when_supplied(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(build_ledger_segment_manifest(ledger_path), sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert verify_velvet_ledger(ledger_path, manifest_path=manifest_path)["status"] == "pass"

    records = _read_records(ledger_path)
    _write_records(ledger_path, records[:-1])
    verification = verify_velvet_ledger(ledger_path, manifest_path=manifest_path)
    assert verification["status"] == "fail"
    assert "checkpoint_record_count_mismatch" in _issue_codes(verification)


def test_cli_ledger_verify_and_tamper_demo(tmp_path: Path, capsys: object) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    assert main(["ledger", "verify", "--ledger", str(ledger_path), "--json"]) == 0
    verification = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert verification["status"] == "pass"

    output_dir = tmp_path / "tamper_demo"
    assert main(["tamper-demo", "--output-dir", str(output_dir), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["valid_verification"]["status"] == "pass"
    assert payload["tampered_verification"]["status"] == "fail"
    assert Path(payload["valid_ledger_path"]).exists()
    assert Path(payload["tampered_ledger_path"]).exists()
    assert Path(payload["html_path"]).exists()

    mutation = cast(Mapping[str, Any], payload["mutation"])
    assert mutation["field_path"] == "decision"
    assert mutation["record_id"]
    assert mutation["sequence_number"] == 2

    failure = cast(Mapping[str, Any], payload["failure"])
    assert failure["offending_record_id"] == mutation["record_id"]
    assert failure["altered_field"] == "decision"
    record_hash_mismatch = cast(Mapping[str, Any], failure["record_hash_mismatch"])
    assert record_hash_mismatch["code"] == "record_hash_mismatch"
    assert record_hash_mismatch["record_id"] == mutation["record_id"]
    broken_link = cast(Mapping[str, Any], failure["broken_link"])
    broken_link_issue = cast(Mapping[str, Any], broken_link["issue"])
    assert broken_link_issue["code"] == "previous_hash_mismatch"
    assert broken_link_issue["sequence_number"] == mutation["next_sequence_number"]
    assert broken_link["expected_previous_record_hash"] == mutation["recomputed_record_hash"]
    assert broken_link["actual_previous_record_hash"] == mutation["next_previous_record_hash"]

    html = Path(payload["html_path"]).read_text(encoding="utf-8")
    assert "BROKEN LINK" in html
    assert "Failing Hash Comparison" in html
    assert "decision" in html
    assert str(mutation["record_id"]) in html


def test_unsupported_legacy_ledger_fails_verification(tmp_path: Path) -> None:
    ledger_path = tmp_path / "legacy.jsonl"
    legacy_field = "ledger_" + "schema_version"
    ledger_path.write_text(
        json.dumps({legacy_field: "velvet.ledger.v1", "decision": "execute"}) + "\n",
        encoding="utf-8",
    )

    report = verify_velvet_ledger(ledger_path)
    assert report["status"] == "fail"
    assert "binary_record_truncated" in _issue_codes(report)
