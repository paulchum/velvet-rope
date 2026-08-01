from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.ledger import (
    LEDGER_GENESIS_HASH,
    VelvetLedger,
    _write_binary_records,
    build_ledger_segment_manifest,
    ledger_record_hash,
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
    name: str = "ledger.vledger",
    signing_key: str | None = None,
) -> Path:
    ledger_path = tmp_path / name
    adapter = _adapter()
    ledger = VelvetLedger(ledger_path, signing_key=signing_key, signing_key_id="test-key")
    for request in _demo_requests():
        ledger.write_admission_decision(
            _decision_for_request(adapter, request),
            request=request,
            label="tamper_evident_ledger_test",
        )
    return ledger_path


def _read_records(path: Path) -> list[dict[str, Any]]:
    return list(read_ledger_records(path))


def _write_records(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    _write_binary_records(path, records)


def _write_manifest(
    tmp_path: Path,
    ledger_path: Path,
    *,
    signing_key: str | None = None,
) -> Path:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            build_ledger_segment_manifest(ledger_path, signing_key=signing_key),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _issue_codes(report: Mapping[str, Any]) -> set[str]:
    return {str(issue["code"]) for issue in cast(list[Mapping[str, Any]], report["issues"])}


def _mutated_report(
    tmp_path: Path,
    mutate: Callable[[list[dict[str, Any]]], object],
) -> Mapping[str, Any]:
    ledger_path = _write_demo_ledger(tmp_path)
    manifest_path = _write_manifest(tmp_path, ledger_path)
    records = _read_records(ledger_path)
    mutate(records)
    tampered_path = tmp_path / "tampered.vledger"
    _write_records(tampered_path, records)
    return verify_velvet_ledger(tampered_path, manifest_path=manifest_path)


def _assert_detected(report: Mapping[str, Any], *expected_codes: str) -> None:
    assert report["status"] == "fail"
    codes = _issue_codes(report)
    for expected_code in expected_codes:
        assert expected_code in codes


def _replace_hash(value: object, replacement_digit: str) -> str:
    assert isinstance(value, str)
    replacement = f"sha256:{replacement_digit * 64}"
    assert value != replacement
    return replacement


def _strip_signatures_and_rehash(records: list[dict[str, Any]]) -> None:
    previous_hash = LEDGER_GENESIS_HASH
    for index, record in enumerate(records, start=1):
        record.pop("signature", None)
        record.pop("signer", None)
        record.pop("signing_key_id", None)
        record["sequence_number"] = index
        record["previous_record_hash"] = previous_hash
        record["record_hash"] = ledger_record_hash(record)
        previous_hash = str(record["record_hash"])


def test_valid_ledger_passes_with_manifest(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    manifest_path = _write_manifest(tmp_path, ledger_path)

    report = verify_velvet_ledger(ledger_path, manifest_path=manifest_path)

    assert report["status"] == "pass"
    assert report["manifest"]["status"] == "pass"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda records: records[0].__setitem__(
                "reason",
                "modified after checkpoint",
            ),
            "record_hash_mismatch",
        ),
        (
            lambda records: records[0].__setitem__(
                "policy_hash",
                _replace_hash(records[0]["policy_hash"], "a"),
            ),
            "record_hash_mismatch",
        ),
        (
            lambda records: records[0].__setitem__(
                "request_hash",
                _replace_hash(records[0]["request_hash"], "b"),
            ),
            "record_hash_mismatch",
        ),
        (
            lambda records: records[0].__setitem__(
                "tool_schema_hash",
                _replace_hash(records[0]["tool_schema_hash"], "c"),
            ),
            "record_hash_mismatch",
        ),
    ],
)
def test_manifest_bounded_payload_and_hash_mutations_are_detected(
    tmp_path: Path,
    mutate: Callable[[list[dict[str, Any]]], object],
    expected_code: str,
) -> None:
    report = _mutated_report(tmp_path, mutate)

    _assert_detected(report, expected_code)


def test_record_replacement_inside_manifest_segment_is_detected(tmp_path: Path) -> None:
    original_path = _write_demo_ledger(tmp_path, name="original.vledger")
    manifest_path = _write_manifest(tmp_path, original_path)
    replacement_path = _write_demo_ledger(tmp_path, name="replacement.vledger")
    records = _read_records(original_path)
    records[1] = _read_records(replacement_path)[1]
    tampered_path = tmp_path / "replaced.vledger"
    _write_records(tampered_path, records)

    report = verify_velvet_ledger(tampered_path, manifest_path=manifest_path)

    _assert_detected(report, "previous_hash_mismatch", "checkpoint_head_frame_hash_mismatch")


def test_insertion_inside_manifest_segment_is_detected(tmp_path: Path) -> None:
    report = _mutated_report(tmp_path, lambda records: records.insert(1, dict(records[1])))

    _assert_detected(report, "sequence_number_mismatch", "checkpoint_record_count_mismatch")


def test_deletion_inside_manifest_segment_is_detected(tmp_path: Path) -> None:
    report = _mutated_report(tmp_path, lambda records: records.pop(1))

    _assert_detected(report, "sequence_number_mismatch", "checkpoint_record_count_mismatch")


def test_reorder_inside_manifest_segment_is_detected(tmp_path: Path) -> None:
    report = _mutated_report(tmp_path, lambda records: records.reverse())

    _assert_detected(report, "previous_hash_mismatch", "checkpoint_head_frame_hash_mismatch")


def test_rehashed_malicious_segment_fails_against_original_manifest(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    manifest_path = _write_manifest(tmp_path, ledger_path)
    records = _read_records(ledger_path)
    records[0]["reason"] = "rewritten and rehashed after checkpoint publication"
    _strip_signatures_and_rehash(records)
    forged_path = tmp_path / "forged.vledger"
    _write_records(forged_path, records)

    local_report = verify_velvet_ledger(forged_path)
    checkpointed_report = verify_velvet_ledger(forged_path, manifest_path=manifest_path)

    assert local_report["status"] == "fail"
    _assert_detected(local_report, "admission_evidence_binding_mismatch")
    _assert_detected(checkpointed_report, "checkpoint_last_record_hash_mismatch")


def test_signed_manifest_mismatch_fails_when_signing_key_is_supplied(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path, signing_key="record-key")
    manifest_path = _write_manifest(tmp_path, ledger_path, signing_key="manifest-key")

    report = verify_velvet_ledger(
        ledger_path,
        manifest_path=manifest_path,
        signing_key="record-key",
    )

    _assert_detected(report, "checkpoint_signature_mismatch")


def test_unsigned_checkpoint_cannot_claim_signed_checkpoint_evidence(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path, signing_key="record-key")
    manifest_path = _write_manifest(tmp_path, ledger_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("signature", None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

    report = verify_velvet_ledger(
        ledger_path,
        manifest_path=manifest_path,
        signing_key="record-key",
    )

    _assert_detected(report, "checkpoint_signature_missing")


def test_trailing_byte_truncation_fails_strict_offline_verification(
    tmp_path: Path,
) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    truncated_path = tmp_path / "truncated.vledger"
    payload = ledger_path.read_bytes()
    truncated_path.write_bytes(payload[:-8])

    report = verify_velvet_ledger(truncated_path)

    _assert_detected(report, "binary_payload_truncated")


def test_header_corruption_fails_with_byte_level_issue(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    corrupted_path = tmp_path / "header_corrupt.vledger"
    payload = bytearray(ledger_path.read_bytes())
    payload[0] ^= 0xFF
    corrupted_path.write_bytes(payload)

    report = verify_velvet_ledger(corrupted_path)

    _assert_detected(report, "binary_magic_mismatch")
    issue = next(issue for issue in report["issues"] if issue["code"] == "binary_magic_mismatch")
    assert issue["byte_offset"] == 0


def test_append_recovers_only_corrupt_trailing_tail(tmp_path: Path) -> None:
    ledger_path = _write_demo_ledger(tmp_path, signing_key="record-key")
    original_records = _read_records(ledger_path)
    ledger_path.write_bytes(ledger_path.read_bytes() + b"partial-trailing-frame")
    assert verify_velvet_ledger(ledger_path)["status"] == "fail"

    adapter = _adapter()
    request = _demo_requests()[0]
    ledger = VelvetLedger(
        ledger_path,
        signing_key="record-key",
        signing_key_id="test-key",
    )
    ledger.write_admission_decision(
        _decision_for_request(adapter, request),
        request=request,
        label="recovery_tail_append",
    )

    quarantine_files = list(tmp_path.glob("ledger.vledger.recovered-tail.*.bin"))
    assert len(quarantine_files) == 1
    assert quarantine_files[0].read_bytes() == b"partial-trailing-frame"
    report = verify_velvet_ledger(ledger_path, signing_key="record-key")
    assert report["status"] == "pass"
    assert report["records"] == len(original_records) + 1


def test_rollback_to_valid_prefix_is_detected_by_checkpoint(
    tmp_path: Path,
) -> None:
    ledger_path = _write_demo_ledger(tmp_path)
    manifest_path = _write_manifest(tmp_path, ledger_path)
    records = _read_records(ledger_path)
    prefix_path = tmp_path / "valid_prefix.vledger"
    _write_records(prefix_path, records[:-1])

    local_report = verify_velvet_ledger(prefix_path)
    checkpointed_report = verify_velvet_ledger(prefix_path, manifest_path=manifest_path)

    assert local_report["status"] == "pass"
    _assert_detected(checkpointed_report, "checkpoint_record_count_mismatch")
