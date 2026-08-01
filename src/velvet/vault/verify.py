"""Offline third-party verifier for Velvet vault artifacts."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from velvet.binary_ledger import BinaryLedgerCorruption, iter_frames, verify_frame_signature
from velvet.ledger import LEDGER_GENESIS_HASH, ledger_record_hash
from velvet.serialization import JsonObject
from velvet.signing import (
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_LEDGER_RECORD,
    verify_signature_record,
)
from velvet.vault.merkle import (
    build_inclusion_proof,
    record_hashes_root,
    verify_consistency_proof,
    verify_inclusion_proof_artifact,
)
from velvet.vault.sth import signed_tree_head_hash, sth_ledger_segment, verify_signed_tree_head

VAULT_VERIFICATION_REPORT_SCHEMA_VERSION = "velvet.vault.verification_report.v1"


class VaultVerificationError(ValueError):
    """Raised when verifier inputs are malformed."""


def verify_vault_segment(
    *,
    segment_range: str,
    sth_path: str | Path,
    public_key: str | bytes | object,
    artifacts_dir: str | Path = ".",
    ledger_path: str | Path | None = None,
    previous_sth_path: str | Path | None = None,
) -> JsonObject:
    first_sequence, last_sequence = parse_segment_range(segment_range)
    artifacts = Path(artifacts_dir)
    ledger = Path(ledger_path) if ledger_path is not None else _find_ledger_artifact(artifacts)
    sth = _read_json_object(sth_path)
    previous_sth = _read_json_object(previous_sth_path) if previous_sth_path else None
    issues: list[JsonObject] = []
    checks: list[JsonObject] = []
    frames = []
    try:
        frames = list(iter_frames(ledger))
    except FileNotFoundError:
        issues.append(
            {
                "code": "ledger_not_found",
                "severity": "error",
                "message": f"Ledger artifact not found: {ledger}",
            }
        )
    except BinaryLedgerCorruption as error:
        issues.append(
            {
                "code": error.code,
                "severity": "error",
                "byte_offset": error.offset,
                "message": str(error),
            }
        )

    selected_frames = [
        frame
        for frame in frames
        if first_sequence <= int(frame.payload.get("sequence_number", -1)) <= last_sequence
    ]
    records = [frame.payload for frame in selected_frames]
    _check(
        checks,
        "binary_frames_parse",
        not any(issue["code"].startswith("binary_") for issue in issues),
    )
    if not records:
        issues.append(
            {
                "code": "segment_records_missing",
                "severity": "error",
                "message": "No ledger records were found for the requested segment range.",
            }
        )
    _verify_records_and_frames(
        records,
        selected_frames,
        first_sequence=first_sequence,
        public_key=public_key,
        issues=issues,
        checks=checks,
    )
    record_hashes = [str(record.get("record_hash", "")) for record in records]
    computed_root = record_hashes_root(record_hashes) if record_hashes else None
    sth_root = sth.get("root_hash")
    _check(
        checks,
        "merkle_root",
        computed_root is not None and computed_root == sth_root,
        expected=sth_root,
        actual=computed_root,
    )
    if computed_root is not None and computed_root != sth_root:
        issues.append(
            {
                "code": "merkle_root_mismatch",
                "severity": "error",
                "expected": sth_root,
                "actual": computed_root,
                "message": "Recomputed Merkle root does not match the STH root_hash.",
            }
        )
    sth_signature_ok = verify_signed_tree_head(sth, public_key=public_key)
    _check(checks, "sth_signature", sth_signature_ok)
    if not sth_signature_ok:
        issues.append(
            {
                "code": "sth_signature_invalid",
                "severity": "error",
                "message": "STH is missing a valid signature for the supplied public key.",
            }
        )
    _verify_sth_segment_bounds(
        sth,
        first_sequence=first_sequence,
        last_sequence=last_sequence,
        record_hashes=record_hashes,
        issues=issues,
        checks=checks,
    )
    _verify_generated_inclusion_proofs(record_hashes, sth, issues=issues, checks=checks)
    if previous_sth is not None:
        _verify_sth_consistency(previous_sth, sth, record_hashes, issues=issues, checks=checks)
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    return {
        "schema_version": VAULT_VERIFICATION_REPORT_SCHEMA_VERSION,
        "status": "fail" if error_count else "pass",
        "ledger_path": str(ledger),
        "sth_path": str(sth_path),
        "segment": {
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "record_count": len(records),
        },
        "sth_hash": signed_tree_head_hash(sth),
        "root_hash": computed_root,
        "checks": checks,
        "issues": issues,
    }


def render_human_summary(report: Mapping[str, Any]) -> str:
    status = str(report.get("status", "fail")).upper()
    segment = cast(Mapping[str, Any], report.get("segment", {}))
    checks = cast(Sequence[Mapping[str, Any]], report.get("checks", ()))
    issues = cast(Sequence[Mapping[str, Any]], report.get("issues", ()))
    passed = sum(1 for check in checks if check.get("status") == "pass")
    return "\n".join(
        [
            f"Velvet vault verification: {status}",
            (
                "Segment: "
                f"{segment.get('first_sequence')}..{segment.get('last_sequence')} "
                f"({segment.get('record_count')} record(s))"
            ),
            f"STH: {report.get('sth_hash')}",
            f"Merkle root: {report.get('root_hash')}",
            f"Checks: {passed}/{len(checks)} passed",
            f"Issues: {len(issues)}",
        ]
    )


def parse_segment_range(value: str) -> tuple[int, int]:
    normalized = value.strip().replace("..", "-").replace(":", "-")
    parts = [part for part in normalized.split("-") if part]
    if len(parts) != 2:
        raise VaultVerificationError("segment must be FIRST-LAST")
    first = int(parts[0])
    last = int(parts[1])
    if first < 1 or last < first:
        raise VaultVerificationError("segment range must be positive and ordered")
    return first, last


def _verify_records_and_frames(
    records: Sequence[Mapping[str, Any]],
    frames: Sequence[Any],
    *,
    first_sequence: int,
    public_key: str | bytes | object,
    issues: list[JsonObject],
    checks: list[JsonObject],
) -> None:
    expected_sequence = first_sequence
    expected_previous_hash: str | None = LEDGER_GENESIS_HASH if first_sequence == 1 else None
    chain_ok = True
    record_signature_ok = True
    frame_signature_ok = True
    for frame, record in zip(frames, records, strict=True):
        sequence = int(record.get("sequence_number", -1))
        context = {
            "sequence_number": sequence,
            "record_id": record.get("record_id"),
            "byte_offset": frame.offset,
        }
        if sequence != expected_sequence:
            chain_ok = False
            issues.append(
                {
                    **context,
                    "code": "sequence_number_mismatch",
                    "severity": "error",
                    "expected": expected_sequence,
                    "actual": sequence,
                    "message": "Ledger sequence number is not contiguous within the segment.",
                }
            )
        if (
            expected_previous_hash is not None
            and record.get("previous_record_hash") != expected_previous_hash
        ):
            chain_ok = False
            issues.append(
                {
                    **context,
                    "code": "previous_hash_mismatch",
                    "severity": "error",
                    "expected": expected_previous_hash,
                    "actual": record.get("previous_record_hash"),
                    "message": "Ledger previous_record_hash does not match.",
                }
            )
        expected_record_hash = ledger_record_hash(record)
        if record.get("record_hash") != expected_record_hash:
            chain_ok = False
            issues.append(
                {
                    **context,
                    "code": "record_hash_mismatch",
                    "severity": "error",
                    "expected": expected_record_hash,
                    "actual": record.get("record_hash"),
                    "message": "Ledger record_hash does not match canonical payload.",
                }
            )
        signature = record.get("signature")
        if not isinstance(signature, Mapping) or not verify_signature_record(
            signature,
            expected_record_hash,
            purpose=PURPOSE_LEDGER_RECORD,
            tenant_id=str(record.get("tenant_id") or LOCAL_DEMO_TENANT_ID),
            key_id=str(signature.get("key_id") if isinstance(signature, Mapping) else ""),
            public_key=public_key,
        ):
            record_signature_ok = False
            issues.append(
                {
                    **context,
                    "code": "record_signature_invalid",
                    "severity": "error",
                    "message": "Ledger record signature is missing or invalid.",
                }
            )
        if not verify_frame_signature(frame, public_key=public_key):
            frame_signature_ok = False
            issues.append(
                {
                    **context,
                    "code": "frame_signature_invalid",
                    "severity": "error",
                    "message": "Binary frame signature is missing or invalid.",
                }
            )
        expected_sequence += 1
        expected_previous_hash = str(record.get("record_hash") or expected_record_hash)
    _check(checks, "ledger_chain", chain_ok and bool(records))
    _check(checks, "record_signatures", record_signature_ok and bool(records))
    _check(checks, "frame_signatures", frame_signature_ok and bool(records))


def _verify_sth_segment_bounds(
    sth: Mapping[str, Any],
    *,
    first_sequence: int,
    last_sequence: int,
    record_hashes: Sequence[str],
    issues: list[JsonObject],
    checks: list[JsonObject],
) -> None:
    bounds_ok = False
    try:
        segment = sth_ledger_segment(sth)
        bounds_ok = (
            int(segment.get("first_sequence", -1)) == first_sequence
            and int(segment.get("last_sequence", -1)) == last_sequence
            and int(sth.get("tree_size", -1)) == len(record_hashes)
            and (not record_hashes or segment.get("first_record_hash") == record_hashes[0])
            and (not record_hashes or segment.get("last_record_hash") == record_hashes[-1])
        )
    except Exception:  # noqa: BLE001 - malformed STH fails closed.
        bounds_ok = False
    _check(checks, "sth_segment_bounds", bounds_ok)
    if not bounds_ok:
        issues.append(
            {
                "code": "sth_segment_bounds_mismatch",
                "severity": "error",
                "message": "STH ledger_segment does not match the requested segment.",
            }
        )


def _verify_generated_inclusion_proofs(
    record_hashes: Sequence[str],
    sth: Mapping[str, Any],
    *,
    issues: list[JsonObject],
    checks: list[JsonObject],
) -> None:
    root_hash = str(sth.get("root_hash", ""))
    ok = bool(record_hashes)
    for index, _record_hash in enumerate(record_hashes):
        proof = build_inclusion_proof(record_hashes, index)
        if not verify_inclusion_proof_artifact(proof, root_hash=root_hash):
            ok = False
            issues.append(
                {
                    "code": "inclusion_proof_invalid",
                    "severity": "error",
                    "leaf_index": index,
                    "message": "Generated inclusion proof did not verify against STH root.",
                }
            )
    _check(checks, "inclusion_proofs", ok)


def _verify_sth_consistency(
    old_sth: Mapping[str, Any],
    new_sth: Mapping[str, Any],
    record_hashes: Sequence[str],
    *,
    issues: list[JsonObject],
    checks: list[JsonObject],
) -> None:
    old_size = int(old_sth.get("tree_size", -1))
    new_size = int(new_sth.get("tree_size", -1))
    if old_size < 0 or old_size > len(record_hashes) or new_size != len(record_hashes):
        ok = False
    else:
        from velvet.vault.merkle import consistency_path, decode_sha256

        leaves = [decode_sha256(value, "record_hash") for value in record_hashes]
        proof = consistency_path(old_size, leaves)
        ok = verify_consistency_proof(
            old_tree_size=old_size,
            new_tree_size=new_size,
            old_root_hash=str(old_sth.get("root_hash", "")),
            new_root_hash=str(new_sth.get("root_hash", "")),
            proof=proof,
        )
    _check(checks, "sth_consistency", ok)
    if not ok:
        issues.append(
            {
                "code": "sth_consistency_invalid",
                "severity": "error",
                "message": "Previous STH is not consistent with the current STH.",
            }
        )


def _check(
    checks: list[JsonObject],
    name: str,
    ok: bool,
    *,
    expected: object | None = None,
    actual: object | None = None,
) -> None:
    payload: JsonObject = {"name": name, "status": "pass" if ok else "fail"}
    if expected is not None:
        payload["expected"] = expected
    if actual is not None:
        payload["actual"] = actual
    checks.append(payload)


def _read_json_object(path: str | Path | None) -> JsonObject:
    if path is None:
        raise VaultVerificationError("JSON path is required")
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise VaultVerificationError(f"JSON artifact is not an object: {path}")
    return cast(JsonObject, payload)


def _find_ledger_artifact(artifacts_dir: Path) -> Path:
    candidates = [
        *sorted(artifacts_dir.glob("*.vledger")),
        *sorted(artifacts_dir.glob("*.bin")),
    ]
    if len(candidates) != 1:
        raise VaultVerificationError(
            f"expected exactly one ledger artifact in {artifacts_dir}, found {len(candidates)}"
        )
    return candidates[0]
