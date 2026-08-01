"""Article 12 technical attestation pack builder for Velvet vault artifacts."""

from __future__ import annotations

import copy
import hashlib
import html
import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from velvet.approvals import load_approval_snapshot
from velvet.attestation.mapping import ARTICLE_12_BOUNDARY_NOTICE, build_coverage_report
from velvet.binary_ledger import BinaryLedgerFrame, iter_frames
from velvet.serialization import JsonObject, canonical_dumps, canonical_hash_sha256
from velvet.signing import SigningProvider, sign_payload_hash, signer_default_key_id
from velvet.vault.merkle import build_consistency_proof, build_inclusion_proof, record_hashes_root
from velvet.vault.verify import verify_vault_segment

ATTESTATION_PACK_SCHEMA_VERSION = "velvet.attestation_pack.v1"
ATTESTATION_PACK_MANIFEST_SCHEMA_VERSION = "velvet.attestation_pack.manifest.v1"
PURPOSE_ATTESTATION_PACK_MANIFEST = "velvet.attestation_pack.manifest.v1"


class AttestationPackError(RuntimeError):
    """Raised when an attestation pack cannot be produced."""


@dataclass(frozen=True)
class AttestationPackBuild:
    generation_parameters: JsonObject
    deployment_metadata: JsonObject
    records: tuple[JsonObject, ...]
    record_hashes: tuple[str, ...]
    segment_range: str
    selected_frames: tuple[BinaryLedgerFrame, ...]
    ledger_segment_bytes: bytes
    sth: JsonObject
    verification_report: JsonObject
    coverage_report: JsonObject
    approval_receipts: tuple[JsonObject, ...]
    latest_sth: JsonObject
    consistency_to_latest: JsonObject


def build_attestation_pack(
    *,
    ledger_path: str | Path,
    sth_path: str | Path,
    public_key: str | bytes | object,
    system_name: str,
    intended_purpose: str,
    deployer_legal_entity: str,
    eu_exposure: bool,
    segment_range: str | None = None,
    thread_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    approvals_path: str | Path | None = None,
    latest_sth_path: str | Path | None = None,
) -> AttestationPackBuild:
    ledger = Path(ledger_path)
    sth = _read_json_object(sth_path)
    frames = tuple(iter_frames(ledger))
    selected_frames = _select_frames(
        frames,
        segment_range=segment_range,
        thread_id=thread_id,
        start=start,
        end=end,
    )
    if not selected_frames:
        raise AttestationPackError("no records selected for attestation pack")
    selected_range = _segment_range_for_frames(selected_frames)
    records = tuple(frame.payload for frame in selected_frames)
    verification_report = verify_vault_segment(
        segment_range=selected_range,
        sth_path=sth_path,
        public_key=public_key,
        ledger_path=ledger,
    )
    if verification_report.get("status") != "pass":
        raise AttestationPackError("vault verification failed; refusing to build pack")
    deployment_metadata: JsonObject = {
        "system_name": system_name,
        "intended_purpose": intended_purpose,
        "deployer_legal_entity": deployer_legal_entity,
        "eu_exposure": eu_exposure,
    }
    approval_receipts = _select_approval_receipts(records, approvals_path=approvals_path)
    coverage_report = build_coverage_report(
        records=records,
        sth=sth,
        verification_report=verification_report,
        deployment_metadata=deployment_metadata,
        approval_receipts=approval_receipts,
    )
    latest_sth = _latest_sth(sth=sth, latest_sth_path=latest_sth_path)
    consistency_to_latest = _consistency_to_latest(
        covering_sth=sth,
        latest_sth=latest_sth,
        all_frames=frames,
    )
    generation_parameters: JsonObject = {
        "ledger_path": str(ledger_path),
        "sth_path": str(sth_path),
        "approvals_path": str(approvals_path) if approvals_path is not None else None,
        "latest_sth_path": str(latest_sth_path) if latest_sth_path is not None else None,
        "segment_range": selected_range,
        "requested_segment_range": segment_range,
        "thread_id": thread_id,
        "start": start,
        "end": end,
        "records_body_mode": "hash_only",
    }
    return AttestationPackBuild(
        generation_parameters=generation_parameters,
        deployment_metadata=deployment_metadata,
        records=records,
        record_hashes=tuple(str(record["record_hash"]) for record in records),
        segment_range=selected_range,
        selected_frames=selected_frames,
        ledger_segment_bytes=_ledger_segment_bytes(ledger, selected_frames),
        sth=sth,
        verification_report=verification_report,
        coverage_report=coverage_report,
        approval_receipts=approval_receipts,
        latest_sth=latest_sth,
        consistency_to_latest=consistency_to_latest,
    )


def write_attestation_pack(
    *,
    ledger_path: str | Path,
    sth_path: str | Path,
    public_key: str | bytes | object,
    output_dir: str | Path,
    system_name: str,
    intended_purpose: str,
    deployer_legal_entity: str,
    eu_exposure: bool,
    signer: SigningProvider,
    signing_key_id: str | None = None,
    segment_range: str | None = None,
    thread_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    approvals_path: str | Path | None = None,
    latest_sth_path: str | Path | None = None,
) -> JsonObject:
    build = build_attestation_pack(
        ledger_path=ledger_path,
        sth_path=sth_path,
        public_key=public_key,
        system_name=system_name,
        intended_purpose=intended_purpose,
        deployer_legal_entity=deployer_legal_entity,
        eu_exposure=eu_exposure,
        segment_range=segment_range,
        thread_id=thread_id,
        start=start,
        end=end,
        approvals_path=approvals_path,
        latest_sth_path=latest_sth_path,
    )
    destination = Path(output_dir)
    _prepare_output_dir(destination)
    _write_pack_files(destination, build)
    manifest = _build_manifest(
        destination,
        build,
        signer=signer,
        signing_key_id=signing_key_id,
    )
    _write_json(destination / "manifest.json", manifest)
    return manifest


def _select_frames(
    frames: Sequence[BinaryLedgerFrame],
    *,
    segment_range: str | None,
    thread_id: str | None,
    start: str | None,
    end: str | None,
) -> tuple[BinaryLedgerFrame, ...]:
    selected = list(frames)
    if segment_range is not None:
        first, last = _parse_segment(segment_range)
        selected = [
            frame
            for frame in selected
            if first <= int(frame.payload.get("sequence_number", -1)) <= last
        ]
    if thread_id is not None:
        selected = [frame for frame in selected if _record_thread_id(frame.payload) == thread_id]
    if start is not None or end is not None:
        start_time = _parse_optional_time(start)
        end_time = _parse_optional_time(end)
        filtered = []
        for frame in selected:
            recorded_at = _parse_optional_time(cast(str | None, frame.payload.get("recorded_at")))
            if recorded_at is None:
                continue
            if start_time is not None and recorded_at < start_time:
                continue
            if end_time is not None and recorded_at > end_time:
                continue
            filtered.append(frame)
        selected = filtered
    _require_contiguous(selected)
    return tuple(selected)


def _write_pack_files(destination: Path, build: AttestationPackBuild) -> None:
    records_dir = destination / "records"
    sth_dir = destination / "sth"
    verification_dir = destination / "verification"
    approvals_dir = destination / "approvals"
    for directory in (records_dir, sth_dir, verification_dir, approvals_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (records_dir / "ledger_segment.vledger").write_bytes(build.ledger_segment_bytes)
    _write_json(records_dir / "index.json", _records_index(build))
    for record in build.records:
        sequence = int(record["sequence_number"])
        _write_json(records_dir / f"decision_record_{sequence:06d}.json", _hash_only_record(record))
    _write_json(sth_dir / "signed_tree_head.json", build.sth)
    _write_json(sth_dir / "latest_signed_tree_head.json", build.latest_sth)
    for index, _record_hash in enumerate(build.record_hashes):
        _write_json(
            sth_dir / f"inclusion_proof_{index:06d}.json",
            build_inclusion_proof(build.record_hashes, index),
        )
    _write_json(sth_dir / "consistency_to_latest.json", build.consistency_to_latest)
    _write_json(verification_dir / "vault_verification_report.json", build.verification_report)
    _copy_browser_verifier(verification_dir / "browser_verifier.html")
    _write_json(destination / "coverage_report.json", build.coverage_report)
    _write_json(approvals_dir / "index.json", {"receipts": len(build.approval_receipts)})
    for receipt in build.approval_receipts:
        receipt_id = str(receipt.get("approval_receipt_id", "unknown"))
        _write_json(approvals_dir / f"{_safe_filename(receipt_id)}.json", receipt)
    (destination / "README.html").write_text(_render_readme_html(build), encoding="utf-8")


def _build_manifest(
    destination: Path,
    build: AttestationPackBuild,
    *,
    signer: SigningProvider,
    signing_key_id: str | None,
) -> JsonObject:
    file_hashes = _hash_pack_files(destination)
    unsigned: JsonObject = {
        "schema_version": ATTESTATION_PACK_MANIFEST_SCHEMA_VERSION,
        "pack_schema_version": ATTESTATION_PACK_SCHEMA_VERSION,
        "notice": ARTICLE_12_BOUNDARY_NOTICE,
        "generated_at": _now_iso(),
        "generation_parameters": build.generation_parameters,
        "deployment_metadata": build.deployment_metadata,
        "segment": {
            "range": build.segment_range,
            "record_count": len(build.records),
            "first_record_hash": build.record_hashes[0],
            "last_record_hash": build.record_hashes[-1],
        },
        "file_hashes": file_hashes,
    }
    unsigned["file_hashes"]["manifest.json"] = {
        "sha256": canonical_hash_sha256(unsigned),
        "hash_scope": "unsigned_manifest_without_signature",
    }
    payload_hash = canonical_hash_sha256(unsigned)
    key_id = signing_key_id or signer_default_key_id(signer)
    return {
        **unsigned,
        "manifest_payload_hash": payload_hash,
        "signature": sign_payload_hash(
            payload_hash,
            purpose=PURPOSE_ATTESTATION_PACK_MANIFEST,
            key_id=key_id,
            signer=signer,
        ),
    }


def _records_index(build: AttestationPackBuild) -> JsonObject:
    return {
        "schema_version": "velvet.attestation_pack.records_index.v1",
        "body_mode": "hash_only",
        "records": [
            {
                "sequence_number": int(record["sequence_number"]),
                "record_id": record.get("record_id"),
                "record_hash": record.get("record_hash"),
                "decision": record.get("decision"),
                "record_file": f"decision_record_{int(record['sequence_number']):06d}.json",
            }
            for record in build.records
        ],
        "ledger_segment_file": "ledger_segment.vledger",
    }


def _hash_only_record(record: Mapping[str, Any]) -> JsonObject:
    sanitized = copy.deepcopy(dict(record))
    evidence = sanitized.get("admission_evidence")
    if isinstance(evidence, Mapping):
        evidence_copy = dict(evidence)
        raw_action = evidence_copy.get("raw_action")
        if isinstance(raw_action, Mapping):
            raw_copy = dict(raw_action)
            raw_copy.pop("redacted_action", None)
            raw_copy["recording_mode"] = "hash_only"
            evidence_copy["raw_action"] = raw_copy
        sanitized["admission_evidence"] = evidence_copy
    sanitized["pack_recording_mode"] = "hash_only"
    return sanitized


def _latest_sth(*, sth: JsonObject, latest_sth_path: str | Path | None) -> JsonObject:
    if latest_sth_path is None:
        return dict(sth)
    return _read_json_object(latest_sth_path)


def _consistency_to_latest(
    *,
    covering_sth: Mapping[str, Any],
    latest_sth: Mapping[str, Any],
    all_frames: Sequence[BinaryLedgerFrame],
) -> JsonObject:
    old_segment = _sth_segment(covering_sth)
    latest_segment = _sth_segment(latest_sth)
    old_size = _sth_tree_size(covering_sth)
    latest_size = _sth_tree_size(latest_sth)
    old_root = str(covering_sth.get("root_hash"))
    latest_root = str(latest_sth.get("root_hash"))
    if old_size > latest_size:
        raise AttestationPackError("covering STH cannot be larger than latest STH")
    if old_size == latest_size:
        if old_root != latest_root:
            raise AttestationPackError("same-size covering/latest STH roots differ")
        proof = build_consistency_proof(
            _record_hashes_for_sth(covering_sth, all_frames),
            _record_hashes_for_sth(latest_sth, all_frames),
        )
        proof["latest_anchor_status"] = "same_tree_as_covering_sth"
        proof["latest_tree_size"] = latest_size
        proof["latest_root_hash"] = latest_root
        return proof
    if int(old_segment.get("first_sequence", -1)) != int(latest_segment.get("first_sequence", -1)):
        raise AttestationPackError(
            "cannot build consistency proof when covering and latest STH start at "
            "different sequences"
        )
    latest_record_hashes = _record_hashes_for_sth(latest_sth, all_frames)
    old_record_hashes = latest_record_hashes[:old_size]
    if record_hashes_root(old_record_hashes) != old_root:
        raise AttestationPackError("covering STH is not a prefix of latest STH")
    proof = build_consistency_proof(old_record_hashes, latest_record_hashes)
    proof["latest_anchor_status"] = "latest_sth_supplied"
    proof["latest_tree_size"] = latest_size
    proof["latest_root_hash"] = latest_root
    return proof


def _record_hashes_for_sth(
    sth: Mapping[str, Any],
    frames: Sequence[BinaryLedgerFrame],
) -> tuple[str, ...]:
    segment = _sth_segment(sth)
    first = int(segment.get("first_sequence", -1))
    size = _sth_tree_size(sth)
    if first < 1 or size < 1:
        raise AttestationPackError("STH segment bounds must be positive")
    last = first + size - 1
    record_hashes = tuple(
        str(frame.payload["record_hash"])
        for frame in frames
        if first <= int(frame.payload.get("sequence_number", -1)) <= last
    )
    if len(record_hashes) != size:
        raise AttestationPackError("ledger does not contain all records for supplied STH")
    if record_hashes[0] != segment.get("first_record_hash"):
        raise AttestationPackError("STH first_record_hash does not match ledger")
    if record_hashes[-1] != segment.get("last_record_hash"):
        raise AttestationPackError("STH last_record_hash does not match ledger")
    if record_hashes_root(record_hashes) != sth.get("root_hash"):
        raise AttestationPackError("STH root_hash does not match ledger records")
    return record_hashes


def _sth_segment(sth: Mapping[str, Any]) -> Mapping[str, Any]:
    segment = sth.get("ledger_segment")
    if not isinstance(segment, Mapping):
        raise AttestationPackError("STH is missing ledger_segment")
    return segment


def _sth_tree_size(sth: Mapping[str, Any]) -> int:
    value = sth.get("tree_size")
    if not isinstance(value, int) or value < 0:
        raise AttestationPackError("STH tree_size must be a non-negative integer")
    return value


def _hash_pack_files(destination: Path) -> JsonObject:
    hashes: JsonObject = {}
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        relative = path.relative_to(destination).as_posix()
        hashes[relative] = {
            "sha256": _file_sha256(path),
            "size_bytes": path.stat().st_size,
            "hash_scope": "file_bytes",
        }
    return hashes


def _copy_browser_verifier(destination: Path) -> None:
    source = Path(__file__).resolve().parents[3] / "docs" / "public" / "velvet-verifier.html"
    if source.exists():
        shutil.copy2(source, destination)
        return
    destination.write_text(
        '<!doctype html><meta charset="utf-8"><title>Velvet Browser Verifier</title>'
        "<p>Browser verifier source was not available in this checkout.</p>\n",
        encoding="utf-8",
    )


def _render_readme_html(build: AttestationPackBuild) -> str:
    decisions: dict[str, int] = {}
    for record in build.records:
        decision = str(record.get("decision", "unknown"))
        decisions[decision] = decisions.get(decision, 0) + 1
    not_evidenced = cast(
        Sequence[Mapping[str, Any]],
        build.coverage_report["not_evidenced_by_velvet"],
    )
    rows = "\n".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(item.get("field_id"))),
            html.escape(str(item.get("label"))),
        )
        for item in not_evidenced
    )
    verifier_script = """
<script>
async function velvetHashFile(inputId, outputId) {
  const file = document.getElementById(inputId).files[0];
  const out = document.getElementById(outputId);
  if (!file) { out.textContent = "Select a file first."; return; }
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
  out.textContent = "sha256:" + hex;
}
</script>
""".strip()
    return "\n".join(
        [
            "<!doctype html>",
            '<html><head><meta charset="utf-8"><title>Velvet Attestation Pack</title>',
            "<style>"
            "body{font-family:system-ui,sans-serif;max-width:920px;margin:32px auto;"
            "padding:0 16px;line-height:1.45}"
            "code{background:#f3f4f6;padding:2px 4px;border-radius:4px}"
            "table{border-collapse:collapse;width:100%}"
            "td,th{border:1px solid #d1d5db;padding:8px;text-align:left}"
            ".notice{border-left:4px solid #334155;padding:12px;background:#f8fafc}</style>",
            "</head><body>",
            "<h1>Velvet Article 12 Technical Evidence Bundle</h1>",
            f'<p class="notice">{html.escape(ARTICLE_12_BOUNDARY_NOTICE)}</p>',
            "<h2>Summary</h2>",
            f"<p>Segment <code>{html.escape(build.segment_range)}</code>, "
            f"{len(build.records)} record(s), verification "
            f"<code>{html.escape(str(build.verification_report.get('status')))}</code>.</p>",
            f"<p>Decisions: <code>{html.escape(json.dumps(decisions, sort_keys=True))}</code></p>",
            "<h2>Not Evidenced By Velvet</h2>",
            "<table><thead><tr><th>Field</th><th>Label</th></tr></thead><tbody>",
            rows,
            "</tbody></table>",
            "<h2>Offline Hash Helper</h2>",
            "<p>Select a pack file to compute its SHA-256 digest in this browser.</p>",
            (
                '<input id="file" type="file"> '
                "<button onclick=\"velvetHashFile('file','hash')\">Hash</button>"
            ),
            '<pre id="hash"></pre>',
            "<h2>Embedded Browser Verifier</h2>",
            (
                "<p>The full single-file browser verifier is embedded below and also saved at "
                "<code>verification/browser_verifier.html</code>. It runs offline and can verify "
                "a decision record against the Signed Tree Head and inclusion proof when supplied "
                "with the operator public key.</p>"
            ),
            (
                '<iframe title="Velvet browser verifier" src="verification/browser_verifier.html" '
                'style="width:100%;height:520px;border:1px solid #d1d5db;'
                'border-radius:8px"></iframe>'
            ),
            verifier_script,
            "</body></html>",
        ]
    )


def _select_approval_receipts(
    records: Sequence[Mapping[str, Any]],
    *,
    approvals_path: str | Path | None,
) -> tuple[JsonObject, ...]:
    snapshot = load_approval_snapshot(approvals_path)
    wanted = {
        value
        for record in records
        for value in (
            _nested_string(record, ("approval_receipt_id",)),
            _nested_string(record, ("admission_evidence", "decision", "approval_receipt_id")),
            _nested_string(record, ("admission_evidence", "decision", "approval_request_id")),
            _nested_string(record, ("selected_warrant", "approval_request_id")),
        )
        if value
    }
    if not wanted:
        return ()
    selected = [
        receipt.to_dict()
        for receipt in snapshot.receipts
        if receipt.approval_receipt_id in wanted or receipt.approval_request_id in wanted
    ]
    return tuple(selected)


def _segment_range_for_frames(frames: Sequence[BinaryLedgerFrame]) -> str:
    first = int(frames[0].payload["sequence_number"])
    last = int(frames[-1].payload["sequence_number"])
    return f"{first}-{last}"


def _ledger_segment_bytes(ledger_path: Path, frames: Sequence[BinaryLedgerFrame]) -> bytes:
    data = ledger_path.read_bytes()
    chunks = [data[frame.offset : frame.end_offset] for frame in frames]
    return b"".join(chunks)


def _require_contiguous(frames: Sequence[BinaryLedgerFrame]) -> None:
    if not frames:
        return
    expected = int(frames[0].payload.get("sequence_number", -1))
    for frame in frames:
        actual = int(frame.payload.get("sequence_number", -1))
        if actual != expected:
            raise AttestationPackError("selected records are not a contiguous ledger segment")
        expected += 1


def _parse_segment(value: str) -> tuple[int, int]:
    parts = value.strip().replace("..", "-").replace(":", "-").split("-")
    numbers = [int(part) for part in parts if part]
    if len(numbers) != 2 or numbers[0] < 1 or numbers[1] < numbers[0]:
        raise AttestationPackError("segment must be FIRST-LAST")
    return numbers[0], numbers[1]


def _parse_optional_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _record_thread_id(record: Mapping[str, Any]) -> str | None:
    value = record.get("thread_id")
    if isinstance(value, str):
        return value
    return _nested_string(record, ("admission_evidence", "thread_id"))


def _nested_string(payload: Mapping[str, Any], path: Sequence[str]) -> str | None:
    current: Any = payload
    for part in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current if isinstance(current, str) and current else None


def _prepare_output_dir(destination: Path) -> None:
    if destination.exists():
        for child in destination.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    destination.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_dumps(payload) + "\n", encoding="utf-8")


def _read_json_object(path: str | Path) -> JsonObject:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AttestationPackError(f"expected JSON object at {path}")
    return cast(JsonObject, payload)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _safe_filename(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="microseconds")
