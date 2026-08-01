"""Buyer-facing Velvet Ledger reports and replay checks."""

from __future__ import annotations

import html
import json
import sqlite3
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hmac import compare_digest
from pathlib import Path
from threading import RLock
from typing import Any, cast

from jsonschema import Draft202012Validator

from velvet.admission_evidence import (
    build_admission_evidence,
    ledger_record_admission_evidence_issues,
)
from velvet.binary_ledger import (
    BINARY_LEDGER_CHECKPOINT_SCHEMA_VERSION,
    BINARY_LEDGER_GENESIS_HASH,
    RECORD_KIND_CANONICAL,
    RECORD_KIND_OAP,
    BinaryLedgerCorruption,
    BinaryLedgerFrame,
    recover_trailing_tail,
    scan_tail_state,
    verify_checkpoint_signature,
    verify_frame_signature,
)
from velvet.binary_ledger import (
    append_record as append_binary_ledger_record,
)
from velvet.binary_ledger import (
    build_checkpoint as build_binary_ledger_checkpoint,
)
from velvet.binary_ledger import (
    iter_frames as iter_binary_ledger_frames,
)
from velvet.binary_ledger import (
    read_records as read_binary_ledger_records,
)
from velvet.rope import AdmissionDecision, manual_mcp_block_seal_id
from velvet.router import Router
from velvet.serialization import canonical_hash_sha256, proof_artifact_hash
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_LEDGER_RECORD,
    PURPOSE_VERDICT_CERTIFICATE,
    SigningProvider,
    default_demo_signer,
    resolve_ed25519_signing_provider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.state_transition import (
    state_transition_certificate_hash,
    validate_state_transition_certificate,
)
from velvet.thread_log import ThreadLogger
from velvet.types import StateTransitionCertificate, ThreadRecord

JsonObject = dict[str, Any]

LEDGER_CONTRACT = "velvet.ledger"
LEDGER_CONTRACT_REVISION = 1
OAP_LEDGER_CONTRACT = "velvet.oap_ledger.v1"
LEDGER_GENESIS_HASH = f"sha256:{'0' * 64}"
LEDGER_RECORD_SCHEMA_ARTIFACT = "schemas/velvet_rope/ledger_record.schema.json"
WARRANT_SCHEMA_ARTIFACT = "schemas/velvet_rope/warrant.schema.json"
LEDGER_SEGMENT_MANIFEST_SCHEMA_VERSION = BINARY_LEDGER_CHECKPOINT_SCHEMA_VERSION
LEDGER_SEGMENT_MANIFEST_SCHEMA_ARTIFACT = (
    "schemas/velvet_rope/ledger_segment_manifest.v1.schema.json"
)
CANONICAL_DECISIONS = frozenset({"execute", "block", "escalate"})
CANONICAL_UPSTREAM_STATUSES = frozenset(
    {"not_forwarded", "forward_authorized", "forwarded", "failed", "pending_approval"}
)
HASH_RE = r"^sha256:[0-9a-f]{64}$"


@dataclass(frozen=True)
class VelvetLedger:
    """Local Velvet Ledger writer for warrant envelopes."""

    path: Path
    tenant_id: str | None = None
    environment: str = "local"
    signing_key: str | None = None
    signing_key_id: str | None = None
    signer: SigningProvider | None = None
    signing_profile: str | None = None
    dev_ephemeral_key: bool = False

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str | None = None,
        environment: str = "local",
        signing_key: str | None = None,
        signing_key_id: str | None = None,
        signer: SigningProvider | None = None,
        signing_profile: str | None = None,
        dev_ephemeral_key: bool = False,
    ) -> None:
        object.__setattr__(self, "path", Path(path))
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "signing_key", signing_key)
        object.__setattr__(self, "signing_key_id", signing_key_id)
        object.__setattr__(self, "signer", signer)
        object.__setattr__(self, "signing_profile", signing_profile)
        object.__setattr__(self, "dev_ephemeral_key", dev_ephemeral_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write_admission_decision(
        self,
        decision: AdmissionDecision,
        *,
        request: Mapping[str, Any] | None = None,
        thread_path: str | Path | None = None,
        label: str = "mcp_authorization",
        state_transition_certificate: StateTransitionCertificate | Mapping[str, Any] | None = None,
        approval_request: Mapping[str, Any] | None = None,
        raw_artifact_dir: str | Path | None = None,
    ) -> JsonObject:
        sequence_state, previous_frame_hash = _next_ledger_sequence_state(self.path)
        active_signer, resolved_key_id = _resolve_record_signer(
            signer=self.signer,
            signing_key=self.signing_key,
            signing_key_id=self.signing_key_id,
            signing_profile=self.signing_profile,
            dev_ephemeral_key=self.dev_ephemeral_key,
        )
        payload = ledger_record_for_decision(
            decision,
            sequence_state=sequence_state,
            request=request,
            thread_path=thread_path,
            label=label,
            state_transition_certificate=state_transition_certificate,
            tenant_id=self.tenant_id,
            environment=self.environment,
            signing_key_id=resolved_key_id,
            signer=active_signer,
            signing_profile=self.signing_profile,
            dev_ephemeral_key=self.dev_ephemeral_key,
            admission_evidence_previous_frame_hash=previous_frame_hash,
            admission_evidence_ledger_path=self.path,
            approval_request=approval_request,
            raw_artifact_dir=raw_artifact_dir,
        )
        append_binary_ledger_record(
            self.path,
            payload,
            kind=RECORD_KIND_CANONICAL,
            sequence_number=sequence_state.sequence_number,
            previous_frame_hash=previous_frame_hash,
            signer=active_signer,
            tenant_id=str(payload.get("tenant_id") or self.tenant_id or LOCAL_DEMO_TENANT_ID),
            key_id=resolved_key_id,
        )
        return payload


@dataclass(frozen=True)
class LedgerSequenceState:
    sequence_number: int
    previous_record_hash: str


def ledger_record_for_decision(
    decision: AdmissionDecision,
    *,
    sequence_state: LedgerSequenceState | None = None,
    request: Mapping[str, Any] | None = None,
    thread_path: str | Path | None = None,
    label: str = "mcp_authorization",
    state_transition_certificate: StateTransitionCertificate | Mapping[str, Any] | None = None,
    tenant_id: str | None = None,
    environment: str = "local",
    signing_key: str | None = None,
    signing_key_id: str | None = None,
    signer: SigningProvider | None = None,
    signing_profile: str | None = None,
    dev_ephemeral_key: bool = False,
    admission_evidence: Mapping[str, Any] | None = None,
    admission_evidence_previous_frame_hash: str | None = None,
    admission_evidence_ledger_path: str | Path | None = None,
    approval_request: Mapping[str, Any] | None = None,
    raw_artifact_dir: str | Path | None = None,
    verdict_certificate: Mapping[str, Any] | None = None,
) -> JsonObject:
    """Convert an admission decision into one canonical hash-chained Ledger record."""

    del thread_path  # Ledger records store thread identity and request hashes, not local paths.
    sequence_state = sequence_state or LedgerSequenceState(1, LEDGER_GENESIS_HASH)
    decision_payload = decision.to_dict()
    selected = cast(JsonObject | None, decision_payload.get("selected_warrant"))
    request_payload = dict(request or {})
    arguments = _arguments_from_request(request_payload)
    recorded_at = _now_iso()
    resolved_tenant_id = (
        tenant_id
        or _mapping_string(selected, "tenant_id")
        or _mapping_string(request_payload, "tenant_id")
        or LOCAL_DEMO_TENANT_ID
    )
    selected_warrant = canonical_warrant_for_decision(
        decision_payload,
        selected,
        request_payload=request_payload,
        tenant_id=resolved_tenant_id,
        environment=environment,
        issued_at=recorded_at,
    )
    request_hash = selected_warrant["request_hash"]
    policy_hash = selected_warrant["policy_hash"]
    tool_schema_hash = selected_warrant["tool_schema_hash"]
    upstream_status = upstream_status_for_decision(str(selected_warrant["decision"]))
    active_signer, resolved_signing_key_id = _resolve_record_signer(
        signer=signer,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        signing_profile=signing_profile,
        dev_ephemeral_key=dev_ephemeral_key,
    )
    payload: JsonObject = {
        "contract": LEDGER_CONTRACT,
        "contract_revision": LEDGER_CONTRACT_REVISION,
        "record_id": f"lr_{uuid.uuid4().hex}",
        "tenant_id": resolved_tenant_id,
        "environment": environment,
        "sequence_number": sequence_state.sequence_number,
        "recorded_at": recorded_at,
        "previous_record_hash": sequence_state.previous_record_hash,
        "warrant_hash": proof_artifact_hash("warrant", selected_warrant),
        "seal_id": decision_payload.get("seal_id"),
        "thread_id": decision_payload.get("thread_id"),
        "product_surface": decision.product_surface,
        "action_type": decision_payload["decision"]["action_type"],
        "decision": selected_warrant["decision"],
        "upstream_execution_status": upstream_status,
        "reason": decision_payload["decision"]["reason"],
        "tool_key": _tool_key_from_request(request) or _tool_key_from_warrant(selected_warrant),
        "request_hash": request_hash,
        "policy_hash": policy_hash,
        "tool_schema_hash": tool_schema_hash,
        "selected_warrant": selected_warrant,
        "redaction_summary": _redaction_summary(request_payload, selected_warrant),
        "label": label,
    }
    policy_version = _policy_version_from_request_or_warrant(request_payload, selected_warrant)
    payload["policy_version"] = policy_version or "unavailable"
    if arguments is not None:
        payload["arguments_hash"] = selected_warrant.get("arguments_hash") or canonical_hash_sha256(
            arguments
        )
    if state_transition_certificate is not None:
        certificate_payload = _state_transition_certificate_payload(
            state_transition_certificate
        )
        payload["state_transition_certificate"] = certificate_payload
        payload["state_transition_certificate_hash"] = state_transition_certificate_hash(
            certificate_payload
        )
    if verdict_certificate is not None:
        verdict_payload = dict(verdict_certificate)
        payload["verdict_certificate"] = verdict_payload
        payload["verdict_certificate_hash"] = _verdict_certificate_unsigned_hash(
            verdict_payload
        )
    if admission_evidence is None and admission_evidence_ledger_path is not None:
        evidence_decision_payload = dict(decision_payload)
        evidence_decision_payload["selected_warrant"] = selected_warrant
        admission_evidence = build_admission_evidence(
            request=request_payload,
            admission_decision=evidence_decision_payload,
            sequence_number=sequence_state.sequence_number,
            previous_record_hash=sequence_state.previous_record_hash,
            previous_frame_hash=admission_evidence_previous_frame_hash,
            ledger_path=admission_evidence_ledger_path,
            approval_request=approval_request,
            raw_artifact_dir=raw_artifact_dir,
            signer=active_signer,
            signing_key_id=resolved_signing_key_id,
            tenant_id=resolved_tenant_id,
            environment=environment,
        )
    if admission_evidence is not None:
        evidence_payload = dict(admission_evidence)
        raw_action = evidence_payload.get("raw_action")
        raw_ref = (
            dict(cast(Mapping[str, Any], raw_action).get("raw_action_ref", {}))
            if isinstance(raw_action, Mapping)
            else {}
        )
        payload["admission_evidence_hash"] = evidence_payload.get("admission_evidence_hash")
        payload["admission_evidence_ref"] = raw_ref
        payload["admission_evidence"] = evidence_payload

    payload["record_hash"] = ledger_record_hash(payload)
    payload["signature"] = sign_payload_hash(
        str(payload["record_hash"]),
        purpose=PURPOSE_LEDGER_RECORD,
        tenant_id=resolved_tenant_id,
        key_id=resolved_signing_key_id,
        signer=active_signer,
    )
    validate_ledger_record(payload, signer=active_signer)
    return payload


def ledger_record_hash(record: Mapping[str, Any]) -> str:
    """Return the canonical hash for a Ledger record."""

    return canonical_hash_sha256(_ledger_record_hash_payload(record))


def _resolve_record_signer(
    *,
    signer: SigningProvider | None = None,
    signing_key: str | None = None,
    signing_key_id: str | None = None,
    signing_profile: str | None = None,
    dev_ephemeral_key: bool = False,
) -> tuple[SigningProvider, str]:
    active_signer = signer or (
        default_demo_signer(signing_key) if signing_key is not None else None
    )
    if active_signer is None:
        active_signer = resolve_ed25519_signing_provider(
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
            key_id=signing_key_id,
        )
    return active_signer, signing_key_id or signer_default_key_id(active_signer)


def sign_ledger_record_hash(record_hash: str, signing_key: str) -> str:
    """Sign a record hash with the provider-backed local demo signer."""

    return default_demo_signer(signing_key).sign(
        record_hash,
        PURPOSE_LEDGER_RECORD,
        LOCAL_DEMO_TENANT_ID,
        LOCAL_DEMO_KEY_ID,
    )


def build_ledger_segment_manifest(
    ledger_path: str | Path,
    *,
    storage_uri: str | None = None,
    signer: SigningProvider | None = None,
    signing_key: str | None = None,
    signing_key_id: str | None = None,
) -> JsonObject:
    """Build a provider-signed checkpoint over one binary ledger file."""

    return build_binary_ledger_checkpoint(
        ledger_path,
        storage_uri=storage_uri,
        signer=signer,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
    )


def verify_velvet_ledger(
    ledger_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    enforce_signatures: bool = False,
    signing_key: str | None = None,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
) -> JsonObject:
    """Verify canonical Ledger hash-chain integrity."""

    path = Path(ledger_path)
    issues: list[JsonObject] = []
    frame_records = _read_binary_frames_for_verification(path, issues)
    contract_counts = Counter(_ledger_contract_name(record) for _, _, record in frame_records)
    first_sequence: int | None = None
    last_sequence: int | None = None
    first_record_hash: str | None = None
    last_record_hash: str | None = None

    if not frame_records and not any(issue.get("code") == "ledger_not_found" for issue in issues):
        issues.append(
            {
                "code": "ledger_empty",
                "severity": "warning",
                "message": "Ledger file has no records to verify.",
            }
        )

    expected_sequence = 1
    expected_previous_hash = LEDGER_GENESIS_HASH
    expected_binary_sequence = 1
    expected_previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    canonical_records: list[tuple[int, BinaryLedgerFrame, JsonObject]] = []
    for index, frame, record in frame_records:
        context = {
            "index": index,
            "line": index,
            "byte_offset": frame.offset,
            "record_id": record.get("record_id"),
            "sequence_number": record.get("sequence_number"),
        }
        if frame.sequence_number != expected_binary_sequence:
            issues.append(
                {
                    **context,
                    "code": "binary_sequence_number_mismatch",
                    "severity": "error",
                    "expected": expected_binary_sequence,
                    "actual": frame.sequence_number,
                    "message": "Binary ledger frame sequence number is not contiguous.",
                }
            )
        if frame.previous_frame_hash != expected_previous_frame_hash:
            issues.append(
                {
                    **context,
                    "code": "binary_previous_hash_mismatch",
                    "severity": "error",
                    "expected": expected_previous_frame_hash,
                    "actual": frame.previous_frame_hash,
                    "message": "Binary ledger previous frame hash does not match.",
                }
            )
        if not verify_frame_signature(
            frame,
            signer=signer,
            signing_key=signing_key,
            public_key=public_key,
        ):
            issues.append(
                {
                    **context,
                    "code": "binary_signature_mismatch",
                    "severity": "error",
                    "message": "Binary ledger provider signature does not match frame hash.",
                }
            )
        if not (
            is_canonical_ledger_record(record)
            or is_oap_ledger_record(record)
            or _is_vault_tombstone_record(record)
        ):
            issues.append(
                {
                    **context,
                    "code": "unsupported_ledger_contract",
                    "severity": "error",
                    "message": "Ledger record is not the current canonical Velvet Ledger contract.",
                }
            )
            continue
        expected_kind = (
            RECORD_KIND_CANONICAL
            if is_canonical_ledger_record(record) or _is_vault_tombstone_record(record)
            else RECORD_KIND_OAP
        )
        if frame.kind != expected_kind:
            issues.append(
                {
                    **context,
                    "code": "binary_record_kind_mismatch",
                    "severity": "error",
                    "expected": expected_kind,
                    "actual": frame.kind,
                    "message": "Binary ledger record kind does not match its Velvet payload.",
                }
            )
        if is_canonical_ledger_record(record):
            validation_signer = signer or (
                default_demo_signer(signing_key) if signing_key is not None else None
            )
            schema_errors = validate_ledger_record(
                record,
                raise_error=False,
                signer=validation_signer,
                public_key=public_key,
            )
            for error in schema_errors:
                issues.append({**context, **error})
        elif is_oap_ledger_record(record):
            _verify_oap_record_shape(record, issues, context)
        else:
            for error in _verify_vault_tombstone_shape(record):
                issues.append({**context, **error})
        canonical_records.append((index, frame, record))
        expected_binary_sequence += 1
        expected_previous_frame_hash = frame.frame_hash

    for index, (record_index, frame, record) in enumerate(canonical_records):
        sequence_number = _int_or_none(record.get("sequence_number"))
        record_hash = cast(str | None, record.get("record_hash"))
        if index == 0:
            first_sequence = sequence_number
            first_record_hash = record_hash
        last_sequence = sequence_number
        last_record_hash = record_hash

        context = {
            "index": record_index,
            "line": record_index,
            "byte_offset": frame.offset,
            "record_id": record.get("record_id"),
            "sequence_number": sequence_number,
        }
        if sequence_number != expected_sequence:
            issues.append(
                {
                    **context,
                    "code": "sequence_number_mismatch",
                    "severity": "error",
                    "expected": expected_sequence,
                    "actual": sequence_number,
                    "message": "Ledger sequence number is not contiguous.",
                }
            )
        previous_hash = record.get("previous_record_hash")
        if previous_hash != expected_previous_hash:
            issues.append(
                {
                    **context,
                    "code": "previous_hash_mismatch",
                    "severity": "error",
                    "expected": expected_previous_hash,
                    "actual": previous_hash,
                    "message": (
                        "Ledger previous_record_hash does not match the preceding record."
                    ),
                }
            )
        expected_record_hash = ledger_record_hash(record)
        if record_hash != expected_record_hash:
            issues.append(
                {
                    **context,
                    "code": "record_hash_mismatch",
                    "severity": "error",
                    "expected": expected_record_hash,
                    "actual": record_hash,
                    "message": "Ledger record_hash does not match the canonical record payload.",
                }
            )

        if is_canonical_ledger_record(record):
            selected_warrant = record.get("selected_warrant")
            expected_warrant_hash = (
                proof_artifact_hash("warrant", selected_warrant)
                if isinstance(selected_warrant, Mapping)
                else None
            )
            if record.get("warrant_hash") != expected_warrant_hash:
                issues.append(
                    {
                        **context,
                        "code": "warrant_hash_mismatch",
                        "severity": "error",
                        "expected": expected_warrant_hash,
                        "actual": record.get("warrant_hash"),
                        "message": "Ledger warrant_hash does not match selected_warrant.",
                    }
                )
            if isinstance(selected_warrant, Mapping):
                if selected_warrant.get("decision") != record.get("decision"):
                    issues.append(
                        {
                            **context,
                            "code": "decision_warrant_mismatch",
                            "severity": "error",
                            "message": "Ledger decision differs from the bound selected warrant.",
                        }
                    )
                tool_name = selected_warrant.get("tool_name")
                if tool_name is not None and record.get("tool_key") not in {tool_name, None}:
                    issues.append(
                        {
                            **context,
                            "code": "tool_warrant_mismatch",
                            "severity": "error",
                            "message": "Ledger tool_key differs from the bound selected warrant.",
                        }
                    )
            _verify_decision_upstream_consistency(record, issues, context)
        elif is_oap_ledger_record(record):
            _verify_oap_decision_consistency(record, issues, context)

        if (
            isinstance(record.get("signature"), Mapping)
            or enforce_signatures
            or signing_key is not None
        ):
            _verify_record_signature(record, signing_key, signer, public_key, issues, context)

        expected_sequence += 1
        expected_previous_hash = str(
            expected_record_hash if record_hash != expected_record_hash else record_hash
        )

    manifest_report = (
        _verify_segment_manifest(
            manifest_path,
            [frame for _, frame, _ in canonical_records],
            [record for _, _, record in canonical_records],
            signing_key=signing_key,
            signer=signer,
            public_key=public_key,
            enforce_signatures=enforce_signatures,
            issues=issues,
        )
        if manifest_path is not None
        else None
    )
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    status = "fail" if error_count else "attention" if warning_count else "pass"
    return {
        "contract": "velvet.ledger_verification",
        "contract_revision": 1,
        "ledger_path": str(path),
        "manifest_path": str(manifest_path) if manifest_path is not None else None,
        "generated_at": _now_iso(),
        "status": status,
        "records": len(frame_records),
        "canonical_records": len(canonical_records),
        "contracts": dict(sorted(contract_counts.items())),
        "first_sequence": first_sequence,
        "last_sequence": last_sequence,
        "first_record_hash": first_record_hash,
        "last_record_hash": last_record_hash,
        "record_schema_artifact": LEDGER_RECORD_SCHEMA_ARTIFACT
        if canonical_records
        else None,
        "manifest": manifest_report,
        "issues": issues,
    }


def build_velvet_ledger_report(
    ledger_path: str | Path,
    *,
    thread_path: str | Path | None = None,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
) -> JsonObject:
    """Build a compact report joining ledger records to schema 9.0 thread records."""

    records = list(read_ledger_records(ledger_path))
    threads = _thread_index(thread_path)
    entries = [_entry_for_record(record, threads) for record in records]
    decision_counts = Counter(str(entry["decision"]) for entry in entries)
    contracts = Counter(
        str(record.get("contract") or "missing")
        for record in records
    )
    signature_providers = Counter(
        str(signature.get("provider_name"))
        for record in records
        for signature in (record.get("signature"),)
        if isinstance(signature, Mapping)
    )
    with_thread = sum(1 for entry in entries if entry["thread_found"])
    state_transition_records = sum(
        1 for entry in entries if entry["state_transition_present"]
    )
    validation = validate_thread_file(thread_path) if thread_path is not None else None
    verification = verify_velvet_ledger(ledger_path, signer=signer, public_key=public_key)
    return {
        "contract": LEDGER_CONTRACT,
        "contract_revision": LEDGER_CONTRACT_REVISION,
        "ledger_path": str(ledger_path),
        "thread_path": str(thread_path) if thread_path is not None else None,
        "generated_at": _now_iso(),
        "summary": {
            "records": len(entries),
            "with_thread": with_thread,
            "without_thread": len(entries) - with_thread,
            "state_transition_records": state_transition_records,
            "decision_counts": dict(sorted(decision_counts.items())),
            "contracts": dict(sorted(contracts.items())),
            "signature_providers": dict(sorted(signature_providers.items())),
            "ledger_verification_status": verification["status"],
        },
        "ledger_verification": verification,
        "thread_validation": validation,
        "entries": entries,
    }


def render_velvet_ledger_markdown(report: Mapping[str, Any]) -> str:
    """Render a Velvet Ledger report for diligence packets."""

    summary = cast(Mapping[str, Any], report["summary"])
    lines = [
        "# Velvet Ledger Report",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Ledger: `{report['ledger_path']}`",
        f"Thread file: `{report.get('thread_path')}`",
        "",
        "## Summary",
        "",
        f"- Records: `{summary['records']}`",
        f"- Linked schema 9.0 thread records: `{summary['with_thread']}`",
        f"- Pre-routing or thread-free records: `{summary['without_thread']}`",
        f"- State transition records: `{summary.get('state_transition_records', 0)}`",
        f"- Decisions: `{json.dumps(summary['decision_counts'], sort_keys=True)}`",
        "- Signature providers: "
        f"`{json.dumps(summary.get('signature_providers', {}), sort_keys=True)}`",
        f"- Ledger verification: `{summary.get('ledger_verification_status')}`",
        "",
    ]
    transition_entries = [
        entry
        for entry in cast(Iterable[Mapping[str, Any]], report["entries"])
        if entry.get("state_transition_present")
    ]
    if transition_entries:
        lines.extend(
            [
                "## State Transitions",
                "",
            ]
        )
        for entry in transition_entries:
            lines.extend(
                [
                    f"- Record `{entry['sequence_number']}`: "
                    f"`{entry.get('state_transition_outcome')}` "
                    f"CAS `{entry.get('state_transition_cas_sequence')}` "
                    f"hash `{entry.get('state_transition_certificate_hash')}`",
                ]
            )
        lines.append("")
    lines.extend(
        [
        "## Entries",
        "",
        ]
    )
    for entry in cast(Iterable[Mapping[str, Any]], report["entries"]):
        policy_reasons = ", ".join(cast(list[str], entry.get("policy_reasons", []))) or "none"
        state_transition_line = (
            f"- State transition: `{entry.get('state_transition_outcome')}` / "
            f"`{entry.get('state_transition_certificate_hash')}`"
            if entry.get("state_transition_present")
            else "- State transition: `none`"
        )
        lines.extend(
            [
                f"### `{entry['seal_id']}`",
                "",
                f"- Surface: `{entry['product_surface']}`",
                f"- Tool: `{entry.get('tool_key')}`",
                f"- Decision: `{entry['decision']}` / `{entry['action_type']}`",
                f"- Policy hash: `{entry.get('policy_hash')}`",
                f"- Reason: {entry['reason']}",
                f"- Policy reasons: `{policy_reasons}`",
                state_transition_line,
                f"- Thread linked: `{entry['thread_found']}`",
                f"- Seal status: `{entry.get('seal_status')}`",
                "",
            ]
        )
    return "\n".join(lines)


def write_velvet_ledger_report(
    ledger_path: str | Path,
    *,
    thread_path: str | Path | None,
    output_dir: str | Path,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
) -> tuple[Path, Path, JsonObject]:
    """Write JSON and Markdown Velvet Ledger report artifacts."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = build_velvet_ledger_report(
        ledger_path,
        thread_path=thread_path,
        signer=signer,
        public_key=public_key,
    )
    json_path = destination / "velvet_ledger_report.json"
    markdown_path = destination / "velvet_ledger_report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_velvet_ledger_markdown(report), encoding="utf-8")
    return json_path, markdown_path, report


def write_ledger_tamper_demo(output_dir: str | Path) -> JsonObject:
    """Write a self-explanatory Ledger tamper-evidence demo."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    valid_ledger = destination / "valid_ledger.vledger"
    tampered_ledger = destination / "tampered_ledger.vledger"
    manifest_path = destination / "valid_manifest.json"
    json_path = destination / "tamper_demo.json"
    markdown_path = destination / "tamper_demo.md"
    html_path = destination / "tamper_demo.html"
    readme_path = destination / "README.md"
    for path in (
        valid_ledger,
        tampered_ledger,
        manifest_path,
        json_path,
        markdown_path,
        html_path,
        readme_path,
    ):
        if path.exists():
            path.unlink()

    from velvet.mcp import DirectVelvetMCPAdapter  # Local import avoids a module cycle.

    adapter = DirectVelvetMCPAdapter.from_list_file("examples/mcp/list.json")
    requests: tuple[JsonObject, ...] = (
        {
            "label": "tamper_demo_allowed_lookup",
            "server": "servicenow",
            "tool": "search_change_requests",
            "arguments": {"query": "service=payments state=open"},
            "user_request": "Find open payment-service change requests.",
        },
        {
            "label": "tamper_demo_blocked_delete",
            "server": "servicenow",
            "tool": "delete_change_request",
            "arguments": {"change_id": "CHG0042007"},
            "user_request": "Delete the stale production change request.",
        },
        {
            "label": "tamper_demo_escalated_create",
            "server": "servicenow",
            "tool": "create_change_request",
            "arguments": {
                "service": "payments",
                "summary": "Approve production deploy",
            },
            "user_request": "Open a production change request.",
        },
    )
    for request in requests:
        adapter.authorize(request, ledger_path=valid_ledger)
    valid_records = list(read_ledger_records(valid_ledger))
    tampered_records = [dict(record) for record in valid_records]
    mutation = _apply_demo_ledger_mutation(tampered_records)
    _write_binary_records(tampered_ledger, tampered_records)
    manifest = build_ledger_segment_manifest(valid_ledger)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    valid_verification = verify_velvet_ledger(valid_ledger, manifest_path=manifest_path)
    tampered_verification = verify_velvet_ledger(tampered_ledger)
    failure = _ledger_tamper_failure_summary(tampered_verification, mutation)
    summary: JsonObject = {
        "contract": "velvet.ledger_tamper_demo",
        "contract_revision": 1,
        "generated_at": _now_iso(),
        "output_dir": str(destination),
        "valid_ledger_path": str(valid_ledger),
        "tampered_ledger_path": str(tampered_ledger),
        "manifest_path": str(manifest_path),
        "json_path": str(json_path),
        "markdown_path": str(markdown_path),
        "html_path": str(html_path),
        "mutation": mutation,
        "failure": failure,
        "valid_verification": valid_verification,
        "tampered_verification": tampered_verification,
        "passing_ledger": str(valid_ledger),
        "failing_ledger": str(tampered_ledger),
        "passing_manifest": str(manifest_path),
        "passing_verification": valid_verification,
        "failing_verification": tampered_verification,
    }
    json_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_render_ledger_tamper_markdown(summary), encoding="utf-8")
    html_path.write_text(
        _clean_html(_render_ledger_tamper_html(summary, tampered_records)),
        encoding="utf-8",
    )
    readme_path.write_text(
        "\n".join(
            [
                "# Ledger Tamper Demo",
                "",
                "`valid_ledger.vledger` verifies as a Velvet Ledger hash chain.",
                (
                    "`tampered_ledger.vledger` changes one recorded decision after hashing. "
                    "`tamper_demo.html` shows the altered field and broken hash link."
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return summary


def _apply_demo_ledger_mutation(records: list[JsonObject]) -> JsonObject:
    if len(records) < 3:
        raise ValueError("tamper demo requires at least three ledger records")
    record = records[1]
    original_value = str(record.get("decision"))
    tampered_value = _alternate_demo_decision(original_value)
    field_path = "decision"
    record[field_path] = tampered_value
    recomputed_hash = ledger_record_hash(record)
    next_record = records[2]
    return {
        "record_id": record.get("record_id"),
        "sequence_number": record.get("sequence_number"),
        "line": 2,
        "field_path": field_path,
        "original_value": original_value,
        "tampered_value": tampered_value,
        "stored_record_hash": record.get("record_hash"),
        "recomputed_record_hash": recomputed_hash,
        "next_record_id": next_record.get("record_id"),
        "next_sequence_number": next_record.get("sequence_number"),
        "next_previous_record_hash": next_record.get("previous_record_hash"),
    }


def _alternate_demo_decision(decision: str) -> str:
    if decision != "execute":
        return "execute"
    return "block"


def _ledger_tamper_failure_summary(
    verification: Mapping[str, Any],
    mutation: Mapping[str, Any],
) -> JsonObject:
    issues = list(cast(Iterable[Mapping[str, Any]], verification.get("issues", [])))
    sequence_number = mutation.get("sequence_number")
    next_sequence_number = mutation.get("next_sequence_number")
    record_hash_issue = _first_issue(
        issues,
        code="record_hash_mismatch",
        sequence_number=sequence_number,
    )
    previous_hash_issue = _first_issue(
        issues,
        code="previous_hash_mismatch",
        sequence_number=next_sequence_number,
    )
    return {
        "status": verification.get("status"),
        "offending_record_id": mutation.get("record_id"),
        "offending_sequence_number": sequence_number,
        "altered_field": mutation.get("field_path"),
        "record_hash_mismatch": _issue_excerpt(record_hash_issue),
        "broken_link": {
            "from_record_id": mutation.get("record_id"),
            "from_sequence_number": sequence_number,
            "to_record_id": mutation.get("next_record_id"),
            "to_sequence_number": next_sequence_number,
            "expected_previous_record_hash": mutation.get("recomputed_record_hash"),
            "actual_previous_record_hash": mutation.get("next_previous_record_hash"),
            "issue": _issue_excerpt(previous_hash_issue),
        },
    }


def _first_issue(
    issues: Iterable[Mapping[str, Any]],
    *,
    code: str,
    sequence_number: Any,
) -> Mapping[str, Any] | None:
    for issue in issues:
        if issue.get("code") == code and issue.get("sequence_number") == sequence_number:
            return issue
    return None


def _issue_excerpt(issue: Mapping[str, Any] | None) -> JsonObject | None:
    if issue is None:
        return None
    return {
        "code": issue.get("code"),
        "line": issue.get("line"),
        "record_id": issue.get("record_id"),
        "sequence_number": issue.get("sequence_number"),
        "expected": issue.get("expected"),
        "actual": issue.get("actual"),
        "message": issue.get("message"),
    }


def _render_ledger_tamper_markdown(report: Mapping[str, Any]) -> str:
    mutation = cast(Mapping[str, Any], report["mutation"])
    failure = cast(Mapping[str, Any], report["failure"])
    broken_link = cast(Mapping[str, Any], failure["broken_link"])
    lines = [
        "# Velvet Ledger Tamper Demo",
        "",
        f"- Valid chain: `{cast(Mapping[str, Any], report['valid_verification'])['status']}`",
        (
            "- Tampered chain: "
            f"`{cast(Mapping[str, Any], report['tampered_verification'])['status']}`"
        ),
        f"- Offending record: `{mutation['record_id']}`",
        f"- Altered field: `{mutation['field_path']}`",
        f"- Before: `{mutation['original_value']}`",
        f"- After: `{mutation['tampered_value']}`",
        "",
        "## Hash Divergence",
        "",
        f"- Stored record hash: `{mutation['stored_record_hash']}`",
        f"- Recomputed record hash: `{mutation['recomputed_record_hash']}`",
        f"- Next record previous hash: `{broken_link['actual_previous_record_hash']}`",
        f"- Expected previous hash: `{broken_link['expected_previous_record_hash']}`",
        "",
    ]
    return "\n".join(lines)


def _render_ledger_tamper_html(
    report: Mapping[str, Any],
    tampered_records: Iterable[Mapping[str, Any]],
) -> str:
    mutation = cast(Mapping[str, Any], report["mutation"])
    failure = cast(Mapping[str, Any], report["failure"])
    broken_link = cast(Mapping[str, Any], failure["broken_link"])
    records = list(tampered_records)
    chain_html = _render_tamper_chain(records, mutation)
    valid_status = _esc(str(cast(Mapping[str, Any], report["valid_verification"])["status"]))
    tampered_status = _esc(
        str(cast(Mapping[str, Any], report["tampered_verification"])["status"])
    )
    expected_previous_hash = str(broken_link["expected_previous_record_hash"])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Velvet Ledger Tamper Evidence</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --ink: #17191d;
      --muted: #5c6673;
      --line: #d7dde6;
      --safe: #13795b;
      --danger: #b42318;
      --warn: #9a6700;
      --code: #20242a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }}
    main {{
      width: min(1180px, calc(100vw - 40px));
      margin: 0 auto;
      padding: 32px 0 42px;
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{ font-size: 32px; line-height: 1.1; font-weight: 720; }}
    h2 {{ font-size: 18px; margin-bottom: 14px; }}
    h3 {{ font-size: 15px; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      overflow-wrap: anywhere;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      align-items: start;
      padding-bottom: 22px;
      border-bottom: 1px solid var(--line);
    }}
    .subhead {{ margin-top: 8px; color: var(--muted); max-width: 780px; }}
    .status {{
      display: grid;
      grid-template-columns: repeat(2, minmax(170px, 1fr));
      gap: 10px;
      min-width: 360px;
    }}
    .pill {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 12px;
    }}
    .pill span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 4px;
    }}
    .pill strong {{ display: block; font-size: 20px; }}
    .safe strong {{ color: var(--safe); }}
    .fail strong {{ color: var(--danger); }}
    .band {{
      margin-top: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }}
    .kv {{
      min-height: 74px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
    }}
    .kv span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 5px;
    }}
    .kv strong {{
      display: block;
      overflow-wrap: anywhere;
      font-size: 14px;
    }}
    .chain {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
    }}
    .record {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 14px;
    }}
    .record.bad {{
      border-color: var(--danger);
      box-shadow: inset 4px 0 0 var(--danger);
    }}
    .record-head {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 12px;
      align-items: start;
      margin-bottom: 12px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 680;
      text-transform: uppercase;
    }}
    .badge.ok {{ color: var(--safe); background: #eaf7f1; }}
    .badge.bad {{ color: var(--danger); background: #fff0ed; }}
    .hashgrid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}
    .hashbox {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f6f8fb;
      padding: 10px;
    }}
    .hashbox.bad {{ border-color: var(--danger); background: #fff7f6; }}
    .hashbox span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 5px;
    }}
    .link {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #eef8f3;
      padding: 12px;
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 12px;
      align-items: center;
    }}
    .link.broken {{
      border: 2px solid var(--danger);
      background: #fff0ed;
    }}
    .link-title {{
      font-weight: 760;
      color: var(--safe);
      text-transform: uppercase;
      font-size: 12px;
    }}
    .link.broken .link-title {{ color: var(--danger); }}
    .compare {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}
    .compare div {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px;
      background: #fff;
    }}
    .compare span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 4px;
    }}
    @media (max-width: 860px) {{
      main {{ width: min(100vw - 28px, 720px); padding-top: 20px; }}
      header, .status, .grid, .hashgrid, .link, .compare {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Velvet Ledger Tamper Evidence</h1>
        <p class="subhead">
          One recorded field changed after sealing. The recomputed hash diverges, and the
          next record points at the old hash.
        </p>
      </div>
      <div class="status">
        <div class="pill safe">
          <span>Valid chain</span>
          <strong>{valid_status}</strong>
        </div>
        <div class="pill fail">
          <span>Tampered chain</span>
          <strong>{tampered_status}</strong>
        </div>
      </div>
    </header>

    <section class="band">
      <h2>Altered Field</h2>
      <div class="grid">
        {_tamper_metric("Record", str(mutation["record_id"]))}
        {_tamper_metric("Field", str(mutation["field_path"]))}
        {_tamper_metric("Before", str(mutation["original_value"]))}
        {_tamper_metric("After", str(mutation["tampered_value"]))}
      </div>
    </section>

    <section class="band">
      <h2>Failing Hash Comparison</h2>
      <div class="grid">
        {_tamper_metric("Stored record hash", str(mutation["stored_record_hash"]))}
        {_tamper_metric("Recomputed record hash", str(mutation["recomputed_record_hash"]))}
        {_tamper_metric("Next previous hash", str(broken_link["actual_previous_record_hash"]))}
        {_tamper_metric("Expected previous hash", expected_previous_hash)}
      </div>
    </section>

    <section class="band">
      <h2>Hash Chain</h2>
      <div class="chain">{chain_html}</div>
    </section>
  </main>
</body>
</html>
"""


def _render_tamper_chain(
    records: list[Mapping[str, Any]],
    mutation: Mapping[str, Any],
) -> str:
    parts: list[str] = []
    mutated_sequence = mutation.get("sequence_number")
    for index, record in enumerate(records):
        if index > 0:
            previous = records[index - 1]
            parts.append(_render_tamper_link(previous, record))
        parts.append(
            _render_tamper_record(
                record,
                is_mutated=record.get("sequence_number") == mutated_sequence,
                mutation=mutation,
            )
        )
    return "".join(parts)


def _render_tamper_link(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> str:
    expected = ledger_record_hash(previous)
    actual = str(current.get("previous_record_hash"))
    ok = actual == expected
    status = "LINK OK" if ok else "BROKEN LINK"
    css = "link" if ok else "link broken"
    return f"""
        <div class="{css}">
          <div class="link-title">{status}</div>
          <div class="compare">
            <div>
              <span>current.previous_record_hash</span>
              <code>{_esc(actual)}</code>
            </div>
            <div>
              <span>previous recomputed record_hash</span>
              <code>{_esc(expected)}</code>
            </div>
          </div>
        </div>
    """


def _render_tamper_record(
    record: Mapping[str, Any],
    *,
    is_mutated: bool,
    mutation: Mapping[str, Any],
) -> str:
    stored_hash = str(record.get("record_hash"))
    recomputed_hash = ledger_record_hash(record)
    hash_ok = stored_hash == recomputed_hash
    badge = "PAYLOAD ALTERED" if is_mutated else "UNCHANGED"
    badge_class = "badge bad" if is_mutated else "badge ok"
    record_class = "record bad" if is_mutated else "record"
    mutation_html = ""
    if is_mutated:
        field = _esc(str(mutation["field_path"]))
        original = _esc(str(mutation["original_value"]))
        tampered = _esc(str(mutation["tampered_value"]))
        mutation_html = f"""
          <div class="hashbox bad">
            <span>Altered field</span>
            <code>{field}: {original} -&gt; {tampered}</code>
          </div>
        """
    return f"""
        <article class="{record_class}">
          <div class="record-head">
            <div>
              <h3>Record {_esc(str(record.get("sequence_number")))}</h3>
              <p><code>{_esc(str(record.get("record_id")))}</code></p>
            </div>
            <span class="{badge_class}">{badge}</span>
          </div>
          <div class="hashgrid">
            <div class="hashbox">
              <span>Decision</span>
              <code>{_esc(str(record.get("decision")))}</code>
            </div>
            {mutation_html}
            <div class="hashbox {'bad' if not hash_ok else ''}">
              <span>Stored record_hash</span>
              <code>{_esc(stored_hash)}</code>
            </div>
            <div class="hashbox {'bad' if not hash_ok else ''}">
              <span>Recomputed from payload</span>
              <code>{_esc(recomputed_hash)}</code>
            </div>
          </div>
        </article>
    """


def _tamper_metric(label: str, value: str) -> str:
    return (
        '<div class="kv">'
        f"<span>{_esc(label)}</span>"
        f"<strong>{_esc(value)}</strong>"
        "</div>"
    )


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _clean_html(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.splitlines()) + "\n"


def seal_thread_decision(
    thread_path: str | Path,
    seal_id: str,
    *,
    policy_dir: str | None = None,
    chain: str | None = None,
) -> JsonObject:
    """Re-run deterministic routing for one stored thread record and compare selected action."""

    thread = _find_thread(thread_path, seal_id)
    manual_report = _manual_mcp_block_replay_report(
        thread,
        thread_path=thread_path,
        seal_id=seal_id,
    )
    if manual_report is not None:
        return manual_report
    resolved_chain = chain or str(thread.get("policy_chain_name") or "default")
    resolved_policy_dir = policy_dir or _infer_policy_dir(resolved_chain)
    raw_candidates = cast(list[Mapping[str, Any]], thread.get("raw_candidates", []))
    decision = Router(policy_dir=resolved_policy_dir, chain=resolved_chain).decide(
        state=cast(Mapping[str, object], thread["state"]),
        candidates=raw_candidates,
    )
    payload = decision.to_dict()
    expected_action = thread.get("selected_action")
    sealed_action = payload.get("action_type")
    expected_seal_id = thread.get("seal_id")
    sealed_seal_id = payload.get("seal_id")
    matched = expected_action == sealed_action and expected_seal_id == sealed_seal_id
    return {
        "status": "pass" if matched else "fail",
        "thread_path": str(thread_path),
        "thread_id": thread.get("thread_id"),
        "seal_id": seal_id,
        "expected_selected_action": expected_action,
        "sealed_selected_action": sealed_action,
        "expected_seal_id": expected_seal_id,
        "sealed_seal_id": sealed_seal_id,
        "decision": payload["decision"],
        "reason": payload["reason"],
        "policy_dir": resolved_policy_dir,
        "chain": resolved_chain,
    }


def _manual_mcp_block_replay_report(
    thread: Mapping[str, Any],
    *,
    thread_path: str | Path,
    seal_id: str,
) -> JsonObject | None:
    metadata = thread.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    if metadata.get("record_kind") != "velvet_mcp.manual_block.v1":
        return None
    tool_key = metadata.get("tool_key")
    reason = metadata.get("reason")
    rule_id = metadata.get("rule_id")
    expected_action = thread.get("selected_action")
    expected_seal_id = thread.get("seal_id")
    if not all(isinstance(value, str) and value for value in (tool_key, reason, rule_id)):
        return {
            "status": "fail",
            "thread_path": str(thread_path),
            "thread_id": thread.get("thread_id"),
            "seal_id": seal_id,
            "expected_selected_action": expected_action,
            "sealed_selected_action": None,
            "expected_seal_id": expected_seal_id,
            "sealed_seal_id": None,
            "decision": "block",
            "reason": "Manual MCP block replay metadata is incomplete.",
            "policy_dir": None,
            "chain": "manual_mcp_block",
        }
    recomputed_seal_id = manual_mcp_block_seal_id(
        str(tool_key),
        reason=str(reason),
        rule_id=str(rule_id),
    )
    matched = expected_action == "CALL_TOOL" and expected_seal_id == recomputed_seal_id
    return {
        "status": "pass" if matched else "fail",
        "thread_path": str(thread_path),
        "thread_id": thread.get("thread_id"),
        "seal_id": seal_id,
        "expected_selected_action": expected_action,
        "sealed_selected_action": "CALL_TOOL",
        "expected_seal_id": expected_seal_id,
        "sealed_seal_id": recomputed_seal_id,
        "decision": "block",
        "reason": str(reason),
        "policy_dir": None,
        "chain": "manual_mcp_block",
    }


def _infer_policy_dir(chain: str) -> str:
    for candidate in ("policies", "examples/mcp/policies", "examples/policies"):
        if _policy_chain_exists(Path(candidate), chain):
            return candidate
    return "policies"


def _policy_chain_exists(policy_dir: Path, chain: str) -> bool:
    if not policy_dir.exists():
        return False
    for path in sorted(policy_dir.glob("*.yaml")):
        try:
            if f"name: {chain}" in path.read_text(encoding="utf-8"):
                return True
        except OSError:
            continue
    return False


def validate_thread_file(thread_path: str | Path) -> JsonObject:
    """Validate thread records with the Python schema 9.0 model."""

    records = list(ThreadLogger.read(thread_path))
    errors: list[JsonObject] = []
    for index, record in enumerate(records):
        try:
            parsed = ThreadRecord.from_dict(record)
            if parsed.schema_version != "9.0":
                errors.append(
                    {
                        "index": index,
                        "thread_id": parsed.thread_id,
                        "error": f"unsupported schema_version {parsed.schema_version}",
                    }
                )
            if not parsed.seal_id.startswith("seal_"):
                errors.append(
                    {
                        "index": index,
                        "thread_id": parsed.thread_id,
                        "error": "seal_id must start with seal_",
                    }
                )
        except Exception as error:  # noqa: BLE001 - report validation failures, do not hide them.
            errors.append(
                {"index": index, "thread_id": record.get("thread_id"), "error": str(error)}
            )
    return {
        "thread_path": str(thread_path),
        "records": len(records),
        "schema_version": "9.0",
        "schema_artifact": "schemas/thread-v9.schema.json",
        "status": "pass" if not errors else "fail",
        "errors": errors,
    }


def read_ledger_records(path: str | Path) -> Iterable[JsonObject]:
    """Read semantic Velvet ledger records from a binary audit ledger."""

    yield from read_binary_ledger_records(path)


def _write_binary_records(path: str | Path, records: Iterable[Mapping[str, Any]]) -> None:
    destination = Path(path)
    if destination.exists():
        destination.unlink()
    previous_frame_hash = BINARY_LEDGER_GENESIS_HASH
    for record in records:
        kind = RECORD_KIND_OAP if is_oap_ledger_record(record) else RECORD_KIND_CANONICAL
        frame = append_binary_ledger_record(
            destination,
            record,
            kind=kind,
            sequence_number=int(record.get("sequence_number", 0) or 0),
            previous_frame_hash=previous_frame_hash,
            tenant_id=_mapping_string(record, "tenant_id") or LOCAL_DEMO_TENANT_ID,
            key_id=LOCAL_DEMO_KEY_ID,
        )
        previous_frame_hash = frame.frame_hash


def _read_binary_frames_for_verification(
    path: Path,
    issues: list[JsonObject],
) -> list[tuple[int, BinaryLedgerFrame, JsonObject]]:
    records: list[tuple[int, BinaryLedgerFrame, JsonObject]] = []
    try:
        for index, frame in enumerate(iter_binary_ledger_frames(path), start=1):
            records.append((index, frame, frame.payload))
    except FileNotFoundError:
        issues.append(
            {
                "code": "ledger_not_found",
                "severity": "error",
                "message": f"Ledger file not found: {path}",
            }
        )
    except BinaryLedgerCorruption as error:
        issue: JsonObject = {
            "code": error.code,
            "severity": "error",
            "byte_offset": error.offset,
            "message": str(error),
        }
        if error.sequence_number is not None:
            issue["sequence_number"] = error.sequence_number
        issues.append(issue)
    return records


def _next_ledger_sequence_state(path: Path) -> tuple[LedgerSequenceState, str]:
    if not path.exists():
        return (
            LedgerSequenceState(
                sequence_number=1,
                previous_record_hash=LEDGER_GENESIS_HASH,
            ),
            BINARY_LEDGER_GENESIS_HASH,
        )
    recover_trailing_tail(path)
    state = scan_tail_state(path)
    return (
        LedgerSequenceState(
            sequence_number=state.next_sequence_number,
            previous_record_hash=state.previous_semantic_record_hash,
        ),
        state.previous_frame_hash,
    )


def _semantic_sequence_state(path: Path) -> LedgerSequenceState:
    if not path.exists():
        return LedgerSequenceState(
            sequence_number=1,
            previous_record_hash=LEDGER_GENESIS_HASH,
        )
    state = scan_tail_state(path)
    return LedgerSequenceState(
        sequence_number=state.next_sequence_number,
        previous_record_hash=state.previous_semantic_record_hash,
    )


def _ledger_record_hash_payload(record: Mapping[str, Any]) -> JsonObject:
    return {
        str(key): value
        for key, value in record.items()
        if key not in {"record_hash", "signer", "signature", "signing_key_id"}
    }


def _state_transition_certificate_payload(
    certificate: StateTransitionCertificate | Mapping[str, Any],
) -> JsonObject:
    parsed = (
        certificate
        if isinstance(certificate, StateTransitionCertificate)
        else StateTransitionCertificate.from_dict(certificate)
    )
    validate_state_transition_certificate(parsed)
    return parsed.to_dict()


def _verify_record_signature(
    record: Mapping[str, Any],
    signing_key: str | None,
    signer: SigningProvider | None,
    public_key: str | bytes | object | None,
    issues: list[JsonObject],
    context: Mapping[str, Any],
) -> None:
    signature_record = record.get("signature")
    if isinstance(signature_record, Mapping):
        active_signer = signer or (
            default_demo_signer(signing_key) if signing_key is not None else None
        )
        if not verify_signature_record(
            signature_record,
            str(record.get("record_hash", "")),
            purpose=PURPOSE_LEDGER_RECORD,
            tenant_id=_mapping_string(record, "tenant_id") or LOCAL_DEMO_TENANT_ID,
            key_id=_mapping_string(signature_record, "key_id") or LOCAL_DEMO_KEY_ID,
            signer=active_signer,
            public_key=public_key,
        ):
            issues.append(
                {
                    **context,
                    "code": "signature_mismatch",
                    "severity": "error",
                    "message": "Ledger provider signature does not match record_hash.",
                }
            )
        return

    legacy_signer = record.get("signer")
    if signing_key is None:
        issues.append(
            {
                **context,
                "code": "signature_key_missing",
                "severity": "error",
                "message": "Signature enforcement requires a signing key.",
            }
        )
        return
    if not isinstance(legacy_signer, Mapping):
        issues.append(
            {
                **context,
                "code": "signature_missing",
                "severity": "error",
                "message": "Ledger record has no signer metadata.",
            }
        )
        return
    signature = legacy_signer.get("signature")
    if not isinstance(signature, str) or not signature:
        issues.append(
            {
                **context,
                "code": "signature_missing",
                "severity": "error",
                "message": "Ledger signer metadata has no signature.",
            }
        )
        return
    expected = sign_ledger_record_hash(str(record.get("record_hash", "")), signing_key)
    if not compare_digest(signature, expected):
        issues.append(
            {
                **context,
                "code": "signature_mismatch",
                "severity": "error",
                "message": "Ledger record signature does not match record_hash.",
            }
        )


def _verify_segment_manifest(
    manifest_path: str | Path,
    frames: list[BinaryLedgerFrame],
    records: list[Mapping[str, Any]],
    *,
    signing_key: str | None,
    signer: SigningProvider | None,
    public_key: str | bytes | object | None,
    enforce_signatures: bool,
    issues: list[JsonObject],
) -> JsonObject:
    path = Path(manifest_path)
    try:
        manifest = cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        issues.append(
            {
                "code": "manifest_not_found",
                "severity": "error",
                "message": f"Ledger segment manifest not found: {path}",
            }
        )
        return {"status": "fail", "manifest_path": str(path)}
    head_frame_hash = frames[-1].frame_hash if frames else BINARY_LEDGER_GENESIS_HASH
    comparisons: JsonObject = {
        "record_count": len(records),
        "head_frame_hash": head_frame_hash,
    }
    checks = {
        "record_count": len(records),
        "next_sequence": int(records[-1]["sequence_number"]) + 1 if records else 1,
        "first_sequence": int(records[0]["sequence_number"]) if records else None,
        "last_sequence": int(records[-1]["sequence_number"]) if records else None,
        "first_record_hash": str(records[0]["record_hash"]) if records else None,
        "last_record_hash": str(records[-1]["record_hash"]) if records else None,
        "head_frame_hash": head_frame_hash,
        "valid_length": frames[-1].end_offset if frames else 0,
    }
    for key, expected in checks.items():
        if manifest.get(key) != expected:
            issues.append(
                {
                    "code": f"checkpoint_{key}_mismatch",
                    "severity": "error",
                    "expected": expected,
                    "actual": manifest.get(key),
                    "message": f"Ledger checkpoint {key} does not match ledger records.",
                }
            )
    signature_ok = True
    signature_required = (
        enforce_signatures
        or signing_key is not None
        or signer is not None
        or manifest.get("signature") is not None
    )
    if signature_required:
        signature = manifest.get("signature")
        signature_ok = verify_checkpoint_signature(
            manifest,
            signer=signer,
            signing_key=signing_key,
            public_key=public_key,
        )
        if not isinstance(signature, Mapping):
            signature_ok = False
            issues.append(
                {
                    "code": "checkpoint_signature_missing",
                    "severity": "error",
                    "message": "Ledger checkpoint has no provider signature.",
                }
            )
        elif not signature_ok:
            issues.append(
                {
                    "code": "checkpoint_signature_mismatch",
                    "severity": "error",
                    "message": "Ledger checkpoint provider signature does not match.",
                }
            )
    fields_ok = all(manifest.get(key) == expected for key, expected in checks.items())
    return {
        "status": "pass" if fields_ok and signature_ok else "fail",
        "manifest_path": str(path),
        "schema_version": manifest.get("schema_version"),
        "segment_id": manifest.get("segment_id") or manifest.get("checkpoint_id"),
        "checkpoint_id": manifest.get("checkpoint_id"),
        "ledger_format": manifest.get("ledger_format"),
        "comparisons": comparisons,
    }


def validate_ledger_file(ledger_path: str | Path) -> JsonObject:
    path = Path(ledger_path)
    issues: list[JsonObject] = []
    records = _read_binary_frames_for_verification(path, issues)
    for index, frame, record in records:
        context = {
            "index": index,
            "line": index,
            "byte_offset": frame.offset,
            "record_id": record.get("record_id"),
            "sequence_number": record.get("sequence_number"),
        }
        if not is_canonical_ledger_record(record):
            issues.append(
                {
                    **context,
                    "code": "unsupported_ledger_contract",
                    "severity": "error",
                    "message": "Ledger record is not the current canonical Velvet Ledger contract.",
                }
            )
            continue
        for error in validate_ledger_record(record, raise_error=False):
            issues.append({**context, **error})
    return {
        "status": "fail" if any(issue.get("severity") == "error" for issue in issues) else "pass",
        "ledger_path": str(path),
        "records": len(records),
        "record_schema_artifact": LEDGER_RECORD_SCHEMA_ARTIFACT,
        "issues": issues,
    }


def validate_ledger_record(
    record: Mapping[str, Any],
    *,
    raise_error: bool = True,
    signer: SigningProvider | None = None,
    public_key: str | bytes | object | None = None,
) -> list[JsonObject]:
    errors = _schema_errors(LEDGER_RECORD_SCHEMA_ARTIFACT, record, "schema_validation_error")
    selected = record.get("selected_warrant")
    if isinstance(selected, Mapping):
        errors.extend(validate_warrant_payload(selected, raise_error=False))
    else:
        errors.append(
            {
                "code": "warrant_schema_validation_error",
                "severity": "error",
                "path": "selected_warrant",
                "message": "selected_warrant must be an object",
            }
        )
    errors.extend(_validate_state_transition_record_binding(record))
    errors.extend(_validate_verdict_certificate_record_binding(record))
    if (
        record.get("admission_evidence_hash") is not None
        and record.get("admission_evidence") is None
    ):
        errors.append(
            {
                "code": "admission_evidence_missing",
                "severity": "error",
                "path": "admission_evidence",
                "message": (
                    "admission_evidence_hash requires embedded admission_evidence "
                    "for replay verification."
                ),
            }
        )
    errors.extend(
        ledger_record_admission_evidence_issues(
            record,
            signer=signer,
            public_key=public_key,
        )
    )
    if raise_error and errors:
        first = errors[0]
        raise ValueError(str(first["message"]))
    return errors


def validate_warrant_payload(
    warrant: Mapping[str, Any],
    *,
    raise_error: bool = True,
) -> list[JsonObject]:
    errors = _schema_errors(WARRANT_SCHEMA_ARTIFACT, warrant, "warrant_schema_validation_error")
    if raise_error and errors:
        first = errors[0]
        raise ValueError(str(first["message"]))
    return errors


def _verdict_certificate_unsigned_hash(certificate: Mapping[str, Any]) -> str:
    unsigned = {
        str(key): value
        for key, value in certificate.items()
        if str(key) not in {"signature", "certificate_hash"}
    }
    return canonical_hash_sha256(unsigned)


def _validate_verdict_certificate_record_binding(
    record: Mapping[str, Any],
) -> list[JsonObject]:
    errors: list[JsonObject] = []
    certificate = record.get("verdict_certificate")
    recorded_hash = record.get("verdict_certificate_hash")
    if certificate is None:
        if recorded_hash is not None:
            errors.append(
                {
                    "code": "verdict_certificate_missing",
                    "severity": "error",
                    "path": "verdict_certificate",
                    "message": (
                        "verdict_certificate_hash requires the embedded "
                        "verdict_certificate for replay verification."
                    ),
                }
            )
        return errors
    if not isinstance(certificate, Mapping):
        errors.append(
            {
                "code": "verdict_certificate_invalid",
                "severity": "error",
                "path": "verdict_certificate",
                "message": "verdict_certificate must be an object",
            }
        )
        return errors
    recomputed = _verdict_certificate_unsigned_hash(certificate)
    if certificate.get("certificate_hash") != recomputed:
        errors.append(
            {
                "code": "verdict_certificate_hash_mismatch",
                "severity": "error",
                "path": "verdict_certificate.certificate_hash",
                "message": "verdict certificate hash does not match its payload",
            }
        )
    if recorded_hash != recomputed:
        errors.append(
            {
                "code": "verdict_certificate_record_hash_mismatch",
                "severity": "error",
                "path": "verdict_certificate_hash",
                "message": "verdict_certificate_hash does not match the embedded certificate",
            }
        )
    signature = certificate.get("signature")
    purpose = signature.get("purpose") if isinstance(signature, Mapping) else None
    if purpose != PURPOSE_VERDICT_CERTIFICATE:
        errors.append(
            {
                "code": "verdict_certificate_purpose_mismatch",
                "severity": "error",
                "path": "verdict_certificate.signature.purpose",
                "message": "verdict certificate signature purpose mismatch",
            }
        )
    return errors


def _validate_state_transition_record_binding(record: Mapping[str, Any]) -> list[JsonObject]:
    errors: list[JsonObject] = []
    certificate = record.get("state_transition_certificate")
    certificate_hash = record.get("state_transition_certificate_hash")
    if certificate is None:
        if certificate_hash is not None:
            errors.append(
                {
                    "code": "state_transition_certificate_missing",
                    "severity": "error",
                    "path": "state_transition_certificate",
                    "message": (
                        "state_transition_certificate_hash requires "
                        "state_transition_certificate."
                    ),
                }
            )
        return errors
    if not isinstance(certificate, Mapping):
        return [
            {
                "code": "state_transition_certificate_invalid",
                "severity": "error",
                "path": "state_transition_certificate",
                "message": "state_transition_certificate must be an object.",
            }
        ]

    errors.extend(validate_state_transition_certificate(certificate, raise_error=False))
    if certificate_hash is None:
        errors.append(
            {
                "code": "state_transition_certificate_hash_missing",
                "severity": "error",
                "path": "state_transition_certificate_hash",
                "message": (
                    "state_transition_certificate requires "
                    "state_transition_certificate_hash."
                ),
            }
        )
        return errors
    try:
        expected_hash = state_transition_certificate_hash(certificate)
    except (TypeError, ValueError) as error:
        errors.append(
            {
                "code": "state_transition_certificate_invalid",
                "severity": "error",
                "path": "state_transition_certificate",
                "message": str(error),
            }
        )
        return errors
    if certificate_hash != expected_hash:
        errors.append(
            {
                "code": "state_transition_certificate_hash_mismatch",
                "severity": "error",
                "path": "state_transition_certificate_hash",
                "expected": expected_hash,
                "actual": certificate_hash,
                "message": (
                    "state_transition_certificate_hash does not match the "
                    "certificate transition_proof_hash."
                ),
            }
        )
    return errors


def is_canonical_ledger_record(record: Mapping[str, Any]) -> bool:
    return (
        record.get("contract") == LEDGER_CONTRACT
        and record.get("contract_revision") == LEDGER_CONTRACT_REVISION
    )


def is_oap_ledger_record(record: Mapping[str, Any]) -> bool:
    return record.get("oap_contract") == OAP_LEDGER_CONTRACT


def _is_vault_tombstone_record(record: Mapping[str, Any]) -> bool:
    from velvet.vault.retention import is_tombstone_record

    return is_tombstone_record(record)


def _ledger_contract_name(record: Mapping[str, Any]) -> str:
    return str(record.get("contract") or record.get("oap_contract") or "missing")


def _verify_vault_tombstone_shape(record: Mapping[str, Any]) -> list[JsonObject]:
    from velvet.vault.retention import validate_tombstone_record

    return validate_tombstone_record(record)


def _verify_oap_record_shape(
    record: Mapping[str, Any],
    issues: list[JsonObject],
    context: Mapping[str, Any],
) -> None:
    for field_name in (
        "record_type",
        "record_id",
        "sequence_number",
        "previous_record_hash",
        "record_hash",
        "decision_id",
        "state",
        "decision",
        "request_hash",
        "redaction_summary",
    ):
        if record.get(field_name) is None:
            issues.append(
                {
                    **context,
                    "code": "oap_ledger_missing_field",
                    "severity": "error",
                    "field": field_name,
                    "message": "OAP ledger record is missing a required field.",
                }
            )
    if record.get("max_de_certificate_required") is True:
        if not isinstance(record.get("max_de_certificate_envelope"), Mapping):
            issues.append(
                {
                    **context,
                    "code": "oap_ledger_missing_certificate_envelope",
                    "severity": "error",
                    "message": "OAP ledger record requires a Max-DE envelope but none is present.",
                }
            )
        if not isinstance(record.get("max_de_certificate_envelope_digest"), str):
            issues.append(
                {
                    **context,
                    "code": "oap_ledger_missing_certificate_digest",
                    "severity": "error",
                    "message": (
                        "OAP ledger record requires a Max-DE envelope digest but none is present."
                    ),
                }
            )
    oap_decision = record.get("oap_decision")
    if isinstance(oap_decision, Mapping) and oap_decision.get("decision_id") != record.get(
        "decision_id"
    ):
        issues.append(
            {
                **context,
                "code": "oap_decision_id_mismatch",
                "severity": "error",
                "message": "OAP Decision ID does not match the containing ledger record.",
            }
        )


def _verify_oap_decision_consistency(
    record: Mapping[str, Any],
    issues: list[JsonObject],
    context: Mapping[str, Any],
) -> None:
    decision = str(record.get("decision") or "")
    expected_state = "allow" if decision in {"execute", "allow_passthrough"} else (
        "escalate" if decision in {"escalate", "ask_approval", "delay"} else "block"
    )
    if record.get("state") != expected_state:
        issues.append(
            {
                **context,
                "code": "oap_ledger_state_mismatch",
                "severity": "error",
                "expected": expected_state,
                "actual": record.get("state"),
                "message": "OAP ledger state does not match decision.",
            }
        )
    record_type = str(record.get("record_type") or "")
    if record_type.endswith("_observation") and not record.get("pre_execution_record_hash"):
        issues.append(
            {
                **context,
                "code": "oap_observation_missing_pre_execution_hash",
                "severity": "error",
                "message": "OAP observation record is missing its pre-execution hash binding.",
            }
        )


def canonical_warrant_for_decision(
    decision_payload: Mapping[str, Any],
    selected: Mapping[str, Any] | None,
    *,
    request_payload: Mapping[str, Any],
    tenant_id: str,
    environment: str,
    issued_at: str,
) -> JsonObject:
    selected_payload = dict(selected or {})
    decision = _canonical_decision(
        str(
            selected_payload.get("decision")
            or cast(Mapping[str, Any], decision_payload["decision"]).get("decision")
        )
    )
    tool_name = (
        _tool_key_from_request(request_payload)
        or _mapping_string(selected_payload, "tool_name")
        or _mapping_string(selected_payload, "tool_key")
        or "unknown"
    )
    request_hash = _ensure_proof_hash(
        _mapping_string(selected_payload, "request_hash"),
        request_payload,
    )
    reason_codes = _reason_codes(selected_payload, decision_payload)
    policy_hash = _ensure_proof_hash(
        _policy_hash_from_request_or_warrant(request_payload, selected_payload),
        {
            "policy_reasons": reason_codes,
            "policy_statuses": list(
                cast(Iterable[Any], selected_payload.get("policy_statuses", []))
            ),
        },
    )
    tool_schema_hash = _ensure_proof_hash(
        _tool_schema_hash_from_request(request_payload)
        or _mapping_string(selected_payload, "tool_schema_hash"),
        {"tool_name": tool_name, "risk_class": selected_payload.get("risk_class", "unknown")},
    )
    arguments = _arguments_from_request(request_payload)
    arguments_hash = (
        _ensure_proof_hash(
            _mapping_string(selected_payload, "arguments_hash"),
            arguments,
        )
        if arguments is not None
        else None
    )
    warrant: JsonObject = {
        "warrant_id": (
            _mapping_string(selected_payload, "warrant_id") or f"wrnt_{uuid.uuid4().hex}"
        ),
        "issued_at": _canonical_timestamp(
            _mapping_string(selected_payload, "issued_at") or issued_at
        ),
        "tenant_id": tenant_id,
        "environment": environment,
        "request_hash": request_hash,
        "policy_hash": policy_hash,
        "tool_schema_hash": tool_schema_hash,
        "tool_name": tool_name,
        "decision": decision,
        "reason_codes": reason_codes,
        "obligations": _obligations_for_decision(decision),
        "approval_required": bool(
            selected_payload.get("approval_required", decision == "escalate")
        ),
        "expires_at": _canonical_timestamp(
            _mapping_string(selected_payload, "expires_at") or "9999-12-31T23:59:59Z"
        ),
        "issuer": _mapping_string(selected_payload, "issuer") or "velvet",
        "reason": str(
            selected_payload.get("reason")
            or cast(Mapping[str, Any], decision_payload["decision"]).get("reason")
            or ""
        ),
        "tool_key": tool_name,
        "policy_statuses": list(cast(Iterable[Any], selected_payload.get("policy_statuses", []))),
        "policy_reasons": list(cast(Iterable[Any], selected_payload.get("policy_reasons", []))),
        "jurisdiction_evidence": list(
            cast(Iterable[Any], selected_payload.get("jurisdiction_evidence", []))
        ),
        "risk_class": selected_payload.get("risk_class", "unknown"),
        "pricing_status": selected_payload.get("pricing_status", "not_priced"),
    }
    if arguments_hash is not None:
        warrant["arguments_hash"] = arguments_hash
    for optional in (
        "seal_id",
        "thread_id",
        "product_surface",
        "action_type",
        "mcp_server",
        "mcp_tool",
        "policy_version",
        "approval_request_id",
        "entry_price",
        "clearance_score",
        "risk_penalty",
        "scarcity_pressure",
    ):
        if optional in selected_payload:
            warrant[optional] = selected_payload[optional]
    validate_warrant_payload(warrant)
    return warrant


def upstream_status_for_decision(decision: str) -> str:
    if decision == "execute":
        return "forwarded"
    if decision == "escalate":
        return "pending_approval"
    return "not_forwarded"


def _verify_decision_upstream_consistency(
    record: Mapping[str, Any],
    issues: list[JsonObject],
    context: Mapping[str, Any],
) -> None:
    decision = record.get("decision")
    status = record.get("upstream_execution_status")
    valid = (
        (decision == "block" and status == "not_forwarded")
        or (decision == "execute" and status in {"forward_authorized", "forwarded", "failed"})
        or (decision == "escalate" and status == "pending_approval")
    )
    if not valid:
        issues.append(
            {
                **context,
                "code": "decision_upstream_status_mismatch",
                "severity": "error",
                "message": "Ledger decision is inconsistent with upstream execution status.",
            }
        )


def _schema_errors(
    schema_path: str,
    payload: Mapping[str, Any],
    code: str,
) -> list[JsonObject]:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors: list[JsonObject] = []
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        errors.append(
            {
                "code": code,
                "severity": "error",
                "path": ".".join(str(part) for part in error.path),
                "message": error.message,
            }
        )
    return errors


def _ensure_proof_hash(value: str | None, fallback: Any) -> str:
    if isinstance(value, str) and value:
        normalized = value.removeprefix("sha256:")
        if len(normalized) == 64 and all(
            character in "0123456789abcdef" for character in normalized
        ):
            return f"sha256:{normalized}"
        if value.startswith("sha256:"):
            return value
    return canonical_hash_sha256(fallback)


def _canonical_decision(decision: str) -> str:
    if decision == "execute":
        return "execute"
    if decision in {"escalate", "ask_approval", "delay", "pending_approval"}:
        return "escalate"
    return "block"


def _obligations_for_decision(decision: str) -> list[str]:
    if decision == "execute":
        return ["forward_upstream"]
    if decision == "escalate":
        return ["await_approval_before_execution"]
    return ["do_not_forward_upstream"]


def _reason_codes(
    selected: Mapping[str, Any],
    decision_payload: Mapping[str, Any],
) -> list[str]:
    policy_reasons = selected.get("policy_reasons")
    if isinstance(policy_reasons, list) and policy_reasons:
        return [str(item) for item in policy_reasons]
    decision = cast(Mapping[str, Any], decision_payload.get("decision", {}))
    reason = str(selected.get("reason") or decision.get("reason") or "velvet.decision")
    return [reason.strip().lower().replace(" ", "_")[:96] or "velvet.decision"]


def _canonical_timestamp(value: str) -> str:
    if value.endswith("+00:00"):
        return f"{value[:-6]}Z"
    return value


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _arguments_from_request(request: Mapping[str, Any]) -> Any | None:
    if "arguments" in request:
        return request["arguments"]
    payload = request.get("payload")
    if isinstance(payload, Mapping) and "arguments" in payload:
        return payload["arguments"]
    return None


def _policy_hash_from_request_or_warrant(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any] | None,
) -> str | None:
    for source in (request, cast(Mapping[str, Any], request.get("metadata", {}))):
        value = source.get("policy_hash") or source.get("policy_snapshot_hash")
        if isinstance(value, str) and value:
            return value
    if selected_warrant is not None:
        value = selected_warrant.get("policy_hash") or selected_warrant.get("policy_snapshot_hash")
        if isinstance(value, str) and value:
            return value
    return None


def _policy_version_from_request_or_warrant(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any] | None,
) -> str | None:
    for source in (request, cast(Mapping[str, Any], request.get("metadata", {}))):
        value = source.get("policy_version")
        if isinstance(value, str) and value:
            return value
    if selected_warrant is not None:
        value = selected_warrant.get("policy_version")
        if isinstance(value, str) and value:
            return value
    return None


def _tool_schema_hash_from_request(request: Mapping[str, Any]) -> str | None:
    for source in (request, cast(Mapping[str, Any], request.get("metadata", {}))):
        value = source.get("tool_schema_hash") or source.get("schema_hash")
        if isinstance(value, str) and value:
            return value
    return None


def _redaction_summary(
    request: Mapping[str, Any],
    selected_warrant: Mapping[str, Any] | None,
) -> JsonObject:
    redactions: list[Mapping[str, Any]] = []
    request_redactions = request.get("redactions")
    if isinstance(request_redactions, list):
        redactions.extend(
            cast(Mapping[str, Any], item)
            for item in request_redactions
            if isinstance(item, Mapping)
        )
    if selected_warrant is not None:
        warrant_redactions = selected_warrant.get("redactions")
        if isinstance(warrant_redactions, list):
            redactions.extend(
                cast(Mapping[str, Any], item)
                for item in warrant_redactions
                if isinstance(item, Mapping)
            )
    fields = sorted(
        {
            str(item.get("field_path"))
            for item in redactions
            if item.get("field_path") is not None
        }
    )
    return {
        "redaction_count": len(redactions),
        "redacted_fields": fields,
    }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _thread_index(thread_path: str | Path | None) -> dict[str, JsonObject]:
    if thread_path is None or not Path(thread_path).exists():
        return {}
    return {
        str(record["seal_id"]): record
        for record in ThreadLogger.read(thread_path)
        if "seal_id" in record
    }


def _find_thread(thread_path: str | Path, seal_id: str) -> JsonObject:
    for record in ThreadLogger.read(thread_path):
        if record.get("seal_id") == seal_id:
            return record
    raise ValueError(f"seal not found in thread file: {seal_id}")


def _entry_for_record(
    record: Mapping[str, Any],
    threads: Mapping[str, Mapping[str, Any]],
) -> JsonObject:
    selected = cast(Mapping[str, Any] | None, record.get("selected_warrant"))
    selected = selected or {}
    transition_certificate = record.get("state_transition_certificate")
    transition = (
        transition_certificate
        if isinstance(transition_certificate, Mapping)
        else {}
    )
    seal_id = str(record.get("seal_id"))
    thread = threads.get(seal_id)
    return {
        "seal_id": seal_id,
        "thread_id": record.get("thread_id") or (thread or {}).get("thread_id"),
        "tenant_id": record.get("tenant_id"),
        "thread_found": thread is not None,
        "seal_status": (thread or {}).get("seal_status"),
        "product_surface": record.get("product_surface"),
        "sequence_number": record.get("sequence_number"),
        "previous_record_hash": record.get("previous_record_hash"),
        "record_hash": record.get("record_hash"),
        "admission_evidence_hash": record.get("admission_evidence_hash"),
        "admission_evidence_ref": record.get("admission_evidence_ref"),
        "signing_provider": _signature_provider(record.get("signature")),
        "policy_hash": record.get("policy_hash") or selected.get("policy_hash"),
        "policy_version": record.get("policy_version") or selected.get("policy_version"),
        "tool_key": record.get("tool_key"),
        "action_type": record.get("action_type"),
        "decision": record.get("decision"),
        "reason": record.get("reason"),
        "policy_statuses": list(cast(Iterable[str], selected.get("policy_statuses", []))),
        "policy_reasons": list(cast(Iterable[str], selected.get("policy_reasons", []))),
        "evidence_count": len(list(cast(Iterable[Any], selected.get("jurisdiction_evidence", [])))),
        "selected_action_from_thread": (thread or {}).get("selected_action"),
        "state_transition_present": isinstance(transition_certificate, Mapping),
        "state_transition_certificate_hash": record.get("state_transition_certificate_hash"),
        "state_transition_outcome": transition.get("outcome"),
        "state_transition_cas_sequence": transition.get("cas_sequence"),
        "state_transition_pre_state_hash": transition.get("pre_state_hash"),
        "state_transition_post_state_hash": transition.get("post_state_hash"),
    }


def _tool_key_from_request(request: Mapping[str, Any] | None) -> str | None:
    if request is None:
        return None
    server = request.get("server")
    tool = request.get("tool")
    if server is None or tool is None:
        return cast(str | None, request.get("tool_key"))
    return f"{server}/{tool}"


def _mapping_string(mapping: Mapping[str, Any] | None, key: str) -> str | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _signature_provider(signature: object) -> str | None:
    if not isinstance(signature, Mapping):
        return None
    value = signature.get("provider_name")
    return value if isinstance(value, str) else None


def _tool_key_from_warrant(selected_warrant: Mapping[str, Any] | None) -> str | None:
    if selected_warrant is None:
        return None
    value = selected_warrant.get("tool_key")
    return str(value) if value is not None else None


@dataclass(frozen=True)
class DenialPressure:
    boundary_key: str
    pressure: int

    def to_dict(self) -> JsonObject:
        return {"boundary_key": self.boundary_key, "pressure": self.pressure}


@dataclass(frozen=True)
class LedgerReservation:
    success: bool
    boundary_key: str
    admission_price: int
    authority_budget_before: int
    authority_budget_after: int
    authority_ledger_sequence: int

    def to_dict(self) -> JsonObject:
        return {
            "success": self.success,
            "boundary_key": self.boundary_key,
            "admission_price": self.admission_price,
            "authority_budget_before": self.authority_budget_before,
            "authority_budget_after": self.authority_budget_after,
            "authority_ledger_sequence": self.authority_ledger_sequence,
        }


@dataclass
class BoundaryLedgerState:
    boundary_key: str
    authority_budget: int
    remaining_authority: int
    cumulative_admitted_authority: int = 0
    admitted_count: int = 0
    denied_count: int = 0
    downgraded_count: int = 0
    escalated_count: int = 0
    refused_count: int = 0
    masked_action_failure_count: int = 0
    denial_pressure: int = 0
    sequence: int = 0
    split_exposure: dict[str, int] = field(default_factory=dict)
    split_attempts: dict[str, int] = field(default_factory=dict)
    split_reservations: dict[str, int] = field(default_factory=dict)

    def snapshot(self) -> JsonObject:
        return {
            "boundary_key": self.boundary_key,
            "authority_budget": self.authority_budget,
            "remaining_authority": self.remaining_authority,
            "cumulative_admitted_authority": self.cumulative_admitted_authority,
            "admitted_count": self.admitted_count,
            "denied_count": self.denied_count,
            "downgraded_count": self.downgraded_count,
            "escalated_count": self.escalated_count,
            "refused_count": self.refused_count,
            "masked_action_failure_count": self.masked_action_failure_count,
            "denial_pressure": self.denial_pressure,
            "sequence": self.sequence,
            "split_exposure": dict(sorted(self.split_exposure.items())),
            "split_attempts": dict(sorted(self.split_attempts.items())),
            "split_reservations": dict(sorted(self.split_reservations.items())),
        }


class AuthorityLedger:
    """Atomic authority-budget accounting per admission boundary."""

    def __init__(
        self,
        *,
        default_authority_budget: int = 0,
        initial_budgets: Mapping[str, int] | None = None,
        persistence_path: str | Path | None = None,
    ) -> None:
        self._default_authority_budget = default_authority_budget
        self._states: dict[str, BoundaryLedgerState] = {}
        self._lock = RLock()
        self._persistence_path = Path(persistence_path) if persistence_path is not None else None
        if self._persistence_path is not None:
            self._initialize_persistence()
            self._load_persisted_states()
        for boundary_key, budget in (initial_budgets or {}).items():
            key = str(boundary_key)
            if key not in self._states:
                state = BoundaryLedgerState(
                    boundary_key=key,
                    authority_budget=int(budget),
                    remaining_authority=int(budget),
                )
                self._states[key] = state
                self._persist_state(state)

    def reserve(
        self, boundary_key: str, admission_price: int, *, budget: int | None = None
    ) -> LedgerReservation:
        with self._lock:
            state = self._ensure_state(boundary_key, budget=budget)
            before = state.remaining_authority
            if admission_price > before:
                return LedgerReservation(
                    success=False,
                    boundary_key=boundary_key,
                    admission_price=admission_price,
                    authority_budget_before=before,
                    authority_budget_after=before,
                    authority_ledger_sequence=state.sequence,
                )
            state.remaining_authority -= admission_price
            state.cumulative_admitted_authority += admission_price
            state.admitted_count += 1
            state.sequence += 1
            self._persist_state(state)
            return LedgerReservation(
                success=True,
                boundary_key=boundary_key,
                admission_price=admission_price,
                authority_budget_before=before,
                authority_budget_after=state.remaining_authority,
                authority_ledger_sequence=state.sequence,
            )

    def reserve_split_bundle(
        self,
        boundary_key: str,
        split_group_key: str,
        bundle_required: int,
        *,
        budget: int | None = None,
    ) -> LedgerReservation:
        with self._lock:
            state = self._ensure_state(boundary_key, budget=budget)
            before = state.remaining_authority
            already_reserved = state.split_reservations.get(split_group_key, 0)
            incremental_price = max(bundle_required - already_reserved, 0)
            if incremental_price > before:
                return LedgerReservation(
                    success=False,
                    boundary_key=boundary_key,
                    admission_price=incremental_price,
                    authority_budget_before=before,
                    authority_budget_after=before,
                    authority_ledger_sequence=state.sequence,
                )
            state.remaining_authority -= incremental_price
            state.cumulative_admitted_authority += incremental_price
            state.admitted_count += 1
            state.sequence += 1
            state.split_reservations[split_group_key] = max(already_reserved, bundle_required)
            self._persist_state(state)
            return LedgerReservation(
                success=True,
                boundary_key=boundary_key,
                admission_price=incremental_price,
                authority_budget_before=before,
                authority_budget_after=state.remaining_authority,
                authority_ledger_sequence=state.sequence,
            )

    def split_bundle_incremental_price(
        self,
        boundary_key: str,
        split_group_key: str,
        bundle_required: int,
        *,
        budget: int | None = None,
    ) -> LedgerReservation:
        with self._lock:
            state = self._ensure_state(boundary_key, budget=budget)
            before = state.remaining_authority
            already_reserved = state.split_reservations.get(split_group_key, 0)
            incremental_price = max(bundle_required - already_reserved, 0)
            return LedgerReservation(
                success=incremental_price <= before,
                boundary_key=boundary_key,
                admission_price=incremental_price,
                authority_budget_before=before,
                authority_budget_after=before,
                authority_ledger_sequence=state.sequence,
            )

    def record_non_admitted(
        self, boundary_key: str, decision: str, *, budget: int | None = None
    ) -> None:
        with self._lock:
            state = self._ensure_state(boundary_key, budget=budget)
            state.denial_pressure += 1
            state.denied_count += 1
            if decision == "FALLBACK_EXECUTED":
                state.downgraded_count += 1
            elif decision == "ESCALATED":
                state.escalated_count += 1
            elif decision == "REFUSED":
                state.refused_count += 1
            elif decision == "MASKED_ACTION_FAILURE":
                state.masked_action_failure_count += 1
            self._persist_state(state)

    def denial_pressure(self, boundary_key: str) -> int:
        with self._lock:
            state = self._states.get(boundary_key)
            return state.denial_pressure if state is not None else 0

    def current_sequence(self, boundary_key: str) -> int:
        with self._lock:
            state = self._states.get(boundary_key)
            return state.sequence if state is not None else 0

    def remaining_authority(self, boundary_key: str, *, budget: int | None = None) -> int:
        with self._lock:
            return self._ensure_state(boundary_key, budget=budget).remaining_authority

    def aggregate_split_exposure(
        self, boundary_key: str, split_group_key: str, exposure: int
    ) -> int:
        with self._lock:
            state = self._ensure_state(boundary_key)
            state.split_exposure[split_group_key] = (
                state.split_exposure.get(split_group_key, 0) + exposure
            )
            state.split_attempts[split_group_key] = state.split_attempts.get(split_group_key, 0) + 1
            self._persist_state(state)
            return state.split_exposure[split_group_key]

    def split_attempt_count(self, boundary_key: str, split_group_key: str) -> int:
        with self._lock:
            state = self._states.get(boundary_key)
            if state is None:
                return 0
            return state.split_attempts.get(split_group_key, 0)

    def snapshot(self) -> JsonObject:
        with self._lock:
            return {
                boundary_key: state.snapshot()
                for boundary_key, state in sorted(self._states.items())
            }

    def _ensure_state(self, boundary_key: str, *, budget: int | None = None) -> BoundaryLedgerState:
        state = self._states.get(boundary_key)
        if state is not None:
            return state
        resolved_budget = self._default_authority_budget if budget is None else budget
        state = BoundaryLedgerState(
            boundary_key=boundary_key,
            authority_budget=resolved_budget,
            remaining_authority=resolved_budget,
        )
        self._states[boundary_key] = state
        self._persist_state(state)
        return state

    def _initialize_persistence(self) -> None:
        persistence_path = self._persistence_path
        if persistence_path is None:
            raise RuntimeError("persistence path is not configured")
        persistence_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(persistence_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authority_ledger_state (
                    boundary_key TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL
                )
                """
            )

    def _load_persisted_states(self) -> None:
        persistence_path = self._persistence_path
        if persistence_path is None:
            raise RuntimeError("persistence path is not configured")
        with sqlite3.connect(persistence_path) as connection:
            rows = connection.execute(
                "SELECT boundary_key, state_json FROM authority_ledger_state"
            ).fetchall()
        for boundary_key, state_json in rows:
            payload = cast(JsonObject, json.loads(str(state_json)))
            self._states[str(boundary_key)] = _boundary_state_from_snapshot(payload)

    def _persist_state(self, state: BoundaryLedgerState) -> None:
        if self._persistence_path is None:
            return
        with sqlite3.connect(self._persistence_path) as connection:
            connection.execute(
                """
                INSERT INTO authority_ledger_state(boundary_key, state_json)
                VALUES (?, ?)
                ON CONFLICT(boundary_key) DO UPDATE SET state_json = excluded.state_json
                """,
                (state.boundary_key, json.dumps(state.snapshot(), sort_keys=True)),
            )


def _boundary_state_from_snapshot(payload: Mapping[str, Any]) -> BoundaryLedgerState:
    if "redeemed_tokens" in payload:
        raise ValueError(
            "obsolete authority ledger state contains redeemed_tokens; "
            "Execution Permit state requires a fresh store"
        )
    return BoundaryLedgerState(
        boundary_key=str(payload["boundary_key"]),
        authority_budget=int(payload["authority_budget"]),
        remaining_authority=int(payload["remaining_authority"]),
        cumulative_admitted_authority=int(payload.get("cumulative_admitted_authority", 0)),
        admitted_count=int(payload.get("admitted_count", 0)),
        denied_count=int(payload.get("denied_count", 0)),
        downgraded_count=int(payload.get("downgraded_count", 0)),
        escalated_count=int(payload.get("escalated_count", 0)),
        refused_count=int(payload.get("refused_count", 0)),
        masked_action_failure_count=int(payload.get("masked_action_failure_count", 0)),
        denial_pressure=int(payload.get("denial_pressure", 0)),
        sequence=int(payload.get("sequence", 0)),
        split_exposure={
            str(key): int(value) for key, value in dict(payload.get("split_exposure", {})).items()
        },
        split_attempts={
            str(key): int(value) for key, value in dict(payload.get("split_attempts", {})).items()
        },
        split_reservations={
            str(key): int(value)
            for key, value in dict(payload.get("split_reservations", {})).items()
        },
    )
