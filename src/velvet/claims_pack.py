"""Incident-scoped Claims Pack generation."""

from __future__ import annotations

import importlib
import importlib.util
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from velvet.assurance import (
    AssuranceAttestationError,
    export_attestations_jsonl,
    issue_control_state_attestation,
    load_ledger_records,
    write_consistency_proofs,
)
from velvet.attestation import write_attestation_pack
from velvet.ledger import seal_thread_decision
from velvet.serialization import JsonObject
from velvet.signing import SigningProvider, signer_default_key_id


def write_claims_pack(
    *,
    incident_window_start: str,
    incident_window_end: str,
    ledger_path: str | Path,
    sth_path: str | Path,
    public_key: str | bytes,
    output_dir: str | Path,
    system_name: str,
    intended_purpose: str,
    deployer_legal_entity: str,
    eu_exposure: bool,
    deployment_id_source: str,
    deployment_salt: str,
    signer: SigningProvider,
    signing_key_id: str | None = None,
    approvals_path: str | Path | None = None,
    latest_sth_path: str | Path | None = None,
    assurance_attestations_path: str | Path | None = None,
    consistency_proofs_path: str | Path | None = None,
    anchor_sths_path: str | Path | None = None,
    thread_path: str | Path | None = None,
    policy_bundle_hash: str | None = None,
    policy_bundle_signature_status: str = "unavailable",
    policy_last_change_timestamp: str | None = None,
    last_successful_anchor_timestamp: str | None = None,
    retention_preset: str = "unavailable",
    signing_degraded: bool = False,
    anchoring_degraded: bool = False,
    fail_open_condition_observed: bool = False,
) -> JsonObject:
    """Build an incident-window Claims Pack and verifier reports."""

    destination = Path(output_dir)
    resolved_key_id = signing_key_id or signer_default_key_id(signer)
    consistency_proofs = _load_assurance_consistency_proofs(consistency_proofs_path)
    anchored_sths = _load_anchor_sths(anchor_sths_path)
    if assurance_attestations_path is not None:
        attestations = _load_assurance_attestations(assurance_attestations_path)
        if not _assurance_series_covers_window(
            attestations,
            start=incident_window_start,
            end=incident_window_end,
        ):
            raise AssuranceAttestationError(
                "assurance attestation series does not cover incident window"
            )
    else:
        sth = _read_json_object(sth_path)
        attestations = [
            issue_control_state_attestation(
                records=load_ledger_records(ledger_path),
                sth=sth,
                period_start=incident_window_start,
                period_end=incident_window_end,
                deployment_id_source=deployment_id_source,
                deployment_salt=deployment_salt,
                signer=signer,
                signing_key_id=resolved_key_id,
                approvals_path=approvals_path,
                policy_bundle_hash=policy_bundle_hash,
                policy_bundle_signature_status=policy_bundle_signature_status,
                policy_last_change_timestamp=policy_last_change_timestamp,
                last_successful_anchor_timestamp=last_successful_anchor_timestamp,
                retention_preset=retention_preset,
                signing_degraded=signing_degraded,
                anchoring_degraded=anchoring_degraded,
                fail_open_condition_observed=fail_open_condition_observed,
            )
        ]

    assurance_verification = _verify_claims_assurance_report(
        attestations=attestations,
        public_key=public_key,
        consistency_proofs=consistency_proofs,
        anchored_sths=anchored_sths,
    )
    if assurance_verification.get("status") != "pass":
        raise AssuranceAttestationError("assurance verification failed; refusing claims pack")

    manifest = write_attestation_pack(
        ledger_path=ledger_path,
        sth_path=sth_path,
        public_key=public_key,
        output_dir=destination,
        system_name=system_name,
        intended_purpose=intended_purpose,
        deployer_legal_entity=deployer_legal_entity,
        eu_exposure=eu_exposure,
        signer=signer,
        signing_key_id=resolved_key_id,
        start=incident_window_start,
        end=incident_window_end,
        approvals_path=approvals_path,
        latest_sth_path=latest_sth_path,
    )
    assurance_dir = destination / "assurance"
    assurance_dir.mkdir(parents=True, exist_ok=True)
    assurance_manifest = export_attestations_jsonl(
        attestations,
        assurance_dir / "attestations.jsonl",
    )
    write_consistency_proofs(consistency_proofs, assurance_dir / "consistency_proofs.json")
    _write_claims_assurance_verification_report(
        output_dir=destination,
        report=assurance_verification,
    )
    replay_report = _write_claims_replay_report(
        output_dir=destination,
        thread_path=str(thread_path) if thread_path is not None else None,
    )
    return {
        "attestation_pack_manifest": manifest,
        "assurance_export": assurance_manifest,
        "assurance_verification": assurance_verification,
        "replay_verification": replay_report,
    }


def _read_json_object(path: str | Path) -> JsonObject:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object at {path}")
    return cast(JsonObject, payload)


def _write_claims_replay_report(
    *,
    output_dir: Path,
    thread_path: str | None,
) -> JsonObject:
    reports: list[JsonObject] = []
    if thread_path:
        for path in sorted((output_dir / "records").glob("decision_record_*.json")):
            record = _read_json_object(path)
            seal_id = record.get("seal_id")
            if not isinstance(seal_id, str) or not seal_id:
                continue
            try:
                reports.append(seal_thread_decision(thread_path, seal_id))
            except (OSError, ValueError, KeyError) as error:
                reports.append(
                    {
                        "status": "fail",
                        "seal_id": seal_id,
                        "record_file": str(path),
                        "reason": str(error),
                    }
                )
    status = "not_run"
    if thread_path:
        all_replayed = reports and all(report.get("status") == "pass" for report in reports)
        status = "pass" if all_replayed else "fail"
    payload: JsonObject = {
        "schema_version": "velvet.claims_pack.replay_verification.v1",
        "status": status,
        "thread_path": thread_path,
        "reports": reports,
    }
    verification_dir = output_dir / "verification"
    verification_dir.mkdir(parents=True, exist_ok=True)
    (verification_dir / "claims_replay_verification_report.json").write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _load_assurance_attestations(path: str | Path) -> list[JsonObject]:
    verifier = _load_assurance_verifier_module()
    return cast(list[JsonObject], verifier.load_attestations_jsonl(path))


def _load_assurance_consistency_proofs(path: str | Path | None) -> list[JsonObject]:
    verifier = _load_assurance_verifier_module()
    return cast(list[JsonObject], verifier.load_consistency_proofs(path))


def _load_anchor_sths(path: str | Path | None) -> list[JsonObject]:
    verifier = _load_assurance_verifier_module()
    return cast(list[JsonObject], verifier.load_anchor_sths(path))


def _verify_claims_assurance_report(
    *,
    attestations: Sequence[Mapping[str, Any]],
    public_key: str | bytes,
    consistency_proofs: Sequence[Mapping[str, Any]],
    anchored_sths: Sequence[Mapping[str, Any]],
) -> JsonObject:
    verifier = _load_assurance_verifier_module()
    return cast(
        JsonObject,
        verifier.verify_attestation_series(
            attestations,
            public_key=public_key,
            consistency_proofs=consistency_proofs,
            anchored_sths=anchored_sths,
        ),
    )


def _write_claims_assurance_verification_report(
    *,
    output_dir: Path,
    report: Mapping[str, Any],
) -> None:
    verification_dir = output_dir / "verification"
    verification_dir.mkdir(parents=True, exist_ok=True)
    (verification_dir / "assurance_verification_report.json").write_text(
        json.dumps(report, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _assurance_series_covers_window(
    attestations: Sequence[Mapping[str, Any]],
    *,
    start: str,
    end: str,
) -> bool:
    target_start = _parse_claims_time(start)
    target_end = _parse_claims_time(end)
    if target_end <= target_start:
        return False
    intervals: list[tuple[datetime, datetime]] = []
    for envelope in attestations:
        payload = envelope.get("payload")
        if not isinstance(payload, Mapping):
            return False
        period = payload.get("period")
        if not isinstance(period, Mapping):
            return False
        period_start = period.get("start")
        period_end = period.get("end")
        if not isinstance(period_start, str) or not isinstance(period_end, str):
            return False
        intervals.append((_parse_claims_time(period_start), _parse_claims_time(period_end)))
    covered_until: datetime | None = None
    for period_start, period_end in sorted(intervals):
        if period_end <= target_start:
            continue
        if covered_until is None:
            if period_start > target_start:
                return False
            covered_until = period_end
        elif period_start > covered_until:
            return False
        else:
            covered_until = max(covered_until, period_end)
        if covered_until >= target_end:
            return True
    return False


def _parse_claims_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _load_assurance_verifier_module() -> Any:
    try:
        return importlib.import_module("velvet_assurance_verifier.verifier")
    except ModuleNotFoundError as error:
        verifier_path = (
            Path(__file__).resolve().parents[2]
            / "assurance"
            / "verifier"
            / "velvet_assurance_verifier"
            / "verifier.py"
        )
        if not verifier_path.exists():
            raise AssuranceAttestationError(
                "offline assurance verifier package is unavailable"
            ) from error
        spec = importlib.util.spec_from_file_location(
            "velvet_assurance_verifier_local",
            verifier_path,
        )
        if spec is None or spec.loader is None:
            raise AssuranceAttestationError(
                "offline assurance verifier could not be loaded"
            ) from error
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
