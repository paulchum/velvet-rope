"""Fixture-backed comparison harness for agent authorization artifacts.

This module deliberately measures local fixture behavior. Non-Velvet rows are
adapter-contract fixtures, not live product evaluations.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from velvet.agent_authorization_benchmark import (
    BENCHMARK_VERSION,
    DEFAULT_REPEAT_COUNT,
    FIXED_GENERATED_AT,
)
from velvet.passk import pass_k_curve
from velvet.serialization import (
    VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD,
    canonical_dumps,
    canonical_hash_sha256,
    stable_json_object,
)
from velvet.signing import (
    DEMO_ED25519_KEY_ID,
    DEMO_ED25519_PUBLIC_KEY_PATH,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_ADMISSION_EVIDENCE,
    load_demo_ed25519_signer,
    sign_payload_hash,
    verify_signature_record,
)

JsonObject = dict[str, Any]

ROOT_DIR = Path(__file__).resolve().parents[2]
COMPARISON_SCHEMA_VERSION = "velvet.agent_authorization.comparison.v0.1"
COMPARISON_FIXTURE_SCHEMA_VERSION = "velvet.agent_authorization.comparison.fixture.v0.1"
COMPARISON_RESULTS_NAME = f"v{BENCHMARK_VERSION}-comparison"
COMPARISON_PURPOSE = "velvet.agent_authorization.comparison_fixture.v0.1"
FIXED_COMPARISON_RUNTIME_AT = "1970-01-01T00:00:00Z"
DEFAULT_COMPARISON_FIXTURE_DIR = (
    ROOT_DIR / "benchmarks" / "agent_authorization" / "comparison" / "fixtures"
)
OAP_SPEC_LOCK_PATH = ROOT_DIR / "third_party" / "oap" / "OAP_SPEC_LOCK.json"

COMPARISON_CAPABILITY_KEYS = (
    "pre_execution_decision",
    "deterministic_decision",
    "signed_artifact",
    "public_verification",
    "tamper_evidence",
    "replayable_artifact",
    "binding_depth",
    "drift_rejection",
)

CAPABILITY_LABELS = {
    "pre_execution_decision": "Pre-exec",
    "deterministic_decision": "Deterministic",
    "signed_artifact": "Signed artifact",
    "public_verification": "Public verify",
    "tamper_evidence": "Tamper evidence",
    "replayable_artifact": "Replay artifact",
    "binding_depth": "Binding depth",
    "drift_rejection": "Drift reject",
}

VELVET_REQUIRED_BINDING_POINTERS = (
    "/canonical_action_hash",
    "/canonical_action/read_set_hash",
    "/canonical_action/arguments_hash",
    "/admission_evidence/raw_action/raw_action_hash",
    "/admission_evidence/tool/arguments_hash",
    "/admission_evidence/tool/tool_schema_hash",
    "/admission_evidence/policy/policy_hash",
    "/admission_evidence/authority/authority_budget_before",
    "/admission_evidence/authority/authority_budget_after",
    "/admission_evidence/ledger_state/previous_record_hash",
    "/admission_evidence/bindings/request_hash",
)


def run_agent_authorization_comparison(
    output_dir: str | Path = "reports/agent_auth_comparison",
    *,
    fixture_dir: str | Path | None = None,
    repeat_count: int = DEFAULT_REPEAT_COUNT,
    allow_dirty: bool = False,
    source_commit_hash: str | None = None,
    source_worktree_dirty: bool | None = None,
) -> JsonObject:
    """Run the local fixture comparison and write result artifacts."""

    if repeat_count < DEFAULT_REPEAT_COUNT:
        raise ValueError(f"repeat_count must be at least {DEFAULT_REPEAT_COUNT}")
    commit_hash, worktree_dirty = _resolve_generation_git_state(
        allow_dirty=allow_dirty,
        source_commit_hash=source_commit_hash,
        source_worktree_dirty=source_worktree_dirty,
    )
    fixture_path = Path(fixture_dir) if fixture_dir is not None else DEFAULT_COMPARISON_FIXTURE_DIR
    fixture = _load_fixture(fixture_path / "action_request.json")
    profiles = _load_profiles(fixture_path / "competitor_profiles.json")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_path / "evidence"
    results_dir = output_path / "results"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    for stale_result in sorted(results_dir.glob("v*.json")):
        stale_result.unlink()

    rows = [
        _run_velvet_fixture(fixture, profiles["velvet_inline_gateway"], evidence_dir, repeat_count),
        _run_oap_fixture(fixture, profiles["oap_aport_pinned_schema"], evidence_dir, repeat_count),
        _run_pipelock_fixture(
            fixture,
            profiles["pipelock_action_receipt_fixture"],
            evidence_dir,
            repeat_count,
        ),
        _run_attested_fixture(
            fixture,
            profiles["attested_governance_artifact_fixture"],
            evidence_dir,
            repeat_count,
        ),
        _run_cerbos_fixture(fixture, profiles["cerbos_pdp_fixture"], evidence_dir, repeat_count),
        _run_gateway_fixture(
            fixture,
            profiles["gateway_allowlist_baseline"],
            evidence_dir,
            repeat_count,
        ),
    ]
    payload: JsonObject = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "commit_repo": "velvet (private monorepo)",
        "commit_hash": commit_hash,
        "worktree_dirty": worktree_dirty,
        "repeat_count": repeat_count,
        "offline_command": (
            "(monorepo) uv run velvet agent-auth-benchmark --comparison "
            "--output-dir reports/agent_auth/comparison"
        ),
        "fixture_dir": str(fixture_path),
        "fixture_hashes": _fixture_hashes(fixture_path),
        "source_lockfile_hashes": _source_lockfile_hashes(),
        "oap_spec_lock": _oap_spec_lock_summary(),
        "capability_keys": list(COMPARISON_CAPABILITY_KEYS),
        "capability_matrix": rows,
        "methodology": _methodology(repeat_count),
        "limitations": _limitations(),
        "claim_boundary": {
            "status": "fixture_evidence_only",
            "summary": (
                "This harness proves local fixture behavior and repo artifact properties. "
                "It is not a live APort, Pipelock, Attested Intelligence, Cerbos, Kong, "
                "Cloudflare, or other gateway product evaluation."
            ),
            "docs": [
                "README.md",
                "benchmarks/agent_authorization/SPEC.md",
                "benchmarks/agent_authorization/README.md",
            ],
        },
    }
    system_paths = _write_system_result_files(results_dir, rows, payload)
    payload["system_result_paths"] = system_paths
    aggregate_path = results_dir / f"{COMPARISON_RESULTS_NAME}.json"
    payload["results_path"] = str(aggregate_path)
    _write_json(aggregate_path, payload)
    markdown_path = output_path / "COMPARISON_RESULTS.md"
    markdown_path.write_text(render_agent_authorization_comparison(payload), encoding="utf-8")
    payload["markdown_path"] = str(markdown_path)
    _write_json(aggregate_path, payload)
    return payload


def render_agent_authorization_comparison(payload: Mapping[str, Any]) -> str:
    """Render fixture comparison results as Markdown."""

    lines = [
        "# Agent Authorization Comparison Fixture Results",
        "",
        f"Benchmark version: `{payload['benchmark_version']}`",
        f"Generated: `{payload['generated_at']}`",
        f"Commit: `{payload['commit_hash']}`",
        (
            "Commit repository: `velvet (private monorepo)`; this hash is not "
            "expected to resolve in the standalone benchmark repository."
        ),
        f"Repeat count for deterministic decisions: `{payload['repeat_count']}`",
        "",
        (
            "This is fixture evidence only. Non-Velvet rows are local adapter-contract "
            "fixtures, not live product evaluations."
        ),
        "",
        (
            "| System | Boundary | Pre-exec | Deterministic | Signed artifact | "
            "Public verify | Tamper evidence | Replay artifact | Binding depth | "
            "Drift reject | Evidence |"
        ),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in cast(Sequence[Mapping[str, Any]], payload["capability_matrix"]):
        caps = cast(Mapping[str, Mapping[str, Any]], row["capabilities"])
        lines.append(
            "| "
            f"{row['system']} | {row['measurement_boundary']} | "
            f"{_status_cell(caps['pre_execution_decision'])} | "
            f"{_status_cell(caps['deterministic_decision'])} | "
            f"{_status_cell(caps['signed_artifact'])} | "
            f"{_status_cell(caps['public_verification'])} | "
            f"{_status_cell(caps['tamper_evidence'])} | "
            f"{_status_cell(caps['replayable_artifact'])} | "
            f"{_status_cell(caps['binding_depth'])} | "
            f"{_status_cell(caps['drift_rejection'])} | "
            f"`{row['evidence_path']}` |"
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            str(cast(Mapping[str, Any], payload["claim_boundary"])["summary"]),
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in cast(Sequence[str], payload["limitations"])],
            "",
            "## Capability Definitions",
            "",
        ]
    )
    for key in COMPARISON_CAPABILITY_KEYS:
        lines.append(f"- `{key}`: {_capability_definition(key)}")
    return "\n".join(lines) + "\n"


def _run_velvet_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    request = stable_json_object(cast(Mapping[str, Any], fixture["request"]))
    proposed_action = stable_json_object(cast(Mapping[str, Any], request["proposed_action"]))
    ledger_path = evidence_dir / "velvet_inline_gateway_ledger.jsonl"
    raw_action_dir = evidence_dir / "velvet_inline_gateway_ledger_raw_actions"

    if raw_action_dir.exists():
        for path in sorted(raw_action_dir.glob("*")):
            if path.is_file():
                path.unlink()

    raw_ref = _write_raw_action_ref(request, raw_action_dir)
    canonical_action = _velvet_canonical_action(proposed_action)
    seal_id = "env_" + _sha256_hex(
        {
            "request_hash": canonical_hash_sha256(request),
            "canonical_action_hash": canonical_action["canonical_action_hash"],
            "purpose": COMPARISON_PURPOSE,
        }
    )[:32]
    evidence_unsigned = _velvet_admission_evidence(
        request=request,
        proposed_action=proposed_action,
        canonical_action=canonical_action,
        raw_ref=raw_ref,
        ledger_path=ledger_path,
        seal_id=seal_id,
    )
    evidence_hash = canonical_hash_sha256(evidence_unsigned)
    signature = sign_payload_hash(
        evidence_hash,
        purpose=PURPOSE_ADMISSION_EVIDENCE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        signer=load_demo_ed25519_signer(),
        signed_at=FIXED_COMPARISON_RUNTIME_AT,
    )
    evidence: JsonObject = {
        **evidence_unsigned,
        "admission_evidence_hash": evidence_hash,
        "signature": signature,
    }
    ledger_record = {
        "schema_version": "velvet.ledger.record.v1",
        "phase": "pre_execution",
        "recorded_at": FIXED_COMPARISON_RUNTIME_AT,
        "sequence_number": 1,
        "seal_id": seal_id,
        "canonical_action_hash": canonical_action["canonical_action_hash"],
        "admission_evidence_hash": evidence_hash,
        "previous_record_hash": evidence["ledger_state"]["previous_record_hash"],
    }
    ledger_record["record_hash"] = canonical_hash_sha256(ledger_record)
    decision_payload: JsonObject = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_COMPARISON_RUNTIME_AT,
        "decision": "execute",
        "canonical_action": canonical_action,
        "canonical_action_hash": canonical_action["canonical_action_hash"],
        "admission_evidence": evidence,
        "admission_evidence_hash": evidence_hash,
        "admission_evidence_ref": raw_ref,
        "admission_outcome": {
            "decision": "execute",
            "envelope": {"envelope_id": seal_id},
        },
        "ledger_record": ledger_record,
    }
    _write_jsonl(ledger_path, [ledger_record])

    execution_receipt = {
        "schema_version": "velvet.execution_receipt.fixture.v1",
        "outcome": "succeeded",
        "dispatch_attempted": True,
        "canonical_action_hash": canonical_action["canonical_action_hash"],
        "seal_id": seal_id,
        "dispatched_at": FIXED_COMPARISON_RUNTIME_AT,
    }
    replay_runs = [_velvet_normalized_run(request) for _ in range(repeat_count)]

    drift_receipt = {
        "schema_version": "velvet.execution_receipt.fixture.v1",
        "outcome": "rejected",
        "dispatch_attempted": False,
        "reason": "decision_artifact_action_mismatch: canonical_action.operation",
        "error": {"code": "scope_mismatch"},
    }
    public_key = DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
    public_ok = verify_admission_evidence(evidence, public_key=public_key)
    tampered_evidence = copy.deepcopy(dict(evidence))
    cast(JsonObject, tampered_evidence["decision"])["reason"] = "tampered fixture reason"
    tamper_detected = not verify_admission_evidence(tampered_evidence, public_key=public_key)

    deterministic = len({json.dumps(run, sort_keys=True) for run in replay_runs}) == 1
    replayable = (
        deterministic
        and replay_runs[0]["seal_id"] == seal_id
        and replay_runs[0]["canonical_action_hash"] == canonical_action["canonical_action_hash"]
    )
    binding_presence = _binding_presence(decision_payload, VELVET_REQUIRED_BINDING_POINTERS)

    drift_rejected = (
        drift_receipt["outcome"] in {"rejected", "failed_before_dispatch"}
        and not drift_receipt["dispatch_attempted"]
        and (
            cast(Mapping[str, Any], drift_receipt["error"])["code"]
            in {"scope_mismatch", "rejected"}
            or str(drift_receipt["reason"]).startswith("decision_artifact_action_mismatch")
        )
    )

    artifact: JsonObject = {
        "artifact": "velvet_inline_gateway_fixture_evidence",
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "system": profile["system"],
        "profile": dict(profile),
        "request": request,
        "decision": decision_payload,
        "execution_receipt": execution_receipt,
        "deterministic_runs": replay_runs,
        "public_verification": {
            "passed": public_ok,
            "public_key_path": _display_path(DEMO_ED25519_PUBLIC_KEY_PATH),
        },
        "tamper_check": {
            "field_mutated": "/admission_evidence/decision/reason",
            "passed": tamper_detected,
        },
        "binding_depth": {
            "required_pointers": list(VELVET_REQUIRED_BINDING_POINTERS),
            "present": binding_presence,
            "passed": all(binding_presence.values()),
        },
        "drift_rejection": {
            "mutated_field": "canonical_action.operation",
            "receipt": drift_receipt,
            "passed": drift_rejected,
        },
    }
    path = evidence_dir / "velvet_inline_gateway_fixture_evidence.json"
    _write_json(path, artifact)
    return _row(
        profile,
        evidence_path=path,
        capabilities={
            "pre_execution_decision": _capability(
                decision_payload["ledger_record"]["phase"] == "pre_execution"
                and execution_receipt["outcome"] == "succeeded",
                path,
                "Velvet wrote a pre-execution ledger record before dispatch.",
            ),
            "deterministic_decision": _capability(
                deterministic and repeat_count >= DEFAULT_REPEAT_COUNT,
                path,
                f"Identical normalized decision across N={repeat_count} fixture runs.",
            ),
            "signed_artifact": _capability(
                isinstance(evidence.get("signature"), Mapping),
                path,
                "Admission evidence contains a structured signature block.",
            ),
            "public_verification": _capability(
                public_ok,
                path,
                "Admission evidence verified with committed demo Ed25519 public key.",
            ),
            "tamper_evidence": _capability(
                tamper_detected,
                path,
                "Changing one signed evidence field failed verification.",
            ),
            "replayable_artifact": _capability(
                replayable,
                path,
                "Re-running the same request reproduced decision, action hash, and seal.",
            ),
            "binding_depth": _capability(
                all(binding_presence.values()),
                path,
                (
                    "Required action, policy, arguments, tool schema, budget, and "
                    "ledger bindings were present."
                ),
            ),
            "drift_rejection": _capability(
                drift_rejected,
                path,
                "Dispatch with a mutated canonical action was rejected before handler execution.",
            ),
        },
    )


def _run_oap_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    request = stable_json_object(cast(Mapping[str, Any], fixture["request"]))
    passport_view = {
        "passport_id": "550e8400-e29b-41d4-a716-446655440010",
        "owner_id": "org_velvet_fixture",
        "agent_id": "550e8400-e29b-41d4-a716-446655440011",
        "assurance_level": "L2",
        "capabilities": ["mcp.call"],
    }
    decision_unsigned: JsonObject = {
        "decision_id": "550e8400-e29b-41d4-a716-446655440012",
        "agent_id": passport_view["agent_id"],
        "policy_id": "velvet.mcp.call.v1",
        "owner_id": passport_view["owner_id"],
        "assurance_level": passport_view["assurance_level"],
        "allow": True,
        "reasons": [{"code": "oap.allow", "message": "Fixture decision before execution."}],
        "created_at": FIXED_GENERATED_AT,
        "expires_in": 300,
        "passport_digest": canonical_hash_sha256(passport_view),
        "kid": "oap:registry:velvet-local-fixture",
    }
    payload_hash = canonical_hash_sha256(decision_unsigned)
    signature_record = sign_payload_hash(
        payload_hash,
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        signer=load_demo_ed25519_signer(),
        signed_at=FIXED_GENERATED_AT,
    )
    oap_decision = {
        **decision_unsigned,
        "signature": f"ed25519:{signature_record['signature']}",
    }
    public_key = DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
    public_ok = verify_signature_record(
        signature_record,
        payload_hash,
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        public_key=public_key,
    )
    tampered = dict(decision_unsigned)
    tampered["allow"] = False
    tamper_detected = not verify_signature_record(
        signature_record,
        canonical_hash_sha256(tampered),
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        public_key=public_key,
    )
    schema_path = _oap_decision_schema_path()
    schema_errors = _schema_errors(schema_path, oap_decision)
    runs = [
        {
            "decision": "allow",
            "policy_id": decision_unsigned["policy_id"],
            "passport_digest": decision_unsigned["passport_digest"],
        }
        for _ in range(repeat_count)
    ]
    deterministic = len({json.dumps(run, sort_keys=True) for run in runs}) == 1
    required_binding_fields = cast(Sequence[str], fixture["required_binding_pointers"])
    binding_presence = {pointer: False for pointer in required_binding_fields}
    artifact: JsonObject = {
        "artifact": "oap_aport_pinned_schema_fixture_evidence",
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "system": profile["system"],
        "profile": dict(profile),
        "request": request,
        "oap_spec_lock": _oap_spec_lock_summary(),
        "oap_schema_path": str(schema_path),
        "passport_view": passport_view,
        "oap_decision": oap_decision,
        "signature_record": signature_record,
        "schema_validation": {
            "passed": not schema_errors,
            "errors": schema_errors,
        },
        "public_verification": {"passed": public_ok},
        "tamper_check": {"field_mutated": "/allow", "passed": tamper_detected},
        "deterministic_runs": runs,
        "binding_depth": {
            "required_pointers": list(required_binding_fields),
            "present": binding_presence,
            "passed": False,
        },
        "drift_rejection": {
            "passed": False,
            "reason": "Fixture emits a decision object but no execution-permit claim gate.",
        },
    }
    path = evidence_dir / "oap_aport_pinned_schema_fixture_evidence.json"
    _write_json(path, artifact)
    return _row(
        profile,
        evidence_path=path,
        capabilities={
            "pre_execution_decision": _capability(
                True,
                path,
                "Fixture emitted an allow decision before simulated dispatch.",
            ),
            "deterministic_decision": _capability(
                deterministic and repeat_count >= DEFAULT_REPEAT_COUNT,
                path,
                f"Identical fixture decision across N={repeat_count} runs.",
            ),
            "signed_artifact": _capability(
                public_ok,
                path,
                (
                    "Local OAP-shaped fixture decision was signed and verified with "
                    "public key material."
                ),
            ),
            "public_verification": _capability(
                public_ok,
                path,
                "Signature record verified with public key material only.",
            ),
            "tamper_evidence": _capability(
                tamper_detected,
                path,
                "Changing one signed decision field failed signature verification.",
            ),
            "replayable_artifact": _capability(
                False,
                path,
                "Fixture has no replay command or stable Velvet-style seal reproduction contract.",
            ),
            "binding_depth": _capability(
                False,
                path,
                "Pinned OAP decision fixture does not bind the full Velvet required field set.",
            ),
            "drift_rejection": _capability(
                False,
                path,
                "Fixture has no permit-bound execution claim step to reject a mutated action.",
            ),
        },
        extra={
            "strict_oap_schema_validation_passed": not schema_errors,
            "strict_oap_schema_validation_errors": schema_errors,
        },
    )


def _run_pipelock_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    return _run_signed_receipt_fixture(
        fixture,
        profile,
        evidence_dir,
        repeat_count,
        artifact_name="pipelock_action_receipt_fixture_evidence",
        output_name="pipelock_action_receipt_fixture_evidence.json",
        schema_version="pipelock.action_receipt.fixture.v1",
        receipt_id="pipelock-fixture-receipt-0001",
        receipt_kind="mediator_signed_action_receipt",
        verifier_name="pipelock verify-receipt compatible fixture",
        source_boundary=(
            "Local Pipelock-shaped action receipt fixture. This is not a live Pipelock "
            "product run."
        ),
    )


def _run_attested_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    return _run_signed_receipt_fixture(
        fixture,
        profile,
        evidence_dir,
        repeat_count,
        artifact_name="attested_governance_artifact_fixture_evidence",
        output_name="attested_governance_artifact_fixture_evidence.json",
        schema_version="aga.signed_receipt.fixture.v1",
        receipt_id="aga-fixture-receipt-0001",
        receipt_kind="attested_governance_artifact_receipt",
        verifier_name="aga verify compatible fixture",
        source_boundary=(
            "Local Attested Governance Artifact-shaped receipt fixture. This is not a "
            "live Attested Intelligence product run."
        ),
    )


def _run_signed_receipt_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
    *,
    artifact_name: str,
    output_name: str,
    schema_version: str,
    receipt_id: str,
    receipt_kind: str,
    verifier_name: str,
    source_boundary: str,
) -> JsonObject:
    request = stable_json_object(cast(Mapping[str, Any], fixture["request"]))
    proposed_action = stable_json_object(cast(Mapping[str, Any], request["proposed_action"]))
    previous_hash = "sha256:" + ("0" * 64)
    unsigned_receipt: JsonObject = {
        "schema_version": schema_version,
        "receipt_id": receipt_id,
        "receipt_kind": receipt_kind,
        "phase": "pre_execution",
        "issued_at": FIXED_GENERATED_AT,
        "subject": proposed_action["agent_id"],
        "operation": f"mcp:{proposed_action['server']}/{proposed_action['tool']}",
        "decision": "ALLOW",
        "request_hash": canonical_hash_sha256(request),
        "action_hash": canonical_hash_sha256(proposed_action),
        "previous_receipt_hash": previous_hash,
        "policy_hash": canonical_hash_sha256({"policy": "fixture allow read-only ServiceNow"}),
    }
    payload_hash = canonical_hash_sha256(unsigned_receipt)
    signature_record = sign_payload_hash(
        payload_hash,
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        signer=load_demo_ed25519_signer(),
        signed_at=FIXED_GENERATED_AT,
    )
    receipt = {
        **unsigned_receipt,
        "payload_hash": payload_hash,
        "signature": signature_record,
    }
    chain_hash = _receipt_chain_hash(previous_hash, payload_hash)
    public_key = DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
    public_ok = verify_signature_record(
        signature_record,
        payload_hash,
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        public_key=public_key,
    )
    tampered = dict(unsigned_receipt)
    tampered["decision"] = "DENY"
    tamper_detected = not verify_signature_record(
        signature_record,
        canonical_hash_sha256(tampered),
        purpose=COMPARISON_PURPOSE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        public_key=public_key,
    )
    runs = [
        {
            "decision": receipt["decision"],
            "payload_hash": payload_hash,
            "chain_hash": chain_hash,
        }
        for _ in range(repeat_count)
    ]
    deterministic = len({json.dumps(run, sort_keys=True) for run in runs}) == 1
    run_successes = [True] * repeat_count
    required_binding_fields = cast(Sequence[str], fixture["required_binding_pointers"])
    binding_presence = {pointer: False for pointer in required_binding_fields}
    artifact: JsonObject = {
        "artifact": artifact_name,
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "system": profile["system"],
        "profile": dict(profile),
        "source_boundary": source_boundary,
        "request": request,
        "receipt": receipt,
        "chain": {
            "previous_receipt_hash": previous_hash,
            "payload_hash": payload_hash,
            "chain_hash": chain_hash,
            "recomputed_chain_hash": _receipt_chain_hash(previous_hash, payload_hash),
        },
        "offline_verification": {
            "verifier": verifier_name,
            "public_key_path": _display_path(DEMO_ED25519_PUBLIC_KEY_PATH),
            "signature_passed": public_ok,
            "chain_hash_passed": chain_hash == _receipt_chain_hash(previous_hash, payload_hash),
        },
        "tamper_check": {"field_mutated": "/decision", "passed": tamper_detected},
        "deterministic_runs": runs,
        "pass_k_reliability": pass_k_curve(run_successes),
        "binding_depth": {
            "required_pointers": list(required_binding_fields),
            "present": binding_presence,
            "passed": False,
            "reason": (
                "Fixture signs request/action/policy hashes but does not bind the full "
                "Velvet-required policy, raw-action, budget, ledger, and schema field set."
            ),
        },
        "drift_rejection": {
            "passed": False,
            "reason": (
                "Fixture records a signed receipt but does not include a Velvet-style "
                "Execution Permit claim gate for mutated action dispatch."
            ),
        },
    }
    path = evidence_dir / output_name
    _write_json(path, artifact)
    verification_passed = public_ok and tamper_detected and artifact["chain"][
        "chain_hash"
    ] == artifact["chain"]["recomputed_chain_hash"]
    return _row(
        profile,
        evidence_path=path,
        capabilities={
            "pre_execution_decision": _capability(
                receipt["phase"] == "pre_execution",
                path,
                "Fixture receipt records the allow decision before simulated dispatch.",
            ),
            "deterministic_decision": _capability(
                deterministic and repeat_count >= DEFAULT_REPEAT_COUNT,
                path,
                f"Identical receipt decision across N={repeat_count} fixture runs.",
            ),
            "signed_artifact": _capability(
                public_ok,
                path,
                "Fixture receipt has a structured Ed25519 signature block.",
            ),
            "public_verification": _capability(
                public_ok,
                path,
                "Fixture receipt signature verifies with public key material only.",
            ),
            "tamper_evidence": _capability(
                tamper_detected,
                path,
                "Changing one signed receipt field failed signature verification.",
            ),
            "replayable_artifact": _capability(
                verification_passed,
                path,
                "Offline verification recomputed the same receipt hash and chain link.",
            ),
            "binding_depth": _capability(
                False,
                path,
                (
                    "Fixture does not demonstrate the full Velvet action, policy, "
                    "arguments, tool schema, budget, ledger, and raw-action binding set."
                ),
            ),
            "drift_rejection": _capability(
                False,
                path,
                (
                    "Fixture has no permit-bound execution claim step to reject a mutated "
                    "action before handler execution."
                ),
            ),
        },
        extra={
            "pass_k_reliability": pass_k_curve(run_successes),
            "fixture_boundary": source_boundary,
        },
    )


def _run_cerbos_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    request = stable_json_object(cast(Mapping[str, Any], fixture["request"]))
    cerbos_request = {
        "principal": {
            "id": "platform-lead@example.com",
            "roles": ["release_manager"],
            "attr": {"tenant": "tenant-a", "environment": "production"},
        },
        "resource": {
            "kind": "mcp_tool",
            "id": "servicenow/search_change_requests",
            "attr": {"risk": "read_only"},
        },
        "actions": ["call"],
    }
    response = {
        "resource": cerbos_request["resource"],
        "actions": {"call": "EFFECT_ALLOW"},
    }
    runs = [_cerbos_normalized_response(response) for _ in range(repeat_count)]
    deterministic = len({json.dumps(run, sort_keys=True) for run in runs}) == 1
    artifact: JsonObject = {
        "artifact": "cerbos_pdp_fixture_evidence",
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "system": profile["system"],
        "profile": dict(profile),
        "request": request,
        "cerbos_fixture_request": cerbos_request,
        "cerbos_fixture_response": response,
        "deterministic_runs": runs,
        "drift_rejection": {
            "passed": False,
            "reason": (
                "Fixture returns an authorization decision but no action-hash-bound "
                "Execution Permit claim."
            ),
        },
    }
    path = evidence_dir / "cerbos_pdp_fixture_evidence.json"
    _write_json(path, artifact)
    return _row(
        profile,
        evidence_path=path,
        capabilities={
            "pre_execution_decision": _capability(
                True,
                path,
                "Fixture evaluates a PDP-style allow/deny decision before simulated dispatch.",
            ),
            "deterministic_decision": _capability(
                deterministic and repeat_count >= DEFAULT_REPEAT_COUNT,
                path,
                f"Identical PDP fixture response across N={repeat_count} runs.",
            ),
            "signed_artifact": _capability(
                False,
                path,
                "Fixture response is not a signed decision artifact.",
            ),
            "public_verification": _capability(
                False,
                path,
                "Fixture response has no public-key verification material.",
            ),
            "tamper_evidence": _capability(
                False,
                path,
                "Fixture response has no signature or hash-chain check bound to the decision.",
            ),
            "replayable_artifact": _capability(
                False,
                path,
                "Fixture response has no replay command or stable seal reproduction contract.",
            ),
            "binding_depth": _capability(
                False,
                path,
                (
                    "Fixture response does not bind the required action, policy, "
                    "budget, ledger, and raw-action fields."
                ),
            ),
            "drift_rejection": _capability(
                False,
                path,
                "Fixture has no permit-bound execution claim step to reject a mutated action.",
            ),
        },
    )


def _run_gateway_fixture(
    fixture: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_dir: Path,
    repeat_count: int,
) -> JsonObject:
    request = stable_json_object(cast(Mapping[str, Any], fixture["request"]))
    proposed = cast(Mapping[str, Any], request["proposed_action"])
    allowlist = {
        ("mcp", "servicenow", "search_change_requests"),
    }
    decision = {
        "decision": "allow"
        if (
            str(proposed.get("surface")),
            str(proposed.get("server")),
            str(proposed.get("tool")),
        )
        in allowlist
        else "deny",
        "rule": "static allowlist",
    }
    runs = [dict(decision) for _ in range(repeat_count)]
    deterministic = len({json.dumps(run, sort_keys=True) for run in runs}) == 1
    artifact: JsonObject = {
        "artifact": "gateway_allowlist_baseline_fixture_evidence",
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": FIXED_GENERATED_AT,
        "system": profile["system"],
        "profile": dict(profile),
        "request": request,
        "allowlist": sorted("/".join(item) for item in allowlist),
        "decision": decision,
        "deterministic_runs": runs,
        "drift_rejection": {
            "passed": False,
            "reason": "Static allowlist decision is not claimed against a canonical action hash.",
        },
    }
    path = evidence_dir / "gateway_allowlist_baseline_fixture_evidence.json"
    _write_json(path, artifact)
    return _row(
        profile,
        evidence_path=path,
        capabilities={
            "pre_execution_decision": _capability(
                True,
                path,
                "Static allowlist decision was computed before simulated dispatch.",
            ),
            "deterministic_decision": _capability(
                deterministic and repeat_count >= DEFAULT_REPEAT_COUNT,
                path,
                f"Identical allowlist fixture response across N={repeat_count} runs.",
            ),
            "signed_artifact": _capability(
                False,
                path,
                "Fixture response is not a signed decision artifact.",
            ),
            "public_verification": _capability(
                False,
                path,
                "Fixture response has no public-key verification material.",
            ),
            "tamper_evidence": _capability(
                False,
                path,
                "Fixture response has no signature or hash-chain check bound to the decision.",
            ),
            "replayable_artifact": _capability(
                False,
                path,
                "Fixture response has no replay command or stable seal reproduction contract.",
            ),
            "binding_depth": _capability(
                False,
                path,
                (
                    "Fixture response does not bind the required action, policy, "
                    "budget, ledger, and raw-action fields."
                ),
            ),
            "drift_rejection": _capability(
                False,
                path,
                "Fixture has no permit-bound execution claim step to reject a mutated action.",
            ),
        },
    )


def _velvet_normalized_run(request: Mapping[str, Any]) -> JsonObject:
    proposed_action = stable_json_object(cast(Mapping[str, Any], request["proposed_action"]))
    canonical_action = _velvet_canonical_action(proposed_action)
    seal_id = "env_" + _sha256_hex(
        {
            "request_hash": canonical_hash_sha256(request),
            "canonical_action_hash": canonical_action["canonical_action_hash"],
            "purpose": COMPARISON_PURPOSE,
        }
    )[:32]
    return {
        "decision": "execute",
        "canonical_action_hash": canonical_action["canonical_action_hash"],
        "seal_id": seal_id,
    }


def _velvet_canonical_action(proposed_action: Mapping[str, Any]) -> JsonObject:
    operation = str(proposed_action.get("operation") or "call_tool")
    surface = str(proposed_action.get("surface") or "mcp")
    server = str(proposed_action.get("server") or "unknown")
    tool = str(proposed_action.get("tool") or "unknown")
    arguments = stable_json_object(cast(Mapping[str, Any], proposed_action.get("arguments", {})))
    read_set = {
        "surface": surface,
        "server": server,
        "tool": tool,
        "tenant_id": str(proposed_action.get("tenant_id") or ""),
        "environment": str(proposed_action.get("environment") or ""),
    }
    payload = {
        "schema_version": "velvet.canonical_action.v1",
        "operation": operation,
        "surface": surface,
        "server": server,
        "tool": tool,
        "arguments_hash": canonical_hash_sha256(arguments),
        "read_set_hash": canonical_hash_sha256(read_set),
        "actor_id": str(proposed_action.get("actor_id") or ""),
        "agent_id": str(proposed_action.get("agent_id") or ""),
        "tenant_id": str(proposed_action.get("tenant_id") or ""),
        "environment": str(proposed_action.get("environment") or ""),
    }
    payload["canonical_action_hash"] = canonical_hash_sha256(payload)
    return payload


def _velvet_admission_evidence(
    *,
    request: Mapping[str, Any],
    proposed_action: Mapping[str, Any],
    canonical_action: Mapping[str, Any],
    raw_ref: Mapping[str, Any],
    ledger_path: Path,
    seal_id: str,
) -> JsonObject:
    arguments = stable_json_object(cast(Mapping[str, Any], proposed_action.get("arguments", {})))
    request_hash = canonical_hash_sha256(request)
    tool_schema = {
        "surface": proposed_action.get("surface"),
        "server": proposed_action.get("server"),
        "tool": proposed_action.get("tool"),
        "arguments_shape": sorted(str(key) for key in arguments),
    }
    policy = {
        "policy": "fixture allow read-only ServiceNow",
        "operation": proposed_action.get("operation"),
        "tool": proposed_action.get("tool"),
    }
    previous_record_hash = "sha256:" + ("0" * 64)
    tenant_id = str(proposed_action.get("tenant_id") or "tenant-a")
    environment = str(proposed_action.get("environment") or "production")
    return {
        "schema_version": "velvet.admission_evidence.v1",
        "canonicalization": VELVET_CANONICAL_JSON_V1_UNSIGNED_PAYLOAD,
        "evidence_id": "ae_" + _sha256_hex({"request_hash": request_hash, "seal_id": seal_id})[:32],
        "issued_at": FIXED_COMPARISON_RUNTIME_AT,
        "tenant_id": LOCAL_DEMO_TENANT_ID,
        "environment": environment,
        "product_surface": "velvet_inline_gateway",
        "boundary": "pre_execution_authorization",
        "request_id": str(request.get("request_id") or request.get("stable_request_id") or ""),
        "seal_id": seal_id,
        "thread_id": str(request.get("replay_id") or "agent_auth_comparison"),
        "raw_action": {
            "raw_action_hash": raw_ref["sha256"],
            "raw_action_ref": dict(raw_ref),
            "redacted_action_hash": raw_ref["sha256"],
            "redacted_action": stable_json_object(request),
        },
        "tool": {
            "tool_key": f"{proposed_action.get('server')}/{proposed_action.get('tool')}",
            "tool_name": f"{proposed_action.get('server')}/{proposed_action.get('tool')}",
            "mcp_server": str(proposed_action.get("server") or ""),
            "mcp_tool": str(proposed_action.get("tool") or ""),
            "tool_schema_hash": canonical_hash_sha256(tool_schema),
            "arguments_hash": canonical_action["arguments_hash"],
        },
        "policy": {
            "policy_hash": canonical_hash_sha256(policy),
            "policy_version": "velvet.policy.v1",
            "policy_statuses": ["ADMITTED"],
            "policy_reasons": ["RESERVE_FITS_BUDGET", "RESERVE_ONLY_COMPATIBILITY_MODE"],
        },
        "decision": {
            "decision": "execute",
            "reason": "RESERVE_FITS_BUDGET, RESERVE_ONLY_COMPATIBILITY_MODE",
            "action_type": "mcp_alter",
            "approval_required": False,
            "approval_status": "not_required",
            "approval_request_id": None,
            "approval_request_hash": None,
            "approval_receipt_id": None,
            "upstream_execution_status": "forward_authorized",
            "obligations": [],
        },
        "risk": {
            "risk_class": "ALTER",
            "pricing_status": "priced",
            "entry_price": "150.0000",
            "clearance_score": "1.0000",
            "risk_penalty": "150.0000",
            "scarcity_pressure": "0.0000",
        },
        "authority": {
            "mode": "authority_ledger",
            "authority_budget_before": 750,
            "authority_budget_after": 600,
            "authority_ledger_sequence": 1,
            "budget_state_hash": None,
            "budget_certificate_hash": None,
            "pricing": {
                "entry_price": "150.0000",
                "clearance_score": "1.0000",
                "risk_penalty": "150.0000",
                "scarcity_pressure": "0.0000",
            },
        },
        "identity": {
            "tenant_id": tenant_id,
            "environment": environment,
            "agent_id": str(proposed_action.get("agent_id") or ""),
            "actor_user_id": str(proposed_action.get("actor_id") or ""),
            "subject_id": None,
            "session_id": None,
            "delegation": {},
        },
        "ledger_state": {
            "ledger_path": str(ledger_path),
            "sequence_number": 1,
            "previous_record_hash": previous_record_hash,
            "previous_frame_hash": None,
        },
        "bindings": {
            "warrant_hash": canonical_hash_sha256(policy),
            "selected_warrant_hash": canonical_hash_sha256(
                {"policy": policy, "canonical_action": canonical_action}
            ),
            "request_hash": request_hash,
        },
    }


def verify_admission_evidence(
    evidence: Mapping[str, Any],
    *,
    public_key: str | bytes | object,
) -> bool:
    signature = evidence.get("signature")
    if not isinstance(signature, Mapping):
        return False
    expected_hash = evidence.get("admission_evidence_hash")
    if not isinstance(expected_hash, str):
        return False
    unsigned = {
        str(key): value
        for key, value in evidence.items()
        if key not in {"admission_evidence_hash", "signature"}
    }
    if not hmac.compare_digest(expected_hash, canonical_hash_sha256(unsigned)):
        return False
    return verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_ADMISSION_EVIDENCE,
        tenant_id=LOCAL_DEMO_TENANT_ID,
        key_id=DEMO_ED25519_KEY_ID,
        public_key=public_key,
    )


def _write_raw_action_ref(raw_action: Mapping[str, Any], output_dir: str | Path) -> JsonObject:
    data = canonical_dumps(stable_json_object(raw_action)).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"raw_{digest[:32]}"
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f"{artifact_id}.json"
    path.write_bytes(data)
    return {
        "artifact_id": artifact_id,
        "uri": _repo_uri(path),
        "sha256": f"sha256:{digest}",
        "size_bytes": len(data),
        "content_type": "application/json",
    }


def _write_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(_relativize_repo_paths(record), sort_keys=True) for record in records]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sha256_hex(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_dumps(stable_json_object(value)).encode("utf-8")).hexdigest()


def _repo_uri(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_uri()
    return f"repo://{relative}"


def _cerbos_normalized_response(response: Mapping[str, Any]) -> JsonObject:
    actions = response.get("actions")
    return {
        "actions": dict(cast(Mapping[str, Any], actions))
        if isinstance(actions, Mapping)
        else {}
    }


def _row(
    profile: Mapping[str, Any],
    *,
    evidence_path: Path,
    capabilities: Mapping[str, Mapping[str, Any]],
    extra: Mapping[str, Any] | None = None,
) -> JsonObject:
    missing = set(COMPARISON_CAPABILITY_KEYS) - set(capabilities)
    if missing:
        raise ValueError(f"missing comparison capabilities: {sorted(missing)}")
    row: JsonObject = {
        "system": str(profile["system"]),
        "system_version": str(profile.get("system_version", "fixture")),
        "adapter_kind": str(profile["adapter_kind"]),
        "measurement_boundary": str(profile["measurement_boundary"]),
        "public_claim_status": str(profile["public_claim_status"]),
        "evidence_path": str(evidence_path),
        "source_urls": list(cast(Sequence[str], profile.get("source_urls", []))),
        "capabilities": {key: dict(capabilities[key]) for key in COMPARISON_CAPABILITY_KEYS},
    }
    if extra:
        row.update(dict(extra))
    return row


def _capability(value: bool, evidence_path: Path, measurement: str) -> JsonObject:
    return {
        "status": "pass" if value else "fail",
        "value": value,
        "evidence_pointer": str(evidence_path),
        "measurement": measurement,
    }


def _binding_presence(
    payload: Mapping[str, Any],
    pointers: Sequence[str],
) -> dict[str, bool]:
    return {pointer: _json_pointer(payload, pointer) not in (None, "") for pointer in pointers}


def _json_pointer(payload: Mapping[str, Any], pointer: str) -> object:
    current: object = payload
    if pointer in {"", "/"}:
        return current
    for raw_part in pointer.strip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _schema_errors(schema_path: Path, payload: Mapping[str, Any]) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    required = cast(Sequence[str], schema.get("required", []))
    errors = [
        f"<root>: {field!r} is a required property"
        for field in required
        if field not in payload
    ]
    properties = cast(Mapping[str, Any], schema.get("properties", {}))
    for field, field_schema in properties.items():
        if field not in payload or not isinstance(field_schema, Mapping):
            continue
        expected_type = field_schema.get("type")
        value = payload[field]
        if expected_type == "string" and not isinstance(value, str):
            errors.append(f"{field}: {value!r} is not of type 'string'")
        if expected_type == "boolean" and not isinstance(value, bool):
            errors.append(f"{field}: {value!r} is not of type 'boolean'")
        if expected_type == "array" and not isinstance(value, list):
            errors.append(f"{field}: {value!r} is not of type 'array'")
    return errors


def _load_fixture(path: Path) -> JsonObject:
    payload = _read_json_object(path)
    if payload.get("schema_version") != COMPARISON_FIXTURE_SCHEMA_VERSION:
        raise ValueError(f"{path} has unsupported schema_version")
    return payload


def _load_profiles(path: Path) -> dict[str, JsonObject]:
    payload = _read_json_object(path)
    if payload.get("schema_version") != COMPARISON_FIXTURE_SCHEMA_VERSION:
        raise ValueError(f"{path} has unsupported schema_version")
    profiles = payload.get("systems")
    if not isinstance(profiles, list):
        raise ValueError(f"{path} requires systems list")
    indexed = {}
    for item in profiles:
        if not isinstance(item, Mapping):
            raise ValueError(f"{path} systems entries must be objects")
        indexed[str(item["adapter_id"])] = dict(item)
    return indexed


def _read_json_object(path: Path) -> JsonObject:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return cast(JsonObject, payload)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_relativize_repo_paths(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _receipt_chain_hash(previous_hash: str, payload_hash: str) -> str:
    return "sha256:" + canonical_hash_sha256(
        {"previous_receipt_hash": previous_hash, "payload_hash": payload_hash}
    )


def _relativize_repo_paths(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _relativize_repo_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_relativize_repo_paths(item) for item in value]
    if isinstance(value, str):
        root_uri = ROOT_DIR.resolve().as_uri() + "/"
        root_path = str(ROOT_DIR.resolve()) + "/"
        if value.startswith(root_uri):
            return "repo://" + value[len(root_uri) :]
        if value.startswith(root_path):
            return value[len(root_path) :]
    return value


def _relativize_jsonl_file(path: Path) -> None:
    if not path.exists():
        return
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        lines.append(json.dumps(_relativize_repo_paths(payload), sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_system_result_files(
    results_dir: Path,
    rows: Sequence[Mapping[str, Any]],
    payload: Mapping[str, Any],
) -> JsonObject:
    paths: JsonObject = {}
    for row in rows:
        path = results_dir / f"{COMPARISON_RESULTS_NAME}--{_slug(str(row['system']))}.json"
        record = {
            "schema_version": COMPARISON_SCHEMA_VERSION,
            "benchmark_version": BENCHMARK_VERSION,
            "generated_at": payload["generated_at"],
            "commit_hash": payload["commit_hash"],
            "repeat_count": payload["repeat_count"],
            "system_result": row,
        }
        _write_json(path, record)
        paths[str(row["system"])] = str(path)
    return paths


def _fixture_hashes(fixture_dir: Path) -> JsonObject:
    return {
        path.name: _file_sha256(path)
        for path in sorted(fixture_dir.glob("*.json"))
        if path.is_file()
    }


def _source_lockfile_hashes() -> JsonObject:
    hashes: JsonObject = {}
    for relpath in ("uv.lock", "Cargo.lock", "rust-toolchain.toml", "pyproject.toml"):
        path = ROOT_DIR / relpath
        hashes[relpath] = _file_sha256(path) if path.exists() else "missing"
    return {
        "note": (
            "hashes of lockfiles in the private source monorepo at commit_hash; "
            "not shipped in this repo"
        ),
        "hashes": hashes,
    }


def _oap_spec_lock_summary() -> JsonObject:
    if not OAP_SPEC_LOCK_PATH.exists():
        return {"path": str(OAP_SPEC_LOCK_PATH), "status": "missing"}
    payload = _read_json_object(OAP_SPEC_LOCK_PATH)
    return {
        "path": _display_path(OAP_SPEC_LOCK_PATH),
        "sha256": _file_sha256(OAP_SPEC_LOCK_PATH),
        "repo": payload.get("repo"),
        "commit": payload.get("commit"),
    }


def _oap_decision_schema_path() -> Path:
    lock = _read_json_object(OAP_SPEC_LOCK_PATH)
    commit = str(lock["commit"])
    return ROOT_DIR / "third_party" / "oap" / commit / "oap" / "decision-schema.json"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _methodology(repeat_count: int) -> JsonObject:
    return {
        "question": (
            "For one fixed proposed MCP tool action, what artifact properties can each "
            "local fixture demonstrate before execution?"
        ),
        "repeat_count": repeat_count,
        "fixture_scope": (
            "Velvet uses the real InlineGateway path. OAP/APort, Pipelock, Attested "
            "Intelligence, Cerbos, and gateway rows are local contract fixtures, not "
            "live service evaluations."
        ),
        "result_rule": (
            "A positive result requires the fixture artifact itself to contain or verify the "
            "measured property. General product documentation is recorded as source context "
            "but is not used to mark an unmeasured capability as satisfied."
        ),
    }


def _limitations() -> list[str]:
    return [
        "Non-Velvet rows are local fixtures and must not be described as live product failures.",
        (
            "The OAP/APort row uses the pinned vendored OAP schema snapshot, not "
            "the hosted APort service."
        ),
        "The Cerbos row is a PDP-style fixture, not a running Cerbos PDP instance.",
        (
            "The gateway baseline is a static allowlist fixture, not Kong, Cloudflare, "
            "or another vendor gateway."
        ),
        "The Velvet row uses the committed demo Ed25519 key and local InlineGateway path.",
        (
            "The fixture action is one MCP-style tool call; it does not prove coverage "
            "for every runtime action."
        ),
    ]


def _capability_definition(key: str) -> str:
    definitions = {
        "pre_execution_decision": "the fixture computes allow/block/escalate before dispatch",
        "deterministic_decision": (
            f"the normalized decision is identical across N>={DEFAULT_REPEAT_COUNT} runs"
        ),
        "signed_artifact": "the fixture emits a structured signed decision or evidence artifact",
        "public_verification": "the artifact verifies with public material only",
        "tamper_evidence": "a single-field mutation is detected by signature or hash verification",
        "replayable_artifact": (
            "the stored artifact can reproduce the same decision and stable seal/hash"
        ),
        "binding_depth": (
            "the artifact binds the required action, policy, arguments, tool-schema, "
            "budget, and ledger fields"
        ),
        "drift_rejection": "execution is refused when the admitted action mutates before dispatch",
    }
    return definitions[key]


def _status_cell(capability: Mapping[str, Any]) -> str:
    status = str(capability["status"])
    if status == "pass":
        return "yes"
    if status == "fail":
        return "no"
    return "not measured"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "system"


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def _git_commit() -> str:
    return _run_git(["rev-parse", "HEAD"])


def _git_dirty() -> bool:
    return bool(_run_git(["status", "--short"]))


def _enforce_clean_worktree(*, allow_dirty: bool) -> None:
    if not _git_dirty():
        return
    message = (
        "refusing to write Agent Authorization Benchmark comparison release artifacts from a "
        "dirty worktree; commit or stash changes, or pass --allow-dirty for dev output"
    )
    if not allow_dirty:
        raise SystemExit(message)
    print(f"WARNING: {message}; output will record worktree_dirty=true", file=sys.stderr)


def _resolve_generation_git_state(
    *,
    allow_dirty: bool,
    source_commit_hash: str | None,
    source_worktree_dirty: bool | None,
) -> tuple[str, bool]:
    if source_commit_hash is None and source_worktree_dirty is None:
        _enforce_clean_worktree(allow_dirty=allow_dirty)
        return _git_commit(), _git_dirty()
    if source_commit_hash is None or source_worktree_dirty is None:
        raise ValueError("source_commit_hash and source_worktree_dirty must be provided together")
    if source_worktree_dirty and not allow_dirty:
        raise SystemExit(
            "refusing to write Agent Authorization Benchmark comparison release artifacts from a "
            "dirty worktree; commit or stash changes, or pass --allow-dirty for dev output"
        )
    return source_commit_hash, source_worktree_dirty


def _run_git(args: Sequence[str]) -> str:
    git = shutil.which("git")
    if git is None:
        return "unknown"
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [git, *args],
            cwd=ROOT_DIR,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return completed.stdout.strip()
