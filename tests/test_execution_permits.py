from __future__ import annotations

import importlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from velvet.cli import main
from velvet.contracts import AdmissionContract
from velvet.execution import (
    ExecutionPermitError,
    ExecutionPermitScope,
    PermitClaimStore,
    PermitValidationContext,
    ResourceScope,
    VelvetExecutor,
    build_pre_execution_record,
    prepare_execution,
    strip_model_controlled_execution_metadata,
    verification_status,
    verify_execution_permit,
)
from velvet.executor import VelvetAdmissionLayer
from velvet.serialization import canonical_hash_sha256
from velvet.signing import (
    DEMO_ED25519_KEY_ID,
    DEMO_ED25519_PUBLIC_KEY_PATH,
    load_demo_ed25519_signer,
)

ROOT = Path(__file__).resolve().parents[1]


def _admitted() -> tuple[AdmissionContract, Any]:
    contract = AdmissionContract(default_authority_budget=10_000)
    outcome = VelvetAdmissionLayer(contract).evaluate(
        {
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:permit",
        },
        logical_step=1,
    )
    return contract, outcome


def _prepare(claim_store: PermitClaimStore | None = None) -> tuple[Any, PermitClaimStore, Any]:
    contract, outcome = _admitted()
    signer = load_demo_ed25519_signer()
    store = claim_store or PermitClaimStore()
    record = build_pre_execution_record(outcome, request={"call": "refund"})
    prepared = prepare_execution(
        outcome,
        actual_request={"call": "refund"},
        pre_execution_record=record,
        contract=contract,
        signer=signer,
        signing_key_id=DEMO_ED25519_KEY_ID,
        logical_step=1,
        claim_store=store,
    )
    return prepared, store, signer


def _context(prepared: Any, signer: Any) -> PermitValidationContext:
    permit = prepared.permit
    return PermitValidationContext(
        tenant_id=permit.tenant_id,
        environment=permit.environment,
        audience=permit.audience,
        policy_hash=permit.policy.policy_hash,
        policy_version=permit.policy.policy_version,
        tool_schema_hash=permit.scope.tool_schema_hash,
        scope=permit.scope,
        now=permit.validity.not_before,
        logical_step=1,
        trusted_signer=signer,
        trusted_key_id=DEMO_ED25519_KEY_ID,
    )


def test_admitted_action_produces_claimable_execution_permit() -> None:
    prepared, store, signer = _prepare()
    checks = verify_execution_permit(prepared.permit, _context(prepared, signer))
    assert verification_status(checks) == "pass"

    executor = VelvetExecutor(
        claim_store=store,
        signer=signer,
        signing_key_id=DEMO_ED25519_KEY_ID,
    )
    authorized = executor.authorize(prepared, context=_context(prepared, signer))
    receipt = executor.execute(authorized)

    assert receipt.outcome == "succeeded"
    assert store.state(prepared.permit.permit_id, prepared.permit.permit_hash) == "succeeded"


def test_execution_permit_and_receipt_match_strict_schemas() -> None:
    prepared, store, signer = _prepare()
    executor = VelvetExecutor(claim_store=store, signer=signer, signing_key_id=DEMO_ED25519_KEY_ID)
    authorized = executor.authorize(prepared, context=_context(prepared, signer))
    receipt = executor.execute(authorized)

    permit_schema = json.loads(
        (ROOT / "schemas/velvet_rope/execution_permit.schema.json").read_text(encoding="utf-8")
    )
    receipt_schema = json.loads(
        (ROOT / "schemas/velvet_rope/execution_receipt.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(permit_schema).validate(prepared.permit.to_dict())
    Draft202012Validator(receipt_schema).validate(receipt.to_dict())


def test_verify_permit_cli_uses_external_trust_anchor(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepared, store, signer = _prepare()
    executor = VelvetExecutor(claim_store=store, signer=signer, signing_key_id=DEMO_ED25519_KEY_ID)
    receipt = executor.execute(executor.authorize(prepared, context=_context(prepared, signer)))

    permit_path = tmp_path / "permit.json"
    receipt_path = tmp_path / "receipt.json"
    request_path = tmp_path / "request.json"
    permit_path.write_text(json.dumps(prepared.permit.to_dict(), sort_keys=True), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt.to_dict(), sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps({"call": "refund"}, sort_keys=True), encoding="utf-8")

    assert (
        main(
            [
                "verify-permit",
                "--file",
                str(permit_path),
                "--trusted-public-key-file",
                str(DEMO_ED25519_PUBLIC_KEY_PATH),
                "--actual-request-file",
                str(request_path),
                "--receipt-file",
                str(receipt_path),
                "--verification-time",
                prepared.permit.validity.not_before,
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "pass"

    assert main(["verify-permit", "--file", str(permit_path), "--json"]) == 1
    missing_key_report = json.loads(capsys.readouterr().out)
    assert missing_key_report["checks"][0]["code"] == "trusted_public_key_required"


def test_blocked_action_cannot_produce_execution_permit() -> None:
    contract = AdmissionContract(default_authority_budget=1)
    outcome = VelvetAdmissionLayer(contract).evaluate(
        {
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:block",
        },
        logical_step=1,
    )
    with pytest.raises(ExecutionPermitError, match="not executable"):
        prepare_execution(
            outcome,
            actual_request={"call": "refund"},
            pre_execution_record=build_pre_execution_record(outcome, request={"call": "refund"}),
            contract=contract,
            signer=load_demo_ed25519_signer(),
            signing_key_id=DEMO_ED25519_KEY_ID,
        )


def test_permit_rejects_scope_drift() -> None:
    prepared, store, signer = _prepare()
    drifted = replace(
        prepared,
        actual_request={"call": "refund", "amount": "changed"},
    )
    executor = VelvetExecutor(claim_store=store, signer=signer, signing_key_id=DEMO_ED25519_KEY_ID)
    authorized = executor.authorize(prepared, context=_context(prepared, signer))
    drifted_authorized = replace(authorized, prepared=drifted)
    receipt = executor.execute(drifted_authorized)
    assert receipt.outcome == "failed_before_dispatch"
    assert receipt.error is not None
    assert receipt.error.code == "scope_mismatch"


def test_model_supplied_execution_metadata_is_not_authority_scope() -> None:
    contract, outcome = _admitted()
    signer = load_demo_ed25519_signer()
    store = PermitClaimStore()
    request = {
        "call": "refund",
        "params": {
            "_meta": {
                "user_request": "refund customer",
                "velvet_execution": {
                    "execution_permit": {
                        "permit_id": "attacker-supplied-permit",
                    },
                },
                "velvet_admission": {"forward": True},
            },
        },
    }
    sanitized = strip_model_controlled_execution_metadata(request)
    record = build_pre_execution_record(outcome, request=request)
    prepared = prepare_execution(
        outcome,
        actual_request=request,
        pre_execution_record=record,
        contract=contract,
        signer=signer,
        signing_key_id=DEMO_ED25519_KEY_ID,
        logical_step=1,
        claim_store=store,
    )

    assert prepared.actual_request == sanitized
    assert prepared.permit.scope.request_hash == record["request_hash"]
    assert "velvet_execution" not in prepared.actual_request["params"]["_meta"]
    assert "velvet_admission" not in prepared.actual_request["params"]["_meta"]


def test_executor_rebuilds_request_fields_without_reinterpreting_issuer_scope() -> None:
    bound_scope = ExecutionPermitScope(
        surface="velvet_inline_gateway.mcp",
        method="tools/call",
        tool_key="velvet-live-target/delete_customer_records",
        operation="delete_customer_records",
        request_hash="sha256:" + "1" * 64,
        canonical_action_hash="sha256:" + "2" * 64,
        arguments_hash="sha256:" + "3" * 64,
        tool_schema_hash="sha256:" + "4" * 64,
        resource=ResourceScope(kind="customer", id_hash="5" * 64),
        subgoal_id_hash="6" * 64,
    )
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "delete_customer_records",
            "_meta": {
                "attack": "approval_replay",
                "velvet_execution": {"execution_permit": {"permit_id": "runtime"}},
            },
        },
    }

    rebuilt = ExecutionPermitScope.from_permit_request(
        bound_scope,
        actual_request=request,
        operation="delete_customer_records",
        canonical_action_hash="7" * 64,
        arguments_hash="8" * 64,
        tool_schema_hash="sha256:" + "9" * 64,
    )

    sanitized = strip_model_controlled_execution_metadata(request)
    assert rebuilt.request_hash == canonical_hash_sha256(sanitized)
    assert sanitized["params"]["_meta"] == {"attack": "approval_replay"}
    assert rebuilt.surface == bound_scope.surface
    assert rebuilt.method == bound_scope.method
    assert rebuilt.tool_key == bound_scope.tool_key
    assert rebuilt.operation == "delete_customer_records"
    assert rebuilt.read_set_hash == bound_scope.read_set_hash
    assert rebuilt.resource == bound_scope.resource
    assert rebuilt.subgoal_id_hash == bound_scope.subgoal_id_hash
    assert rebuilt.to_dict()["canonical_action_hash"] == "sha256:" + "7" * 64
    assert rebuilt.to_dict()["arguments_hash"] == "sha256:" + "8" * 64
    assert rebuilt.to_dict()["subgoal_id_hash"] == "sha256:" + "6" * 64


def test_second_use_fails_after_claim() -> None:
    prepared, store, signer = _prepare()
    executor = VelvetExecutor(claim_store=store, signer=signer, signing_key_id=DEMO_ED25519_KEY_ID)
    first = executor.authorize(prepared, context=_context(prepared, signer))
    assert first.claim.permit_id == prepared.permit.permit_id
    with pytest.raises(ExecutionPermitError, match="already claimed"):
        executor.authorize(prepared, context=_context(prepared, signer))


def test_many_threads_claim_permit_once() -> None:
    prepared, store, signer = _prepare()

    def claim_once(_index: int) -> bool:
        executor = VelvetExecutor(
            claim_store=store,
            signer=signer,
            signing_key_id=DEMO_ED25519_KEY_ID,
        )
        try:
            executor.authorize(prepared, context=_context(prepared, signer))
        except ExecutionPermitError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(claim_once, range(32)))

    assert results.count(True) == 1


def _sqlite_claim(path: str, permit_payload: dict[str, Any]) -> bool:
    from velvet.execution import ExecutionPermit, PermitClaimStore

    permit = ExecutionPermit.from_dict(permit_payload)
    store = PermitClaimStore(path)
    return store.claim(permit, claimant="process") is not None


def test_two_python_processes_sharing_sqlite_claim_once(tmp_path: Path) -> None:
    path = tmp_path / "permits.sqlite"
    store = PermitClaimStore(path)
    prepared, _store, _signer = _prepare(store)
    payload = prepared.permit.to_dict()
    ctx = get_context("spawn")
    with ctx.Pool(2) as pool:
        results = pool.starmap(_sqlite_claim, [(str(path), payload), (str(path), payload)])
    assert results.count(True) == 1


def test_clean_break_no_admission_token_api() -> None:
    velvet = importlib.import_module("velvet")
    signing = importlib.import_module("velvet.signing")
    outcome = VelvetAdmissionLayer(AdmissionContract(default_authority_budget=10_000)).evaluate(
        {
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:clean-break",
        },
        logical_step=1,
    )

    assert not hasattr(velvet, "AdmissionToken")
    assert not hasattr(signing, "PURPOSE_ADMISSION_TOKEN")
    assert not hasattr(AdmissionContract(), "token_ttl_steps")
    assert not hasattr(outcome, "token")
    assert not hasattr(VelvetExecutor(), "redeem")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("velvet.tokens")
