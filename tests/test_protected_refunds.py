from __future__ import annotations

import copy
import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from velvet.execution import PermitValidity
from velvet.refunds.contract import (
    VERSION,
    RefundCommand,
    RefundRejected,
    close_transition,
    initial_state,
    issue_permit,
    transition,
)
from velvet.refunds.demo import ReferenceLedger, reference_ledger
from velvet.refunds.evidence import seal_snapshot, verify_bundle
from velvet.refunds.postgres import RefundLedger
from velvet.serialization import canonical_hash_sha256
from velvet.signing import Ed25519SigningProvider


@pytest.fixture
def reference() -> Iterator[ReferenceLedger]:
    dsn = os.environ.get("VELVET_REFUNDS_TEST_DSN")
    if not dsn:
        pytest.skip("set VELVET_REFUNDS_TEST_DSN to a disposable PostgreSQL database")
    with reference_ledger(dsn) as value:
        yield value


def command(reference: ReferenceLedger, index: int = 1, amount: int = 1000) -> RefundCommand:
    return RefundCommand(
        f"operation-{index}", reference.config["ledger_id"], f"order-{index}", amount, 0, 0
    )


def submit(reference: ReferenceLedger, index: int, amount: int) -> str:
    request = command(reference, index, amount)
    permit = issue_permit(reference.config, request, reference.authority)
    try:
        reference.executor.refund(request, permit)
        return "committed"
    except RefundRejected:
        return "rejected"


def verify(reference: ReferenceLedger, bundle: dict[str, Any]) -> dict[str, Any]:
    material = reference.observer_signer.public_verification_material("reference-observer") or {}
    return verify_bundle(
        bundle,
        observer_public_key=material["public_key_pem"],
        observer_key_id="reference-observer",
        contract_hash=canonical_hash_sha256(reference.config),
    )


def seal(reference: ReferenceLedger) -> dict[str, Any]:
    return seal_snapshot(
        reference.observer.observe(), reference.observer_signer, key_id="reference-observer"
    )


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "100", 2**53])
def test_amount_requires_positive_integer(value: Any) -> None:
    with pytest.raises(RefundRejected):
        RefundCommand("op", "ledger", "order", value, 0, 0)


def test_bounded_state_space_preserves_arithmetic_invariants() -> None:
    config = {
        "version": VERSION,
        "ledger_id": "finite-model",
        "tenant_id": "test",
        "environment": "test",
        "audience": "test",
        "authority_key_id": "test",
        "authority_public_key": "not used by pure state transitions",
        "currency": "USD",
        "budget_cents": 3,
        "orders": {"a": 2, "b": 2},
    }
    pending = [initial_state(config)]
    seen: set[str] = set()
    while pending:
        state = pending.pop()
        key = json.dumps(state, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        assert 0 <= state["spent_cents"] <= 3
        assert (
            sum(order["refunded_cents"] for order in state["orders"].values())
            == state["spent_cents"]
        )
        assert all(0 <= order["refunded_cents"] <= 2 for order in state["orders"].values())
        if not state["closed"]:
            pending.append(close_transition(state))
        for order_id, order in state["orders"].items():
            for amount in (1, 2, 3):
                request = RefundCommand(
                    "next", "finite-model", order_id, amount, order["revision"], state["epoch"]
                )
                try:
                    after = transition(config, state, request)
                except RefundRejected:
                    continue
                assert not state["closed"]
                pending.append(after)
    assert len(seen) >= 20


def test_concurrent_refunds_share_one_budget(reference: ReferenceLedger) -> None:
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda index: submit(reference, index, 3000), range(1, 6)))
    assert results.count("committed") == 3
    assert results.count("rejected") == 2
    reference.executor.close()
    result = verify(reference, seal(reference))
    assert result["status"] == "COMPLETE"
    assert result["spent_cents"] == 9000
    assert result["committed_refunds"] == 3


def test_parallel_retries_and_new_process_handle_return_one_commit(
    reference: ReferenceLedger,
) -> None:
    request = command(reference)
    permit = issue_permit(reference.config, request, reference.authority)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: reference.executor.refund(request, permit), range(8)))
    assert sum(not result["replayed"] for result in results) == 1
    reference.executor.close()
    reopened = RefundLedger(reference.executor.dsn, reference.executor.schema)
    assert reopened.refund(request, permit)["replayed"] is True
    assert verify(reference, seal(reference))["committed_refunds"] == 1


def test_reused_operation_requires_same_request_and_permit(reference: ReferenceLedger) -> None:
    request = command(reference)
    permit = issue_permit(reference.config, request, reference.authority)
    reference.executor.refund(request, permit)
    for different in (replace(request, amount_cents=500), replace(request, order_id="order-2")):
        with pytest.raises(RefundRejected, match="identity"):
            reference.executor.refund(different, permit)
    with pytest.raises(RefundRejected, match="identity"):
        reference.executor.refund(
            request, issue_permit(reference.config, request, reference.authority)
        )
    assert len(reference.observer.observe()["operations"]) == 1


def test_exact_authorization_revision_and_ttl(reference: ReferenceLedger) -> None:
    request = command(reference)
    permit = issue_permit(reference.config, request, reference.authority)
    with pytest.raises(RefundRejected, match="permit"):
        reference.executor.refund(replace(request, amount_cents=2000), permit)
    reference.executor.refund(request, permit)
    stale = replace(request, operation_id="stale")
    with pytest.raises(RefundRejected, match="revision"):
        reference.executor.refund(stale, issue_permit(reference.config, stale, reference.authority))
    new = command(reference, 2)
    expired = issue_permit(reference.config, new, reference.authority)
    before = (datetime.now(UTC) - timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
    end = (datetime.now(UTC) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    expired = replace(expired, validity=PermitValidity(before, before, end), permit_hash="")
    expired = expired.with_hash_and_signature(
        signer=reference.authority, key_id="reference-authority"
    )
    with pytest.raises(RefundRejected, match="permit"):
        reference.executor.refund(new, expired)
    assert len(reference.observer.observe()["operations"]) == 1


def test_journal_failure_rolls_back_mutation_and_operation(
    reference: ReferenceLedger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = RefundLedger._append

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        original(*args, **kwargs)
        raise RuntimeError("simulated failure before transaction commit")

    with monkeypatch.context() as patch:
        patch.setattr(RefundLedger, "_append", staticmethod(interrupted))
        with pytest.raises(RuntimeError, match="simulated"):
            submit(reference, 1, 1000)
    snapshot = reference.observer.observe()
    assert snapshot["state"]["spent_cents"] == 0
    assert len(snapshot["records"]) == 1
    assert snapshot["operations"] == []
    assert submit(reference, 1, 1000) == "committed"


def test_closure_is_ordered_with_in_flight_refund(reference: ReferenceLedger) -> None:
    with ThreadPoolExecutor(max_workers=2) as pool:
        refund = pool.submit(submit, reference, 1, 1000)
        closure = pool.submit(reference.executor.close)
        assert refund.result() in {"committed", "rejected"}
        assert closure.result()["closed"] is True
    assert submit(reference, 2, 1000) == "rejected"
    bundle = seal(reference)
    assert bundle["snapshot"]["records"][-1]["event"]["kind"] == "close"
    assert verify(reference, bundle)["status"] == "COMPLETE"


def test_observer_and_agent_permissions(reference: ReferenceLedger) -> None:
    with pytest.raises(RefundRejected, match="write privileges"):
        reference.executor.observe()
    with psycopg.connect(reference.agent_dsn) as conn:
        row = conn.execute(
            "SELECT has_schema_privilege(current_user, %s, 'USAGE')", (reference.executor.schema,)
        ).fetchone()
        assert row == (False,)
    assert reference.observer.observe()["observation"]["observer"].endswith("_observer")


def test_open_interval_and_signing_failure_never_yield_complete(
    reference: ReferenceLedger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert submit(reference, 1, 1000) == "committed"
    assert verify(reference, seal(reference))["status"] == "OPEN_INTERVAL"
    reference.executor.close()

    def unavailable(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("observer key unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(reference.observer_signer, "sign", unavailable)
        with pytest.raises(RuntimeError, match="unavailable"):
            seal(reference)
    assert verify(reference, seal(reference))["status"] == "COMPLETE"


@pytest.mark.parametrize("field", ["records", "operations", "state", "head_hash"])
def test_missing_or_inconsistent_evidence_fails(reference: ReferenceLedger, field: str) -> None:
    assert submit(reference, 1, 1000) == "committed"
    reference.executor.close()
    bundle = seal(reference)
    broken = copy.deepcopy(bundle)
    if field in ("records", "operations"):
        broken["snapshot"][field].pop()
    elif field == "state":
        broken["snapshot"][field]["spent_cents"] = 0
    else:
        broken["snapshot"][field] = "sha256:" + "0" * 64
    assert verify(reference, broken)["status"] == "INVALID"
    # Even an observer with its own signing key cannot seal an inconsistent snapshot.
    with pytest.raises(RefundRejected):
        seal_snapshot(broken["snapshot"], reference.observer_signer, key_id="reference-observer")


def test_trust_inputs_must_be_pinned_outside_bundle(reference: ReferenceLedger) -> None:
    reference.executor.close()
    bundle = seal(reference)
    other = Ed25519SigningProvider(key_id="reference-observer")
    key = (other.public_verification_material("reference-observer") or {})["public_key_pem"]
    result = verify_bundle(
        bundle,
        observer_public_key=key,
        observer_key_id="reference-observer",
        contract_hash=canonical_hash_sha256(reference.config),
    )
    assert result["status"] == "INVALID"
    assert (
        verify_bundle(
            bundle,
            observer_public_key="",
            observer_key_id="reference-observer",
            contract_hash=canonical_hash_sha256(reference.config),
        )["status"]
        == "INVALID"
    )


@pytest.mark.parametrize("bundle", [{}, {"checkpoint": None}, {"snapshot": []}])
def test_malformed_evidence_has_explicit_invalid_verdict(bundle: dict[str, Any]) -> None:
    assert (
        verify_bundle(
            bundle,
            observer_public_key="missing",
            observer_key_id="missing",
            contract_hash="missing",
        )["status"]
        == "INVALID"
    )
