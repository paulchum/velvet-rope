"""Offline replay and externally pinned observer checkpoints for a finite ledger."""

from __future__ import annotations

from datetime import datetime

from velvet.execution import ExecutionPermit
from velvet.refunds.contract import (
    VERSION,
    RefundCommand,
    RefundRejected,
    close_transition,
    initial_state,
    transition,
    validate_permit,
)
from velvet.serialization import JsonObject, canonical_hash_sha256
from velvet.signing import SigningProvider, sign_payload_hash, verify_signature_record

PURPOSE = "velvet.protected_refunds.observer_checkpoint.v1"


def _reconcile(snapshot: JsonObject, contract_hash: str) -> JsonObject:
    config = snapshot["config"]
    if canonical_hash_sha256(config) != contract_hash:
        raise RefundRejected("contract does not match the independently pinned hash")
    state = initial_state(config)
    previous_hash = None
    previous_time: datetime | None = None
    operations: list[JsonObject] = []
    operation_ids: set[str] = set()
    permit_ids: set[str] = set()
    records = snapshot["records"]
    if not records or len(records) != snapshot["sequence"] + 1:
        raise RefundRejected("journal interval is incomplete")
    for sequence, record in enumerate(records):
        event = record["event"]
        digest = canonical_hash_sha256(event)
        if (
            event["sequence"] != sequence
            or record["sequence"] != sequence
            or record["event_hash"] != digest
            or event["previous_hash"] != previous_hash
            or event["contract_hash"] != contract_hash
        ):
            raise RefundRejected("journal sequence or hash differs")
        timestamp = datetime.fromisoformat(event["evaluated_at"])
        if timestamp.tzinfo is None or (previous_time is not None and timestamp < previous_time):
            raise RefundRejected("journal time is missing or moves backwards")
        if sequence == 0:
            if (
                event["kind"] != "open"
                or event["command"] is not None
                or event["permit"] is not None
            ):
                raise RefundRejected("invalid opening record")
        elif event["kind"] == "refund":
            command = RefundCommand(**event["command"])
            permit = ExecutionPermit.from_dict(event["permit"])
            validate_permit(config, command, permit, event["evaluated_at"])
            if command.operation_id in operation_ids or permit.permit_id in permit_ids:
                raise RefundRejected("duplicate operation or permit")
            state = transition(config, state, command)
            operation_ids.add(command.operation_id)
            permit_ids.add(permit.permit_id)
            operations.append(
                {
                    "operation_id": command.operation_id,
                    "permit_id": permit.permit_id,
                    "command_hash": canonical_hash_sha256(command.to_dict()),
                    "event_sequence": sequence,
                    "event_hash": digest,
                }
            )
        elif event["kind"] == "close":
            if event["command"] is not None or event["permit"] is not None:
                raise RefundRejected("invalid closure record")
            state = close_transition(state)
        else:
            raise RefundRejected("unsupported journal transition")
        if canonical_hash_sha256(state) != event["state_hash"]:
            raise RefundRejected("recorded state does not match replay")
        previous_hash, previous_time = digest, timestamp
    if (
        state != snapshot["state"]
        or previous_hash != snapshot["head_hash"]
        or sorted(operations, key=lambda item: item["operation_id"]) != snapshot["operations"]
    ):
        raise RefundRejected("observed ledger and journal do not reconcile")
    observed = datetime.fromisoformat(snapshot["observation"]["observed_at"])
    started = datetime.fromisoformat(snapshot["observation"]["snapshot_started_at"])
    if (
        observed.tzinfo is None
        or started.tzinfo is None
        or observed < started
        or previous_time is None
        or observed < previous_time
    ):
        raise RefundRejected("invalid observation interval")
    return {
        "status": "COMPLETE" if state["closed"] else "OPEN_INTERVAL",
        "committed_refunds": len(operations),
        "records_checked": len(records),
        "spent_cents": state["spent_cents"],
        "budget_cents": config["budget_cents"],
        "closed": state["closed"],
        "contract_hash": contract_hash,
    }


def seal_snapshot(snapshot: JsonObject, signer: SigningProvider, *, key_id: str) -> JsonObject:
    """Run as the observer; signing/export errors leave the database journal pending."""
    contract_hash = canonical_hash_sha256(snapshot["config"])
    _reconcile(snapshot, contract_hash)
    checkpoint = {
        "version": VERSION,
        "contract_hash": contract_hash,
        "snapshot_hash": canonical_hash_sha256(snapshot),
        "record_count": len(snapshot["records"]),
        "head_hash": snapshot["head_hash"],
        "observed_at": snapshot["observation"]["observed_at"],
        "closed": snapshot["state"]["closed"],
    }
    signature = sign_payload_hash(
        canonical_hash_sha256(checkpoint),
        purpose=PURPOSE,
        tenant_id=snapshot["config"]["tenant_id"],
        key_id=key_id,
        signer=signer,
    )
    return {"checkpoint": checkpoint, "signature": signature, "snapshot": snapshot}


def verify_bundle(
    bundle: JsonObject,
    *,
    observer_public_key: str,
    observer_key_id: str,
    contract_hash: str,
) -> JsonObject:
    """Require trust inputs supplied separately, never trust keys embedded in the bundle.

    COMPLETE is scoped to this closed ledger snapshot. It does not attest to events
    outside the database, privileged administrators, human intent, or current freshness.
    """
    try:
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (observer_public_key, observer_key_id, contract_hash)
        ):
            raise RefundRejected("explicit observer key, key ID and contract hash are required")
        checkpoint, snapshot = bundle["checkpoint"], bundle["snapshot"]
        expected = {
            "version": VERSION,
            "contract_hash": contract_hash,
            "snapshot_hash": canonical_hash_sha256(snapshot),
            "record_count": len(snapshot["records"]),
            "head_hash": snapshot["head_hash"],
            "observed_at": snapshot["observation"]["observed_at"],
            "closed": snapshot["state"]["closed"],
        }
        if checkpoint != expected or not verify_signature_record(
            bundle["signature"],
            canonical_hash_sha256(checkpoint),
            purpose=PURPOSE,
            tenant_id=snapshot["config"]["tenant_id"],
            key_id=observer_key_id,
            public_key=observer_public_key,
        ):
            raise RefundRejected("observer checkpoint or pinned signature differs")
        return _reconcile(snapshot, contract_hash)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as error:
        return {"status": "INVALID", "error": str(error)}
