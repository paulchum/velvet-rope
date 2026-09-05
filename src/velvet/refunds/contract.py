"""Versioned refund state machine shared by the executor and offline verifier."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from velvet.execution import (
    EXECUTION_CANONICALIZATION,
    EXECUTION_PERMIT_SCHEMA_VERSION,
    ArtifactReference,
    ExecutionPermit,
    ExecutionPermitScope,
    PermitConstraints,
    PermitLineage,
    PermitPolicyBinding,
    PermitValidationContext,
    PermitValidity,
    SubjectBinding,
    verify_execution_permit,
)
from velvet.serialization import JsonObject, canonical_hash_sha256
from velvet.signing import SigningProvider

VERSION = "velvet.protected_refunds.v1"
SCHEMA_HASH = canonical_hash_sha256(
    {
        "version": VERSION,
        "command": ["operation_id", "ledger_id", "order_id", "amount_cents", "revision", "epoch"],
        "currency": "single configured currency; integer minor units",
    }
)


class RefundRejected(ValueError):
    """A definitive rejection before any refund commits."""


def integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 2**53 - 1:
        raise RefundRejected("expected a bounded integer in minor units")
    return value


@dataclass(frozen=True)
class RefundCommand:
    operation_id: str
    ledger_id: str
    order_id: str
    amount_cents: int
    revision: int
    epoch: int

    def __post_init__(self) -> None:
        for value in (self.operation_id, self.ledger_id, self.order_id):
            if not isinstance(value, str) or not value.strip() or len(value) > 128:
                raise RefundRejected("identifiers must contain 1–128 characters")
        integer(self.amount_cents, minimum=1)
        integer(self.revision)
        integer(self.epoch)

    def to_dict(self) -> JsonObject:
        return asdict(self)


def initial_state(config: JsonObject) -> JsonObject:
    if config.get("version") != VERSION:
        raise RefundRejected("unsupported refund contract")
    for key in (
        "ledger_id",
        "tenant_id",
        "environment",
        "audience",
        "authority_key_id",
        "authority_public_key",
        "currency",
    ):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise RefundRejected(f"missing contract field: {key}")
    integer(config["budget_cents"])
    if not isinstance(config["orders"], dict) or not config["orders"]:
        raise RefundRejected("at least one order is required")
    orders = {}
    for key, total in config["orders"].items():
        RefundCommand("validate", config["ledger_id"], key, 1, 0, 0)
        orders[key] = {"total_cents": integer(total, minimum=1), "refunded_cents": 0, "revision": 0}
    return {"spent_cents": 0, "epoch": 0, "closed": False, "orders": orders}


def scope_for(command: RefundCommand) -> ExecutionPermitScope:
    digest = canonical_hash_sha256(command.to_dict())
    return ExecutionPermitScope(
        surface="function",
        method="refund",
        tool_key="velvet.protected_refunds.refund",
        operation="refund",
        request_hash=digest,
        canonical_action_hash=digest,
        arguments_hash=digest,
        tool_schema_hash=SCHEMA_HASH,
    )


def issue_permit(
    config: JsonObject,
    command: RefundCommand,
    signer: SigningProvider,
    *,
    ttl_seconds: int = 60,
) -> ExecutionPermit:
    """Operator-side issuance for an already approved command; not an agent endpoint.

    This attests authorization by the configured key, not human intent or a policy engine run.
    """
    integer(ttl_seconds, minimum=1)
    if ttl_seconds > 300:
        raise RefundRejected("permit TTL cannot exceed 300 seconds")
    now = datetime.now(UTC)
    ref = ArtifactReference(
        "operator_approved_refund", command.operation_id, canonical_hash_sha256(command.to_dict())
    )
    return ExecutionPermit(
        permit_id=str(uuid4()),
        issuer=config["authority_key_id"],
        tenant_id=config["tenant_id"],
        environment=config["environment"],
        audience=config["audience"],
        subject=SubjectBinding(),
        scope=scope_for(command),
        policy=PermitPolicyBinding(canonical_hash_sha256(config), VERSION),
        lineage=PermitLineage(ref, ref),
        constraints=PermitConstraints(idempotency_key=command.operation_id),
        obligations=(),
        validity=PermitValidity(
            now.isoformat().replace("+00:00", "Z"),
            now.isoformat().replace("+00:00", "Z"),
            (now + timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z"),
        ),
    ).with_hash_and_signature(signer=signer, key_id=config["authority_key_id"])


def validate_permit(
    config: JsonObject,
    command: RefundCommand,
    permit: ExecutionPermit,
    now: str,
) -> None:
    context = PermitValidationContext(
        tenant_id=config["tenant_id"],
        environment=config["environment"],
        audience=config["audience"],
        policy_hash=canonical_hash_sha256(config),
        policy_version=VERSION,
        tool_schema_hash=SCHEMA_HASH,
        scope=scope_for(command),
        now=now,
        trusted_public_key=config["authority_public_key"],
        trusted_key_id=config["authority_key_id"],
    )
    checks = verify_execution_permit(permit, context)
    if (
        any(check["status"] != "pass" for check in checks)
        or permit.schema_version != EXECUTION_PERMIT_SCHEMA_VERSION
        or permit.canonicalization != EXECUTION_CANONICALIZATION
        or permit.obligations
        or permit.constraints.idempotency_key != command.operation_id
    ):
        raise RefundRejected("permit is invalid for this exact command and contract")


def transition(config: JsonObject, state: JsonObject, command: RefundCommand) -> JsonObject:
    """Pure normative transition; callers must serialize the read/check/write boundary."""
    if command.ledger_id != config["ledger_id"]:
        raise RefundRejected("ledger identity differs")
    if state["closed"] or command.epoch != state["epoch"]:
        raise RefundRejected("workflow is closed or its epoch differs")
    order = state["orders"].get(command.order_id)
    if order is None or command.revision != order["revision"]:
        raise RefundRejected("order is missing or its revision differs")
    if order["refunded_cents"] + command.amount_cents > order["total_cents"]:
        raise RefundRejected("refund exceeds the order total")
    if state["spent_cents"] + command.amount_cents > config["budget_cents"]:
        raise RefundRejected("refund exceeds the shared budget")
    result = copy.deepcopy(state)
    result["spent_cents"] += command.amount_cents
    result["orders"][command.order_id]["refunded_cents"] += command.amount_cents
    result["orders"][command.order_id]["revision"] += 1
    return result


def close_transition(state: JsonObject) -> JsonObject:
    if state["closed"]:
        raise RefundRejected("workflow is already closed")
    result = copy.deepcopy(state)
    result["closed"] = True
    result["epoch"] += 1
    return result
