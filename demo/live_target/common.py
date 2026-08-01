from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, cast

import psycopg
from psycopg.rows import dict_row

from velvet.actions import CanonicalAction
from velvet.contracts import AdmissionContract
from velvet.execution import (
    ExecutionPermit,
    ExecutionPermitScope,
    PermitValidationContext,
    verification_status,
    verify_execution_permit,
)
from velvet.normalizer import VelvetActionNormalizer
from velvet.serialization import canonical_hash_sha256
from velvet.signing import (
    DEMO_ED25519_PUBLIC_KEY_PATH,
    PURPOSE_APPROVAL_RECEIPT_V1,
    load_demo_ed25519_signer,
    sign_payload_hash,
    verify_signature_record,
)

JsonObject = dict[str, Any]

DEFAULT_DATABASE_URL = "postgresql://velvet_live:velvet_live@127.0.0.1:55433/velvet_live_demo"
DEFAULT_POLICY_HASH = "sha256:" + "a" * 64
ALT_POLICY_HASH = "sha256:" + "b" * 64
APPROVAL_RECEIPT_PURPOSE = PURPOSE_APPROVAL_RECEIPT_V1
ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SQL = Path(__file__).resolve().parent / "db" / "schema.sql"
SEED_SQL = Path(__file__).resolve().parent / "db" / "seed.sql"


class DispatchRefusal(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        admitted_action_hash: str | None = None,
        attempted_action_hash: str | None = None,
        admitted_arguments_hash: str | None = None,
        attempted_arguments_hash: str | None = None,
        admitted_tool_schema_hash: str | None = None,
        attempted_tool_schema_hash: str | None = None,
        admitted_policy_hash: str | None = None,
        attempted_policy_hash: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.admitted_action_hash = admitted_action_hash
        self.attempted_action_hash = attempted_action_hash
        self.admitted_arguments_hash = admitted_arguments_hash
        self.attempted_arguments_hash = attempted_arguments_hash
        self.admitted_tool_schema_hash = admitted_tool_schema_hash
        self.attempted_tool_schema_hash = attempted_tool_schema_hash
        self.admitted_policy_hash = admitted_policy_hash
        self.attempted_policy_hash = attempted_policy_hash
        self.metadata = dict(metadata or {})

    def to_dict(self) -> JsonObject:
        return {
            "reason": self.reason,
            "admitted_action_hash": self.admitted_action_hash,
            "attempted_action_hash": self.attempted_action_hash,
            "admitted_arguments_hash": self.admitted_arguments_hash,
            "attempted_arguments_hash": self.attempted_arguments_hash,
            "admitted_tool_schema_hash": self.admitted_tool_schema_hash,
            "attempted_tool_schema_hash": self.attempted_tool_schema_hash,
            "admitted_policy_hash": self.admitted_policy_hash,
            "attempted_policy_hash": self.attempted_policy_hash,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GuardResult:
    admitted_action_hash: str
    attempted_action: CanonicalAction
    attempted_action_hash: str
    admitted_arguments_hash: str
    attempted_arguments_hash: str
    admitted_tool_schema_hash: str
    attempted_tool_schema_hash: str
    admitted_policy_hash: str
    attempted_policy_hash: str


def database_url() -> str:
    return os.environ.get("VELVET_LIVE_DATABASE_URL", DEFAULT_DATABASE_URL)


def connect() -> psycopg.Connection[JsonObject]:
    return psycopg.connect(database_url(), row_factory=dict_row)


def reset_database() -> None:
    with connect() as conn:
        conn.execute(SCHEMA_SQL.read_text(encoding="utf-8"))
        conn.execute(SEED_SQL.read_text(encoding="utf-8"))


def set_control(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO live_demo_control(key, value)
            VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (key, value),
        )


def get_control(conn: psycopg.Connection[JsonObject], key: str, default: str) -> str:
    row = conn.execute(
        "SELECT value FROM live_demo_control WHERE key = %s",
        (key,),
    ).fetchone()
    return str(row["value"]) if row else default


def cents(value: object) -> int:
    if isinstance(value, int):
        return value
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int(amount * 100)


def amount_string(cents_value: int) -> str:
    return f"{Decimal(cents_value) / Decimal(100):.2f}"


def stable_hash(value: Mapping[str, Any] | list[Any]) -> str:
    return canonical_hash_sha256(value)


def arguments_hash(arguments: Mapping[str, Any]) -> str:
    return stable_hash(dict(arguments))


def tool_schema_hash(tool: Mapping[str, Any]) -> str:
    material = {
        "name": tool["name"],
        "inputSchema": tool.get("inputSchema"),
        "outputSchema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
    }
    return stable_hash(material)


def _trusted_velvet_public_key() -> str:
    configured = os.environ.get("VELVET_LIVE_TRUSTED_PUBLIC_KEY")
    if configured:
        return configured
    configured_file = os.environ.get("VELVET_LIVE_TRUSTED_PUBLIC_KEY_FILE")
    if configured_file:
        return Path(configured_file).read_text(encoding="utf-8")
    return DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8")


def current_tools(conn: psycopg.Connection[JsonObject]) -> list[JsonObject]:
    schema_version = get_control(conn, "schema_version", "1")
    update_required = ["order_id", "status"]
    if schema_version == "2":
        update_required.append("operator_note")
    return [
        {
            "name": "query_orders",
            "title": "Query Orders",
            "description": "Read-only order lookup.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string"},
                    "status": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "update_order_status",
            "title": "Update Order Status",
            "description": "Mutate the status of one order.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["pending", "paid", "shipped", "cancelled", "refunded"],
                    },
                    "operator_note": {"type": "string"},
                },
                "required": update_required,
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False},
        },
        {
            "name": "delete_customer_records",
            "title": "Delete Customer Records",
            "description": "Delete one customer and cascading order/refund rows.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "approval_receipt": {"type": "object"},
                },
                "required": ["customer_id", "reason"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True},
        },
        {
            "name": "issue_refund",
            "title": "Issue Refund",
            "description": "Issue a monetary refund against one order.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "amount": {"type": "number", "exclusiveMinimum": 0},
                    "reason": {"type": "string"},
                },
                "required": ["order_id", "amount", "reason"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False},
        },
    ]


def tool_by_name(conn: psycopg.Connection[JsonObject], name: str) -> JsonObject:
    for tool in current_tools(conn):
        if tool["name"] == name:
            return tool
    raise KeyError(name)


def order_customer(conn: psycopg.Connection[JsonObject], order_id: str) -> str:
    row = conn.execute(
        "SELECT customer_id FROM orders WHERE order_id = %s",
        (order_id,),
    ).fetchone()
    return str(row["customer_id"]) if row else "unknown"


def proposal_for_tool(
    conn: psycopg.Connection[JsonObject],
    tool_name: str,
    arguments: Mapping[str, Any],
) -> JsonObject:
    args = dict(arguments)
    proposal: JsonObject = {
        "surface": "function",
        "name": tool_name,
        "operation": operation_for_tool(tool_name),
        "arguments": args,
        "agent_id": "velvet-live-demo-agent",
        "timestamp_input": "2026-06-13T00:00:00.000Z",
    }
    if tool_name == "issue_refund":
        amount_cents = cents(args.get("amount", 0))
        order_id = str(args.get("order_id", "unknown"))
        proposal.update(
            {
                "refund_amount": amount_cents,
                "amount": amount_cents,
                "customer_id": order_customer(conn, order_id),
                "refund_case_id": order_id,
                "boundary_key": "refunds:global",
            }
        )
    elif tool_name == "delete_customer_records":
        proposal.update(
            {
                "customer_id": str(args.get("customer_id", "unknown")),
                "boundary_key": f"customer:{args.get('customer_id', 'unknown')}:delete",
            }
        )
    elif tool_name == "update_order_status":
        proposal.update(
            {
                "boundary_key": f"order:{args.get('order_id', 'unknown')}:status",
                "target_resource": f"order:{args.get('order_id', 'unknown')}",
            }
        )
    else:
        proposal["boundary_key"] = "orders:read"
    return proposal


def operation_for_tool(tool_name: str) -> str:
    return {
        "query_orders": "read_rows",
        "update_order_status": "update",
        "delete_customer_records": "delete",
        "issue_refund": "issue_refund",
    }.get(tool_name, tool_name)


def normalize_for_tool(
    conn: psycopg.Connection[JsonObject],
    tool_name: str,
    arguments: Mapping[str, Any],
) -> CanonicalAction:
    contract = AdmissionContract(
        default_authority_budget=1_000_000,
        spend_cap=1_000_000,
        execute_fallback_on_insufficient_budget=False,
    )
    return VelvetActionNormalizer().normalize(
        proposal_for_tool(conn, tool_name, arguments),
        contract,
    )


def normalize_for_execution_permit(
    request: Mapping[str, Any],
    tool_name: str,
    arguments: Mapping[str, Any],
    permit: ExecutionPermit,
) -> CanonicalAction:
    """Rebuild the proxy's signed MCP action at the executor boundary."""

    request_id = request.get("id")
    if request_id is not None and not isinstance(request_id, str):
        request_id = json.dumps(request_id, sort_keys=True, separators=(",", ":"))
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    request_session_id = meta.get("session_id") if isinstance(meta, Mapping) else None
    session_id = request_session_id if isinstance(request_session_id, str) else None
    upstream_server, separator, _ = permit.scope.tool_key.partition("/")
    if not separator:
        upstream_server = os.environ.get("VELVET_LIVE_UPSTREAM_SERVER", "velvet-live-target")
    proposal: JsonObject = {
        "surface": "mcp",
        "server": upstream_server,
        "tool": tool_name,
        "arguments": dict(arguments),
        "tenant_id": permit.tenant_id,
        "environment": permit.environment,
        "actor_id": os.environ.get("VELVET_LIVE_ACTOR_ID"),
        "agent_id": os.environ.get("VELVET_LIVE_AGENT_ID"),
        "session_id": session_id or os.environ.get("VELVET_LIVE_SESSION_ID"),
        "request_id": request_id,
    }
    return VelvetActionNormalizer().normalize(
        proposal,
        AdmissionContract(policy_version=permit.policy.policy_version),
    )


def admission_bundle(meta: Mapping[str, Any]) -> Mapping[str, Any]:
    value = meta.get("velvet_execution")
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


def execution_permit_from_bundle(bundle: Mapping[str, Any]) -> ExecutionPermit:
    value = bundle.get("execution_permit") or bundle.get("permit")
    if not isinstance(value, Mapping):
        raise DispatchRefusal("execution permit missing")
    return ExecutionPermit.from_dict(cast(Mapping[str, Any], value))


def guard_dispatch(
    conn: psycopg.Connection[JsonObject],
    *,
    request: Mapping[str, Any],
    tool_name: str,
    actual_arguments: Mapping[str, Any],
    meta: Mapping[str, Any],
    attack: str,
) -> GuardResult:
    bundle = admission_bundle(meta)
    permit = execution_permit_from_bundle(bundle)

    attempted_effect_action = normalize_for_tool(conn, tool_name, actual_arguments)
    attempted_action = normalize_for_execution_permit(
        request,
        tool_name,
        actual_arguments,
        permit,
    )
    admitted_action_hash = permit.scope.canonical_action_hash
    attempted_action_hash = f"sha256:{attempted_action.canonical_action_hash}"
    admitted_args_hash = permit.scope.arguments_hash
    attempted_args_hash = arguments_hash(actual_arguments)
    current_schema_hash = tool_schema_hash(tool_by_name(conn, tool_name))
    admitted_schema_hash = permit.scope.tool_schema_hash
    admitted_policy_hash = permit.policy.policy_hash
    current_policy_hash = get_control(conn, "policy_hash", DEFAULT_POLICY_HASH)

    result = GuardResult(
        admitted_action_hash=admitted_action_hash,
        attempted_action=attempted_action,
        attempted_action_hash=attempted_action_hash,
        admitted_arguments_hash=admitted_args_hash,
        attempted_arguments_hash=attempted_args_hash,
        admitted_tool_schema_hash=admitted_schema_hash,
        attempted_tool_schema_hash=current_schema_hash,
        admitted_policy_hash=admitted_policy_hash,
        attempted_policy_hash=current_policy_hash,
    )
    if admitted_schema_hash != current_schema_hash:
        raise _refusal("tool schema hash mismatch", result)
    if admitted_policy_hash != current_policy_hash:
        raise _refusal("policy hash mismatch", result)
    if admitted_action_hash != attempted_action_hash:
        raise _refusal("canonical action hash mismatch", result)
    if admitted_args_hash != attempted_args_hash:
        raise _refusal("arguments hash mismatch", result)
    _validate_execution_permit(conn, permit, request, tool_name, result)
    if tool_name == "delete_customer_records":
        _validate_approval_receipt(actual_arguments, attempted_effect_action, result)
    return result


def _validate_execution_permit(
    conn: psycopg.Connection[JsonObject],
    permit: ExecutionPermit,
    request: Mapping[str, Any],
    tool_name: str,
    result: GuardResult,
) -> None:
    expected_scope = ExecutionPermitScope.from_action(
        result.attempted_action,
        actual_request=request,
        method=permit.scope.method,
        tool_key=permit.scope.tool_key,
        arguments_hash=result.attempted_arguments_hash,
        tool_schema_hash=result.attempted_tool_schema_hash,
    )
    context = PermitValidationContext(
        tenant_id=os.environ.get("VELVET_LIVE_TENANT_ID", permit.tenant_id),
        environment=os.environ.get("VELVET_LIVE_ENVIRONMENT", permit.environment),
        audience=os.environ.get("VELVET_LIVE_AUDIENCE", permit.audience),
        policy_hash=result.attempted_policy_hash,
        policy_version=permit.policy.policy_version,
        tool_schema_hash=result.attempted_tool_schema_hash,
        scope=expected_scope,
        now=os.environ.get("VELVET_LIVE_VERIFY_TIME"),
        trusted_public_key=_trusted_velvet_public_key(),
        trusted_key_id=str(permit.signature.get("key_id"))
        if isinstance(permit.signature, Mapping)
        else None,
    )
    checks = verify_execution_permit(permit, context)
    if verification_status(checks) != "pass":
        failed = [check for check in checks if check.get("status") != "pass"]
        refusal = _refusal("execution permit verification failed", result)
        refusal.metadata["permit_check_failures"] = failed[:3]
        raise refusal
    row = conn.execute(
        """
        INSERT INTO live_demo_execution_permit_claims(
            permit_id,
            permit_hash,
            tool_name,
            request_hash
        )
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (permit_id) DO NOTHING
        RETURNING permit_id
        """,
        (
            permit.permit_id,
            permit.permit_hash,
            tool_name,
            expected_scope.request_hash,
        ),
    ).fetchone()
    if row is None:
        raise _refusal("execution permit replay", result)


def _validate_approval_receipt(
    arguments: Mapping[str, Any],
    attempted_effect_action: CanonicalAction,
    result: GuardResult,
) -> None:
    receipt = arguments.get("approval_receipt")
    if not isinstance(receipt, Mapping):
        raise _refusal("approval receipt required", result)
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    if not isinstance(payload, Mapping) or not isinstance(signature, Mapping):
        raise _refusal("approval receipt malformed", result)
    payload_hash = stable_hash(dict(payload))
    signer = load_demo_ed25519_signer()
    if not verify_signature_record(
        signature,
        payload_hash,
        purpose=APPROVAL_RECEIPT_PURPOSE,
        signer=signer,
    ):
        raise _refusal("approval receipt signature invalid", result)
    if payload.get("canonical_action_hash") != attempted_effect_action.canonical_action_hash:
        raise _refusal("approval receipt action hash mismatch", result)


def _refusal(reason: str, result: GuardResult) -> DispatchRefusal:
    return DispatchRefusal(
        reason,
        admitted_action_hash=result.admitted_action_hash,
        attempted_action_hash=result.attempted_action_hash,
        admitted_arguments_hash=result.admitted_arguments_hash,
        attempted_arguments_hash=result.attempted_arguments_hash,
        admitted_tool_schema_hash=result.admitted_tool_schema_hash,
        attempted_tool_schema_hash=result.attempted_tool_schema_hash,
        admitted_policy_hash=result.admitted_policy_hash,
        attempted_policy_hash=result.attempted_policy_hash,
    )


def issue_approval_receipt(
    conn: psycopg.Connection[JsonObject],
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    approver: str = "velvet-demo-approver",
) -> JsonObject:
    action = normalize_for_tool(conn, tool_name, arguments)
    payload = {
        "schema_version": "velvet.live_demo.approval_receipt.v1",
        "approval_receipt_id": f"aprct_{uuid.uuid4().hex[:16]}",
        "tool_name": tool_name,
        "canonical_action_hash": action.canonical_action_hash,
        "arguments_hash": arguments_hash(arguments),
        "approved": True,
        "approver": approver,
    }
    signer = load_demo_ed25519_signer()
    return {
        "payload": payload,
        "signature": sign_payload_hash(
            stable_hash(payload),
            purpose=APPROVAL_RECEIPT_PURPOSE,
            signer=signer,
            tenant_id="velvet-demo-tenant",
            key_id="demo-not-for-production",
        ),
    }


def db_snapshot(conn: psycopg.Connection[JsonObject]) -> JsonObject:
    customers = conn.execute(
        "SELECT customer_id, email, name, segment FROM customers ORDER BY customer_id"
    ).fetchall()
    orders = conn.execute(
        """
        SELECT order_id, customer_id, status, total_cents, refunded_cents
        FROM orders ORDER BY order_id
        """
    ).fetchall()
    refunds = conn.execute(
        """
        SELECT refund_id, order_id, customer_id, amount_cents, reason
        FROM refunds ORDER BY refund_id
        """
    ).fetchall()
    budget = conn.execute(
        "SELECT account, cap_cents, spent_cents FROM refund_budget ORDER BY account"
    ).fetchall()
    return {
        "customers": customers,
        "orders": orders,
        "refunds": refunds,
        "budget": budget,
        "hash": stable_hash(
            {
                "customers": customers,
                "orders": orders,
                "refunds": refunds,
                "budget": budget,
            }
        ),
    }


def record_audit(
    conn: psycopg.Connection[JsonObject],
    *,
    attack: str,
    tool_name: str,
    decision: str,
    reason: str,
    before_hash: str,
    after_hash: str,
    guard: GuardResult | None = None,
    refusal: DispatchRefusal | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> JsonObject:
    source = refusal
    row = conn.execute(
        """
        INSERT INTO live_demo_dispatch_audit(
            attack,
            tool_name,
            decision,
            reason,
            admitted_action_hash,
            attempted_action_hash,
            admitted_arguments_hash,
            attempted_arguments_hash,
            admitted_tool_schema_hash,
            attempted_tool_schema_hash,
            admitted_policy_hash,
            attempted_policy_hash,
            db_state_hash_before,
            db_state_hash_after,
            metadata
        )
        VALUES (
            %(attack)s,
            %(tool_name)s,
            %(decision)s,
            %(reason)s,
            %(admitted_action_hash)s,
            %(attempted_action_hash)s,
            %(admitted_arguments_hash)s,
            %(attempted_arguments_hash)s,
            %(admitted_tool_schema_hash)s,
            %(attempted_tool_schema_hash)s,
            %(admitted_policy_hash)s,
            %(attempted_policy_hash)s,
            %(db_state_hash_before)s,
            %(db_state_hash_after)s,
            %(metadata)s::jsonb
        )
        RETURNING *
        """,
        {
            "attack": attack,
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "admitted_action_hash": (source.admitted_action_hash if source else None)
            or (guard.admitted_action_hash if guard else None),
            "attempted_action_hash": (source.attempted_action_hash if source else None)
            or (guard.attempted_action_hash if guard else None),
            "admitted_arguments_hash": (source.admitted_arguments_hash if source else None)
            or (guard.admitted_arguments_hash if guard else None),
            "attempted_arguments_hash": (source.attempted_arguments_hash if source else None)
            or (guard.attempted_arguments_hash if guard else None),
            "admitted_tool_schema_hash": (source.admitted_tool_schema_hash if source else None)
            or (guard.admitted_tool_schema_hash if guard else None),
            "attempted_tool_schema_hash": (source.attempted_tool_schema_hash if source else None)
            or (guard.attempted_tool_schema_hash if guard else None),
            "admitted_policy_hash": (source.admitted_policy_hash if source else None)
            or (guard.admitted_policy_hash if guard else None),
            "attempted_policy_hash": (source.attempted_policy_hash if source else None)
            or (guard.attempted_policy_hash if guard else None),
            "db_state_hash_before": before_hash,
            "db_state_hash_after": after_hash,
            "metadata": json.dumps(dict(metadata or {}), sort_keys=True),
        },
    ).fetchone()
    return dict(row or {})
