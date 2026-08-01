from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, cast

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from demo.live_target.common import (
    ALT_POLICY_HASH,
    DEFAULT_POLICY_HASH,
    DispatchRefusal,
    _refusal,
    amount_string,
    cents,
    connect,
    current_tools,
    db_snapshot,
    get_control,
    guard_dispatch,
    issue_approval_receipt,
    record_audit,
    reset_database,
    set_control,
)

JsonObject = dict[str, Any]


def handle_jsonrpc(request: Mapping[str, Any]) -> JsonObject | None:
    if request.get("jsonrpc") != "2.0":
        return error_response(request.get("id"), -32600, "invalid JSON-RPC request")
    method = str(request.get("method") or "")
    if not method and "id" not in request:
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "velvet-live-target", "version": "1.0.0"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
    if method == "tools/list":
        with connect() as conn:
            tools = current_tools(conn)
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": tools}}
    if method == "tools/call":
        return handle_tool_call(request)
    return error_response(request.get("id"), -32601, "method not found")


def handle_tool_call(request: Mapping[str, Any]) -> JsonObject:
    params = request.get("params")
    if not isinstance(params, Mapping):
        return error_response(request.get("id"), -32602, "tools/call requires params object")
    tool_name = str(params.get("name") or "")
    arguments = params.get("arguments") if isinstance(params.get("arguments"), Mapping) else {}
    meta = params.get("_meta") if isinstance(params.get("_meta"), Mapping) else {}
    attack = str(cast(Mapping[str, Any], meta).get("attack") or "none")
    try:
        with connect() as conn:
            before = db_snapshot(conn)
            if tool_name == "query_orders":
                result = query_orders(conn, cast(Mapping[str, Any], arguments))
                after = db_snapshot(conn)
                record_audit(
                    conn,
                    attack=attack,
                    tool_name=tool_name,
                    decision="execute",
                    reason="read-only query executed",
                    before_hash=str(before["hash"]),
                    after_hash=str(after["hash"]),
                )
            else:
                guard = guard_dispatch(
                    conn,
                    request=request,
                    tool_name=tool_name,
                    actual_arguments=cast(Mapping[str, Any], arguments),
                    meta=cast(Mapping[str, Any], meta),
                    attack=attack,
                )
                result = execute_mutation(
                    conn,
                    tool_name,
                    cast(Mapping[str, Any], arguments),
                    guard,
                )
                after = db_snapshot(conn)
                record_audit(
                    conn,
                    attack=attack,
                    tool_name=tool_name,
                    decision="execute",
                    reason="guard admitted dispatch before SQL",
                    before_hash=str(before["hash"]),
                    after_hash=str(after["hash"]),
                    guard=guard,
                    metadata={"result": result},
                )
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                    "structuredContent": result,
                    "isError": False,
                },
            }
    except DispatchRefusal as refusal:
        with connect() as conn:
            before_after = db_snapshot(conn)
            audit = record_audit(
                conn,
                attack=attack,
                tool_name=tool_name or "unknown",
                decision="refuse",
                reason=refusal.reason,
                before_hash=str(before_after["hash"]),
                after_hash=str(before_after["hash"]),
                refusal=refusal,
                metadata=refusal.metadata,
            )
        return error_response(
            request.get("id"),
            -32091,
            "executor dispatch refused",
            {
                "boundary": "executor_dispatch_validation",
                "velvet_dispatch_refusal": refusal.to_dict(),
                "audit_id": audit.get("audit_id"),
            },
        )
    except Exception as error:  # noqa: BLE001 - JSON-RPC server boundary.
        return error_response(
            request.get("id"),
            -32090,
            "live target failed",
            {"detail": str(error)},
        )


def query_orders(conn: Any, arguments: Mapping[str, Any]) -> JsonObject:
    params: list[Any] = []
    if arguments.get("customer_id") and arguments.get("status"):
        params.append(str(arguments["customer_id"]))
        params.append(str(arguments["status"]))
        query = """
            SELECT order_id, customer_id, status, total_cents, refunded_cents
            FROM orders
            WHERE customer_id = %s AND status = %s
            ORDER BY order_id
            """
    elif arguments.get("customer_id"):
        params.append(str(arguments["customer_id"]))
        query = """
            SELECT order_id, customer_id, status, total_cents, refunded_cents
            FROM orders
            WHERE customer_id = %s
            ORDER BY order_id
            """
    elif arguments.get("status"):
        params.append(str(arguments["status"]))
        query = """
            SELECT order_id, customer_id, status, total_cents, refunded_cents
            FROM orders
            WHERE status = %s
            ORDER BY order_id
            """
    else:
        query = """
            SELECT order_id, customer_id, status, total_cents, refunded_cents
            FROM orders
            ORDER BY order_id
            """
    rows = conn.execute(query, params).fetchall()
    return {"rows": rows, "row_count": len(rows)}


def execute_mutation(
    conn: Any,
    tool_name: str,
    arguments: Mapping[str, Any],
    guard: Any,
) -> JsonObject:
    if tool_name == "update_order_status":
        order_id = str(arguments["order_id"])
        status = str(arguments["status"])
        row = conn.execute(
            """
            UPDATE orders
            SET status = %s
            WHERE order_id = %s
            RETURNING order_id, customer_id, status
            """,
            (status, order_id),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown order_id {order_id}")
        return {"updated_order": row}
    if tool_name == "delete_customer_records":
        customer_id = str(arguments["customer_id"])
        deleted = conn.execute(
            "DELETE FROM customers WHERE customer_id = %s RETURNING customer_id",
            (customer_id,),
        ).fetchone()
        return {"deleted_customer_id": deleted["customer_id"] if deleted else None}
    if tool_name == "issue_refund":
        order_id = str(arguments["order_id"])
        amount_cents = cents(arguments["amount"])
        budget = conn.execute(
            """
            SELECT account, cap_cents, spent_cents
            FROM refund_budget
            WHERE account = %s
            FOR UPDATE
            """,
            ("refunds:global",),
        ).fetchone()
        if budget is None:
            raise ValueError("refund budget missing")
        if int(budget["spent_cents"]) + amount_cents > int(budget["cap_cents"]):
            raise _refusal("refund budget cap exceeded", guard)
        order = conn.execute(
            """
            SELECT order_id, customer_id, total_cents, refunded_cents
            FROM orders
            WHERE order_id = %s
            FOR UPDATE
            """,
            (order_id,),
        ).fetchone()
        if order is None:
            raise ValueError(f"unknown order_id {order_id}")
        if int(order["refunded_cents"]) + amount_cents > int(order["total_cents"]):
            raise _refusal("refund exceeds order total", guard)
        refund_id = f"rfnd_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """
            INSERT INTO refunds(
                refund_id,
                order_id,
                customer_id,
                amount_cents,
                reason,
                admitted_action_hash,
                attempted_action_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                refund_id,
                order_id,
                order["customer_id"],
                amount_cents,
                str(arguments["reason"]),
                guard.admitted_action_hash,
                guard.attempted_action_hash,
            ),
        )
        conn.execute(
            "UPDATE orders SET refunded_cents = refunded_cents + %s WHERE order_id = %s",
            (amount_cents, order_id),
        )
        conn.execute(
            "UPDATE refund_budget SET spent_cents = spent_cents + %s WHERE account = %s",
            (amount_cents, "refunds:global"),
        )
        return {
            "refund_id": refund_id,
            "order_id": order_id,
            "amount": amount_string(amount_cents),
        }
    raise ValueError(f"unknown tool {tool_name}")


def error_response(
    request_id: object,
    code: int,
    message: str,
    data: Mapping[str, Any] | None = None,
) -> JsonObject:
    error: JsonObject = {"code": code, "message": message}
    if data is not None:
        error["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


async def mcp_http(request: Request) -> JSONResponse:
    payload = await request.json()
    if isinstance(payload, list):
        return JSONResponse(
            [handle_jsonrpc(item) for item in payload if isinstance(item, Mapping)]
        )
    if not isinstance(payload, Mapping):
        return JSONResponse(
            error_response(None, -32600, "invalid JSON-RPC request"),
            status_code=400,
        )
    response = handle_jsonrpc(payload)
    if response is None:
        return JSONResponse({}, status_code=202)
    return JSONResponse(response)


async def mcp_sse(_: Request) -> StreamingResponse:
    async def events() -> Any:
        yield (
            "event: message\n"
            'data: {"jsonrpc":"2.0","method":"notifications/initialized"}\n\n'
        )

    return StreamingResponse(events(), media_type="text/event-stream")


async def reset_http(_: Request) -> JSONResponse:
    reset_database()
    return JSONResponse({"status": "reset", "state": state_payload()})


async def state_http(_: Request) -> JSONResponse:
    return JSONResponse(state_payload())


async def control_http(request: Request) -> JSONResponse:
    payload = await request.json()
    if not isinstance(payload, Mapping):
        return JSONResponse({"error": "expected object"}, status_code=400)
    for key, value in payload.items():
        if key == "policy_swap":
            set_control("policy_hash", ALT_POLICY_HASH if value else DEFAULT_POLICY_HASH)
        elif key in {"schema_version", "policy_hash"}:
            set_control(str(key), str(value))
        elif key == "refund_cap_cents":
            with connect() as conn:
                conn.execute(
                    "UPDATE refund_budget SET cap_cents = %s, spent_cents = 0 WHERE account = %s",
                    (int(value), "refunds:global"),
                )
    return JSONResponse({"status": "ok", "state": state_payload()})


async def receipt_http(request: Request) -> JSONResponse:
    payload = await request.json()
    if not isinstance(payload, Mapping):
        return JSONResponse({"error": "expected object"}, status_code=400)
    tool_name = str(payload.get("tool_name") or "delete_customer_records")
    arguments = payload.get("arguments")
    if not isinstance(arguments, Mapping):
        return JSONResponse({"error": "arguments required"}, status_code=400)
    with connect() as conn:
        receipt = issue_approval_receipt(conn, tool_name=tool_name, arguments=arguments)
    return JSONResponse(receipt)


def state_payload() -> JsonObject:
    with connect() as conn:
        state = db_snapshot(conn)
        state["schema_version"] = get_control(conn, "schema_version", "1")
        state["policy_hash"] = get_control(conn, "policy_hash", DEFAULT_POLICY_HASH)
        state["audit"] = conn.execute(
            """
            SELECT audit_id, attack, tool_name, decision, reason,
                   admitted_action_hash, attempted_action_hash,
                   admitted_arguments_hash, attempted_arguments_hash,
                   admitted_tool_schema_hash, attempted_tool_schema_hash,
                   admitted_policy_hash, attempted_policy_hash,
                   db_state_hash_before, db_state_hash_after, metadata
            FROM live_demo_dispatch_audit
            ORDER BY audit_id
            """
        ).fetchall()
    return state


def create_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/mcp", mcp_http, methods=["POST"]),
            Route("/mcp", mcp_sse, methods=["GET"]),
            Route("/demo/reset", reset_http, methods=["POST"]),
            Route("/demo/state", state_http, methods=["GET"]),
            Route("/demo/control", control_http, methods=["POST"]),
            Route("/demo/approval-receipt", receipt_http, methods=["POST"]),
        ]
    )


def stdio_loop() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            response = handle_jsonrpc(payload)
        except Exception as error:  # noqa: BLE001
            response = error_response(None, -32700, "parse error", {"detail": str(error)})
        if response is not None:
            print(json.dumps(response, sort_keys=True), flush=True)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8891)
    parser.add_argument("--reset-db", action="store_true")
    args = parser.parse_args(argv)
    if args.reset_db:
        reset_database()
    if args.stdio:
        return stdio_loop()
    if args.http:
        import uvicorn

        uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
        return 0
    parser.error("choose --stdio, --http, or --reset-db")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
