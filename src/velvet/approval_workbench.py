"""Local approval workbench for pilot MCP approval flows."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from html import escape
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from velvet.approvals import ApprovalStatus, ApprovalStore
from velvet.signing import LOCAL_DEMO_KEY_ID, SigningProvider

JsonObject = dict[str, Any]


def create_approval_app(
    approval_store: ApprovalStore | str | Path,
    *,
    signer: SigningProvider | None = None,
    tenant_id: str | None = None,
    signing_key_id: str | None = None,
    auth_token: str | None = None,
    csrf_secret: str | None = None,
    allow_unauthenticated_local: bool = False,
) -> Starlette:
    """Create a small localhost-oriented approval workbench ASGI app."""

    if not allow_unauthenticated_local and (not auth_token or not csrf_secret):
        raise ValueError(
            "approval workbench requires auth_token and csrf_secret unless "
            "allow_unauthenticated_local=True is set for loopback-only development"
        )

    store = (
        approval_store
        if isinstance(approval_store, ApprovalStore)
        else ApprovalStore(
            approval_store,
            signer=signer,
            tenant_id=tenant_id,
            signing_key_id=signing_key_id or LOCAL_DEMO_KEY_ID,
        )
    )

    async def index(request: Request) -> Response:
        if response := _auth_failure(request):
            return response
        return RedirectResponse("/approvals", status_code=303)

    async def approvals_page(request: Request) -> Response:
        if response := _auth_failure(request):
            return response
        snapshot = store.load()
        return HTMLResponse(_layout("Approvals", _approval_list_html(snapshot.to_dict())))

    async def approval_detail_page(request: Request) -> Response:
        if response := _auth_failure(request):
            return response
        approval_request_id = request.path_params["approval_request_id"]
        snapshot = store.load()
        approval = next(
            (
                item
                for item in snapshot.requests
                if item.approval_request_id == approval_request_id
            ),
            None,
        )
        if approval is None:
            return HTMLResponse(_layout("Not found", "<p>Approval request not found.</p>"), 404)
        receipts = [
            receipt
            for receipt in snapshot.receipts
            if receipt.approval_request_id == approval.approval_request_id
        ]
        return HTMLResponse(
            _layout(
                approval.approval_request_id,
                _approval_detail_html(
                    approval.to_dict(),
                    [receipt.to_dict() for receipt in receipts],
                    csrf_token=csrf_secret if not allow_unauthenticated_local else None,
                ),
            )
        )

    async def approvals_api(request: Request) -> Response:
        if response := _auth_failure(request):
            return response
        return JSONResponse(store.load().to_dict())

    async def approval_detail_api(request: Request) -> Response:
        if response := _auth_failure(request):
            return response
        approval_request_id = request.path_params["approval_request_id"]
        snapshot = store.load()
        approval = next(
            (
                item
                for item in snapshot.requests
                if item.approval_request_id == approval_request_id
            ),
            None,
        )
        if approval is None:
            return JSONResponse({"error": "approval request not found"}, status_code=404)
        return JSONResponse(
            {
                "request": approval.to_dict(),
                "receipts": [
                    receipt.to_dict()
                    for receipt in snapshot.receipts
                    if receipt.approval_request_id == approval.approval_request_id
                ],
            }
        )

    async def approve(request: Request) -> Response:
        return await _decide(request, ApprovalStatus.APPROVED)

    async def deny(request: Request) -> Response:
        return await _decide(request, ApprovalStatus.DENIED)

    async def _decide(request: Request, status: ApprovalStatus) -> Response:
        if response := _auth_failure(request):
            return response
        approval_request_id = request.path_params["approval_request_id"]
        payload = await _request_payload(request)
        if response := _csrf_failure(request, payload):
            return response
        approver = str(payload.get("approver") or "velvet-operator")
        reason = str(payload.get("reason") or "Reviewed in Velvet approval workbench.")
        try:
            receipt = store.decide(
                approval_request_id,
                status=status,
                approver=approver,
                reason=reason,
            )
        except (KeyError, ValueError) as error:
            if _wants_html(request):
                return HTMLResponse(_layout("Approval error", f"<p>{escape(str(error))}</p>"), 400)
            return JSONResponse({"error": str(error)}, status_code=400)
        if _wants_html(request):
            return RedirectResponse(f"/approvals/{approval_request_id}", status_code=303)
        return JSONResponse(receipt.to_dict())

    def _auth_failure(request: Request) -> Response | None:
        if allow_unauthenticated_local:
            return None
        authorization = request.headers.get("authorization", "")
        prefix = "Bearer "
        if authorization.startswith(prefix) and hmac.compare_digest(
            authorization[len(prefix) :],
            str(auth_token),
        ):
            return None
        return _error_response(request, "approval workbench authentication required", 401)

    def _csrf_failure(request: Request, payload: Mapping[str, Any]) -> Response | None:
        if allow_unauthenticated_local:
            return None
        token = request.headers.get("x-csrf-token") or str(payload.get("csrf_token") or "")
        if hmac.compare_digest(token, str(csrf_secret)):
            return None
        return _error_response(request, "valid approval workbench CSRF token required", 403)

    return Starlette(
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/approvals", approvals_page, methods=["GET"]),
            Route("/approvals/{approval_request_id}", approval_detail_page, methods=["GET"]),
            Route("/api/approvals", approvals_api, methods=["GET"]),
            Route("/api/approvals/{approval_request_id}", approval_detail_api, methods=["GET"]),
            Route(
                "/api/approvals/{approval_request_id}/approve",
                approve,
                methods=["POST"],
            ),
            Route(
                "/api/approvals/{approval_request_id}/deny",
                deny,
                methods=["POST"],
            ),
            Route("/approvals/{approval_request_id}/approve", approve, methods=["POST"]),
            Route("/approvals/{approval_request_id}/deny", deny, methods=["POST"]),
        ]
    )


async def _request_payload(request: Request) -> JsonObject:
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    if "application/json" in content_type and body:
        decoded = json.loads(body.decode("utf-8"))
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    if body:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}
    return {}


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


def _error_response(request: Request, message: str, status_code: int) -> Response:
    if _wants_html(request):
        return HTMLResponse(_layout("Approval error", f"<p>{escape(message)}</p>"), status_code)
    return JSONResponse({"error": message}, status_code=status_code)


def _layout(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} - Velvet Approvals</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --surface: #ffffff;
      --ink: #1f2933;
      --muted: #5d6978;
      --border: #d7dde5;
      --accent: #1d5fd1;
      --danger: #b42318;
      --ok: #176b3a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.45;
    }}
    header {{
      border-bottom: 1px solid var(--border);
      background: var(--surface);
      padding: 18px 24px;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.2; }}
    h2 {{ margin: 28px 0 10px; font-size: 16px; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
        "Liberation Mono", monospace;
      font-size: 12px;
    }}
    pre {{
      overflow: auto;
      padding: 14px;
      background: #101820;
      color: #f3f6f8;
      border-radius: 6px;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .field {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      min-width: 0;
    }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .value {{ overflow-wrap: anywhere; margin-top: 3px; }}
    form {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: end;
      margin: 12px 0;
    }}
    input {{
      min-width: 240px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font: inherit;
    }}
    button {{
      border: 0;
      border-radius: 6px;
      color: white;
      cursor: pointer;
      font: inherit;
      font-weight: 650;
      padding: 9px 12px;
    }}
    .approve {{ background: var(--ok); }}
    .deny {{ background: var(--danger); }}
    .status {{ font-weight: 700; }}
    @media (max-width: 760px) {{
      main {{ padding: 16px; }}
      .grid {{ grid-template-columns: 1fr; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <header><h1>Velvet Approval Workbench</h1></header>
  <main>{body}</main>
</body>
</html>"""


def _approval_list_html(snapshot: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], snapshot.get("summary", {}))
    rows = []
    for item in cast(list[Mapping[str, Any]], snapshot.get("requests", [])):
        rows.append(
            "<tr>"
            f"<td><a href=\"/approvals/{escape(str(item['approval_request_id']))}\">"
            f"{escape(str(item['approval_request_id']))}</a></td>"
            f"<td>{escape(str(item.get('tool_key')))}</td>"
            f"<td class=\"status\">{escape(str(item.get('status')))}</td>"
            f"<td>{escape(str(item.get('risk_class')))}</td>"
            f"<td>{escape(str(item.get('user_id') or item.get('subject_id') or ''))}</td>"
            f"<td>{escape(str(item.get('agent_id') or ''))}</td>"
            f"<td>{escape(str(item.get('expires_at')))}</td>"
            "</tr>"
        )
    body = (
        f"<p>{escape(str(summary.get('pending', 0)))} pending, "
        f"{escape(str(summary.get('approved', 0)))} approved, "
        f"{escape(str(summary.get('denied', 0)))} denied, "
        f"{escape(str(summary.get('redeemed', 0)))} redeemed.</p>"
        "<table><thead><tr>"
        "<th>Request id</th><th>Tool</th><th>Status</th><th>Risk</th>"
        "<th>User</th><th>Agent</th><th>Expiry</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return body


def _approval_detail_html(
    request_payload: Mapping[str, Any],
    receipts: list[Mapping[str, Any]],
    *,
    csrf_token: str | None = None,
) -> str:
    fields = [
        ("Request id", request_payload.get("approval_request_id")),
        ("Tool key", request_payload.get("tool_key")),
        ("Decision reason", request_payload.get("reason")),
        ("Risk class", request_payload.get("risk_class")),
        ("Requester", request_payload.get("requester")),
        ("User", request_payload.get("user_id")),
        ("Subject", request_payload.get("subject_id")),
        ("Agent", request_payload.get("agent_id")),
        ("Request hash", request_payload.get("request_hash")),
        ("Arguments hash", request_payload.get("arguments_hash")),
        ("Policy hash", request_payload.get("policy_hash")),
        ("Policy version", request_payload.get("policy_version")),
        ("Tool schema hash", request_payload.get("tool_schema_hash")),
        ("Expiry", request_payload.get("expires_at")),
    ]
    form = ""
    if request_payload.get("status") == ApprovalStatus.PENDING.value:
        request_id = escape(str(request_payload["approval_request_id"]))
        csrf_input = (
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
            if csrf_token
            else ""
        )
        form = f"""
<h2>Decision</h2>
<form method="post" action="/approvals/{request_id}/approve">
  {csrf_input}
  <label><span class="label">Approver</span><br>
    <input name="approver" value="velvet-operator"></label>
  <label><span class="label">Reason</span><br>
    <input name="reason" value="Approved in local workbench."></label>
  <button class="approve" type="submit">Approve</button>
</form>
<form method="post" action="/approvals/{request_id}/deny">
  {csrf_input}
  <label><span class="label">Approver</span><br>
    <input name="approver" value="velvet-operator"></label>
  <label><span class="label">Reason</span><br>
    <input name="reason" value="Denied in local workbench."></label>
  <button class="deny" type="submit">Deny</button>
</form>"""
    receipt_rows = "".join(
        "<tr>"
        f"<td>{escape(str(receipt.get('approval_receipt_id')))}</td>"
        f"<td>{'approved' if receipt.get('approved') else 'denied'}</td>"
        f"<td>{escape(str(receipt.get('approver_id')))}</td>"
        f"<td>{escape(str(receipt.get('used_at') or 'unused'))}</td>"
        f"<td>{escape(str(receipt.get('receipt_hash')))}</td>"
        "</tr>"
        for receipt in receipts
    )
    return (
        '<p><a href="/approvals">Back to approvals</a></p>'
        f"<h2>{escape(str(request_payload.get('status'))).title()} Request</h2>"
        "<div class=\"grid\">"
        + "".join(_field(label, value) for label, value in fields)
        + "</div>"
        + form
        + "<h2>Original Request JSON</h2>"
        + "<pre>"
        + escape(
            json.dumps(request_payload.get("redacted_request", {}), indent=2, sort_keys=True)
        )
        + "</pre>"
        + "<h2>Receipts</h2>"
        + "<table><thead><tr><th>Receipt id</th><th>Status</th><th>Approver</th>"
        + "<th>Redemption</th><th>Hash</th></tr></thead><tbody>"
        + receipt_rows
        + "</tbody></table>"
    )


def _field(label: str, value: object) -> str:
    return (
        '<div class="field">'
        f'<div class="label">{escape(label)}</div>'
        f'<div class="value"><code>{escape("" if value is None else str(value))}</code></div>'
        "</div>"
    )
