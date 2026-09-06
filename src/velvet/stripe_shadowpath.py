"""Provider-backed ShadowPath: Velvet -> Stripe MCP -> Stripe refund records.

This is an opt-in, test-key-only integration, not the synthetic ShadowPath demo.
Run this file directly for a source-only installation, or use
``python -m velvet.stripe_shadowpath --help`` with Velvet installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request  # nosec B310 - HTTPS allowlist; redirects disabled below.
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, cast
from uuid import uuid4

from jsonschema import SchemaError, ValidationError
from jsonschema.validators import validator_for

Json = dict[str, Any]
SCHEMA = "velvet.shadowpath.stripe.v1"
STRIPE_API = "https://api.stripe.com"
STRIPE_MCP = "https://mcp.stripe.com"
MAX_BYTES = 2 * 1024 * 1024
TERMINAL = {"succeeded", "failed", "canceled"}
PENDING = {"pending", "requires_action"}
CLAIM_BOUNDARY = (
    "Hosted Stripe sandbox requests, not live funds. One protected MCP call and, only when "
    "explicitly enabled, one agent-credential REST route. The positive control uses Stripe MCP "
    "directly (or the configured control gateway). Observation is bounded; no universal effect "
    "prevention, credential inventory completeness, or independent operator claim is made."
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def obj(value: object, label: str = "response") -> Json:
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return cast(Json, value)


class ProbeError(RuntimeError):
    """Configuration, protocol, or observation failure; never a passing denial."""


class HttpFailure(ProbeError):
    def __init__(self, status: int, request_id: str | None = None) -> None:
        self.status = status
        self.request_id = request_id
        super().__init__(f"HTTP {status}; request_id={request_id or 'unavailable'}")


def test_key(value: str, role: str, *, restricted: bool = False) -> str:
    prefixes = ("rk_test_",) if restricted else ("sk_test_", "rk_test_")
    if not value.startswith(prefixes) or not re.fullmatch(r"[A-Za-z0-9_]+", value):
        raise ProbeError(f"{role} requires a {'restricted ' if restricted else ''}Stripe test key")
    return value


def gateway_url(value: str) -> str:
    url = urllib.parse.urlsplit(value)
    if url.username or url.password or url.fragment or url.query or not url.hostname:
        raise ProbeError("gateway URL must not contain credentials, query, or fragment")
    if url.scheme != "https" and not (
        url.scheme == "http" and url.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ProbeError("gateway requires HTTPS, except explicit loopback HTTP")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise ProbeError("HTTP redirects are refused; credentials were not forwarded")


def read_rpc(stream: BinaryIO, content_type: str, expected_id: object) -> Json:
    """Consume a matching JSON/SSE response without waiting for an SSE stream to close."""
    if "text/event-stream" not in content_type:
        raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ProbeError("response exceeds size limit")
        candidates = [json.loads(raw)]
    else:
        candidates = []
        data: list[str] = []
        total = 0
        started = time.monotonic()
        while True:
            raw_line = stream.readline(MAX_BYTES + 1)
            total += len(raw_line)
            if total > MAX_BYTES or time.monotonic() - started > 60:
                raise ProbeError("SSE response exceeds bounded read")
            line = raw_line.decode().rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
            if not line or not raw_line:
                if data:
                    item = obj(json.loads("\n".join(data)), "SSE event")
                    data = []
                    if item.get("id") == expected_id and "method" not in item:
                        candidates.append(item)
                        break
                    if "method" in item and "id" in item:
                        raise ProbeError(
                            "server requested interaction; unattended approval refused")
                if not raw_line:
                    break
    for item in candidates:
        result = obj(item, "JSON-RPC response")
        if (result.get("jsonrpc") == "2.0" and result.get("id") == expected_id
                and ("result" in result) != ("error" in result)):
            return result
    raise ProbeError("missing or mismatched JSON-RPC response")


class Transport:
    def __init__(self, timeout: float = 20) -> None:
        self.timeout = timeout
        # Do not inherit an unrelated process's proxy configuration or follow redirects.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.requests: list[Json] = []

    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None = None, *, rpc_id: object = None,
                notification: bool = False) -> tuple[Json, Mapping[str, str]]:
        request = urllib.request.Request(  # noqa: S310 - client URLs are validated/allowlisted.
            url, data=body, headers=dict(headers), method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:  # noqa: S310
                meta = {key.lower(): value for key, value in response.headers.items()}
                self.requests.append({"method": method,
                                      "path": urllib.parse.urlsplit(url).path,
                                      "status": response.status,
                                      "request_id": meta.get("request-id")})
                if notification:
                    if response.status not in (200, 202, 204):
                        raise ProbeError("MCP notification was not accepted")
                    return {}, meta
                if rpc_id is not None:
                    return read_rpc(response, meta.get("content-type", ""), rpc_id), meta
                raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ProbeError("response exceeds size limit")
                return obj(json.loads(raw)), meta
        except urllib.error.HTTPError as error:
            raise HttpFailure(error.code, error.headers.get("Request-Id")) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            # Never persist response bodies, authorization headers, or exception URLs.
            raise ProbeError(f"transport/protocol failure: {type(error).__name__}") from None


class Stripe:
    def __init__(self, key: str, transport: Transport) -> None:
        self.key = test_key(key, "REST client")
        self.transport = transport

    def request(self, method: str, path: str, params: Mapping[str, object] | None = None,
                *, idempotency: str | None = None) -> Json:
        allowed = r"/v1/(charges(?:/ch_[A-Za-z0-9]+)?|refunds|payment_intents|account)"
        if not re.fullmatch(allowed, path):
            raise ProbeError("Stripe endpoint outside this probe's allowlist")
        if method not in {"GET", "POST"}:
            raise ProbeError("unsupported Stripe method")
        encoded = urllib.parse.urlencode(params or {}).encode()
        url = STRIPE_API + path
        headers = {"Authorization": "Bearer " + self.key,
                   "Content-Type": "application/x-www-form-urlencoded"}
        if method == "GET" and encoded:
            url += "?" + encoded.decode()
        if method == "POST":
            if not idempotency:
                raise ProbeError("writes require a stable operation id")
            headers["Idempotency-Key"] = idempotency
        value, _ = self.transport.request(method, url, headers,
                                           encoded if method == "POST" else None)
        return value

    def charge(self, charge_id: str) -> Json:
        if not re.fullmatch(r"ch_[A-Za-z0-9]+", charge_id):
            raise ProbeError("invalid charge id")
        charge = self.request("GET", "/v1/charges/" + charge_id)
        if (charge.get("id") != charge_id or charge.get("object") != "charge"
                or charge.get("livemode") is not False or charge.get("paid") is not True
                or charge.get("captured") is not True):
            raise ProbeError("charge must be a paid, captured, test-mode charge")
        return charge

    def refunds(self, charge_id: str) -> list[Json]:
        result: list[Json] = []
        seen: set[str] = set()
        cursor: str | None = None
        for _ in range(100):
            params: Json = {"charge": charge_id, "limit": 100}
            if cursor:
                params["starting_after"] = cursor
            page = self.request("GET", "/v1/refunds", params)
            data = page.get("data")
            if not isinstance(data, list) or type(page.get("has_more")) is not bool:
                raise ProbeError("malformed refund pagination")
            for raw in data:
                refund = obj(raw, "refund")
                identifier = refund.get("id")
                if (not isinstance(identifier, str) or not identifier.startswith("re_")
                        or identifier in seen or refund.get("charge") != charge_id
                        or refund.get("object") != "refund"
                        or type(refund.get("amount")) is not int or refund["amount"] <= 0
                        or refund.get("status") not in TERMINAL | PENDING):
                    raise ProbeError("invalid, duplicate, or unknown-status refund record")
                seen.add(identifier)
                # Deliberately omit customer/card details and arbitrary metadata.
                result.append({key: refund.get(key) for key in
                               ("id", "charge", "amount", "currency", "status", "created")})
            if not page["has_more"]:
                return result
            if not data:
                raise ProbeError("empty page with has_more=true")
            cursor = str(data[-1]["id"])
        raise ProbeError("refund pagination limit exceeded; observation is incomplete")

    def create_charge(self, run_id: str, role: str, amount: int) -> str:
        intent = self.request("POST", "/v1/payment_intents", {
            "amount": max(amount, 1000), "currency": "usd", "payment_method": "pm_card_visa",
            "payment_method_types[]": "card", "confirm": "true",
            "metadata[shadowpath_run]": run_id, "metadata[shadowpath_role]": role,
        }, idempotency=f"shadowpath:{run_id}:setup:{role}")
        charge_id = intent.get("latest_charge")
        if (intent.get("livemode") is not False or intent.get("status") != "succeeded"
                or not isinstance(charge_id, str)):
            raise ProbeError("test payment did not produce a captured charge")
        return charge_id


class Mcp:
    def __init__(self, url: str, token: str, transport: Transport) -> None:
        self.url = gateway_url(url)
        self.token = token
        self.transport = transport
        self.session: str | None = None
        self.protocol = "2025-11-25"

    def rpc(self, method: str, params: Json, *, notification: bool = False) -> Json:
        identifier = str(uuid4())
        payload: Json = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            payload["id"] = identifier
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": self.protocol}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.session:
            headers["MCP-Session-Id"] = self.session
        response, meta = self.transport.request(
            "POST", self.url, headers, json.dumps(payload).encode(),
            rpc_id=None if notification else identifier, notification=notification)
        if "mcp-session-id" in meta:
            self.session = meta["mcp-session-id"]
        return response

    def initialize(self) -> None:
        response = self.rpc("initialize", {
            "protocolVersion": self.protocol, "capabilities": {},
            "clientInfo": {"name": "velvet-stripe-shadowpath", "version": "1.0.0"},
        })
        result = obj(response.get("result"), "MCP initialize result")
        version = result.get("protocolVersion")
        if version not in {"2025-11-25", "2025-06-18", "2025-03-26"}:
            raise ProbeError("unsupported negotiated MCP protocol")
        self.protocol = str(version)
        self.rpc("notifications/initialized", {}, notification=True)

    def tools(self) -> dict[str, Json]:
        tools: dict[str, Json] = {}
        cursors: set[str] = set()
        params: Json = {}
        for _ in range(100):
            result = obj(self.rpc("tools/list", params).get("result"), "tools/list")
            raw_tools = result.get("tools")
            if not isinstance(raw_tools, list):
                raise ProbeError("tools/list is missing tools")
            for raw in raw_tools:
                tool = obj(raw, "tool")
                name = tool.get("name")
                if not isinstance(name, str) or name in tools:
                    raise ProbeError("invalid or duplicate tool name")
                tools[name] = tool
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not cursor or cursor in cursors:
                raise ProbeError("invalid tools/list cursor")
            cursors.add(cursor)
            params = {"cursor": cursor}
        raise ProbeError("tools/list pagination limit exceeded")

    def call(self, name: str, arguments: Json) -> Json:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})


def validate_schema(schema: Json, arguments: Json) -> None:
    def local_refs(value: object) -> None:
        if isinstance(value, dict):
            ref = value.get("$ref")
            if ref is not None and (not isinstance(ref, str) or not ref.startswith("#")):
                raise ProbeError("remote JSON Schema references are not allowed")
            for child in value.values():
                local_refs(child)
        elif isinstance(value, list):
            for child in value:
                local_refs(child)
    local_refs(schema)
    try:
        validator = validator_for(schema)
        validator.check_schema(schema)
        validator(schema).validate(arguments)
    except (ValidationError, SchemaError):
        raise ProbeError("arguments do not match the discovered Stripe tool schema") from None


def refund_arguments(tool: Json, charge_id: str, amount: int, account: str | None) -> Json:
    """Use the documented API dispatcher, validating against live tools/list, never a fake tool.

    Unknown required fields (including interactive approval) fail closed. No approval token
    or human_confirmation value is invented by this runner.
    """
    schema = obj(tool.get("inputSchema"), "Stripe inputSchema")
    properties = obj(schema.get("properties"), "Stripe schema properties")
    if not {"stripe_api_operation_id", "parameters"} <= properties.keys():
        raise ProbeError("unsupported Stripe dispatcher schema; run discover and review it")
    arguments: Json = {"stripe_api_operation_id": "PostRefunds",
                       "parameters": {"charge": charge_id, "amount": amount}}
    if "livemode" in properties:
        arguments["livemode"] = False
    if "stripe_context" in properties:
        if not account or not re.fullmatch(r"acct_[A-Za-z0-9]+", account):
            raise ProbeError("this Stripe schema requires --account acct_...")
        arguments["stripe_context"] = account
    validate_schema(schema, arguments)
    return arguments


def response_evidence(response: Json) -> Json:
    error = response.get("error")
    evidence: Json = {"response_hash": digest(response), "rpc_id": response.get("id")}
    if isinstance(error, dict):
        data = error.get("data")
        data = data if isinstance(data, dict) else {}
        decision = data.get("oap_decision")
        decision = decision if isinstance(decision, dict) else {}
        evidence.update({"error_code": error.get("code"),
                         "boundary": data.get("boundary"),
                         "inventory_status": data.get("inventory_status"),
                         "allow": decision.get("allow"),
                         "admission_evidence_hash": data.get("admission_evidence_hash"),
                         "decision_digest": data.get("signed_decision_digest")})
    else:
        result = response.get("result")
        evidence["tool_error"] = result.get("isError", False) if isinstance(result, dict) else True
    return evidence


def denied_by_velvet(response: Json) -> bool:
    evidence = response_evidence(response)
    return (evidence.get("error_code") == -32071
            and evidence.get("boundary") == "pre_execution_authorization"
            and evidence.get("inventory_status") in {"blocked", "approved"}
            and evidence.get("allow") is False)


@dataclass(frozen=True)
class Settings:
    gateway: str
    output: Path
    amount: int = 100
    observe_seconds: float = 15
    poll_seconds: float = 1
    control_charge: str | None = None
    protected_charge: str | None = None
    provision: bool = False
    direct_route: bool = False
    account: str | None = None
    control_gateway: str | None = None

    def validate(self) -> None:
        gateway_url(self.gateway)
        if self.control_gateway:
            gateway_url(self.control_gateway)
        if type(self.amount) is not int or not 1 <= self.amount <= 10000:
            raise ProbeError("refund amount must be 1..10000 integer minor units")
        if not 1 <= self.observe_seconds <= 300 or not 0.1 <= self.poll_seconds <= 10:
            raise ProbeError("observation interval must be 1..300s; polling 0.1..10s")
        if self.provision:
            if self.control_charge or self.protected_charge:
                raise ProbeError("choose provisioning OR two existing fresh test charges")
        elif (not self.control_charge or not self.protected_charge
              or self.control_charge == self.protected_charge):
            raise ProbeError("two distinct fresh test charges are required")


class Probe:
    def __init__(self, settings: Settings, env: Mapping[str, str],
                 transport: Transport | None = None) -> None:
        settings.validate()
        self.settings = settings
        self.transport = transport or Transport()
        writer = test_key(env.get("VELVET_STRIPE_MCP_KEY", ""), "MCP")
        reader = test_key(env.get("VELVET_STRIPE_OBSERVER_KEY", ""), "observer", restricted=True)
        agent = test_key(env.get("VELVET_STRIPE_AGENT_KEY", ""), "agent") \
            if settings.direct_route else None
        setup = test_key(env.get("VELVET_STRIPE_SETUP_KEY", ""), "setup") \
            if settings.provision else None
        if reader in {writer, agent, setup}:
            raise ProbeError("observer credential must differ from every write credential")
        self.observer = Stripe(reader, self.transport)
        self.agent = Stripe(agent, self.transport) if agent else None
        self.setup = Stripe(setup, self.transport) if setup else None
        self.writer = Stripe(writer, self.transport)
        self.upstream = Mcp(STRIPE_MCP, writer, self.transport)
        self.gateway = Mcp(settings.gateway, env.get("VELVET_STRIPE_GATEWAY_TOKEN", ""),
                           self.transport)
        self.control = Mcp(settings.control_gateway,
                           env.get("VELVET_STRIPE_CONTROL_GATEWAY_TOKEN", ""), self.transport) \
            if settings.control_gateway else self.upstream
        self.report: Json = {
            "schema_version": SCHEMA, "mode": "hosted_stripe_sandbox", "run_id": str(uuid4()),
            "started_at": now(), "claim_boundary": CLAIM_BOUNDARY,
            "source_commit": env.get("GITHUB_SHA", "unrecorded"),
            "observation_scope": {"seconds_per_phase": settings.observe_seconds,
                                  "poll_seconds": settings.poll_seconds},
            "control_path": "control_gateway" if settings.control_gateway else "stripe_mcp_direct",
            "gateway_url": settings.gateway, "charges": {}, "phases": [],
            "observer": {"separate_restricted_key": True,
                         "read_only_permissions": "operator_configured_not_introspected"},
            "summary": {"overall_verdict": "INDETERMINATE", "effect_breach_count": 0},
            "exit_code": 4,
        }

    def save(self) -> None:
        self.report["updated_at"] = now()
        self.report["http_requests"] = self.transport.requests
        target = self.settings.output / "result.json"
        temporary = target.with_suffix(".tmp")
        # The output directory is new and private; keys/PII are never serialized.
        temporary.write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")
        temporary.replace(target)

    def observe(self, charge: str, phase: Json) -> None:
        stop = time.monotonic() + self.settings.observe_seconds
        observed: dict[str, Json] = {}
        phase["observations"] = []
        while True:
            current = self.observer.refunds(charge)
            current_ids = {item["id"] for item in current}
            if not set(observed) <= current_ids:
                raise ProbeError("previously observed refund disappeared")
            phase["observations"].append({"observed_at": now(), "refunds": current})
            for refund in current:
                previous = observed.get(refund["id"])
                if previous and previous["status"] in TERMINAL and previous != refund:
                    raise ProbeError("terminal refund changed between observations")
                observed[refund["id"]] = refund
                if refund["status"] == "succeeded":
                    phase["effect_observed"] = True
            phase["refunds"] = list(observed.values())
            phase["pending"] = any(item["status"] in PENDING for item in observed.values())
            self.save()
            remaining = stop - time.monotonic()
            if remaining <= 0:
                phase["observation_complete"] = True
                self.save()
                return
            time.sleep(min(self.settings.poll_seconds, remaining))

    def phase(self, name: str, charge: str, call: Callable[[], Json]) -> Json:
        phase: Json = {"name": name, "charge": charge, "started_at": now(),
                       "effect_observed": False, "pending": False,
                       "observation_complete": False}
        self.report["phases"].append(phase)
        self.save()  # Preserve intent before dispatch: never auto-repeat an ambiguous write.
        try:
            response = call()
            phase["response"] = response_evidence(response)
            phase["denied_by_velvet"] = denied_by_velvet(response)
        except ProbeError as error:
            phase["dispatch_error"] = str(error)
        self.save()
        try:
            self.observe(charge, phase)
        except ProbeError as error:
            phase["observation_error"] = str(error)
            self.save()
        return phase

    def run(self) -> Json:
        self.settings.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.save()
        try:
            self.upstream.initialize()
            tools = self.upstream.tools()
            tool = tools.get("stripe_api_write")
            if tool is None:
                raise ProbeError("Stripe did not advertise stripe_api_write for this credential")
            self.report["stripe_tool"] = {"name": tool["name"], "definition_hash": digest(tool),
                                          "input_schema": tool.get("inputSchema")}
            self.gateway.initialize()
            inventory = self.gateway.tools()
            self.report["gateway_advertised_tools"] = sorted(inventory)
            if self.control is not self.upstream:
                self.control.initialize()
            account = self.settings.account
            properties = obj(obj(tool.get("inputSchema")).get("properties"))
            if "stripe_context" in properties and not account:
                account = str(self.writer.request("GET", "/v1/account").get("id", ""))
            # Fail on unsupported tool schemas before creating any test payments.
            refund_arguments(tool, "ch_schemaPreflight", self.settings.amount, account)
            charges = {"control": self.settings.control_charge,
                       "protected": self.settings.protected_charge}
            for role, value in charges.items():
                if self.setup:
                    value = self.setup.create_charge(self.report["run_id"], role,
                                                     self.settings.amount)
                if not value:
                    raise ProbeError("missing test charge")
                self.report["charges"][role] = value
                self.save()
                charge = self.observer.charge(value)
                self.writer.charge(value)  # Check account visibility before sending a write.
                if self.agent:
                    self.agent.charge(value)
                if (self.observer.refunds(value) or charge.get("amount_refunded") != 0
                        or type(charge.get("amount")) is not int
                        or charge["amount"] < self.settings.amount):
                    raise ProbeError("each trial requires a fresh, sufficiently funded test charge")
            control_id = str(self.report["charges"]["control"])
            protected_id = str(self.report["charges"]["protected"])
            args = refund_arguments(tool, control_id, self.settings.amount, account)
            control = self.phase("authorized_control", control_id,
                                 lambda: self.control.call("stripe_api_write", args))
            successful = [item for item in control.get("refunds", [])
                          if item["status"] == "succeeded"]
            if (not control["observation_complete"] or control.get("dispatch_error")
                    or control.get("response", {}).get("error_code")
                    or control.get("response", {}).get("tool_error") is True
                    or len(successful) != 1 or successful[0]["amount"] != self.settings.amount
                    or control["pending"]):
                raise ProbeError("positive control failed: no calibrated MCP/observer measurement")
            self.report["calibration_passed"] = True
            args = refund_arguments(tool, protected_id, self.settings.amount, account)
            self.report["protected_request"] = {"name": "stripe_api_write", "arguments": args}
            protected = self.phase("protected_mcp", protected_id,
                                   lambda: self.gateway.call("stripe_api_write", args))
            # Do not conflate a delayed protected-path mutation with the later REST attempt.
            if (not protected.get("denied_by_velvet") or protected["effect_observed"]
                    or protected["pending"] or not protected["observation_complete"]
                    or protected.get("dispatch_error")):
                raise ProbeError("protected path was not an observed, clean Velvet denial")
            if not self.agent:
                self.report["alternate_route"] = {"status": "UNAVAILABLE",
                                                   "reason": "no explicit agent REST credential"}
            else:
                def direct() -> Json:
                    if self.agent is None:
                        raise ProbeError("agent REST route is unavailable")
                    refund = self.agent.request("POST", "/v1/refunds",
                        {"charge": protected_id, "amount": self.settings.amount},
                        idempotency=f"shadowpath:{self.report['run_id']}:direct-refund")
                    return {"jsonrpc": "2.0", "id": "direct-rest", "result": {
                        "refund_id": refund.get("id"), "provider_status": refund.get("status")}}
                self.phase("alternate_rest", protected_id, direct)
        except (ProbeError, ValueError, OSError) as error:
            # Do not lose an earlier breach because a later read or operation failed.
            self.report["error"] = (
                str(error) if isinstance(error, ProbeError) else type(error).__name__
            )
        self.finalize()
        self.save()
        return self.report

    def finalize(self) -> None:
        phases = {phase["name"]: phase for phase in self.report["phases"]}
        protected = phases.get("protected_mcp", {})
        direct = phases.get("alternate_rest", {})
        breached = [p for p in (protected, direct) if p.get("effect_observed")]
        unknown = bool(self.report.get("error")) or any(
            not p.get("observation_complete") or p.get("pending") or p.get("dispatch_error")
            for p in phases.values())
        if breached:
            verdict = "CONTROL_FALSE_SUCCESS" if protected.get("denied_by_velvet") \
                else "EFFECT_BREACH"
            code = 3
        elif unknown or not self.report.get("calibration_passed"):
            verdict, code = "INDETERMINATE", 4
        elif not direct:
            verdict, code = "ROUTE_UNAVAILABLE", 2
        else:
            # A rejected or failed provider call is not proof that Velvet protected this route.
            verdict, code = "NO_BREACH_OBSERVED_IN_WINDOW", 0
        self.report["summary"] = {"overall_verdict": verdict,
                                  "effect_breach_count": len(breached),
                                  "measurement_complete": not unknown and bool(direct),
                                  "protected_route_denied": protected.get(
                                      "denied_by_velvet", False),
                                  }
        self.report["exit_code"] = code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    discover = sub.add_parser("discover", help="Read Stripe MCP's actual tool schemas; no writes")
    discover.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run", help="Execute the hosted sandbox integration (test writes only)")
    run.add_argument("--gateway", required=True)
    run.add_argument("--control-gateway")
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--control-charge")
    run.add_argument("--protected-charge")
    run.add_argument("--provision", action="store_true")
    run.add_argument("--with-direct-route", action="store_true")
    run.add_argument("--allow-test-writes", action="store_true")
    run.add_argument("--amount", type=int, default=100)
    run.add_argument("--observe-seconds", type=float, default=15)
    run.add_argument("--poll-seconds", type=float, default=1)
    run.add_argument("--account")
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            key = test_key(os.environ.get("VELVET_STRIPE_MCP_KEY", ""), "MCP")
            client = Mcp(STRIPE_MCP, key, Transport())
            client.initialize()
            payload = {"source": STRIPE_MCP, "observed_at": now(), "tools": client.tools()}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            print(f"Saved discovered tool definitions to {args.output}")
            return 0
        if not args.allow_test_writes:
            raise ProbeError("run requires --allow-test-writes; live keys are always refused")
        settings = Settings(args.gateway, args.output_dir, args.amount, args.observe_seconds,
                            args.poll_seconds, args.control_charge, args.protected_charge,
                            args.provision, args.with_direct_route, args.account,
                            args.control_gateway)
        result = Probe(settings, os.environ).run()
        print(json.dumps({"result": str(args.output_dir / "result.json"),
                          **result["summary"], "exit_code": result["exit_code"]}, sort_keys=True))
        return int(result["exit_code"])
    except (ProbeError, OSError, ValueError) as error:
        print(json.dumps({"status": "NOT_RUN", "error": str(error)
                          if isinstance(error, ProbeError) else type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
