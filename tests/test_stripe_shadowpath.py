"""Offline protocol and measurement tests; these are NOT Stripe measurements."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

# Source-only loading also works before building Velvet's optional Rust Python binding.
SOURCE = Path(__file__).resolve().parents[1] / "src" / "velvet" / "stripe_shadowpath.py"
spec = importlib.util.spec_from_file_location("stripe_shadowpath_under_test", SOURCE)
assert spec is not None and spec.loader is not None
sp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sp
spec.loader.exec_module(sp)

TOOL = {
    "name": "stripe_api_write",
    "inputSchema": {
        "type": "object", "additionalProperties": False,
        "properties": {"stripe_api_operation_id": {"type": "string"},
                       "parameters": {"type": "object"}, "livemode": {"type": "boolean"}},
        "required": ["stripe_api_operation_id", "parameters", "livemode"],
    },
}
# Intentionally invalid provider credentials, used only by the injected transport.
ENV = {"VELVET_STRIPE_MCP_KEY": "rk_test_notARealMcpKey",
       "VELVET_STRIPE_OBSERVER_KEY": "rk_test_notARealObserverKey",
       "VELVET_STRIPE_AGENT_KEY": "rk_test_notARealAgentKey",
       "VELVET_STRIPE_SETUP_KEY": "sk_test_notARealSetupKey"}


def denial(identifier: str = "x") -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {
        "code": -32071, "data": {"boundary": "pre_execution_authorization",
                                  "inventory_status": "blocked",
                                  "oap_decision": {"allow": False},
                                  "signed_decision_digest": "sha256:test"}}}


class FakeTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.rows: dict[str, list[dict[str, Any]]] = {"ch_control": [], "ch_protected": []}
        self.gateway_response = "deny"
        self.direct_status = "succeeded"
        self.control_status = "succeeded"
        self.direct_error: int | None = None
        self.error_after_direct = False
        self.later_observer_error = False
        self.observer_reads_after_direct = 0
        self.direct_sent = False
        self.posts = 0
        self.live_charge = False
        self.tool: dict[str, Any] = json.loads(json.dumps(TOOL))
        self.no_tool = False
        self.use_unknown_refund_status = False
        self.setup_roles: list[str] = []

    def refund(self, charge: str, status: str) -> dict[str, Any]:
        value = {"id": "re_" + charge.removeprefix("ch_"), "object": "refund",
                 "charge": charge, "amount": 100, "currency": "usd", "status": status,
                 "created": 1000, "metadata": {"private": "must not be recorded"}}
        self.rows.setdefault(charge, []).append(value)
        return value

    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None = None, *, rpc_id: object = None,
                notification: bool = False) -> tuple[dict[str, Any], Mapping[str, str]]:
        self.requests.append({"method": method, "path": urllib.parse.urlsplit(url).path})
        if method == "POST":
            self.posts += 1
        if "/v1/" in url:
            path = urllib.parse.urlsplit(url).path
            if method == "GET" and path == "/v1/account":
                return {"id": "acct_sandbox"}, {}
            if method == "GET" and path.startswith("/v1/charges/"):
                charge = path.rsplit("/", 1)[-1]
                return {"id": charge, "object": "charge", "livemode": self.live_charge,
                        "paid": True, "captured": True, "amount": 1000,
                        "amount_refunded": 0}, {}
            if method == "GET" and path == "/v1/refunds":
                charge = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["charge"][0]
                if self.direct_sent:
                    self.observer_reads_after_direct += 1
                    if self.later_observer_error and self.observer_reads_after_direct > 1:
                        raise sp.ProbeError("observer disconnected after a recorded breach")
                rows = self.rows.get(charge, [])
                if self.use_unknown_refund_status and rows:
                    rows[0]["status"] = "new_unrecognized_status"
                return {"object": "list", "data": rows, "has_more": False}, {}
            params = urllib.parse.parse_qs((body or b"").decode())
            if method == "POST" and path == "/v1/payment_intents":
                role = params["metadata[shadowpath_role]"][0]
                self.setup_roles.append(role)
                return {"livemode": False, "status": "succeeded", "latest_charge": "ch_" + role}, {}
            if method == "POST" and path == "/v1/refunds":
                self.direct_sent = True
                if not headers.get("Idempotency-Key"):
                    raise AssertionError("missing idempotency key")
                if self.direct_error:
                    raise sp.HttpFailure(self.direct_error)
                result = self.refund(params["charge"][0], self.direct_status)
                if self.error_after_direct:
                    raise sp.ProbeError("lost response after dispatch")
                return result, {}
            raise AssertionError((method, path))
        payload = json.loads(body or b"{}")
        identifier = payload.get("id")
        if notification:
            return {}, {}
        if payload["method"] == "initialize":
            return {"jsonrpc": "2.0", "id": identifier,
                    "result": {"protocolVersion": "2025-11-25"}}, {"mcp-session-id": "session"}
        if payload["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": identifier,
                    "result": {"tools": [] if self.no_tool else [self.tool]}}, {}
        if payload["method"] == "tools/call":
            if url.startswith("http://127.0.0.1"):
                if self.gateway_response == "deny":
                    return denial(str(identifier)), {}
                if self.gateway_response == "timeout":
                    raise sp.ProbeError("gateway timeout")
                if self.gateway_response == "auth":
                    raise sp.HttpFailure(401)
                if self.gateway_response == "unrelated_error":
                    return {"jsonrpc": "2.0", "id": identifier,
                            "error": {"code": -32070, "data": {
                                "boundary": "pre_execution_authorization"}}}, {}
            args = payload["params"]["arguments"]
            charge = args["parameters"]["charge"]
            self.refund(charge, self.control_status if charge == "ch_control" else "succeeded")
            return {"jsonrpc": "2.0", "id": identifier,
                    "result": {"content": [{"type": "text", "text": "refund accepted"}]}}, {}
        raise AssertionError(payload)


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += max(seconds, 0.1)


class StripeTests(unittest.TestCase):
    def run_probe(self, transport: FakeTransport | None = None, *, direct: bool = True,
                  provision: bool = False) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as directory:
            settings = sp.Settings("http://127.0.0.1:8791/mcp", Path(directory) / "run",
                                   observe_seconds=1, poll_seconds=0.5,
                                   control_charge=None if provision else "ch_control",
                                   protected_charge=None if provision else "ch_protected",
                                   provision=provision, direct_route=direct)
            clock = Clock()
            with patch.object(sp.time, "monotonic", clock.monotonic), \
                    patch.object(sp.time, "sleep", clock.sleep):
                probe = sp.Probe(settings, ENV, transport or FakeTransport())
                result = probe.run()
            self.assertEqual(result, json.loads((settings.output / "result.json").read_text()))
            serialized = json.dumps(result)
            for value in ENV.values():
                self.assertNotIn(value, serialized)
            self.assertNotIn("must not be recorded", serialized)
            return result

    def test_real_shape_denial_then_provider_effect(self) -> None:
        result = self.run_probe()
        self.assertEqual(result["summary"]["overall_verdict"], "CONTROL_FALSE_SUCCESS")
        self.assertEqual(result["exit_code"], 3)
        self.assertTrue(result["calibration_passed"])
        self.assertTrue(result["summary"]["measurement_complete"])
        self.assertEqual(result["summary"]["effect_breach_count"], 1)

    def test_no_agent_key_is_unavailable_not_pass(self) -> None:
        result = self.run_probe(direct=False)
        self.assertEqual(result["summary"]["overall_verdict"], "ROUTE_UNAVAILABLE")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual(len(result["phases"]), 2)

    def test_control_failure_stops_adversarial_calls(self) -> None:
        transport = FakeTransport()
        transport.control_status = "failed"
        result = self.run_probe(transport)
        self.assertEqual(len(result["phases"]), 1)
        self.assertEqual(result["exit_code"], 4)
        self.assertFalse(transport.direct_sent)

    def test_control_pending_is_not_calibration(self) -> None:
        transport = FakeTransport()
        transport.control_status = "pending"
        result = self.run_probe(transport)
        self.assertNotIn("calibration_passed", result)
        self.assertEqual(result["exit_code"], 4)

    def test_pending_direct_refund_is_unknown(self) -> None:
        transport = FakeTransport()
        transport.direct_status = "pending"
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 4)
        self.assertFalse(result["summary"]["measurement_complete"])

    def test_requires_action_is_unknown(self) -> None:
        transport = FakeTransport()
        transport.direct_status = "requires_action"
        self.assertEqual(self.run_probe(transport)["exit_code"], 4)

    def test_failed_refund_is_only_no_breach_in_window(self) -> None:
        transport = FakeTransport()
        transport.direct_status = "failed"
        result = self.run_probe(transport)
        self.assertEqual(result["summary"]["overall_verdict"], "NO_BREACH_OBSERVED_IN_WINDOW")
        self.assertEqual(result["exit_code"], 0)

    def test_gateway_timeout_is_not_deny(self) -> None:
        transport = FakeTransport()
        transport.gateway_response = "timeout"
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 4)
        self.assertFalse(transport.direct_sent)

    def test_gateway_auth_failure_is_not_deny(self) -> None:
        transport = FakeTransport()
        transport.gateway_response = "auth"
        self.assertEqual(self.run_probe(transport)["exit_code"], 4)
        self.assertFalse(transport.direct_sent)

    def test_unrelated_fail_closed_error_is_not_the_policy(self) -> None:
        transport = FakeTransport()
        transport.gateway_response = "unrelated_error"
        self.assertEqual(self.run_probe(transport)["exit_code"], 4)

    def test_protected_path_effect_is_counted(self) -> None:
        transport = FakeTransport()
        transport.gateway_response = "allow"
        result = self.run_probe(transport)
        self.assertEqual(result["summary"]["overall_verdict"], "EFFECT_BREACH")
        self.assertEqual(result["summary"]["effect_breach_count"], 1)
        self.assertFalse(transport.direct_sent)

    def test_recorded_breach_survives_later_observer_failure(self) -> None:
        transport = FakeTransport()
        transport.later_observer_error = True
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["summary"]["effect_breach_count"], 1)
        self.assertFalse(result["summary"]["measurement_complete"])

    def test_lost_post_response_does_not_erase_provider_effect(self) -> None:
        transport = FakeTransport()
        transport.error_after_direct = True
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 3)
        self.assertFalse(result["summary"]["measurement_complete"])
        self.assertEqual(len(transport.rows["ch_protected"]), 1)

    def test_provider_auth_failure_is_not_velvet_prevention(self) -> None:
        transport = FakeTransport()
        transport.direct_error = 403
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 4)

    def test_live_charge_rejected_before_refund(self) -> None:
        transport = FakeTransport()
        transport.live_charge = True
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 4)
        self.assertEqual(result["phases"], [])

    def test_optional_provision_uses_two_fresh_payments(self) -> None:
        transport = FakeTransport()
        result = self.run_probe(transport, provision=True)
        self.assertEqual(transport.setup_roles, ["control", "protected"])
        self.assertEqual(result["exit_code"], 3)

    def test_missing_real_tool_is_not_a_fake_fallback(self) -> None:
        transport = FakeTransport()
        transport.no_tool = True
        result = self.run_probe(transport)
        self.assertEqual(result["phases"], [])
        self.assertEqual(result["exit_code"], 4)

    def test_unknown_schema_fails_before_provision(self) -> None:
        transport = FakeTransport()
        transport.tool["inputSchema"]["required"].append("approval_token")
        result = self.run_probe(transport, provision=True)
        self.assertEqual(transport.setup_roles, [])
        self.assertEqual(result["exit_code"], 4)

    def test_no_fake_human_confirmation_is_added(self) -> None:
        args = sp.refund_arguments(TOOL, "ch_control", 100, None)
        self.assertNotIn("human_confirmation", args)
        self.assertEqual(args["parameters"]["charge"], "ch_control")
        self.assertIs(args["livemode"], False)

    def test_separate_observer_required(self) -> None:
        settings = sp.Settings("http://localhost:8791/mcp", Path("unused"),
                               control_charge="ch_control", protected_charge="ch_protected")
        bad = {**ENV, "VELVET_STRIPE_OBSERVER_KEY": ENV["VELVET_STRIPE_MCP_KEY"]}
        with self.assertRaises(sp.ProbeError):
            sp.Probe(settings, bad, FakeTransport())

    def test_live_and_non_restricted_observer_keys_refused(self) -> None:
        for value in ("sk_live_neverUse", "rk_live_neverUse", "", "Bearer sk_test_bad"):
            with self.subTest(value=value), self.assertRaises(sp.ProbeError):
                sp.test_key(value, "key")
        with self.assertRaises(sp.ProbeError):
            sp.test_key("sk_test_notRestricted", "observer", restricted=True)

    def test_gateway_url_restrictions(self) -> None:
        for value in ("http://example.com/mcp", "https://user:pass@example.com",
                      "https://example.com/?token=secret", "file:///etc/passwd"):
            with self.subTest(value=value), self.assertRaises(sp.ProbeError):
                sp.gateway_url(value)
        self.assertEqual(sp.gateway_url("http://127.0.0.1:8791/mcp"),
                         "http://127.0.0.1:8791/mcp")

    def test_rpc_json_id_mismatch_refused(self) -> None:
        raw = json.dumps({"jsonrpc": "2.0", "id": "other", "result": {}}).encode()
        with self.assertRaises(sp.ProbeError):
            sp.read_rpc(io.BytesIO(raw), "application/json", "wanted")

    def test_rpc_sse_multiline_and_notifications(self) -> None:
        raw = (b':keepalive\r\n\r\ndata: {"jsonrpc":"2.0","method":"notifications/log"}\n\n'
               b'data: {"jsonrpc":"2.0",\n'
               b'data: "id":"wanted","result":{"ok":true}}\n\n')
        self.assertTrue(sp.read_rpc(io.BytesIO(raw), "text/event-stream", "wanted")["result"]["ok"])

    def test_sse_approval_request_not_auto_accepted(self) -> None:
        raw = b'data: {"jsonrpc":"2.0","id":"approval","method":"elicitation/create"}\n\n'
        with self.assertRaises(sp.ProbeError):
            sp.read_rpc(io.BytesIO(raw), "text/event-stream", "wanted")

    def test_rpc_size_limit(self) -> None:
        with self.assertRaises(sp.ProbeError):
            sp.read_rpc(io.BytesIO(b" " * (sp.MAX_BYTES + 1)), "application/json", "x")

    def test_redirect_refused(self) -> None:
        with self.assertRaises(sp.ProbeError):
            sp.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.test")

    def test_explicit_deny_contract(self) -> None:
        self.assertTrue(sp.denied_by_velvet(denial()))
        for path, value in (("code", -32070), ("code", 403)):
            changed = denial()
            changed["error"][path] = value
            self.assertFalse(sp.denied_by_velvet(changed))
        changed = denial()
        changed["error"]["data"]["inventory_status"] = "drifted"
        self.assertFalse(sp.denied_by_velvet(changed))

    def test_remote_schema_ref_refused(self) -> None:
        with self.assertRaises(sp.ProbeError):
            sp.validate_schema({"$ref": "https://untrusted.example/schema"}, {})

    def test_amount_and_time_bounds(self) -> None:
        for amount in (True, 0, -1, 1.5, 10001):
            with self.subTest(amount=amount), self.assertRaises(sp.ProbeError):
                sp.Settings("http://localhost/mcp", Path("unused"), amount=amount,
                            control_charge="ch_control", protected_charge="ch_protected").validate()

    def test_no_test_write_acknowledgement_no_network(self) -> None:
        with patch.object(sp.Transport, "request", side_effect=AssertionError("network")):
            with patch("sys.stdout", new=io.StringIO()):
                code = sp.main(["run", "--gateway", "http://localhost/mcp",
                                "--output-dir", "unused", "--provision"])
            self.assertEqual(code, 2)

    def test_unknown_refund_status_is_not_safe(self) -> None:
        transport = FakeTransport()
        transport.use_unknown_refund_status = True
        result = self.run_probe(transport)
        self.assertEqual(result["exit_code"], 4)

    def test_refund_pagination_and_scope(self) -> None:
        transport = FakeTransport()
        client = sp.Stripe(ENV["VELVET_STRIPE_OBSERVER_KEY"], transport)
        a = transport.refund("ch_control", "succeeded")
        b = {**a, "id": "re_second"}
        with patch.object(client, "request", side_effect=[
            {"data": [a], "has_more": True}, {"data": [b], "has_more": False},
        ]) as request:
            rows = client.refunds("ch_control")
            self.assertEqual(len(rows), 2)
            self.assertEqual(request.call_args_list[1].args[2]["starting_after"], a["id"])
        with patch.object(client, "request", return_value={"data": [{**a, "charge": "ch_other"}],
                                                           "has_more": False}):
            with self.assertRaises(sp.ProbeError):
                client.refunds("ch_control")

    def test_duplicate_refunds_and_empty_more_refused(self) -> None:
        transport = FakeTransport()
        client = sp.Stripe(ENV["VELVET_STRIPE_OBSERVER_KEY"], transport)
        a = transport.refund("ch_control", "succeeded")
        for page in ({"data": [a, a], "has_more": False}, {"data": [], "has_more": True}):
            with self.subTest(page=page), patch.object(client, "request", return_value=page):
                with self.assertRaises(sp.ProbeError):
                    client.refunds("ch_control")

    def test_existing_output_is_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = sp.Settings("http://localhost/mcp", Path(directory),
                                   control_charge="ch_control", protected_charge="ch_protected")
            transport = FakeTransport()
            with self.assertRaises(FileExistsError):
                sp.Probe(settings, ENV, transport).run()
            self.assertEqual(transport.posts, 0)


if __name__ == "__main__":
    unittest.main()
