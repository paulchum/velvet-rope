"""Offline fixed-route relay tests. Every upstream call uses a fake transport."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parents[1] / "src" / "velvet"
MODULES = ("velvet", "velvet.stripe_credit_note_probe", "velvet.stripe_rest_relay")
previous = {name: sys.modules.get(name) for name in MODULES}
package = types.ModuleType("velvet")
package.__path__ = [str(SOURCE)]
sys.modules["velvet"] = package

from velvet import stripe_credit_note_probe as probe  # noqa: E402
from velvet import stripe_rest_relay as relay  # noqa: E402

for name, original in previous.items():
    if original is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = original


class FakeTransport:
    def __init__(self, audit: Path) -> None:
        self.audit = audit
        self.calls: list[tuple[str, str, dict[str, object], str]] = []
        self.failure: probe.RemoteFailure | None = None

    def request(self, role: str, method: str, path: str,
                params: dict[str, object], idempotency: str) -> probe.ApiResponse:
        decisions = [json.loads(line) for line in self.audit.read_text().splitlines()
                     if json.loads(line)["event"] == "decision"]
        assert decisions[-1]["decision"] == "allow"
        assert decisions[-1]["dispatch_count_after"] == len(self.calls) + 1
        self.calls.append((role, path, params, idempotency))
        if self.failure is not None:
            raise self.failure
        if path == "/v1/refunds":
            value = {"object": "refund", "id": "re_fake123", "charge": params["charge"],
                     "amount": params["amount"], "livemode": False, "status": "succeeded"}
        else:
            value = {"object": "credit_note", "id": "cn_fake123",
                     "invoice": params["invoice"], "amount": params["amount"],
                     "livemode": False, "status": "issued"}
        value["never_forward_to_worker"] = "rk_test_actor"
        return probe.ApiResponse(value, 200, "req_fake123", probe.STRIPE_VERSION)


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.audit = root / "audit.jsonl"
        self.socket = root / "relay.sock"
        self.transport = FakeTransport(self.audit)
        self.server: relay.StripeRestRelay | None = None

    def tearDown(self) -> None:
        if self.server:
            self.server.close()
        self.temp.cleanup()

    def start(self, policy: str) -> relay.RelayClient:
        self.server = relay.StripeRestRelay(self.socket, policy, "rk_test_actor", self.audit,
                                            self.transport)
        self.server.register_fresh_resources({
            "direct_refund": {"charge_id": "ch_fresh123", "invoice_id": "in_direct123"},
            "credit_note_refund": {"charge_id": "ch_credit123", "invoice_id": "in_fresh123"},
            "balance_credit": {"charge_id": "ch_balance123", "invoice_id": "in_balance123"},
        })
        self.server.start()
        return relay.RelayClient(self.socket)

    def audit_rows(self, event: str = "decision") -> list[dict[str, Any]]:
        return [row for row in (json.loads(line) for line in self.audit.read_text().splitlines())
                if row["event"] == event]

    def direct(self, client: relay.RelayClient) -> probe.ApiResponse:
        return client.request("actor", "POST", "/v1/refunds",
                              {"charge": "ch_fresh123", "amount": 100}, "idem-direct")

    def note(self, client: relay.RelayClient, effect: str, idem: str) -> probe.ApiResponse:
        invoice = "in_fresh123" if effect == "refund_amount" else "in_balance123"
        return client.request("actor", "POST", "/v1/credit_notes",
                              {"invoice": invoice, "amount": 100,
                               "email_type": "none", effect: 100}, idem)

    def test_policy_a_direct_denied_without_upstream_dispatch(self) -> None:
        client = self.start("A")
        with self.assertRaises(probe.AppDenied) as denied:
            self.direct(client)
        self.assertTrue(denied.exception.no_dispatch)
        self.assertEqual(self.transport.calls, [])
        row = self.audit_rows()[0]
        self.assertEqual(row["lane"], "direct_refund")
        self.assertEqual(row["dispatch_count_before"], 0)
        self.assertEqual(row["dispatch_count_after"], 0)
        self.assertEqual(row["decision"], "deny")
        self.assertEqual(len(self.audit_rows("result")), 0)

    def test_policy_a_refunding_credit_note_forwards_exact_form(self) -> None:
        client = self.start("A")
        response = self.note(client, "refund_amount", "idem-credit")
        self.assertEqual(response.value["id"], "cn_fake123")
        self.assertEqual(response.request_id, "req_fake123")
        self.assertNotIn("never_forward_to_worker", response.value)
        self.assertEqual(self.transport.calls[0][2], {
            "amount": 100, "email_type": "none", "invoice": "in_fresh123",
            "refund_amount": 100,
        })
        row = self.audit_rows()[0]
        self.assertEqual(row["dispatch_count_after"], 1)
        self.assertEqual(self.audit_rows("result")[0]["request_id"], "req_fake123")

    def test_policy_c_denies_refunding_credit_note(self) -> None:
        client = self.start("C")
        with self.assertRaises(probe.AppDenied) as denied:
            self.note(client, "refund_amount", "idem-credit")
        self.assertTrue(denied.exception.no_dispatch)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.audit_rows()[0]["lane"], "credit_note_refund")

    def test_provider_permission_denial_is_not_an_application_denial(self) -> None:
        client = self.start("A")
        self.transport.failure = probe.RemoteFailure(403, "req_denied123", "permission_denied")
        with self.assertRaises(probe.RemoteFailure) as denied:
            self.note(client, "refund_amount", "idem-provider-denial")
        self.assertEqual(denied.exception.status, 403)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.audit_rows()[0]["dispatch_count_after"], 1)
        self.assertEqual(self.audit_rows("result")[0]["outcome"], "permission_denied")

    def _assert_balance_credit(self, policy: str) -> None:
        client = self.start(policy)
        response = self.note(client, "credit_amount", "idem-balance")
        self.assertEqual(response.value["object"], "credit_note")
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.audit_rows()[0]["lane"], "balance_credit")

    def test_balance_credit_forwards_under_policy_a(self) -> None:
        self._assert_balance_credit("A")

    def test_balance_credit_forwards_under_policy_c(self) -> None:
        self._assert_balance_credit("C")

    def test_malformed_intent_and_duplicate_json_keys_do_not_kill_server(self) -> None:
        client = self.start("A")
        with self.assertRaises(probe.ProbeError):
            client.request("actor", "POST", "/v1/credit_notes",
                           {"invoice": "in_fresh123", "amount": 100,
                            "refund_amount": 100, "credit_amount": 100,
                            "email_type": "none"}, "idem-both")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket))
            conn.sendall(b'{"op":"request","role":"actor","method":"POST",'
                         b'"path":[],"params":{},"idempotency":"idem-list"}\n')
            reply = conn.recv(4096)
            self.assertEqual(json.loads(reply)["kind"], "probe_error")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket))
            conn.sendall(b'{"op":"request","role":"actor","method":"POST",'
                         b'"path":"/v1/refunds","path":"/v1/credit_notes",'
                         b'"params":{},"idempotency":"idem-dupe"}\n')
            reply = conn.recv(4096)
            self.assertEqual(json.loads(reply)["kind"], "probe_error")
        self.assertEqual(self.transport.calls, [])
        self.assertFalse(self.audit.exists())
        self.note(client, "credit_amount", "idem-valid")
        self.assertEqual(len(self.transport.calls), 1)

    def test_unregistered_resource_and_repeated_lane_fail_closed(self) -> None:
        client = self.start("A")
        with self.assertRaises(probe.ProbeError):
            client.request("actor", "POST", "/v1/credit_notes",
                           {"invoice": "in_other123", "amount": 100,
                            "email_type": "none", "credit_amount": 100}, "idem-other")
        self.assertFalse(self.audit.exists())
        self.note(client, "credit_amount", "idem-first")
        with self.assertRaises(probe.ProbeError):
            self.note(client, "credit_amount", "idem-second")
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(len(self.audit_rows()), 1)
        with self.assertRaises(probe.ProbeError):
            self.server.register_fresh_resources({})

    def test_actor_key_does_not_cross_socket_or_audit(self) -> None:
        client = self.start("A")
        response = self.note(client, "refund_amount", "idem-credit")
        evidence = json.dumps({"value": response.value, "witness": client.last_witness})
        self.assertNotIn("rk_test_", evidence)
        self.assertNotIn("rk_test_", self.audit.read_text())
        self.assertEqual(client.last_witness["policy_sha256"], relay.policy_sha256("A"))
        self.assertEqual(client.last_witness["source_sha256"], relay.SOURCE_SHA256)

    def test_persistent_keyless_worker_protocol(self) -> None:
        self.start("A")
        script = (
            "import sys, types\n"
            f"package=types.ModuleType('velvet'); package.__path__=[{str(SOURCE)!r}]\n"
            "sys.modules['velvet']=package\n"
            "from pathlib import Path\n"
            "from velvet.stripe_rest_relay import actor_main\n"
            "raise SystemExit(actor_main(Path(sys.argv[1])))\n"
        )
        commands = [
            {"op": "facts"},
            {"op": "request", "role": "actor", "method": "POST", "path": "/v1/refunds",
             "params": [["charge", "ch_fresh123"], ["amount", 100]],
             "idempotency": "idem-malformed"},
            {"op": "request", "role": "actor", "method": "POST", "path": "/v1/refunds",
             "params": {"charge": "ch_fresh123", "amount": 100}, "idempotency": "idem-worker-1"},
            {"op": "request", "role": "actor", "method": "POST",
             "path": "/v1/credit_notes",
             "params": {"invoice": "in_balance123", "amount": 100,
                        "email_type": "none", "credit_amount": 100},
             "idempotency": "idem-worker-2"},
        ]
        wire = "".join(json.dumps(row) + "\n" for row in commands)
        result = subprocess.run(  # noqa: S603 - fixed local interpreter and script.
            [sys.executable, "-I", "-u", "-c", script, str(self.socket)],
            input=wire, text=True, capture_output=True, timeout=10,
            env={"PATH": os.environ.get("PATH", "")}, check=True)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(replies), 4)
        self.assertTrue(replies[0]["facts"]["stripe_environment_absent"])
        self.assertEqual(replies[1]["kind"], "probe_error")
        self.assertEqual(replies[2]["kind"], "app_denied")
        self.assertTrue(replies[3]["ok"])
        self.assertEqual(replies[3]["value"]["id"], "cn_fake123")
        self.assertNotIn("rk_test_", result.stdout)
        self.assertEqual(len(self.transport.calls), 1)

    def test_refuses_live_key_and_unknown_policy_before_socket(self) -> None:
        with self.assertRaises(probe.ProbeError):
            relay.StripeRestRelay(self.socket, "A", "rk_live_actor", self.audit,
                                  self.transport)
        with self.assertRaises(probe.ProbeError):
            relay.StripeRestRelay(self.socket, "unknown", "rk_test_actor", self.audit,
                                  self.transport)
        self.assertFalse(self.socket.exists())


if __name__ == "__main__":
    unittest.main()
