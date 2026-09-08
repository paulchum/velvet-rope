"""Offline isolation regressions. These tests do not establish Stripe provider outcomes."""
from __future__ import annotations

import copy
import errno
import importlib.util
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


iso = load("stripe_isolation_test", ROOT / "src/velvet/stripe_isolated.py")
worker = load("stripe_worker_test", ROOT / "src/velvet/stripe_isolated_agent.py")
fixture = load("stripe_fixture_isolation", ROOT / "tests/test_stripe_shadowpath.py")
sp = iso.sp
fixture.sp = sp


class Boundary:
    def __init__(self, transport: Any, behavior: str) -> None:
        self.transport = transport
        self.behavior = behavior
        self.evidence: dict[str, Any] = {"verified": True}

    def verify_mcp(self, request: Any, response: Any) -> bool:
        return self.behavior != "missing_witness"

    def attempt(self, charge: str, amount: int, operation: str) -> dict[str, Any]:
        assert charge == "ch_protected" and amount == 100 and operation.endswith("isolated-rest")
        self.transport.direct_sent = True
        if self.behavior in {"breach_error", "pending_error"}:
            self.transport.refund(charge, "succeeded" if self.behavior == "breach_error"
                                  else "pending")
            raise OSError("worker transport disappeared")
        if self.behavior == "dispatch_error":
            raise sp.ProbeError("agent unavailable")
        if self.behavior == "observer_error":
            self.transport.immediate_observer_error = True
        return {"network_blocked": self.behavior == "blocked",
                "unexpected_connectivity": self.behavior == "connected"}


class ClassificationTests(unittest.TestCase):
    def run_probe(self, behavior: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as directory:
            transport = fixture.FakeTransport()
            boundary = Boundary(transport, behavior)
            settings = sp.Settings("http://127.0.0.1:8791/mcp", Path(directory) / "run",
                                   control_charge="ch_control", protected_charge="ch_protected",
                                   observe_seconds=1, poll_seconds=0.5)
            clock = fixture.Clock()
            with patch.object(sp.time, "monotonic", clock.monotonic), \
                    patch.object(sp.time, "sleep", clock.sleep):
                result: dict[str, Any] = sp.Probe(
                    settings, fixture.ENV, transport, boundary=boundary).run()
            self.assertEqual(result, json.loads((settings.output / "result.json").read_text()))
            return result

    def test_isolation_is_separate_from_old_agent_key_model(self) -> None:
        result = self.run_probe("blocked")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["summary"]["measurement_complete"])
        self.assertEqual(result["control_path"], "stripe_mcp_direct")
        self.assertEqual(result["summary"]["access_model"],
                         "isolated_agent_without_stripe_authority")
        self.assertEqual(result["phases"][-1]["name"], "isolated_rest")

    def test_unexpected_connectivity_is_failure_even_without_refunds(self) -> None:
        result = self.run_probe("connected")
        self.assertEqual(result["exit_code"], 5)
        self.assertEqual(result["summary"]["effect_breach_count"], 0)
        self.assertEqual(result["summary"]["overall_verdict"], "ISOLATION_FAILURE")

    def test_breach_survives_os_error_and_observation_continues(self) -> None:
        result = self.run_probe("breach_error")
        self.assertEqual(result["exit_code"], 3)
        phase = result["phases"][-1]
        self.assertIn("dispatch_error", phase)
        self.assertGreaterEqual(len(phase["observations"]), 3)
        self.assertEqual(phase["refunds"][0]["status"], "succeeded")

    def test_pending_errors_and_missing_witness_never_pass(self) -> None:
        for behavior in ("pending_error", "dispatch_error", "observer_error",
                         "missing_witness", "dns_failure"):
            with self.subTest(behavior=behavior):
                result = self.run_probe(behavior)
                self.assertEqual(result["exit_code"], 4)
                self.assertFalse(result["summary"]["measurement_complete"])
                if behavior != "missing_witness":
                    self.assertGreaterEqual(len(result["phases"][-1]["observations"]), 3)


class InspectionTests(unittest.TestCase):
    def inspection(self) -> dict[str, Any]:
        return {"Id": "container", "Image": "image", "Config": {
            "User": "65532:65532", "Env": ["PATH=/usr/bin"],
            "Entrypoint": ["python", "-I", "-u", "/app/agent.py"], "Cmd": None},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                           "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                           "IpcMode": "private", "PidsLimit": 32, "Memory": 134217728,
                           "NanoCpus": 500000000, "LogConfig": {"Type": "none"}},
            "Mounts": [{"Type": "bind", "Source": "/gateway-socket",
                        "Destination": "/gateway", "RW": False}]}

    def test_host_credentials_privileges_network_and_mounts_rejected(self) -> None:
        baseline = self.inspection()
        self.assertTrue(iso.inspect_boundary(
            baseline, "image", Path("/gateway-socket"))["verified"])
        mutations = [
            ("Config", "User", "0"), ("Config", "Env", ["VELVET_STRIPE_MCP_KEY=not-a-secret"]),
            ("HostConfig", "NetworkMode", "bridge"), ("HostConfig", "PidMode", "host"),
            ("HostConfig", "Privileged", True), ("HostConfig", "CapAdd", ["NET_ADMIN"]),
            ("HostConfig", "ReadonlyRootfs", False), ("HostConfig", "SecurityOpt", []),
            ("HostConfig", "LogConfig", {"Type": "json-file"}),
        ]
        for group, key, value in mutations:
            with self.subTest(key=key):
                raw = copy.deepcopy(baseline)
                raw[group][key] = value
                self.assertFalse(iso.inspect_boundary(raw, "image", Path("/gateway-socket"))[
                    "verified"])
        raw = copy.deepcopy(baseline)
        raw["Mounts"].append({"Destination": "/var/run/docker.sock"})
        self.assertFalse(iso.inspect_boundary(raw, "image", Path("/gateway-socket"))["verified"])

    def test_docker_child_environment_drops_all_stripe_credentials(self) -> None:
        with patch.dict(iso.os.environ, fixture.ENV):
            self.assertFalse(any("STRIPE" in key for key in iso.docker_env()))

    def test_worker_attempts_real_network_without_authorization_header(self) -> None:
        headers: list[str] = []
        original = worker.StripeHttp.putheader

        def capture(connection: Any, name: str, *values: Any) -> None:
            headers.append(name.lower())
            original(connection, name, *values)

        with patch.object(worker, "runtime_facts", return_value={}), \
                patch.object(worker.StripeHttp, "putheader", capture), \
                patch.object(worker.socket, "create_connection",
                             side_effect=OSError(errno.ENETUNREACH, "offline")) as connect:
            result = worker.probe({"addresses": ["1.1.1.1"], "charge": "ch_offline",
                                   "amount": 100, "operation": "offline-operation"})
        self.assertEqual(connect.call_count, 2)
        self.assertNotIn("authorization", headers)
        self.assertTrue(all(row["os_network_denial"] for row in result["attempts"]))

    def test_connection_evidence_survives_http_and_runtime_errors(self) -> None:
        def connected_then_error(connection: Any, *args: Any, **kwargs: Any) -> None:
            connection.tcp_connected = True
            raise worker.http.client.BadStatusLine("untrusted provider text")

        with patch.object(worker.StripeHttp, "request", connected_then_error), \
                patch.object(worker, "runtime_facts", side_effect=OSError("runtime unavailable")):
            result = worker.probe({"addresses": ["1.1.1.1"], "charge": "ch_offline",
                                   "amount": 100, "operation": "offline-operation"})
        self.assertTrue(all(row["connected"] for row in result["attempts"]))
        self.assertEqual(result["runtime"], {})
        self.assertNotIn("untrusted provider text", json.dumps(result))


class RelayTests(unittest.TestCase):
    def test_fixed_destination_and_transport_failure_is_not_denial(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vr-") as directory:
            path = Path(directory) / "s"
            relay = iso.Relay(path, "http://127.0.0.1:1/mcp")
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
            try:
                for method, target, extra in (
                    ("CONNECT", "api.stripe.com:443", ""),
                    ("POST", "https://api.stripe.com/v1/refunds", ""),
                    ("POST", "/mcp?target=api.stripe.com", ""),
                    ("POST", "/mcp", "Transfer-Encoding: chunked\r\n"),
                    ("POST", "/mcp", "Upgrade: websocket\r\n"),
                    ("POST", "/mcp", "Content-Length: 2\r\n"),
                ):
                    with self.subTest(method=method, target=target, extra=extra):
                        with socket.socket(socket.AF_UNIX) as client:
                            client.settimeout(3)
                            client.connect(str(path))
                            client.sendall((f"{method} {target} HTTP/1.1\r\nHost: attacker\r\n"
                                            f"Content-Type: application/json\r\n{extra}"
                                            "Content-Length: 2\r\n\r\n{}").encode())
                            self.assertNotIn(b" 200 ", client.recv(4096).split(b"\r\n")[0])
                self.assertEqual(relay.witnesses, [])
                with patch.object(worker, "SOCKET", str(path)):
                    with self.assertRaises(ValueError):
                        worker.rpc({"payload": {"jsonrpc": "2.0", "id": "offline",
                                                "method": "tools/call", "params": {}},
                                    "headers": {"Content-Type": "application/json"}})
                self.assertNotIn("response_hash", relay.witnesses[-1])
            finally:
                relay.shutdown()
                relay.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
