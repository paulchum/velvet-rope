"""Actual Rust proxy contract test with a local MCP protocol stub, NOT a Stripe run."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import socket
import subprocess  # nosec B404 - explicit repository-built binary, no shell.
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stripe_native_contract_test", ROOT / "src/velvet/stripe_shadowpath.py")
assert spec is not None and spec.loader is not None
sp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sp
spec.loader.exec_module(sp)


class Upstream(BaseHTTPRequestHandler):
    tool_calls = 0
    strict_session = False
    sse = False
    release_streams = threading.Event()
    protocol_version = "HTTP/1.1"

    def do_DELETE(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def do_POST(self) -> None:
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request.get("method")
        if self.headers.get("Authorization") != "Bearer offline-protocol-only":
            self.send_error(401)
            return
        if self.strict_session and method != "initialize" and (
            self.headers.get("MCP-Protocol-Version") != "2025-03-26"
            or self.headers.get("MCP-Session-Id") != "offline-session"
        ):
            self.send_error(400)
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        result: dict[str, Any]
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26" if self.strict_session else "2025-11-25",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "offline-protocol-stub", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "stripe_api_write", "inputSchema": {"type": "object"}}]}
            if self.strict_session and not request["params"].get("cursor"):
                result = {"tools": [], "nextCursor": "refund-page"}
        else:
            type(self).tool_calls += 1
            result = {"content": [{"type": "text", "text": "must not reach this handler"}]}
        body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if self.sse else "application/json")
        if method == "initialize" and self.strict_session:
            self.send_header("MCP-Session-Id", "offline-session")
        if not self.sse:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(b"data: " + body + b"\n\n" if self.sse else body)
        self.wfile.flush()
        if self.sse:
            # A terminal RPC response is sufficient; clients must not wait for EOF.
            self.release_streams.wait(35)


@unittest.skipUnless(os.environ.get("VELVET_STRIPE_PROXY_BIN"), "set compiled proxy binary path")
class NativeProxyTest(unittest.TestCase):
    def test_real_proxy_denies_without_invoking_upstream_tool(self) -> None:
        self.run_contract()

    def test_negotiated_stateful_paginated_inventory(self) -> None:
        self.run_contract(strict=True)

    def test_sse_initialize_inventory_without_waiting_for_eof(self) -> None:
        self.run_contract(strict=True, sse=True)

    def run_contract(self, *, strict: bool = False, sse: bool = False) -> None:
        binary = Path(os.environ["VELVET_STRIPE_PROXY_BIN"]).resolve()
        self.assertTrue(binary.is_file(), "configured binary must exist; never silently skip")
        Upstream.tool_calls = 0
        Upstream.strict_session = strict
        Upstream.sse = sse
        Upstream.release_streams.clear()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            config = json.loads((ROOT / "examples/shadowpath/stripe/proxy.json").read_text())
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            config["upstream"]["endpoint"] = f"http://127.0.0.1:{server.server_port}/mcp"
            config["http"]["allow_plaintext_loopback_upstream"] = True
            config["http"]["bind"] = f"127.0.0.1:{port}"
            for name in ("ledger_path", "thread_path", "inventory_path", "approval_requests_path",
                         "evidence_pack_path"):
                config[name] = str(output / (name + ".jsonl"))
            path = output / "proxy.json"
            path.write_text(json.dumps(config))
            token = secrets.token_hex(24)
            env = {**os.environ, "VELVET_STRIPE_GATEWAY_TOKEN": token,
                   "VELVET_STRIPE_MCP_KEY": "offline-protocol-only",
                   "VELVET_OAP_ED25519_PRIVATE_KEY": secrets.token_hex(32),
                   "VELVET_MAXDE_ED25519_PRIVATE_KEY": secrets.token_hex(32)}
            log = output / "proxy.log"
            with log.open("w") as handle:
                process = subprocess.Popen(  # noqa: S603  # nosec B603
                    [str(binary), "--config", str(path)], cwd=ROOT, env=env,
                    stdout=handle, stderr=handle)
            try:
                deadline = time.monotonic() + 30
                client = sp.Mcp(f"http://127.0.0.1:{port}/mcp", token, sp.Transport(timeout=1))
                while True:
                    if process.poll() is not None:
                        self.fail("proxy exited: " + log.read_text())
                    try:
                        client.initialize()
                        break
                    except sp.ProbeError:
                        if time.monotonic() > deadline:
                            self.fail("proxy did not initialize: " + log.read_text())
                        time.sleep(0.1)
                response = client.call("stripe_api_write", {
                    "stripe_api_operation_id": "PostRefunds",
                    "parameters": {"charge": "ch_offline", "amount": 100},
                })
                self.assertTrue(sp.denied_by_velvet(response), json.dumps(response))
                self.assertEqual(Upstream.tool_calls, 0)
                self.assertTrue(Path(config["ledger_path"]).exists())
                inventory = json.loads(Path(config["inventory_path"]).read_text())
                entry = next(e for e in inventory["entries"].values()
                             if e["name"] == "stripe_api_write")
                self.assertIsNotNone(entry["schema_hash"],
                                     "target must be discovered from upstream")
            finally:
                Upstream.release_streams.set()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
