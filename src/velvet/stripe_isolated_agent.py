"""Credential-free worker for the opt-in Stripe isolation measurement (stdlib only).

The container restrictions are enforced by Docker, not by this cooperative worker.
Commands and the gateway token arrive on private stdin, never argv or environment.
"""
from __future__ import annotations

import errno
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path
from typing import Any

MAX_BYTES = 2 * 1024 * 1024
SOCKET = "/gateway/mcp.sock"
BLOCKED = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM}


class UnixHttp(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


class StripeHttp(http.client.HTTPSConnection):
    def __init__(self, address: str) -> None:
        super().__init__("api.stripe.com", timeout=3)
        self.address = address
        self.tcp_connected = False

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), timeout=3)
        self.tcp_connected = True
        try:
            self.sock = ssl.create_default_context().wrap_socket(
                raw, server_hostname="api.stripe.com")
        except BaseException:
            raw.close()
            raise


def runtime_facts() -> dict[str, Any]:
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    interfaces = sorted(name for _, name in socket.if_nameindex())
    active = [name for name in interfaces
              if int(Path("/sys/class/net", name, "flags").read_text().strip(), 16) & 1]
    return {
        "uid": os.getuid(), "no_new_privileges": status.get("NoNewPrivs", "").strip() == "1",
        "capabilities_empty": all(int(status.get(key, "1").strip(), 16) == 0
                                  for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
        "interfaces": interfaces, "active_interfaces": active,
        "stripe_environment_absent": not any("STRIPE" in key for key in os.environ),
        "docker_socket_absent": not any(Path(path).exists() for path in (
            "/var/run/docker.sock", "/run/docker.sock")),
    }


def rpc(command: dict[str, Any]) -> dict[str, Any]:
    connection = UnixHttp("velvet", timeout=45)
    try:
        connection.request(command.get("method", "POST"), command.get("path", "/mcp"),
                           json.dumps(command["payload"]).encode(), command["headers"])
        response = connection.getresponse()
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("response_limit")
        return {"status": response.status,
                "headers": {key.lower(): value for key, value in response.getheaders()
                            if key.lower() in {"content-type", "mcp-session-id"}},
                "response": json.loads(raw) if raw else {}}
    finally:
        connection.close()


def probe(command: dict[str, Any]) -> dict[str, Any]:
    addresses = command["addresses"]
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 8:
        raise ValueError("numeric_addresses_required")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("public_stripe_address_required")
    rows = []
    for address in ["api.stripe.com", *addresses]:
        connection = StripeHttp(address)
        row: dict[str, Any] = {"address": address, "connected": False}
        try:
            # A real unauthenticated request, not the Stripe client's missing-key guard.
            connection.request("POST", "/v1/refunds", urllib.parse.urlencode({
                "charge": command["charge"], "amount": command["amount"]}), {
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": command["operation"],
            })
            row["connected"] = True
            row["http_status"] = connection.getresponse().status
        except (OSError, http.client.HTTPException) as error:
            row["errno"] = error.errno if isinstance(error, OSError) else None
            row["os_network_denial"] = row["errno"] in BLOCKED
            row["error_type"] = type(error).__name__
        finally:
            row["connected"] = connection.tcp_connected
            connection.close()
        rows.append(row)
    try:
        facts = runtime_facts()
    except OSError:
        facts = {}  # Earlier connectivity evidence must survive a later runtime read failure.
    return {"runtime": facts, "attempts": rows}


def main() -> None:
    while True:
        line = sys.stdin.buffer.readline(MAX_BYTES + 1)
        if not line:
            return
        try:
            if len(line) > MAX_BYTES or not line.endswith(b"\n"):
                raise ValueError("command_limit")
            command = json.loads(line)
            operation = command["op"]
            if operation == "facts":
                result = runtime_facts()
            elif operation == "rpc":
                result = rpc(command)
            elif operation == "probe":
                result = probe(command)
            else:
                raise ValueError("unknown_operation")
            print(json.dumps({"ok": True, "result": result}), flush=True)
        except Exception as error:
            # Do not echo commands, headers, provider bodies or exception messages.
            print(json.dumps({"ok": False, "error_type": type(error).__name__}), flush=True)


if __name__ == "__main__":
    main()
