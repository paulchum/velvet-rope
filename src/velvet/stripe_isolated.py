"""Trusted Linux launcher for Stripe's gateway-only, credential-free agent measurement.

Build before granting provider credentials. Run only on a trusted Linux Docker host.
Source-only use: python -I src/velvet/stripe_isolated.py --help
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import selectors
import shutil
import socket
import socketserver
import subprocess  # nosec B404 - fixed executables, argument lists, no shell.
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import IO, Any, cast

ROOT = Path(__file__).resolve().parents[2]
AGENT = Path(__file__).with_name("stripe_isolated_agent.py")
spec = importlib.util.spec_from_file_location(
    "velvet_stripe_provider", Path(__file__).with_name("stripe_shadowpath.py"))
assert spec is not None and spec.loader is not None
sp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sp
spec.loader.exec_module(sp)
Json = dict[str, Any]
MAX_BYTES = 2 * 1024 * 1024
IMAGE_TAG = "velvet-stripe-isolated:local"


def docker_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in {
        "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"}}


def docker(*args: str, timeout: float = 30) -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise sp.ProbeError("Docker is required; no unisolated fallback")
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [executable, *args], env=docker_env(), capture_output=True,
            timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise sp.ProbeError("Docker operation failed; output withheld") from None
    if result.returncode:
        raise sp.ProbeError("Docker operation failed; no unisolated fallback")
    return result.stdout.decode()


def build_image() -> str:
    # No broad COPY: the build context contains only these two reviewed files.
    with tempfile.TemporaryDirectory(prefix="velvet-agent-build-") as directory:
        context = Path(directory)
        shutil.copyfile(AGENT, context / AGENT.name)
        shutil.copyfile(ROOT / "examples/shadowpath/stripe/isolated.Dockerfile",
                        context / "Dockerfile")
        docker("build", "--quiet", "--label", "org.velvet.agent.sha256=" +
               hashlib.sha256(AGENT.read_bytes()).hexdigest(), "--tag", IMAGE_TAG,
               str(context), timeout=240)
    return docker("image", "inspect", IMAGE_TAG, "--format", "{{.Id}}").strip()


class Relay(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, target: str) -> None:
        # Fixed target is selected by the trusted launcher, never by the agent.
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+/mcp", target):
            raise sp.ProbeError("relay must target the fixed loopback Rust endpoint")
        self.target = target
        self.witnesses: list[Json] = []
        self.transport_errors = 0
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(str(path), RelayHandler)
        path.chmod(0o666)  # noqa: S103 - socket alone inside a private, narrowly mounted directory.

    def process_request(self, request: socket.socket | tuple[bytes, socket.socket],
                        client_address: Any) -> None:
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: socket.socket | tuple[bytes, socket.socket],
                               client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Do not emit tracebacks with untrusted request/provider text into credentialed logs.
        self.transport_errors += 1


class RelayHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(45)

    def do_POST(self) -> None:
        relay = cast(Relay, self.server)
        if (self.path != "/mcp" or self.headers.get("Transfer-Encoding")
                or self.headers.get("Upgrade")
                or len(self.headers.get_all("Content-Length", [])) != 1
                or self.headers.get("Content-Type") != "application/json"):
            self.send_error(400)
            return
        try:
            size = int(self.headers["Content-Length"])
            if not 0 < size <= MAX_BYTES:
                raise ValueError("request_limit")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("request_truncated")
            request = sp.obj(json.loads(raw))
            if (request.get("method") not in {"initialize", "notifications/initialized",
                                              "tools/list", "tools/call"}
                    or len(relay.witnesses) >= 256):
                raise ValueError("relay_protocol_or_request_limit")
            identifier = request.get("id")
            witness = {"received_at": sp.now(), "rpc_id": identifier,
                       "request_hash": sp.digest(request), "target": relay.target,
                       "method": request.get("method")}
            relay.witnesses.append(witness)
            headers = {key: value for key, value in self.headers.items() if key.lower() in {
                "authorization", "content-type", "accept", "mcp-session-id",
                "mcp-protocol-version"}}
            response, meta = sp.Transport(timeout=35).request(
                "POST", relay.target, headers, raw, rpc_id=identifier,
                notification=identifier is None)
            witness.update({"responded_at": sp.now(), "response_hash": sp.digest(response),
                            "admission": sp.response_evidence(response)})
            body = json.dumps(response).encode() if identifier is not None else b""
            self.send_response(200 if identifier is not None else 202)
            for key in ("mcp-session-id",):
                if key in meta:
                    self.send_header(key, meta[key])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (sp.ProbeError, OSError, ValueError, TypeError):
            # Upstream failure is a transport failure, never a manufactured admission denial.
            self.send_error(502, "Gateway transport unavailable")


def inspect_boundary(raw: Json, image: str, socket_directory: Path) -> Json:
    config, host = raw["Config"], raw["HostConfig"]
    mounts = raw["Mounts"]
    checks = {
        "image_pinned": raw["Image"] == image,
        "nonroot": config["User"] == "65532:65532",
        "network_none": host["NetworkMode"] == "none" and
            set(raw.get("NetworkSettings", {}).get("Networks", {})) <= {"none"},
        "read_only_root": host["ReadonlyRootfs"] is True,
        "not_privileged": host["Privileged"] is False,
        "no_capabilities": host["CapDrop"] == ["ALL"] and not host.get("CapAdd"),
        "no_new_privileges": "no-new-privileges" in host["SecurityOpt"],
        "private_namespaces": host.get("PidMode", "") == "" and
            host.get("IpcMode") == "private" and host.get("UTSMode", "") == "",
        "no_devices": not host.get("Devices") and not host.get("DeviceRequests"),
        "bounded_resources": host["PidsLimit"] == 32 and host["Memory"] == 134217728
            and host["NanoCpus"] == 500000000,
        "no_container_logs": host["LogConfig"]["Type"] == "none",
        "only_socket_mount": len(mounts) == 1 and mounts[0]["Type"] == "bind"
            and mounts[0]["Source"] == str(socket_directory.resolve())
            and mounts[0]["Destination"] == "/gateway" and mounts[0]["RW"] is False,
        "credential_free_environment": all(entry.split("=", 1)[0] in {
            "PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}
            for entry in config.get("Env", [])),
        "fixed_entrypoint": config["Entrypoint"] == ["python", "-I", "-u", "/app/agent.py"]
            and not config.get("Cmd"),
    }
    return {"source": "trusted_host_docker_inspect", "inspected_at": sp.now(),
            "image_id": image, "container_id": raw["Id"], "checks": checks,
            "verified": all(checks.values())}


def runtime_verified(facts: Json) -> bool:
    return (facts.get("uid") == 65532 and facts.get("active_interfaces") == ["lo"]
            and all(facts.get(key) is True for key in (
                "no_new_privileges", "capabilities_empty", "stripe_environment_absent",
                "docker_socket_absent")))


class IsolatedAgent:
    def __init__(self, directory: Path, gateway: str, image: str) -> None:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise sp.ProbeError("an immutable Docker image ID is required")
        self.image = image
        self.directory = directory
        self.relay = Relay(directory / "mcp.sock", gateway)
        self.thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        self.thread.start()
        self.container: str | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.evidence: Json = {"verified": False, "relay_requests": self.relay.witnesses}
        self.gateway = gateway

    def start(self) -> None:
        metadata = json.loads(docker("image", "inspect", self.image))[0]
        code_hash = hashlib.sha256(AGENT.read_bytes()).hexdigest()
        if metadata["Config"]["Labels"].get("org.velvet.agent.sha256") != code_hash:
            raise sp.ProbeError("agent image does not match the reviewed source")
        self.container = docker(
            "create", "--interactive", "--network", "none", "--user", "65532:65532",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--ipc", "private", "--pids-limit", "32", "--memory", "128m", "--cpus", "0.5",
            "--log-driver", "none", "--mount",
            f"type=bind,src={self.directory.resolve()},dst=/gateway,readonly", self.image).strip()
        if not re.fullmatch(r"[a-f0-9]{64}", self.container):
            raise sp.ProbeError("invalid container identity")
        self.check_inspection()
        executable = shutil.which("docker")
        if executable is None:
            raise sp.ProbeError("Docker executable disappeared")
        self.process = subprocess.Popen(  # noqa: S603  # nosec B603
            [executable, "start", "--attach", "--interactive", self.container],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=docker_env(), bufsize=0)
        facts = self.command({"op": "facts"})
        if not runtime_verified(facts):
            raise sp.ProbeError("agent runtime isolation failed")
        self.evidence["runtime"] = facts
        self.evidence["agent_source_sha256"] = code_hash

    def check_inspection(self) -> None:
        if self.container is None:
            raise sp.ProbeError("agent not created")
        inspection = inspect_boundary(json.loads(docker("inspect", self.container))[0],
                                      self.image, self.directory)
        self.evidence.update(inspection)
        if not inspection["verified"]:
            raise sp.ProbeError("trusted Docker inspection did not establish isolation")

    def command(self, request: Json) -> Json:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise sp.ProbeError("isolated agent unavailable")
        try:
            self.process.stdin.write(json.dumps(request).encode() + b"\n")
            self.process.stdin.flush()
            response = self.read_line(self.process.stdout)
            data = sp.obj(json.loads(response))
            if data.get("ok") is not True:
                raise sp.ProbeError("isolated agent command failed; output withheld")
            return cast(Json, sp.obj(data.get("result")))
        except (OSError, ValueError) as error:
            raise sp.ProbeError(
                "isolated agent transport failed: " + type(error).__name__) from None

    @staticmethod
    def read_line(stream: IO[bytes]) -> bytes:
        deadline = time.monotonic() + 55
        result = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(stream, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > MAX_BYTES:
                    raise sp.ProbeError("isolated agent response exceeds limit")
                if b"\n" in result:
                    if not result.endswith(b"\n") or result.count(b"\n") != 1:
                        raise sp.ProbeError("isolated agent response framing failed")
                    return bytes(result)
        raise sp.ProbeError("isolated agent response missing or timed out")

    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None = None, *, rpc_id: object = None,
                notification: bool = False) -> tuple[Json, Mapping[str, str]]:
        if method != "POST" or url != self.gateway or body is None:
            raise sp.ProbeError("agent transport only supports the fixed MCP gateway")
        result = self.command({"op": "rpc", "payload": json.loads(body), "headers": dict(headers)})
        if result.get("status") not in ({200, 202, 204} if notification else {200}):
            raise sp.ProbeError("isolated gateway HTTP request failed")
        response = sp.obj(result.get("response"))
        if not notification and (response.get("id") != rpc_id or response.get("jsonrpc") != "2.0"):
            raise sp.ProbeError("isolated gateway RPC identity mismatch")
        return response, sp.obj(result.get("headers"))

    def verify_mcp(self, request: Json, response: Json) -> bool:
        return any(row.get("request_hash") == sp.digest(request)
                   and row.get("response_hash") == response.get("response_hash")
                   and row.get("rpc_id") == request.get("id")
                   and row.get("method") == "tools/call" for row in self.relay.witnesses)

    def attempt(self, charge: str, amount: int, operation: str) -> Json:
        self.check_inspection()
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(
            "api.stripe.com", 443, type=socket.SOCK_STREAM)})
        if not 1 <= len(addresses) <= 8:
            raise sp.ProbeError("bounded Stripe address resolution failed")
        raw = self.command({"op": "probe", "addresses": addresses, "charge": charge,
                            "amount": amount, "operation": operation})
        facts = sp.obj(raw.get("runtime"))
        rows = raw.get("attempts")
        if (not runtime_verified(facts) or not isinstance(rows, list)
                or not all(isinstance(row, dict) for row in rows)
                or [row.get("address") for row in rows] != ["api.stripe.com", *addresses]):
            raise sp.ProbeError("isolated network evidence malformed")
        # Whitelist agent-produced fields; no headers, response bodies or free-form messages.
        clean = [{"address": row["address"], "connected": row.get("connected") is True,
                  "os_network_denial": row.get("os_network_denial") is True,
                  "errno": row.get("errno") if type(row.get("errno")) is int else None,
                  "http_status": row.get("http_status")
                  if type(row.get("http_status")) is int else None} for row in rows]
        unexpected = any(row["connected"] or row["http_status"] is not None for row in clean)
        blocked = not unexpected and all(row["os_network_denial"] for row in clean[1:])
        return {"observed_at": sp.now(), "credential": "none", "dns_source": "trusted_host",
                "runtime_verified": True, "attempts": clean,
                "unexpected_connectivity": unexpected,
                "network_blocked": blocked, "docker_inspection_verified": True}

    def close(self) -> None:
        if self.container is not None:
            docker("rm", "--force", self.container)
        if self.process is not None:
            self.process.wait(timeout=10)
            for stream in (self.process.stdin, self.process.stdout):
                if stream:
                    stream.close()
        self.relay.shutdown()
        self.relay.server_close()
        self.thread.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build-image")
    run = commands.add_parser("run")
    run.add_argument("--gateway", default="http://127.0.0.1:8791/mcp")
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--image", required=True)
    run.add_argument("--allow-test-writes", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build-image":
            print(build_image())
            return 0
        if platform.system() != "Linux":
            raise sp.ProbeError("hosted isolation measurement requires a Linux Docker host")
        if not args.allow_test_writes:
            raise sp.ProbeError("run requires --allow-test-writes")
        if os.environ.get("VELVET_STRIPE_AGENT_KEY"):
            raise sp.ProbeError("isolated mode must not receive the adversarial agent Stripe key")
        with tempfile.TemporaryDirectory(prefix="velvet-gateway-") as directory:
            mount = Path(directory) / "socket"
            mount.mkdir(mode=0o755)
            agent = IsolatedAgent(mount, args.gateway, args.image)
            try:
                agent.start()
                settings = sp.Settings(args.gateway, args.output_dir, provision=True)
                probe = sp.Probe(settings, os.environ, gateway_transport=agent, boundary=agent)
                result = probe.run()
                print(json.dumps({"result": str(args.output_dir / "result.json"),
                                  **result["summary"], "exit_code": result["exit_code"]}))
                return int(result["exit_code"])
            finally:
                agent.close()
    except (sp.ProbeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "INDETERMINATE", "error_type": type(error).__name__}))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
