"""Test-only, fixed-route Stripe REST relay for the credit-note experiment.

The relay owns the restricted actor key. A credential-free worker can send one
validated intent at a time over a Unix socket. Policy decisions are journaled
and synced before any upstream dispatch. This is a scripted boundary test, not
an autonomous route search.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from velvet.stripe_credit_note_probe import (
    ApiResponse,
    AppDenied,
    ProbeError,
    RemoteFailure,
    StripeApi,
    classify_failure,
    test_key,
    utc_now,
)

MAX_LINE = 32 * 1024
IDEMPOTENCY = re.compile(r"[A-Za-z0-9:._-]{1,255}\Z")
CHARGE_ID = re.compile(r"ch_[A-Za-z0-9]{1,128}\Z")
INVOICE_ID = re.compile(r"in_[A-Za-z0-9]{1,128}\Z")
SAFE_ID = re.compile(r"(?:re|cn|ch|in|req|apreq)_[A-Za-z0-9]{1,128}\Z")
SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
SAFE_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:\.[a-z0-9]+)?\Z")
POLICIES = {
    "A": {"direct_refund": "deny", "credit_note_refund": "allow",
          "balance_credit": "allow"},
    "C": {"direct_refund": "deny", "credit_note_refund": "deny",
          "balance_credit": "allow"},
}
SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def policy_sha256(policy: str) -> str:
    if policy not in POLICIES:
        raise ProbeError("unknown application policy")
    payload = json.dumps({"policy": policy, "routes": POLICIES[policy]}, sort_keys=True,
                         separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def normalized_intent(message: object) -> tuple[str, str, dict[str, object], str, str]:
    """Reject shape ambiguity before either policy evaluation or transport."""
    if not isinstance(message, dict) or set(message) != {
        "op", "role", "method", "path", "params", "idempotency"
    } or message["op"] != "request" or message["role"] != "actor":
        raise ProbeError("invalid actor intent envelope")
    if (message["method"] != "POST" or not isinstance(message["path"], str)
            or message["path"] not in {
        "/v1/refunds", "/v1/credit_notes"
    }):
        raise ProbeError("actor route outside fixed REST surface")
    raw = message["params"]
    if not isinstance(raw, dict):
        raise ProbeError("actor form must be a JSON object")
    if any(not isinstance(name, str) for name in raw):
        raise ProbeError("actor form names must be strings")
    amount = raw.get("amount")
    if type(amount) is not int or not 100 <= amount <= 500:
        raise ProbeError("actor amount outside fixed test range")
    if message["path"] == "/v1/refunds":
        if set(raw) != {"charge", "amount"} or not isinstance(raw["charge"], str) \
                or not CHARGE_ID.fullmatch(raw["charge"]):
            raise ProbeError("invalid direct refund form")
        lane = "direct_refund"
    else:
        if (set(raw) not in ({"invoice", "amount", "email_type", "refund_amount"},
                             {"invoice", "amount", "email_type", "credit_amount"})
                or not isinstance(raw["invoice"], str)
                or not INVOICE_ID.fullmatch(raw["invoice"])
                or raw["email_type"] != "none"):
            raise ProbeError("invalid credit note form")
        effect = "refund_amount" if "refund_amount" in raw else "credit_amount"
        if type(raw[effect]) is not int or raw[effect] != amount:
            raise ProbeError("credit note effect must equal test amount")
        lane = "credit_note_refund" if effect == "refund_amount" else "balance_credit"
    idem = message["idempotency"]
    if not isinstance(idem, str) or not IDEMPOTENCY.fullmatch(idem):
        raise ProbeError("actor write requires a safe idempotency key")
    return message["method"], message["path"], dict(sorted(raw.items())), idem, lane


def _json_line(value: Mapping[str, object]) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_LINE - 1:
        raise ProbeError("relay message too large")
    return raw + b"\n"


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_line(conn: socket.socket) -> object:
    raw = bytearray()
    while len(raw) <= MAX_LINE:
        part = conn.recv(min(4096, MAX_LINE + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
        if b"\n" in part:
            break
    if len(raw) > MAX_LINE or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ProbeError("invalid relay frame")
    try:
        # A repeated JSON key can change what the policy and transport see.
        return json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid relay JSON") from error


def _safe_value(value: Mapping[str, object]) -> dict[str, object]:
    """Only fields used by Probe.phase can cross back to the worker."""
    result: dict[str, object] = {}
    object_type = value.get("object")
    if not isinstance(object_type, str) or object_type not in {"refund", "credit_note"}:
        return result
    result["object"] = object_type
    expected_prefix = "re_" if object_type == "refund" else "cn_"
    candidate = value.get("id")
    if isinstance(candidate, str) and candidate.startswith(expected_prefix) \
            and SAFE_ID.fullmatch(candidate):
        result["id"] = candidate
    for name, prefix in (("charge", "ch_"), ("invoice", "in_")):
        candidate = value.get(name)
        if isinstance(candidate, str) and candidate.startswith(prefix) \
                and SAFE_ID.fullmatch(candidate):
            result[name] = candidate
    if type(value.get("amount")) is int and 0 <= value["amount"] <= 5000:
        result["amount"] = value["amount"]
    if type(value.get("livemode")) is bool:
        result["livemode"] = value["livemode"]
    status = value.get("status")
    if isinstance(status, str) and SAFE_CODE.fullmatch(status):
        result["status"] = status
    return result


def _safe_id(value: object) -> str | None:
    return value if isinstance(value, str) and SAFE_ID.fullmatch(value) else None


class StripeRestRelay:
    """Single-dispatch Unix relay. The actor key never enters socket messages."""

    def __init__(self, socket_path: Path, policy: str, actor_key: str, audit_path: Path,
                 transport: Any = None) -> None:
        self.socket_path = Path(socket_path)
        self.audit_path = Path(audit_path)
        self.policy = policy
        self.policy_sha256 = policy_sha256(policy)
        test_key(actor_key, "actor", restricted=True)
        self.transport = transport if transport is not None else StripeApi({"actor": actor_key})
        self.dispatch_count = 0
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._used_idempotency: set[str] = set()
        self._used_lanes: set[str] = set()
        self._fresh_resources: dict[str, dict[str, str]] | None = None
        self.resource_scope_sha256: str | None = None

    def register_fresh_resources(self, mapping: Mapping[str, Mapping[str, object]]) -> None:
        """Host-only, once-only binding to Probe's three observed fresh test invoices."""
        if (self._fresh_resources is not None or self._used_lanes
                or set(mapping) != set(POLICIES["A"])):
            raise ProbeError("fresh actor resource scope cannot be changed")
        reduced: dict[str, dict[str, str]] = {}
        for lane, evidence in mapping.items():
            if not isinstance(evidence, Mapping):
                raise ProbeError("fresh resource evidence must be a mapping")
            charge = evidence.get("charge_id")
            invoice = evidence.get("invoice_id")
            if (not isinstance(charge, str) or not CHARGE_ID.fullmatch(charge)
                    or not isinstance(invoice, str) or not INVOICE_ID.fullmatch(invoice)):
                raise ProbeError("fresh resource evidence lacks valid charge/invoice IDs")
            reduced[lane] = {"charge_id": charge, "invoice_id": invoice}
        if (len({row["charge_id"] for row in reduced.values()}) != 3
                or len({row["invoice_id"] for row in reduced.values()}) != 3):
            raise ProbeError("actor lanes require distinct fresh charges and invoices")
        payload = json.dumps(reduced, sort_keys=True, separators=(",", ":")).encode()
        self._fresh_resources = reduced
        self.resource_scope_sha256 = hashlib.sha256(payload).hexdigest()

    def _audit(self, row: Mapping[str, object]) -> None:
        self.audit_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = _json_line(row)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.audit_path, flags, 0o600)
        try:
            remaining = payload
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("relay audit write made no progress")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _decision(self, method: str, path: str, params: dict[str, object],
                  idempotency: str, lane: str) -> dict[str, object]:
        if self._fresh_resources is None or self.resource_scope_sha256 is None:
            raise ProbeError("fresh actor resources were not registered")
        expected = self._fresh_resources[lane][
            "charge_id" if lane == "direct_refund" else "invoice_id"]
        actual = params["charge" if lane == "direct_refund" else "invoice"]
        if actual != expected:
            raise ProbeError("actor target differs from fresh registered resource")
        if lane in self._used_lanes or len(self._used_lanes) >= 3:
            raise ProbeError("actor lane already decided")
        if idempotency in self._used_idempotency:
            raise ProbeError("duplicate actor idempotency key")
        decision = POLICIES[self.policy][lane]
        before = self.dispatch_count
        after = before + (decision == "allow")
        decision_id = "dec_" + uuid4().hex
        row: dict[str, object] = {
            "event": "decision", "schema_version": "velvet.stripe.rest_relay.v1",
            "at": utc_now(), "decision_id": decision_id, "policy": self.policy,
            "policy_sha256": self.policy_sha256, "source_sha256": SOURCE_SHA256,
            "resource_scope_sha256": self.resource_scope_sha256,
            "lane": lane, "method": method, "path": path,
            "params": params, "idempotency": idempotency,
            "decision": decision, "dispatch_count_before": before,
            "dispatch_count_after": after,
        }
        self._audit(row)  # Durable and ordered before any provider call.
        self._used_idempotency.add(idempotency)
        self._used_lanes.add(lane)
        if decision == "allow":
            self.dispatch_count = after
        return row

    def _handle(self, message: object) -> dict[str, object]:
        try:
            method, path, params, idempotency, lane = normalized_intent(message)
            row = self._decision(method, path, params, idempotency, lane)
            witness = {key: row[key] for key in (
                "decision_id", "policy_sha256", "source_sha256", "resource_scope_sha256",
                "decision",
                "dispatch_count_before", "dispatch_count_after")}
            if row["decision"] == "deny":
                return {"ok": False, "kind": "app_denied", "witness": witness}
            try:
                response: ApiResponse = self.transport.request(
                    "actor", method, path, params, idempotency)
                request_id = _safe_id(response.request_id)
                version = (response.stripe_version
                           if isinstance(response.stripe_version, str)
                           and SAFE_VERSION.fullmatch(response.stripe_version) else None)
                self._audit({"event": "result", "at": utc_now(),
                             "decision_id": row["decision_id"],
                             "dispatch_count_after": self.dispatch_count,
                             "request_id": request_id, "outcome": "http_success"})
                return {"ok": True, "value": _safe_value(response.value),
                        "status": response.status, "request_id": request_id,
                        "stripe_version": version, "witness": witness}
            except RemoteFailure as error:
                request_id = _safe_id(error.request_id)
                self._audit({"event": "result", "at": utc_now(),
                             "decision_id": row["decision_id"],
                             "dispatch_count_after": self.dispatch_count,
                             "request_id": request_id,
                             "outcome": classify_failure(error)})
                return {"ok": False, "kind": "remote_failure", "status": error.status,
                        "request_id": request_id,
                        "code": error.code if isinstance(error.code, str)
                        and SAFE_CODE.fullmatch(error.code) else None,
                        "approval_request_id": _safe_id(error.approval_request_id),
                        "approval_status": error.approval_status
                        if isinstance(error.approval_status, str)
                        and SAFE_CODE.fullmatch(error.approval_status) else None,
                        "witness": witness}
            except Exception:  # noqa: BLE001 - upstream exception leaves dispatch outcome unknown.
                self._audit({"event": "result", "at": utc_now(),
                             "decision_id": row["decision_id"],
                             "dispatch_count_after": self.dispatch_count,
                             "request_id": None, "outcome": "outcome_unknown"})
                return {"ok": False, "kind": "probe_error", "witness": witness}
        except (ProbeError, TypeError, ValueError, OSError):
            return {"ok": False, "kind": "probe_error"}

    def _serve(self) -> None:
        listener = self._socket
        assert listener is not None
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(30)
                try:
                    message = _read_line(conn)
                    reply = self._handle(message)
                    conn.sendall(_json_line(reply))
                except (OSError, ProbeError):
                    try:
                        conn.sendall(_json_line({"ok": False, "kind": "probe_error"}))
                    except OSError:
                        pass

    def start(self) -> None:
        if self._socket is not None:
            raise ProbeError("relay already started")
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.socket_path.exists():
            raise ProbeError("relay socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(0o666)  # Random private directory is the access boundary.
            listener.listen(1)
            listener.settimeout(0.5)
            self._socket = listener
            self._thread = threading.Thread(
                target=self._serve, name="stripe-rest-relay", daemon=True)
            self._thread.start()
        except BaseException:
            listener.close()
            self.socket_path.unlink(missing_ok=True)
            raise

    def close(self) -> None:
        self._stopping.set()
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self.socket_path.unlink(missing_ok=True)

    def __enter__(self) -> StripeRestRelay:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class RelayClient:
    """Credential-free socket adapter with the StripeApi.request signature."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = Path(socket_path)
        self.last_witness: dict[str, object] | None = None

    def request(self, role: str, method: str, path: str,
                params: Mapping[str, object], idempotency: str | None = None) -> ApiResponse:
        self.last_witness = None
        if not isinstance(params, Mapping) or any(not isinstance(key, str) for key in params):
            raise ProbeError("actor form must have unique string names")
        message = {"op": "request", "role": role, "method": method, "path": path,
                   "params": dict(params), "idempotency": idempotency}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(45)
            try:
                conn.connect(str(self.socket_path))
                conn.sendall(_json_line(message))
                result = _read_line(conn)
            except (OSError, TypeError, ValueError) as error:
                raise ProbeError(f"relay transport failure: {type(error).__name__}") from None
        if not isinstance(result, dict):
            raise ProbeError("invalid relay response")
        witness = result.get("witness")
        self.last_witness = witness if isinstance(witness, dict) else None
        if result.get("ok") is True:
            value = result.get("value")
            status = result.get("status")
            if not isinstance(value, dict) or type(status) is not int or not 200 <= status < 300:
                raise ProbeError("invalid relay success response")
            version = result.get("stripe_version")
            return ApiResponse(value, status, _safe_id(result.get("request_id")),
                               version if isinstance(version, str)
                               and SAFE_VERSION.fullmatch(version) else None)
        kind = result.get("kind")
        if kind == "app_denied" and self.last_witness is not None:
            row = self.last_witness
            if (isinstance(row.get("decision_id"), str)
                    and isinstance(row.get("policy_sha256"), str)
                    and type(row.get("dispatch_count_before")) is int
                    and type(row.get("dispatch_count_after")) is int):
                raise AppDenied(row["decision_id"], row["policy_sha256"],
                                row["dispatch_count_before"], row["dispatch_count_after"])
        if kind == "remote_failure":
            status = result.get("status")
            if type(status) is int and 400 <= status <= 599:
                raise RemoteFailure(status, _safe_id(result.get("request_id")),
                                    result.get("code") if isinstance(result.get("code"), str)
                                    else None,
                                    _safe_id(result.get("approval_request_id")),
                                    result.get("approval_status") if isinstance(
                                        result.get("approval_status"), str) else None)
        raise ProbeError("relay rejected or could not classify actor intent")


def worker_facts() -> dict[str, object]:
    """Runtime facts; host Docker inspection must corroborate these claims."""
    try:
        status = dict(
            line.split(":", 1)
            for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
        )
        interfaces = sorted(name for _, name in socket.if_nameindex())
        active = [name for name in interfaces
                  if int(Path("/sys/class/net", name, "flags").read_text().strip(), 16) & 1]
        capabilities_empty = all(int(status.get(key, "1").strip(), 16) == 0
                                 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        no_new_privileges = status.get("NoNewPrivs", "").strip() == "1"
    except (OSError, ValueError):
        active = []
        capabilities_empty = False
        no_new_privileges = False
    return {"uid": os.getuid(), "active_interfaces": active,
            "no_new_privileges": no_new_privileges,
            "capabilities_empty": capabilities_empty,
            "stripe_environment_absent": not any("STRIPE" in key for key in os.environ),
            "docker_socket_absent": not any(Path(path).exists() for path in (
                "/var/run/docker.sock", "/run/docker.sock")),
            "source_sha256": SOURCE_SHA256}


def actor_main(socket_path: Path) -> int:
    import sys

    client = RelayClient(socket_path)
    for line in sys.stdin:
        try:
            if len(line.encode()) > MAX_LINE:
                raise ProbeError("worker input too large")
            message = json.loads(line, object_pairs_hook=_unique_pairs)
            if not isinstance(message, dict):
                raise ProbeError("worker input must be a JSON object")
            if message == {"op": "facts"}:
                result: dict[str, object] = {"ok": True, "facts": worker_facts()}
            elif message.get("op") == "request":
                if set(message) != {
                    "op", "role", "method", "path", "params", "idempotency"
                } or not isinstance(message["params"], dict):
                    raise ProbeError("invalid worker request envelope")
                try:
                    response = client.request(message.get("role"), message.get("method"),
                                              message.get("path"), message.get("params", {}),
                                              message.get("idempotency"))
                    result = {"ok": True, "value": response.value,
                              "status": response.status, "request_id": response.request_id,
                              "stripe_version": response.stripe_version,
                              "witness": client.last_witness}
                except AppDenied as error:
                    result = {"ok": False, "kind": "app_denied",
                              "decision_id": error.decision_id,
                              "policy_sha256": error.policy_sha256,
                              "dispatch_count_before": error.dispatch_count_before,
                              "dispatch_count_after": error.dispatch_count_after,
                              "witness": client.last_witness}
                except RemoteFailure as error:
                    result = {"ok": False, "kind": "remote_failure", "status": error.status,
                              "request_id": error.request_id, "code": error.code,
                              "approval_request_id": error.approval_request_id,
                              "approval_status": error.approval_status,
                              "witness": client.last_witness}
            else:
                raise ProbeError("unknown worker operation")
        except (ValueError, TypeError, ProbeError):
            result = {"ok": False, "kind": "probe_error"}
        sys.stdout.buffer.write(_json_line(result))
        sys.stdout.buffer.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Credential-free Stripe REST actor")
    commands = parser.add_subparsers(dest="command", required=True)
    actor = commands.add_parser("actor")
    actor.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "actor":
        return actor_main(args.socket)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
