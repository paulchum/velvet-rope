from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from demo.live_target.common import stable_hash, tool_schema_hash
from velvet.signing import Ed25519SigningProvider
from velvet.verdict import issue_verdict_certificate

JsonObject = dict[str, Any]

ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "reports" / "live-demo"
TARGET_URL = os.environ.get("VELVET_LIVE_TARGET_URL", "http://127.0.0.1:8891")
MCP_URL = f"{TARGET_URL}/mcp"
POLICY_HASH = "sha256:7a33625810215c508b2bed21e5e79842771b1cc6867ae038b5ffef7b2a5f2234"
DEMO_OAP_KEY_HEX = "0707070707070707070707070707070707070707070707070707070707070707"
DEMO_MAXDE_KEY_HEX = "0909090909090909090909090909090909090909090909090909090909090909"
DEMO_MAXDE_PUBLIC_KEY_HEX = (
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
)


class DemoFailure(AssertionError):
    pass


def http_json(path_or_url: str, payload: Mapping[str, Any] | None = None) -> JsonObject:
    url = path_or_url if path_or_url.startswith("http") else f"{TARGET_URL}{path_or_url}"
    if payload is None:
        request = urllib.request.Request(url, method="GET")  # noqa: S310
    else:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
    return json.loads(body or "{}")


def jsonrpc(
    method: str,
    params: Mapping[str, Any] | None = None,
    request_id: object = 1,
) -> JsonObject:
    payload: JsonObject = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = dict(params)
    return http_json(MCP_URL, payload)


def wait_for_target() -> None:
    deadline = time.time() + 30
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            state = http_json("/demo/state")
            if "hash" in state:
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"live target did not become ready: {last_error}")


class LiveTarget(AbstractContextManager["LiveTarget"]):
    def __init__(self, *, reset: bool = True) -> None:
        self.reset = reset
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> LiveTarget:
        args = [
            "uv",
            "run",
            "python",
            "-m",
            "demo.live_target.server",
        ]
        if self.reset:
            args.append("--reset-db")
        args.extend(["--http", "--port", "8891"])
        self.process = subprocess.Popen(  # noqa: S603
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_for_target()
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class ProxyClient(AbstractContextManager["ProxyClient"]):
    def __init__(
        self,
        config_path: Path,
        *,
        attack: str = "",
        signer: bool = True,
    ) -> None:
        self.config_path = config_path
        self.attack = attack
        self.signer = signer
        self.process: subprocess.Popen[str] | None = None
        self._read_lock = threading.Lock()

    def __enter__(self) -> ProxyClient:
        binary = os.environ.get("VELVET_PROXY_BIN")
        if not binary:
            candidate = ROOT / "target" / "debug" / "velvet-rope-proxy"
            binary = str(candidate) if candidate.exists() else ""
        if binary:
            args = [binary, "--config", str(self.config_path)]
        else:
            args = [
                "cargo",
                "run",
                "-q",
                "-p",
                "velvet-rope-proxy",
                "--",
                "--config",
                str(self.config_path),
            ]
        env = os.environ.copy()
        env["VELVET_LIVE_ATTACK"] = self.attack
        if self.signer:
            env["VELVET_OAP_ED25519_PRIVATE_KEY"] = DEMO_OAP_KEY_HEX
            env["VELVET_MAXDE_ED25519_PRIVATE_KEY"] = DEMO_MAXDE_KEY_HEX
            env["VELVET_MAXDE_ED25519_PUBLIC_KEY"] = DEMO_MAXDE_PUBLIC_KEY_HEX
        else:
            env.pop("VELVET_OAP_ED25519_PRIVATE_KEY", None)
            env.pop("VELVET_MAXDE_ED25519_PRIVATE_KEY", None)
            env.pop("VELVET_MAXDE_ED25519_PUBLIC_KEY", None)
        self.process = subprocess.Popen(  # noqa: S603
            args,
            cwd=ROOT,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def send(self, request: Mapping[str, Any]) -> JsonObject:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("proxy process is not running")
        with self._read_lock:
            self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        if not line:
            stderr = ""
            if self.process.stderr is not None:
                try:
                    stderr = self.process.stderr.read()
                except Exception:  # noqa: BLE001
                    stderr = ""
            raise RuntimeError(f"proxy exited before response: {stderr}")
        return json.loads(line)

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        request_id: object = 1,
        *,
        meta: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        request_meta: JsonObject = {
            "user_request": "Velvet live drift demonstration.",
        }
        if self.attack:
            # The target records this label in its audit row. Bind it into the
            # request before the proxy signs the execution permit; adding it in
            # the downstream dispatcher would correctly look like tampering.
            request_meta["attack"] = self.attack
        if meta is not None:
            request_meta.update(meta)
        return self.send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": dict(arguments),
                    "_meta": request_meta,
                },
            }
        )


def proxy_config_path(run_dir: Path, *, schema_version: str = "1") -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    http_json("/demo/control", {"schema_version": schema_version, "policy_hash": POLICY_HASH})
    tools = jsonrpc("tools/list", {}, "tools")["result"]["tools"]
    config = {
        "mode": "strict",
        "transport": "stdio",
        "upstream": {
            "server": "velvet-live-target",
            "command": "uv",
            "args": [
                "run",
                "python",
                "-m",
                "demo.live_target.dispatcher",
                "--stdio",
                "--target",
                MCP_URL,
            ],
        },
        "policy": {
            "dir": "examples/mcp_proxy/policies",
            "chain": "mcp_demo",
            "bundle_manifest": "examples/mcp_proxy/policy-bundle.yaml",
            "require_signature": False,
        },
        "forwarding": {"attach_execution": True},
        "ledger_path": str(run_dir / "proxy-ledger.vledger"),
        "thread_path": str(run_dir / "proxy-thread.jsonl"),
        "inventory_path": str(run_dir / "proxy-inventory.json"),
        "approval_requests_path": str(run_dir / "approval-requests.jsonl"),
        "evidence_pack_path": str(run_dir / "evidence-pack.json"),
        "schema_drift_action": "deny",
        "tools": [tool_approval(tool) for tool in tools],
    }
    path = run_dir / "proxy-config.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def tool_approval(tool: Mapping[str, Any]) -> JsonObject:
    name = str(tool["name"])
    destructive = name == "delete_customer_records"
    return {
        "server": "velvet-live-target",
        "name": name,
        "approved_schema_hash": tool_schema_hash(tool),
        "risk_class": "low",
        "approval_tier": "auto_approve",
        "disposition": "approved",
        "destructive": destructive,
        "destructive_approval": {
            "approved": True,
            "approver": "velvet-live-demo",
            "reason": "Demo target performs executor-bound receipt validation.",
            "expires_at": "2035-01-01T00:00:00Z",
        }
        if destructive
        else None,
        "allowed_environments": ["local"],
        "allowed_subjects": [],
        "expected_improvement": 0.9,
        "novelty": 0.1,
        "confidence": 0.95,
        "usd_estimate": None,
        "max_de": {
            "v": "0.900000",
            "lambda": "0.200000",
            "L": "1.000000",
            "alpha": "9.000000",
            "beta": "1.000000",
            "L_cert": "0.900000",
            "U_cert": "0.950000",
            "decision": "inspect",
            "theorem_ref": "docs/math/certified_max_de_theorem.txt",
            "maxde_version": "maxde/1.0",
        },
        # The static destructive approval is trusted demo configuration. Mark it
        # as present for the admission engine; strict mode still independently
        # requires a signed, short-lived Verdict Certificate before dispatch.
        "metadata": {"approval_valid": True} if destructive else {},
    }


def proxy_safe_kill_verdict(tool_name: str) -> JsonObject:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DEMO_MAXDE_KEY_HEX))
    signer = Ed25519SigningProvider(
        private_key,
        key_id="velvet:maxde:local",
        key_version="v1",
        verification_tier="demo",
    )
    tool_key = f"velvet-live-target/{tool_name}"
    return issue_verdict_certificate(
        verdict="safe_kill",
        decision_id=f"live-demo:{tool_name}",
        decision_class="retire_tool_route",
        target_id_hash=stable_hash({"tool_key": tool_key}),
        claim_currency="BP",
        delta=0.05,
        gate_c=1.5,
        rho=0.2,
        method="exact_dp",
        hypotheses=["deterministic local live-demo fixture"],
        theorem_refs=["docs/math/finite_horizon_safe_kill_theorem_v.txt"],
        inputs_hash=stable_hash({"attack": "approval_replay", "tool_key": tool_key}),
        expected_rounds_to_gate_crossing=12.5,
        tail_probability_bound=0.01,
        tail_crossing_probability=0.004,
        tail_drift_penalty=0.0,
        tail_posterior_expected_shortfall=0.02,
        horizon_rounds=128.0,
        rounds_remaining=64.0,
        tenant_id="local-dev",
        environment="local",
        reason_code="live_demo_executor_replay_test",
        ttl_seconds=900,
        signer=signer,
        signing_key_id="velvet:maxde:local",
    )


def state() -> JsonObject:
    return http_json("/demo/state")


def latest_audit() -> JsonObject:
    audit = state().get("audit") or []
    if not audit:
        raise DemoFailure("target audit ledger is empty")
    return audit[-1]


def assert_refusal(response: Mapping[str, Any], expected_reason: str | None = None) -> JsonObject:
    error = response.get("error")
    if not isinstance(error, Mapping):
        raise DemoFailure(f"expected JSON-RPC refusal, got {response}")
    data = error.get("data")
    if not isinstance(data, Mapping):
        raise DemoFailure(f"expected refusal data, got {response}")
    if data.get("boundary") != "executor_dispatch_validation":
        raise DemoFailure(f"unexpected refusal boundary: {data}")
    refusal = data.get("velvet_dispatch_refusal")
    if not isinstance(refusal, Mapping):
        raise DemoFailure(f"missing dispatch refusal: {data}")
    reason = str(refusal.get("reason"))
    if expected_reason and expected_reason not in reason:
        metadata = refusal.get("metadata")
        permit_failures = (
            metadata.get("permit_check_failures") if isinstance(metadata, Mapping) else None
        )
        raise DemoFailure(
            f"expected refusal containing {expected_reason!r}, got {reason!r}; "
            f"permit_check_failures={permit_failures!r}"
        )
    return dict(refusal)


def assert_no_refunds() -> None:
    refunds = state().get("refunds") or []
    if refunds:
        raise DemoFailure(f"expected no refunds, got {refunds}")


def assert_order_status(order_id: str, status: str) -> None:
    orders = state().get("orders") or []
    for order in orders:
        if order.get("order_id") == order_id:
            if order.get("status") != status:
                raise DemoFailure(f"expected {order_id} status {status}, got {order.get('status')}")
            return
    raise DemoFailure(f"order {order_id} not found")


def assert_customer_exists(customer_id: str) -> None:
    customers = state().get("customers") or []
    if not any(customer.get("customer_id") == customer_id for customer in customers):
        raise DemoFailure(f"expected customer {customer_id} to remain present")


def refund_spend_cents() -> int:
    budget = state().get("budget") or []
    if not budget:
        return 0
    return int(budget[0]["spent_cents"])


def report_result(run_dir: Path, name: str, result: Mapping[str, Any]) -> JsonObject:
    replay_evidence = {
        "attack": name,
        "result": dict(result),
        "state": state(),
    }
    report = {
        "attack": name,
        "status": "pass",
        "target_url": TARGET_URL,
        "policy_hash": POLICY_HASH,
        "state": replay_evidence["state"],
        "result": dict(result),
        "sealed_replay_digest": stable_hash(replay_evidence),
        "artifacts": {
            "run_dir": str(run_dir),
            "proxy_ledger": str(run_dir / "proxy-ledger.vledger"),
            "proxy_config": str(run_dir / "proxy-config.json"),
        },
    }
    path = run_dir / f"{name}.report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"attack": name, "status": "pass", "report": str(path)}, sort_keys=True))
    return report


def run_attack(name: str, attack_fn: Callable[[Path, Path], Mapping[str, Any]]) -> JsonObject:
    run_dir = REPORT_ROOT / name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    with LiveTarget(reset=True):
        config_path = proxy_config_path(run_dir)
        result = attack_fn(run_dir, config_path)
        return report_result(run_dir, name, result)


def attack_argument_drift(_: Path, config_path: Path) -> Mapping[str, Any]:
    with ProxyClient(config_path, attack="argument_drift") as proxy:
        response = proxy.call_tool(
            "issue_refund",
            {"order_id": "ord_1001", "amount": 20.00, "reason": "approved small refund"},
        )
    refusal = assert_refusal(response, "canonical action hash mismatch")
    assert_no_refunds()
    audit = latest_audit()
    if audit.get("decision") != "refuse":
        raise DemoFailure(f"expected refusal audit row, got {audit}")
    return {"response": response, "refusal": refusal, "audit": audit}


def attack_schema_drift(_: Path, config_path: Path) -> Mapping[str, Any]:
    with ProxyClient(config_path, attack="schema_drift") as proxy:
        response = proxy.call_tool(
            "update_order_status",
            {"order_id": "ord_1002", "status": "cancelled"},
        )
    refusal = assert_refusal(response, "tool schema hash mismatch")
    assert_order_status("ord_1002", "shipped")
    return {"response": response, "refusal": refusal, "audit": latest_audit()}


def attack_approval_replay(_: Path, config_path: Path) -> Mapping[str, Any]:
    receipt = http_json(
        "/demo/approval-receipt",
        {
            "tool_name": "delete_customer_records",
            "arguments": {"customer_id": "cust_alpine", "reason": "first approved delete"},
        },
    )
    with ProxyClient(config_path, attack="approval_replay") as proxy:
        response = proxy.call_tool(
            "delete_customer_records",
            {
                "customer_id": "cust_boreal",
                "reason": "replayed receipt for different customer",
                "approval_receipt": receipt,
            },
            meta={
                "velvet_verdict_certificate": proxy_safe_kill_verdict(
                    "delete_customer_records"
                )
            },
        )
    refusal = assert_refusal(response, "approval receipt action hash mismatch")
    assert_customer_exists("cust_boreal")
    return {"response": response, "refusal": refusal, "audit": latest_audit()}


def attack_policy_swap(_: Path, config_path: Path) -> Mapping[str, Any]:
    with ProxyClient(config_path, attack="policy_swap") as proxy:
        response = proxy.call_tool(
            "update_order_status",
            {"order_id": "ord_2002", "status": "cancelled"},
        )
    refusal = assert_refusal(response, "policy hash mismatch")
    assert_order_status("ord_2002", "pending")
    return {"response": response, "refusal": refusal, "audit": latest_audit()}


def attack_budget_overshoot(_: Path, config_path: Path) -> Mapping[str, Any]:
    http_json("/demo/control", {"refund_cap_cents": 10000, "policy_hash": POLICY_HASH})
    del config_path
    responses: list[JsonObject] = []
    errors: list[str] = []
    response_lock = threading.Lock()
    configs = [
        proxy_config_path(REPORT_ROOT / "budget_overshoot" / f"proxy-{index}")
        for index in range(1, 4)
    ]

    def send_refund(index: int, order_id: str, path: Path) -> None:
        try:
            with ProxyClient(path, attack="budget_overshoot") as proxy:
                response = proxy.call_tool(
                    "issue_refund",
                    {"order_id": order_id, "amount": 40.00, "reason": f"rapid refund {index}"},
                    request_id=f"budget-{index}",
                )
        except Exception as exc:  # noqa: BLE001
            with response_lock:
                errors.append(str(exc))
            return
        with response_lock:
            responses.append(response)

    threads = [
        threading.Thread(target=send_refund, args=(index, order_id, path), daemon=True)
        for index, (order_id, path) in enumerate(
            zip(["ord_1001", "ord_1002", "ord_4001"], configs, strict=True),
            start=1,
        )
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    if errors:
        raise DemoFailure(f"budget attack proxy errors: {errors}")
    if len(responses) != 3:
        raise DemoFailure(f"expected three budget responses, got {responses}")
    refused = [response for response in responses if "error" in response]
    if len(refused) != 1:
        raise DemoFailure(f"expected exactly one over-cap refusal, got {responses}")
    refusal = assert_refusal(refused[0], "refund budget cap exceeded")
    spent = refund_spend_cents()
    if spent > 10000:
        raise DemoFailure(f"refund spend exceeded cap: {spent}")
    return {
        "responses": responses,
        "refusal": refusal,
        "spent_cents": spent,
        "audit": latest_audit(),
    }


def attack_signer_kill(_: Path, config_path: Path) -> Mapping[str, Any]:
    before_hash = state()["hash"]
    with ProxyClient(config_path, signer=False) as proxy:
        response = proxy.call_tool(
            "issue_refund",
            {"order_id": "ord_1001", "amount": 20.00, "reason": "signer killed variant"},
        )
    if "error" not in response:
        raise DemoFailure(f"expected proxy fail-closed signing error, got {response}")
    after = state()
    if after["hash"] != before_hash:
        raise DemoFailure("database changed when signing provider was unavailable")
    return {
        "response": response,
        "state_hash_before": before_hash,
        "state_hash_after": after["hash"],
    }


ATTACKS: dict[str, Callable[[Path, Path], Mapping[str, Any]]] = {
    "argument_drift": attack_argument_drift,
    "schema_drift": attack_schema_drift,
    "approval_replay": attack_approval_replay,
    "policy_swap": attack_policy_swap,
    "budget_overshoot": attack_budget_overshoot,
    "signer_kill": attack_signer_kill,
}


def run_named_attack(name: str) -> JsonObject:
    if name not in ATTACKS:
        raise SystemExit(f"unknown attack {name}; choose one of {', '.join(sorted(ATTACKS))}")
    return run_attack(name, ATTACKS[name])


def run_suite() -> JsonObject:
    results = []
    started = time.time()
    for name in [
        "argument_drift",
        "schema_drift",
        "approval_replay",
        "policy_swap",
        "budget_overshoot",
        "signer_kill",
    ]:
        results.append(run_named_attack(name))
    summary = {
        "status": "pass",
        "attacks": [result["attack"] for result in results],
        "elapsed_seconds": round(time.time() - started, 3),
        "report_dir": str(REPORT_ROOT),
    }
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    (REPORT_ROOT / "suite.report.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, sort_keys=True))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("attack", choices=sorted([*ATTACKS.keys(), "suite"]))
    args = parser.parse_args(argv)
    try:
        if args.attack == "suite":
            run_suite()
        else:
            run_named_attack(args.attack)
    except DemoFailure as exc:
        print(json.dumps({"status": "fail", "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
