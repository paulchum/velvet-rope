import importlib
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
attack_common = cast(Any, importlib.import_module("demo.attacks.common"))
ProxyClient = attack_common.ProxyClient
dispatcher = cast(Any, importlib.import_module("demo.live_target.dispatcher"))


def test_live_target_receives_the_permit_signers_trust_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeProcess:
        def terminate(self) -> None:
            return

        def wait(self, timeout: int) -> int:
            captured["wait_timeout"] = timeout
            return 0

    def fake_popen(*_args: Any, **kwargs: Any) -> FakeProcess:
        captured.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(attack_common.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(attack_common, "wait_for_target", lambda: None)

    with attack_common.LiveTarget(reset=False):
        pass

    assert captured["env"]["VELVET_LIVE_TRUSTED_PUBLIC_KEY"] == (
        attack_common.DEMO_MAXDE_PUBLIC_KEY_HEX
    )
    assert captured["wait_timeout"] == 5


def test_proxy_binds_attack_label_before_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ProxyClient(Path("unused.json"), attack="approval_replay")
    monkeypatch.setattr(client, "send", lambda request: dict(request))

    request = client.call_tool("delete_customer_records", {"customer_id": "cust_boreal"})

    params = cast(dict[str, Any], request["params"])
    meta = cast(dict[str, Any], params["_meta"])
    assert meta["attack"] == "approval_replay"


def test_non_mutating_attack_does_not_change_signed_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VELVET_LIVE_ATTACK", "approval_replay")
    request: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "delete_customer_records",
            "arguments": {"customer_id": "cust_boreal"},
            "_meta": {"attack": "approval_replay"},
        },
    }

    forwarded = dispatcher.mutate_request(request, "http://127.0.0.1:8891/mcp")

    assert forwarded is request
    assert forwarded == request


def test_argument_drift_changes_only_the_governed_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VELVET_LIVE_ATTACK", "argument_drift")
    request: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "issue_refund",
            "arguments": {"order_id": "ord_1001", "amount": 20.0},
            "_meta": {"attack": "argument_drift"},
        },
    }

    forwarded = dispatcher.mutate_request(request, "http://127.0.0.1:8891/mcp")

    assert forwarded is not request
    forwarded_params = cast(dict[str, Any], forwarded["params"])
    forwarded_args = cast(dict[str, Any], forwarded_params["arguments"])
    assert forwarded_args["amount"] == 2000.0
    assert forwarded_params["_meta"] == {"attack": "argument_drift"}
    assert cast(dict[str, Any], request["params"])["arguments"] == {
        "order_id": "ord_1001",
        "amount": 20.0,
    }


def test_refusal_mismatch_reports_failed_permit_check() -> None:
    response = {
        "error": {
            "data": {
                "boundary": "executor_dispatch_validation",
                "velvet_dispatch_refusal": {
                    "reason": "execution permit verification failed",
                    "metadata": {
                        "permit_check_failures": [
                            {"name": "scope", "status": "fail", "code": "scope_mismatch"}
                        ]
                    },
                },
            }
        }
    }

    with pytest.raises(attack_common.DemoFailure, match="scope_mismatch"):
        attack_common.assert_refusal(response, "approval receipt action hash mismatch")
