import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


def _load_common_module() -> ModuleType:
    module_name = "velvet_live_demo_common_dispatch_test"
    module_path = Path(__file__).resolve().parents[1] / "demo" / "live_target" / "common.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


common: Any = _load_common_module()


def test_dispatch_guard_compares_attempt_to_signed_admitted_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admitted_hash = "sha256:" + "a" * 64
    attempted_hash = "sha256:" + "b" * 64
    arguments = {"order_id": "ord_1001", "amount": 2000.0}
    arguments_hash = common.arguments_hash(arguments)
    schema_hash = "sha256:" + "c" * 64
    policy_hash = "sha256:" + "d" * 64
    permit = SimpleNamespace(
        scope=SimpleNamespace(
            canonical_action_hash=admitted_hash,
            arguments_hash=arguments_hash,
            tool_schema_hash=schema_hash,
        ),
        policy=SimpleNamespace(policy_hash=policy_hash),
    )

    monkeypatch.setattr(common, "execution_permit_from_bundle", lambda _bundle: permit)
    monkeypatch.setattr(
        common,
        "normalize_for_tool",
        lambda _conn, _tool_name, _arguments: SimpleNamespace(
            canonical_action_hash=attempted_hash.removeprefix("sha256:")
        ),
    )
    monkeypatch.setattr(common, "tool_by_name", lambda _conn, _tool_name: {})
    monkeypatch.setattr(common, "tool_schema_hash", lambda _tool: schema_hash)
    monkeypatch.setattr(
        common,
        "get_control",
        lambda _conn, _key, _default: policy_hash,
    )
    monkeypatch.setattr(
        common,
        "_validate_execution_permit",
        lambda *_args, **_kwargs: pytest.fail(
            "generic permit validation must not mask explicit action drift"
        ),
    )

    with pytest.raises(common.DispatchRefusal, match="canonical action hash mismatch") as exc:
        common.guard_dispatch(
            None,
            request={},
            tool_name="issue_refund",
            actual_arguments=arguments,
            meta={"velvet_execution": {}},
            attack="argument_drift",
        )

    assert exc.value.admitted_action_hash == admitted_hash
    assert exc.value.attempted_action_hash == attempted_hash
