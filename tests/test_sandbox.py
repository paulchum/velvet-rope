from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import velvet._native as _native
from velvet.sandbox import (
    SandboxConfig,
    SandboxExecutor,
    apply_output_transforms,
    strip_timestamps_v1,
)
from velvet.types import (
    MountMode,
    MountSpec,
    NetworkPolicy,
    OutputTransform,
    ResourceLimits,
    SandboxBackendKind,
    SandboxedCommand,
    SandboxExecutionPlan,
    SandboxProvenance,
    ThreadRecord,
)


@given(st.text())
def test_strip_timestamps_is_deterministic_and_idempotent(text: str) -> None:
    transform = f"{text} 2026-05-17T12:34:56Z 12:34:56"
    once = strip_timestamps_v1(transform)
    assert once == strip_timestamps_v1(transform)
    assert once == strip_timestamps_v1(once)


def test_sandbox_thread_models_round_trip() -> None:
    raw = _native.route_thread(
        {
            "sandbox_config": {
                "backend": "none",
                "allow_unsafe_exec": True,
            }
        },
        [
            {
                "action_type": "EXECUTE_CODE",
                "parameters": {"command": ["python3", "-c", "print('ok')"], "cwd": "."},
            }
        ],
        thread_id="thread_sandbox_roundtrip",
        timestamp="2026-05-14T00:00:00+00:00",
    )["thread"]
    parsed = ThreadRecord.from_dict(raw)
    assert parsed.sandbox_plan is not None
    assert parsed.sandbox_plan.to_dict() == raw["sandbox_plan"]
    assert parsed.to_dict() == raw


def test_normalized_output_hash_is_stable_for_deterministic_fixture(tmp_path: Path) -> None:
    raw = _native.route_thread(
        {
            "sandbox_config": {
                "backend": "none",
                "allow_unsafe_exec": True,
            }
        },
        [
            {
                "action_type": "EXECUTE_CODE",
                "parameters": {"command": ["/bin/echo", "fixed"], "cwd": "."},
            }
        ],
        thread_id="thread_sandbox_hash",
        timestamp="2026-05-14T00:00:00+00:00",
    )["thread"]
    plan = SandboxExecutionPlan.from_dict(raw["sandbox_plan"])
    executor = SandboxExecutor(tmp_path)
    hashes = {
        hashlib.sha256(
            executor.run(plan).normalized_stdout.encode("utf-8")
        ).hexdigest()
        for _ in range(1000)
    }
    assert len(hashes) == 1


def test_sandbox_executor_rejects_cwd_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    plan = _sandbox_plan(cwd=str(outside), backend=SandboxBackendKind.NONE)

    with pytest.raises(RuntimeError, match="cwd is outside approved roots"):
        SandboxExecutor(workspace).run(plan)


def test_sandbox_executor_allows_cwd_under_configured_mount(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    mount = MountSpec(
        host_path=str(mounted),
        sandbox_path=str(mounted),
        mode=MountMode.READ_ONLY,
    )
    plan = _sandbox_plan(cwd=str(mounted), backend=SandboxBackendKind.NONE, mounts=(mount,))
    executor = SandboxExecutor(workspace)

    assert executor._host_path_allowed(mounted.resolve(), plan) is True


def test_macos_lightweight_backend_requires_unsafe_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("velvet.sandbox.platform.system", lambda: "Darwin")
    monkeypatch.setattr("velvet.sandbox.shutil.which", lambda _name: "/usr/bin/sandbox-exec")
    plan = _sandbox_plan(cwd=str(tmp_path), backend=SandboxBackendKind.LIGHTWEIGHT)

    with pytest.raises(RuntimeError, match="disabled by default"):
        SandboxExecutor(tmp_path)._lightweight_argv(plan)

    opted_in = SandboxExecutor(
        tmp_path,
        sandbox_config=SandboxConfig(allow_macos_lightweight_broad_reads=True),
    )
    assert opted_in._lightweight_argv(plan)[0] == "sandbox-exec"


@given(st.text())
def test_output_transform_chain_is_stable(text: str) -> None:
    transforms = (OutputTransform(kind="strip_timestamps_v1"),)
    first = apply_output_transforms(text, transforms)
    second = apply_output_transforms(first, transforms)
    assert first == second


def test_execute_code_thread_requires_sandbox_plan() -> None:
    raw = _native.route_thread(
        {
            "sandbox_config": {
                "backend": "none",
                "allow_unsafe_exec": True,
            }
        },
        [
            {
                "action_type": "EXECUTE_CODE",
                "parameters": {"command": ["python3", "-c", "print('ok')"], "cwd": "."},
            }
        ],
    )["thread"]
    assert raw["selected_action"] == "EXECUTE_CODE"
    assert raw["sandbox_plan"]["provenance"]["profile_hash"]
    assert raw["sandbox_plan"]["output_transforms"] == [{"kind": "strip_timestamps_v1"}]


def _sandbox_plan(
    *,
    cwd: str,
    backend: SandboxBackendKind,
    mounts: tuple[MountSpec, ...] = (),
) -> SandboxExecutionPlan:
    limits = ResourceLimits(
        cpu_seconds=1,
        memory_bytes=64 * 1024 * 1024,
        wall_clock_ms=1000,
        max_fs_writes_bytes=1024,
        max_stdout_bytes=1024,
        max_processes=4,
    )
    return SandboxExecutionPlan(
        backend=backend,
        command=SandboxedCommand(
            argv=("/bin/echo", "ok"),
            cwd=cwd,
            mounts=mounts,
        ),
        limits=limits,
        output_transforms=(OutputTransform(kind="strip_timestamps_v1"),),
        provenance=SandboxProvenance(
            backend=backend,
            profile_hash="test-profile",
            image_digest=None,
            container_runtime=None,
            mount_spec=mounts,
            network_policy=NetworkPolicy(mode="deny_all"),
            applied_limits=limits,
            backend_guarantees=(),
        ),
    )
