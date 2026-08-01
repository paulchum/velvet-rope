"""Sandbox configuration and Python execution adapters for EXECUTE_CODE."""

from __future__ import annotations

import logging
import os
import platform
import re
import resource
import selectors
import shutil
import signal
import subprocess  # nosec B404
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .types import (
    ContainerRuntime,
    EgressRule,
    ExecutionStatus,
    MountMode,
    MountSpec,
    OutputTransform,
    ResourceLimits,
    RuntimeMode,
    SandboxBackendKind,
    SandboxExecutionPlan,
    SandboxViolation,
)

LOGGER = logging.getLogger(__name__)
_TIMESTAMP_PATTERNS = (
    re.compile(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
    ),
    re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"),
)


@dataclass(frozen=True)
class SandboxConfig:
    mode: RuntimeMode = RuntimeMode.DEVELOPMENT
    backend: SandboxBackendKind | None = None
    allow_unsafe_exec: bool = False
    allow_macos_lightweight_broad_reads: bool = False
    container_runtime: ContainerRuntime | None = None
    container_image: str | None = None
    env_list: tuple[str, ...] = ()
    mounts: tuple[MountSpec, ...] = ()
    egress_list: tuple[EgressRule, ...] = ()
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    output_transforms: tuple[OutputTransform, ...] = (
        OutputTransform(kind="strip_timestamps_v1"),
    )

    @classmethod
    def from_env(cls, *, mode: RuntimeMode = RuntimeMode.DEVELOPMENT) -> SandboxConfig:
        return cls(
            mode=mode,
            allow_unsafe_exec=os.environ.get("VELVET_ALLOW_UNSAFE_EXEC") == "1",
            allow_macos_lightweight_broad_reads=(
                os.environ.get("VELVET_ALLOW_MACOS_LIGHTWEIGHT_BROAD_READS") == "1"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "mode": self.mode.value,
            "backend": self.backend.value if self.backend is not None else None,
            "allow_unsafe_exec": self.allow_unsafe_exec,
            "container_runtime": (
                self.container_runtime.value if self.container_runtime is not None else None
            ),
            "container_image": self.container_image,
            "env_list": list(self.env_list),
            "mounts": [mount.to_dict() for mount in self.mounts],
            "egress_list": [rule.to_dict() for rule in self.egress_list],
            "limits": self.limits.to_dict(),
            "output_transforms": [transform.to_dict() for transform in self.output_transforms],
        }
        if self.allow_macos_lightweight_broad_reads:
            payload["allow_macos_lightweight_broad_reads"] = True
        return payload


@dataclass(frozen=True)
class SandboxRunResult:
    status: ExecutionStatus
    provider: str
    summary: str
    stdout: str
    stderr: str
    exit_code: int | None
    violations: tuple[SandboxViolation, ...]
    normalized_stdout: str
    normalized_stderr: str


def strip_timestamps_v1(text: str) -> str:
    stripped = text
    for pattern in _TIMESTAMP_PATTERNS:
        stripped = pattern.sub("<timestamp>", stripped)
    return stripped


def apply_output_transforms(text: str, transforms: Sequence[OutputTransform]) -> str:
    transformed = text
    for transform in transforms:
        if transform.kind == "strip_timestamps_v1":
            transformed = strip_timestamps_v1(transformed)
        else:
            raise ValueError(f"unsupported output transform: {transform.kind}")
    return transformed


def merge_sandbox_state(state: Mapping[str, Any], config: SandboxConfig) -> dict[str, Any]:
    merged = dict(state)
    merged["sandbox_config"] = config.to_dict()
    return merged


class SandboxExecutor:
    """Executes Rust-authored sandbox plans using Python-side I/O."""

    def __init__(self, workspace: Path, *, sandbox_config: SandboxConfig | None = None) -> None:
        self.workspace = workspace.resolve()
        self.sandbox_config = sandbox_config or SandboxConfig.from_env()
        self._last_unsafe_warning_at: float | None = None

    def run(self, plan: SandboxExecutionPlan) -> SandboxRunResult:
        self._assert_command_cwd_allowed(plan)
        if plan.backend == SandboxBackendKind.NONE:
            self._warn_unsafe_execution()
        argv = self._build_argv(plan)
        return self._run_supervised(plan, argv)

    def _warn_unsafe_execution(self) -> None:
        now = time.monotonic()
        if self._last_unsafe_warning_at is None or now - self._last_unsafe_warning_at >= 60.0:
            LOGGER.warning(
                "Unsafe EXECUTE_CODE backend=none is active; "
                "this must never be used for hosted workloads."
            )
            self._last_unsafe_warning_at = now

    def _build_argv(self, plan: SandboxExecutionPlan) -> list[str]:
        if plan.backend == SandboxBackendKind.NONE:
            return list(plan.command.argv)
        if plan.backend == SandboxBackendKind.LIGHTWEIGHT:
            return self._lightweight_argv(plan)
        if plan.backend == SandboxBackendKind.CONTAINER:
            return self._container_argv(plan)
        raise AssertionError(f"unsupported sandbox backend {plan.backend}")

    def _lightweight_argv(self, plan: SandboxExecutionPlan) -> list[str]:
        system = platform.system()
        if system == "Linux":
            if shutil.which("bwrap") is None:
                raise RuntimeError("lightweight backend requires bwrap on Linux")
            if plan.command.egress_list:
                raise RuntimeError(
                    "lightweight Linux backend currently supports deny-all egress only"
                )
            argv = [
                "bwrap",
                "--die-with-parent",
                "--new-session",
                "--unshare-pid",
                "--unshare-net",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
            ]
            for path in ("/usr", "/bin", "/lib", "/lib64"):
                if Path(path).exists():
                    argv.extend(["--ro-bind", path, path])
            for mount in plan.command.mounts:
                flag = "--ro-bind" if mount.mode == MountMode.READ_ONLY else "--bind"
                argv.extend([flag, mount.host_path, mount.sandbox_path])
            cwd = Path(plan.command.cwd)
            if not any(mount.sandbox_path == str(cwd) for mount in plan.command.mounts):
                resolved_cwd = self._resolve_host_cwd(plan.command.cwd)
                if not self._host_path_allowed(resolved_cwd, plan):
                    raise RuntimeError(
                        f"lightweight Linux cwd is outside approved roots: {resolved_cwd}"
                    )
                argv.extend(["--ro-bind", str(resolved_cwd), str(cwd)])
            argv.extend(["--chdir", plan.command.cwd, "--"])
            argv.extend(plan.command.argv)
            return argv
        if system == "Darwin":
            if shutil.which("sandbox-exec") is None:
                raise RuntimeError("lightweight backend requires sandbox-exec on macOS")
            if not self.sandbox_config.allow_macos_lightweight_broad_reads:
                raise RuntimeError(
                    "lightweight macOS backend is disabled by default because the current "
                    "profile cannot enforce filesystem read confinement; set "
                    "VELVET_ALLOW_MACOS_LIGHTWEIGHT_BROAD_READS=1 only for local development"
                )
            if plan.command.egress_list:
                raise RuntimeError(
                    "lightweight macOS backend cannot safely enforce non-empty egress lists"
                )
            writable_paths = [
                mount.sandbox_path
                for mount in plan.command.mounts
                if mount.mode == MountMode.READ_WRITE
            ]
            profile = [
                "(version 1)",
                "(allow default)",
                "(deny network*)",
                "(deny file-write*)",
            ]
            profile.extend(
                f'(allow file-write* (subpath "{path}"))' for path in sorted(writable_paths)
            )
            return ["sandbox-exec", "-p", "".join(profile), *plan.command.argv]
        raise RuntimeError("lightweight backend is supported only on Linux and macOS")

    def _container_argv(self, plan: SandboxExecutionPlan) -> list[str]:
        runtime = plan.provenance.container_runtime
        image = plan.provenance.image_digest
        if runtime is None or image is None:
            raise RuntimeError("container plan is missing runtime or image digest")
        executable = runtime.value
        if shutil.which(executable) is None:
            raise RuntimeError(f"container backend requires {executable}")
        if plan.command.egress_list:
            raise RuntimeError("container backend currently supports deny-all egress only")
        argv = [
            executable,
            "run",
            "--rm",
            "--read-only",
            "--network",
            "none",
            "--memory",
            str(plan.limits.memory_bytes),
            "--pids-limit",
            str(plan.limits.max_processes),
            "--workdir",
            plan.command.cwd,
            "--tmpfs",
            f"/tmp:rw,size={plan.limits.max_fs_writes_bytes}",  # noqa: S108  # nosec B108
        ]
        for mount in plan.command.mounts:
            mode = "ro" if mount.mode == MountMode.READ_ONLY else "rw"
            argv.extend(
                ["--mount", f"type=bind,src={mount.host_path},dst={mount.sandbox_path},{mode}"]
            )
        argv.append(image)
        argv.extend(plan.command.argv)
        return argv

    def _assert_command_cwd_allowed(self, plan: SandboxExecutionPlan) -> None:
        if plan.backend == SandboxBackendKind.CONTAINER:
            return
        cwd = self._resolve_host_cwd(plan.command.cwd)
        if self._host_path_allowed(cwd, plan):
            return
        raise RuntimeError(f"EXECUTE_CODE cwd is outside approved roots: {cwd}")

    def _resolve_host_cwd(self, raw_cwd: str) -> Path:
        cwd = Path(raw_cwd).expanduser()
        if not cwd.is_absolute():
            cwd = self.workspace / cwd
        return cwd.resolve()

    def _host_path_allowed(self, path: Path, plan: SandboxExecutionPlan) -> bool:
        if _is_relative_to(path, self.workspace):
            return True
        for mount in plan.command.mounts:
            host_path = Path(mount.host_path).expanduser()
            if not host_path.is_absolute():
                host_path = self.workspace / host_path
            if _is_relative_to(path, host_path.resolve()):
                return True
        return False

    def _run_supervised(self, plan: SandboxExecutionPlan, argv: Sequence[str]) -> SandboxRunResult:
        before_writes = self._measure_writable_mounts(plan)
        violations: list[SandboxViolation] = []
        process = subprocess.Popen(  # noqa: S603  # nosec B603
            list(argv),
            cwd=plan.command.cwd if plan.backend != SandboxBackendKind.CONTAINER else None,
            stdin=subprocess.PIPE if plan.command.stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=self._filtered_env(plan),
            preexec_fn=self._preexec_limits(plan.limits),
        )
        if process.stdin is not None and plan.command.stdin is not None:
            process.stdin.write(bytes(plan.command.stdin))
            process.stdin.close()

        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        selector = selectors.DefaultSelector()
        if process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, stdout_buffer)
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, stderr_buffer)

        deadline = time.monotonic() + plan.limits.wall_clock_ms / 1000.0
        killed = False
        while selector.get_map():
            remaining = max(0.0, deadline - time.monotonic())
            if remaining == 0.0 and process.poll() is None:
                violations.append(
                    SandboxViolation(
                        kind="wall_clock_exceeded",
                        message="Process exceeded wall_clock_ms.",
                        details={"limit_ms": plan.limits.wall_clock_ms},
                    )
                )
                self._kill_process_group(process)
                killed = True
                break
            events = selector.select(timeout=min(0.05, remaining if remaining else 0.05))
            for key, _ in events:
                chunk = cast(Any, key.fileobj).read(4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = key.data
                buffer.extend(chunk)
                if buffer is stdout_buffer and len(stdout_buffer) > plan.limits.max_stdout_bytes:
                    violations.append(
                        SandboxViolation(
                            kind="stdout_exceeded",
                            message="Process exceeded max_stdout_bytes.",
                            details={"limit_bytes": plan.limits.max_stdout_bytes},
                        )
                    )
                    self._kill_process_group(process)
                    killed = True
                    break
            if killed:
                break
            if process.poll() is not None and not selector.get_map():
                break

        try:
            returncode = process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            self._kill_process_group(process)
            returncode = process.wait(timeout=0.2)

        stdout = bytes(stdout_buffer[: plan.limits.max_stdout_bytes]).decode(
            "utf-8", errors="replace"
        )
        stderr = bytes(stderr_buffer[: plan.limits.max_stdout_bytes]).decode(
            "utf-8", errors="replace"
        )
        violations.extend(self._infer_runtime_violations(plan, returncode, stderr))
        violations.extend(self._detect_write_overrun(plan, before_writes))

        normalized_stdout = apply_output_transforms(stdout, plan.output_transforms)
        normalized_stderr = apply_output_transforms(stderr, plan.output_transforms)
        status = self._status_for(returncode, violations)
        summary = self._summary_for(returncode, violations)
        return SandboxRunResult(
            status=status,
            provider=plan.backend.value,
            summary=summary,
            stdout=stdout,
            stderr=stderr,
            exit_code=returncode,
            violations=tuple(violations),
            normalized_stdout=normalized_stdout,
            normalized_stderr=normalized_stderr,
        )

    def _filtered_env(self, plan: SandboxExecutionPlan) -> dict[str, str]:
        return {
            key: value
            for key, value in os.environ.items()
            if key in set(plan.command.env_list)
        }

    def _preexec_limits(self, limits: ResourceLimits) -> Any:
        def apply_limits() -> None:
            self._try_setrlimit(resource.RLIMIT_CPU, limits.cpu_seconds)
            self._try_setrlimit(resource.RLIMIT_AS, limits.memory_bytes)
            self._try_setrlimit(resource.RLIMIT_FSIZE, limits.max_fs_writes_bytes)
            if hasattr(resource, "RLIMIT_NPROC"):
                self._try_setrlimit(resource.RLIMIT_NPROC, limits.max_processes)

        return apply_limits

    def _try_setrlimit(self, limit: int, value: int) -> None:
        try:
            resource.setrlimit(limit, (value, value))
        except (OSError, ValueError):
            return

    def _kill_process_group(self, process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _measure_writable_mounts(self, plan: SandboxExecutionPlan) -> dict[str, int]:
        sizes: dict[str, int] = {}
        for mount in plan.command.mounts:
            if mount.mode == MountMode.READ_WRITE:
                sizes[mount.host_path] = self._dir_size(Path(mount.host_path))
        return sizes

    def _detect_write_overrun(
        self, plan: SandboxExecutionPlan, before_writes: Mapping[str, int]
    ) -> list[SandboxViolation]:
        violations: list[SandboxViolation] = []
        for path, before in before_writes.items():
            after = self._dir_size(Path(path))
            delta = max(0, after - before)
            if delta > plan.limits.max_fs_writes_bytes:
                violations.append(
                    SandboxViolation(
                        kind="filesystem_writes_exceeded",
                        message="Writable mount exceeded max_fs_writes_bytes.",
                        details={
                            "path": path,
                            "delta_bytes": delta,
                            "limit_bytes": plan.limits.max_fs_writes_bytes,
                        },
                    )
                )
        return violations

    def _dir_size(self, root: Path) -> int:
        if not root.exists():
            return 0
        total = 0
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    total += path.stat().st_size
                except FileNotFoundError:
                    continue
        return total

    def _infer_runtime_violations(
        self, plan: SandboxExecutionPlan, returncode: int | None, stderr: str
    ) -> list[SandboxViolation]:
        lowered = stderr.lower()
        violations: list[SandboxViolation] = []
        if returncode == -signal.SIGXCPU:
            violations.append(
                SandboxViolation(
                    kind="cpu_exceeded",
                    message="Process exceeded cpu_seconds.",
                    details={"limit_seconds": plan.limits.cpu_seconds},
                )
            )
        if returncode == -signal.SIGXFSZ:
            violations.append(
                SandboxViolation(
                    kind="filesystem_writes_exceeded",
                    message="Process exceeded file write size limit.",
                    details={"limit_bytes": plan.limits.max_fs_writes_bytes},
                )
            )
        if "memoryerror" in lowered or "cannot allocate memory" in lowered:
            violations.append(
                SandboxViolation(
                    kind="memory_exceeded",
                    message="Process exceeded memory limit.",
                    details={"limit_bytes": plan.limits.memory_bytes},
                )
            )
        if "resource temporarily unavailable" in lowered:
            violations.append(
                SandboxViolation(
                    kind="process_count_exceeded",
                    message="Process exceeded process-count limit.",
                    details={"limit_processes": plan.limits.max_processes},
                )
            )
        if (
            plan.provenance.network_policy.mode == "deny_all"
            and any(
                token in lowered
                for token in (
                    "network is unreachable",
                    "name or service not known",
                    "temporary failure in name resolution",
                    "could not resolve host",
                )
            )
        ):
            violations.append(
                SandboxViolation(
                    kind="network_denied",
                    message="Sandbox blocked network egress under deny-all policy.",
                    details={"policy": "deny_all"},
                )
            )
        if any(token in lowered for token in ("permission denied", "operation not permitted")):
            violations.append(
                SandboxViolation(
                    kind="filesystem_denied",
                    message="Sandbox denied filesystem access.",
                    details={},
                )
            )
        return violations

    def _status_for(
        self, returncode: int | None, violations: Sequence[SandboxViolation]
    ) -> ExecutionStatus:
        kinds = {violation.kind for violation in violations}
        if kinds & {
            "wall_clock_exceeded",
            "stdout_exceeded",
            "filesystem_writes_exceeded",
            "cpu_exceeded",
            "memory_exceeded",
            "process_count_exceeded",
        }:
            return (
                ExecutionStatus.TIMED_OUT
                if "wall_clock_exceeded" in kinds
                else ExecutionStatus.FAILED
            )
        return ExecutionStatus.SUCCEEDED if returncode == 0 else ExecutionStatus.FAILED

    def _summary_for(
        self, returncode: int | None, violations: Sequence[SandboxViolation]
    ) -> str:
        if violations:
            return f"Sandbox recorded {len(violations)} violation(s)."
        return f"Command exited with code {returncode}."


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
