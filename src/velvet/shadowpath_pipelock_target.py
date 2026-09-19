"""An exploration target for Pipelock mediating the official filesystem server.

This runs operator-supplied Pipelock and filesystem MCP server binaries over
stdio against a disposable workspace. A supplied ``baseline_root`` provides
the starting filesystem without embedding asset names or route recipes. The
a synthetic configuration-and-payload baseline remains available for older callers.
Runtime digests are verified only when an external lock is supplied.

Three things here are deliberate rather than incidental.

Sessions default to one Pipelock process per call.  The preset carries an
unrelated cross-request budget that can refuse a second call in one session, so
the published result was a two-session sequence and explicitly did not claim a
same-session bypass.  Keeping that the default means a composed route reproduces
the published claim rather than quietly making a stronger one.

:meth:`resolve` joins a prefix and nothing else.  The explorer generates
separator and traversal spellings on purpose; canonicalising them here would
delete the very inputs worth sending.

The workspace is refused if it resolves anywhere near the real home directory.
A generator binds whatever is in its pool, and the pool now includes ancestors
of the protected paths, so the blast radius of a mistake is a directory tree
rather than one file.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import queue
import shutil
import stat
import subprocess  # nosec B404
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Any, cast

from velvet.shadowpath_effects import ResourceRef
from velvet.shadowpath_explorer import CallOutcome, SessionScope
from velvet.shadowpath_observer import OBSERVER_SCHEMA_VERSION, AssetState, snapshot
from velvet.shadowpath_scope import ResourceRelation, filesystem_relations

JsonObject = dict[str, Any]

TARGET_SCHEMA_VERSION = "velvet.shadowpath.pipelock-target.v0.2"

PROTOCOL_VERSION = "2025-11-25"
CLIENT_INFO = {"name": "velvet-shadowpath-explorer", "version": "1"}

APPROVED_CONFIGURATION = "ShadowPath synthetic configuration: approved\n"
STAGED_PAYLOAD = "ShadowPath synthetic configuration: replacement\n"

# Pipelock answers a policy denial with this JSON-RPC code.
_POLICY_DENY_CODE = -32002


class PipelockTargetError(RuntimeError):
    """Raised when the pinned runtime is wrong, missing, or unsafe to drive."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _host_platform_key() -> str:
    """Return the lockfile key for the current operating system and CPU."""

    system = host_platform.system().strip().lower() or "unknown"
    system = {"macos": "darwin"}.get(system, system)
    machine = host_platform.machine().strip().lower() or "unknown"
    machine = {
        "aarch64": "arm64",
        "x86_64": "amd64",
        "x64": "amd64",
    }.get(machine, machine)
    return f"{system}-{machine}"


def _guard_workspace_root(root: Path) -> Path:
    """Refuse any root that is not plainly disposable."""

    resolved = root.resolve()
    home = Path.home().resolve()
    if resolved == home or home in resolved.parents or resolved in home.parents:
        raise PipelockTargetError(
            f"refusing to explore at or near the real home directory: {resolved}"
        )

    def _forms(path: Path) -> set[Path]:
        # /etc and friends are symlinks on macOS, so compare both spellings.
        return {path, path.resolve()} if path.exists() else {path}

    # Trees that never legitimately hold a disposable workspace are refused
    # entirely; roots that do (macOS temp dirs live under /var) only by name.
    for reserved in (Path("/etc"), Path("/usr"), Path("/System"), Path("/bin"), Path("/sbin")):
        for form in _forms(reserved):
            if resolved == form or form in resolved.parents:
                raise PipelockTargetError(f"refusing to explore a system directory: {resolved}")
    for reserved in (
        Path("/"),
        Path("/var"),
        # This is a reserved path being refused, never a temporary-file destination.
        Path("/tmp"),  # noqa: S108  # nosec B108
        Path("/opt"),
    ):
        if resolved in _forms(reserved):
            raise PipelockTargetError(f"refusing to explore a system directory: {resolved}")
    return resolved


class _StdioSession:
    """One mediated (or direct) MCP session over stdio."""

    def __init__(
        self,
        *,
        command: Sequence[str],
        session_dir: Path,
        timeout_seconds: float,
    ) -> None:
        self.command = list(command)
        self.session_dir = session_dir
        self.timeout_seconds = timeout_seconds
        self.process: subprocess.Popen[bytes] | None = None
        self.stderr_stream: IO[str] | None = None
        self.transcript: list[JsonObject] = []
        self._next_id = 1
        self._stdout_buffer = bytearray()
        self._stdout_queue: queue.Queue[bytes | Exception | None] = queue.Queue()
        self._stdout_thread: threading.Thread | None = None

    def __enter__(self) -> _StdioSession:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.stderr_stream = (self.session_dir / "session.stderr.log").open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(  # noqa: S603  # nosec B603
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.stderr_stream,
                bufsize=0,
                env={
                    key: os.environ[key]
                    for key in ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC")
                    if key in os.environ
                },
            )
            self.request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            )
            self._notify("notifications/initialized")
        except Exception:
            self.close()
            raise
        return self

    def _ensure_stdout_reader(self) -> None:
        if self._stdout_thread is not None:
            return
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name="shadowpath-mcp-stdout",
            daemon=True,
        )
        self._stdout_thread.start()

    def _read_stdout(self) -> None:
        """Move pipe bytes into a timed queue on POSIX and Windows."""

        process = self.process
        if process is None or process.stdout is None:
            self._stdout_queue.put(PipelockTargetError("MCP session is not running"))
            return
        try:
            while chunk := process.stdout.read(1 << 16):
                self._stdout_queue.put(chunk)
        except Exception as error:
            self._stdout_queue.put(error)
        finally:
            self._stdout_queue.put(None)

    def __exit__(self, *_: object) -> None:
        self.close()

    def _notify(self, method: str) -> None:
        if self.process is None or self.process.stdin is None:
            return
        message = {"jsonrpc": "2.0", "method": method}
        self.transcript.append({"direction": "client_to_server", "message": message})
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()

    def _next_message(self, deadline: float) -> JsonObject:
        """Read one newline-delimited JSON object without blocking past the deadline."""

        if self.process is None or self.process.stdout is None:
            raise PipelockTargetError("MCP session is not running")
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._stdout_buffer[:newline])
                del self._stdout_buffer[: newline + 1]
                if not raw.strip():
                    continue
                try:
                    decoded = json.loads(raw)
                except (UnicodeDecodeError, ValueError) as error:
                    raise PipelockTargetError("non-JSON output on the MCP channel") from error
                if not isinstance(decoded, Mapping):
                    raise PipelockTargetError("non-object JSON output on the MCP channel")
                return dict(decoded)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PipelockTargetError(
                    f"no complete MCP response within {self.timeout_seconds}s"
                )
            try:
                chunk = self._stdout_queue.get(timeout=remaining)
            except queue.Empty as error:
                raise PipelockTargetError(
                    f"no complete MCP response within {self.timeout_seconds}s"
                ) from error
            if chunk is None:
                if self._stdout_buffer:
                    raise PipelockTargetError("incomplete JSON frame on the MCP channel")
                raise PipelockTargetError("MCP channel closed before a response")
            if isinstance(chunk, Exception):
                raise PipelockTargetError("failed reading the MCP channel") from chunk
            self._stdout_buffer.extend(chunk)

    def request(self, method: str, params: Mapping[str, Any]) -> JsonObject:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise PipelockTargetError("MCP session is not running")
        self._ensure_stdout_reader()
        request_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
        self.transcript.append({"direction": "client_to_server", "message": message})
        self.process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            response = self._next_message(deadline)
            self.transcript.append({"direction": "server_to_client", "message": response})
            if response.get("id") == request_id:
                return response

    def close(self) -> None:
        if self.process is not None:
            process = self.process
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except OSError:
                pass
            if self._stdout_thread is not None:
                self._stdout_thread.join(timeout=1)
                self._stdout_thread = None
            self.process = None
        if self.stderr_stream is not None:
            self.stderr_stream.close()
            self.stderr_stream = None


class PipelockFilesystemTarget:
    """Drive Pipelock's MCP proxy over the official filesystem server."""

    def __init__(
        self,
        *,
        pipelock: str | Path,
        config: str | Path,
        node: str | Path,
        server_entrypoint: str | Path,
        work_root: str | Path,
        baseline_root: str | Path | None = None,
        external_lock: str | Path | None = None,
        platform_key: str | None = None,
        session_scope: SessionScope = "per_call",
        mediated: bool = True,
        timeout_seconds: float = 30.0,
        keep_workspaces: bool = False,
    ) -> None:
        self.pipelock = Path(pipelock).resolve()
        self.config = Path(config).resolve()
        self.node = Path(node).resolve()
        self.server_entrypoint = Path(server_entrypoint).resolve()
        self.work_root = _guard_workspace_root(Path(work_root))
        self.baseline_root = Path(baseline_root).resolve() if baseline_root is not None else None
        self.host_platform_key = _host_platform_key()
        self.platform_key = (platform_key or self.host_platform_key).strip()
        if not self.platform_key:
            raise PipelockTargetError("platform key must not be empty")
        if self.baseline_root is not None:
            self._validate_baseline()
        if session_scope not in ("per_call", "per_route"):
            raise PipelockTargetError(
                "PipelockFilesystemTarget supports per_call and per_route sessions only"
            )
        self.session_scope: SessionScope = session_scope
        self.mediated = mediated
        self.timeout_seconds = timeout_seconds
        self.keep_workspaces = keep_workspaces
        self._sessions: dict[str, _StdioSession] = {}
        self._trial_counter = 0
        for label, path in (
            ("pipelock binary", self.pipelock),
            ("pipelock config", self.config),
            ("node", self.node),
            ("filesystem server entrypoint", self.server_entrypoint),
        ):
            if not path.exists():
                raise PipelockTargetError(f"{label} not found: {path}")
        self._verified = self._verify(Path(external_lock) if external_lock else None)

    # -- pinning ---------------------------------------------------------

    def _verify(self, lock_path: Path | None) -> JsonObject:
        """Check the runtime against the recorded lock and fail closed."""

        observed = {
            "pipelock_binary_sha256": _sha256(self.pipelock),
            "pipelock_config_sha256": _sha256(self.config),
            "node_binary_sha256": _sha256(self.node),
            "server_entrypoint_sha256": _sha256(self.server_entrypoint),
        }
        if lock_path is None:
            return {
                "lock": None,
                "lock_sha256": None,
                "platform_key": self.platform_key,
                "observed": observed,
                "expected": {},
                "verified": False,
                "all_recorded_components_verified": False,
                "complete_runtime_verified": False,
                "verified_components": [],
                "unverified_components": sorted([*observed, "server_dependency_closure"]),
                "verification_scope": "selected executable and configuration files only",
            }
        try:
            lock = cast(JsonObject, json.loads(lock_path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as error:
            raise PipelockTargetError(f"cannot read external lock: {error}") from error
        try:
            pipelock_lock = cast(Mapping[str, Any], lock["pipelock"])
            platforms = cast(Mapping[str, Any], pipelock_lock["platforms"])
            if self.platform_key not in platforms:
                raise PipelockTargetError(
                    f"external lock has no runtime hash for platform {self.platform_key!r}"
                )
            platform = cast(Mapping[str, Any], platforms[self.platform_key])
            mcp_lock = cast(Mapping[str, Any], lock["mcp_filesystem"])
            expected = {
                "pipelock_binary_sha256": str(platform["binary_sha256"]),
                "pipelock_config_sha256": str(pipelock_lock["config_sha256"]),
                "server_entrypoint_sha256": str(mcp_lock["entrypoint_sha256"]),
            }
        except (KeyError, TypeError) as error:
            raise PipelockTargetError("external lock is missing required runtime hashes") from error
        if mcp_lock.get("node_binary_sha256") is not None:
            expected["node_binary_sha256"] = str(mcp_lock["node_binary_sha256"])
        mismatches = {
            key: {"expected": expected[key], "observed": observed[key]}
            for key in expected
            if expected[key] != observed[key]
        }
        if mismatches:
            raise PipelockTargetError(
                f"pinned runtime does not match the recorded lock: {json.dumps(mismatches)}"
            )
        unverified_recorded = sorted(set(observed) - set(expected))
        return {
            "lock": lock_path.as_posix(),
            "lock_sha256": _sha256(lock_path),
            "platform_key": self.platform_key,
            "observed": observed,
            "expected": expected,
            "verified": True,
            "all_recorded_components_verified": not unverified_recorded,
            # The entrypoint hash does not bind the imported package tree or its
            # dependency closure, so this adapter cannot claim a complete runtime.
            "complete_runtime_verified": False,
            "verified_components": sorted(expected),
            "unverified_components": sorted([*unverified_recorded, "server_dependency_closure"]),
            "verification_scope": "selected executable and configuration files only",
        }

    def manifest(self) -> Mapping[str, Any]:
        return {
            "schema_version": TARGET_SCHEMA_VERSION,
            "pipelock": self.pipelock.as_posix(),
            "config": self.config.as_posix(),
            "node": self.node.as_posix(),
            "server_entrypoint": self.server_entrypoint.as_posix(),
            "mediated": self.mediated,
            "session_scope": self.session_scope,
            "platform_key": self.platform_key,
            "host_platform_key": self.host_platform_key,
            "work_root": self.work_root.as_posix(),
            "baseline": {
                "kind": "directory" if self.baseline_root is not None else "legacy_fixture",
                "root": self.baseline_root.as_posix() if self.baseline_root is not None else None,
            },
            "resource_model": {
                "namespace": "pipelock.filesystem.workspace",
                "invocation_namespace": "pipelock.mcp.proxy",
                "kinds": ["filesystem.entry"],
                "default_resource_kind": "filesystem.entry",
                "observer_schema": OBSERVER_SCHEMA_VERSION,
                "path_flavor": ("windows" if os.name == "nt" else "posix"),
            },
            "observation_scope": {
                "observer": "direct recursive filesystem snapshot",
                "independent_of_mediation": True,
                "sampling": "on demand after reset and each call",
                "settling": "explorer requires repeated identical scope digests",
                "completeness": "bounded to entries under the disposable workspace root",
                "replay_address_stability": "stable wire root across sequential trial resets",
                "concurrency": "one trial at a time",
            },
            "pinning": self._verified,
        }

    # -- workspace -------------------------------------------------------

    def _validate_baseline(self) -> None:
        baseline = self.baseline_root
        if baseline is None:
            return
        if not baseline.is_dir():
            raise PipelockTargetError(f"baseline directory not found: {baseline}")
        if baseline.is_relative_to(self.work_root) or self.work_root.is_relative_to(baseline):
            raise PipelockTargetError("baseline and work root must not overlap")
        self._validate_tree(baseline)

    @staticmethod
    def _validate_tree(root: Path) -> None:
        """Check links without following them during traversal or copying."""

        for directory, directories, files in os.walk(root, followlinks=False):
            for name in [*directories, *files]:
                path = Path(directory) / name
                info = path.lstat()
                mode = info.st_mode
                if stat.S_ISLNK(mode):
                    link = Path(os.readlink(path))
                    lexical = Path(
                        os.path.normpath(link if link.is_absolute() else path.parent / link)
                    )
                    try:
                        resolved = path.resolve()
                    except (OSError, RuntimeError) as error:
                        raise PipelockTargetError(
                            f"cannot resolve baseline symlink: {path}"
                        ) from error
                    if not lexical.is_relative_to(root) or not resolved.is_relative_to(root):
                        raise PipelockTargetError(f"baseline symlink escapes its root: {path}")
                elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise PipelockTargetError(f"unsupported baseline entry: {path}")
                elif stat.S_ISREG(mode) and info.st_nlink > 1:
                    raise PipelockTargetError(
                        f"baseline hard links cannot be copied faithfully: {path}"
                    )

    def _copy_baseline(self, space: Path) -> None:
        baseline = self.baseline_root
        if baseline is None:
            raise PipelockTargetError("baseline root is not configured")
        self._validate_baseline()
        shutil.copytree(baseline, space, symlinks=True)
        # An absolute link into the original tree must point at the disposable
        # copy before any server sees it. Relative links retain their spelling.
        for directory, directories, files in os.walk(space, followlinks=False):
            for name in [*directories, *files]:
                path = Path(directory) / name
                if path.is_symlink():
                    link = Path(os.readlink(path))
                    if link.is_absolute():
                        try:
                            relative = link.relative_to(baseline)
                        except ValueError as error:
                            raise PipelockTargetError(
                                f"baseline symlink escapes its root: {path}"
                            ) from error
                        path.unlink()
                        path.symlink_to(os.path.relpath(space / relative, path.parent))
        self._validate_tree(space)

    def _trial_dir(self, trial_id: str) -> Path:
        safe = "".join(char if char.isalnum() or char in "-_." else "_" for char in trial_id)
        if safe in ("", ".", ".."):
            raise PipelockTargetError("trial id must name a child of the work root")
        return self.work_root / safe

    def workspace(self, trial_id: str) -> Path:
        # Logical path arguments can be persisted as ordinary data. A stable
        # wire root keeps such state replayable across fresh trial IDs.
        self._trial_dir(trial_id)  # Validate the identifier even though the path is shared.
        return self.work_root / "workspace"

    def reset(self, trial_id: str) -> None:
        self.teardown(trial_id)
        trial = self._trial_dir(trial_id)
        if trial.exists():
            shutil.rmtree(trial)
        space = self.workspace(trial_id)
        # ``keep_workspaces`` preserves the final state for inspection after a
        # trial. A reset must still begin from a clean baseline.
        if space.exists():
            shutil.rmtree(space)
        if self.baseline_root is not None:
            try:
                self._copy_baseline(space)
            except Exception:
                shutil.rmtree(trial, ignore_errors=True)
                shutil.rmtree(space, ignore_errors=True)
                raise
            return
        (space / "home").mkdir(parents=True)
        # A synthetic disposable configuration plus independently controlled
        # content inside the allowed root.
        (space / "home" / "settings.cfg").write_text(
            APPROVED_CONFIGURATION, encoding="utf-8"
        )
        (space / "home" / "payload.txt").write_text(STAGED_PAYLOAD, encoding="utf-8")

    def observe(self, trial_id: str) -> dict[str, AssetState]:
        return snapshot(self.workspace(trial_id))

    def root(self, trial_id: str) -> str | None:
        return self.workspace(trial_id).as_posix()

    def resource_relations(
        self, resources: Sequence[ResourceRef]
    ) -> Sequence[ResourceRelation]:
        """Declare filesystem containment using the host provider's path rules."""

        return filesystem_relations(
            resources,
            flavor="windows" if os.name == "nt" else "posix",
        )

    def resolve(self, trial_id: str, path: str) -> str:
        """Prefix-join only: the spelling the explorer generated is preserved."""

        base = self.workspace(trial_id).as_posix()
        candidate = path.strip()
        if not candidate:
            return base
        if candidate.startswith("/"):
            return candidate
        return f"{base}/{candidate}"

    # -- dispatch --------------------------------------------------------

    def _command(self, trial_id: str, session_dir: Path) -> list[str]:
        server = [
            str(self.node),
            str(self.server_entrypoint),
            str(self.workspace(trial_id)),
        ]
        if not self.mediated:
            return server
        return [
            str(self.pipelock),
            "--home",
            str(session_dir / "pipelock-home"),
            "mcp",
            "proxy",
            "--config",
            str(self.config),
            "--capture-output",
            str(session_dir / "capture"),
            "--",
            *server,
        ]

    def _session(self, trial_id: str) -> _StdioSession:
        if self.session_scope != "per_call":
            existing = self._sessions.get(trial_id)
            if existing is not None:
                return existing
        self._trial_counter += 1
        session_dir = self._trial_dir(trial_id) / f"session-{self._trial_counter:05d}"
        session = _StdioSession(
            command=self._command(trial_id, session_dir),
            session_dir=session_dir,
            timeout_seconds=self.timeout_seconds,
        ).__enter__()
        if self.session_scope != "per_call":
            self._sessions[trial_id] = session
        return session

    def advertise(self) -> Sequence[Mapping[str, Any]]:
        """Read the tool surface through the mediation boundary."""

        trial_id = "advertise"
        self.reset(trial_id)
        session: _StdioSession | None = None
        try:
            session = self._session(trial_id)
            tools: list[JsonObject] = []
            cursor: str | None = None
            cursors_seen: set[str] = set()
            while True:
                params: JsonObject = {"cursor": cursor} if cursor is not None else {}
                response = session.request("tools/list", params)
                result = response.get("result")
                if not isinstance(result, Mapping) or not isinstance(result.get("tools"), list):
                    raise PipelockTargetError("tools/list did not return a tool surface")
                raw_tools = cast(Sequence[Any], result["tools"])
                if any(not isinstance(tool, Mapping) for tool in raw_tools):
                    raise PipelockTargetError("tools/list returned a malformed tool entry")
                tools.extend(dict(cast(Mapping[str, Any], tool)) for tool in raw_tools)
                next_cursor = result.get("nextCursor")
                if next_cursor is None:
                    break
                if not isinstance(next_cursor, str) or not next_cursor:
                    raise PipelockTargetError("tools/list returned a malformed nextCursor")
                if next_cursor in cursors_seen:
                    raise PipelockTargetError("tools/list repeated a pagination cursor")
                cursors_seen.add(next_cursor)
                cursor = next_cursor
        finally:
            if self.session_scope == "per_call" and session is not None:
                session.close()
            self.teardown(trial_id)
        if not tools:
            raise PipelockTargetError("tools/list returned an empty surface")
        return tools

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        session = self._session(trial_id)
        try:
            response = session.request(
                "tools/call",
                {"name": call["name"], "arguments": dict(call.get("arguments", {}))},
            )
        except PipelockTargetError as error:
            return CallOutcome(status="error", block_reason=None, raw={"error": str(error)})
        finally:
            if self.session_scope == "per_call":
                session.close()
        rpc_error = response.get("error")
        if isinstance(rpc_error, Mapping):
            data = rpc_error.get("data")
            reason = (
                str(cast(Mapping[str, Any], data).get("block_reason"))
                if isinstance(data, Mapping) and data.get("block_reason") is not None
                else None
            )
            blocked = rpc_error.get("code") == _POLICY_DENY_CODE or reason is not None
            return CallOutcome(
                status="blocked" if blocked else "error",
                block_reason=reason,
                raw=dict(rpc_error),
            )
        result = response.get("result")
        if not isinstance(result, Mapping) or not isinstance(result.get("content"), list):
            return CallOutcome(
                status="error",
                block_reason=None,
                raw={"error": "malformed tools/call result", "response": dict(response)},
            )
        if result.get("isError") is True:
            return CallOutcome(status="error", block_reason=None, raw=dict(result))
        return CallOutcome(
            status="executed",
            block_reason=None,
            raw=dict(result),
        )

    def teardown(self, trial_id: str) -> None:
        session = self._sessions.pop(trial_id, None)
        if session is not None:
            session.close()
        if not self.keep_workspaces:
            space = self.workspace(trial_id)
            if space.exists():
                shutil.rmtree(space, ignore_errors=True)

    def close(self) -> None:
        for trial_id in list(self._sessions):
            self.teardown(trial_id)
