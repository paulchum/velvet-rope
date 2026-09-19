"""Target contract checks that do not need the pinned binaries.

These cover the parts that must be right before a real run is worth trusting:
the workspace safety interlock, prefix-only path resolution, fail-closed
pinning, the proxy command shape, and how a response becomes a CallOutcome.
Driving the real Pipelock release is a separate, explicitly opted-in run.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from velvet.shadowpath_pipelock_target import (
    PipelockFilesystemTarget,
    PipelockTargetError,
    _guard_workspace_root,
)


def _runtime(tmp_path: Path) -> dict[str, Path]:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    paths = {
        "pipelock": runtime / "pipelock",
        "config": runtime / "policy.yaml",
        "node": runtime / "node",
        "server_entrypoint": runtime / "dist" / "index.js",
    }
    paths["server_entrypoint"].parent.mkdir(parents=True)
    for name, path in paths.items():
        path.write_text(f"stand-in for {name}\n", encoding="utf-8")
    return paths


def _target(tmp_path: Path, **overrides: Any) -> PipelockFilesystemTarget:
    paths = _runtime(tmp_path)
    kwargs: dict[str, Any] = {
        **{key: value for key, value in paths.items()},
        "work_root": tmp_path / "work",
        **overrides,
    }
    (tmp_path / "work").mkdir(exist_ok=True)
    return PipelockFilesystemTarget(**kwargs)


def test_workspace_guard_refuses_the_real_home() -> None:
    with pytest.raises(PipelockTargetError, match="real home directory"):
        _guard_workspace_root(Path.home() / "Documents" / "velvet-scratch")
    with pytest.raises(PipelockTargetError, match="real home directory"):
        _guard_workspace_root(Path.home().parent)
    with pytest.raises(PipelockTargetError, match="system directory"):
        _guard_workspace_root(Path("/etc"))


def test_resolve_is_prefix_join_and_preserves_generated_spellings(tmp_path: Path) -> None:
    target = _target(tmp_path)
    base = target.workspace("t1").as_posix()

    assert target.resolve("t1", "home/settings.cfg") == f"{base}/home/settings.cfg"
    # The spellings the explorer generates must survive onto the wire; a
    # canonicalising resolver would silently delete these test cases.
    assert target.resolve("t1", r"home\settings.cfg") == f"{base}/home\\settings.cfg"
    assert target.resolve(
        "t1", "home/sentinel/../settings.cfg"
    ) == f"{base}/home/sentinel/../settings.cfg"
    assert target.resolve("t1", "home/./settings.cfg") == f"{base}/home/./settings.cfg"
    # An absolute path is already on the wire and is passed through untouched.
    assert target.resolve("t1", "/sandbox/exact") == "/sandbox/exact"


def test_workspace_and_resolved_paths_are_stable_across_trial_replay(tmp_path: Path) -> None:
    target = _target(tmp_path)

    assert target.workspace("first") == target.workspace("second")
    assert target.resolve("first", "home/file") == target.resolve("second", "home/file")


def test_missing_runtime_component_is_refused(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)
    paths["pipelock"].unlink()
    with pytest.raises(PipelockTargetError, match="pipelock binary not found"):
        PipelockFilesystemTarget(
            pipelock=paths["pipelock"],
            config=paths["config"],
            node=paths["node"],
            server_entrypoint=paths["server_entrypoint"],
            work_root=tmp_path / "work",
        )


def test_pinning_fails_closed_on_a_hash_mismatch(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)
    lock = tmp_path / "external-lock.json"
    lock.write_text(
        json.dumps(
            {
                "pipelock": {
                    "config_sha256": "0" * 64,
                    "platforms": {"darwin-arm64": {"binary_sha256": "1" * 64}},
                },
                "mcp_filesystem": {"entrypoint_sha256": "2" * 64},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PipelockTargetError, match="does not match the recorded lock"):
        PipelockFilesystemTarget(
            pipelock=paths["pipelock"],
            config=paths["config"],
            node=paths["node"],
            server_entrypoint=paths["server_entrypoint"],
            work_root=tmp_path / "work",
            external_lock=lock,
            platform_key="darwin-arm64",
        )


def test_malformed_external_lock_fails_with_a_target_error(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)
    lock = tmp_path / "external-lock.json"
    lock.write_text('{"pipelock": {}}', encoding="utf-8")
    with pytest.raises(PipelockTargetError, match="required runtime hashes"):
        PipelockFilesystemTarget(
            pipelock=paths["pipelock"],
            config=paths["config"],
            node=paths["node"],
            server_entrypoint=paths["server_entrypoint"],
            work_root=tmp_path / "work",
            external_lock=lock,
            platform_key="darwin-arm64",
        )


def test_lock_reports_unpinned_node_runtime_as_partial_verification(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    lock = tmp_path / "external-lock.json"
    lock.write_text(
        json.dumps(
            {
                "pipelock": {
                    "config_sha256": digest(paths["config"]),
                    "platforms": {"darwin-arm64": {"binary_sha256": digest(paths["pipelock"])}},
                },
                "mcp_filesystem": {"entrypoint_sha256": digest(paths["server_entrypoint"])},
            }
        ),
        encoding="utf-8",
    )
    target = PipelockFilesystemTarget(
        pipelock=paths["pipelock"],
        config=paths["config"],
        node=paths["node"],
        server_entrypoint=paths["server_entrypoint"],
        work_root=tmp_path / "work",
        external_lock=lock,
        platform_key="darwin-arm64",
    )
    pinning = target.manifest()["pinning"]
    assert pinning["verified"] is True
    assert pinning["complete_runtime_verified"] is False
    assert pinning["all_recorded_components_verified"] is False
    assert pinning["unverified_components"] == [
        "node_binary_sha256",
        "server_dependency_closure",
    ]
    assert pinning["expected"]["pipelock_binary_sha256"] == digest(paths["pipelock"])
    assert pinning["lock_sha256"] == digest(lock)
    assert pinning["platform_key"] == "darwin-arm64"


def test_lock_selects_an_explicit_non_host_platform_key(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    lock = tmp_path / "external-lock.json"
    lock.write_text(
        json.dumps(
            {
                "pipelock": {
                    "config_sha256": digest(paths["config"]),
                    "platforms": {"linux-amd64": {"binary_sha256": digest(paths["pipelock"])}},
                },
                "mcp_filesystem": {
                    "entrypoint_sha256": digest(paths["server_entrypoint"]),
                    "node_binary_sha256": digest(paths["node"]),
                },
            }
        ),
        encoding="utf-8",
    )

    target = PipelockFilesystemTarget(
        pipelock=paths["pipelock"],
        config=paths["config"],
        node=paths["node"],
        server_entrypoint=paths["server_entrypoint"],
        work_root=tmp_path / "work",
        external_lock=lock,
        platform_key="linux-amd64",
    )
    pinning = target.manifest()["pinning"]
    assert pinning["platform_key"] == "linux-amd64"
    assert pinning["all_recorded_components_verified"] is True
    assert pinning["complete_runtime_verified"] is False
    assert pinning["unverified_components"] == ["server_dependency_closure"]


def test_lock_fails_closed_when_selected_platform_is_absent(tmp_path: Path) -> None:
    paths = _runtime(tmp_path)
    lock = tmp_path / "external-lock.json"
    lock.write_text(
        json.dumps(
            {
                "pipelock": {
                    "config_sha256": "0" * 64,
                    "platforms": {"darwin-arm64": {"binary_sha256": "1" * 64}},
                },
                "mcp_filesystem": {"entrypoint_sha256": "2" * 64},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PipelockTargetError, match="no runtime hash for platform 'linux-amd64'"):
        PipelockFilesystemTarget(
            pipelock=paths["pipelock"],
            config=paths["config"],
            node=paths["node"],
            server_entrypoint=paths["server_entrypoint"],
            work_root=tmp_path / "work",
            external_lock=lock,
            platform_key="linux-amd64",
        )


def test_manifest_reports_unverified_when_no_lock_is_supplied(tmp_path: Path) -> None:
    target = _target(tmp_path)
    manifest = target.manifest()
    pinning = manifest["pinning"]
    assert pinning["verified"] is False
    assert set(pinning["observed"]) == {
        "pipelock_binary_sha256",
        "pipelock_config_sha256",
        "node_binary_sha256",
        "server_entrypoint_sha256",
    }
    assert pinning["complete_runtime_verified"] is False
    assert pinning["unverified_components"] == sorted(
        [*pinning["observed"], "server_dependency_closure"]
    )
    assert manifest["session_scope"] == "per_call"


def test_target_rejects_a_persistent_session_claim_it_cannot_implement(tmp_path: Path) -> None:
    with pytest.raises(PipelockTargetError, match="per_call and per_route"):
        _target(tmp_path, session_scope="persistent")


def test_proxy_command_matches_the_pinned_invocation(tmp_path: Path) -> None:
    target = _target(tmp_path)
    session_dir = tmp_path / "sess"
    command = target._command("t1", session_dir)

    assert command[0] == str(target.pipelock)
    assert command[1:3] == ["--home", str(session_dir / "pipelock-home")]
    assert command[3:5] == ["mcp", "proxy"]
    assert command[5:7] == ["--config", str(target.config)]
    assert command[7:9] == ["--capture-output", str(session_dir / "capture")]
    assert command[9] == "--"
    # The mediated server is launched behind the separator, rooted at the
    # disposable workspace and nothing wider.
    assert command[10:] == [
        str(target.node),
        str(target.server_entrypoint),
        str(target.workspace("t1")),
    ]


def test_unmediated_command_drops_the_proxy(tmp_path: Path) -> None:
    target = _target(tmp_path, mediated=False)
    command = target._command("t1", tmp_path / "sess")
    assert command == [
        str(target.node),
        str(target.server_entrypoint),
        str(target.workspace("t1")),
    ]


def test_reset_stages_a_disposable_configuration_and_payload(tmp_path: Path) -> None:
    target = _target(tmp_path)
    target.reset("t1")
    space = target.workspace("t1")
    assert (space / "home" / "settings.cfg").read_text(encoding="utf-8").endswith("approved\n")
    assert (space / "home" / "payload.txt").read_text(encoding="utf-8").endswith(
        "replacement\n"
    )
    observed = target.observe("t1")
    assert "home/settings.cfg" in observed
    assert target.root("t1") == space.as_posix()


@pytest.mark.parametrize(
    ("response", "expected_status", "expected_reason"),
    [
        (
            {"error": {"code": -32002, "data": {"block_reason": "tool_policy_deny"}}},
            "blocked",
            "tool_policy_deny",
        ),
        ({"error": {"code": -32603, "message": "boom"}}, "error", None),
        ({"result": {"isError": True, "content": []}}, "error", None),
        ({"result": {"content": [{"type": "text", "text": "ok"}]}}, "executed", None),
        ({}, "error", None),
        ({"result": None}, "error", None),
        ({"result": "ok"}, "error", None),
        ({"result": {}}, "error", None),
    ],
)
def test_response_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any],
    expected_status: str,
    expected_reason: str | None,
) -> None:
    target = _target(tmp_path)

    class _FakeSession:
        def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return response

        def close(self) -> None:
            return None

    monkeypatch.setattr(target, "_session", lambda trial_id: _FakeSession())
    outcome = target.invoke("t1", {"name": "move_file", "arguments": {}})
    assert outcome.status == expected_status
    assert outcome.block_reason == expected_reason
