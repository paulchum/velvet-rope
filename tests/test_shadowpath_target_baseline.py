"""Filesystem baselines and target lifecycle, without external subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock, call, patch

import pytest

from velvet.shadowpath_pipelock_target import (
    PipelockFilesystemTarget,
    PipelockTargetError,
    _StdioSession,
)


def _target(tmp_path: Path, baseline: Path, **kwargs: Any) -> PipelockFilesystemTarget:
    runtime = tmp_path / "runtime"
    runtime.mkdir(exist_ok=True)
    paths: dict[str, Any] = {}
    for label in ("pipelock", "config", "node", "server_entrypoint"):
        path = runtime / label
        path.write_text("stand-in runtime", encoding="utf-8")
        paths[label] = path
    return PipelockFilesystemTarget(
        **paths, baseline_root=baseline, work_root=tmp_path / "work", **kwargs
    )


def test_baseline_copy_is_independent_and_reset_restores_it(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    (baseline / "docs" / "empty").mkdir(parents=True)
    (baseline / "docs" / "settings.cfg").write_text("approved", encoding="utf-8")
    (baseline / "docs" / "settings.cfg").chmod(0o640)
    target = _target(tmp_path, baseline)
    target.reset("one")
    assert set(target.observe("one")) == {"docs", "docs/empty", "docs/settings.cfg"}
    assert target.observe("one")["docs/settings.cfg"].mode == 0o640
    copied = target.workspace("one") / "docs" / "settings.cfg"
    copied.write_text("mutated", encoding="utf-8")
    assert (baseline / "docs" / "settings.cfg").read_text(encoding="utf-8") == "approved"
    target.reset("one")
    assert copied.read_text(encoding="utf-8") == "approved"
    assert target.manifest()["baseline"] == {"kind": "directory", "root": str(baseline)}
    assert target.manifest()["pinning"]["verified"] is False


def test_internal_symlinks_point_only_at_disposable_copy(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "data").write_text("original", encoding="utf-8")
    (baseline / "relative").symlink_to("data")
    (baseline / "absolute").symlink_to(baseline / "data")
    (baseline / "dangling").symlink_to("missing")
    target = _target(tmp_path, baseline)
    target.reset("one")
    space = target.workspace("one")
    assert os.readlink(space / "relative") == "data"
    assert os.readlink(space / "dangling") == "missing"
    assert (space / "absolute").resolve() == space / "data"
    (space / "absolute").write_text("changed", encoding="utf-8")
    assert (baseline / "data").read_text(encoding="utf-8") == "original"
    assert os.readlink(baseline / "absolute") == str(baseline / "data")


@pytest.mark.parametrize("link", ["../outside", "/etc/passwd", "../baseline/data"])
def test_escaping_or_nonportable_symlinks_are_refused(tmp_path: Path, link: str) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "data").write_text("original", encoding="utf-8")
    (baseline / "escape").symlink_to(link)
    if link == "../baseline/data":
        # This resolves inside the source, but would escape the copy under its
        # new name. Lexical containment prevents preserving an unsafe link.
        with pytest.raises(PipelockTargetError, match="symlink escapes"):
            target = _target(tmp_path, baseline)
            target.reset("one")
    else:
        with pytest.raises(PipelockTargetError, match="symlink escapes"):
            _target(tmp_path, baseline)


@pytest.mark.parametrize("layout", ["equal", "baseline_inside_work", "work_inside_baseline"])
def test_baseline_must_not_overlap_work_root(tmp_path: Path, layout: str) -> None:
    baseline = {
        "equal": tmp_path / "work",
        "baseline_inside_work": tmp_path / "work" / "baseline",
        "work_inside_baseline": tmp_path,
    }[layout]
    baseline.mkdir(parents=True, exist_ok=True)
    with pytest.raises(PipelockTargetError, match="must not overlap"):
        _target(tmp_path, baseline)


def test_baseline_is_revalidated_before_each_copy(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    target = _target(tmp_path, baseline)
    (baseline / "late-link").symlink_to("/etc/passwd")
    with pytest.raises(PipelockTargetError, match="symlink escapes"):
        target.reset("one")
    assert not target.workspace("one").exists()


def test_baseline_rejects_hard_links_that_copytree_would_split(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    first = baseline / "first"
    first.write_text("shared", encoding="utf-8")
    os.link(first, baseline / "second")

    with pytest.raises(PipelockTargetError, match="hard links cannot be copied faithfully"):
        _target(tmp_path, baseline)


@pytest.mark.parametrize("scope", ["per_call", "per_route"])
@pytest.mark.parametrize("fails", [False, True])
def test_advertisement_releases_session_and_workspace(
    tmp_path: Path, scope: str, fails: bool
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    target = _target(tmp_path, baseline, session_scope=scope)
    session = Mock()
    session.request.return_value = {"result": {"tools": [{"name": "list"}]}}
    if fails:
        session.request.side_effect = PipelockTargetError("request failed")

    def connect(trial_id: str) -> Mock:
        if scope != "per_call":
            target._sessions[trial_id] = session
        return session

    with patch.object(target, "_session", side_effect=connect):
        if fails:
            with pytest.raises(PipelockTargetError, match="request failed"):
                target.advertise()
        else:
            assert target.advertise() == [{"name": "list"}]
    session.close.assert_called_once()
    assert not target._sessions
    assert not target.workspace("advertise").exists()


def test_advertisement_rejects_a_partially_malformed_tool_list(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    target = _target(tmp_path, baseline)
    session = Mock()
    session.request.return_value = {
        "result": {"tools": [{"name": "valid", "inputSchema": {}}, "malformed"]}
    }

    with (
        patch.object(target, "_session", return_value=session),
        pytest.raises(PipelockTargetError, match="malformed tool entry"),
    ):
        target.advertise()

    session.close.assert_called_once()
    assert not target.workspace("advertise").exists()


def test_advertisement_collects_every_paginated_tool_page(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    target = _target(tmp_path, baseline)
    session = Mock()
    session.request.side_effect = [
        {
            "result": {
                "tools": [{"name": "first", "inputSchema": {}}],
                "nextCursor": "page-2",
            }
        },
        {"result": {"tools": [{"name": "second", "inputSchema": {}}]}},
    ]

    with patch.object(target, "_session", return_value=session):
        tools = target.advertise()

    assert [tool["name"] for tool in tools] == ["first", "second"]
    assert session.request.call_args_list == [
        call("tools/list", {}),
        call("tools/list", {"cursor": "page-2"}),
    ]


def test_advertisement_rejects_a_repeated_pagination_cursor(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    target = _target(tmp_path, baseline)
    session = Mock()
    session.request.return_value = {"result": {"tools": [], "nextCursor": "same"}}

    with (
        patch.object(target, "_session", return_value=session),
        pytest.raises(PipelockTargetError, match="repeated a pagination cursor"),
    ):
        target.advertise()


def test_initialization_failure_closes_process_and_stderr(tmp_path: Path) -> None:
    session = _StdioSession(command=["unused"], session_dir=tmp_path, timeout_seconds=1)
    process = Mock()
    with (
        patch("velvet.shadowpath_pipelock_target.subprocess.Popen", return_value=process),
        patch.object(session, "request", side_effect=PipelockTargetError("no handshake")),
        pytest.raises(PipelockTargetError, match="no handshake"),
    ):
        session.__enter__()
    process.terminate.assert_called_once()
    assert session.process is None
    assert session.stderr_stream is None


def _wire_session(tmp_path: Path, code: str, *, timeout: float = 0.2) -> _StdioSession:
    session = _StdioSession(command=["test-server"], session_dir=tmp_path, timeout_seconds=timeout)
    session.process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-u", "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return session


def test_partial_mcp_frame_cannot_block_past_request_deadline(tmp_path: Path) -> None:
    session = _wire_session(
        tmp_path,
        "import sys,time; sys.stdin.buffer.readline(); "
        "sys.stdout.buffer.write(b'{\"jsonrpc\":'); sys.stdout.buffer.flush(); time.sleep(2)",
    )
    started = time.monotonic()
    try:
        with pytest.raises(PipelockTargetError, match="no complete MCP response"):
            session.request("tools/list", {})
    finally:
        session.close()

    assert time.monotonic() - started < 1


def test_buffered_notification_does_not_hide_following_response(tmp_path: Path) -> None:
    session = _wire_session(
        tmp_path,
        "import json,sys; request=json.loads(sys.stdin.readline()); "
        "frames=[{'jsonrpc':'2.0','method':'notice'},"
        "{'jsonrpc':'2.0','id':request['id'],'result':{'ok':True}}]; "
        "sys.stdout.write(''.join(json.dumps(item)+'\\n' for item in frames)); "
        "sys.stdout.flush()",
    )
    try:
        response = session.request("tools/list", {})
    finally:
        session.close()

    assert response["result"] == {"ok": True}
    assert len(session.transcript) == 3


def test_non_object_json_frame_is_rejected_as_a_protocol_error(tmp_path: Path) -> None:
    session = _wire_session(
        tmp_path,
        "import sys; sys.stdin.buffer.readline(); sys.stdout.write('[]\\n'); sys.stdout.flush()",
    )
    try:
        with pytest.raises(PipelockTargetError, match="non-object JSON"):
            session.request("tools/list", {})
    finally:
        session.close()
