"""Route discovery against a synthetic mediated-filesystem regression.

The central test gives the explorer nothing but an advertised tool list, a
protected path, and the filesystem state it can observe. Direct mutation is
gated while a generic relocation operation is present, and the server refuses
to relocate onto an existing destination. Nobody tells the explorer which
composition changes the protected state.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from velvet.shadowpath_explorer import (
    CallOutcome,
    ExplorationScope,
    SessionScope,
    ShadowPathExplorerError,
    classify_operations,
    encode_variants,
    explore,
    path_candidates_from_policy,
    plan_routes,
)
from velvet.shadowpath_observer import AssetState, ProtectedAsset, snapshot

APPROVED = "approved synthetic configuration\n"
PAYLOAD = "replacement synthetic configuration\n"

POLICY_TEXT = (
    '- name: "Protected Configuration Mutation"\n'
    "  tool_pattern: '(?i)^(write_file|edit_file)$'\n"
    "  arg_pattern: '(?i)(?:^|/)\\.guardedcfg\\b'\n"
    "  action: block\n"
)

PROTECTED_BASENAMES = ("settings.cfg",)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "file to read"}},
            "required": ["path"],
        },
    },
    {
        "name": "list_directory",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "directory"}},
            "required": ["path"],
        },
    },
    {
        "name": "get_file_info",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "file metadata"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "file to write"},
                "content": {"type": "string", "description": "bytes to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "edit_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "file to edit"},
                "edits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "oldText": {"type": "string"},
                            "newText": {"type": "string"},
                        },
                        "required": ["oldText", "newText"],
                    },
                },
            },
            "required": ["path", "edits"],
        },
    },
    {
        "name": "move_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "path to move from"},
                "destination": {"type": "string", "description": "path to move to"},
            },
            "required": ["source", "destination"],
        },
    },
    {
        "name": "create_directory",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "directory to create"}},
            "required": ["path"],
        },
    },
]


def _recorded_filesystem_surface() -> list[dict[str, Any]]:
    """The 14 operation/input-schema surface advertised by the recorded MCP server."""

    by_name = {tool["name"]: copy.deepcopy(tool) for tool in TOOLS}
    read_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "head": {"type": "number"},
            "tail": {"type": "number"},
        },
        "required": ["path"],
    }
    by_name.update(
        {
            "read_file": {
                "name": "read_file",
                "inputSchema": copy.deepcopy(read_schema),
            },
            "read_text_file": {
                "name": "read_text_file",
                "inputSchema": copy.deepcopy(read_schema),
            },
            "read_media_file": {
                "name": "read_media_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            "read_multiple_files": {
                "name": "read_multiple_files",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        }
                    },
                    "required": ["paths"],
                },
            },
            "list_directory_with_sizes": {
                "name": "list_directory_with_sizes",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "sortBy": {
                            "type": "string",
                            "enum": ["name", "size"],
                            "default": "name",
                        },
                    },
                    "required": ["path"],
                },
            },
            "directory_tree": {
                "name": "directory_tree",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "excludePatterns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": [],
                        },
                    },
                    "required": ["path"],
                },
            },
            "search_files": {
                "name": "search_files",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "pattern": {"type": "string"},
                        "excludePatterns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": [],
                        },
                    },
                    "required": ["path", "pattern"],
                },
            },
            "list_allowed_directories": {
                "name": "list_allowed_directories",
                "inputSchema": {"type": "object", "properties": {}},
            },
            "edit_file": {
                "name": "edit_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "edits": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "oldText": {"type": "string"},
                                    "newText": {"type": "string"},
                                },
                                "required": ["oldText", "newText"],
                            },
                        },
                        "dryRun": {"type": "boolean", "default": False},
                    },
                    "required": ["path", "edits"],
                },
            },
        }
    )
    names = (
        "read_file",
        "read_text_file",
        "read_media_file",
        "read_multiple_files",
        "write_file",
        "edit_file",
        "create_directory",
        "list_directory",
        "list_directory_with_sizes",
        "directory_tree",
        "move_file",
        "search_files",
        "get_file_info",
        "list_allowed_directories",
    )
    return [by_name[name] for name in names]


class MediatedFilesystem:
    """A disposable server behind a policy with the shape of the real defect.

    Write and edit are refused when an argument names the synthetic protected
    configuration. Relocation remains independently discoverable.
    """

    session_scope: SessionScope = "per_call"

    def __init__(self, base: Path) -> None:
        self.base = base

    def manifest(self) -> Mapping[str, Any]:
        return {"fixture": "MediatedFilesystem"}

    def advertise(self) -> Sequence[Mapping[str, Any]]:
        return TOOLS

    def resolve(self, trial_id: str, path: str) -> str:
        # Prefix-join only, exactly as a real target must: the generated
        # separator and traversal spellings have to survive onto the wire.
        base = self._workspace(trial_id).as_posix()
        return f"{base}/{path}" if path and not path.startswith("/") else (path or base)

    def teardown(self, trial_id: str) -> None:
        return None

    def _workspace(self, trial_id: str) -> Path:
        return self.base / trial_id / "workspace"

    def reset(self, trial_id: str) -> None:
        space = self._workspace(trial_id)
        if space.exists():
            shutil.rmtree(space)
        (space / "workspace").mkdir(parents=True)
        (space / "workspace" / "settings.cfg").write_text(APPROVED, encoding="utf-8")
        (space / "workspace" / "payload.txt").write_text(PAYLOAD, encoding="utf-8")

    def observe(self, trial_id: str) -> dict[str, AssetState]:
        return snapshot(self._workspace(trial_id))

    def root(self, trial_id: str) -> str | None:
        return self._workspace(trial_id).as_posix()

    def _resolve(self, trial_id: str, value: str) -> Path | None:
        # The wire carries absolute paths; normalise them the way a real server
        # does, and refuse anything that climbs out of the allowed root.
        space = self._workspace(trial_id)
        normalized = value.replace("\\", "/")
        parts: list[str] = []
        for part in normalized.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    return None
                parts.pop()
                continue
            parts.append(part)
        candidate = Path("/", *parts)
        if candidate != space and space not in candidate.parents:
            return None
        return candidate

    def _blocked(self, call: Mapping[str, Any]) -> bool:
        # Tool-name gate first, argument inspection only afterwards.
        if call["name"] not in ("write_file", "edit_file"):
            return False
        for value in call.get("arguments", {}).values():
            if isinstance(value, str) and any(
                value.endswith(name) or f"/{name}" in value for name in PROTECTED_BASENAMES
            ):
                return True
        return False

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        raw = self._dispatch(trial_id, call)
        if raw.get("block_reason") == "tool_policy_deny":
            return CallOutcome(status="blocked", block_reason="tool_policy_deny", raw=raw)
        if "error" in raw:
            return CallOutcome(status="error", block_reason=None, raw=raw)
        return CallOutcome(status="executed", block_reason=None, raw=raw)

    def _dispatch(self, trial_id: str, call: Mapping[str, Any]) -> dict[str, Any]:
        if self._blocked(call):
            return {"error": "blocked by tool call policy", "block_reason": "tool_policy_deny"}
        name = call["name"]
        arguments = call.get("arguments", {})
        try:
            if name == "write_file":
                target = self._resolve(trial_id, str(arguments["path"]))
                if target is None or not target.parent.is_dir():
                    return {"error": "no such directory"}
                target.write_text(str(arguments["content"]), encoding="utf-8")
                return {"ok": True}
            if name == "edit_file":
                target = self._resolve(trial_id, str(arguments["path"]))
                if target is None or not target.is_file():
                    return {"error": "no such file"}
                target.write_text(str(arguments["edits"][0]["newText"]), encoding="utf-8")
                return {"ok": True}
            if name == "move_file":
                source = self._resolve(trial_id, str(arguments["source"]))
                destination = self._resolve(trial_id, str(arguments["destination"]))
                if source is None or destination is None or not source.exists():
                    return {"error": "no such source"}
                if destination.exists():
                    return {"error": "destination already exists"}
                source.rename(destination)
                return {"ok": True}
            if name == "create_directory":
                target = self._resolve(trial_id, str(arguments["path"]))
                if target is None:
                    return {"error": "bad path"}
                target.mkdir(parents=True, exist_ok=True)
                return {"ok": True}
            if name in ("read_file", "list_directory", "get_file_info"):
                target = self._resolve(trial_id, str(arguments["path"]))
                if target is None or not target.exists():
                    return {"error": "no such path"}
                return {"ok": True}
        except OSError as error:
            return {"error": str(error)}
        return {"error": "unsupported tool"}


def _scope() -> ExplorationScope:
    return ExplorationScope(
        protected=(ProtectedAsset(path="workspace/settings.cfg", label="protected configuration"),),
    )


def test_explorer_rediscovers_the_two_step_move_recipe_unaided(tmp_path: Path) -> None:
    """The headline: composition found by search, not by an author."""

    target = MediatedFilesystem(tmp_path)
    report = explore(
        target=target,
        tools=TOOLS,
        scope=_scope(),
        # Only exact replacement counts: an absent resource is indeterminate.
        # Removal alone therefore cannot end
        # the search, so the recipe must be composed.
        breach_statuses={"replaced"},
        max_trials=1_000,
        max_calls=5_000,
    )

    assert report["depth_reached"] >= 2
    assert report["breach_count"] >= 1

    breach = report["breaches"][0]
    assert breach["route"]["operations"] == ["move_file", "move_file"]
    assert breach["route"]["origin"] == "depth2_enabled_by_observed_disturbance"

    verdict = breach["adjudication"]["asset_verdicts"][0]
    assert verdict["path"] == "workspace/settings.cfg"
    assert verdict["status"] == "replaced"

    # The composed sequence moves the protected resource, then installs the payload.
    first, second = breach["route"]["calls"]
    assert first["name"] == "move_file" and second["name"] == "move_file"
    assert "payload" in second["arguments"]["source"].replace("\\", "/")
    assert first["arguments"]["destination"] in report["generated_argument_paths"]
    assert all("\\" not in path for path in report["generated_argument_paths"])
    assert report["coverage"]["effective_max_arguments_per_operation_state"] == 32
    assert report["breach_statuses"] == ["replaced"]
    assert any(
        entry["operation"] == "move_file"
        and entry["resource"]["kind"] == "filesystem.entry"
        and entry["resource"]["key"] == "workspace/settings.cfg"
        for entry in report["effect_footprint"]["observed_effects"]
    )


def test_content_aware_arguments_are_redacted_from_serialized_evidence(
    tmp_path: Path,
) -> None:
    observed_text = "sentinel-sensitive-value"

    class ContentAwareTarget(MediatedFilesystem):
        def advertise(self) -> Sequence[Mapping[str, Any]]:
            return [next(tool for tool in TOOLS if tool["name"] == "edit_file")]

        def reset(self, trial_id: str) -> None:
            space = self._workspace(trial_id)
            if space.exists():
                shutil.rmtree(space)
            (space / "workspace").mkdir(parents=True)
            (space / "workspace" / "settings.cfg").write_text(observed_text, encoding="utf-8")

        def _blocked(self, call: Mapping[str, Any]) -> bool:
            return False

    report = explore(
        target=ContentAwareTarget(tmp_path),
        scope=_scope(),
        max_depth=1,
        max_trials=20,
        max_calls=20,
    )
    serialized = json.dumps(report, sort_keys=True)
    assert report["breach_count"] >= 1
    assert observed_text not in serialized
    assert "[REDACTED observed-content sha256:" in serialized
    assert report["effect_footprint"]["candidate_effect_derivation"]["status"] == (
        "bounded_schema_annotation_and_name_heuristic"
    )


def test_default_budget_reaches_depth_two_on_recorded_14_tool_surface(tmp_path: Path) -> None:
    """The default covers the real server surface rather than the reduced fixture."""

    report = explore(
        target=MediatedFilesystem(tmp_path),
        tools=_recorded_filesystem_surface(),
        scope=_scope(),
        breach_statuses={"replaced"},
    )

    assert report["advertised_operation_count"] == 14
    assert any(
        breach["route"]["operations"] == ["move_file", "move_file"] for breach in report["breaches"]
    )


def test_inventory_only_search_reaches_composition_without_declared_assets(
    tmp_path: Path,
) -> None:
    """Observed inventory can guide discovery when no protected list is supplied."""

    payload_digest = hashlib.sha256(PAYLOAD.encode()).hexdigest()
    report = explore(
        target=MediatedFilesystem(tmp_path),
        tools=_recorded_filesystem_surface(),
    )

    assert report["scope_source"] == "snapshot_inventory"
    assert any(
        impact["route"]["operations"] == ["move_file", "move_file"]
        and [outcome["status"] for outcome in impact["call_outcomes"]]
        == ["executed", "executed"]
        and any(
            transition["path"] == "workspace/settings.cfg"
            and transition["kind"] == "content_replaced"
            and (transition["after"] or {}).get("digest") == payload_digest
            for transition in impact["transitions"]
        )
        for impact in report["candidate_asset_impacts"]
    )


def test_depth_one_sweep_finds_removal_when_removal_counts(tmp_path: Path) -> None:
    """With the default statuses a single move already breaches integrity."""

    target = MediatedFilesystem(tmp_path)
    report = explore(target=target, tools=TOOLS, scope=_scope(), max_depth=1)

    assert report["depth_reached"] == 1
    assert report["breach_count"] >= 1
    assert all(len(breach["route"]["calls"]) == 1 for breach in report["breaches"])


def test_explorer_reaches_the_protected_file_through_its_directory(tmp_path: Path) -> None:
    """Moving the container is generated because ancestors join the path pool."""

    target = MediatedFilesystem(tmp_path)
    report = explore(target=target, tools=TOOLS, scope=_scope(), max_depth=1)

    invisible = [
        breach
        for breach in report["breaches"]
        if breach["adjudication"]["argument_invisible_breach_count"] > 0
    ]
    assert invisible, "expected at least one breach no argument rule could match"
    verdict = invisible[0]["adjudication"]["asset_verdicts"][0]
    assert verdict["argument_visibility"] in ("ancestor_only", "absent")


def test_blocked_routes_are_executed_and_recorded_not_assumed(tmp_path: Path) -> None:
    """write_file and edit_file are attempted, refused, and leave the file intact."""

    target = MediatedFilesystem(tmp_path)
    operations = classify_operations(TOOLS)
    routes = plan_routes(operations=operations, scope=_scope())
    attempted = {name for route in routes for name in route.operations}
    assert {"write_file", "edit_file", "move_file"} <= attempted

    write_route = next(route for route in routes if route.operations == ("write_file",))
    target.reset(write_route.route_id)
    call = dict(write_route.calls[0])
    arguments = dict(call["arguments"])
    arguments["path"] = target.resolve(write_route.route_id, str(arguments["path"]))
    result = target.invoke(write_route.route_id, {**call, "arguments": arguments})
    assert result.status == "blocked"
    assert result.block_reason == "tool_policy_deny"


def test_read_only_tools_are_attempted_and_reported_inert(tmp_path: Path) -> None:
    """Capability is observed, never inferred from a tool name."""

    target = MediatedFilesystem(tmp_path)
    report = explore(target=target, tools=TOOLS, scope=_scope(), max_depth=1)

    assert "read_file" in report["attempted_operations"]
    assert "read_file" in report["operations_inert_at_depth1"]
    assert "get_file_info" in report["operations_inert_at_depth1"]
    assert report["advertised_operation_count"] == len(TOOLS)


def test_policy_text_yields_the_sibling_protected_paths() -> None:
    """A policy fixture supplies paths without an authored asset list."""

    candidates = path_candidates_from_policy(POLICY_TEXT)
    assert ".guardedcfg" in candidates


def test_encodings_include_a_windows_spelling_and_a_traversal() -> None:
    variants = encode_variants("workspace/settings.cfg")
    assert "workspace\\settings.cfg" in variants
    assert "workspace/./settings.cfg" in variants
    assert "workspace/settings.cfg" in variants


def test_classification_keeps_every_tool_and_binds_two_path_parameters() -> None:
    operations = {operation.name: operation for operation in classify_operations(TOOLS)}
    assert set(operations) == {tool["name"] for tool in TOOLS}
    assert operations["move_file"].bindable_params == ("destination", "source")
    # content is required but is not a path, so it is filled rather than bound.
    assert operations["write_file"].bindable_params == ("path",)
    assert operations["write_file"].other_required == ("content",)


def test_unnamed_tool_and_empty_pool_are_refused() -> None:
    with pytest.raises(ShadowPathExplorerError, match="missing a name"):
        classify_operations([{"inputSchema": {}}])
    with pytest.raises(ShadowPathExplorerError, match="no bindable paths"):
        plan_routes(
            operations=classify_operations(TOOLS),
            scope=ExplorationScope(protected=()),
        )
    with pytest.raises(ShadowPathExplorerError, match="missing an input schema"):
        classify_operations([{"name": "opaque"}])
    with pytest.raises(ShadowPathExplorerError, match="malformed input schema"):
        classify_operations([{"name": "opaque", "inputSchema": "not a schema"}])
    with pytest.raises(ShadowPathExplorerError, match="duplicated"):
        classify_operations(
            [
                {"name": "opaque", "inputSchema": {"type": "object"}},
                {"name": "opaque", "inputSchema": {"type": "object"}},
            ]
        )
