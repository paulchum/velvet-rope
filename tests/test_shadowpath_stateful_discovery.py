"""Behavioral discovery benchmarks with no winning routes supplied to the explorer.

Opaque tool names prevent name-based capability tables from satisfying these tests.
The targets expose only schemas, their disposable state, and observed call results.
"""

from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from velvet.shadowpath_explorer import (
    CallOutcome,
    ExplorationScope,
    SessionScope,
    ShadowPathExplorerError,
    explore,
)
from velvet.shadowpath_observer import AssetState, ProtectedAsset


def _file(content: str) -> AssetState:
    data = content.encode()
    return AssetState(
        kind="file", mode=0o644, digest=hashlib.sha256(data).hexdigest(), size=len(data)
    )


def _directory() -> AssetState:
    return AssetState(kind="directory", mode=0o755)


def _tool(name: str, *, path_parameter: bool = False) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    if path_parameter:
        properties["object"] = {"type": "string", "description": "path of an existing file"}
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        },
    }


class DisposableState:
    session_scope: SessionScope = "per_route"

    def __init__(self, tools: Sequence[Mapping[str, Any]]) -> None:
        self.tools = tools
        self.states: dict[str, dict[str, AssetState]] = {}
        self.started: list[str] = []
        self.released: list[str] = []
        self.calls: list[Mapping[str, Any]] = []

    def manifest(self) -> Mapping[str, Any]:
        return {"target": "disposable state discovery benchmark"}

    def advertise(self) -> Sequence[Mapping[str, Any]]:
        return self.tools

    def reset(self, trial_id: str) -> None:
        self.started.append(trial_id)
        self.states[trial_id] = {"config.txt": _file("approved")}

    def observe(self, trial_id: str) -> dict[str, AssetState]:
        return dict(self.states[trial_id])

    def resolve(self, trial_id: str, path: str) -> str:
        return path

    def root(self, trial_id: str) -> None:
        return None

    def teardown(self, trial_id: str) -> None:
        self.released.append(trial_id)
        self.states.pop(trial_id, None)

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        return CallOutcome(status="executed", block_reason=None, raw={"ok": True})


class ThreeStepTarget(DisposableState):
    """Two changes outside the protected set enable a third operation."""

    def __init__(self, *, direct_second_impact: bool = False) -> None:
        names = ["k14", "m27", "q93"]
        if direct_second_impact:
            names.append("a02")
        super().__init__([_tool(name) for name in names])
        self.direct_second_impact = direct_second_impact

    def reset(self, trial_id: str) -> None:
        super().reset(trial_id)
        self.states[trial_id]["latch"] = _file("closed")
        if self.direct_second_impact:
            self.states[trial_id]["second.txt"] = _file("approved")

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        state = self.states[trial_id]
        name = call["name"]
        if name == "k14":
            state["latch"] = _file("open")
        elif name == "m27" and state["latch"] == _file("open"):
            state["ready"] = _file("yes")
        elif name == "q93" and "ready" in state:
            state["config.txt"] = _file("changed")
        elif name == "a02":
            state["second.txt"] = _file("changed")
        else:
            return CallOutcome(status="error", block_reason=None, raw={"error": "precondition"})
        return CallOutcome(status="executed", block_reason=None, raw={"ok": True})


def _scope(*paths: str) -> ExplorationScope:
    return ExplorationScope(
        protected=tuple(ProtectedAsset(path=path) for path in paths or ("config.txt",)),
        include_encodings=False,
        include_ancestors=False,
        max_bindings_per_operation=64,
    )


def _routes_affecting(report: Mapping[str, Any], path: str) -> list[list[str]]:
    return [
        [call["name"] for call in item["route"]["calls"]]
        for item in report["breaches"]
        if any(
            verdict["path"] == path and verdict["status"] != "intact"
            for verdict in item["adjudication"]["asset_verdicts"]
        )
    ]


def test_unprotected_state_enables_discovery_beyond_two_steps() -> None:
    shallow = explore(
        target=ThreeStepTarget(), scope=_scope(), max_depth=2, max_trials=200, max_calls=500
    )
    assert shallow["breach_count"] == 0

    target = ThreeStepTarget()
    report = explore(target=target, scope=_scope(), max_depth=3, max_trials=200, max_calls=500)

    assert ["k14", "m27", "q93"] in _routes_affecting(report, "config.txt")
    assert report["depth_reached"] == 3
    assert "ready" in report["discovered_paths"]
    assert target.started == target.released
    assert not target.states


def test_first_breach_does_not_prevent_discovering_a_different_asset() -> None:
    target = ThreeStepTarget(direct_second_impact=True)
    report = explore(
        target=target,
        scope=_scope("config.txt", "second.txt"),
        max_depth=3,
        max_trials=500,
        max_calls=1500,
    )

    assert ["a02"] in _routes_affecting(report, "second.txt")
    assert ["k14", "m27", "q93"] in _routes_affecting(report, "config.txt")


class GeneratedPathTarget(DisposableState):
    def __init__(self) -> None:
        super().__init__([_tool("b16"), _tool("r88", path_parameter=True)])

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        state = self.states[trial_id]
        if call["name"] == "b16":
            state["fresh-object-627.bin"] = _file("generated material")
        elif (
            call["arguments"].get("object") == "fresh-object-627.bin"
            and "fresh-object-627.bin" in state
        ):
            state["config.txt"] = _file("changed")
        else:
            return CallOutcome(status="error", block_reason=None, raw={"error": "not ready"})
        return CallOutcome(status="executed", block_reason=None, raw={"ok": True})


def test_a_path_created_during_search_becomes_a_new_argument_candidate() -> None:
    report = explore(
        target=GeneratedPathTarget(), scope=_scope(), max_depth=2, max_trials=100, max_calls=250
    )

    assert ["b16", "r88"] in _routes_affecting(report, "config.txt")
    assert "fresh-object-627.bin" in report["discovered_paths"]
    winning = next(
        item
        for item in report["breaches"]
        if [call["name"] for call in item["route"]["calls"]] == ["b16", "r88"]
    )
    assert winning["route"]["calls"][1]["arguments"]["object"] == "fresh-object-627.bin"


def test_inventory_discovers_impacts_without_inventing_a_protection_policy() -> None:
    report = explore(target=GeneratedPathTarget(), max_depth=2, max_trials=100, max_calls=250)

    assert report["scope_source"] == "snapshot_inventory"
    assert report["scope_assessment"]["status"] == "incomplete_product_scope"
    assert report["scope_assessment"]["dimensions"]["policy_families"] == "not_supplied"
    assert {tool["name"] for tool in report["advertised_tool_surface"]} == {"b16", "r88"}
    assert report["candidate_asset_impacts"]
    assert any(
        item["affected_paths"] == ["config.txt", "fresh-object-627.bin"]
        and [call["name"] for call in item["route"]["calls"]] == ["b16", "r88"]
        for item in report["candidate_asset_impacts"]
    )
    assert report["breach_count"] == 0
    assert report["breaches"] == []
    assert "fresh-object-627.bin" in report["discovered_paths"]


def test_parameterless_capability_is_attempted_even_with_an_empty_inventory() -> None:
    class EmptyTarget(DisposableState):
        def reset(self, trial_id: str) -> None:
            super().reset(trial_id)
            self.states[trial_id].clear()

        def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
            self.states[trial_id]["new.txt"] = _file("created")
            return super().invoke(trial_id, call)

    report = explore(target=EmptyTarget([_tool("v51")]), max_depth=1)

    assert report["attempted_operations"] == ["v51"]
    assert "new.txt" in report["discovered_paths"]


def test_generated_scratch_path_replaces_a_hand_authored_path_fixture() -> None:
    class CreateAtPath(DisposableState):
        def __init__(self) -> None:
            super().__init__([_tool("opaque-create", path_parameter=True)])

        def reset(self, trial_id: str) -> None:
            super().reset(trial_id)
            self.states[trial_id] = {}

        def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
            self.calls.append(call)
            path = posixpath.normpath(str(call["arguments"]["object"]))
            self.states[trial_id][path] = _file("created")
            return CallOutcome(status="executed", raw={"ok": True})

    report = explore(target=CreateAtPath(), max_depth=1, max_trials=20, max_calls=20)

    assert ".shadowpath-probe-000" in report["discovered_paths"]
    assert ".shadowpath-probe-000" in report["generated_argument_paths"]
    assert report["breach_count"] == 0


def test_generated_scratch_path_reaches_inside_an_observed_empty_directory() -> None:
    class CreateInsideDirectory(DisposableState):
        def __init__(self) -> None:
            super().__init__([_tool("opaque-create", path_parameter=True)])

        def reset(self, trial_id: str) -> None:
            super().reset(trial_id)
            self.states[trial_id] = {"uploads": _directory()}

        def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
            self.calls.append(call)
            path = str(call["arguments"]["object"])
            if path == "uploads/.shadowpath-probe-000":
                self.states[trial_id][path] = _file("created")
                return CallOutcome(status="executed", raw={"ok": True})
            return CallOutcome(status="error", raw={"error": "not inside directory"})

    report = explore(target=CreateInsideDirectory(), max_depth=1, max_trials=20, max_calls=20)

    assert "uploads/.shadowpath-probe-000" in report["generated_argument_paths"]
    assert "uploads/.shadowpath-probe-000" in report["discovered_paths"]


class MixedOutcomesTarget(DisposableState):
    def __init__(self) -> None:
        super().__init__([_tool(name) for name in ("a00", "b00", "c00")])

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        if call["name"] == "a00":
            return CallOutcome(status="blocked", block_reason="policy", raw={})
        if call["name"] == "b00":
            return CallOutcome(status="error", block_reason=None, raw={"error": "backend"})
        return CallOutcome(status="executed", block_reason=None, raw={"ok": True})


def test_error_and_blocked_operations_are_not_reported_as_executed_inert() -> None:
    report = explore(target=MixedOutcomesTarget(), scope=_scope(), max_depth=1)

    assert report["call_status_counts"] == {"executed": 1, "blocked": 1, "error": 1}
    assert report["operations_inert_at_depth1"] == ["c00"]
    assert report["operations_blocked_at_least_once"] == ["a00"]
    assert report["operations_errored_at_least_once"] == ["b00"]
    assert report["operations_unattempted"] == []


@pytest.mark.parametrize("budget", ["max_trials", "max_calls"])
def test_small_budgets_leave_operations_explicitly_unattempted(budget: str) -> None:
    target = MixedOutcomesTarget()
    report = explore(
        target=target,
        scope=_scope(),
        max_depth=3,
        max_trials=1 if budget == "max_trials" else 100,
        max_calls=1 if budget == "max_calls" else 100,
    )

    assert len(target.calls) == 1
    assert report["executed_route_count"] == 1
    assert len(report["attempted_operations"]) == 1
    assert set(report["operations_unattempted"]) == {"b00", "c00"}
    assert report["operations_inert_at_depth1"] == []
    assert report["coverage"]["budget_exhausted"] is True
    assert target.started == target.released


def test_replayed_prefix_calls_count_toward_the_call_budget() -> None:
    target = ThreeStepTarget()
    report = explore(target=target, scope=_scope(), max_depth=3, max_trials=100, max_calls=5)

    assert len(target.calls) <= 5
    assert sum(report["call_status_counts"].values()) == len(target.calls)
    assert report["coverage"]["budget_exhausted"] is True
    assert target.started == target.released


def test_idempotent_setup_does_not_consume_budget_with_equivalent_prefixes() -> None:
    target = ThreeStepTarget()
    report = explore(target=target, scope=_scope(), max_depth=8, max_trials=100, max_calls=300)

    assert ["k14", "m27", "q93"] in _routes_affecting(report, "config.txt")
    # There are four reachable snapshots and three advertised actions. Repeating
    # k14 or m27 is idempotent, so an engine that indexes observed states needs
    # at most twelve candidate transitions rather than enumerating 3**8 routes.
    assert report["executed_route_count"] <= 12
    assert report["coverage"]["budget_exhausted"] is False


class UnstableReplayTarget(DisposableState):
    def __init__(self) -> None:
        super().__init__([_tool("a11"), _tool("b22")])
        self.sequence = 0

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        state = self.states[trial_id]
        if call["name"] == "a11":
            self.sequence += 1
            state["latch"] = _file(str(self.sequence))
        elif "latch" in state:
            state["config.txt"] = _file("changed")
        else:
            return CallOutcome(status="error", block_reason=None, raw={"error": "not ready"})
        return CallOutcome(status="executed", block_reason=None, raw={"ok": True})


def test_unstable_replayed_prefix_cannot_receive_breach_credit() -> None:
    target = UnstableReplayTarget()
    report = explore(target=target, scope=_scope(), max_depth=2, max_trials=100, max_calls=200)

    assert report["replay_rejections"] > 0
    assert report["breach_count"] == 0
    assert report["transition_trials_started"] > report["candidate_actions_invoked"]
    assert report["executed_route_count"] == report["candidate_actions_completed"]
    assert report["coverage"]["state_action_pairs_attempted"] == report["candidate_actions_invoked"]
    assert target.started == target.released


def test_replay_with_a_different_call_outcome_cannot_receive_breach_credit() -> None:
    class OutcomeUnstableTarget(DisposableState):
        def __init__(self) -> None:
            super().__init__([_tool("a11"), _tool("b22")])
            self.sequence = 0

        def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
            self.calls.append(call)
            state = self.states[trial_id]
            if call["name"] == "a11":
                self.sequence += 1
                state["latch"] = _file("same observed state")
                if self.sequence == 1:
                    return CallOutcome(status="executed", raw={"sequence": self.sequence})
                return CallOutcome(status="error", raw={"sequence": self.sequence})
            if "latch" in state:
                state["config.txt"] = _file("changed")
                return CallOutcome(status="executed", raw={"ok": True})
            return CallOutcome(status="error", raw={"error": "not ready"})

    report = explore(
        target=OutcomeUnstableTarget(),
        scope=_scope(),
        max_depth=2,
        max_trials=100,
        max_calls=200,
    )

    assert report["replay_rejections"] > 0
    assert report["breach_count"] == 0


def test_invoked_candidate_is_counted_when_post_call_observation_never_settles() -> None:
    class OscillatingAfterCallTarget(DisposableState):
        def __init__(self) -> None:
            super().__init__([_tool("mutate")])
            self.invoked: set[str] = set()
            self.tick = 0

        def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
            self.calls.append(call)
            self.invoked.add(trial_id)
            return CallOutcome(status="executed", raw={"ok": True})

        def observe(self, trial_id: str) -> dict[str, AssetState]:
            state = dict(self.states[trial_id])
            if trial_id in self.invoked:
                self.tick += 1
                state["oscillating"] = _file(str(self.tick))
            return state

    report = explore(
        target=OscillatingAfterCallTarget(),
        scope=_scope(),
        max_depth=1,
        max_trials=1,
        max_calls=1,
    )
    assert report["call_status_counts"]["executed"] == 1
    assert report["candidate_actions_invoked"] == 1
    assert report["candidate_actions_completed"] == 0
    assert report["executed_route_count"] == 0
    assert report["replay_rejections"] == 1
    assert report["unsettled_observation_count"] == 1
    assert report["coverage"]["state_action_pairs_attempted"] == 1


def test_path_pool_truncation_is_reported_separately_from_schema_truncation() -> None:
    report = explore(
        target=GeneratedPathTarget(),
        scope=_scope(),
        max_depth=1,
        max_trials=20,
        max_calls=20,
        max_paths_per_state=1,
    )

    coverage = report["coverage"]
    assert coverage["path_pool_truncated"] is True
    assert coverage["path_pool_truncated_states"] >= 1
    assert (
        coverage["path_candidates_available_across_states"]
        > coverage["path_candidates_used_across_states"]
    )
    assert coverage["argument_generation_truncated"] is True
    assert report["scope_assessment"]["dimensions"]["argument_space"] == (
        "bounded_sample_with_gaps"
    )


def test_unknown_breach_status_is_rejected_instead_of_silently_missing_effects() -> None:
    with pytest.raises(ShadowPathExplorerError, match="unknown breach status"):
        explore(
            target=GeneratedPathTarget(),
            scope=_scope(),
            breach_statuses={"replace"},  # type: ignore[arg-type]
            max_depth=1,
        )


class LifecycleFailureTarget(DisposableState):
    def __init__(self, phase: str) -> None:
        super().__init__([_tool("z01")])
        self.phase = phase

    def reset(self, trial_id: str) -> None:
        super().reset(trial_id)
        if self.phase == "reset":
            raise RuntimeError("reset failed after allocation")

    def observe(self, trial_id: str) -> dict[str, AssetState]:
        if self.phase == "observe":
            raise RuntimeError("observation failed")
        return super().observe(trial_id)

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        self.calls.append(call)
        raise RuntimeError("invocation failed")


@pytest.mark.parametrize("phase", ["reset", "observe", "invoke"])
def test_resources_are_released_when_a_target_fails(phase: str) -> None:
    target = LifecycleFailureTarget(phase)
    try:
        explore(target=target, scope=_scope(), max_depth=1)
    except RuntimeError:
        pass

    assert target.started
    assert target.started == target.released
    assert not target.states
