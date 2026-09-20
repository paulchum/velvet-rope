from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, cast

import pytest

from velvet.shadowpath_effects import EffectRecord, ResourceRef
from velvet.shadowpath_resource_explorer import (
    ArgumentBinding,
    CandidateAction,
    InvocationOutcome,
    ResourceExplorationTarget,
    ResourceExplorerError,
    ResourceObservation,
    ResourceSnapshot,
    explore_resources,
)

_CONTAINER = ResourceRef("example.docker", "docker.container", "worker-7")
_SERVICE = ResourceRef("example.control-plane", "service.object", "orders")
_TOOLS_NAMESPACE = "example.delegated-tools"


def _candidate_call(operation: str) -> EffectRecord:
    return EffectRecord(
        effect="delegated_tool.call",
        resource=ResourceRef(_TOOLS_NAMESPACE, "delegated_tool.operation", operation),
        evidence_level="candidate",
        provenance="test_action_model",
        operation=operation,
    )


class _MixedResourceTarget:
    session_scope = "per_route"

    def __init__(self) -> None:
        self.containers: dict[str, str] = {}
        self.service_revision = 1
        self.invocation_serial = 0

    def manifest(self) -> Mapping[str, Any]:
        return {"target": "mixed-resource-fixture", "isolation": "reset per trial"}

    def reset(self, trial_id: str) -> None:
        assert trial_id
        self.containers = {}
        self.service_revision = 1

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> InvocationOutcome:
        assert trial_id
        self.invocation_serial += 1
        operation = call.get("name")
        arguments = call.get("arguments")
        if not isinstance(arguments, Mapping):
            return InvocationOutcome("error", details={"reason": "arguments missing"})
        if operation == "delegate.launch_container":
            self.containers[_CONTAINER.key] = "running"
            return InvocationOutcome("executed", details={"serial": self.invocation_serial})
        if operation == "delegate.reconfigure_service":
            selector = arguments.get("container")
            if selector not in self.containers:
                return InvocationOutcome("error", details={"reason": "container unavailable"})
            self.service_revision = 2
            return InvocationOutcome("executed", details={"serial": self.invocation_serial})
        return InvocationOutcome("error", details={"reason": "unknown operation"})

    def teardown(self, trial_id: str) -> None:
        assert trial_id


class _MixedResourceModel:
    def manifest(self) -> Mapping[str, Any]:
        return {
            "model": "mixed-resource-model",
            "resource_kinds": ["docker.container", "service.object"],
            "observer": "synthetic independent state",
        }

    def observe(
        self,
        target: ResourceExplorationTarget,
        trial_id: str,
    ) -> ResourceSnapshot:
        assert trial_id
        concrete = cast(_MixedResourceTarget, target)
        observations = [
            ResourceObservation(
                _SERVICE,
                {"revision": concrete.service_revision},
                "service_api",
            )
        ]
        observations.extend(
            ResourceObservation(
                ResourceRef("example.docker", "docker.container", name),
                {"status": status},
                "docker_api",
            )
            for name, status in concrete.containers.items()
        )
        return ResourceSnapshot(tuple(observations))

    def actions(
        self,
        *,
        baseline: ResourceSnapshot,
        current: ResourceSnapshot,
    ) -> Sequence[CandidateAction]:
        assert baseline.observations
        containers = [
            item for item in current.observations if item.resource.kind == "docker.container"
        ]
        if not containers:
            return (
                CandidateAction(
                    operation="delegate.launch_container",
                    arguments={"name": _CONTAINER.key},
                    bindings=(
                        ArgumentBinding(
                            address=("name",),
                            role="destination_selector",
                            origin="generated",
                            resource=_CONTAINER,
                        ),
                    ),
                    candidate_effects=(
                        _candidate_call("delegate.launch_container"),
                        EffectRecord(
                            effect="resource.create",
                            resource=_CONTAINER,
                            evidence_level="adapter_declared",
                            provenance="test_action_model",
                            operation="delegate.launch_container",
                        ),
                    ),
                ),
            )

        discovered = containers[0].resource
        return (
            CandidateAction(
                operation="delegate.reconfigure_service",
                arguments={"container": discovered.key, "service": _SERVICE.key},
                bindings=(
                    ArgumentBinding(
                        address=("container",),
                        role="authority_selector",
                        origin="observed",
                        resource=discovered,
                    ),
                    ArgumentBinding(
                        address=("service",),
                        role="destination_selector",
                        origin="declared",
                        resource=_SERVICE,
                    ),
                ),
                candidate_effects=(
                    _candidate_call("delegate.reconfigure_service"),
                    EffectRecord(
                        effect="resource.state.change",
                        resource=_SERVICE,
                        evidence_level="adapter_declared",
                        provenance="test_action_model",
                        operation="delegate.reconfigure_service",
                    ),
                ),
            ),
        )

    def materialize(
        self,
        target: ResourceExplorationTarget,
        trial_id: str,
        action: CandidateAction,
    ) -> Mapping[str, Any]:
        assert target.session_scope == "per_route"
        assert trial_id
        return action.logical_call()

    def observed_effects(
        self,
        *,
        before: ResourceSnapshot,
        after: ResourceSnapshot,
        action: CandidateAction,
        outcome: InvocationOutcome,
    ) -> Sequence[EffectRecord]:
        effects = [
            EffectRecord(
                effect="delegated_tool.call",
                resource=ResourceRef(
                    _TOOLS_NAMESPACE,
                    "delegated_tool.operation",
                    action.operation,
                ),
                evidence_level="observed",
                provenance="dispatch_outcome",
                operation=action.operation,
                details={
                    "status": outcome.status,
                    "serial": outcome.details.get("serial"),
                },
            )
        ]
        before_by_id = {item.resource.resource_id: item for item in before.observations}
        for observed in after.observations:
            previous = before_by_id.get(observed.resource.resource_id)
            if previous is None:
                effect = "resource.create"
            elif previous.state_sha256 != observed.state_sha256:
                effect = "resource.state.change"
            else:
                continue
            effects.append(
                EffectRecord(
                    effect=effect,
                    resource=observed.resource,
                    evidence_level="observed",
                    provenance=observed.provenance,
                    operation=action.operation,
                    details={
                        "before_state_sha256": (
                            previous.state_sha256 if previous is not None else None
                        ),
                        "after_state_sha256": observed.state_sha256,
                    },
                )
            )
        return tuple(effects)


class _SelfLoopModel(_MixedResourceModel):
    def actions(
        self,
        *,
        baseline: ResourceSnapshot,
        current: ResourceSnapshot,
    ) -> Sequence[CandidateAction]:
        assert baseline.fingerprint == current.fingerprint
        return (
            CandidateAction(
                "delegate.noop",
                {},
                candidate_effects=(_candidate_call("delegate.noop"),),
            ),
        )


def test_resource_snapshot_is_order_independent_and_rejects_duplicate_identity() -> None:
    supplied_state: dict[str, Any] = {"revision": 1, "replicas": ["one"]}
    service = ResourceObservation(_SERVICE, supplied_state, "service_api")
    container = ResourceObservation(_CONTAINER, {"status": "running"}, "docker_api")
    supplied_state["replicas"].append("two")

    first = ResourceSnapshot((service, container))
    second = ResourceSnapshot((container, service))

    assert first.fingerprint == second.fingerprint
    assert first.to_json() == second.to_json()
    assert service.state_json() == {"revision": 1, "replicas": ["one"]}
    with pytest.raises(ResourceExplorerError, match="duplicate resource identities"):
        ResourceSnapshot((service, service))


def test_candidate_action_detaches_mutable_binding_and_effect_inputs() -> None:
    bindings = [
        ArgumentBinding(
            address=["name"],  # type: ignore[arg-type]
            role="destination_selector",
            origin="generated",
            resource=_CONTAINER,
        )
    ]
    effects = [_candidate_call("delegate.launch_container")]
    arguments: dict[str, Any] = {
        "name": _CONTAINER.key,
        "metadata": {"labels": ["before"]},
    }
    action = CandidateAction(
        "delegate.launch_container",
        arguments,
        bindings=bindings,  # type: ignore[arg-type]
        candidate_effects=effects,  # type: ignore[arg-type]
    )
    fingerprint = action.fingerprint
    bindings.clear()
    effects.clear()
    arguments["metadata"]["labels"].append("after")

    assert action.fingerprint == fingerprint
    assert action.arguments_json()["metadata"] == {"labels": ["before"]}
    assert len(action.bindings) == 1
    assert len(action.candidate_effects) == 1


def test_discovered_container_enables_depth_two_service_effect_without_paths() -> None:
    report = explore_resources(
        target=_MixedResourceTarget(),
        model=_MixedResourceModel(),
        max_depth=2,
        max_trials=4,
        max_calls=8,
        max_states=4,
        max_actions_per_state=4,
    )

    assert report["depth_reached"] == 2
    assert report["target_manifest"]["target"] == "mixed-resource-fixture"
    assert report["model_manifest"]["resource_kinds"] == [
        "docker.container",
        "service.object",
    ]
    assert len(report["target_manifest_sha256"]) == 64
    assert len(report["model_manifest_sha256"]) == 64
    edges = report["state_graph"]["edges"]
    create_edge = next(edge for edge in edges if edge["depth"] == 1)
    service_edge = next(edge for edge in edges if edge["depth"] == 2)
    assert create_edge["route"]["operations"] == ["delegate.launch_container"]
    assert any(
        effect["effect"] == "resource.create" and effect["resource"]["kind"] == "docker.container"
        for effect in create_edge["effect_footprint"]["observed_effects"]
    )

    assert service_edge["route"]["operations"] == [
        "delegate.launch_container",
        "delegate.reconfigure_service",
    ]
    selector = service_edge["action"]["bindings"][0]
    assert selector["origin"] == "observed"
    assert selector["resource"]["kind"] == "docker.container"
    assert selector["resource"]["key"] == "worker-7"
    assert any(
        effect["effect"] == "resource.state.change"
        and effect["resource"]["kind"] == "service.object"
        for effect in service_edge["effect_footprint"]["observed_effects"]
    )
    outcome_serials = [outcome["details"]["serial"] for outcome in service_edge["outcomes"]]
    route_serials = [
        effect["details"]["serial"]
        for effect in service_edge["route_effect_footprint"]["observed_effects"]
        if effect["effect"] == "delegated_tool.call"
    ]
    assert route_serials == outcome_serials

    serialized = json.dumps(report, sort_keys=True)
    assert "filesystem" not in serialized
    assert "baseline_paths" not in report
    assert "discovered_paths" not in report
    assert {item["kind"] for item in report["discovered_resources"]} >= {
        "docker.container",
        "service.object",
    }


def test_trial_budget_bounds_resource_search() -> None:
    report = explore_resources(
        target=_MixedResourceTarget(),
        model=_MixedResourceModel(),
        max_depth=3,
        max_trials=1,
        max_calls=3,
    )

    assert report["depth_reached"] == 1
    assert report["termination_reason"] == "budget_exhausted"
    assert report["coverage"]["trials_used"] == 1
    assert report["coverage"]["state_action_pairs_considered"] == 2
    assert report["coverage"]["state_action_pairs_scheduled"] == 1
    assert report["coverage"]["state_action_pairs_attempted"] == 1
    assert report["coverage"]["budget_exhaustion_reasons"] == ["max_trials"]


def test_unchanged_observed_state_is_not_reexpanded_by_route_depth() -> None:
    report = explore_resources(
        target=_MixedResourceTarget(),
        model=_SelfLoopModel(),
        max_depth=3,
        max_trials=10,
        max_calls=20,
    )

    assert report["depth_reached"] == 1
    assert report["termination_reason"] == "state_space_exhausted"
    assert report["coverage"]["trials_used"] == 1
    assert len(report["state_graph"]["edges"]) == 1


def test_state_limit_keeps_every_graph_edge_endpoint_indexed() -> None:
    report = explore_resources(
        target=_MixedResourceTarget(),
        model=_MixedResourceModel(),
        max_depth=3,
        max_trials=4,
        max_calls=8,
        max_states=1,
    )

    assert report["termination_reason"] == "state_limit_reached"
    assert report["state_graph"]["edges"] == []
    assert len(report["state_graph"]["nodes"]) == 1
    assert report["coverage"]["trials_used"] == 0
