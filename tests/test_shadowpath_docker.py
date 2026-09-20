from __future__ import annotations

from velvet.shadowpath_docker import (
    DockerContainerModel,
    _container_effect,
    analyze_docker_routes,
)
from velvet.shadowpath_effects import ResourceRef
from velvet.shadowpath_resource_explorer import (
    CandidateAction,
    InvocationOutcome,
    ResourceObservation,
    ResourceSnapshot,
)

NAMESPACE = "docker.engine.test"
INVOCATIONS = "docker.engine.test.operations"
CONTAINER = ResourceRef(NAMESPACE, "docker.container", "protected", "lifecycle")


def _snapshot(**state: object) -> ResourceSnapshot:
    return ResourceSnapshot((ResourceObservation(CONTAINER, state, "docker inspect"),))


def test_running_container_generates_two_routes_to_the_stop_effect() -> None:
    model = DockerContainerModel(NAMESPACE, INVOCATIONS)
    running = _snapshot(running=True, paused=False, status="running", exit_code=0)

    actions = model.actions(baseline=running, current=running)
    stop_routes = {
        action.operation
        for action in actions
        if any(effect.effect == "container.stop" for effect in action.candidate_effects)
    }

    assert stop_routes == {"docker.container.kill", "docker.container.stop"}
    assert {action.operation for action in actions} == {
        "docker.container.kill",
        "docker.container.pause",
        "docker.container.remove",
        "docker.container.stop",
    }


def test_absent_container_enables_only_declared_baseline_recreation() -> None:
    model = DockerContainerModel(NAMESPACE, INVOCATIONS)
    baseline = _snapshot(running=True, paused=False, status="running", exit_code=0)

    actions = model.actions(baseline=baseline, current=ResourceSnapshot(()))

    assert len(actions) == 1
    assert actions[0].operation == "docker.container.create"
    assert actions[0].bindings[0].origin == "declared"
    assert actions[0].bindings[0].resource == CONTAINER


def test_observer_classifies_effect_from_state_not_operation_name() -> None:
    model = DockerContainerModel(NAMESPACE, INVOCATIONS)
    before = _snapshot(running=True, paused=False, status="running", exit_code=0)
    after = _snapshot(running=False, paused=False, status="exited", exit_code=137)
    action = CandidateAction("unexpected.alias", {"container": "protected"})

    effects = model.observed_effects(
        before=before,
        after=after,
        action=action,
        outcome=InvocationOutcome("executed"),
    )

    assert [effect.effect for effect in effects] == ["delegated_tool.call", "container.stop"]
    assert effects[1].provenance == "independent Docker Engine inspection difference"


def test_container_effect_distinguishes_lifecycle_transitions() -> None:
    running = {"running": True, "paused": False}
    paused = {"running": True, "paused": True}
    exited = {"running": False, "paused": False}

    assert _container_effect(None, running) == "container.create"
    assert _container_effect(running, None) == "container.remove"
    assert _container_effect(running, paused) == "container.pause"
    assert _container_effect(paused, running) == "container.unpause"
    assert _container_effect(running, exited) == "container.stop"
    assert _container_effect(paused, exited) == "container.stop"
    assert _container_effect(exited, running) == "container.start"


def test_analysis_groups_distinct_routes_only_after_observation() -> None:
    resource = CONTAINER.to_json()

    def edge(operation: str, observed: bool = True) -> dict[str, object]:
        effects = (
            [
                {
                    "effect": "container.stop",
                    "resource": resource,
                    "evidence_level": "observed",
                    "provenance": "docker inspect",
                }
            ]
            if observed
            else []
        )
        return {
            "route": {"operations": [operation]},
            "effect_footprint": {"observed_effects": effects},
        }

    analysis = analyze_docker_routes(
        {
            "state_graph": {
                "edges": [
                    edge("docker.container.kill"),
                    edge("docker.container.stop"),
                    edge("declared.but.unobserved", observed=False),
                ]
            }
        }
    )

    assert analysis["equivalent_effect_route_class_count"] == 1
    route_class = analysis["equivalent_effect_route_classes"][0]
    assert route_class["effect"] == "container.stop"
    assert route_class["routes"] == [
        ["docker.container.kill"],
        ["docker.container.stop"],
    ]
