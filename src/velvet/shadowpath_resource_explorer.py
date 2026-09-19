"""Resource-neutral state-space exploration for ShadowPath.

The filesystem explorer predates ShadowPath's effect-footprint model.  This
module keeps the search algorithm independent of any one substrate: models
observe stable resource identities, generate actions from the resources seen in
the current state, materialize those actions for a target, and translate state
changes into effect evidence.

Nothing in the core assigns meaning to a resource key.  A key may identify a
filesystem entry, container, process, service object, network endpoint, or a
delegated operation.  Substrate-specific normalization belongs to the model.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

from velvet.shadowpath_effects import EffectRecord, ResourceRef, effect_footprint, merge_effects

JsonObject = dict[str, Any]
AddressComponent = str | int
Address = tuple[AddressComponent, ...]

RESOURCE_EXPLORER_SCHEMA_VERSION = "velvet.shadowpath.resource-exploration.v0.1"

CallStatus = Literal["executed", "blocked", "error"]
BindingOrigin = Literal["observed", "declared", "generated"]


class ResourceExplorerError(RuntimeError):
    """Raised when resource exploration cannot proceed honestly."""


def _canonical_json(value: Any, *, label: str) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ResourceExplorerError(f"{label} must be JSON serializable") from error


def _nonempty(label: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ResourceExplorerError(f"{label} must be a non-empty string without NUL bytes")
    return value.strip()


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True)
class ResourceObservation:
    """One normalized observation of a platform-neutral resource.

    Models must omit volatile fields such as sampling timestamps from ``state``.
    The canonical state is captured during construction, so later mutation of a
    caller-owned mapping cannot alter replay identity or preserved evidence.
    """

    resource: ResourceRef
    state: Mapping[str, Any] = field(compare=False)
    provenance: str
    _state_json: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.resource, ResourceRef):
            raise ResourceExplorerError("resource observation needs a ResourceRef")
        object.__setattr__(self, "provenance", _nonempty("observation provenance", self.provenance))
        object.__setattr__(
            self,
            "_state_json",
            _canonical_json(dict(self.state), label="observed resource state"),
        )
        object.__setattr__(self, "state", _freeze_json(json.loads(self._state_json)))

    @property
    def state_sha256(self) -> str:
        return hashlib.sha256(self._state_json.encode()).hexdigest()

    def state_json(self) -> JsonObject:
        return cast(JsonObject, json.loads(self._state_json))

    def identity_json(self) -> JsonObject:
        return {
            "resource": self.resource.to_json(),
            "state_sha256": self.state_sha256,
        }

    def to_json(self) -> JsonObject:
        return {
            **self.identity_json(),
            "state": self.state_json(),
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class ResourceSnapshot:
    """A deterministic state made from any mixture of resource kinds."""

    observations: tuple[ResourceObservation, ...]

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.observations, key=lambda item: item.resource.resource_id))
        identifiers = [item.resource.resource_id for item in ordered]
        if len(identifiers) != len(set(identifiers)):
            raise ResourceExplorerError("resource snapshot contains duplicate resource identities")
        object.__setattr__(self, "observations", ordered)

    @property
    def fingerprint(self) -> str:
        payload = [item.identity_json() for item in self.observations]
        serialized = _canonical_json(payload, label="resource snapshot")
        return hashlib.sha256(serialized.encode()).hexdigest()

    @property
    def resource_ids(self) -> frozenset[str]:
        return frozenset(item.resource.resource_id for item in self.observations)

    def by_id(self, resource_id: str) -> ResourceObservation | None:
        return next(
            (item for item in self.observations if item.resource.resource_id == resource_id),
            None,
        )

    def to_json(self) -> JsonObject:
        return {
            "fingerprint": self.fingerprint,
            "resources": [item.to_json() for item in self.observations],
        }


@dataclass(frozen=True)
class ArgumentBinding:
    """The resource semantics of one generated argument value."""

    address: Address
    role: str
    origin: BindingOrigin
    resource: ResourceRef | None = None

    def __post_init__(self) -> None:
        address = tuple(self.address)
        if not address:
            raise ResourceExplorerError("argument binding address cannot be empty")
        for component in address:
            if isinstance(component, str):
                _nonempty("argument address component", component)
            elif not isinstance(component, int) or isinstance(component, bool) or component < 0:
                raise ResourceExplorerError(
                    "argument address components must be non-empty strings or nonnegative integers"
                )
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "role", _nonempty("argument binding role", self.role))
        if self.origin not in ("observed", "declared", "generated"):
            raise ResourceExplorerError(f"unknown argument binding origin: {self.origin!r}")

    def to_json(self) -> JsonObject:
        return {
            "address": list(self.address),
            "role": self.role,
            "origin": self.origin,
            "resource": self.resource.to_json() if self.resource is not None else None,
        }


@dataclass(frozen=True)
class CandidateAction:
    """One logical operation proposed from the currently observed resources."""

    operation: str
    arguments: Mapping[str, Any] = field(compare=False)
    bindings: tuple[ArgumentBinding, ...] = ()
    candidate_effects: tuple[EffectRecord, ...] = ()
    _arguments_json: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", _nonempty("candidate operation", self.operation))
        bindings = tuple(self.bindings)
        if any(not isinstance(binding, ArgumentBinding) for binding in bindings):
            raise ResourceExplorerError("candidate bindings must be ArgumentBinding values")
        candidate_effects = tuple(self.candidate_effects)
        if any(not isinstance(effect, EffectRecord) for effect in candidate_effects):
            raise ResourceExplorerError("candidate effects must be EffectRecord values")
        object.__setattr__(self, "bindings", bindings)
        object.__setattr__(self, "candidate_effects", candidate_effects)
        object.__setattr__(
            self,
            "_arguments_json",
            _canonical_json(dict(self.arguments), label="candidate arguments"),
        )
        object.__setattr__(self, "arguments", _freeze_json(json.loads(self._arguments_json)))
        # This validates evidence-tier separation before the action reaches a trial.
        effect_footprint(candidates=candidate_effects)

    @property
    def fingerprint(self) -> str:
        payload = {
            "operation": self.operation,
            "arguments": self.arguments_json(),
            "bindings": [item.to_json() for item in self.bindings],
            "candidate_effects": [item.to_json() for item in self.candidate_effects],
        }
        serialized = _canonical_json(payload, label="candidate action")
        return hashlib.sha256(serialized.encode()).hexdigest()

    def arguments_json(self) -> JsonObject:
        return cast(JsonObject, json.loads(self._arguments_json))

    def logical_call(self) -> JsonObject:
        return {"name": self.operation, "arguments": self.arguments_json()}

    def to_json(self) -> JsonObject:
        return {
            "operation": self.operation,
            "arguments": self.arguments_json(),
            "bindings": [item.to_json() for item in self.bindings],
            "candidate_effects": [item.to_json() for item in self.candidate_effects],
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class InvocationOutcome:
    """Stable replay evidence returned by a resource exploration target."""

    status: CallStatus
    block_reason: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict, compare=False)
    _details_json: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.status not in ("executed", "blocked", "error"):
            raise ResourceExplorerError(f"unknown invocation status: {self.status!r}")
        if self.block_reason is not None:
            object.__setattr__(
                self,
                "block_reason",
                _nonempty("invocation block reason", self.block_reason),
            )
        object.__setattr__(
            self,
            "_details_json",
            _canonical_json(dict(self.details), label="invocation details"),
        )
        object.__setattr__(self, "details", _freeze_json(json.loads(self._details_json)))

    @property
    def replay_key(self) -> tuple[CallStatus, str | None]:
        return self.status, self.block_reason

    def to_json(self) -> JsonObject:
        return {
            "status": self.status,
            "block_reason": self.block_reason,
            "details": cast(JsonObject, json.loads(self._details_json)),
        }


class ResourceExplorationTarget(Protocol):
    """Lifecycle and invocation boundary required by the generic search core."""

    session_scope: str

    def manifest(self) -> Mapping[str, Any]:
        """Return the pinned identity and isolation contract of the target."""

    def reset(self, trial_id: str) -> None:
        """Restore the target to its trial baseline."""

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> InvocationOutcome:
        """Dispatch one already-materialized operation."""

    def teardown(self, trial_id: str) -> None:
        """Release resources held by one trial."""


class ResourceExplorationModel(Protocol):
    """Substrate hooks used by the generic search core."""

    def manifest(self) -> Mapping[str, Any]:
        """Describe observer coverage, normalization, and resource kinds."""

    def observe(
        self,
        target: ResourceExplorationTarget,
        trial_id: str,
    ) -> ResourceSnapshot:
        """Observe and normalize every resource relevant to the search."""

    def actions(
        self,
        *,
        baseline: ResourceSnapshot,
        current: ResourceSnapshot,
    ) -> Sequence[CandidateAction]:
        """Generate logical actions from observed state alone.

        An action enabled only by hidden or route-depth state means the observer
        is incomplete and cannot receive discovery coverage.
        """

    def materialize(
        self,
        target: ResourceExplorationTarget,
        trial_id: str,
        action: CandidateAction,
    ) -> Mapping[str, Any]:
        """Encode a logical action for this target without changing its meaning."""

    def observed_effects(
        self,
        *,
        before: ResourceSnapshot,
        after: ResourceSnapshot,
        action: CandidateAction,
        outcome: InvocationOutcome,
    ) -> Sequence[EffectRecord]:
        """Map independently observed state change to observed effect records."""


@dataclass(frozen=True)
class _SearchNode:
    snapshot: ResourceSnapshot
    actions: tuple[CandidateAction, ...] = ()
    prefix_fingerprints: tuple[str, ...] = ()
    prefix_outcomes: tuple[tuple[CallStatus, str | None], ...] = ()

    @property
    def depth(self) -> int:
        return len(self.actions)


@dataclass(frozen=True)
class _TrialExecution:
    trial_id: str
    wire_calls: tuple[JsonObject, ...]
    outcomes: tuple[InvocationOutcome, ...]
    snapshots: tuple[ResourceSnapshot, ...]
    after: ResourceSnapshot | None
    replay_rejected: bool
    candidate_invoked: bool


@dataclass
class _Budget:
    max_trials: int
    max_calls: int
    trials: int = 0
    calls: int = 0
    exhausted: set[str] = field(default_factory=set)

    def reserve(self, route_length: int) -> bool:
        reasons: set[str] = set()
        if self.trials >= self.max_trials:
            reasons.add("max_trials")
        if self.calls + route_length > self.max_calls:
            reasons.add("max_calls")
        if reasons:
            self.exhausted.update(reasons)
            return False
        self.trials += 1
        return True


def _safe_invoke(
    target: ResourceExplorationTarget,
    trial_id: str,
    call: Mapping[str, Any],
) -> InvocationOutcome:
    try:
        outcome = target.invoke(trial_id, call)
    except Exception as error:
        return InvocationOutcome(
            "error",
            details={"exception": type(error).__name__, "message": str(error)},
        )
    if not isinstance(outcome, InvocationOutcome):
        raise ResourceExplorerError("target.invoke must return InvocationOutcome")
    return outcome


def _materialize(
    *,
    model: ResourceExplorationModel,
    target: ResourceExplorationTarget,
    trial_id: str,
    action: CandidateAction,
) -> JsonObject:
    call = model.materialize(target, trial_id, action)
    if not isinstance(call, Mapping):
        raise ResourceExplorerError("model.materialize must return a mapping")
    serialized = _canonical_json(dict(call), label="materialized call")
    return cast(JsonObject, json.loads(serialized))


def _observe(
    *,
    model: ResourceExplorationModel,
    target: ResourceExplorationTarget,
    trial_id: str,
) -> ResourceSnapshot:
    snapshot = model.observe(target, trial_id)
    if not isinstance(snapshot, ResourceSnapshot):
        raise ResourceExplorerError("model.observe must return ResourceSnapshot")
    return snapshot


def _manifest(owner: Any, *, label: str) -> tuple[JsonObject, str]:
    value = owner.manifest()
    if not isinstance(value, Mapping):
        raise ResourceExplorerError(f"{label}.manifest must return a mapping")
    serialized = _canonical_json(dict(value), label=f"{label} manifest")
    manifest = cast(JsonObject, json.loads(serialized))
    return manifest, hashlib.sha256(serialized.encode()).hexdigest()


def _execute_transition(
    *,
    target: ResourceExplorationTarget,
    model: ResourceExplorationModel,
    baseline_fingerprint: str,
    node: _SearchNode,
    action: CandidateAction,
    budget: _Budget,
) -> _TrialExecution | None:
    route_length = node.depth + 1
    if not budget.reserve(route_length):
        return None
    safe_operation = re.sub(r"[^A-Za-z0-9_.-]", "_", action.operation)[:32] or "operation"
    trial_id = (
        f"resource-{budget.trials:05d}-d{route_length}-{safe_operation}-{action.fingerprint[:8]}"
    )
    wire_calls: list[JsonObject] = []
    outcomes: list[InvocationOutcome] = []
    snapshots: list[ResourceSnapshot] = []
    try:
        target.reset(trial_id)
        initial = _observe(model=model, target=target, trial_id=trial_id)
        snapshots.append(initial)
        if initial.fingerprint != baseline_fingerprint:
            return _TrialExecution(trial_id, (), (), tuple(snapshots), None, True, False)

        for prefix, expected_fingerprint, expected_outcome in zip(
            node.actions,
            node.prefix_fingerprints,
            node.prefix_outcomes,
            strict=True,
        ):
            call = _materialize(
                model=model,
                target=target,
                trial_id=trial_id,
                action=prefix,
            )
            wire_calls.append(call)
            budget.calls += 1
            outcome = _safe_invoke(target, trial_id, call)
            outcomes.append(outcome)
            replayed = _observe(model=model, target=target, trial_id=trial_id)
            snapshots.append(replayed)
            if (
                replayed.fingerprint != expected_fingerprint
                or outcome.replay_key != expected_outcome
            ):
                return _TrialExecution(
                    trial_id,
                    tuple(wire_calls),
                    tuple(outcomes),
                    tuple(snapshots),
                    replayed,
                    True,
                    False,
                )

        call = _materialize(
            model=model,
            target=target,
            trial_id=trial_id,
            action=action,
        )
        wire_calls.append(call)
        budget.calls += 1
        outcome = _safe_invoke(target, trial_id, call)
        outcomes.append(outcome)
        after = _observe(model=model, target=target, trial_id=trial_id)
        snapshots.append(after)
        return _TrialExecution(
            trial_id,
            tuple(wire_calls),
            tuple(outcomes),
            tuple(snapshots),
            after,
            False,
            True,
        )
    finally:
        target.teardown(trial_id)


def _inventory(
    target: ResourceExplorationTarget,
    model: ResourceExplorationModel,
) -> ResourceSnapshot:
    trial_id = "resource-inventory"
    try:
        target.reset(trial_id)
        return _observe(model=model, target=target, trial_id=trial_id)
    finally:
        target.teardown(trial_id)


def _unique_actions(actions: Sequence[CandidateAction]) -> list[CandidateAction]:
    unique: dict[str, CandidateAction] = {}
    for action in actions:
        if not isinstance(action, CandidateAction):
            raise ResourceExplorerError("model.actions must return CandidateAction values")
        unique.setdefault(action.fingerprint, action)
    by_operation: dict[str, list[CandidateAction]] = {}
    for action in unique.values():
        by_operation.setdefault(action.operation, []).append(action)
    for group in by_operation.values():
        group.sort(key=lambda item: item.fingerprint)

    ordered: list[CandidateAction] = []
    width = max((len(group) for group in by_operation.values()), default=0)
    for index in range(width):
        for operation in sorted(by_operation):
            group = by_operation[operation]
            if index < len(group):
                ordered.append(group[index])
    return ordered


def explore_resources(
    *,
    target: ResourceExplorationTarget,
    model: ResourceExplorationModel,
    max_depth: int = 3,
    max_trials: int = 1_000,
    max_calls: int = 5_000,
    max_states: int = 1_000,
    max_actions_per_state: int = 64,
) -> JsonObject:
    """Run bounded breadth-first search over platform-neutral resource states."""

    for name, value in (
        ("max_depth", max_depth),
        ("max_trials", max_trials),
        ("max_calls", max_calls),
        ("max_states", max_states),
        ("max_actions_per_state", max_actions_per_state),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ResourceExplorerError(f"{name} must be a positive integer")

    target_manifest, target_manifest_sha256 = _manifest(target, label="target")
    model_manifest, model_manifest_sha256 = _manifest(model, label="model")
    baseline = _inventory(target, model)
    baseline_node = _SearchNode(snapshot=baseline)
    queue: deque[_SearchNode] = deque([baseline_node])
    known_states: dict[str, _SearchNode] = {baseline.fingerprint: baseline_node}
    considered_state_actions: set[tuple[str, str]] = set()
    scheduled_state_actions: set[tuple[str, str]] = set()
    discovered_resources: dict[str, ResourceRef] = {
        item.resource.resource_id: item.resource for item in baseline.observations
    }
    budget = _Budget(max_trials=max_trials, max_calls=max_calls)
    graph_edges: list[JsonObject] = []
    aggregate_candidates: list[EffectRecord] = []
    aggregate_observed: list[EffectRecord] = []
    replay_rejections = 0
    generated_actions = 0
    truncated_action_states = 0
    depth_reached = 0
    depth_limited = False
    state_limited = False
    stop = False

    while queue and not stop:
        node = queue.popleft()
        if node.depth >= max_depth:
            depth_limited = True
            continue
        proposed = _unique_actions(
            model.actions(
                baseline=baseline,
                current=node.snapshot,
            )
        )
        generated_actions += len(proposed)
        if len(proposed) > max_actions_per_state:
            proposed = proposed[:max_actions_per_state]
            truncated_action_states += 1

        for action in proposed:
            if len(known_states) >= max_states:
                state_limited = True
                stop = True
                break
            state_action = (node.snapshot.fingerprint, action.fingerprint)
            if state_action in considered_state_actions:
                continue
            considered_state_actions.add(state_action)
            execution = _execute_transition(
                target=target,
                model=model,
                baseline_fingerprint=baseline.fingerprint,
                node=node,
                action=action,
                budget=budget,
            )
            if execution is None:
                stop = True
                break
            scheduled_state_actions.add(state_action)
            if execution.replay_rejected:
                replay_rejections += 1
                continue
            if execution.after is None or not execution.candidate_invoked:
                continue

            after = execution.after
            outcome = execution.outcomes[-1]
            route_actions = (*node.actions, action)
            route_effect_groups: list[tuple[EffectRecord, ...]] = []
            for route_action, before_snapshot, after_snapshot, route_outcome in zip(
                route_actions,
                execution.snapshots[:-1],
                execution.snapshots[1:],
                execution.outcomes,
                strict=True,
            ):
                effects = tuple(
                    model.observed_effects(
                        before=before_snapshot,
                        after=after_snapshot,
                        action=route_action,
                        outcome=route_outcome,
                    )
                )
                if any(not isinstance(effect, EffectRecord) for effect in effects):
                    raise ResourceExplorerError(
                        "model.observed_effects must return EffectRecord values"
                    )
                route_effect_groups.append(effects)
            observed_effects = route_effect_groups[-1]
            # Validate that the model did not promote declarations into observation.
            edge_footprint = effect_footprint(
                candidates=action.candidate_effects,
                observed=observed_effects,
            )
            route_candidates = merge_effects(
                *(route_action.candidate_effects for route_action in route_actions)
            )
            route_observed = merge_effects(*route_effect_groups)
            aggregate_candidates.extend(action.candidate_effects)
            aggregate_observed.extend(observed_effects)
            for observation in after.observations:
                discovered_resources[observation.resource.resource_id] = observation.resource

            candidate_depth = node.depth + 1
            depth_reached = max(depth_reached, candidate_depth)
            graph_edges.append(
                {
                    "from": node.snapshot.fingerprint,
                    "to": after.fingerprint,
                    "depth": candidate_depth,
                    "trial_id": execution.trial_id,
                    "operation": action.operation,
                    "action": action.to_json(),
                    "route": {
                        "operations": [item.operation for item in route_actions],
                        "logical_calls": [item.logical_call() for item in route_actions],
                    },
                    "wire_calls": execution.wire_calls,
                    "outcomes": [item.to_json() for item in execution.outcomes],
                    "effect_footprint": edge_footprint,
                    "route_effect_footprint": effect_footprint(
                        candidates=route_candidates,
                        observed=route_observed,
                    ),
                }
            )

            if after.fingerprint in known_states:
                continue
            child = _SearchNode(
                snapshot=after,
                actions=route_actions,
                prefix_fingerprints=(*node.prefix_fingerprints, after.fingerprint),
                prefix_outcomes=(*node.prefix_outcomes, outcome.replay_key),
            )
            known_states[after.fingerprint] = child
            if candidate_depth < max_depth:
                queue.append(child)
            else:
                depth_limited = True

    if budget.exhausted:
        termination_reason = "budget_exhausted"
    elif state_limited:
        termination_reason = "state_limit_reached"
    elif depth_limited:
        termination_reason = "depth_limit_reached"
    else:
        termination_reason = "state_space_exhausted"

    graph_nodes = [
        {
            "fingerprint": fingerprint,
            "depth": node.depth,
            "snapshot": node.snapshot.to_json(),
        }
        for fingerprint, node in sorted(known_states.items())
    ]
    relation_provider = getattr(target, "resource_relations", None)
    if callable(relation_provider):
        relations = tuple(relation_provider(tuple(discovered_resources.values())))
        relation_payload = {
            "status": "provider_declared",
            "relations": [relation.to_json() for relation in relations],
        }
    else:
        relation_payload = {"status": "unavailable", "relations": []}
    return {
        "schema_version": RESOURCE_EXPLORER_SCHEMA_VERSION,
        "session_scope": target.session_scope,
        "target_manifest": target_manifest,
        "target_manifest_sha256": target_manifest_sha256,
        "model_manifest": model_manifest,
        "model_manifest_sha256": model_manifest_sha256,
        "baseline": baseline.to_json(),
        "discovered_resources": [
            discovered_resources[key].to_json() for key in sorted(discovered_resources)
        ],
        "resource_relations": relation_payload,
        "depth_reached": depth_reached,
        "replay_rejections": replay_rejections,
        "state_graph": {"nodes": graph_nodes, "edges": graph_edges},
        "effect_footprint": effect_footprint(
            candidates=aggregate_candidates,
            observed=aggregate_observed,
        ),
        "coverage": {
            "max_depth": max_depth,
            "max_trials": max_trials,
            "max_calls": max_calls,
            "max_states": max_states,
            "max_actions_per_state": max_actions_per_state,
            "trials_used": budget.trials,
            "calls_used": budget.calls,
            "states_observed": len(known_states),
            "state_action_pairs_considered": len(considered_state_actions),
            "state_action_pairs_scheduled": len(scheduled_state_actions),
            "state_action_pairs_attempted": len(graph_edges),
            "generated_actions": generated_actions,
            "action_generation_truncated": truncated_action_states > 0,
            "action_generation_truncated_states": truncated_action_states,
            "budget_exhausted": bool(budget.exhausted),
            "budget_exhaustion_reasons": sorted(budget.exhausted),
            "state_limit_reached": state_limited,
        },
        "termination_reason": termination_reason,
        "scope_assessment": {
            "status": "incomplete_product_scope",
            "dimensions": {
                "resource_kinds": "model_manifest_and_observed_resources",
                "action_space": (
                    "model_generated_with_truncation"
                    if truncated_action_states
                    else "model_generated_bounded_sample"
                ),
                "observable_state_space": termination_reason,
                "effect_semantics": "model_declared_candidates_and_observed_differences",
                "hidden_or_delayed_state": "outside_claim_unless_observed",
            },
        },
        "claim_boundary": (
            "Routes were generated by the recorded model from normalized resource snapshots. "
            "Every extension was reset and replayed, and only stable observed states entered "
            "the graph. Coverage is bounded by the model's resource observers, action generator, "
            "effect mapper, settling contract, depth, state, trial, call, and action budgets. "
            "Hidden state and actions the model did not generate remain outside the claim."
        ),
    }
