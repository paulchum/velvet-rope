"""Route discovery: generate candidate call sequences instead of authoring them.

Hand-authored routes were ShadowPath's weakest part. A human wrote a winning
recipe into the adapter, the engine adjudicated it, and the resulting coverage
number described the author's imagination rather than the system's surface.

This module generates routes instead.  It reads the tool surface the system
actually advertises, binds every path-shaped parameter to a pool of interesting
paths and spellings, executes the result, and lets
:mod:`velvet.shadowpath_observer` adjudicate.

Two design positions follow from having a reliable oracle:

*Capability is never inferred from a tool name.*  The original adapter carried a
hand-written table saying which tools could reach the target, which is the same
reasoning error as the policy bug it was reporting.  Here every advertised tool
with a bindable parameter is attempted, and a tool that changes nothing is
recorded as attempted-and-inert.  That is evidence rather than assumption, and
it makes the coverage denominator real.

*Depth comes from observation, not from a guess.* The explorer indexes every
observed state, including changes outside a declared protected set, and searches
outward from those states. Newly observed paths become argument candidates. A
route is replayed from the baseline before extension, so unstable setup steps do
not receive breach credit.
"""

from __future__ import annotations

import copy
import hashlib
import json
import posixpath
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast

from velvet.shadowpath_effects import (
    EffectRecord,
    ResourceRef,
    effect_footprint,
    merge_effects,
)
from velvet.shadowpath_observer import (
    ASSET_STATUSES,
    DEFAULT_BREACH_STATUSES,
    OBSERVER_SCHEMA_VERSION,
    AssetState,
    AssetStatus,
    ProtectedAsset,
    Transition,
    adjudicate,
    diff,
)
from velvet.shadowpath_schema import Address, generate_arguments
from velvet.shadowpath_scope import (
    CompiledPolicyScope,
    compile_policy_scope,
    operation_may_write,
    static_policy_coverage,
)

JsonObject = dict[str, Any]

EXPLORER_SCHEMA_VERSION = "velvet.shadowpath.exploration.v0.3"

# Parameter names that suggest a path.  This heuristic only orders which
# parameters are bound first; it never excludes a tool, because a tool with no
# path-shaped parameter still has every string parameter bound.
_NAME_TOKENS = (
    "path",
    "file",
    "filename",
    "dir",
    "directory",
    "folder",
    "source",
    "src",
    "destination",
    "dest",
    "target",
    "archive",
    "uri",
    "url",
    "location",
    "output",
    "input",
    "from",
    "to",
)

# Descriptions are prose, so only unambiguous nouns are read from them.  Short
# function words such as "to" appear in any sentence ("bytes to write") and
# would classify a content parameter as a path.
_DESCRIPTION_TOKENS = (
    "path",
    "file",
    "filename",
    "directory",
    "folder",
    "archive",
)

_NAME_PATTERN = re.compile(r"(?:^|[^a-z])(?:" + "|".join(_NAME_TOKENS) + r")(?:[^a-z]|$)")
_DESCRIPTION_PATTERN = re.compile(r"\b(?:" + "|".join(_DESCRIPTION_TOKENS) + r")s?\b")

_MARKER = "# shadowpath explorer payload\nexport SHADOWPATH_VALUE=explored\n"


SessionScope = Literal["per_call", "per_route", "persistent"]

CallStatus = Literal["executed", "blocked", "error"]


class ShadowPathExplorerError(RuntimeError):
    """Raised when a target cannot be explored honestly."""


@dataclass(frozen=True)
class CallOutcome:
    """How the system answered one dispatched call.

    Adjudication never reads this -- a breach is credited from observed state
    alone.  It exists so a route that did not breach can be told apart from a
    route that never ran: ``blocked`` is the policy working, ``error`` is our
    own call being malformed, and conflating them would turn a defect in the
    generator into a coverage claim.
    """

    status: CallStatus
    block_reason: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> JsonObject:
        return {
            "status": self.status,
            "block_reason": self.block_reason,
            "raw": dict(self.raw),
        }


class ExplorationTarget(Protocol):
    """A system under test the explorer can reset, drive and observe.

    The target owns the disposable workspace.  The explorer never interprets a
    call result as proof of anything; it only reads the snapshots.
    """

    session_scope: SessionScope

    def manifest(self) -> Mapping[str, Any]:
        """Return the pinned identity of the runtime, already verified."""

    def advertise(self) -> Sequence[Mapping[str, Any]]:
        """Return the tool surface as offered through the mediation boundary."""

    def resolve(self, trial_id: str, path: str) -> str:
        """Map a generated root-relative path onto the wire.

        Implementations must join a prefix and nothing else.  Canonicalising
        here would destroy the separator and traversal spellings the explorer
        generates, which are the point of generating them.
        """

    def reset(self, trial_id: str) -> None:
        """Restore the disposable workspace to its baseline."""

    def observe(self, trial_id: str) -> dict[str, AssetState]:
        """Return a snapshot of the watched root."""

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
        """Dispatch one call and classify how the system answered."""

    def root(self, trial_id: str) -> str | None:
        """Return the absolute watched root, for argument-visibility spelling."""

    def teardown(self, trial_id: str) -> None:
        """Release anything the trial held open."""

@dataclass(frozen=True)
class Operation:
    """One advertised tool, with its parameters classified for binding."""

    name: str
    bindable_params: tuple[str, ...]
    other_required: tuple[str, ...]
    schema: Mapping[str, Any] = field(default_factory=dict)
    description: str = ""
    annotations: Mapping[str, Any] = field(default_factory=dict)

    @property
    def access(self) -> tuple[str, str]:
        may_write, basis = operation_may_write(
            {"name": self.name, "annotations": self.annotations}
        )
        if may_write:
            return "write", basis
        if self.annotations.get("readOnlyHint") is True:
            return "read", basis
        return "unknown", basis

    def to_json(self) -> JsonObject:
        schema = copy.deepcopy(dict(self.schema))
        serialized = json.dumps(schema, sort_keys=True, separators=(",", ":"))
        return {
            "name": self.name,
            "bindable_params": list(self.bindable_params),
            "other_required": list(self.other_required),
            "binding_classification_basis": (
                "path-like schema name or description; all-string fallback when absent"
            ),
            "schema": schema,
            "schema_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
            "description": self.description,
            "annotations": copy.deepcopy(dict(self.annotations)),
            "effect_access": self.access[0],
            "effect_access_basis": self.access[1],
        }


@dataclass(frozen=True)
class CandidateRoute:
    """A generated call sequence, before it is known to do anything."""

    route_id: str
    calls: tuple[Mapping[str, Any], ...]
    origin: str
    operations: tuple[str, ...]
    # Which argument keys of each call hold generated paths, so dispatch can
    # put them on the wire without touching synthesized filler values.
    bound_params: tuple[tuple[str, ...], ...] = ()

    def to_json(self) -> JsonObject:
        return {
            "route_id": self.route_id,
            "origin": self.origin,
            "operations": list(self.operations),
            "calls": [dict(call) for call in self.calls],
            "bound_params": [list(params) for params in self.bound_params],
        }


def _looks_like_path(name: str, description: str) -> bool:
    if _NAME_PATTERN.search(name.lower()):
        return True
    return bool(_DESCRIPTION_PATTERN.search(description.lower()))


def classify_operations(tools: Sequence[Mapping[str, Any]]) -> list[Operation]:
    """Derive bindable operations from an advertised tool surface.

    Every tool is kept.  Capability is decided by executing it and observing the
    result, never by recognising its name, so a tool this function cannot read
    is still attempted with whatever string parameters it declares.
    """

    operations: list[Operation] = []
    names_seen: set[str] = set()
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            raise ShadowPathExplorerError("advertised tool is missing a name")
        if name in names_seen:
            raise ShadowPathExplorerError(f"advertised tool name is duplicated: {name!r}")
        names_seen.add(name)
        if "inputSchema" in tool:
            schema = tool["inputSchema"]
        elif "input_schema" in tool:
            schema = tool["input_schema"]
        else:
            raise ShadowPathExplorerError(f"advertised tool {name!r} is missing an input schema")
        if not isinstance(schema, Mapping):
            raise ShadowPathExplorerError(f"advertised tool {name!r} has a malformed input schema")
        properties = schema.get("properties")
        properties = properties if isinstance(properties, Mapping) else {}
        required_raw = schema.get("required")
        required = [str(item) for item in required_raw] if isinstance(required_raw, list) else []
        path_like: list[str] = []
        string_params: list[str] = []
        for param, spec in sorted(properties.items()):
            detail = spec if isinstance(spec, Mapping) else {}
            kind = detail.get("type")
            description = str(detail.get("description", ""))
            if kind == "string":
                string_params.append(str(param))
                if _looks_like_path(str(param), description):
                    path_like.append(str(param))
        bindable = tuple(path_like) if path_like else tuple(string_params)
        other_required = tuple(param for param in sorted(required) if param not in bindable)
        operations.append(
            Operation(
                name=name,
                bindable_params=bindable,
                other_required=other_required,
                schema=schema,
                description=str(tool.get("description", "")),
                annotations=(
                    dict(cast(Mapping[str, Any], tool["annotations"]))
                    if isinstance(tool.get("annotations"), Mapping)
                    else {}
                ),
            )
        )
    return sorted(operations, key=lambda item: item.name)


def path_candidates_from_policy(policy_text: str) -> list[str]:
    """Return validated resource witnesses compiled from policy regexes."""

    return sorted({item.resource_key for item in compile_policy_scope(policy_text).witnesses})


def encode_variants(path: str) -> list[str]:
    """Return spellings of one path that reach it without matching literally.

    Windows separators and a redundant traversal are the cheap multipliers: an
    argument-matching rule written with forward slashes and no normalisation
    never sees them, while the filesystem resolves them all the same.
    """

    variants = {path}
    if path and not path.startswith("/"):
        variants.add(f"./{path}")
        variants.add(f"sentinel/../{path}")
    if "/" in path:
        variants.add(path.replace("/", "\\"))
        head, _, tail = path.rpartition("/")
        if head:
            variants.add(f"{head}/./{tail}")
            variants.add(f"{head}/sentinel/../{tail}")
    return sorted(variants)


def _ancestors_of(path: str) -> list[str]:
    parts = [part for part in path.split("/") if part not in ("", ".")]
    return ["/".join(parts[:index]) for index in range(1, len(parts))]


@dataclass(frozen=True)
class ExplorationScope:
    """What the adversary is assumed to control and what must not change."""

    protected: tuple[ProtectedAsset, ...]
    payload_paths: tuple[str, ...] = ()
    scratch_paths: tuple[str, ...] = ()
    extra_paths: tuple[str, ...] = ()
    include_ancestors: bool = True
    include_encodings: bool = True
    # Retained for the legacy ``plan_routes`` helper. Stateful exploration has
    # one independent, reportable cap for both declared and automatic scopes.
    max_bindings_per_operation: int = 32
    source: str = "operator_declared"
    resource_groups: Mapping[str, str] = field(default_factory=dict)

    def binding_pool(self) -> list[str]:
        """Return every path worth binding, protected first."""

        protected_paths = [asset.path for asset in self.protected]
        if self.resource_groups:
            groups: dict[str, list[str]] = {}
            for path in protected_paths:
                groups.setdefault(self.resource_groups.get(path, "ungrouped"), []).append(path)
            protected_paths = [
                group[index]
                for index in range(max(map(len, groups.values()), default=0))
                for group in groups.values()
                if index < len(group)
            ]
        # Seed one protected destination and an attacker-controlled source
        # before widening across the rest of the scope. This is role ordering,
        # not an operation recipe, and applies to any schema with resource
        # parameters.
        pool: list[str] = protected_paths[:1]
        pool.extend(self.payload_paths)
        pool.extend(protected_paths[1:])
        if self.include_ancestors:
            for asset in self.protected:
                pool.extend(_ancestors_of(asset.path))
        pool.extend(self.scratch_paths)
        pool.extend(self.extra_paths)
        seen: set[str] = set()
        ordered: list[str] = []
        for item in pool:
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered


def _synthesize(spec: Mapping[str, Any], marker: str, depth: int = 0) -> Any:
    """Build a minimal value satisfying one JSON Schema fragment."""

    if depth > 4:
        return marker
    kind = spec.get("type")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), "string")
    if kind == "array":
        items = spec.get("items")
        item_spec = items if isinstance(items, Mapping) else {}
        return [_synthesize(item_spec, marker, depth + 1)]
    if kind == "object":
        properties = spec.get("properties")
        properties = properties if isinstance(properties, Mapping) else {}
        required_raw = spec.get("required")
        required = (
            [str(item) for item in required_raw]
            if isinstance(required_raw, list)
            else sorted(str(key) for key in properties)
        )
        built: JsonObject = {}
        for key in required:
            detail = properties.get(key)
            built[key] = _synthesize(
                detail if isinstance(detail, Mapping) else {}, marker, depth + 1
            )
        return built
    if kind == "boolean":
        return True
    if kind in ("integer", "number"):
        return 1
    return marker


def _fill_other_required(operation: Operation, marker: str) -> JsonObject:
    properties = operation.schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}
    filled: JsonObject = {}
    for param in operation.other_required:
        spec = properties.get(param)
        filled[param] = _synthesize(spec if isinstance(spec, Mapping) else {}, marker)
    return filled


def plan_routes(
    *,
    operations: Sequence[Operation],
    scope: ExplorationScope,
    marker: str = _MARKER,
) -> list[CandidateRoute]:
    """Enumerate depth-1 candidate routes over the advertised surface.

    Every operation appears at least once even when nothing can be bound to it,
    so the plan doubles as the coverage denominator: what was offered, and what
    was tried against it.
    """

    pool = scope.binding_pool()
    if not pool:
        raise ShadowPathExplorerError("exploration scope declares no bindable paths")
    routes: list[CandidateRoute] = []
    for operation in operations:
        bindings: list[JsonObject] = []
        if not operation.bindable_params:
            bindings.append({})
        elif len(operation.bindable_params) == 1:
            param = operation.bindable_params[0]
            for path in pool:
                spellings = encode_variants(path) if scope.include_encodings else [path]
                for spelling in spellings:
                    bindings.append({param: spelling})
        else:
            first, second = operation.bindable_params[0], operation.bindable_params[1]
            for source in pool:
                for destination in pool:
                    if source == destination:
                        continue
                    bindings.append({first: source, second: destination})
                    if scope.include_encodings:
                        for spelling in encode_variants(destination)[:2]:
                            if spelling != destination:
                                bindings.append({first: source, second: spelling})
        for index, binding in enumerate(bindings[: scope.max_bindings_per_operation]):
            arguments = {**_fill_other_required(operation, marker), **binding}
            routes.append(
                CandidateRoute(
                    route_id=f"d1-{operation.name}-{index}",
                    calls=({"name": operation.name, "arguments": arguments},),
                    origin="depth1_sweep",
                    operations=(operation.name,),
                    bound_params=(tuple(sorted(binding)),),
                )
            )
    return routes


@dataclass(frozen=True)
class _Action:
    operation: str
    arguments: dict[str, Any]
    path_slots: tuple[Address, ...]
    access: str = "unknown"
    access_basis: str = "no mutation evidence"

    @property
    def fingerprint(self) -> str:
        value = json.dumps(
            [self.operation, self.arguments, self.path_slots],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class _SearchNode:
    snapshot: Mapping[str, AssetState]
    fingerprint: str
    calls: tuple[Mapping[str, Any], ...] = ()
    slots: tuple[tuple[Address, ...], ...] = ()
    prefix_fingerprints: tuple[str, ...] = ()
    prefix_outcomes: tuple[tuple[CallStatus, str | None], ...] = ()
    prefix_candidate_effects: tuple[EffectRecord, ...] = ()
    prefix_observed_effects: tuple[EffectRecord, ...] = ()

    @property
    def depth(self) -> int:
        return len(self.calls)


@dataclass(frozen=True)
class _TrialExecution:
    trial_id: str
    wire_calls: tuple[Mapping[str, Any], ...]
    outcomes: tuple[CallOutcome, ...]
    after: Mapping[str, AssetState] | None
    root: str | None
    replay_rejected: bool
    candidate_invoked: bool
    observation_samples: int = 0
    observation_settled: bool = True


def _invoke(target: ExplorationTarget, trial_id: str, call: Mapping[str, Any]) -> CallOutcome:
    """Keep one malformed generated call from aborting the bounded search."""

    try:
        outcome = target.invoke(trial_id, call)
    except Exception as error:
        return CallOutcome(
            status="error",
            raw={"exception": type(error).__name__, "message": str(error)},
        )
    if not isinstance(outcome, CallOutcome):
        raise ShadowPathExplorerError("target.invoke must return CallOutcome")
    return outcome


@dataclass
class _Budget:
    max_trials: int
    max_calls: int
    trials: int = 0
    calls: int = 0
    exhausted: set[str] = field(default_factory=set)

    def reserve(self, route_length: int) -> bool:
        if self.trials >= self.max_trials:
            self.exhausted.add("max_trials")
        if self.calls + route_length > self.max_calls:
            self.exhausted.add("max_calls")
        if self.exhausted:
            return False
        self.trials += 1
        return True


def _snapshot_fingerprint(observed: Mapping[str, AssetState]) -> str:
    payload = {path: observed[path].to_json() for path in sorted(observed)}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


@dataclass(frozen=True)
class _SettledObservation:
    snapshot: Mapping[str, AssetState]
    fingerprint: str
    samples: int
    settled: bool


def _observe_stable(
    target: ExplorationTarget,
    trial_id: str,
    *,
    consecutive: int,
    maximum: int,
) -> _SettledObservation:
    """Require repeated scope digests without assuming a provider's clock."""

    previous: str | None = None
    matching = 0
    latest: Mapping[str, AssetState] = {}
    fingerprint = ""
    for sample in range(1, maximum + 1):
        latest = target.observe(trial_id)
        fingerprint = _snapshot_fingerprint(latest)
        matching = matching + 1 if fingerprint == previous else 1
        if matching >= consecutive:
            return _SettledObservation(dict(latest), fingerprint, sample, True)
        previous = fingerprint
    return _SettledObservation(dict(latest), fingerprint, maximum, False)


def _set_address(value: Any, address: Address, replacement: str) -> None:
    if not address:
        raise ShadowPathExplorerError("a path binding cannot replace the argument object itself")
    cursor = value
    for component in address[:-1]:
        cursor = cursor[component]
    cursor[address[-1]] = replacement


def _value_at_address(value: Any, address: Address) -> Any:
    cursor = value
    for component in address:
        cursor = cursor[component]
    return cursor


def _candidate_effects(
    action: _Action,
    *,
    namespace: str,
    invocation_namespace: str,
    resource_kind: str,
) -> tuple[EffectRecord, ...]:
    effects: list[EffectRecord] = [
        EffectRecord(
            effect="delegated_tool.call",
            resource=ResourceRef(
                invocation_namespace, "delegated_tool.operation", action.operation
            ),
            evidence_level="candidate",
            provenance="generated_call_plan",
            operation=action.operation,
            details={"status": "planned"},
        )
    ]
    seen: set[tuple[Address, str]] = set()
    for address in action.path_slots:
        presented = _value_at_address(action.arguments, address)
        if not isinstance(presented, str):
            continue
        key = posixpath.normpath(presented.replace("\\", "/"))
        identity = (address, key)
        if identity in seen:
            continue
        seen.add(identity)
        evidence_level = (
            "adapter_declared"
            if action.access_basis.startswith("mcp.annotation")
            else "candidate"
        )
        effects.append(
            EffectRecord(
                effect=(
                    f"resource.{action.access}"
                    if action.access != "unknown"
                    else "effect.unknown"
                ),
                resource=ResourceRef(namespace, resource_kind, key),
                evidence_level=cast(Any, evidence_level),
                provenance=f"schema_bound_argument; {action.access_basis}",
                operation=action.operation,
                details={
                    "argument_address": list(address),
                    "presented_value": presented,
                    "access": action.access,
                },
            )
        )
    return tuple(effects)


_TRANSITION_EFFECTS = {
    "created": "resource.create",
    "deleted": "resource.delete",
    "content_replaced": "resource.content.replace",
    "permissions_changed": "resource.permissions.change",
    "type_replaced": "resource.type.replace",
}


def _observed_effects(
    *,
    action: _Action,
    outcome: CallOutcome,
    transitions: Sequence[Transition],
    namespace: str,
    invocation_namespace: str,
    resource_kind: str,
) -> tuple[EffectRecord, ...]:
    delegated = EffectRecord(
        effect="delegated_tool.call",
        resource=ResourceRef(invocation_namespace, "delegated_tool.operation", action.operation),
        evidence_level="observed",
        provenance="explorer_dispatch_outcome",
        operation=action.operation,
        details={"status": outcome.status, "block_reason": outcome.block_reason},
    )
    return (
        delegated,
        *_transition_effect_records(
            transitions=transitions,
            operation=action.operation,
            namespace=namespace,
            resource_kind=resource_kind,
            provenance="independent_state_observer",
        ),
    )


def _transition_effect_records(
    *,
    transitions: Sequence[Transition],
    operation: str,
    namespace: str,
    resource_kind: str,
    provenance: str,
) -> tuple[EffectRecord, ...]:
    effects: list[EffectRecord] = []
    for transition in transitions:
        details: JsonObject = {"transition_kind": transition.kind}
        effect = _TRANSITION_EFFECTS[transition.kind]
        if transition.relocated_to is not None:
            effect = "resource.relocate.source"
            details["relocated_to"] = ResourceRef(
                namespace, resource_kind, transition.relocated_to
            ).to_json()
        elif transition.relocated_from is not None:
            effect = "resource.relocate.destination"
            details["relocated_from"] = ResourceRef(
                namespace, resource_kind, transition.relocated_from
            ).to_json()
        effects.append(
            EffectRecord(
                effect=effect,
                resource=ResourceRef(namespace, resource_kind, transition.path),
                evidence_level="observed",
                provenance=provenance,
                operation=operation,
                details=details,
            )
        )
    return tuple(effects)


def _wire_call(
    *, target: ExplorationTarget, trial_id: str, call: Mapping[str, Any], slots: Sequence[Address]
) -> Mapping[str, Any]:
    arguments = copy.deepcopy(dict(cast(Mapping[str, Any], call.get("arguments", {}))))
    for address in slots:
        cursor: Any = arguments
        for component in address:
            cursor = cursor[component]
        if isinstance(cursor, str):
            _set_address(arguments, address, target.resolve(trial_id, cursor))
    return {"name": str(call["name"]), "arguments": arguments}


def _execute_transition(
    *,
    target: ExplorationTarget,
    baseline_fingerprint: str,
    node: _SearchNode,
    action: _Action,
    budget: _Budget,
    observation_consecutive: int,
    max_observation_samples: int,
) -> _TrialExecution | None:
    route_length = node.depth + 1
    if not budget.reserve(route_length):
        return None
    safe_operation = re.sub(r"[^A-Za-z0-9_.-]", "_", action.operation)[:32] or "operation"
    trial_id = (
        f"trial-{budget.trials:05d}-d{route_length}-{safe_operation}-{action.fingerprint[:8]}"
    )
    wire_calls: list[Mapping[str, Any]] = []
    outcomes: list[CallOutcome] = []
    root: str | None = None
    try:
        target.reset(trial_id)
        initial_observation = _observe_stable(
            target,
            trial_id,
            consecutive=observation_consecutive,
            maximum=max_observation_samples,
        )
        root = target.root(trial_id)
        if (
            not initial_observation.settled
            or initial_observation.fingerprint != baseline_fingerprint
        ):
            return _TrialExecution(
                trial_id,
                (),
                (),
                None,
                root,
                True,
                False,
                initial_observation.samples,
                initial_observation.settled,
            )

        for call, slots, expected, expected_outcome in zip(
            node.calls,
            node.slots,
            node.prefix_fingerprints,
            node.prefix_outcomes,
            strict=True,
        ):
            dispatched = _wire_call(target=target, trial_id=trial_id, call=call, slots=slots)
            wire_calls.append(dispatched)
            budget.calls += 1
            outcome = _invoke(target, trial_id, dispatched)
            outcomes.append(outcome)
            replay_observation = _observe_stable(
                target,
                trial_id,
                consecutive=observation_consecutive,
                maximum=max_observation_samples,
            )
            replayed = replay_observation.snapshot
            observed_outcome = (outcome.status, outcome.block_reason)
            if (
                not replay_observation.settled
                or replay_observation.fingerprint != expected
                or observed_outcome != expected_outcome
            ):
                return _TrialExecution(
                    trial_id,
                    tuple(wire_calls),
                    tuple(outcomes),
                    replayed,
                    root,
                    True,
                    False,
                    replay_observation.samples,
                    replay_observation.settled,
                )

        logical = {"name": action.operation, "arguments": action.arguments}
        dispatched = _wire_call(
            target=target, trial_id=trial_id, call=logical, slots=action.path_slots
        )
        wire_calls.append(dispatched)
        budget.calls += 1
        outcome = _invoke(target, trial_id, dispatched)
        outcomes.append(outcome)
        after_observation = _observe_stable(
            target,
            trial_id,
            consecutive=observation_consecutive,
            maximum=max_observation_samples,
        )
        after = after_observation.snapshot
        return _TrialExecution(
            trial_id,
            tuple(wire_calls),
            tuple(outcomes),
            after,
            root,
            not after_observation.settled,
            True,
            after_observation.samples,
            after_observation.settled,
        )
    finally:
        target.teardown(trial_id)


def _inventory(
    target: ExplorationTarget, *, observation_consecutive: int, max_observation_samples: int
) -> dict[str, AssetState]:
    trial_id = "inventory"
    try:
        target.reset(trial_id)
        observed = _observe_stable(
            target,
            trial_id,
            consecutive=observation_consecutive,
            maximum=max_observation_samples,
        )
        if not observed.settled:
            raise ShadowPathExplorerError(
                "baseline scope digest did not settle within the observation budget"
            )
        return dict(observed.snapshot)
    finally:
        target.teardown(trial_id)


@dataclass(frozen=True)
class _CandidatePathPool:
    values: tuple[str, ...]
    preferred_pairs: tuple[tuple[str, str], ...]
    available: int
    truncated: bool


def _candidate_paths(
    *,
    scope: ExplorationScope | None,
    baseline_paths: Sequence[str],
    observed: Mapping[str, AssetState],
    maximum: int,
    include_windows_separators: bool,
) -> _CandidatePathPool:
    """Build a fair path sample from declared and observed state.

    Canonical paths are emitted before alternate spellings. This prevents a
    handful of encodings for the first protected path from consuming the whole
    budget. Every mode also receives a fresh sibling in each observed parent,
    so create and move operations do not need a hand-authored destination.
    """

    originals = [
        *(scope.binding_pool() if scope is not None else ()),
        *baseline_paths,
        *sorted(observed),
    ]
    canonical: list[str] = []
    canonical_seen: set[str] = set()
    for path in originals:
        if path and path not in canonical_seen:
            canonical_seen.add(path)
            canonical.append(path)

    # Pair each sampled resource with a fresh sibling. Operations that require
    # an absent destination (rename, move, clone, export) then receive a valid
    # role pairing before the global path cap is consumed. This is derived from
    # resource topology and does not encode an operation-specific route.
    occupied = set(canonical)
    paired: list[str] = []
    next_suffix: dict[str, int] = {}
    scratch_for: dict[str, str] = {}

    def add_scratch(parent: str) -> str:
        suffix = next_suffix.get(parent, 0)
        while True:
            name = f".shadowpath-probe-{suffix:03d}"
            candidate = f"{parent}/{name}" if parent else name
            if candidate not in occupied:
                occupied.add(candidate)
                next_suffix[parent] = suffix + 1
                return candidate
            suffix += 1

    for path in canonical:
        paired.append(path)
        if ".shadowpath-probe-" in path:
            continue
        parent, separator, _ = path.rpartition("/")
        parent = parent if separator else ""
        state = observed.get(path)
        if state is not None and state.kind == "directory":
            paired.append(add_scratch(path))
        scratch = add_scratch(parent)
        paired.append(scratch)
        scratch_for[path] = scratch
    if not paired:
        paired.append(add_scratch(""))

    ordered = list(paired)
    seen = set(ordered)
    if scope is None or scope.include_encodings:
        variant_groups = [
            [
                value
                for value in encode_variants(path)
                if value != path and (include_windows_separators or "\\" not in value)
            ]
            for path in paired
        ]
        for index in range(max((len(group) for group in variant_groups), default=0)):
            for group in variant_groups:
                if index < len(group) and group[index] not in seen:
                    seen.add(group[index])
                    ordered.append(group[index])
    selected = tuple(ordered[:maximum])
    selected_set = set(selected)
    preferred_pairs: list[tuple[str, str]] = []
    if scope is not None:
        protected_set = {item.path for item in scope.protected}
        guarded_set = set(protected_set)
        if scope.include_ancestors:
            for protected in protected_set:
                guarded_set.update(_ancestors_of(protected))
        source_candidates = list(scope.payload_paths)
        if not source_candidates:
            source_candidates = [
                path
                for path, state in observed.items()
                if state.kind == "file" and path not in protected_set
            ]
        guarded_order = [path for path in scope.binding_pool() if path in guarded_set]
        guarded_position = {path: index for index, path in enumerate(guarded_order)}
        guarded_order.sort(
            key=lambda path: (path in observed, guarded_position[path])
        )
    else:
        canonical_order = {path: index for index, path in enumerate(canonical)}
        guarded_order = sorted(
            canonical,
            key=lambda path: (
                0
                if path not in observed
                else 1
                if observed[path].kind == "file"
                else 2,
                canonical_order[path],
            ),
        )
        baseline_order = {path: index for index, path in enumerate(baseline_paths)}
        source_candidates = sorted(
            (path for path, state in observed.items() if state.kind == "file"),
            key=lambda path: (path not in baseline_order, baseline_order.get(path, 0), path),
        )
    for guarded in guarded_order:
        protected_scratch = scratch_for.get(guarded)
        pairs: list[tuple[str, str]] = []
        source_pairs = [
            pair
            for source in source_candidates
            if source != guarded
            for pair in ((source, guarded), (guarded, source))
        ]
        scratch_pairs = (
            [(guarded, protected_scratch), (protected_scratch, guarded)]
            if protected_scratch is not None
            else []
        )
        # A missing baseline key is the most informative state transition: try
        # surviving baseline resources against it before inventing more paths.
        # For present resources, try the fresh sibling first so the explorer
        # can discover the enabling removal/relocation state.
        pairs.extend(source_pairs if guarded not in observed else scratch_pairs)
        pairs.extend(scratch_pairs if guarded not in observed else source_pairs)
        for pair in pairs:
            if pair[0] in selected_set and pair[1] in selected_set:
                preferred_pairs.append(pair)
    return _CandidatePathPool(
        values=selected,
        preferred_pairs=tuple(dict.fromkeys(preferred_pairs)),
        available=len(ordered),
        truncated=len(ordered) > maximum,
    )


def _operation_actions(
    *,
    operation: Operation,
    paths: Sequence[str],
    observed: Mapping[str, AssetState],
    preferred_path_pairs: Sequence[tuple[str, str]] = (),
    marker: str,
    maximum: int,
) -> tuple[list[_Action], tuple[str, ...], bool]:
    bindable_roots = frozenset(operation.bindable_params)
    ordered_pairs = list(preferred_path_pairs)
    if len(operation.bindable_params) == 2:
        first, second = (item.lower().replace("_", "") for item in operation.bindable_params)
        source_tokens = ("source", "src", "from")
        destination_tokens = ("destination", "dest", "dst", "target", "to")
        first_is_source = any(token in first for token in source_tokens)
        second_is_source = any(token in second for token in source_tokens)
        first_is_destination = any(token in first for token in destination_tokens)
        second_is_destination = any(token in second for token in destination_tokens)

        def role_score(pair: tuple[str, str]) -> int:
            first_exists = pair[0] in observed
            second_exists = pair[1] in observed
            if first_is_source and second_is_destination:
                return 0 if first_exists and not second_exists else 1
            if second_is_source and first_is_destination:
                return 0 if second_exists and not first_exists else 1
            return 0 if first_exists != second_exists else 1

        ordered_pairs.sort(key=role_score)

    def is_path_slot(address: Address, _schema: Mapping[str, Any]) -> bool:
        return not bindable_roots or bool(address) and str(address[0]) in bindable_roots

    content_samples = tuple(
        dict.fromkeys(
            state.sample_text
            for state in observed.values()
            if state.kind == "file" and state.sample_text is not None
        )
    )

    def literal_values(address: Address, schema: Mapping[str, Any]) -> Sequence[Any]:
        leaf = str(address[-1]).lower().replace("_", "") if address else ""
        description = str(schema.get("description", "")).lower()
        is_current_value = (
            leaf.startswith(("old", "current", "existing", "expected"))
            or "must match exactly" in description
            or "text to search for" in description
        )
        return content_samples if is_current_value else ()

    try:
        plan = generate_arguments(
            operation.schema,
            paths,
            marker=marker,
            max_candidates=maximum,
            path_slot_predicate=is_path_slot,
            literal_value_provider=literal_values,
            preferred_path_pairs=ordered_pairs,
        )
    except Exception as error:
        issue = f"argument generation failed: {type(error).__name__}: {error}"
        return [], (issue,), False
    actions = [
        _Action(
            operation.name,
            copy.deepcopy(candidate.arguments),
            candidate.path_slots,
            *operation.access,
        )
        for candidate in plan.candidates
    ]
    return actions, plan.issues, plan.truncated


def _route_origin(depth: int) -> str:
    if depth == 1:
        return "depth1_state_search"
    if depth == 2:
        return "depth2_enabled_by_observed_disturbance"
    return "state_space_bfs"


def _route_json(
    *,
    route_id: str,
    calls: Sequence[Mapping[str, Any]],
    operation_names: Sequence[str],
    slots: Sequence[Sequence[Address]],
    redacted_values: Mapping[str, str] | None = None,
) -> JsonObject:
    replacements = redacted_values or {}

    def redact(value: Any) -> Any:
        if isinstance(value, str) and value in replacements:
            return replacements[value]
        if isinstance(value, Mapping):
            return {str(key): redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return {
        "route_id": route_id,
        "origin": _route_origin(len(calls)),
        "operations": list(operation_names),
        "calls": [redact(copy.deepcopy(dict(call))) for call in calls],
        "bound_params": [],
        "path_slots": [[list(address) for address in call_slots] for call_slots in slots],
    }


def _node_priority(
    node: _SearchNode,
    *,
    baseline: Mapping[str, AssetState],
    scope: ExplorationScope | None,
) -> tuple[int, int, int]:
    """Keep breadth first, then prefer security-relevant and topology-changing states."""

    if scope is not None and any(
        asset.path in baseline and asset.path not in node.snapshot for asset in scope.protected
    ):
        relevance = 0
    elif scope is not None and any(
        node.snapshot.get(asset.path) != baseline.get(asset.path) for asset in scope.protected
    ):
        relevance = 1
    elif any(path not in node.snapshot for path in baseline):
        # A removed/relocated baseline resource can unlock an operation that
        # refuses to replace existing destinations. This is the enabling state
        # in stateful compositions and is useful even with no declared scope.
        relevance = 2
    elif any(path not in baseline for path in node.snapshot):
        relevance = 3
    elif any(node.snapshot.get(path) != state for path, state in baseline.items()):
        relevance = 4
    else:
        relevance = 5
    changed_paths = sum(
        node.snapshot.get(path) != baseline.get(path) for path in set(node.snapshot) | set(baseline)
    )
    # ``min`` preserves queue insertion order when this key ties. That makes
    # deterministic generation order, rather than an opaque hash, decide which
    # equally small disturbance is extended first.
    return node.depth, relevance, changed_paths


def explore(
    *,
    target: ExplorationTarget,
    tools: Sequence[Mapping[str, Any]] | None = None,
    scope: ExplorationScope | None = None,
    max_depth: int = 3,
    breach_statuses: Iterable[AssetStatus] | None = None,
    marker: str = _MARKER,
    max_depth2_routes: int | None = None,
    max_trials: int = 1_000,
    max_calls: int = 5_000,
    max_paths_per_state: int = 64,
    max_arguments_per_operation_state: int = 32,
    policy_scope: CompiledPolicyScope | None = None,
    observation_consecutive: int = 2,
    max_observation_samples: int = 4,
    max_actions_per_state_visit: int = 96,
) -> JsonObject:
    """Explore reachable observed states without supplied route recipes.

    Breadth-first search extends every distinct observed state. Each extension
    replays its prefix from a fresh baseline and rejects the route if any prefix
    snapshot changes. With no explicit scope, changes are reported as candidate
    asset impacts and never promoted to policy breaches.
    """

    for name, value in (
        ("max_depth", max_depth),
        ("max_trials", max_trials),
        ("max_calls", max_calls),
        ("max_paths_per_state", max_paths_per_state),
        ("max_arguments_per_operation_state", max_arguments_per_operation_state),
        ("observation_consecutive", observation_consecutive),
        ("max_observation_samples", max_observation_samples),
        ("max_actions_per_state_visit", max_actions_per_state_visit),
    ):
        if value < 1:
            raise ShadowPathExplorerError(f"{name} must be positive")
    if max_depth2_routes is not None and max_depth2_routes < 1:
        raise ShadowPathExplorerError("max_depth2_routes must be positive when supplied")
    if observation_consecutive > max_observation_samples:
        raise ShadowPathExplorerError(
            "observation_consecutive cannot exceed max_observation_samples"
        )
    if scope is not None and not scope.protected:
        raise ShadowPathExplorerError("an explicit exploration scope needs a protected asset")
    status_set = frozenset(
        breach_statuses if breach_statuses is not None else DEFAULT_BREACH_STATUSES
    )
    unknown_statuses = status_set.difference(ASSET_STATUSES)
    if unknown_statuses:
        raise ShadowPathExplorerError(
            f"unknown breach status: {', '.join(sorted(str(item) for item in unknown_statuses))}"
        )
    statuses = tuple(sorted(status_set))

    surface_source = "caller_supplied" if tools is not None else "target_advertised"
    surface = list(tools) if tools is not None else list(target.advertise())
    if not surface:
        raise ShadowPathExplorerError("target advertised no tools")
    operations = classify_operations(surface)
    operation_names = {operation.name for operation in operations}
    runtime_manifest = dict(target.manifest())
    resource_model = runtime_manifest.get(
        "resource_model",
        {
            "namespace": "shadowpath.filesystem.target",
            "invocation_namespace": "shadowpath.target.invocation",
            "kinds": ["filesystem.entry"],
            "default_resource_kind": "filesystem.entry",
            "observer_schema": OBSERVER_SCHEMA_VERSION,
            "path_flavor": "posix",
        },
    )
    observation_scope = runtime_manifest.get(
        "observation_scope",
        {
            "observer": "target-provided filesystem snapshot",
            "independent_of_mediation": "target_attested",
            "sampling": "after reset and after each call",
            "settling": "target_defined",
            "completeness": "bounded to the target observer",
        },
    )
    path_flavor = (
        str(cast(Mapping[str, Any], resource_model).get("path_flavor", "posix"))
        if isinstance(resource_model, Mapping)
        else "posix"
    )
    resource_namespace = (
        str(cast(Mapping[str, Any], resource_model).get("namespace", "shadowpath.target"))
        if isinstance(resource_model, Mapping)
        else "shadowpath.target"
    )
    invocation_namespace = (
        str(
            cast(Mapping[str, Any], resource_model).get(
                "invocation_namespace", f"{resource_namespace}.invocation"
            )
        )
        if isinstance(resource_model, Mapping)
        else f"{resource_namespace}.invocation"
    )
    resource_kind = (
        str(
            cast(Mapping[str, Any], resource_model).get("default_resource_kind", "filesystem.entry")
        )
        if isinstance(resource_model, Mapping)
        else "filesystem.entry"
    )
    baseline = _inventory(
        target,
        observation_consecutive=observation_consecutive,
        max_observation_samples=max_observation_samples,
    )
    baseline_fingerprint = _snapshot_fingerprint(baseline)
    scope_source = scope.source if scope is not None else "snapshot_inventory"

    baseline_node = _SearchNode(snapshot=baseline, fingerprint=baseline_fingerprint)
    queue: list[_SearchNode] = [baseline_node]
    known_states: dict[str, _SearchNode] = {baseline_fingerprint: baseline_node}
    state_action_seen: set[tuple[str, str]] = set()
    discovered_paths = set(baseline)
    generated_argument_paths: set[str] = set()
    budget = _Budget(max_trials=max_trials, max_calls=max_calls)
    status_counts: dict[str, int] = {"executed": 0, "blocked": 0, "error": 0}
    attempted_operations: set[str] = set()
    blocked_operations: set[str] = set()
    errored_operations: set[str] = set()
    depth1_executed: set[str] = set()
    depth1_changed: set[str] = set()
    replay_rejections = 0
    unsettled_observations = 0
    candidate_actions_invoked = 0
    candidate_actions_completed = 0
    depth_reached = 0
    planned_route_count = 0
    depth2_attempts = 0
    depth_limited = False
    breaches: list[JsonObject] = []
    candidate_impacts: list[JsonObject] = []
    graph_edges: list[JsonObject] = []
    aggregate_candidate_effects: list[EffectRecord] = []
    aggregate_observed_effects: list[EffectRecord] = []
    operations_with_observed_mutations: set[str] = set()
    path_pool_available = 0
    path_pool_used = 0
    path_pool_max_available = 0
    path_pool_truncated_states = 0
    schema_diagnostics: dict[str, dict[str, Any]] = {
        operation.name: {"issues": set(), "truncated": False, "candidate_sets": 0}
        for operation in operations
    }
    state_action_plans: dict[str, list[_Action]] = {}
    state_action_offsets: dict[str, int] = {}
    redacted_values = {
        state.sample_text: f"[REDACTED observed-content sha256:{state.digest}]"
        for state in baseline.values()
        if state.sample_text is not None and state.digest is not None
    }

    stop = False
    while queue and not stop:
        node_index = min(
            range(len(queue)),
            key=lambda index: (
                state_action_offsets.get(queue[index].fingerprint, 0)
                // max_actions_per_state_visit,
                *_node_priority(queue[index], baseline=baseline, scope=scope),
            ),
        )
        node = queue.pop(node_index)
        if node.depth >= max_depth:
            depth_limited = True
            continue
        if node.fingerprint not in state_action_plans:
            path_pool = _candidate_paths(
                scope=scope,
                baseline_paths=tuple(sorted(baseline)),
                observed=node.snapshot,
                maximum=max_paths_per_state,
                include_windows_separators=path_flavor == "windows",
            )
            paths = path_pool.values
            path_pool_available += path_pool.available
            path_pool_used += len(paths)
            path_pool_max_available = max(path_pool_max_available, path_pool.available)
            if path_pool.truncated:
                path_pool_truncated_states += 1
            generated_argument_paths.update(set(paths) - set(node.snapshot))
            generated_batches: list[list[_Action]] = []
            for operation in operations:
                actions, issues, truncated = _operation_actions(
                    operation=operation,
                    paths=paths,
                    observed=node.snapshot,
                    preferred_path_pairs=path_pool.preferred_pairs,
                    marker=marker,
                    maximum=max_arguments_per_operation_state,
                )
                diagnostics = schema_diagnostics[operation.name]
                cast(set[str], diagnostics["issues"]).update(issues)
                diagnostics["truncated"] = bool(diagnostics["truncated"]) or truncated
                diagnostics["candidate_sets"] = int(diagnostics["candidate_sets"]) + 1
                planned_route_count += len(actions)
                generated_batches.append(actions)
            plan: list[_Action] = []
            maximum_generated = max((len(actions) for actions in generated_batches), default=0)
            for action_index in range(maximum_generated):
                for actions in generated_batches:
                    if action_index < len(actions):
                        plan.append(actions[action_index])
            state_action_plans[node.fingerprint] = plan
            state_action_offsets[node.fingerprint] = 0

        plan = state_action_plans[node.fingerprint]
        start = state_action_offsets[node.fingerprint]
        end = min(len(plan), start + max_actions_per_state_visit)
        visit_actions = plan[start:end]
        state_action_offsets[node.fingerprint] = end
        if end < len(plan):
            queue.append(node)
        # Keep the existing nested dispatch loop; one synthetic batch now
        # represents a fair slice of this state. Requeued peers receive their
        # slice before this state can consume the global trial budget again.
        action_batches: list[tuple[Operation | None, list[_Action]]] = [
            (None, visit_actions)
        ]
        maximum_actions = len(visit_actions)
        # Round-robin keeps a schema with many valid bindings from starving the
        # rest of the advertised surface under a global trial budget.
        for action_index in range(maximum_actions):
            for _operation, actions in action_batches:
                if action_index >= len(actions):
                    continue
                action = actions[action_index]
                state_action = (node.fingerprint, action.fingerprint)
                if state_action in state_action_seen:
                    continue
                state_action_seen.add(state_action)
                candidate_depth = node.depth + 1
                if candidate_depth == 2 and max_depth2_routes is not None:
                    if depth2_attempts >= max_depth2_routes:
                        depth_limited = True
                        continue
                    depth2_attempts += 1
                execution = _execute_transition(
                    target=target,
                    baseline_fingerprint=baseline_fingerprint,
                    node=node,
                    action=action,
                    budget=budget,
                    observation_consecutive=observation_consecutive,
                    max_observation_samples=max_observation_samples,
                )
                if execution is None:
                    stop = True
                    break
                for call, outcome in zip(execution.wire_calls, execution.outcomes, strict=True):
                    name = str(call["name"])
                    attempted_operations.add(name)
                    status_counts[outcome.status] += 1
                    if outcome.status == "blocked":
                        blocked_operations.add(name)
                    elif outcome.status == "error":
                        errored_operations.add(name)
                if execution.candidate_invoked:
                    candidate_actions_invoked += 1
                if execution.replay_rejected:
                    if not execution.observation_settled:
                        unsettled_observations += 1
                    replay_rejections += 1
                    continue
                if execution.after is None or not execution.candidate_invoked:
                    continue
                candidate_actions_completed += 1

                after = execution.after
                redacted_values.update(
                    {
                        state.sample_text: (
                            f"[REDACTED observed-content sha256:{state.digest}]"
                        )
                        for state in after.values()
                        if state.sample_text is not None and state.digest is not None
                    }
                )
                after_fingerprint = _snapshot_fingerprint(after)
                discovered_paths.update(after)
                depth_reached = max(depth_reached, candidate_depth)
                changed_from_node = after_fingerprint != node.fingerprint
                candidate_outcome = execution.outcomes[-1]
                if candidate_depth == 1 and candidate_outcome.status == "executed":
                    depth1_executed.add(action.operation)
                    if changed_from_node:
                        depth1_changed.add(action.operation)

                logical_call: Mapping[str, Any] = {
                    "name": action.operation,
                    "arguments": copy.deepcopy(action.arguments),
                }
                route_calls = (*node.calls, logical_call)
                route_slots = (*node.slots, action.path_slots)
                route_names = [str(call["name"]) for call in route_calls]
                route_id = execution.trial_id
                route = _route_json(
                    route_id=route_id,
                    calls=route_calls,
                    operation_names=route_names,
                    slots=route_slots,
                    redacted_values=redacted_values,
                )
                edge_transitions = diff(node.snapshot, after)
                edge_candidate_effects = _candidate_effects(
                    action,
                    namespace=resource_namespace,
                    invocation_namespace=invocation_namespace,
                    resource_kind=resource_kind,
                )
                edge_observed_effects = _observed_effects(
                    action=action,
                    outcome=candidate_outcome,
                    transitions=edge_transitions,
                    namespace=resource_namespace,
                    invocation_namespace=invocation_namespace,
                    resource_kind=resource_kind,
                )
                aggregate_candidate_effects.extend(edge_candidate_effects)
                aggregate_observed_effects.extend(edge_observed_effects)
                if edge_transitions:
                    operations_with_observed_mutations.add(action.operation)
                graph_edges.append(
                    {
                        "from": node.fingerprint,
                        "to": after_fingerprint,
                        "scope_digest_before": node.fingerprint,
                        "scope_digest_after": after_fingerprint,
                        "route_id": route_id,
                        "operation": action.operation,
                        "outcome": candidate_outcome.status,
                        "transitions": [item.to_json() for item in edge_transitions],
                        "effect_footprint": effect_footprint(
                            candidates=edge_candidate_effects,
                            observed=edge_observed_effects,
                        ),
                    }
                )

                full_transitions = diff(baseline, after)
                route_candidate_effects = merge_effects(
                    node.prefix_candidate_effects, edge_candidate_effects
                )
                route_observed_effects = merge_effects(
                    node.prefix_observed_effects, edge_observed_effects
                )
                final_net_effects = _transition_effect_records(
                    transitions=full_transitions,
                    operation="route.final_net",
                    namespace=resource_namespace,
                    resource_kind=resource_kind,
                    provenance="baseline_to_route_final_observer",
                )
                result_record: JsonObject = {
                    "route": route,
                    "wire_calls": [
                        _route_json(
                            route_id="redaction-only",
                            calls=(call,),
                            operation_names=(),
                            slots=(),
                            redacted_values=redacted_values,
                        )["calls"][0]
                        for call in execution.wire_calls
                    ],
                    "call_outcomes": [item.to_json() for item in execution.outcomes],
                    "effect_footprint": effect_footprint(
                        candidates=route_candidate_effects,
                        observed=route_observed_effects,
                    ),
                    "final_net_effect_footprint": effect_footprint(observed=final_net_effects),
                }
                if scope is None:
                    if full_transitions:
                        candidate_impacts.append(
                            {
                                **result_record,
                                "transitions": [item.to_json() for item in full_transitions],
                                "affected_paths": sorted({item.path for item in full_transitions}),
                            }
                        )
                else:
                    kwargs: JsonObject = {
                        "before": baseline,
                        "after": after,
                        "protected": list(scope.protected),
                        "calls": list(execution.wire_calls),
                        "root": execution.root,
                    }
                    kwargs["breach_statuses"] = statuses
                    adjudication = adjudicate(**kwargs)
                    if bool(adjudication["any_breach"]):
                        breaches.append({**result_record, "adjudication": adjudication})

                if after_fingerprint not in known_states:
                    prefix_fingerprints = (*node.prefix_fingerprints, after_fingerprint)
                    prefix_outcomes = (
                        *node.prefix_outcomes,
                        (candidate_outcome.status, candidate_outcome.block_reason),
                    )
                    child = _SearchNode(
                        snapshot=dict(after),
                        fingerprint=after_fingerprint,
                        calls=route_calls,
                        slots=route_slots,
                        prefix_fingerprints=prefix_fingerprints,
                        prefix_outcomes=prefix_outcomes,
                        prefix_candidate_effects=route_candidate_effects,
                        prefix_observed_effects=route_observed_effects,
                    )
                    known_states[after_fingerprint] = child
                    if candidate_depth < max_depth:
                        queue.append(child)
                    else:
                        depth_limited = True
            if stop:
                break

    invisible = [
        breach
        for breach in breaches
        if int(cast(Mapping[str, Any], breach["adjudication"])["argument_invisible_breach_count"])
        > 0
    ]
    invisible_breach_observations = sum(
        int(cast(Mapping[str, Any], breach["adjudication"])["argument_invisible_breach_count"])
        for breach in breaches
    )
    unattempted = sorted(operation_names - attempted_operations)
    inert_depth1 = sorted(depth1_executed - depth1_changed)
    breached_asset_paths = sorted(
        {
            str(path)
            for breach in breaches
            for path in cast(Mapping[str, Any], breach["adjudication"])["breached_asset_paths"]
        }
    )
    candidate_asset_paths = sorted(
        {
            str(path)
            for impact in candidate_impacts
            for path in cast(Sequence[Any], impact["affected_paths"])
        }
    )
    diagnostics_json = [
        {
            "operation": operation.name,
            "issues": sorted(cast(set[str], schema_diagnostics[operation.name]["issues"])),
            "truncated": bool(schema_diagnostics[operation.name]["truncated"]),
            "candidate_sets": int(schema_diagnostics[operation.name]["candidate_sets"]),
        }
        for operation in operations
    ]
    termination = (
        "budget_exhausted"
        if budget.exhausted
        else "depth_limit_reached"
        if depth_limited
        else "state_space_exhausted"
    )
    graph_nodes = [
        {
            "fingerprint": fingerprint,
            "depth": node.depth,
            "path_count": len(node.snapshot),
        }
        for fingerprint, node in known_states.items()
    ]
    serialized_surface = [copy.deepcopy(dict(tool)) for tool in surface]
    surface_digest = hashlib.sha256(
        json.dumps(serialized_surface, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    schema_generation_truncated = any(bool(item["truncated"]) for item in diagnostics_json)
    schema_generation_has_issues = any(bool(item["issues"]) for item in diagnostics_json)
    generation_truncated = schema_generation_truncated or path_pool_truncated_states > 0
    generation_has_gaps = generation_truncated or schema_generation_has_issues
    aggregate_footprint = effect_footprint(
        candidates=aggregate_candidate_effects,
        observed=aggregate_observed_effects,
    )
    declared_read_only = {
        operation.name for operation in operations if operation.access[0] == "read"
    }
    read_only_violations = sorted(declared_read_only & operations_with_observed_mutations)
    static_coverage = (
        static_policy_coverage(tools=surface, scope=policy_scope)
        if policy_scope is not None
        else None
    )
    policy_family_status = (
        "not_supplied"
        if policy_scope is None
        else "bounded_index_with_gaps"
        if policy_scope.truncated or policy_scope.issues
        else "bounded_index"
    )
    resource_refs = tuple(
        ResourceRef(resource_namespace, resource_kind, path) for path in sorted(discovered_paths)
    )
    relation_provider = getattr(target, "resource_relations", None)
    if callable(relation_provider):
        relations = tuple(relation_provider(resource_refs))
        relation_status = "provider_declared"
    else:
        relations = ()
        relation_status = "unavailable"
    return {
        "schema_version": EXPLORER_SCHEMA_VERSION,
        "session_scope": target.session_scope,
        "runtime_manifest": runtime_manifest,
        "resource_model": resource_model,
        "observation_scope": observation_scope,
        "tool_surface_source": surface_source,
        "tool_surface_sha256": surface_digest,
        "advertised_tool_surface": serialized_surface,
        "scope_source": scope_source,
        "policy_derived_scope": policy_scope.to_json() if policy_scope is not None else None,
        "static_policy_coverage": static_coverage,
        "resource_relations": {
            "status": relation_status,
            "relations": [relation.to_json() for relation in relations],
        },
        "breach_statuses": list(statuses),
        "declared_protected_assets": (
            [asset.to_json() for asset in scope.protected] if scope is not None else []
        ),
        "resource_groups": (
            dict(sorted(scope.resource_groups.items())) if scope is not None else {}
        ),
        "baseline_fingerprint": baseline_fingerprint,
        "baseline_paths": sorted(baseline),
        "discovered_paths": sorted(discovered_paths),
        "generated_argument_paths": sorted(generated_argument_paths),
        "call_status_counts": status_counts,
        "operations_blocked_at_least_once": sorted(blocked_operations),
        "operations_errored_at_least_once": sorted(errored_operations),
        "operations_unattempted": unattempted,
        "advertised_operation_count": len(operations),
        "advertised_operations": [operation.to_json() for operation in operations],
        "schema_generation": diagnostics_json,
        "planned_route_count": planned_route_count,
        "generated_state_action_count": planned_route_count,
        "executed_route_count": candidate_actions_completed,
        "candidate_actions_invoked": candidate_actions_invoked,
        "candidate_actions_completed": candidate_actions_completed,
        "transition_trials_started": budget.trials,
        "depth_reached": depth_reached,
        "attempted_operation_count": len(attempted_operations),
        "attempted_operations": sorted(attempted_operations),
        "operations_inert_at_depth1": inert_depth1,
        "replay_rejections": replay_rejections,
        "unsettled_observation_count": unsettled_observations,
        "declared_read_only_violations": read_only_violations,
        "unattributed_observed_effect_count": len(
            cast(Sequence[Any], aggregate_footprint["observed_effects_not_in_candidates"])
        ),
        "breach_count": len(breaches),
        "breaching_route_count": len(breaches),
        "breach_count_unit": "generated routes with at least one breached asset",
        "breached_asset_paths": breached_asset_paths,
        "argument_invisible_breach_count": invisible_breach_observations,
        "routes_with_argument_invisible_breach": len(invisible),
        "breaches": breaches,
        "candidate_asset_impacts": candidate_impacts,
        "candidate_asset_paths": candidate_asset_paths,
        "state_graph": {"nodes": graph_nodes, "edges": graph_edges},
        "effect_footprint": {
            **aggregate_footprint,
            "resource_model": resource_model,
            "observed_evidence_basis": (
                "dispatch outcomes plus adapter-mapped independent state transitions"
            ),
            "attempted_operations_without_observed_resource_mutations": sorted(
                attempted_operations - operations_with_observed_mutations
            ),
            "candidate_effect_derivation": {
                "status": "bounded_schema_annotation_and_name_heuristic",
                "reason": (
                    "resource arguments come from advertised JSON Schema; one operation-level "
                    "access classification is applied to every bound resource. Access comes "
                    "from MCP annotations when present and otherwise from a name heuristic; "
                    "source and destination roles are not inferred."
                ),
            },
        },
        "coverage": {
            "max_depth": max_depth,
            "max_depth2_routes": max_depth2_routes,
            "max_trials": max_trials,
            "max_calls": max_calls,
            "max_paths_per_state": max_paths_per_state,
            "max_arguments_per_operation_state": max_arguments_per_operation_state,
            "max_actions_per_state_visit": max_actions_per_state_visit,
            "effective_max_arguments_per_operation_state": max_arguments_per_operation_state,
            "trials_used": budget.trials,
            "trial_budget_scope": (
                "transition trials started, including prefixes rejected before "
                "candidate invocation; tool advertisement and baseline inventory excluded"
            ),
            "calls_used": budget.calls,
            "call_budget_scope": "generated tool calls, including replayed prefix calls",
            "states_observed": len(known_states),
            "state_action_pairs_considered": len(state_action_seen),
            "state_action_pairs_scheduled": budget.trials,
            "state_action_pairs_attempted": candidate_actions_invoked,
            "candidate_actions_completed": candidate_actions_completed,
            "observation_consecutive": observation_consecutive,
            "max_observation_samples": max_observation_samples,
            "path_candidates_available_across_states": path_pool_available,
            "path_candidates_used_across_states": path_pool_used,
            "path_pool_max_available": path_pool_max_available,
            "path_pool_truncated": path_pool_truncated_states > 0,
            "path_pool_truncated_states": path_pool_truncated_states,
            "budget_exhausted": bool(budget.exhausted),
            "budget_exhaustion_reasons": sorted(budget.exhausted),
            "schema_generation_truncated": schema_generation_truncated,
            "schema_generation_has_issues": schema_generation_has_issues,
            "argument_generation_truncated": generation_truncated,
            "argument_generation_has_gaps": generation_has_gaps,
        },
        "termination_reason": termination,
        "scope_assessment": {
            "status": "incomplete_product_scope",
            "dimensions": {
                "advertised_tool_surface": "observed_for_this_runtime",
                "argument_space": (
                    "bounded_sample_with_gaps" if generation_has_gaps else "bounded_sample"
                ),
                "observable_state_space": termination,
                "effective_configuration": "one_runtime_configuration",
                "policy_families": policy_family_status,
                "platforms": "one_runtime_platform",
                "resource_domains": "target_manifest_only",
                "candidate_effect_semantics": (
                    "bounded_schema_annotation_and_name_heuristic"
                ),
                "observed_effect_semantics": "adapter_mapped_independent_state_differences",
                "hidden_or_delayed_state": "unknown",
            },
        },
        "claim_boundary": (
            "Routes were generated from advertised schemas, paths present in observed "
            "disposable state, and generated scratch siblings inside that state. Search used "
            "bounded fair slices across distinct snapshots. Prefixes "
            "were replayed before extension and unstable replays received no breach credit. "
            "Settling means repeated immediate observer digests; it does not establish that "
            "a provider with delayed effects has reached quiescence. "
            "Operator-declared assets were adjudicated by state difference; automatically "
            "inventoried changes are candidate impacts, not policy violations. Coverage is "
            "bounded by the logical argument schemas before target path mapping, observable "
            "state, generation truncation, depth, trial and call budgets. Hidden state, target "
            "mapping constraints, and ungenerated valid arguments remain outside the claim."
        ),
    }
