"""Production filesystem substrate for the provider-neutral resource explorer.

The Pipelock target remains responsible for process isolation, MCP mediation,
and direct filesystem observation.  These wrappers translate that concrete
boundary into the same ResourceSnapshot/CandidateAction contract used by
container, runtime, service, database, and delegated-tool providers.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from velvet.shadowpath_effects import EffectRecord, ResourceRef
from velvet.shadowpath_explorer import (
    ExplorationScope,
    Operation,
    _candidate_paths,
    _operation_actions,
    classify_operations,
)
from velvet.shadowpath_observer import AssetState
from velvet.shadowpath_pipelock_target import PipelockFilesystemTarget
from velvet.shadowpath_resource_explorer import (
    ArgumentBinding,
    CandidateAction,
    InvocationOutcome,
    ResourceExplorerError,
    ResourceObservation,
    ResourceSnapshot,
)
from velvet.shadowpath_schema import Address
from velvet.shadowpath_scope import ResourceRelation

JsonObject = dict[str, Any]


@dataclass
class PipelockResourceTarget:
    """Adapt the live Pipelock target to the generic invocation contract."""

    target: PipelockFilesystemTarget

    @property
    def session_scope(self) -> str:
        return self.target.session_scope

    def manifest(self) -> Mapping[str, Any]:
        return {
            **dict(self.target.manifest()),
            "resource_explorer_adapter": "velvet.pipelock-filesystem.v1",
        }

    def reset(self, trial_id: str) -> None:
        self.target.reset(trial_id)

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> InvocationOutcome:
        outcome = self.target.invoke(trial_id, call)
        return InvocationOutcome(
            outcome.status,
            outcome.block_reason,
            details=outcome.raw,
        )

    def teardown(self, trial_id: str) -> None:
        self.target.teardown(trial_id)

    def observe_raw(self, trial_id: str) -> dict[str, AssetState]:
        return self.target.observe(trial_id)

    def resolve(self, trial_id: str, key: str) -> str:
        return self.target.resolve(trial_id, key)

    def resource_relations(
        self, resources: Sequence[ResourceRef]
    ) -> Sequence[ResourceRelation]:
        return self.target.resource_relations(resources)


@dataclass
class PipelockFilesystemModel:
    """Generate resource actions and effects from the live filesystem surface."""

    tools: Sequence[Mapping[str, Any]]
    scope: ExplorationScope | None = None
    max_paths_per_state: int = 64
    max_arguments_per_operation_state: int = 32
    marker: str = "# shadowpath resource explorer payload\n"
    namespace: str = "pipelock.filesystem.workspace"
    resource_kind: str = "filesystem.entry"
    invocation_namespace: str = "pipelock.mcp.proxy"
    operations: tuple[Operation, ...] = field(init=False)
    _raw_by_fingerprint: dict[str, dict[str, AssetState]] = field(
        init=False, default_factory=dict, repr=False
    )

    def __post_init__(self) -> None:
        self.operations = tuple(classify_operations(self.tools))

    def manifest(self) -> Mapping[str, Any]:
        return {
            "model": "velvet.pipelock-filesystem-resource-model.v1",
            "namespace": self.namespace,
            "resource_kind": self.resource_kind,
            "observation": "direct recursive snapshot outside mediation",
            "argument_generation": "advertised JSON Schema plus observed resource values",
            "relations": "provider-declared filesystem containment",
            "operation_count": len(self.operations),
        }

    @staticmethod
    def _target(target: Any) -> PipelockResourceTarget:
        if not isinstance(target, PipelockResourceTarget):
            raise ResourceExplorerError("PipelockFilesystemModel needs PipelockResourceTarget")
        return target

    def observe(self, target: Any, trial_id: str) -> ResourceSnapshot:
        adapter = self._target(target)
        raw = adapter.observe_raw(trial_id)
        snapshot = ResourceSnapshot(
            tuple(
                ResourceObservation(
                    ResourceRef(self.namespace, self.resource_kind, path),
                    state.to_json(),
                    "pipelock direct filesystem observer",
                )
                for path, state in raw.items()
            )
        )
        self._raw_by_fingerprint[snapshot.fingerprint] = raw
        return snapshot

    def actions(
        self, *, baseline: ResourceSnapshot, current: ResourceSnapshot
    ) -> Sequence[CandidateAction]:
        raw = self._raw_by_fingerprint.get(current.fingerprint)
        if raw is None:
            raise ResourceExplorerError("raw filesystem observation is unavailable for state")
        baseline_paths = [item.resource.key for item in baseline.observations]
        pool = _candidate_paths(
            scope=self.scope,
            baseline_paths=baseline_paths,
            observed=raw,
            maximum=self.max_paths_per_state,
            include_windows_separators=False,
        )
        observed_keys = {item.resource.key for item in current.observations}
        actions: list[CandidateAction] = []
        for operation in self.operations:
            generated, _, _ = _operation_actions(
                operation=operation,
                paths=pool.values,
                observed=raw,
                preferred_path_pairs=pool.preferred_pairs,
                marker=self.marker,
                maximum=self.max_arguments_per_operation_state,
            )
            for action in generated:
                bindings: list[ArgumentBinding] = []
                effects: list[EffectRecord] = [
                    EffectRecord(
                        "delegated_tool.call",
                        ResourceRef(
                            self.invocation_namespace,
                            "delegated_tool.operation",
                            action.operation,
                        ),
                        "candidate",
                        "generated resource action",
                        operation=action.operation,
                    )
                ]
                for address in action.path_slots:
                    value = _value_at(action.arguments, address)
                    if not isinstance(value, str):
                        continue
                    resource = ResourceRef(self.namespace, self.resource_kind, value)
                    bindings.append(
                        ArgumentBinding(
                            address,
                            "resource",
                            "observed" if value in observed_keys else "generated",
                            resource,
                        )
                    )
                    access, basis = operation.access
                    effects.append(
                        EffectRecord(
                            f"resource.{access}" if access != "unknown" else "effect.unknown",
                            resource,
                            "adapter_declared"
                            if basis.startswith("mcp.annotation")
                            else "candidate",
                            f"schema binding; {basis}",
                            operation=operation.name,
                            details={"address": list(address), "access": access},
                        )
                    )
                actions.append(
                    CandidateAction(
                        action.operation,
                        action.arguments,
                        tuple(bindings),
                        tuple(effects),
                    )
                )
        return actions

    def materialize(
        self, target: Any, trial_id: str, action: CandidateAction
    ) -> Mapping[str, Any]:
        adapter = self._target(target)
        arguments = copy.deepcopy(action.arguments_json())
        for binding in action.bindings:
            value = _value_at(arguments, binding.address)
            if isinstance(value, str):
                _set_value(arguments, binding.address, adapter.resolve(trial_id, value))
        return {"name": action.operation, "arguments": arguments}

    def observed_effects(
        self,
        *,
        before: ResourceSnapshot,
        after: ResourceSnapshot,
        action: CandidateAction,
        outcome: InvocationOutcome,
    ) -> Sequence[EffectRecord]:
        before_by_id = {item.resource.resource_id: item for item in before.observations}
        after_by_id = {item.resource.resource_id: item for item in after.observations}
        effects: list[EffectRecord] = [
            EffectRecord(
                "delegated_tool.call",
                ResourceRef(
                    self.invocation_namespace,
                    "delegated_tool.operation",
                    action.operation,
                ),
                "observed",
                "Pipelock MCP dispatch outcome",
                operation=action.operation,
                details={"status": outcome.status, "block_reason": outcome.block_reason},
            )
        ]
        for resource_id in sorted(before_by_id.keys() | after_by_id.keys()):
            old = before_by_id.get(resource_id)
            new = after_by_id.get(resource_id)
            if old is not None and new is not None and old.state_sha256 == new.state_sha256:
                continue
            resource = new.resource if new is not None else cast(ResourceObservation, old).resource
            effect = (
                "resource.create"
                if old is None
                else "resource.delete"
                if new is None
                else "resource.change"
            )
            effects.append(
                EffectRecord(
                    effect,
                    resource,
                    "observed",
                    "independent filesystem snapshot difference",
                    operation=action.operation,
                )
            )
        return effects


def _value_at(value: Any, address: Address) -> Any:
    cursor = value
    for component in address:
        cursor = cursor[component]
    return cursor


def _set_value(value: Any, address: Address, replacement: str) -> None:
    cursor = value
    for component in address[:-1]:
        cursor = cursor[component]
    cursor[address[-1]] = replacement
