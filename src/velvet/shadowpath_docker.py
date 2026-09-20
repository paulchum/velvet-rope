"""Live Docker container-lifecycle adapter for ShadowPath resource discovery.

The adapter owns only containers carrying its per-run labels.  Every search
trial starts from a newly-created container backed by a locally available,
digest-resolved image.  Lifecycle calls go through the Docker CLI while state
is read back through ``docker container inspect`` and normalized to stable
logical resource identities.

This is deliberately a bounded Docker surface.  It measures container
lifecycle equivalence; it does not claim coverage of images, volumes, networks,
Compose, Swarm, Kubernetes, Docker MCP Gateway policy, or authorization
plugins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - the adapter invokes a pinned Docker CLI without a shell
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from velvet.shadowpath_effects import EffectRecord, ResourceRef
from velvet.shadowpath_resource_explorer import (
    ArgumentBinding,
    CandidateAction,
    InvocationOutcome,
    ResourceExplorerError,
    ResourceObservation,
    ResourceSnapshot,
    explore_resources,
)
from velvet.shadowpath_scope import ResourceRelation

JsonObject = dict[str, Any]

DOCKER_ADAPTER_SCHEMA_VERSION = "velvet.shadowpath.docker-adapter.v0.1"
DOCKER_ANALYSIS_SCHEMA_VERSION = "velvet.shadowpath.docker-analysis.v0.1"

_MANAGED_LABEL = "io.velvet.shadowpath.managed"
_RUN_LABEL = "io.velvet.shadowpath.run"
_TRIAL_LABEL = "io.velvet.shadowpath.trial"
_RESOURCE_LABEL = "io.velvet.shadowpath.resource"
_TARGET_LABEL = "io.velvet.shadowpath.target"
_PROTECTED_KEY = "protected"
_TARGET_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_BLOCK_PATTERNS = (
    "authorization denied",
    "access denied",
    "permission denied",
    "not authorized",
)


class DockerAdapterError(RuntimeError):
    """Raised when Docker cannot provide an isolated, observable trial."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_fragment(value: str, *, maximum: int = 42) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-._")
    return (normalized or "trial")[:maximum]


def _json_object(text: str, *, label: str) -> JsonObject:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as error:
        raise DockerAdapterError(f"{label} returned invalid JSON") from error
    if not isinstance(loaded, Mapping):
        raise DockerAdapterError(f"{label} must return a JSON object")
    return dict(loaded)


def _json_array(text: str, *, label: str) -> list[JsonObject]:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as error:
        raise DockerAdapterError(f"{label} returned invalid JSON") from error
    if not isinstance(loaded, list) or not all(isinstance(item, Mapping) for item in loaded):
        raise DockerAdapterError(f"{label} must return a JSON object array")
    return [dict(item) for item in loaded]


@dataclass
class DockerContainerTarget:
    """A disposable Docker Engine target constrained by ownership labels."""

    docker: str | Path = "docker"
    image: str = "alpine:3.24"
    target_id: str = "local-engine"
    timeout_seconds: float = 20.0
    settle_timeout_seconds: float = 3.0
    settle_interval_seconds: float = 0.05
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    session_scope: str = field(init=False, default="per_route")
    docker_path: Path = field(init=False)
    image_id: str = field(init=False)
    _manifest: JsonObject = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not _TARGET_TOKEN.fullmatch(self.target_id):
            raise DockerAdapterError(
                "target_id must start with an alphanumeric and contain only letters, "
                "digits, dots, underscores, or hyphens"
            )
        if not self.run_id or not _TARGET_TOKEN.fullmatch(self.run_id):
            raise DockerAdapterError("run_id must be a non-empty Docker label token")
        if self.timeout_seconds <= 0 or self.settle_timeout_seconds <= 0:
            raise DockerAdapterError("Docker timeouts must be positive")
        if self.settle_interval_seconds < 0:
            raise DockerAdapterError("settle interval cannot be negative")

        supplied = os.fspath(self.docker)
        resolved = shutil.which(supplied) if Path(supplied).name == supplied else supplied
        if resolved is None:
            raise DockerAdapterError(f"Docker CLI is unavailable: {supplied}")
        self.docker_path = Path(resolved).expanduser().resolve()
        if not self.docker_path.is_file():
            raise DockerAdapterError(f"Docker CLI is not a file: {self.docker_path}")

        version = _json_object(
            self._run(("version", "--format", "{{json .}}"), check=True).stdout,
            label="docker version",
        )
        context = self._run(("context", "show"), check=True).stdout.strip()
        images = _json_array(
            self._run(("image", "inspect", self.image), check=True).stdout,
            label="docker image inspect",
        )
        if len(images) != 1:
            raise DockerAdapterError("Docker image reference must resolve to exactly one image")
        image = images[0]
        image_id = image.get("Id")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise DockerAdapterError("Docker image inspect did not return a content ID")
        self.image_id = image_id
        platform = {
            "os": image.get("Os"),
            "architecture": image.get("Architecture"),
            "variant": image.get("Variant"),
        }
        self._manifest = {
            "schema_version": DOCKER_ADAPTER_SCHEMA_VERSION,
            "target": "docker-container-lifecycle",
            "target_id": self.target_id,
            "run_id": self.run_id,
            "session_scope": self.session_scope,
            "docker_cli": {
                "path": self.docker_path.as_posix(),
                "sha256": _sha256_file(self.docker_path),
            },
            "docker_context": context,
            "docker_version": version,
            "image": {
                "requested": self.image,
                "id": self.image_id,
                "repo_digests": image.get("RepoDigests", []),
                "platform": platform,
            },
            "isolation": {
                "ownership": "per-run and per-trial Docker labels",
                "baseline": "new container for every trial",
                "network": "none",
                "restart_policy": "no",
            },
            "observation": {
                "source": "docker container inspect outside lifecycle dispatch",
                "settling": "two consecutive normalized snapshots must agree",
                "timeout_seconds": self.settle_timeout_seconds,
                "interval_seconds": self.settle_interval_seconds,
            },
            "scope": {
                "resource_kinds": ["docker.container"],
                "facets": ["lifecycle"],
                "excluded": [
                    "images",
                    "volumes",
                    "networks",
                    "compose",
                    "swarm",
                    "kubernetes",
                    "mcp_gateway_policy",
                    "authorization_plugins",
                ],
            },
        }

    @property
    def namespace(self) -> str:
        return f"docker.engine.{self.target_id}"

    @property
    def invocation_namespace(self) -> str:
        return f"docker.engine.{self.target_id}.operations"

    def _run(
        self,
        arguments: Sequence[str],
        *,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603 - pinned argv, no shell
                [self.docker_path.as_posix(), *arguments],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DockerAdapterError(f"Docker command failed to run: {arguments[0]}") from error
        if check and result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "unknown Docker error"
            raise DockerAdapterError(f"Docker {arguments[0]} failed: {message[:1000]}")
        return result

    def manifest(self) -> Mapping[str, Any]:
        return self._manifest

    def _labels(self, trial_id: str) -> dict[str, str]:
        return {
            _MANAGED_LABEL: "true",
            _RUN_LABEL: self.run_id,
            _TRIAL_LABEL: trial_id,
            _RESOURCE_LABEL: _PROTECTED_KEY,
            _TARGET_LABEL: self.target_id,
        }

    def _container_name(self, trial_id: str) -> str:
        return (
            f"velvet-shadowpath-{_safe_fragment(self.target_id, maximum=18)}-"
            f"{self.run_id[:8]}-{_safe_fragment(trial_id)}"
        )[:120]

    def _container_ids(self, trial_id: str | None = None) -> list[str]:
        filters = (
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label={_MANAGED_LABEL}=true",
            "--filter",
            f"label={_RUN_LABEL}={self.run_id}",
        )
        arguments = list(filters)
        if trial_id is not None:
            arguments.extend(("--filter", f"label={_TRIAL_LABEL}={trial_id}"))
        result = self._run(tuple(arguments), check=True)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _remove(self, trial_id: str | None = None) -> None:
        identifiers = self._container_ids(trial_id)
        if not identifiers:
            return
        result = self._run(("container", "rm", "--force", *identifiers), check=False)
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise DockerAdapterError(f"could not remove disposable containers: {message[:1000]}")

    def _create(self, trial_id: str) -> None:
        arguments: list[str] = [
            "run",
            "--detach",
            "--name",
            self._container_name(trial_id),
            "--network",
            "none",
            "--restart",
            "no",
        ]
        for key, value in self._labels(trial_id).items():
            arguments.extend(("--label", f"{key}={value}"))
        arguments.extend(
            (
                self.image_id,
                "sh",
                "-c",
                "trap 'exit 0' TERM INT; while :; do sleep 1 & wait $!; done",
            )
        )
        self._run(tuple(arguments), check=True)

    def reset(self, trial_id: str) -> None:
        self._remove(trial_id)
        self._create(trial_id)
        observed = self.observe_raw(trial_id)
        state = observed.get(_PROTECTED_KEY)
        if state is None or state.get("running") is not True:
            raise DockerAdapterError("Docker trial baseline did not reach running state")

    def _inspect_once(self, trial_id: str) -> dict[str, JsonObject]:
        identifiers = self._container_ids(trial_id)
        if not identifiers:
            return {}
        inspected = _json_array(
            self._run(("container", "inspect", *identifiers), check=True).stdout,
            label="docker container inspect",
        )
        expected = self._labels(trial_id)
        observed: dict[str, JsonObject] = {}
        for item in inspected:
            config = item.get("Config")
            state = item.get("State")
            host_config = item.get("HostConfig")
            if not isinstance(config, Mapping) or not isinstance(state, Mapping):
                raise DockerAdapterError("Docker inspect omitted container configuration or state")
            labels = config.get("Labels")
            if not isinstance(labels, Mapping) or any(
                labels.get(key) != value for key, value in expected.items()
            ):
                raise DockerAdapterError("Docker observer encountered a container it does not own")
            key = labels.get(_RESOURCE_LABEL)
            if not isinstance(key, str) or not key:
                raise DockerAdapterError("Docker container is missing its logical resource key")
            if key in observed:
                raise DockerAdapterError(f"duplicate Docker logical resource key: {key}")
            restart_policy: Any = None
            if isinstance(host_config, Mapping):
                restart = host_config.get("RestartPolicy")
                if isinstance(restart, Mapping):
                    restart_policy = restart.get("Name")
            observed[key] = {
                "status": state.get("Status"),
                "running": state.get("Running"),
                "paused": state.get("Paused"),
                "restarting": state.get("Restarting"),
                "oom_killed": state.get("OOMKilled"),
                "dead": state.get("Dead"),
                "exit_code": state.get("ExitCode"),
                "image_id": item.get("Image"),
                "restart_policy": restart_policy,
            }
        return observed

    def observe_raw(self, trial_id: str) -> dict[str, JsonObject]:
        deadline = time.monotonic() + self.settle_timeout_seconds
        previous: dict[str, JsonObject] | None = None
        while True:
            current = self._inspect_once(trial_id)
            if previous == current:
                return current
            if time.monotonic() >= deadline:
                raise DockerAdapterError(
                    "Docker state did not settle before the observation deadline"
                )
            previous = current
            if self.settle_interval_seconds:
                time.sleep(self.settle_interval_seconds)

    def _owned_name(self, trial_id: str, key: str) -> str | None:
        observed = self._inspect_once(trial_id)
        if key not in observed:
            return None
        identifiers = self._container_ids(trial_id)
        if len(identifiers) != 1:
            raise DockerAdapterError("expected exactly one owned Docker container")
        return identifiers[0]

    def invoke(self, trial_id: str, call: Mapping[str, Any]) -> InvocationOutcome:
        operation = call.get("name")
        arguments = call.get("arguments")
        if not isinstance(operation, str) or not isinstance(arguments, Mapping):
            return InvocationOutcome("error", details={"reason": "malformed logical call"})
        key = arguments.get("container")
        if key != _PROTECTED_KEY:
            return InvocationOutcome("error", details={"reason": "unknown container selector"})

        if operation == "docker.container.create":
            if self._owned_name(trial_id, key) is not None:
                return InvocationOutcome("error", details={"reason": "container already exists"})
            try:
                self._create(trial_id)
            except DockerAdapterError as error:
                return InvocationOutcome("error", details={"reason": str(error)})
            return InvocationOutcome("executed", details={"operation": operation})

        identifier = self._owned_name(trial_id, key)
        if identifier is None:
            return InvocationOutcome("error", details={"reason": "container does not exist"})
        commands: dict[str, tuple[str, ...]] = {
            "docker.container.stop": ("container", "stop", "--time", "1", identifier),
            "docker.container.kill": (
                "container",
                "kill",
                "--signal",
                "KILL",
                identifier,
            ),
            "docker.container.pause": ("container", "pause", identifier),
            "docker.container.unpause": ("container", "unpause", identifier),
            "docker.container.start": ("container", "start", identifier),
            "docker.container.remove": ("container", "rm", "--force", identifier),
        }
        command = commands.get(operation)
        if command is None:
            return InvocationOutcome("error", details={"reason": "unsupported Docker operation"})
        result = self._run(command, check=False)
        if result.returncode == 0:
            return InvocationOutcome(
                "executed",
                details={"operation": operation, "returncode": result.returncode},
            )
        message = (result.stderr.strip() or result.stdout.strip())[:2000]
        details = {
            "operation": operation,
            "returncode": result.returncode,
            "message": message,
        }
        if any(token in message.lower() for token in _BLOCK_PATTERNS):
            return InvocationOutcome("blocked", block_reason=message, details=details)
        return InvocationOutcome("error", details=details)

    def teardown(self, trial_id: str) -> None:
        self._remove(trial_id)

    def close(self) -> None:
        self._remove()

    def resource_relations(
        self, resources: Sequence[ResourceRef]
    ) -> Sequence[ResourceRelation]:
        del resources
        return ()


@dataclass
class DockerContainerModel:
    """Generate lifecycle actions and map Docker state changes to effects."""

    namespace: str
    invocation_namespace: str

    def manifest(self) -> Mapping[str, Any]:
        return {
            "schema_version": DOCKER_ADAPTER_SCHEMA_VERSION,
            "model": "velvet.docker-container-resource-model.v1",
            "namespace": self.namespace,
            "resource_kind": "docker.container",
            "facet": "lifecycle",
            "observation": "normalized Docker Engine container inspection",
            "action_generation": "container lifecycle state machine",
            "relations": "none for the bounded single-container lifecycle surface",
            "supported_operations": [
                "docker.container.create",
                "docker.container.stop",
                "docker.container.kill",
                "docker.container.pause",
                "docker.container.unpause",
                "docker.container.start",
                "docker.container.remove",
            ],
        }

    @staticmethod
    def _target(target: Any) -> DockerContainerTarget:
        if not isinstance(target, DockerContainerTarget):
            raise ResourceExplorerError("DockerContainerModel needs DockerContainerTarget")
        return target

    def _resource(self) -> ResourceRef:
        return ResourceRef(self.namespace, "docker.container", _PROTECTED_KEY, "lifecycle")

    def observe(self, target: Any, trial_id: str) -> ResourceSnapshot:
        adapter = self._target(target)
        raw = adapter.observe_raw(trial_id)
        return ResourceSnapshot(
            tuple(
                ResourceObservation(
                    ResourceRef(self.namespace, "docker.container", key, "lifecycle"),
                    state,
                    "Docker Engine container inspect",
                )
                for key, state in raw.items()
            )
        )

    def _action(self, operation: str, effect: str, resource: ResourceRef) -> CandidateAction:
        invocation = ResourceRef(
            self.invocation_namespace,
            "delegated_tool.operation",
            operation,
        )
        return CandidateAction(
            operation=operation,
            arguments={"container": resource.key},
            bindings=(
                ArgumentBinding(
                    address=("container",),
                    role="resource_selector",
                    origin="observed",
                    resource=resource,
                ),
            ),
            candidate_effects=(
                EffectRecord(
                    "delegated_tool.call",
                    invocation,
                    "candidate",
                    "Docker lifecycle adapter operation inventory",
                    operation=operation,
                ),
                EffectRecord(
                    effect,
                    resource,
                    "adapter_declared",
                    "Docker lifecycle state-machine contract",
                    operation=operation,
                ),
            ),
        )

    def actions(
        self, *, baseline: ResourceSnapshot, current: ResourceSnapshot
    ) -> Sequence[CandidateAction]:
        baseline_resource = next(
            (
                item.resource
                for item in baseline.observations
                if item.resource.key == _PROTECTED_KEY
            ),
            self._resource(),
        )
        observed = next(
            (
                item
                for item in current.observations
                if item.resource.key == _PROTECTED_KEY
            ),
            None,
        )
        if observed is None:
            action = self._action("docker.container.create", "container.create", baseline_resource)
            binding = ArgumentBinding(
                address=("container",),
                role="resource_selector",
                origin="declared",
                resource=baseline_resource,
            )
            return (
                CandidateAction(
                    action.operation,
                    action.arguments_json(),
                    (binding,),
                    action.candidate_effects,
                ),
            )

        state = observed.state_json()
        running = state.get("running") is True
        paused = state.get("paused") is True
        actions: list[CandidateAction] = []
        if running and not paused:
            actions.extend(
                (
                    self._action("docker.container.stop", "container.stop", observed.resource),
                    self._action("docker.container.kill", "container.stop", observed.resource),
                    self._action("docker.container.pause", "container.pause", observed.resource),
                )
            )
        elif running and paused:
            actions.extend(
                (
                    self._action(
                        "docker.container.unpause", "container.unpause", observed.resource
                    ),
                    self._action("docker.container.kill", "container.stop", observed.resource),
                )
            )
        else:
            actions.append(
                self._action("docker.container.start", "container.start", observed.resource)
            )
        actions.append(
            self._action("docker.container.remove", "container.remove", observed.resource)
        )
        return tuple(actions)

    def materialize(
        self, target: Any, trial_id: str, action: CandidateAction
    ) -> Mapping[str, Any]:
        self._target(target)
        if not trial_id:
            raise ResourceExplorerError("Docker trial id cannot be empty")
        return action.logical_call()

    def observed_effects(
        self,
        *,
        before: ResourceSnapshot,
        after: ResourceSnapshot,
        action: CandidateAction,
        outcome: InvocationOutcome,
    ) -> Sequence[EffectRecord]:
        effects: list[EffectRecord] = [
            EffectRecord(
                "delegated_tool.call",
                ResourceRef(
                    self.invocation_namespace,
                    "delegated_tool.operation",
                    action.operation,
                ),
                "observed",
                "Docker CLI dispatch outcome",
                operation=action.operation,
                details={"status": outcome.status, "block_reason": outcome.block_reason},
            )
        ]
        old_by_id = {item.resource.resource_id: item for item in before.observations}
        new_by_id = {item.resource.resource_id: item for item in after.observations}
        for resource_id in sorted(old_by_id.keys() | new_by_id.keys()):
            old = old_by_id.get(resource_id)
            new = new_by_id.get(resource_id)
            if old is not None and new is not None and old.state_sha256 == new.state_sha256:
                continue
            resource = new.resource if new is not None else cast(ResourceObservation, old).resource
            old_state = old.state_json() if old is not None else None
            new_state = new.state_json() if new is not None else None
            effect = _container_effect(old_state, new_state)
            effects.append(
                EffectRecord(
                    effect,
                    resource,
                    "observed",
                    "independent Docker Engine inspection difference",
                    operation=action.operation,
                    details={
                        "before_state_sha256": old.state_sha256 if old is not None else None,
                        "after_state_sha256": new.state_sha256 if new is not None else None,
                    },
                )
            )
        return tuple(effects)


def _container_effect(before: JsonObject | None, after: JsonObject | None) -> str:
    if before is None:
        return "container.create"
    if after is None:
        return "container.remove"
    if before.get("running") is True and after.get("running") is not True:
        return "container.stop"
    if before.get("running") is not True and after.get("running") is True:
        return "container.start"
    if before.get("paused") is not True and after.get("paused") is True:
        return "container.pause"
    if before.get("paused") is True and after.get("paused") is not True:
        return "container.unpause"
    return "container.state.change"


def analyze_docker_routes(report: Mapping[str, Any]) -> JsonObject:
    """Group distinct observed routes that reached the same Docker effect."""

    graph = report.get("state_graph")
    edges = graph.get("edges") if isinstance(graph, Mapping) else None
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, Mapping):
                continue
            route = edge.get("route")
            operations = route.get("operations") if isinstance(route, Mapping) else None
            footprint = edge.get("effect_footprint")
            effects = footprint.get("observed_effects") if isinstance(footprint, Mapping) else None
            if not isinstance(operations, list) or not isinstance(effects, list):
                continue
            route_operations = [str(item) for item in operations]
            for effect in effects:
                if not isinstance(effect, Mapping) or effect.get("effect") == "delegated_tool.call":
                    continue
                resource = effect.get("resource")
                if not isinstance(resource, Mapping):
                    continue
                resource_id = resource.get("resource_id")
                effect_name = effect.get("effect")
                if not isinstance(effect_name, str) or not isinstance(resource_id, str):
                    continue
                entry = grouped.setdefault(
                    (effect_name, resource_id),
                    {
                        "effect": effect_name,
                        "resource": dict(resource),
                        "routes": [],
                    },
                )
                if route_operations not in entry["routes"]:
                    entry["routes"].append(route_operations)
    classes = []
    for entry in grouped.values():
        entry["routes"].sort(key=lambda route: (len(route), route))
        entry["route_count"] = len(entry["routes"])
        if entry["route_count"] > 1:
            classes.append(entry)
    classes.sort(key=lambda item: (str(item["effect"]), str(item["resource"]["resource_id"])))
    return {
        "schema_version": DOCKER_ANALYSIS_SCHEMA_VERSION,
        "equivalent_effect_route_classes": classes,
        "equivalent_effect_route_class_count": len(classes),
        "claim_boundary": (
            "Equivalent routes show that distinct Docker lifecycle operations reached the same "
            "observed effect on disposable, run-labeled containers. This run did not place a "
            "Docker authorization or MCP policy boundary in front of those operations, so it "
            "does not establish a policy bypass or Docker vulnerability."
        ),
    }


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover equivalent Docker container-lifecycle routes on disposable resources."
    )
    parser.add_argument("--docker", default="docker", help="Docker CLI path or executable name")
    parser.add_argument(
        "--image",
        default="alpine:3.24",
        help="Locally available baseline image; resolved to its content ID before execution",
    )
    parser.add_argument("--target-id", default="local-engine")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-depth", type=_positive_int, default=2)
    parser.add_argument("--max-trials", type=_positive_int, default=50)
    parser.add_argument("--max-calls", type=_positive_int, default=200)
    parser.add_argument("--max-states", type=_positive_int, default=30)
    parser.add_argument("--max-actions-per-state", type=_positive_int, default=16)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--settle-timeout-seconds", type=float, default=3.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    target: DockerContainerTarget | None = None
    output = args.output.expanduser().resolve()
    try:
        target = DockerContainerTarget(
            docker=args.docker,
            image=args.image,
            target_id=args.target_id,
            timeout_seconds=args.timeout_seconds,
            settle_timeout_seconds=args.settle_timeout_seconds,
        )
        model = DockerContainerModel(target.namespace, target.invocation_namespace)
        report = explore_resources(
            target=target,
            model=model,
            max_depth=args.max_depth,
            max_trials=args.max_trials,
            max_calls=args.max_calls,
            max_states=args.max_states,
            max_actions_per_state=args.max_actions_per_state,
        )
        report["docker_analysis"] = analyze_docker_routes(report)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=output.parent, delete=False
            ) as handle:
                temporary = handle.name
                json.dump(report, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)
    except (DockerAdapterError, ResourceExplorerError, OSError, ValueError) as error:
        raise SystemExit(f"Docker discovery failed: {error}") from error
    finally:
        if target is not None:
            target.close()
    analysis = cast(Mapping[str, Any], report["docker_analysis"])
    print(f"Docker discovery report written to {output}")
    print(
        "Equivalent effect route classes: "
        f"{analysis['equivalent_effect_route_class_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
