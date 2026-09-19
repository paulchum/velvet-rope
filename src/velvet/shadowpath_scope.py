"""Provider-neutral resource relations and policy-derived exploration scope.

ShadowPath's core does not decide that slash-delimited keys are trees.  A
provider canonicalizes its own keys and supplies typed relation edges.  This
keeps filesystem containment, Kubernetes ownership, volume mounts, service
delegation, and aliases distinct while still allowing the search planner to
ask whether an operation on one resource can affect another.

Policy scope is compiled into concrete, regex-validated witnesses.  Witnesses
are samples, not a proof that a regular language was exhausted; unsupported or
truncated constructs remain visible in the result.
"""

from __future__ import annotations

import itertools
import ntpath
import os
import posixpath
import re
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any, Literal, cast

import yaml

from velvet.shadowpath_effects import ResourceRef

JsonObject = dict[str, Any]

RESOURCE_SCOPE_SCHEMA_VERSION = "velvet.shadowpath.resource-scope.v0.1"

RelationKind = Literal["contains", "owns", "mounts", "delegates", "aliases"]
RELATION_KINDS: frozenset[str] = frozenset(
    {"contains", "owns", "mounts", "delegates", "aliases"}
)


class ResourceScopeError(ValueError):
    """Raised when a provider relation or derived scope is malformed."""


@dataclass(frozen=True)
class ResourceRelation:
    """A provider-asserted semantic edge between two stable resources."""

    source: ResourceRef
    target: ResourceRef
    kind: RelationKind
    transitive: bool = False
    provenance: str = "adapter_declared"

    def __post_init__(self) -> None:
        if self.kind not in RELATION_KINDS:
            raise ResourceScopeError(f"unknown resource relation: {self.kind!r}")
        if not self.provenance.strip():
            raise ResourceScopeError("resource relation provenance must not be empty")

    def to_json(self) -> JsonObject:
        return {
            "source": self.source.to_json(),
            "target": self.target.to_json(),
            "kind": self.kind,
            "transitive": self.transitive,
            "provenance": self.provenance,
        }


@dataclass
class ResourceGraph:
    """Traverse only relations whose semantics a provider has declared."""

    relations: tuple[ResourceRelation, ...] = ()
    _outgoing: dict[str, list[ResourceRelation]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        outgoing: dict[str, list[ResourceRelation]] = {}
        for relation in self.relations:
            outgoing.setdefault(relation.source.resource_id, []).append(relation)
            if relation.kind == "aliases":
                outgoing.setdefault(relation.target.resource_id, []).append(
                    ResourceRelation(
                        source=relation.target,
                        target=relation.source,
                        kind="aliases",
                        transitive=relation.transitive,
                        provenance=relation.provenance,
                    )
                )
        self._outgoing = outgoing

    def affects(
        self,
        source: ResourceRef,
        target: ResourceRef,
        *,
        relations: Iterable[RelationKind] = ("contains", "owns", "mounts", "delegates", "aliases"),
    ) -> bool:
        """Return whether declared edges allow ``source`` to reach ``target``."""

        if source.resource_id == target.resource_id:
            return True
        allowed = frozenset(relations)
        queue: deque[tuple[ResourceRef, RelationKind | None]] = deque([(source, None)])
        seen = {source.resource_id}
        while queue:
            current, incoming_kind = queue.popleft()
            for edge in self._outgoing.get(current.resource_id, ()):
                if edge.kind not in allowed:
                    continue
                # Chaining is allowed through explicit edges. Reusing one
                # relation kind requires the provider to mark it transitive;
                # mixed edges remain useful for mount->contains and
                # delegates->owns relationships.
                if incoming_kind == edge.kind and not edge.transitive:
                    continue
                if edge.target.resource_id == target.resource_id:
                    return True
                if edge.target.resource_id not in seen:
                    seen.add(edge.target.resource_id)
                    queue.append((edge.target, edge.kind))
        return False

    def to_json(self) -> JsonObject:
        return {
            "schema_version": RESOURCE_SCOPE_SCHEMA_VERSION,
            "relations": [relation.to_json() for relation in self.relations],
        }


def canonical_filesystem_key(key: str, *, flavor: Literal["posix", "windows"]) -> str:
    """Canonicalize a provider-owned filesystem key and reject root escape."""

    if not key or "\x00" in key:
        raise ResourceScopeError("filesystem resource key must be non-empty")
    if flavor == "windows":
        drive, tail = ntpath.splitdrive(key.replace("/", "\\"))
        absolute = tail.startswith("\\")
        parts = tail.split("\\")
        separator = "\\"
    else:
        drive = ""
        absolute = key.startswith("/")
        parts = key.split("/")
        separator = "/"
    normalized: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not normalized:
                raise ResourceScopeError("filesystem resource key escapes its root")
            normalized.pop()
        else:
            normalized.append(part)
    prefix = f"{drive}{separator}" if absolute else drive
    result = prefix + separator.join(normalized)
    return result or (separator if absolute else ".")


def filesystem_relations(
    resources: Iterable[ResourceRef], *, flavor: Literal["posix", "windows"] = "posix"
) -> tuple[ResourceRelation, ...]:
    """Derive filesystem parent edges after provider-specific canonicalization."""

    normalized: dict[str, ResourceRef] = {}
    for resource in resources:
        key = canonical_filesystem_key(resource.key, flavor=flavor)
        normalized[key] = ResourceRef(resource.namespace, resource.kind, key, resource.facet)
    edges: list[ResourceRelation] = []
    path_module = ntpath if flavor == "windows" else posixpath
    for key, child in sorted(normalized.items()):
        parent_key = path_module.dirname(key)
        while parent_key and parent_key != key:
            parent = normalized.get(parent_key)
            if parent is not None:
                edges.append(
                    ResourceRelation(
                        parent,
                        child,
                        "contains",
                        transitive=True,
                        provenance=f"filesystem.{flavor}.canonical_parent",
                    )
                )
                break
            key, parent_key = parent_key, path_module.dirname(parent_key)
    return tuple(edges)


@dataclass(frozen=True)
class PolicyRule:
    name: str
    tool_pattern: str
    arg_pattern: str
    action: str
    line: int

    def to_json(self) -> JsonObject:
        return {
            "name": self.name,
            "tool_pattern": self.tool_pattern,
            "arg_pattern": self.arg_pattern,
            "action": self.action,
            "line": self.line,
        }


@dataclass(frozen=True)
class ScopeWitness:
    """One concrete resource sample derived from a policy expression."""

    rule: str
    argument: str
    resource_key: str
    family: str
    provenance: str

    def to_json(self) -> JsonObject:
        return {
            "rule": self.rule,
            "argument": self.argument,
            "resource_key": self.resource_key,
            "family": self.family,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class CompiledPolicyScope:
    rules: tuple[PolicyRule, ...]
    witnesses: tuple[ScopeWitness, ...]
    issues: tuple[str, ...]
    truncated: bool

    def to_json(self) -> JsonObject:
        return {
            "schema_version": RESOURCE_SCOPE_SCHEMA_VERSION,
            "rules": [rule.to_json() for rule in self.rules],
            "witnesses": [witness.to_json() for witness in self.witnesses],
            "issues": list(self.issues),
            "truncated": self.truncated,
            "claim_boundary": (
                "Concrete arguments were generated from policy regex branches and accepted "
                "only when the original regex matched. They are bounded witnesses, not an "
                "exhaustive enumeration of each regular language."
            ),
        }


@dataclass(frozen=True)
class MaterializedFilesystemScope:
    """Safe root-relative assets built from compiled policy witnesses."""

    protected_paths: tuple[str, ...]
    payload_path: str
    path_provenance: Mapping[str, tuple[str, ...]]
    path_families: Mapping[str, tuple[str, ...]]

    def to_json(self) -> JsonObject:
        return {
            "protected_paths": list(self.protected_paths),
            "payload_path": self.payload_path,
            "path_provenance": {
                path: list(provenance)
                for path, provenance in sorted(self.path_provenance.items())
            },
            "path_families": {
                path: list(families) for path, families in sorted(self.path_families.items())
            },
        }


def parse_policy_rules(policy_text: str) -> tuple[PolicyRule, ...]:
    """Parse the effective Pipelock rule list with safe YAML semantics.

    A top-level list remains supported for focused fixtures. Production
    configuration is read only from ``mcp_tool_policy.rules`` so unrelated
    mappings containing a ``name`` key cannot be mistaken for enforcement
    rules. A malformed rule fails closed instead of disappearing from scope.
    """

    try:
        document = yaml.safe_load(policy_text)
    except yaml.YAMLError as error:
        raise ResourceScopeError(f"invalid policy YAML: {error}") from error
    raw_rules: Any
    if isinstance(document, list):
        raw_rules = document
    elif isinstance(document, Mapping):
        policy = document.get("mcp_tool_policy")
        raw_rules = policy.get("rules") if isinstance(policy, Mapping) else []
    elif document is None:
        raw_rules = []
    else:
        raise ResourceScopeError("policy YAML must be a mapping or a rule list")
    if not isinstance(raw_rules, list):
        raise ResourceScopeError("mcp_tool_policy.rules must be a list")

    required = ("name", "tool_pattern", "arg_pattern", "action")
    rules: list[PolicyRule] = []
    search_from = 0
    lines = policy_text.splitlines()
    for index, item in enumerate(raw_rules):
        if not isinstance(item, Mapping):
            raise ResourceScopeError(f"policy rule {index} must be a mapping")
        missing = [field for field in required if field not in item]
        if missing:
            raise ResourceScopeError(
                f"policy rule {index} is missing required fields: {', '.join(missing)}"
            )
        values = {field: item[field] for field in required}
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ResourceScopeError(f"policy rule {index} fields must be non-empty strings")
        name = cast(str, values["name"])
        line_number = index + 1
        for line_index in range(search_from, len(lines)):
            if re.search(r"\bname\s*:\s*['\"]?" + re.escape(name), lines[line_index]):
                line_number = line_index + 1
                search_from = line_index + 1
                break
        rules.append(
            PolicyRule(
                name=name,
                tool_pattern=cast(str, values["tool_pattern"]),
                arg_pattern=cast(str, values["arg_pattern"]),
                action=cast(str, values["action"]),
                line=line_number,
            )
        )
    return tuple(rules)


def _merge(left: Sequence[str], right: Sequence[str], limit: int) -> tuple[list[str], bool]:
    products = [a + b for a, b in itertools.product(left, right)]
    return products[:limit], len(products) > limit


def _regex_samples(
    tokens: Any, limit: int, *, max_repeat: int = 64, max_length: int = 4_096
) -> tuple[list[str], bool, list[str]]:
    values = [""]
    truncated = False
    issues: list[str] = []
    for opcode, argument in tokens:
        pieces: list[str]
        if opcode is sre_constants.LITERAL:
            pieces = [chr(argument)]
        elif opcode is sre_constants.NOT_LITERAL:
            pieces = ["x" if argument != ord("x") else "y"]
        elif opcode is sre_constants.ANY:
            pieces = ["x"]
        elif opcode is sre_constants.AT:
            pieces = [""]
        elif opcode in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            pieces = [""]
        elif opcode is sre_constants.SUBPATTERN:
            pieces, cut, nested = _regex_samples(
                argument[-1], limit, max_repeat=max_repeat, max_length=max_length
            )
            truncated |= cut
            issues.extend(nested)
        elif opcode is sre_constants.BRANCH:
            pieces = []
            for branch in argument[1]:
                samples, cut, nested = _regex_samples(
                    branch, limit, max_repeat=max_repeat, max_length=max_length
                )
                pieces.extend(samples)
                truncated |= cut
                issues.extend(nested)
            if len(pieces) > limit:
                pieces = pieces[:limit]
                truncated = True
        elif opcode in (
            sre_constants.MAX_REPEAT,
            sre_constants.MIN_REPEAT,
            sre_constants.POSSESSIVE_REPEAT,
        ):
            minimum, maximum, repeated = argument
            unit, cut, nested = _regex_samples(
                repeated, limit, max_repeat=max_repeat, max_length=max_length
            )
            truncated |= cut or maximum > max(minimum, 1)
            issues.extend(nested)
            if minimum > max_repeat:
                issues.append(
                    f"repeat minimum {minimum} exceeds generation cap {max_repeat}"
                )
                truncated = True
            counts = sorted(
                {
                    min(minimum, max_repeat),
                    min(maximum, max(minimum, 1), max_repeat),
                }
            )
            pieces = []
            for count in counts:
                expanded = [""]
                for _ in range(count):
                    expanded, cut = _merge(expanded, unit, limit)
                    truncated |= cut
                    if any(len(value) > max_length for value in expanded):
                        expanded = [value[:max_length] for value in expanded]
                        truncated = True
                        issues.append(f"regex witness exceeded {max_length} characters")
                        break
                pieces.extend(expanded)
            pieces = pieces[:limit]
        elif opcode is sre_constants.IN:
            negate = False
            pieces = []
            for item_opcode, item in argument:
                if item_opcode is sre_constants.NEGATE:
                    negate = True
                elif item_opcode is sre_constants.LITERAL:
                    pieces.append(chr(item))
                elif item_opcode is sre_constants.RANGE:
                    pieces.extend((chr(item[0]), chr(item[1])))
                elif item_opcode is sre_constants.CATEGORY:
                    pieces.append(_category_sample(item))
            if negate:
                pieces = [next(char for char in "x0_/ " if char not in pieces)]
            pieces = list(dict.fromkeys(pieces or ["x"]))[:limit]
        elif opcode is sre_constants.CATEGORY:
            pieces = [_category_sample(argument)]
        elif opcode is sre_constants.GROUPREF:
            pieces = [""]
            issues.append("backreference sampled as empty")
        else:
            pieces = [""]
            issues.append(f"unsupported regex opcode sampled as empty: {opcode}")
        values, cut = _merge(values, pieces, limit)
        if any(len(value) > max_length for value in values):
            values = [value[:max_length] for value in values]
            truncated = True
            issues.append(f"regex witness exceeded {max_length} characters")
        truncated |= cut
    return list(dict.fromkeys(values)), truncated, list(dict.fromkeys(issues))


def _category_sample(category: Any) -> str:
    if category in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_UNI_DIGIT):
        return "0"
    if category in (sre_constants.CATEGORY_SPACE, sre_constants.CATEGORY_UNI_SPACE):
        return " "
    if category in (sre_constants.CATEGORY_WORD, sre_constants.CATEGORY_UNI_WORD):
        return "x"
    return "/"


def regex_witnesses(
    pattern: str, *, limit: int = 128
) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """Generate bounded branch witnesses and validate each against ``pattern``."""

    try:
        compiled = re.compile(pattern)
        parsed = sre_parse.parse(pattern, 0)
    except re.error as error:
        return (), (f"invalid regex: {error}",), False
    samples, truncated, issues = _regex_samples(parsed, limit)
    accepted = tuple(sample for sample in samples if compiled.search(sample) is not None)
    if not accepted:
        issues.append("no generated witness matched the original regex")
    return accepted, tuple(dict.fromkeys(issues)), truncated


_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.])/(?:[A-Za-z0-9_.-]+/)*(?:[A-Za-z0-9_.-]+)?"
)
_DOTFILE = re.compile(
    r"(?<![A-Za-z0-9_.-])\.[A-Za-z][A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*/?"
)
_AUDIT_SUFFIX = re.compile(r"\.(?:log|audit|jsonl)\b", re.IGNORECASE)


def _resource_keys(argument: str) -> list[str]:
    keys: list[str] = []
    for match in _ABSOLUTE_PATH.finditer(argument):
        candidate = match.group(0)
        if candidate != "/":
            keys.append(candidate)
    keys.extend(match.group(0) for match in _DOTFILE.finditer(argument))
    if _AUDIT_SUFFIX.search(argument) and not any(_AUDIT_SUFFIX.search(key) for key in keys):
        suffix = cast(re.Match[str], _AUDIT_SUFFIX.search(argument)).group(0)
        keys.append(f"shadowpath{suffix.lower()}")
    return list(dict.fromkeys(keys))


def _family(rule_name: str) -> str:
    lowered = rule_name.lower()
    for family in ("shell profile", "persistence", "audit log", "credential", "secret"):
        if family in lowered:
            return family.replace(" ", "_")
    return "policy_resource"


def compile_policy_scope(
    policy_text: str, *, max_witnesses_per_rule: int = 128
) -> CompiledPolicyScope:
    """Derive filesystem resource witnesses from policy rules without fixtures."""

    rules = parse_policy_rules(policy_text)
    witnesses: list[ScopeWitness] = []
    issues: list[str] = []
    truncated = False
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        if rule.action.lower() != "block":
            continue
        samples, sample_issues, cut = regex_witnesses(
            rule.arg_pattern, limit=max_witnesses_per_rule
        )
        truncated |= cut
        issues.extend(f"{rule.name}: {issue}" for issue in sample_issues)
        for argument in samples:
            for key in _resource_keys(argument):
                pattern_without_flags = re.sub(r"^\(\?[aiLmsux-]+\)", "", rule.arg_pattern)
                if key.startswith("/") and pattern_without_flags.startswith(("^/", r"\A/")):
                    issues.append(
                        f"{rule.name}: anchored absolute resource cannot be preserved "
                        "inside a disposable provider root"
                    )
                    truncated = True
                    continue
                identity = (rule.name, key)
                if identity in seen:
                    continue
                seen.add(identity)
                witnesses.append(
                    ScopeWitness(
                        rule=rule.name,
                        argument=argument,
                        resource_key=key,
                        family=_family(rule.name),
                        provenance=f"policy.rule:{rule.line}:regex_witness",
                    )
                )
    if not rules:
        issues.append("no policy rules were parsed")
    if not witnesses:
        issues.append("no resource-shaped policy witnesses were derived")
    return CompiledPolicyScope(
        rules=rules,
        witnesses=tuple(witnesses),
        issues=tuple(dict.fromkeys(issues)),
        truncated=truncated,
    )


def materialize_filesystem_scope(
    *,
    root: str | Path,
    scope: CompiledPolicyScope,
    approved_content: str = "# ShadowPath policy-derived protected asset\n",
    payload_content: str = "# ShadowPath generated replacement payload\n",
    additional_paths: Sequence[str] = (),
) -> MaterializedFilesystemScope:
    """Build a disposable filesystem baseline solely from compiled policy scope."""

    base = Path(root)
    if base.is_symlink():
        raise ResourceScopeError("materialization root must not be a symlink")
    base.mkdir(parents=True, exist_ok=True)
    if not base.is_dir() or any(base.iterdir()):
        raise ResourceScopeError("materialization requires an owned empty directory")
    candidates: list[tuple[str, ScopeWitness]] = []
    for witness in scope.witnesses:
        raw = witness.resource_key.strip()
        if raw in (".log", ".audit", ".jsonl"):
            raw = f"shadowpath{raw}"
        directory_witness = raw.endswith("/")
        relative = raw.lstrip("/")
        try:
            relative = canonical_filesystem_key(relative, flavor="posix")
        except ResourceScopeError:
            continue
        if relative in ("", ".") or PurePosixPath(relative).is_absolute():
            continue
        if directory_witness:
            relative = f"{relative.rstrip('/')}/shadowpath-target"
        candidates.append((relative, witness))
    for relative in additional_paths:
        canonical = canonical_filesystem_key(relative, flavor="posix")
        if canonical in ("", ".") or PurePosixPath(canonical).is_absolute():
            raise ResourceScopeError(f"invalid additional protected path: {relative!r}")
        candidates.append(
            (
                canonical,
                ScopeWitness(
                    rule="operator-declared",
                    argument=relative,
                    resource_key=relative,
                    family="operator_declared",
                    provenance="cli.protected",
                ),
            )
        )

    # A policy may name both a path and descendants of that path. A disposable
    # filesystem cannot make the former both a file and a directory, so keep
    # the protected witness as a deterministic child in that case.
    parent_paths = {
        parent.as_posix()
        for relative, _ in candidates
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    provenance: dict[str, list[str]] = {}
    families: dict[str, list[str]] = {}
    for relative, witness in candidates:
        if relative in parent_paths:
            relative = f"{relative}/shadowpath-target"
        destination = base / relative
        if not destination.resolve().is_relative_to(base.resolve()):
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if relative not in provenance:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(approved_content)
        provenance.setdefault(relative, []).append(
            f"{witness.rule} ({witness.provenance}; argument={witness.argument!r})"
        )
        families.setdefault(relative, []).append(witness.family)

    payload_index = 0
    while True:
        suffix = "" if payload_index == 0 else f"-{payload_index:03d}"
        payload_path = f".shadowpath-generated-payload{suffix}"
        if payload_path not in provenance and not (base / payload_path).exists():
            break
        payload_index += 1
    payload_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        payload_flags |= os.O_NOFOLLOW
    payload_descriptor = os.open(base / payload_path, payload_flags, 0o600)
    with os.fdopen(payload_descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload_content)
    return MaterializedFilesystemScope(
        protected_paths=tuple(provenance),
        payload_path=payload_path,
        path_provenance={
            path: tuple(dict.fromkeys(items)) for path, items in provenance.items()
        },
        path_families={
            path: tuple(dict.fromkeys(items)) for path, items in families.items()
        },
    )


def operation_may_write(tool: Mapping[str, Any]) -> tuple[bool, str]:
    """Conservatively classify mutation capability with explicit provenance."""

    annotations = tool.get("annotations")
    if isinstance(annotations, Mapping):
        if (
            annotations.get("readOnlyHint") is True
            and annotations.get("destructiveHint") is True
        ):
            return True, "mcp.annotation.conflict:readOnlyHint=true,destructiveHint=true"
        if annotations.get("readOnlyHint") is True:
            return False, "mcp.annotation.readOnlyHint=true"
        if annotations.get("readOnlyHint") is False:
            return True, "mcp.annotation.readOnlyHint=false"
        if annotations.get("destructiveHint") is True:
            return True, "mcp.annotation.destructiveHint=true"
    name = str(tool.get("name", "")).lower()
    mutation_tokens = (
        "write",
        "edit",
        "create",
        "move",
        "rename",
        "delete",
        "remove",
        "patch",
        "update",
        "append",
    )
    if any(token in name for token in mutation_tokens):
        return True, "operation-name heuristic"
    return False, "no mutation evidence"


def static_policy_coverage(
    *, tools: Sequence[Mapping[str, Any]], scope: CompiledPolicyScope
) -> JsonObject:
    """Compare derived policy witnesses with every advertised writer."""

    rows: list[JsonObject] = []
    writers: list[JsonObject] = []
    for tool in tools:
        may_write, basis = operation_may_write(tool)
        if may_write:
            writers.append({"name": str(tool.get("name", "")), "basis": basis})
    for witness in scope.witnesses:
        for writer in writers:
            matched: list[str] = []
            for rule in scope.rules:
                if rule.action.lower() != "block":
                    continue
                try:
                    tool_match = re.search(rule.tool_pattern, cast(str, writer["name"]))
                    # A command-shaped regex witness establishes that the
                    # policy names this resource. Structured filesystem tools
                    # present the resource value itself, not shell syntax such
                    # as ``rm`` or ``>``. Testing the bare resource prevents a
                    # command grammar from being credited to a path argument.
                    arg_match = re.search(rule.arg_pattern, witness.resource_key)
                except re.error:
                    continue
                if tool_match is not None and arg_match is not None:
                    matched.append(rule.name)
            rows.append(
                {
                    "resource_key": witness.resource_key,
                    "family": witness.family,
                    "source_rule": witness.rule,
                    "source_regex_witness": witness.argument,
                    "presented_resource_argument": witness.resource_key,
                    "operation": writer["name"],
                    "operation_write_basis": writer["basis"],
                    "matched_block_rules": matched,
                    "predicted_open": not matched,
                }
            )
    family_summary: list[JsonObject] = []
    for family in sorted({witness.family for witness in scope.witnesses}):
        family_rows = [row for row in rows if row["family"] == family]
        operation_status: dict[str, str] = {}
        for operation in sorted({cast(str, row["operation"]) for row in family_rows}):
            values = [
                bool(row["predicted_open"])
                for row in family_rows
                if row["operation"] == operation
            ]
            operation_status[operation] = (
                "uncovered" if all(values) else "partial" if any(values) else "covered"
            )
        family_summary.append(
            {
                "family": family,
                "resource_keys": sorted(
                    {cast(str, row["resource_key"]) for row in family_rows}
                ),
                "predicted_open_operations": sorted(
                    {
                        cast(str, row["operation"])
                        for row in family_rows
                        if bool(row["predicted_open"])
                    }
                ),
                "covered_operations": sorted(
                    {
                        cast(str, row["operation"])
                        for row in family_rows
                        if not bool(row["predicted_open"])
                    }
                ),
                "operation_status": operation_status,
                "predicted_open_pairs": sum(
                    bool(row["predicted_open"]) for row in family_rows
                ),
            }
        )
    return {
        "schema_version": RESOURCE_SCOPE_SCHEMA_VERSION,
        "writers": writers,
        "rows": rows,
        "families": family_summary,
        "predicted_open_count": sum(bool(row["predicted_open"]) for row in rows),
        "claim_boundary": (
            "Predictions compare advertised write evidence and concrete regex witnesses. "
            "They do not prove that an implementation performs the predicted effect; live "
            "observation must confirm it."
        ),
    }
