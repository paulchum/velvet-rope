"""Bounded, schema-validated argument discovery without tool-specific recipes.

The schema supplies shapes and literal values; observed paths supply possible
string bindings.  Every free string leaf is eligible, including leaves inside
arrays.  A path binding records its exact address so dispatch can prefix only
that value.  This is a candidate generator, not a completeness proof.
"""

from __future__ import annotations

import copy
import itertools
import json
import math
import posixpath
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for
from referencing import Registry

Address = tuple[str | int, ...]
PathSlotPredicate = Callable[[Address, Mapping[str, Any]], bool]
LiteralValueProvider = Callable[[Address, Mapping[str, Any]], Sequence[Any]]


@dataclass(frozen=True)
class ArgumentCandidate:
    arguments: dict[str, Any]
    path_slots: tuple[Address, ...]


@dataclass(frozen=True)
class ArgumentPlan:
    candidates: tuple[ArgumentCandidate, ...]
    issues: tuple[str, ...]
    truncated: bool


@dataclass(frozen=True)
class _Template:
    value: Any
    slots: tuple[Address, ...] = ()


def _address(address: Address) -> str:
    return "/" + "/".join(str(part) for part in address)


def _vectors(lengths: Sequence[int]) -> Iterator[tuple[int, ...]]:
    """Cover each coordinate early, then enumerate remaining combinations.

    Rotations place different paths in different slots before spending budget
    on every spelling of the first source.  Single-coordinate changes include
    mixed marker/path roles without interpreting parameter names.
    """
    if not lengths:
        yield ()
        return
    if any(length == 0 for length in lengths):
        return
    seen: set[tuple[int, ...]] = set()
    width = max(lengths)
    for offset in range(width):
        vectors = [
            tuple((offset + index) % length for index, length in enumerate(lengths)),
            tuple(offset % length for length in lengths),
        ]
        for vector in vectors:
            if vector not in seen:
                seen.add(vector)
                yield vector
    for offset in range(1, width):
        for index, length in enumerate(lengths):
            vector = tuple(
                offset % length if other == index else 0 for other in range(len(lengths))
            )
            if vector not in seen:
                seen.add(vector)
                yield vector
    # Increasing sums avoid the first coordinate dominating the remainder.
    # Stop upstream once the explicit generation budget has been consumed.
    for total in range(sum(length - 1 for length in lengths) + 1):
        for vector in _diagonal(lengths, total):
            if vector not in seen:
                seen.add(vector)
                yield vector


def _diagonal(lengths: Sequence[int], total: int) -> Iterator[tuple[int, ...]]:
    if not lengths:
        if total == 0:
            yield ()
        return
    rest_max = sum(length - 1 for length in lengths[1:])
    for value in range(max(0, total - rest_max), min(lengths[0] - 1, total) + 1):
        for rest in _diagonal(lengths[1:], total - value):
            yield (value, *rest)


class _Builder:
    def __init__(
        self,
        root: Mapping[str, Any],
        marker: str,
        limit: int,
        path_slot_predicate: PathSlotPredicate | None,
        literal_value_provider: LiteralValueProvider | None,
    ) -> None:
        self.root = root
        self.marker = marker
        self.limit = limit
        self.path_slot_predicate = path_slot_predicate
        self.literal_value_provider = literal_value_provider
        self.issues: list[str] = []
        self.truncated = False

    def issue(self, message: str) -> None:
        if message not in self.issues:
            self.issues.append(message)

    def bounded(self, values: Iterator[_Template]) -> list[_Template]:
        results = list(itertools.islice(values, self.limit + 1))
        if len(results) > self.limit:
            self.truncated = True
        return results[: self.limit]

    def templates(
        self,
        schema: Any,
        address: Address = (),
        refs: tuple[str, ...] = (),
        depth: int = 0,
    ) -> list[_Template]:
        if depth > 24:
            self.issue(f"{_address(address)}: schema nesting exceeds generation limit")
            self.truncated = True
            return []
        if schema is False:
            return []
        if schema is True:
            schema = {}
        if not isinstance(schema, Mapping):
            return []
        ref = schema.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#"):
                self.issue(f"{_address(address)}: external reference is not resolved: {ref}")
                return []
            if ref in refs:
                self.issue(f"{_address(address)}: recursive reference needs a bounded model: {ref}")
                return []
            resolved: Any = self.root
            try:
                if ref != "#":
                    if not ref.startswith("#/"):
                        raise KeyError(ref)
                    for part in ref[2:].split("/"):
                        resolved = resolved[part.replace("~1", "/").replace("~0", "~")]
            except (KeyError, TypeError, IndexError):
                self.issue(f"{_address(address)}: unresolved local reference: {ref}")
                return []
            # Validation against the original schema also enforces ref siblings.
            return self.templates(resolved, address, (*refs, ref), depth + 1)
        for keyword in ("allOf", "not", "if", "dependentSchemas", "$dynamicRef"):
            if keyword in schema:
                self.issue(f"{_address(address)}: unsupported generation keyword: {keyword}")
                return []
        for keyword in ("patternProperties", "contains", "unevaluatedProperties"):
            if keyword in schema:
                self.issue(
                    f"{_address(address)}: {keyword} is validated but not exhaustively generated"
                )
        if "const" in schema:
            return [_Template(copy.deepcopy(schema["const"]))]
        if "enum" in schema:
            return self.bounded(_Template(copy.deepcopy(value)) for value in schema["enum"])
        for keyword in ("oneOf", "anyOf"):
            if keyword in schema:
                branches = [
                    self.templates(branch, address, refs, depth + 1) for branch in schema[keyword]
                ]
                return self.bounded(_round_robin(branches))
        kind = schema.get("type")
        if isinstance(kind, list):
            branches = [
                self.templates({**schema, "type": item}, address, refs, depth + 1) for item in kind
            ]
            return self.bounded(_round_robin(branches))
        if kind is None:
            if "properties" in schema or "required" in schema or not address:
                kind = "object"
            elif "items" in schema or "prefixItems" in schema:
                kind = "array"
            else:
                kind = "string"
                self.issue(f"{_address(address)}: unspecified type sampled as string")
        templates: list[_Template]
        if kind == "object":
            templates = self.object_templates(schema, address, refs, depth)
        elif kind == "array":
            templates = self.array_templates(schema, address, refs, depth)
        elif kind == "string":
            minimum = schema.get("minLength", 0)
            maximum = schema.get("maxLength", max(len(self.marker), minimum))
            if minimum > 4096:
                self.issue(f"{_address(address)}: minLength exceeds generation limit")
                return []
            is_path_slot = self.path_slot_predicate is None or self.path_slot_predicate(
                address, schema
            )
            supplied = (
                list(self.literal_value_provider(address, schema))
                if self.literal_value_provider is not None and not is_path_slot
                else []
            )
            value = (self.marker + "x" * minimum)[: max(minimum, min(maximum, len(self.marker)))]
            values = [*supplied, value]
            templates = [
                _Template(item, (address,) if is_path_slot else ())
                for item in dict.fromkeys(item for item in values if isinstance(item, str))
            ]
        elif kind in ("number", "integer"):
            minimum = schema.get("minimum", -math.inf)
            exclusive = schema.get("exclusiveMinimum")
            if isinstance(exclusive, (int, float)) and not isinstance(exclusive, bool):
                minimum = max(minimum, math.nextafter(exclusive, math.inf))
            maximum = schema.get("maximum", math.inf)
            upper_exclusive = schema.get("exclusiveMaximum")
            if isinstance(upper_exclusive, (int, float)) and not isinstance(upper_exclusive, bool):
                maximum = min(maximum, math.nextafter(upper_exclusive, -math.inf))
            if kind == "integer":
                if math.isfinite(minimum):
                    minimum = math.ceil(minimum)
                if math.isfinite(maximum):
                    maximum = math.floor(maximum)
            value = max(minimum, min(0, maximum))
            multiple = schema.get("multipleOf")
            if multiple:
                value = math.ceil(value / multiple) * multiple
                if value > maximum:
                    value = math.floor(maximum / multiple) * multiple
            if kind == "integer":
                value = math.ceil(value)
            templates = [_Template(value)]
        elif kind == "boolean":
            templates = [_Template(False), _Template(True)]
        elif kind == "null":
            templates = [_Template(None)]
        else:
            self.issue(f"{_address(address)}: unsupported type: {kind}")
            templates = []
        if "default" in schema:
            templates.insert(0, _Template(copy.deepcopy(schema["default"])))
        return self.bounded(iter(templates))

    def object_templates(
        self, schema: Mapping[str, Any], address: Address, refs: tuple[str, ...], depth: int
    ) -> list[_Template]:
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        keys = sorted(set(properties) | required)
        options = [
            self.templates(
                properties.get(key, schema.get("additionalProperties", {})),
                (*address, key),
                refs,
                depth + 1,
            )
            for key in keys
        ]

        # Both full and minimal objects matter: optional parameters can expose
        # behavior, while omitted parameters exercise the implementation default.
        def generate() -> Iterator[_Template]:
            for include_optional in (True, False):
                selected = [
                    index for index, key in enumerate(keys) if include_optional or key in required
                ]
                for indices in _vectors([len(options[index]) for index in selected]):
                    chosen = [
                        options[index][choice]
                        for index, choice in zip(selected, indices, strict=True)
                    ]
                    yield _Template(
                        {
                            keys[index]: item.value
                            for index, item in zip(selected, chosen, strict=True)
                        },
                        tuple(slot for item in chosen for slot in item.slots),
                    )
                if all(key in required for key in keys):
                    break

        return self.bounded(generate())

    def array_templates(
        self, schema: Mapping[str, Any], address: Address, refs: tuple[str, ...], depth: int
    ) -> list[_Template]:
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", max(minimum, 1))
        prefix = schema.get("prefixItems", [])
        # Draft 7 tuple arrays use an items array rather than prefixItems.
        items = schema.get("items", {})
        if isinstance(items, list):
            prefix, items = items, schema.get("additionalItems", {})
        length = min(maximum, max(minimum, len(prefix), 1))
        if length > 32:
            self.issue(f"{_address(address)}: array length exceeds generation limit")
            self.truncated = True
            return []
        options = [
            self.templates(
                prefix[index] if index < len(prefix) else items, (*address, index), refs, depth + 1
            )
            for index in range(length)
        ]

        def generate() -> Iterator[_Template]:
            for indices in _vectors([len(option) for option in options]):
                chosen = [option[index] for option, index in zip(options, indices, strict=True)]
                yield _Template(
                    [item.value for item in chosen],
                    tuple(slot for item in chosen for slot in item.slots),
                )
            if minimum == 0 and length:
                yield _Template([])

        return self.bounded(generate())


def _round_robin(groups: Sequence[Sequence[_Template]]) -> Iterator[_Template]:
    for index in range(max((len(group) for group in groups), default=0)):
        for group in groups:
            if index < len(group):
                yield group[index]


def _path_groups(paths: Sequence[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for path in paths:
        key = posixpath.normpath(path.replace("\\", "/"))
        group = groups.setdefault(key, [])
        if path not in group:
            group.append(path)
    return list(groups.values())


def _set_leaf(value: Any, address: Address, replacement: Any) -> None:
    for component in address[:-1]:
        value = value[component]
    value[address[-1]] = replacement


def _bindings(
    template: _Template,
    paths: Sequence[str],
    preferred_path_pairs: Sequence[tuple[str, str]],
) -> Iterator[_Template]:
    if not isinstance(template.value, dict) or not template.slots:
        yield template
        return
    # The unbound marker is a role, not a path spelling.  Alternate all roles
    # over the canonical pool before opening additional spelling layers.
    groups = _path_groups(paths)
    if len(template.slots) == 2:
        available = {value for group in groups for value in group}
        for source, destination in preferred_path_pairs:
            if source not in available or destination not in available:
                continue
            value = copy.deepcopy(template.value)
            _set_leaf(value, template.slots[0], source)
            _set_leaf(value, template.slots[1], destination)
            yield _Template(value, template.slots)
    for layer in range(max((len(group) for group in groups), default=1)):
        pool = [group[layer] for group in groups if layer < len(group)]
        for vector in _binding_vectors(len(template.slots), len(pool)):
            value = copy.deepcopy(template.value)
            bound: list[Address] = []
            for address, index in zip(template.slots, vector, strict=True):
                if index < len(pool):
                    _set_leaf(value, address, pool[index])
                    bound.append(address)
            yield _Template(value, tuple(bound))


def _binding_vectors(slots: int, paths: int) -> Iterator[tuple[int, ...]]:
    """Cover directed path pairs and content roles fairly.

    Two-slot filesystem operations are common, but the schema does not say
    which value is a source and which is a destination. Directed pairs by
    cyclic distance cover both orientations without reading parameter names.
    Marker roles follow the first ring so mixed path/content operations are
    still sampled before wider path pairings.
    """
    seen: set[tuple[int, ...]] = set()
    if slots == 2 and paths:
        # The first ring reaches every path in both roles. The second ring is
        # interleaved with marker roles: it catches common non-adjacent source /
        # destination pairs without delaying path/content samples.
        for first in range(paths):
            if paths > 1:
                pair_vector = (first, (first + 1) % paths)
                if pair_vector not in seen:
                    seen.add(pair_vector)
                    yield pair_vector
            pair_values = (first, (first + 1) % paths)
            marker_index = first % slots
            marker_vector = tuple(
                paths if index == marker_index else value for index, value in enumerate(pair_values)
            )
            if marker_vector not in seen:
                seen.add(marker_vector)
                yield marker_vector
        if paths > 2:
            for offset in range(paths):
                pair_vector = (offset, (offset + 2) % paths)
                if pair_vector not in seen:
                    seen.add(pair_vector)
                    yield pair_vector
        for distance in range(3, paths):
            for first in range(paths):
                pair_vector = (first, (first + distance) % paths)
                if pair_vector not in seen:
                    seen.add(pair_vector)
                    yield pair_vector
    elif slots > 1 and paths:
        for offset in range(max(slots, paths)):
            wide_values = tuple((offset + index) % paths for index in range(slots))
            marker_index = offset % slots
            with_marker = tuple(
                paths if index == marker_index else value for index, value in enumerate(wide_values)
            )
            for wide_vector in (wide_values, with_marker):
                if wide_vector not in seen:
                    seen.add(wide_vector)
                    yield wide_vector
    for fallback_vector in _vectors([paths + 1] * slots):
        if fallback_vector not in seen:
            seen.add(fallback_vector)
            yield fallback_vector


def generate_arguments(
    schema: Mapping[str, Any],
    paths: Sequence[str],
    *,
    marker: str,
    max_candidates: int,
    path_slot_predicate: PathSlotPredicate | None = None,
    literal_value_provider: LiteralValueProvider | None = None,
    preferred_path_pairs: Sequence[tuple[str, str]] = (),
) -> ArgumentPlan:
    """Generate a deterministic, bounded sample of valid argument objects.

    Unsupported features and invalid samples are visible in ``issues``.  A
    result with ``truncated=True`` leaves candidates unexplored.  The generator
    never resolves external references and never interprets a tool's name.
    ``truncated=False`` describes this finite sample, not every value permitted
    by the schema (free strings and numbers usually have infinite domains).
    """
    if max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    builder = _Builder(
        schema,
        marker,
        max_candidates + 1,
        path_slot_predicate,
        literal_value_provider,
    )
    try:
        validator_class = validator_for(schema, default=Draft202012Validator)
        validator_class.check_schema(dict(schema))
    except SchemaError as exc:
        return ArgumentPlan((), (f"invalid JSON Schema: {exc.message}",), False)
    # An explicit empty registry has no retriever.  Unlike jsonschema's legacy
    # implicit resolver, it cannot fetch an external resource from the network.
    validator = validator_class(schema, registry=Registry(), format_checker=FormatChecker())
    templates = builder.templates(schema)
    streams = [
        iter(_bindings(template, paths, preferred_path_pairs)) for template in templates
    ]
    candidates: list[ArgumentCandidate] = []
    seen: set[str] = set()
    # Invalid samples cannot create unbounded work.  The cap is separate from
    # the output cap so common pattern constraints can reject a few bindings.
    attempt_limit = max(64, max_candidates * 32)
    attempts = 0
    while streams and attempts < attempt_limit:
        remaining: list[Iterator[_Template]] = []
        for stream in streams:
            if attempts >= attempt_limit:
                remaining.append(stream)
                continue
            try:
                candidate = next(stream)
            except StopIteration:
                continue
            remaining.append(stream)
            attempts += 1
            if not isinstance(candidate.value, dict):
                builder.issue("root schema generated a non-object; tool arguments must be objects")
                continue
            try:
                errors = list(validator.iter_errors(candidate.value))
            except Exception as exc:
                builder.issue(
                    f"schema validation could not resolve constraints: {type(exc).__name__}"
                )
                continue
            if errors:
                for error in errors[:3]:
                    builder.issue(
                        f"{_address(tuple(error.absolute_path))}: "
                        f"sample rejected by {error.validator}"
                    )
                continue
            fingerprint = json.dumps([candidate.value, candidate.slots], sort_keys=True)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            if len(candidates) == max_candidates:
                return ArgumentPlan(tuple(candidates), tuple(builder.issues), True)
            candidates.append(ArgumentCandidate(copy.deepcopy(candidate.value), candidate.slots))
        streams = remaining
    if streams:
        builder.truncated = True
        builder.issue("argument generation attempt budget exhausted")
    if not candidates:
        builder.issue("no valid argument candidate generated")
    return ArgumentPlan(tuple(candidates), tuple(builder.issues), builder.truncated)
