"""Schema discovery generates useful valid calls without parameter-name rules."""

from __future__ import annotations

from typing import Any

import pytest
from jsonschema import Draft202012Validator

from velvet.shadowpath_schema import generate_arguments


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def test_four_string_slots_include_distinct_paths_and_marker_roles() -> None:
    schema = _object({key: {"type": "string"} for key in ("a", "b", "c", "d")})
    plan = generate_arguments(schema, ["one", "two", "three"], marker="DATA", max_candidates=20)

    assert plan.candidates
    assert any(len(candidate.path_slots) == 4 for candidate in plan.candidates)
    assert any(
        candidate.arguments == {"a": "one", "b": "two", "c": "three", "d": "DATA"}
        for candidate in plan.candidates
    )
    assert {slot for candidate in plan.candidates for slot in candidate.path_slots} == {
        ("a",),
        ("b",),
        ("c",),
        ("d",),
    }
    for candidate in plan.candidates:
        Draft202012Validator(schema).validate(candidate.arguments)


def test_nested_objects_and_arrays_retain_exact_path_addresses() -> None:
    schema = _object(
        {
            "container": _object(
                {
                    "rows": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": _object({"value": {"type": "string"}}),
                    },
                    "third": {"type": "string"},
                }
            ),
        }
    )
    plan = generate_arguments(schema, ["from", "to"], marker="DATA", max_candidates=12)

    assert any(len(candidate.path_slots) == 3 for candidate in plan.candidates)
    assert {slot for candidate in plan.candidates for slot in candidate.path_slots} == {
        ("container", "rows", 0, "value"),
        ("container", "rows", 1, "value"),
        ("container", "third"),
    }


def test_const_enum_defaults_and_booleans_remain_schema_valid() -> None:
    schema = _object(
        {
            "literal": {"const": "fixed"},
            "mode": {"enum": ["a", "b", "c"]},
            "enabled": {"type": "boolean", "default": True},
            "count": {"type": "integer", "minimum": 4, "default": 8},
        }
    )
    plan = generate_arguments(
        schema, ["should-not-replace-literals"], marker="DATA", max_candidates=30
    )

    assert {candidate.arguments["mode"] for candidate in plan.candidates} == {"a", "b", "c"}
    assert {candidate.arguments["enabled"] for candidate in plan.candidates} == {True, False}
    assert any(candidate.arguments["count"] == 8 for candidate in plan.candidates)
    for candidate in plan.candidates:
        Draft202012Validator(schema).validate(candidate.arguments)
        assert candidate.arguments["literal"] == "fixed"
        assert candidate.path_slots == ()


def test_optional_fields_are_both_exercised_and_omitted() -> None:
    schema = _object({"required": {"const": "yes"}, "optional": {"type": "string"}})
    schema["required"] = ["required"]
    plan = generate_arguments(schema, ["path"], marker="DATA", max_candidates=12)

    assert any("optional" in candidate.arguments for candidate in plan.candidates)
    assert any("optional" not in candidate.arguments for candidate in plan.candidates)


def test_canonical_paths_are_sampled_before_spelling_variants() -> None:
    schema = _object({"a": {"type": "string"}})
    plan = generate_arguments(
        schema,
        ["first/file", "first/./file", "first//file", "second/file", "third/file"],
        marker="DATA",
        max_candidates=3,
    )

    assert [candidate.arguments["a"] for candidate in plan.candidates] == [
        "first/file",
        "second/file",
        "third/file",
    ]
    assert plan.truncated


def test_source_slots_rotate_before_first_source_exhausts_budget() -> None:
    schema = _object({"a": {"type": "string"}, "b": {"type": "string"}})
    paths = ["one", "two", "three", "four"]
    plan = generate_arguments(schema, paths, marker="DATA", max_candidates=8)

    assert {candidate.arguments["a"] for candidate in plan.candidates} >= set(paths)
    assert plan.candidates[0].arguments == {"a": "one", "b": "two"}


def test_large_path_pools_still_exercise_every_content_role_early() -> None:
    schema = _object({key: {"type": "string"} for key in ("a", "b", "c")})
    paths = [f"file-{index}" for index in range(40)]
    plan = generate_arguments(schema, paths, marker="DATA", max_candidates=6)

    for key in ("a", "b", "c"):
        assert any(candidate.arguments[key] == "DATA" for candidate in plan.candidates)
    assert any(len(candidate.path_slots) == 3 for candidate in plan.candidates)
    assert any(candidate.arguments["a"] == "file-2" for candidate in plan.candidates)


def test_two_string_slots_keep_marker_roles_with_a_large_path_pool() -> None:
    schema = _object({"content": {"type": "string"}, "path": {"type": "string"}})
    paths = [f"file-{index:02d}" for index in range(40)]
    plan = generate_arguments(schema, paths, marker="PAYLOAD", max_candidates=32)

    assert any(candidate.arguments["content"] == "PAYLOAD" for candidate in plan.candidates)
    assert any(candidate.arguments["path"] == "PAYLOAD" for candidate in plan.candidates)
    assert any(len(candidate.path_slots) == 2 for candidate in plan.candidates)


def test_path_slot_predicate_keeps_content_markers_off_the_wire_path_mapper() -> None:
    schema = _object({"content": {"type": "string"}, "path": {"type": "string"}})
    plan = generate_arguments(
        schema,
        ["one", "two"],
        marker="PAYLOAD",
        max_candidates=8,
        path_slot_predicate=lambda address, _schema: address == ("path",),
    )

    assert plan.candidates
    assert all(candidate.arguments["content"] == "PAYLOAD" for candidate in plan.candidates)
    assert all(set(candidate.path_slots) <= {("path",)} for candidate in plan.candidates)
    assert all(
        candidate.path_slots == (("path",),)
        for candidate in plan.candidates
        if candidate.arguments["path"] != "PAYLOAD"
    )


def test_local_reference_preserves_nested_slots() -> None:
    schema = _object({"payload": {"$ref": "#/$defs/payload"}})
    schema["$defs"] = {"payload": _object({"address": {"type": "string"}})}
    plan = generate_arguments(schema, ["file"], marker="DATA", max_candidates=8)

    assert any(candidate.path_slots == (("payload", "address"),) for candidate in plan.candidates)
    assert not plan.issues


@pytest.mark.parametrize("ref", ["https://invalid.example/schema.json", "#/missing"])
def test_unresolvable_references_are_explicit_coverage_gaps(ref: str) -> None:
    schema = _object({"value": {"$ref": ref}})
    plan = generate_arguments(schema, ["file"], marker="DATA", max_candidates=8)

    assert not plan.candidates
    assert any("reference" in issue for issue in plan.issues)


def test_recursive_reference_stops_with_a_reported_gap() -> None:
    schema = _object({"next": {"$ref": "#"}})
    plan = generate_arguments(schema, ["file"], marker="DATA", max_candidates=8)

    assert not plan.candidates
    assert any("recursive reference" in issue for issue in plan.issues)


def test_unsupported_intersection_does_not_claim_schema_coverage() -> None:
    plan = generate_arguments({"allOf": [_object({})]}, [], marker="DATA", max_candidates=8)

    assert not plan.candidates
    assert any("unsupported generation keyword: allOf" in issue for issue in plan.issues)


def test_every_returned_pattern_constrained_candidate_passes_validation() -> None:
    schema = _object({"a": {"type": "string", "pattern": "^safe/", "minLength": 7}})
    plan = generate_arguments(schema, ["bad", "safe/file"], marker="DATA", max_candidates=8)

    assert [candidate.arguments for candidate in plan.candidates] == [{"a": "safe/file"}]
    assert any("sample rejected" in issue for issue in plan.issues)


def test_union_branches_and_empty_array_are_sampled() -> None:
    schema = _object(
        {
            "value": {
                "anyOf": [
                    {"type": "array", "items": {"type": "string"}, "maxItems": 1},
                    {"type": "null"},
                ]
            }
        }
    )
    plan = generate_arguments(schema, ["file"], marker="DATA", max_candidates=12)

    assert any(candidate.arguments == {"value": []} for candidate in plan.candidates)
    assert any(candidate.arguments == {"value": None} for candidate in plan.candidates)
    assert any(candidate.path_slots == (("value", 0),) for candidate in plan.candidates)


def test_invalid_schema_is_reported_without_generation() -> None:
    plan = generate_arguments({"type": "unknown"}, [], marker="DATA", max_candidates=8)

    assert not plan.candidates
    assert any("invalid JSON Schema" in issue for issue in plan.issues)


def test_no_paths_still_generates_a_valid_marker_call() -> None:
    schema = _object({"value": {"type": "string"}})
    plan = generate_arguments(schema, [], marker="DATA", max_candidates=8)

    assert len(plan.candidates) == 1
    assert plan.candidates[0].arguments == {"value": "DATA"}
    assert plan.candidates[0].path_slots == ()
    assert not plan.truncated


def test_generation_is_deterministic_and_does_not_mutate_schema() -> None:
    schema = _object({"value": {"type": "string", "default": "literal"}})
    before = repr(schema)
    first = generate_arguments(schema, ["one", "two"], marker="DATA", max_candidates=8)
    second = generate_arguments(schema, ["one", "two"], marker="DATA", max_candidates=8)

    assert first == second
    assert repr(schema) == before
    first.candidates[0].arguments["value"] = "changed"
    assert repr(schema) == before


def test_generation_rejects_nonpositive_budgets() -> None:
    with pytest.raises(ValueError, match="positive"):
        generate_arguments({}, [], marker="DATA", max_candidates=0)


@pytest.mark.parametrize(
    "numeric",
    [
        {"type": "number", "exclusiveMinimum": 0.2, "exclusiveMaximum": 0.3},
        {"type": "integer", "exclusiveMinimum": -2, "exclusiveMaximum": 0},
        {"type": "number", "maximum": -1, "multipleOf": 3},
        {"type": "integer", "minimum": 5, "maximum": 6, "multipleOf": 3},
    ],
)
def test_numeric_constraints_generate_an_executable_value(numeric: dict[str, Any]) -> None:
    schema = _object({"number": numeric})
    plan = generate_arguments(schema, [], marker="DATA", max_candidates=4)

    assert plan.candidates
    for candidate in plan.candidates:
        Draft202012Validator(schema).validate(candidate.arguments)


def test_nonobject_root_is_a_reported_gap_instead_of_an_exception() -> None:
    plan = generate_arguments({"type": "string"}, ["file"], marker="DATA", max_candidates=4)

    assert not plan.candidates
    assert any("non-object" in issue for issue in plan.issues)


def test_false_optional_schema_can_be_omitted() -> None:
    schema = {"type": "object", "properties": {"impossible": False}}
    plan = generate_arguments(schema, ["file"], marker="DATA", max_candidates=4)

    assert len(plan.candidates) == 1
    assert plan.candidates[0].arguments == {}


def test_content_role_can_use_observed_values_without_marking_them_as_paths() -> None:
    schema = {
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
        },
        "required": ["path", "edits"],
    }

    plan = generate_arguments(
        schema,
        ["config.txt"],
        marker="replacement",
        max_candidates=16,
        path_slot_predicate=lambda address, _schema: bool(address) and address[0] == "path",
        literal_value_provider=lambda address, _schema: (
            ("current file contents",) if address and address[-1] == "oldText" else ()
        ),
    )

    candidate = next(
        item
        for item in plan.candidates
        if item.arguments.get("edits")
        and item.arguments["edits"][0]["oldText"] == "current file contents"
    )
    assert candidate.arguments["path"] == "config.txt"
    assert candidate.path_slots == (("path",),)


def test_preferred_resource_pairs_are_generated_before_cartesian_sampling() -> None:
    schema = _object(
        {
            "source": {"type": "string"},
            "destination": {"type": "string"},
        }
    )
    plan = generate_arguments(
        schema,
        [*(f"resource-{index}" for index in range(64)), "payload", "protected"],
        marker="DATA",
        max_candidates=1,
        preferred_path_pairs=(("payload", "protected"),),
    )

    assert plan.candidates[0].arguments == {
        "destination": "payload",
        "source": "protected",
    } or plan.candidates[0].arguments == {
        "destination": "protected",
        "source": "payload",
    }
