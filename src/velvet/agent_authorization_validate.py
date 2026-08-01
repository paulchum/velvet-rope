"""CLI validation helpers for Agent Authorization Benchmark artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from velvet.agent_authorization_benchmark import (
    BENCHMARK_VERSION,
    CAPABILITY_KEYS,
    DEFAULT_REPEAT_COUNT,
    LEADERBOARD_SCHEMA_VERSION,
    RESULTS_SCHEMA_VERSION,
    SUBMISSION_SCHEMA_VERSION,
    append_submission_to_leaderboard,
    load_submission_from_adapter_command,
    validate_agent_authorization_submission,
)
from velvet.shadowpath import (
    REQUIRED_ROUTE_IDS,
    SHADOWPATH_CAPABILITY_KEYS,
    SHADOWPATH_SCHEMA_VERSION,
)

JsonObject = dict[str, Any]

COMPARISON_SCHEMA_VERSION = "velvet.agent_authorization.comparison.v0.1"
COMPARISON_CAPABILITY_KEYS = (
    "pre_execution_decision",
    "deterministic_decision",
    "signed_artifact",
    "public_verification",
    "tamper_evidence",
    "replayable_artifact",
    "binding_depth",
    "drift_rejection",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Agent Authorization Benchmark submissions and result files.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Benchmark result, comparison result, leaderboard, or submission JSON files.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--submission", help="Path to a JSON submission.")
    source.add_argument("--adapter-command", help="Command that emits one JSON submission.")
    parser.add_argument(
        "--append-to",
        default="benchmarks/agent_authorization/results/community_leaderboard.json",
        help="Leaderboard JSON file to append --submission or --adapter-command output to.",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.paths and (args.submission or args.adapter_command):
        return _reject(
            "--submission/--adapter-command cannot be combined with positional paths",
            json_output=bool(args.json),
        )

    if args.paths:
        errors = _validate_files([Path(path) for path in args.paths])
        if errors:
            return _reject("; ".join(errors), json_output=bool(args.json))
        result: JsonObject = {"status": "accepted", "validated_files": len(args.paths)}
        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(f"accepted: validated {len(args.paths)} file(s)")
        return 0

    if not args.submission and not args.adapter_command:
        parser.error("provide positional paths, --submission, or --adapter-command")

    try:
        if args.submission:
            payload = json.loads(Path(args.submission).read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("submission must be a JSON object")
            submission = cast(JsonObject, payload)
        else:
            submission = load_submission_from_adapter_command(str(args.adapter_command))
        errors = validate_agent_authorization_submission(submission)
        if errors:
            raise ValueError("; ".join(errors))
        leaderboard = append_submission_to_leaderboard(submission, args.append_to)
    except Exception as error:  # noqa: BLE001 - CLI reports one concise validation error.
        return _reject(str(error), json_output=bool(args.json))

    result = {
        "status": "accepted",
        "leaderboard_path": str(args.append_to),
        "submission_count": len(leaderboard["submissions"]),
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"accepted: appended to {args.append_to}")
    return 0


def _reject(error: str, *, json_output: bool) -> int:
    result: JsonObject = {"status": "rejected", "error": error}
    if json_output:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"rejected: {error}", file=sys.stderr)
    return 1


def _validate_files(paths: Sequence[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:  # noqa: BLE001 - include path-specific parse errors.
            errors.append(f"{path}: {error}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path}: expected a JSON object")
            continue
        errors.extend(f"{path}: {error}" for error in _validate_artifact(cast(JsonObject, payload)))
    return errors


def _validate_artifact(payload: Mapping[str, Any]) -> list[str]:
    schema_version = payload.get("schema_version")
    if schema_version == SUBMISSION_SCHEMA_VERSION:
        return validate_agent_authorization_submission(payload)
    if schema_version == LEADERBOARD_SCHEMA_VERSION:
        return _validate_leaderboard(payload)
    if schema_version == RESULTS_SCHEMA_VERSION:
        return _validate_results_payload(payload)
    if schema_version == COMPARISON_SCHEMA_VERSION:
        return _validate_comparison_payload(payload)
    if schema_version == SHADOWPATH_SCHEMA_VERSION:
        return _validate_shadowpath_payload(payload)
    return [f"unsupported schema_version: {schema_version!r}"]


def _validate_leaderboard(payload: Mapping[str, Any]) -> list[str]:
    errors = _validate_common_benchmark_fields(payload)
    submissions = payload.get("submissions")
    if not isinstance(submissions, list):
        errors.append("submissions must be a list")
        return errors
    for index, submission in enumerate(submissions):
        if not isinstance(submission, Mapping):
            errors.append(f"submissions[{index}] must be an object")
            continue
        for error in validate_agent_authorization_submission(submission):
            errors.append(f"submissions[{index}]: {error}")
    return errors


def _validate_results_payload(payload: Mapping[str, Any]) -> list[str]:
    errors = _validate_common_benchmark_fields(payload)
    if "system_result" in payload:
        system_result = payload.get("system_result")
        if not isinstance(system_result, Mapping):
            errors.append("system_result must be an object")
        else:
            errors.extend(_validate_result_row(system_result, CAPABILITY_KEYS))
        return errors
    matrix = payload.get("capability_matrix")
    if not isinstance(matrix, list):
        errors.append("capability_matrix must be a list")
        return errors
    for index, row in enumerate(matrix):
        if not isinstance(row, Mapping):
            errors.append(f"capability_matrix[{index}] must be an object")
            continue
        for error in _validate_result_row(row, CAPABILITY_KEYS):
            errors.append(f"capability_matrix[{index}]: {error}")
    return errors


def _validate_comparison_payload(payload: Mapping[str, Any]) -> list[str]:
    errors = _validate_common_benchmark_fields(payload)
    if "system_result" in payload:
        system_result = payload.get("system_result")
        if not isinstance(system_result, Mapping):
            errors.append("system_result must be an object")
        else:
            errors.extend(_validate_result_row(system_result, COMPARISON_CAPABILITY_KEYS))
        return errors
    matrix = payload.get("capability_matrix")
    if not isinstance(matrix, list):
        errors.append("capability_matrix must be a list")
        return errors
    for index, row in enumerate(matrix):
        if not isinstance(row, Mapping):
            errors.append(f"capability_matrix[{index}] must be an object")
            continue
        for error in _validate_result_row(row, COMPARISON_CAPABILITY_KEYS):
            errors.append(f"capability_matrix[{index}]: {error}")
    return errors


def _validate_shadowpath_payload(payload: Mapping[str, Any]) -> list[str]:
    errors = _validate_common_benchmark_fields(payload)
    if payload.get("exit_code") == 2:
        if payload.get("status") not in {
            "INVENTORY_INCOMPLETE",
            "CONFIGURATION_ERROR",
        }:
            errors.append(
                "exit_code 2 requires status INVENTORY_INCOMPLETE "
                "or CONFIGURATION_ERROR"
            )
        return errors
    if payload.get("exit_code") == 4:
        if payload.get("status") != "AGENT_ADAPTER_ERROR":
            errors.append("exit_code 4 requires status AGENT_ADAPTER_ERROR")
        return errors
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, Mapping):
        errors.append("capabilities must be an object")
    else:
        missing = [
            key for key in SHADOWPATH_CAPABILITY_KEYS if key not in capabilities
        ]
        extra = sorted(
            set(str(key) for key in capabilities) - set(SHADOWPATH_CAPABILITY_KEYS)
        )
        if missing:
            errors.append(f"missing ShadowPath capabilities: {missing}")
        if extra:
            errors.append(f"unsupported ShadowPath capabilities: {extra}")
        for key in SHADOWPATH_CAPABILITY_KEYS:
            cell = capabilities.get(key)
            if isinstance(cell, Mapping):
                errors.extend(
                    f"{key}: {error}" for error in _validate_result_capability(cell)
                )
    routes = payload.get("route_results")
    if not isinstance(routes, list):
        errors.append("route_results must be a list")
        return errors
    route_ids: list[str] = []
    for index, result in enumerate(routes):
        if not isinstance(result, Mapping):
            errors.append(f"route_results[{index}] must be an object")
            continue
        route = result.get("route")
        if not isinstance(route, Mapping):
            errors.append(f"route_results[{index}].route must be an object")
            continue
        route_id = route.get("route_id")
        if not isinstance(route_id, str):
            errors.append(f"route_results[{index}].route.route_id must be a string")
        else:
            route_ids.append(route_id)
        if not isinstance(result.get("effect_observed"), bool):
            errors.append(f"route_results[{index}].effect_observed must be boolean")
        for field in ("pre_state", "post_state", "benchmark_reconciliation"):
            if not isinstance(result.get(field), Mapping):
                errors.append(f"route_results[{index}].{field} must be an object")
    if set(route_ids) != set(REQUIRED_ROUTE_IDS) or len(route_ids) != len(
        REQUIRED_ROUTE_IDS
    ):
        errors.append(
            "route_results must contain each required ShadowPath route exactly once"
        )
    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        errors.append("summary must be an object")
    elif summary.get("overall_verdict") == "CONTROL_FALSE_SUCCESS":
        if summary.get("route_authorization_reported_success") is not True:
            errors.append(
                "CONTROL_FALSE_SUCCESS requires route authorization success"
            )
        breach_count = summary.get("effect_breach_count")
        if not isinstance(breach_count, int) or breach_count < 1:
            errors.append("CONTROL_FALSE_SUCCESS requires at least one effect breach")
        if payload.get("exit_code") != 3:
            errors.append("CONTROL_FALSE_SUCCESS requires exit_code 3")
    return errors


def _validate_common_benchmark_fields(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("benchmark_version") != BENCHMARK_VERSION:
        errors.append(f"benchmark_version must be {BENCHMARK_VERSION!r}")
    repeat_count = payload.get("repeat_count")
    if repeat_count is not None and (
        not isinstance(repeat_count, int) or repeat_count < DEFAULT_REPEAT_COUNT
    ):
        errors.append(f"repeat_count must be an integer >= {DEFAULT_REPEAT_COUNT}")
    return errors


def _validate_result_row(
    row: Mapping[str, Any],
    capability_keys: Sequence[str],
) -> list[str]:
    errors: list[str] = []
    system = row.get("system")
    if not isinstance(system, str) or not system.strip():
        errors.append("system must be a non-empty string")
    capabilities = row.get("capabilities")
    if not isinstance(capabilities, Mapping):
        errors.append("capabilities must be an object")
        return errors
    missing = [key for key in capability_keys if key not in capabilities]
    extra = sorted(set(str(key) for key in capabilities) - set(capability_keys))
    if missing:
        errors.append(f"missing capabilities: {missing}")
    if extra:
        errors.append(f"unsupported capabilities: {extra}")
    for key in capability_keys:
        capability = capabilities.get(key)
        if not isinstance(capability, Mapping):
            continue
        errors.extend(f"{key}: {error}" for error in _validate_result_capability(capability))
    return errors


def _validate_result_capability(capability: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    status = capability.get("status")
    value = capability.get("value")
    if status not in {"pass", "fail", "not_measured"}:
        errors.append("status must be pass, fail, or not_measured")
    if status == "pass" and value is not True:
        errors.append("pass requires value=true")
    if status == "fail" and value is not False:
        errors.append("fail requires value=false")
    if status == "not_measured" and value is not None:
        errors.append("not_measured requires value=null")
    pointer = capability.get("evidence_pointer")
    if not isinstance(pointer, str) or not pointer.strip():
        errors.append("evidence_pointer is required")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
