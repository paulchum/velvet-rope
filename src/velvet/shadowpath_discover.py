"""Bounded filesystem exploration from a supplied disposable baseline.

Run ``python -m velvet.shadowpath_discover --help`` for the required runtime
paths. No route recipes or protected asset declarations are required. With no
``--protected`` declarations, observed changes are impacts requiring review,
not evidence that a policy promise was broken.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from velvet.shadowpath_explorer import (
    ExplorationScope,
    SessionScope,
    ShadowPathExplorerError,
    explore,
)
from velvet.shadowpath_observer import (
    DEFAULT_BREACH_STATUSES,
    ProtectedAsset,
    ShadowPathObserverError,
)
from velvet.shadowpath_pipelock_target import PipelockFilesystemTarget, PipelockTargetError
from velvet.shadowpath_scope import compile_policy_scope, materialize_filesystem_scope


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _protected_asset(value: str) -> ProtectedAsset:
    try:
        return ProtectedAsset(path=value)
    except (ShadowPathObserverError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover bounded MCP filesystem routes from tool schemas and observed state."
    )
    for option, help_text in (
        ("pipelock", "Pipelock executable"),
        ("config", "Pipelock policy configuration"),
        ("node", "Node executable"),
        ("server-entrypoint", "Filesystem MCP server JavaScript entrypoint"),
        ("work-root", "Disposable trial directory outside the real home and baseline"),
        ("output", "Destination for the JSON discovery report"),
    ):
        parser.add_argument(f"--{option}", type=Path, required=True, help=help_text)
    parser.add_argument(
        "--baseline-root",
        type=Path,
        help=(
            "Optional directory copied into each trial. When omitted, ShadowPath derives "
            "and materializes protected assets from the policy configuration."
        ),
    )
    parser.add_argument("--external-lock", type=Path, help="Optional runtime digest lock")
    parser.add_argument(
        "--platform-key",
        help="External-lock platform key; defaults to the current OS and CPU",
    )
    parser.add_argument("--max-depth", type=_positive_int, default=3)
    parser.add_argument("--max-trials", type=_positive_int, default=1_000)
    parser.add_argument("--max-calls", type=_positive_int, default=5_000)
    parser.add_argument("--max-paths-per-state", type=_positive_int, default=64)
    parser.add_argument("--max-arguments-per-operation-state", type=_positive_int, default=32)
    parser.add_argument(
        "--protected",
        type=_protected_asset,
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="Declare an asset that must not change; repeat for multiple assets",
    )
    parser.add_argument(
        "--breach-status",
        choices=sorted(DEFAULT_BREACH_STATUSES),
        action="append",
        default=[],
        help="Asset status that counts as a breach; repeat to override integrity defaults",
    )
    parser.add_argument("--session-scope", choices=("per_call", "per_route"), default="per_call")
    parser.add_argument("--timeout-seconds", type=_positive_int, default=30)
    parser.add_argument("--keep-workspaces", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    work_root = args.work_root.resolve()
    output = args.output.resolve()
    if output.is_relative_to(work_root):
        parser.error("output must be outside the disposable work directory")
    runtime_inputs = {
        "pipelock": args.pipelock,
        "config": args.config,
        "node": args.node,
        "server entrypoint": args.server_entrypoint,
        "external lock": args.external_lock,
    }
    for label, candidate in runtime_inputs.items():
        if candidate is not None and output == candidate.resolve():
            parser.error(f"output must not replace the {label}")
    policy_scope = (
        compile_policy_scope(args.config.read_text(encoding="utf-8"))
        if args.config.is_file()
        else None
    )
    baseline_temporary: tempfile.TemporaryDirectory[str] | None = None
    materialized = None
    scope: ExplorationScope | None
    if args.baseline_root is None:
        if policy_scope is None:
            parser.error("--config must be readable when deriving the baseline")
        baseline_temporary = tempfile.TemporaryDirectory(prefix="shadowpath-policy-baseline-")
        baseline = Path(baseline_temporary.name).resolve()
        materialized = materialize_filesystem_scope(
            root=baseline,
            scope=policy_scope,
            additional_paths=tuple(asset.path for asset in args.protected),
        )
        if not materialized.protected_paths:
            baseline_temporary.cleanup()
            baseline_temporary = None
            parser.error("policy configuration yielded no materializable resource witnesses")
        scope = ExplorationScope(
            protected=tuple(
                ProtectedAsset(
                    path=path,
                    label=f"derived:{','.join(materialized.path_families[path])}",
                )
                for path in materialized.protected_paths
            ),
            payload_paths=(materialized.payload_path,),
            source="policy_derived",
            resource_groups={
                path: materialized.path_families[path][0]
                for path in materialized.protected_paths
            },
        )
    else:
        baseline = args.baseline_root.resolve()
        if output.is_relative_to(baseline):
            parser.error("output must be outside the baseline directory")
        scope = (
            ExplorationScope(protected=tuple(args.protected), source="operator_declared")
            if args.protected
            else None
        )
    target: PipelockFilesystemTarget | None = None
    try:
        target = PipelockFilesystemTarget(
            pipelock=args.pipelock,
            config=args.config,
            node=args.node,
            server_entrypoint=args.server_entrypoint,
            work_root=work_root,
            baseline_root=baseline,
            external_lock=args.external_lock,
            platform_key=args.platform_key,
            session_scope=cast(SessionScope, args.session_scope),
            timeout_seconds=args.timeout_seconds,
            keep_workspaces=args.keep_workspaces,
        )
        explore_options = dict(
            target=target,
            scope=scope,
            breach_statuses=args.breach_status or None,
            max_depth=args.max_depth,
            max_trials=args.max_trials,
            max_calls=args.max_calls,
            max_paths_per_state=args.max_paths_per_state,
            max_arguments_per_operation_state=args.max_arguments_per_operation_state,
        )
        if policy_scope is not None:
            explore_options["policy_scope"] = policy_scope
        report = explore(**explore_options)
        if materialized is not None:
            report["materialized_policy_scope"] = materialized.to_json()
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
    except (
        PipelockTargetError,
        ShadowPathExplorerError,
        ShadowPathObserverError,
        OSError,
        ValueError,
    ) as error:
        parser.exit(2, f"discovery failed: {error}\n")
    finally:
        if target is not None:
            target.close()
        if baseline_temporary is not None:
            baseline_temporary.cleanup()
    print(f"Discovery report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
