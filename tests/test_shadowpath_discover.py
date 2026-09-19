"""The discovery CLI passes explicit budgets and defaults to inferred assets."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from velvet.shadowpath_discover import main
from velvet.shadowpath_explorer import ShadowPathExplorerError


def _arguments(tmp_path: Path) -> list[str]:
    arguments: list[str] = []
    for name in ("pipelock", "config", "node", "server-entrypoint", "work-root", "baseline-root"):
        arguments.extend([f"--{name}", str(tmp_path / name)])
    return [*arguments, "--output", str(tmp_path / "report.json")]


def test_cli_defaults_to_discovery_and_writes_report(tmp_path: Path) -> None:
    target = Mock()
    report = {"scope_source": "observed_inventory", "confirmed_breaches": []}
    with (
        patch(
            "velvet.shadowpath_discover.PipelockFilesystemTarget", return_value=target
        ) as factory,
        patch("velvet.shadowpath_discover.explore", return_value=report) as explore,
    ):
        assert main(_arguments(tmp_path)) == 0
    assert factory.call_args.kwargs["baseline_root"] == tmp_path / "baseline-root"
    assert factory.call_args.kwargs["external_lock"] is None
    explore.assert_called_once_with(
        target=target,
        scope=None,
        breach_statuses=None,
        max_depth=3,
        max_trials=1000,
        max_calls=5000,
        max_paths_per_state=64,
        max_arguments_per_operation_state=32,
    )
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8")) == report
    target.close.assert_called_once()


def test_cli_passes_declared_assets_and_budget_overrides(tmp_path: Path) -> None:
    target = Mock()
    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget", return_value=target),
        patch("velvet.shadowpath_discover.explore", return_value={}) as explore,
    ):
        main(
            [
                *_arguments(tmp_path),
                "--protected",
                "./docs//settings",
                "--max-depth",
                "4",
                "--max-trials",
                "20",
                "--max-calls",
                "60",
                "--breach-status",
                "replaced",
            ]
        )
    kwargs = explore.call_args.kwargs
    assert [asset.path for asset in kwargs["scope"].protected] == ["docs/settings"]
    assert (kwargs["max_depth"], kwargs["max_trials"], kwargs["max_calls"]) == (4, 20, 60)
    assert kwargs["breach_statuses"] == ["replaced"]


@pytest.mark.parametrize(
    "invalid", [["--max-depth", "0"], ["--max-trials", "-1"], ["--protected", "../escape"]]
)
def test_invalid_options_do_not_start_target(tmp_path: Path, invalid: list[str]) -> None:
    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget") as factory,
        pytest.raises(SystemExit) as error,
    ):
        main([*_arguments(tmp_path), *invalid])
    assert error.value.code == 2
    factory.assert_not_called()


def test_failure_closes_target_without_overwriting_existing_report(tmp_path: Path) -> None:
    target = Mock()
    output = tmp_path / "report.json"
    output.write_text("previous report", encoding="utf-8")
    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget", return_value=target),
        patch("velvet.shadowpath_discover.explore", side_effect=ShadowPathExplorerError("failed")),
        pytest.raises(SystemExit) as error,
    ):
        main(_arguments(tmp_path))
    assert error.value.code == 2
    assert output.read_text(encoding="utf-8") == "previous report"
    target.close.assert_called_once()


def test_output_cannot_mutate_baseline(tmp_path: Path) -> None:
    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget") as factory,
        pytest.raises(SystemExit),
    ):
        main([*_arguments(tmp_path), "--output", str(tmp_path / "baseline-root" / "report.json")])
    factory.assert_not_called()


def test_output_cannot_be_deleted_by_disposable_trial_cleanup(tmp_path: Path) -> None:
    output = tmp_path / "work-root" / "inventory" / "report.json"
    output.parent.mkdir(parents=True)
    output.write_text("preserve", encoding="utf-8")

    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget") as factory,
        pytest.raises(SystemExit),
    ):
        main([*_arguments(tmp_path), "--output", str(output)])

    assert output.read_text(encoding="utf-8") == "preserve"
    factory.assert_not_called()


def test_cli_derives_scope_and_baseline_when_baseline_is_omitted(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(
        """
    - name: "Protected Configuration Mutation"
      tool_pattern: '(?i)^(write_file|edit_file)$'
      arg_pattern: '(?i)((?:^|/)\\.(interactivecfg|sessioncfg)\\b)'
      action: block
""",
        encoding="utf-8",
    )
    arguments = _arguments(tmp_path)
    baseline_index = arguments.index("--baseline-root")
    del arguments[baseline_index : baseline_index + 2]
    target = Mock()
    with (
        patch(
            "velvet.shadowpath_discover.PipelockFilesystemTarget", return_value=target
        ) as factory,
        patch("velvet.shadowpath_discover.explore", return_value={}) as explore,
    ):
        assert main(arguments) == 0

    scope = explore.call_args.kwargs["scope"]
    assert scope.source == "policy_derived"
    assert {asset.path for asset in scope.protected} == {".interactivecfg", ".sessioncfg"}
    assert scope.payload_paths == (".shadowpath-generated-payload",)
    assert "policy_scope" in explore.call_args.kwargs
    assert factory.call_args.kwargs["baseline_root"].name.startswith(
        "shadowpath-policy-baseline-"
    )


@pytest.mark.parametrize(
    "input_option",
    ["pipelock", "config", "node", "server-entrypoint", "external-lock"],
)
def test_output_cannot_replace_runtime_input_or_symlink_alias(
    tmp_path: Path, input_option: str
) -> None:
    arguments = _arguments(tmp_path)
    if input_option == "external-lock":
        target = tmp_path / "external-lock"
        arguments.extend(["--external-lock", str(target)])
    else:
        target = tmp_path / input_option
    target.write_text("input", encoding="utf-8")
    alias = tmp_path / f"{input_option}-alias"
    alias.symlink_to(target)
    with (
        patch("velvet.shadowpath_discover.PipelockFilesystemTarget") as factory,
        pytest.raises(SystemExit),
    ):
        main([*arguments, "--output", str(alias)])
    assert target.read_text(encoding="utf-8") == "input"
    factory.assert_not_called()


def test_auto_baseline_unions_operator_declared_assets(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(
        """
- name: Protected Configuration Mutation
  tool_pattern: '^write_file$'
  arg_pattern: '(?:^|/)\\.guardedcfg\\b'
  action: block
""",
        encoding="utf-8",
    )
    arguments = _arguments(tmp_path)
    baseline_index = arguments.index("--baseline-root")
    del arguments[baseline_index : baseline_index + 2]
    captured: dict[str, object] = {}

    def target_factory(**kwargs: object) -> Mock:
        baseline = Path(str(kwargs["baseline_root"]))
        captured["paths"] = sorted(
            path.relative_to(baseline).as_posix()
            for path in baseline.rglob("*")
            if path.is_file()
        )
        return Mock()

    with (
        patch(
            "velvet.shadowpath_discover.PipelockFilesystemTarget",
            side_effect=target_factory,
        ),
        patch("velvet.shadowpath_discover.explore", return_value={}) as explore,
    ):
        main([*arguments, "--protected", "manual/guarded.txt"])
    materialized_paths = captured["paths"]
    assert isinstance(materialized_paths, list)
    assert "manual/guarded.txt" in materialized_paths
    assert {asset.path for asset in explore.call_args.kwargs["scope"].protected} >= {
        ".guardedcfg",
        "manual/guarded.txt",
    }
