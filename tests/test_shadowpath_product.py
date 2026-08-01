from __future__ import annotations

import json
from pathlib import Path

import pytest

from velvet.cli import main as velvet_main
from velvet.shadowpath_product import (
    EXIT_EFFECT_BREACH,
    PROJECT_RESULTS_SCHEMA_VERSION,
    build_demo_payload,
    init_shadowpath_project,
    render_share_pack,
    run_shadowpath_project,
)


def test_demo_replay_is_explicit_and_writes_share_pack(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_dir = tmp_path / "demo"
    assert (
        velvet_main(
            ["shadowpath", "demo", "--output-dir", str(output_dir), "--json"]
        )
        == 0
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["mode"] == "committed_fixture_replay"
    assert payload["summary"]["effect_breach_count"] == 8
    assert (output_dir / "results" / "v0.4.0--shadowpath-replay.json").is_file()
    assert (output_dir / "share" / "shadowpath-card-x.png").is_file()
    assert (output_dir / "share" / "shadowpath-badge.svg").is_file()
    assert (output_dir / "share" / "shadowpath-carousel-05.png").is_file()


def test_scaffold_runs_as_a_custom_effect_project(tmp_path: Path) -> None:
    project_dir = tmp_path / "my-effect"
    created = init_shadowpath_project(project_dir)
    assert project_dir / "shadowpath.json" in created
    assert project_dir / "adapter.py" in created

    payload = run_shadowpath_project(
        project_dir / "shadowpath.json",
        tmp_path / "reports",
    )

    assert payload["schema_version"] == PROJECT_RESULTS_SCHEMA_VERSION
    assert payload["exit_code"] == EXIT_EFFECT_BREACH
    assert payload["summary"]["overall_verdict"] == "CONTROL_FALSE_SUCCESS"
    assert payload["summary"]["effect_breach_count"] == 3
    assert payload["protected_route"]["route_authorization_passed"] is True


def test_custom_project_cli_preserves_strict_and_expected_breach_modes(
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    assert velvet_main(["shadowpath", "init", str(project_dir)]) == 0

    base = [
        "shadowpath",
        "run",
        "--project",
        str(project_dir / "shadowpath.json"),
        "--output-dir",
        str(tmp_path / "strict"),
    ]
    assert velvet_main(base) == EXIT_EFFECT_BREACH
    assert velvet_main([*base, "--expect-breach"]) == 0


def test_share_pack_is_exact_and_deterministic(tmp_path: Path) -> None:
    payload = build_demo_payload(tmp_path / "demo")
    first = render_share_pack(payload, tmp_path / "first", presets=("x",))
    render_share_pack(payload, tmp_path / "second", presets=("x",))

    first_svg = (tmp_path / "first" / "shadowpath-card-x.svg").read_text(
        encoding="utf-8"
    )
    second_svg = (tmp_path / "second" / "shadowpath-card-x.svg").read_text(
        encoding="utf-8"
    )
    assert first_svg == second_svg
    assert "CONTROL_FALSE_SUCCESS" in first_svg
    assert "8/8" in first_svg
    assert (tmp_path / "first" / "shadowpath-card-x.png").read_bytes().startswith(
        b"\x89PNG\r\n\x1a\n"
    )
    assert {item["preset"] for item in first["files"] if "preset" in item} == {"x"}
