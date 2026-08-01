"""Shared helpers for Velvet public-tree exporters."""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
LOCAL_USER = "paul" + "chumbe"

FORBIDDEN_TEXT = (
    "/Users/" + LOCAL_USER,
    "/home/" + LOCAL_USER,
    LOCAL_USER + "/Developer/velvet",
)

COMPARISON_RELATIVE_DIR = Path("benchmarks/agent_authorization/comparison")
COMPARISON_GENERATED_PATHS = (
    Path("COMPARISON_RESULTS.md"),
    Path("evidence"),
    Path("results"),
)


def assert_scrubbed(root: Path) -> None:
    """Fail if exported text files contain local-only absolute path fragments."""

    violations: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or binary_suffix(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for needle in FORBIDDEN_TEXT:
            if needle in text:
                violations.append(f"{path.relative_to(root)} contains {needle}")
    if violations:
        joined = "\n".join(violations[:50])
        raise SystemExit(f"OSS export scrub failed:\n{joined}")


def binary_suffix(path: Path) -> bool:
    return path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}


def regenerate_agent_authorization_comparison(
    export_root: Path,
    *,
    comparison_rel: Path = COMPARISON_RELATIVE_DIR,
    allow_dirty: bool = False,
) -> None:
    """Regenerate comparison results/evidence inside an exported repository tree."""

    comparison_dir = export_root / comparison_rel
    fixture_dir = comparison_dir / "fixtures"
    if not fixture_dir.exists():
        raise SystemExit(f"comparison fixture directory missing: {fixture_dir}")
    for relpath in COMPARISON_GENERATED_PATHS:
        target = comparison_dir / relpath
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()

    from velvet.agent_authorization_comparison import run_agent_authorization_comparison

    run_agent_authorization_comparison(
        comparison_dir,
        fixture_dir=fixture_dir,
        allow_dirty=allow_dirty,
    )
    _relativize_generated_comparison_paths(export_root, comparison_dir)


def _relativize_generated_comparison_paths(export_root: Path, comparison_dir: Path) -> None:
    for path in sorted(comparison_dir.rglob("*")):
        if path.is_dir() or binary_suffix(path):
            continue
        if path.suffix.lower() in {".json", ".jsonl"}:
            _relativize_json_file(path, export_root)
        elif path.suffix.lower() in {".md", ".txt"}:
            _relativize_text_file(path, export_root)


def _relativize_json_file(path: Path, export_root: Path) -> None:
    if path.suffix.lower() == ".jsonl":
        lines: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            lines.append(json.dumps(_relativize_value(payload, export_root), sort_keys=True))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    payload = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(
        json.dumps(_relativize_value(payload, export_root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _relativize_text_file(path: Path, export_root: Path) -> None:
    text = path.read_text(encoding="utf-8")
    path.write_text(_relativize_string(text, export_root), encoding="utf-8")


def _relativize_value(value: Any, export_root: Path) -> Any:
    if isinstance(value, Mapping):
        return {key: _relativize_value(item, export_root) for key, item in value.items()}
    if isinstance(value, list):
        return [_relativize_value(item, export_root) for item in value]
    if isinstance(value, str):
        return _relativize_string(value, export_root)
    return value


def _relativize_string(value: str, export_root: Path) -> str:
    resolved_root = export_root.resolve()
    replacements = {
        resolved_root.as_posix() + "/": "",
        resolved_root.as_uri() + "/": "repo://",
    }
    try:
        build_prefix = resolved_root.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        build_prefix = ""
    if build_prefix:
        replacements[build_prefix + "/"] = ""
        replacements["repo://" + build_prefix + "/"] = "repo://"
    output = value
    for needle, replacement in replacements.items():
        output = output.replace(needle, replacement)
    return output


def read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return cast(dict[str, Any], payload)
