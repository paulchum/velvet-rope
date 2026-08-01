#!/usr/bin/env python3
"""Validate standalone AAB evidence pointers resolve inside the repository."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

JSON_SUFFIXES = {".json"}
TEXT_SUFFIXES = {".md"}
SKIP_DIRS = {".git", ".venv", ".v", "__pycache__", ".pytest_cache", ".hypothesis"}
BACKTICK_PATH_RE = re.compile(r"`([^`]+(?:\.json|\.jsonl)(?:#/[^`]*)?)`")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    errors = check_evidence_pointers(root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("accepted: evidence pointers resolve")
    return 0


def check_evidence_pointers(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in JSON_SUFFIXES:
            errors.extend(_check_json_file(root, path, rel))
        elif path.suffix.lower() in TEXT_SUFFIXES:
            errors.extend(_check_markdown_file(root, path, rel))
    return errors


def _iter_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_file():
            yield path


def _check_json_file(root: Path, path: Path, rel: str) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for pointer_path, value in _iter_interesting_json_strings(payload):
        errors.extend(_check_reference(root, rel, pointer_path, value))
    return errors


def _iter_interesting_json_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if isinstance(item, str) and _interesting_key(str(key)):
                yield child_path, item
            else:
                yield from _iter_interesting_json_strings(item, child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_interesting_json_strings(item, f"{path}[{index}]")


def _interesting_key(key: str) -> bool:
    return key == "evidence_pointer" or key.endswith("_path")


def _check_markdown_file(root: Path, path: Path, rel: str) -> list[str]:
    errors: list[str] = []
    evidence_index: int | None = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        cells = _markdown_table_cells(line)
        if cells is None:
            evidence_index = None
            continue
        if any(cell.strip().lower() == "evidence" for cell in cells):
            evidence_index = next(
                index for index, cell in enumerate(cells) if cell.strip().lower() == "evidence"
            )
            continue
        if evidence_index is None or _is_markdown_separator_row(cells):
            continue
        if evidence_index >= len(cells):
            continue
        for match in BACKTICK_PATH_RE.finditer(cells[evidence_index]):
            value = match.group(1)
            errors.extend(_check_reference(root, rel, f"line {line_number}", value))
    return errors


def _markdown_table_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _is_markdown_separator_row(cells: list[str]) -> bool:
    return all(set(cell.replace(" ", "")) <= {"-", ":"} for cell in cells)


def _check_reference(root: Path, source_rel: str, pointer_path: str, value: str) -> list[str]:
    if _skip_reference(value):
        return []
    file_part = value.split("#/", 1)[0]
    if not file_part:
        return []
    target = (root / file_part).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return [f"{source_rel}:{pointer_path}: reference escapes repo root: {value}"]
    if not target.exists():
        return [f"{source_rel}:{pointer_path}: missing referenced file: {value}"]
    return []


def _skip_reference(value: str) -> bool:
    return (
        not value
        or value.startswith(("http://", "https://", "repo://"))
        or value.startswith("#/")
        or value.startswith("sha256:")
    )


if __name__ == "__main__":
    raise SystemExit(main())
