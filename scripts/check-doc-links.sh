#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path.cwd()
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")

errors: list[str] = []


def is_external(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https", "mailto", "app"}


def strip_target(raw: str) -> str:
    target = raw.strip()
    if not target:
        return target
    if target[0] in {'"', "'"} and target[-1:] == target[0]:
        target = target[1:-1]
    if " " in target and not target.startswith("<"):
        target = target.split(" ", 1)[0]
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    return unquote(target)


for md_path in sorted(ROOT.rglob("*.md")):
    if any(part in {".git", ".venv", "target", "archive", "third_party"} for part in md_path.parts):
        continue
    if md_path.relative_to(ROOT).parts[:2] == ("reports", "underwriter_review"):
        continue
    text = md_path.read_text(encoding="utf-8", errors="replace")
    for match in LINK_RE.finditer(text):
        target = strip_target(match.group(1))
        if not target or target.startswith("#") or is_external(target):
            continue
        path_part = target.split("#", 1)[0]
        if not path_part:
            continue
        candidate = Path(path_part)
        if candidate.is_absolute():
            resolved = candidate
        else:
            resolved = (md_path.parent / candidate).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"{md_path}: link leaves repo: {target}")
            continue
        if not resolved.exists():
            errors.append(f"{md_path}: missing link target: {target}")

if errors:
    print("Markdown link check failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print("Markdown link check passed.")
PY
