#!/usr/bin/env python3
"""Fail if a tree about to be published publicly still carries private material.

Reused by the OSS exporter (as a post-export assertion) and by CI. It checks a
candidate public tree for five classes of leak:

1. Blocklisted top-level paths (enterprise source, investor/commercial docs,
   generated reports, local Codex thread transcripts, local databases) that
   must never reach the public repo.
2. Packaging wiring that references a stripped private package.
3. OSS export manifest references to paths that must not be published.
4. Release manifest references to paths that must not be published.
5. Local absolute-path fragments (the maintainer's home directory).

Mirrors ``BLOCKLIST_PATTERNS`` in ``export_oss_tree.py``; keep the two in sync.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Assembled at runtime so this file never contains the literal home path (which
# would trip its own scan and the exporter's assert_scrubbed).
_LOCAL_USER = "paul" + "chumbe"
_PRIVATE_PACKAGE = "velvet" + "_enterprise"
_AWS_SHARED_SAAS_MIGRATION = "0002_" + "aws_shared" + "_saas_mvp.py"


def _public_path(*parts: str) -> str:
    return "/".join(parts)


FORBIDDEN_PRIVATE_SOURCE = _public_path("src", _PRIVATE_PACKAGE)
FORBIDDEN_AWS_SHARED_SAAS_MIGRATION = _public_path(
    "db",
    "migrations",
    _AWS_SHARED_SAAS_MIGRATION,
)
FORBIDDEN_TERRAFORM_PREFIX = _public_path("infra", "aws", "terraform")
FORBIDDEN_CODEX_THREADS_PREFIX = _public_path("threads")
FORBIDDEN_OSS_DOCS_PREFIX = _public_path("docs", "oss")

FORBIDDEN_TOP_LEVEL = (
    "archive",
    "concepts",
    "db",
    "docker-compose.enterprise.yml",
    "docs/commercial",
    "docs/diligence",
    "docs/enterprise",
    "docs/fundraise",
    "docs/investors",
    "docs/marketing",
    FORBIDDEN_OSS_DOCS_PREFIX,
    "infra",
    "reports",
    "results",
    FORBIDDEN_PRIVATE_SOURCE,
)

FORBIDDEN_OSS_EXPORT_PATHS = (
    FORBIDDEN_PRIVATE_SOURCE,
    FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
)

FORBIDDEN_OSS_EXPORT_PREFIXES = (
    FORBIDDEN_TERRAFORM_PREFIX,
    FORBIDDEN_CODEX_THREADS_PREFIX,
)

FORBIDDEN_MANIFEST_PATH_FRAGMENTS = (
    (FORBIDDEN_PRIVATE_SOURCE, FORBIDDEN_PRIVATE_SOURCE),
    (
        FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
        FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
    ),
    (FORBIDDEN_TERRAFORM_PREFIX, FORBIDDEN_TERRAFORM_PREFIX + "/*"),
    (
        f'"{FORBIDDEN_CODEX_THREADS_PREFIX}/',
        FORBIDDEN_CODEX_THREADS_PREFIX + "/*",
    ),
)

LOCAL_PATH_FRAGMENTS = ("/Users/" + _LOCAL_USER, "/home/" + _LOCAL_USER)
FORBIDDEN_EXACT_TEXT_FRAGMENTS = (
    _PRIVATE_PACKAGE,
    FORBIDDEN_PRIVATE_SOURCE,
    FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
    FORBIDDEN_TERRAFORM_PREFIX,
)

# Private packages whose wiring must not survive in the public pyproject.
FORBIDDEN_PYPROJECT_REFS = (_PRIVATE_PACKAGE,)

_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}


def check(root: Path) -> list[str]:
    """Return a list of publish-safety problems for ``root`` (empty == safe)."""

    problems: list[str] = []

    for rel in FORBIDDEN_OSS_EXPORT_PATHS:
        if (root / rel).exists():
            problems.append(f"forbidden OSS export path present: {rel}")
    for prefix in FORBIDDEN_OSS_EXPORT_PREFIXES:
        prefix_root = root / prefix
        if prefix_root.exists():
            leaked = next(
                (
                    path.relative_to(root).as_posix()
                    for path in sorted(prefix_root.rglob("*"))
                    if path.is_file()
                ),
                prefix,
            )
            problems.append(f"forbidden OSS export path present: {leaked}")

    for rel in FORBIDDEN_TOP_LEVEL:
        if (root / rel).exists():
            problems.append(f"forbidden private path present: {rel}")

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8")
        for needle in FORBIDDEN_PYPROJECT_REFS:
            if needle in text:
                problems.append(
                    f"pyproject.toml references stripped private package: {needle}"
                )

    for manifest in _manifest_files(root):
        manifest_text = manifest.read_text(encoding="utf-8")
        manifest_label = _manifest_label(root, manifest)
        for needle, display in FORBIDDEN_MANIFEST_PATH_FRAGMENTS:
            if needle in manifest_text:
                problems.append(
                    f"{manifest_label} references forbidden private path: {display}"
                )

    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.suffix.lower() in _BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for needle in LOCAL_PATH_FRAGMENTS:
            if needle in text:
                problems.append(f"{path.relative_to(root)} contains local path {needle}")
                break
        for needle in FORBIDDEN_EXACT_TEXT_FRAGMENTS:
            if needle in text:
                problems.append(
                    f"{path.relative_to(root)} contains forbidden private fragment: {needle}"
                )
                break

    return problems


def _manifest_files(root: Path) -> list[Path]:
    manifests = {path for path in root.rglob("*.manifest.json") if path.is_file()}
    oss_manifest = root / "OSS_EXPORT_MANIFEST.json"
    if oss_manifest.is_file():
        manifests.add(oss_manifest)
    return sorted(manifests, key=lambda path: path.relative_to(root).as_posix())


def _manifest_label(root: Path, path: Path) -> str:
    if path.name == "OSS_EXPORT_MANIFEST.json":
        return "OSS export manifest"
    return f"release manifest {path.relative_to(root).as_posix()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", nargs="?", default="build/oss/velvet")
    args = parser.parse_args()

    root = Path(args.tree).resolve()
    if not root.exists():
        print(f"publish-safety: tree not found: {root}", file=sys.stderr)
        return 2

    problems = check(root)
    if problems:
        print("publish-safety: FAIL", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(f"publish-safety: OK ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
