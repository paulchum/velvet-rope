"""Fail if npm project files are introduced in the Rust/Python v1 workspace."""

from __future__ import annotations

from pathlib import Path

BLOCKED_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}
# ``site`` is an independently versioned hosted marketing application, not
# part of the Python/Rust package or its publishable OSS export.
SKIPPED_DIRS = {".venv", "__pycache__", "site", "third_party"}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    found = sorted(
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file()
        and path.name in BLOCKED_FILES
        and not any(part in SKIPPED_DIRS for part in path.parts)
    )
    if found:
        print("npm or JavaScript package-manager files are out of scope for this workspace:")
        for path in found:
            print(f"- {path}")
        return 1
    print("No npm package-manager files found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
