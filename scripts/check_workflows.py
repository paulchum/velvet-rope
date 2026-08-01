"""Policy checks for GitHub Actions workflow hardening."""

from __future__ import annotations

import re
from pathlib import Path

FULL_SHA = re.compile(r"^[a-f0-9]{40}$")
USES_LINE = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workflow_dir = root / ".github" / "workflows"
    failures: list[str] = []
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        content = path.read_text(encoding="utf-8")
        rel = path.relative_to(root)
        if "pull_request_target" in content:
            failures.append(f"{rel}: pull_request_target is not allowed")
        if "permissions: write-all" in content:
            failures.append(f"{rel}: write-all permissions are not allowed")
        if "PYPI_API_TOKEN" in content or "NPM_TOKEN" in content:
            failures.append(f"{rel}: long-lived publish token reference is not allowed")
        if "release" in path.name and re.search(r"\bcache\b", content, flags=re.IGNORECASE):
            failures.append(f"{rel}: release workflows must not use dependency caches")
        for action, ref in USES_LINE.findall(content):
            if action.startswith("./"):
                continue
            if not FULL_SHA.fullmatch(ref):
                failures.append(f"{rel}: {action}@{ref} must be pinned by full commit SHA")
    if failures:
        for failure in failures:
            print(failure)
        return 1
    print("Workflow policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
