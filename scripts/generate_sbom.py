"""Generate a minimal CycloneDX-style SBOM from installed Python distributions."""

from __future__ import annotations

import argparse
import json
from importlib import metadata
from pathlib import Path
from tomllib import load as toml_load
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = build_sbom()
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote SBOM to {args.output}")
    return 0


def build_sbom() -> dict[str, Any]:
    components = []
    for dist in sorted(metadata.distributions(), key=lambda item: item.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        version = dist.version
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}",
            }
        )
    components.extend(_cargo_components())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "velvet"}},
        "components": components,
    }


def _cargo_components() -> list[dict[str, str]]:
    lock_path = Path(__file__).resolve().parents[1] / "Cargo.lock"
    if not lock_path.exists():
        return []
    with lock_path.open("rb") as handle:
        payload = toml_load(handle)
    packages = payload.get("package", [])
    if not isinstance(packages, list):
        return []
    components: list[dict[str, str]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:cargo/{name}@{version}",
                }
            )
    return sorted(components, key=lambda item: (item["name"], item["version"]))


if __name__ == "__main__":
    raise SystemExit(main())
