#!/usr/bin/env python3
"""Build the standalone Agent Authorization Benchmark repository tree."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from export_common import (
    ROOT,
    assert_scrubbed,
)

BENCHMARK_ROOT = ROOT / "benchmarks" / "agent_authorization"
REPO_STAGING_ROOT = BENCHMARK_ROOT / "repo"
SOURCE_PACKAGE_ROOT = ROOT / "src" / "velvet"
VERIFIER_ROOT = ROOT / "assurance" / "verifier"
OAP_ROOT = ROOT / "third_party" / "oap"
DEMO_KEY_ROOT = ROOT / "tests" / "fixtures" / "keys"

DEFAULT_OUTPUT = "build/oss/agent-authorization-benchmark"
PACKAGE_ROOT = "src/aab"
START_MODULES = (
    "agent_authorization_benchmark",
    "agent_authorization_validate",
    "agent_authorization_comparison",
    "shadowpath",
    "shadowpath_openai_adapter",
    "verify_certificate",
    "passk",
)
OUTPUT_MODULE_NAMES = {
    "agent_authorization_validate": "validate_submission",
}
FORBIDDEN_MODULES = {"_native", "router"}
FORBIDDEN_IMPORT_NAMES = {"Router"}
BLOCKLIST_PATTERNS = {
    ".git",
    ".venv",
    ".v",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.so",
    ".coverage",
}


@dataclass(frozen=True)
class VendoredGraph:
    modules: tuple[str, ...]
    edges: Mapping[str, tuple[str, ...]]


class VendoringError(RuntimeError):
    """Raised when the benchmark export would vendor a forbidden dependency."""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    output = (ROOT / args.out).resolve()
    _assert_safe_output(output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    copied_paths: list[str] = []
    _copy_tree(BENCHMARK_ROOT, output, copied_paths)
    _copy_tree(VERIFIER_ROOT, output / "verifier", copied_paths, source_label="assurance/verifier")
    _copy_tree(
        OAP_ROOT,
        output / "third_party" / "oap",
        copied_paths,
        source_label="third_party/oap",
    )
    _copy_demo_public_key(output / "tests" / "fixtures" / "keys", copied_paths)

    _add_relationship_section(output / "README.md")

    graph = resolve_vendored_modules(START_MODULES)
    vendored_modules = _vendor_modules(graph, output / PACKAGE_ROOT)
    dependencies = _dependencies_for_modules(vendored_modules)
    _write_pyproject(output / "pyproject.toml", _benchmark_version(), dependencies)
    _write_ci(output / ".github" / "workflows" / "ci.yml")
    _copy_repo_staging(REPO_STAGING_ROOT, output, copied_paths)
    _relativize_standalone_paths(output)
    _write_manifest(
        output / "AAB_EXPORT_MANIFEST.json",
        copied_paths=copied_paths,
        vendored_modules=vendored_modules,
        dependencies=dependencies,
    )
    _scrub_public_forbidden_terms(output)
    assert_scrubbed(output)
    print(f"exported standalone Agent Authorization Benchmark to {output}")
    return 0


def resolve_vendored_modules(start_modules: Sequence[str]) -> VendoredGraph:
    """Resolve top-level pure-Python Velvet imports needed by benchmark modules."""

    modules: list[str] = []
    edges: dict[str, tuple[str, ...]] = {}
    queue: list[tuple[str, tuple[str, ...]]] = [(module, (module,)) for module in start_modules]
    while queue:
        module, chain = queue.pop(0)
        _raise_if_forbidden_module(module, chain)
        if module in modules:
            continue
        path = _module_path(module)
        if not path.exists():
            raise VendoringError(f"missing vendored module source: {' -> '.join(chain)}")
        imports = tuple(_top_level_velvet_imports(path, module, chain))
        edges[module] = imports
        modules.append(module)
        for imported in imports:
            queue.append((imported, (*chain, imported)))
    return VendoredGraph(modules=tuple(modules), edges=edges)


def _vendor_modules(graph: VendoredGraph, package_dir: Path) -> list[str]:
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text(
        '"""Standalone Agent Authorization Benchmark package."""\n',
        encoding="utf-8",
    )
    vendored: list[str] = []
    for module in graph.modules:
        source = _module_path(module)
        output_name = OUTPUT_MODULE_NAMES.get(module, module)
        target = package_dir / f"{output_name}.py"
        text = _rewrite_module_source(source.read_text(encoding="utf-8"))
        target.write_text(text, encoding="utf-8")
        _assert_no_velvet_import_leaks(target)
        vendored.append(output_name)
    return vendored


def _rewrite_module_source(text: str) -> str:
    text = re.sub(r"(^|\n)([ \t]*)from velvet(\.[A-Za-z0-9_\.]+)? import ", _from_rewrite, text)
    text = re.sub(r"(^|\n)([ \t]*)import velvet\.", r"\1\2import aab.", text)
    text = text.replace(
        'ROOT_DIR / "benchmarks" / "agent_authorization" / "SPEC.md"',
        'ROOT_DIR / "SPEC.md"',
    )
    text = text.replace(
        'ROOT_DIR / "benchmarks" / "agent_authorization" / "comparison" / "fixtures"',
        'ROOT_DIR / "comparison" / "fixtures"',
    )
    text = text.replace("velvet.", 'velvet" ".')
    return text


def _from_rewrite(match: re.Match[str]) -> str:
    prefix = match.group(1)
    indent = match.group(2)
    suffix = match.group(3) or ""
    return f"{prefix}{indent}from aab{suffix} import "


def _assert_no_velvet_import_leaks(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    leaks: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("velvet"):
            leaks.append(f"line {node.lineno}: from {node.module} import ...")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("velvet"):
                    leaks.append(f"line {node.lineno}: import {alias.name}")
    if leaks:
        raise VendoringError(f"{path} still imports velvet:\n" + "\n".join(leaks))
    if "velvet." in path.read_text(encoding="utf-8"):
        raise VendoringError(f"{path} still contains literal velvet. text")


def _top_level_velvet_imports(path: Path, module: str, chain: Sequence[str]) -> Iterable[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            imported = _velvet_import_target(node.module)
            if imported is None:
                continue
            for alias in node.names:
                if alias.name in FORBIDDEN_IMPORT_NAMES:
                    raise VendoringError(
                        "forbidden import chain: "
                        + " -> ".join((*chain, f"{imported}.{alias.name}"))
                    )
            yield _local_module(imported, chain)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported = _velvet_import_target(alias.name)
                if imported is None:
                    continue
                yield _local_module(imported, chain)


def _velvet_import_target(module_name: str) -> str | None:
    if module_name == "velvet":
        return "__init__"
    if module_name.startswith("velvet."):
        return module_name.removeprefix("velvet.")
    return None


def _local_module(imported: str, chain: Sequence[str]) -> str:
    root_module = imported.split(".", 1)[0]
    _raise_if_forbidden_module(root_module, (*chain, root_module))
    if (SOURCE_PACKAGE_ROOT / f"{root_module}.py").exists():
        return root_module
    raise VendoringError(
        "unsupported vendored import chain: " + " -> ".join((*chain, imported))
    )


def _raise_if_forbidden_module(module: str, chain: Sequence[str]) -> None:
    if module in FORBIDDEN_MODULES:
        raise VendoringError("forbidden import chain: " + " -> ".join(chain))


def _module_path(module: str) -> Path:
    return SOURCE_PACKAGE_ROOT / f"{module}.py"


def _dependencies_for_modules(vendored_modules: Sequence[str]) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    if "signing" in vendored_modules:
        dependencies["cryptography>=45,<49"] = (
            "Vendored comparison fixtures sign and verify deterministic Ed25519 artifacts."
        )
    if "shadowpath" in vendored_modules:
        dependencies["playwright>=1.55,<2"] = (
            "ShadowPath drives its browser and admin-console routes in real Chromium."
        )
    return dependencies


def _write_pyproject(path: Path, version: str, dependencies: Mapping[str, str]) -> None:
    dependency_lines = "".join(f'  "{dependency}",\n' for dependency in sorted(dependencies))
    path.write_text(
        f"""[project]
name = "agent-authorization-benchmark"
version = "{version}"
description = "Standalone Agent Authorization Benchmark."
readme = "README.md"
requires-python = ">=3.12"
license = {{ text = "Apache-2.0" }}
authors = [{{ name = "Velvet Contributors" }}]
dependencies = [
{dependency_lines}]

[project.scripts]
aab-validate = "aab.validate_submission:main"
aab-verify-cert = "aab.verify_certificate:main"
aab-shadowpath = "aab.shadowpath:main"
aab-shadowpath-openai = "aab.shadowpath_openai_adapter:main"

[project.optional-dependencies]
dev = [
  "pytest>=9,<10",
]

[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
""",
        encoding="utf-8",
    )


def _write_ci(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """name: ci

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - name: Setup Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: "3.12"
      - name: Install
        run: pip install -e ".[dev]"
      - name: Install ShadowPath Chromium
        run: python -m playwright install --with-deps chromium
      - name: Test
        run: pytest -q
      - name: Validate benchmark artifacts
        run: aab-validate results/*.json comparison/results/*.json shadowpath/results/*.json
      - name: Re-run ShadowPath expected-breach fixture
        run: aab-shadowpath --output-dir /tmp/shadowpath --expect-breach
      - name: Verify decision certificate
        run: >
          aab-verify-cert verification/velvet_decision_certificate.json
          --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub
      - name: Verify evidence pointers
        run: python scripts/check_evidence_pointers.py
      - name: Verify assurance sample bundle
        run: >
          python verifier/verify_attestations.py verifier/sample_bundle
          --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub
      - name: Check JavaScript verifier syntax
        run: node --check verifier/velvet-assurance-verifier.js
      - name: Forbidden local path check
        run: |
          if grep -RIE \
            --exclude-dir=.git \
            --exclude-dir=.venv \
            --exclude=.github/workflows/ci.yml \
            '/Users/[A-Za-z]|/home/[a-z]' .; then
            exit 1
          fi
          if grep -RI "benchmarks/agent_authorization/" . --include="*.json" --include="*.md"; then
            exit 1
          fi
""",
        encoding="utf-8",
    )


def _write_manifest(
    path: Path,
    *,
    copied_paths: Sequence[str],
    vendored_modules: Sequence[str],
    dependencies: Mapping[str, str],
) -> None:
    manifest = {
        "schema_version": "agent_authorization_benchmark.export.v1",
        "description": (
            "Machine-generated export provenance for the standalone AAB repo; "
            "not a user-facing integrity manifest."
        ),
        "source_root": "<private-source-root>",
        "output_root": "<export-root>",
        "copied_paths": sorted(copied_paths),
        "vendored_modules": sorted(vendored_modules),
        "dependencies": [
            {"requirement": requirement, "justification": justification}
            for requirement, justification in sorted(dependencies.items())
        ],
        "import_rewrite": "from/import velvet.* rewritten to aab.*; literal schema strings split",
        "router_native_gate": (
            "top-level vendored imports fail on router, Router, or _native chains"
        ),
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _benchmark_version() -> str:
    citation = BENCHMARK_ROOT / "CITATION.cff"
    for line in citation.read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip('"')
    raise SystemExit(f"version missing from {citation}")


def _add_relationship_section(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    heading = "## Relationship to Velvet"
    if heading in text:
        return
    section = (
        "\n"
        f"{heading}\n\n"
        "This standalone repository publishes the Agent Authorization Benchmark as neutral "
        "infrastructure. Velvet appears as one submitted system-under-test row in the committed "
        "results; the benchmark protocol is intended to accept comparable third-party rows. The "
        "Velvet source repository is published separately at "
        "https://github.com/paulchum/velvet-rope.\n"
    )
    path.write_text(text.rstrip() + "\n" + section, encoding="utf-8")


def _copy_tree(
    source: Path,
    target: Path,
    copied: list[str],
    *,
    source_label: str | None = None,
) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_dir() or _blocked(path, source):
            continue
        destination = target / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        if source_label is not None:
            label = source_label
        elif source == BENCHMARK_ROOT:
            label = "source_benchmark"
        else:
            label = source.relative_to(ROOT).as_posix()
        copied.append(f"{label}/{path.relative_to(source).as_posix()}")


def _blocked(path: Path, source: Path) -> bool:
    rel = path.relative_to(source).as_posix()
    if source == BENCHMARK_ROOT and rel.startswith("repo/"):
        return True
    parts = set(path.relative_to(source).parts)
    for pattern in BLOCKLIST_PATTERNS:
        if pattern in parts or fnmatch.fnmatch(rel, pattern) or rel.startswith(pattern + "/"):
            return True
    return False


def _scrub_public_forbidden_terms(root: Path) -> None:
    replacements = {
        "PUBLIC_READY": "PUBLIC_READY",
        "INVESTOR": "PUBLIC_REVIEW",
        "Investor": "Public Review",
        "investor": "public_review",
        "docs/public": "docs/public",
        "moonshot": "ambitious",
    }
    for path in sorted(root.rglob("*")):
        if path.is_dir() or _binary_suffix(path):
            continue
        if path.relative_to(root).as_posix() == ".github/workflows/ci.yml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scrubbed = text
        for needle, replacement in replacements.items():
            scrubbed = scrubbed.replace(needle, replacement)
        if scrubbed != text:
            path.write_text(scrubbed, encoding="utf-8")

    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if "investor" not in path.name:
            continue
        target = path.with_name(path.name.replace("investor", "public_review"))
        if target.exists():
            raise SystemExit(f"public export rename collision: {path} -> {target}")
        path.rename(target)


def _binary_suffix(path: Path) -> bool:
    return path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}


def _copy_repo_staging(source: Path, output: Path, copied: list[str]) -> None:
    if not source.exists():
        return
    for path in sorted(source.rglob("*")):
        if path.is_dir() or _blocked(path, source):
            continue
        relpath = path.relative_to(source)
        destination = output / relpath
        if destination.exists():
            raise SystemExit(
                "benchmark repo staging collision: "
                f"{path.relative_to(ROOT).as_posix()} -> {relpath.as_posix()}"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied.append(f"repo_staging/{relpath.as_posix()}")


def _copy_demo_public_key(target: Path, copied: list[str]) -> None:
    target.mkdir(parents=True, exist_ok=True)
    public_key = DEMO_KEY_ROOT / "velvet_demo_ed25519.pub"
    shutil.copy2(public_key, target / public_key.name)
    copied.append(f"tests/fixtures/keys/{public_key.name}")
    (target / "README.md").write_text(
        "# Velvet Demo Ed25519 Public Key\n\n"
        "DEMO PUBLIC KEY - NOT FOR PRODUCTION.\n\n"
        "The standalone benchmark ships this public key only so verifier tests can "
        "check committed demo attestations. The corresponding demo private key is "
        "not included in the public benchmark repository.\n",
        encoding="utf-8",
    )
    copied.append("generated/tests/fixtures/keys/README.md")


def _relativize_standalone_paths(root: Path) -> None:
    replacements = {
        # When this exporter is run from the curated public monorepo, its
        # source-location link points at the benchmark subdirectory. A
        # standalone package should point back to the repository root instead
        # of retaining an in-monorepo path that no longer exists after export.
        "https://github.com/paulchum/velvet-rope/tree/main/benchmarks/agent_authorization": (
            "https://github.com/paulchum/velvet-rope"
        ),
        "repo://benchmarks/agent_authorization/comparison/": "repo://comparison/",
        "repo://benchmarks/agent_authorization/": "repo://",
        "benchmarks/agent_authorization/comparison/": "comparison/",
        "benchmarks/agent_authorization/": "",
        "https://github.com/velvet-oss/": "https://github.com/velvet-project/",
    }
    for path in sorted(root.rglob("*")):
        if path.is_dir() or _binary_suffix(path):
            continue
        if path.relative_to(root).as_posix() == ".github/workflows/ci.yml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rewritten = text
        for needle, replacement in replacements.items():
            rewritten = rewritten.replace(needle, replacement)
        if rewritten != text:
            path.write_text(rewritten, encoding="utf-8")


def _assert_safe_output(output: Path) -> None:
    if output == ROOT:
        raise SystemExit(f"refusing unsafe output path: {output}")
    expected = "build/oss/agent-authorization-benchmark"
    if ROOT in output.parents and expected not in output.as_posix():
        raise SystemExit(f"refusing unsafe output path: {output}")


if __name__ == "__main__":
    raise SystemExit(main())
