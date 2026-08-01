#!/usr/bin/env python3
"""Build the curated Velvet OSS tree from the private source workspace."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path

from check_publish_safety import check as _check_publish_safety
from export_common import assert_scrubbed, regenerate_agent_authorization_comparison

ROOT = Path(__file__).resolve().parents[1]
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

# Repo coordinates. The docs were written against an org that was never created;
# the public home is a personal-account repo. Assembled from fragments so this
# file's own source is not rewritten when it is scrubbed by itself.
_PRIVATE_ORG = "velvet" + "-project"
PRIVATE_REPO_URL_PREFIX = "https://github.com/" + _PRIVATE_ORG
PRIVATE_IMAGE_PREFIX = "ghcr.io/" + _PRIVATE_ORG
PUBLIC_OWNER = "paulchum"
PUBLIC_REPO_URL = "https://github.com/" + PUBLIC_OWNER + "/velvet-rope"
PUBLIC_BENCHMARK_URL = PUBLIC_REPO_URL + "/tree/main/benchmarks/agent_authorization"
PUBLIC_IMAGE_PREFIX = "ghcr.io/" + PUBLIC_OWNER

# Claims that are false at publication time: the benchmark ships in this
# repository rather than in a separate public repository, and the current
# committed release is v0.4.0.
CLAIM_CORRECTIONS = {
    (
        "with the standalone repository at "
        + PRIVATE_REPO_URL_PREFIX
        + "/agent-authorization-benchmark and the in-repo source under"
    ): "with the source under",
    (
        " The benchmark repository is published separately at "
        + PRIVATE_REPO_URL_PREFIX
        + "/agent-authorization-benchmark."
    ): (
        " The benchmark ships in this repository under "
        "[`benchmarks/agent_authorization/`](benchmarks/agent_authorization/)."
    ),
    "The Agent Authorization Benchmark v0.4.0 currently contains": (
        "The Agent Authorization Benchmark v0.4.0 currently contains"
    ),
}

# Public-facing files stranded inside a blocklisted private directory. These are
# inputs to shipped features (attestation packs embed the offline verifier;
# `velvet underwriter-bundle` requires the claim-boundary doc), so the export
# republishes them under docs/public/ and repoints the code that reads them.
_PRIVATE_DOCS_DIR = "docs/" + "investors"
STRANDED_PUBLIC_DOCS = {
    _PRIVATE_DOCS_DIR + "/velvet-verifier.html": "docs/public/velvet-verifier.html",
    _PRIVATE_DOCS_DIR + "/CLAIMS.md": "docs/public/CLAIMS.md",
}

# Both the posix form and the pathlib-segment form appear in shipped code/tests.
STRANDED_DOC_REFERENCES = {
    '"docs" / "' + "investors" + '"': '"docs" / "public"',
    **STRANDED_PUBLIC_DOCS,
}

# The verifier is a public artifact; its title still called it internal.
VERIFIER_TITLE_CORRECTIONS = {
    "Velvet Offline Proof Verifier": "Velvet Offline Proof Verifier",
}

# Public CLI surfaces backed by excluded modules. Only the "naming and shaming"
# video animatics are excluded: they are outbound marketing that calls out a
# named third party, unlike the demo payload modules, which are built from real
# repo primitives and carry nothing confidential. Those keep their upstream
# names -- renaming them across the export is what previously corrupted the
# shipped CLI into "velvet public_review-demo".
INVESTOR_CLI_MODULES = ("velvet." + "investor_video_html",)
INVESTOR_CLI_FUNCTIONS = frozenset({"investor_video_html_main"})
INVESTOR_CLI_COMMANDS = ("investor-video-html",)

ROOT_FILES = {
    ".gitleaks.toml",
    ".gitignore",
    "AUTHORS",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "Cargo.lock",
    "Cargo.toml",
    "CITATION.cff",
    "DEPENDENCY_POLICY.md",
    "DOC_SYNC_INVENTORY.md",
    "DOC_SYNC_REPORT.md",
    "IMPLEMENTATION_STATUS.md",
    "LICENSE",
    "Makefile",
    "NOTICE",
    "README.md",
    "REFACTOR_NOTES.md",
    "SECURITY.md",
    "TEST_RESULTS.md",
    "deny.toml",
    "docs/execution-permits.md",
    "docs/policy-compiler.md",
    # Required by shipped code, not just prose: velvet-policy-loader's
    # integration test and its policy_schema binary both read
    # docs/policy-schema.md, and docs/verdicts/certified-decisions.md links
    # docs/velvet-rope-mcp.md.
    "docs/policy-schema.md",
    "docs/velvet-rope-mcp.md",
    "docs/vault.md",
    "docs/velvet-ledger.md",
    "pyproject.toml",
    "rust-toolchain.toml",
    "scripts/check-claim-language.py",
    "scripts/check-doc-links.sh",
    "scripts/check_no_npm.py",
    "scripts/check_publish_safety.py",
    "scripts/check_workflows.py",
    "scripts/build_shadowpath_launch_video.py",
    "scripts/export_benchmark_tree.py",
    "scripts/export_common.py",
    "scripts/export_oss_tree.py",
    "scripts/generate_moonshot_parity.py",
    "scripts/generate_sbom.py",
    "scripts/package_benchmark_release.py",
    "scripts/package_release_tree.py",
    "scripts/reconstructability_test.py",
    "uv.lock",
}

ALLOWLIST_DIRS = {
    ".github",
    "assurance",
    "benchmarks/agent_authorization",
    # Shipped code globs this: liability_benchmark.py reads
    # benchmarks/liability/real_world_incidents/*.json. Omitting it silently
    # shrank the generated benchmark thread below its asserted record count.
    "benchmarks/liability",
    "benchmarks/tau_bench",
    "crates",
    "demo",
    "deploy/mcp_proxy",
    "deploy/shadowpath",
    "docs/assurance",
    "docs/compliance",
    "docs/deployment",
    "docs/design",
    "docs/liability",
    "docs/math",
    "docs/mcp_proxy",
    "docs/oap",
    "docs/paper",
    "docs/public",
    "docs/roadmap",
    "docs/verdicts",
    "examples",
    "policies",
    "scenarios",
    "schemas",
    "shadowpath-action",
    "src/velvet",
    "tests",
    "third_party/oap",
}

# Build junk and VCS metadata that may legitimately appear at ANY depth.
# Matched against every path component.
BLOCKLIST_ANY_COMPONENT = {
    ".git",
    ".venv",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "target",
}

# Private trees anchored at the repository root. These are matched as root
# prefixes only -- never as bare path components -- so legitimate nested
# directories that happen to share a name still export. Matching these by
# component previously deleted benchmarks/agent_authorization/results/ (the
# whole published benchmark result set) and demo/live_target/db/ (the live
# demo schema and seed), leaving dangling references in shipped code and docs.
BLOCKLIST_ROOT_PREFIXES = {
    "archive",
    "concepts",
    "db",
    "docs/commercial",
    "docs/diligence",
    "docs/enterprise",
    "docs/fundraise",
    "docs/investors",
    "docs/marketing",
    "docs/public",
    "infra",
    "reports",
    "results",
    FORBIDDEN_PRIVATE_SOURCE,
    FORBIDDEN_CODEX_THREADS_PREFIX,
}

# Glob patterns matched against the root-relative path. Fundraise and pitch
# surfaces are EXCLUDED here rather than renamed by the text scrub: renaming
# them rewrote identifiers inside shipped source (the public CLI advertised
# "velvet public_review-demo") and corrupted this exporter's own scrub table.
BLOCKLIST_GLOBS = {
    "*.pyc",
    "*.pyo",
    "*.so",
    ".coverage",
    "docker-compose.enterprise.yml",
    "src/velvet/investor_video_html.py",
    "src/velvet/khosla_*.py",
    "tests/test_enterprise_*.py",
    "tests/test_investor_*.py",
    "tests/test_khosla_*.py",
    # Fixtures are private by nature: the test drives the bundler with
    # reports/live-demo/incident and docs/commercial, neither of which is (or
    # should be) published. The bundler itself ships and is exercised by its
    # tmp_path cases.
    "tests/test_underwriter_bundle.py",
    "tests/test_vc_demo.py",
}

BLOCKLIST_PATTERNS = BLOCKLIST_ANY_COMPONENT | BLOCKLIST_ROOT_PREFIXES | BLOCKLIST_GLOBS

PUBLIC_BLOCKED_PATH_CLASSES = (
    "generated artifacts and local caches",
    "local Codex thread transcripts",
    "private enterprise source, database, and infrastructure",
    "private launch, commercial, diligence, and investor materials",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="build/oss/velvet")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow dev export from a dirty source worktree and mark regenerated artifacts dirty.",
    )
    args = parser.parse_args(argv)
    if args.check and args.allow_dirty:
        raise SystemExit("--allow-dirty is for dev exports and cannot be combined with --check")

    output_arg = ROOT / args.out
    if output_arg.is_symlink():
        raise SystemExit(f"refusing unsafe output path: {output_arg}")
    output = output_arg.resolve()
    _assert_safe_output(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent))
    try:
        copied: list[str] = []
        for rel in sorted(ROOT_FILES):
            source = ROOT / rel
            if source.exists():
                _copy_file(source, staging / rel)
                copied.append(rel)
        for rel in sorted(ALLOWLIST_DIRS):
            source = ROOT / rel
            if source.exists():
                _copy_tree(source, staging / rel, copied)

        regenerate_agent_authorization_comparison(staging, allow_dirty=args.allow_dirty)
        _publish_stranded_public_docs(staging, copied)
        _strip_investor_cli_wiring(staging)
        _strip_private_root_files(staging)

        manifest = {
            "schema_version": "velvet.oss_export.v1",
            "source_root": "<private-source-root>",
            "output_root": "<export-root>",
            "copied_paths": copied,
            "blocked_path_classes": list(PUBLIC_BLOCKED_PATH_CLASSES),
            "blocked_path_count": len(BLOCKLIST_PATTERNS),
        }
        (staging / "OSS_EXPORT_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _scrub_public_forbidden_terms(staging)
        assert_scrubbed(staging)
        _assert_publish_safe(staging)

        if output.exists():
            if not output.is_dir() or output.is_symlink():
                raise SystemExit(f"refusing unsafe output path: {output}")
            shutil.rmtree(output)
        staging.replace(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(f"exported {len(copied)} path(s) to {output}")
    return 0


def _copy_tree(source: Path, target: Path, copied: list[str]) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_dir() or _blocked(path):
            continue
        rel = path.relative_to(ROOT).as_posix()
        _copy_file(path, target / path.relative_to(source))
        copied.append(rel)


def _copy_file(source: Path, target: Path) -> None:
    if source.is_symlink():
        raise SystemExit(f"refusing symlink in OSS export: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _assert_safe_output(output: Path) -> None:
    expected = (ROOT / "build" / "oss" / "velvet").resolve()
    if output == ROOT or output in ROOT.parents:
        raise SystemExit(f"refusing unsafe output path: {output}")
    if ROOT in output.parents and output != expected:
        raise SystemExit(f"refusing unsafe output path: {output}")
    if output.name != "velvet":
        raise SystemExit(f"refusing unsafe output path: {output}")


def _blocked(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    rel = relative.as_posix()
    if set(relative.parts) & BLOCKLIST_ANY_COMPONENT:
        return True
    for prefix in BLOCKLIST_ROOT_PREFIXES:
        if rel == prefix or rel.startswith(prefix + "/"):
            return True
    return any(fnmatch.fnmatch(rel, pattern) for pattern in BLOCKLIST_GLOBS)


def _scrub_public_forbidden_terms(root: Path) -> None:
    """Rewrite local-only paths and stale repo URLs in the curated public copy.

    This deliberately does NOT rewrite ``investor``/``vc`` terminology. Those
    surfaces are excluded by ``BLOCKLIST_GLOBS`` and ``_strip_investor_cli_wiring``
    instead. A blind term rewrite corrupts shipped Python: it renamed public CLI
    commands to ``velvet public_review-demo`` and turned this function's own
    replacement table into no-op identity mappings in the published copy.

    Needles are assembled at runtime for the same reason -- so this file's own
    source survives being scrubbed by itself.
    """

    local_user = "paul" + "chumbe"
    workspace = "/Users/" + local_user + "/Developer/velvet"
    replacements = {
        "PUBLIC_READY": "PUBLIC_READY",
        "docs/" + "oss": "docs/public",
        workspace: "<workspace>",
        "/Users/" + local_user: "<home>",
        local_user + "/Developer/velvet": "<workspace>",
        **CLAIM_CORRECTIONS,
        **STRANDED_DOC_REFERENCES,
        **VERIFIER_TITLE_CORRECTIONS,
        PRIVATE_REPO_URL_PREFIX + "/agent-authorization-benchmark": PUBLIC_BENCHMARK_URL,
        PRIVATE_REPO_URL_PREFIX + "/velvet": PUBLIC_REPO_URL,
        PRIVATE_IMAGE_PREFIX: PUBLIC_IMAGE_PREFIX,
    }
    for path in sorted(root.rglob("*")):
        if path.is_dir() or _binary_suffix(path):
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


def _binary_suffix(path: Path) -> bool:
    return path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}


def _strip_private_root_files(root: Path) -> None:
    """Drop root-level wiring that points at stripped private packages and tools."""

    _strip_private_pyproject(root)
    _write_public_makefile(root)
    _write_public_contributing(root)


def _write_public_contributing(root: Path) -> None:
    """Write a CONTRIBUTING.md for the public repo.

    The source tree's CONTRIBUTING.md is deliberately excluded: it is addressed
    to maintainers of the private monorepo and opens with "do not push it to a
    public remote". Without this the published repo has no contributing guide
    at all, so emit a public equivalent pointing only at published paths.
    """

    (root / "CONTRIBUTING.md").write_text(
        """# Contributing To Velvet

Velvet is an Apache-2.0 open-core project for local, self-hosted agent action
admission and verifiable evidence. Contributions should keep the implemented
claim boundary clear: no hosted enterprise claims, no legal compliance outcome,
and no universal agent-safety guarantees.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.

## Development Setup

```bash
uv sync --dev
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 uv run maturin develop
uv run velvet --help
```

Use the focused checks for the area you touched, then broaden before larger
changes:

```bash
uv run ruff check .
uv run pytest
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo fmt --all --check
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --workspace
```

If disk is tight, start with the touched package or test module and report the
scope in the pull request.

## Pull Request Guidelines

- Keep unrelated refactors out of feature or bugfix pull requests.
- Add or update tests for behavior changes.
- Update docs and `CHANGELOG.md` for user-visible changes.
- Keep generated evidence, benchmark, and paper artifacts repo-relative. Do not
  commit local absolute paths or secrets.

## Claim Boundary

Use the implemented language in [`README.md`](README.md) and
[`docs/public/CLAIMS.md`](docs/public/CLAIMS.md). Velvet currently provides
local/self-hosted evidence and verification surfaces; it is not a hosted
shared-tenant platform, legal compliance determination, audit outcome, or
general solution to agent safety.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).
Please do not open a public issue for a suspected vulnerability.
""",
        encoding="utf-8",
    )


def _publish_stranded_public_docs(root: Path, copied: list[str]) -> None:
    """Republish public artifacts that live inside a blocklisted private directory.

    ``attestation/pack.py`` embeds the offline verifier HTML and
    ``underwriter_bundle.py`` requires the claim-boundary doc, but both sources
    sit under the private docs tree. Copy them to ``docs/public/`` so the
    shipped features and their tests resolve; ``STRANDED_DOC_REFERENCES``
    repoints the readers during the scrub.
    """

    if not (ROOT / _PRIVATE_DOCS_DIR).is_dir():
        # Already exporting from a public tree (the exporter ships, and its own
        # tests re-run it against fixture trees). Nothing to republish.
        return
    for source_rel, target_rel in sorted(STRANDED_PUBLIC_DOCS.items()):
        source = ROOT / source_rel
        if not source.exists():
            raise SystemExit(f"stranded public doc missing from source tree: {source_rel}")
        _copy_file(source, root / target_rel)
        copied.append(target_rel)


def _strip_investor_cli_wiring(root: Path) -> None:
    """Remove fundraise/VC command wiring from the public CLI.

    The backing modules are excluded by ``BLOCKLIST_GLOBS``, so leaving the
    imports in place would make ``velvet`` unimportable. Statements are located
    by AST node rather than by text match so the removal stays exact.
    """

    cli = root / "src" / "velvet" / "cli.py"
    if not cli.exists():
        return
    if not (ROOT / "src" / "velvet" / "investor_video_html.py").exists():
        # Exporting from an already-public tree: the wiring is long gone and
        # there is nothing to strip. The exporter ships, so it must stay
        # idempotent when re-run against its own output.
        return
    source = cli.read_text(encoding="utf-8")
    drop: set[int] = set()

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module in INVESTOR_CLI_MODULES:
            drop.update(_node_lines(node))
        elif isinstance(node, ast.FunctionDef) and node.name in INVESTOR_CLI_FUNCTIONS:
            drop.update(_node_lines(node))
            for decorator in node.decorator_list:
                drop.update(_node_lines(decorator))
        elif isinstance(node, ast.If) and _dispatches_investor_command(node):
            drop.update(_node_lines(node))
        elif isinstance(node, ast.Expr) and _prints_investor_usage(node):
            drop.update(_node_lines(node))

    if not drop:
        raise SystemExit("expected investor CLI wiring in cli.py but found none")

    kept = [line for number, line in enumerate(source.splitlines(), 1) if number not in drop]
    stripped = "\n".join(kept) + "\n"
    try:
        ast.parse(stripped)
    except SyntaxError as error:  # pragma: no cover - guards a malformed strip
        raise SystemExit(f"investor CLI strip produced invalid Python: {error}") from error
    cli.write_text(stripped, encoding="utf-8")


def _node_lines(node: ast.AST) -> range:
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is None or end is None:
        return range(0)
    return range(start, end + 1)


def _dispatches_investor_command(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or not isinstance(test.left, ast.Name):
        return False
    if test.left.id != "command":
        return False
    return any(
        isinstance(comparator, ast.Constant) and comparator.value in INVESTOR_CLI_COMMANDS
        for comparator in test.comparators
    )


def _prints_investor_usage(node: ast.Expr) -> bool:
    call = node.value
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        return False
    if call.func.id != "print":
        return False
    literals = [arg.value for arg in ast.walk(call) if isinstance(arg, ast.Constant)]
    text = " ".join(item for item in literals if isinstance(item, str))
    return any(f"velvet {command}" in text for command in INVESTOR_CLI_COMMANDS)


def _strip_private_pyproject(root: Path) -> None:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return
    kept = [
        line
        for line in pyproject.read_text(encoding="utf-8").splitlines()
        if _PRIVATE_PACKAGE not in line
    ]
    pyproject.write_text("\n".join(kept) + "\n", encoding="utf-8")


def _write_public_makefile(root: Path) -> None:
    makefile = root / "Makefile"
    if not makefile.exists():
        return
    phony_targets = (
        "seal-conformance",
        "live-demo",
        "live-demo-db-up",
        "live-demo-suite",
        "live-demo-incident",
        "live-demo-down",
        "live-demo-argument-drift",
        "live-demo-schema-drift",
        "live-demo-approval-replay",
        "live-demo-policy-swap",
        "live-demo-budget-overshoot",
        "live-demo-signer-kill",
        "underwriter-review-bundle",
    )
    lines = [
        "LIVE_DEMO_COMPOSE ?= demo/live_target/docker-compose.yml",
        "",
        ".PHONY: " + " ".join(phony_targets),
        "",
        "seal-conformance:",
        "\tuv run pytest tests/test_seal_conformance.py -q",
        "",
        "live-demo-db-up:",
        "\tdocker compose -f $(LIVE_DEMO_COMPOSE) up -d",
        "",
        "live-demo-suite:",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.run_suite",
        "",
        "live-demo-incident:",
        "\tuv run python -m demo.incident.run",
        "",
        "live-demo: live-demo-db-up live-demo-suite live-demo-incident",
        "",
        "underwriter-review-bundle:",
        "\tuv run velvet underwriter-bundle --json",
        "",
        "live-demo-down:",
        "\tdocker compose -f $(LIVE_DEMO_COMPOSE) down",
        "",
        "live-demo-argument-drift: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.argument_drift",
        "",
        "live-demo-schema-drift: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.schema_drift",
        "",
        "live-demo-approval-replay: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.approval_replay",
        "",
        "live-demo-policy-swap: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.policy_swap",
        "",
        "live-demo-budget-overshoot: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.budget_overshoot",
        "",
        "live-demo-signer-kill: live-demo-db-up",
        "\tcargo build -q -p velvet-rope-proxy",
        "\tuv run python -m demo.attacks.signer_kill",
    ]
    makefile.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _assert_publish_safe(root: Path) -> None:
    problems = _check_publish_safety(root)
    if problems:
        joined = "\n".join(f"  - {item}" for item in problems)
        raise SystemExit(f"OSS export publish-safety failed:\n{joined}")


if __name__ == "__main__":
    raise SystemExit(main())
