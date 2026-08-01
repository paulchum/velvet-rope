from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PACKAGE = "velvet" + "_enterprise"
AWS_SHARED_SAAS_MIGRATION = "0002_" + "aws_shared" + "_saas_mvp.py"


def _public_path(*parts: str) -> str:
    return "/".join(parts)


FORBIDDEN_PRIVATE_SOURCE = _public_path("src", PRIVATE_PACKAGE)
FORBIDDEN_AWS_SHARED_SAAS_MIGRATION = _public_path(
    "db",
    "migrations",
    AWS_SHARED_SAAS_MIGRATION,
)
FORBIDDEN_TERRAFORM_PREFIX = _public_path("infra", "aws", "terraform")
FORBIDDEN_CODEX_THREADS_PREFIX = _public_path("threads")
FORBIDDEN_FRAGMENTS = (
    PRIVATE_PACKAGE,
    FORBIDDEN_PRIVATE_SOURCE,
    FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
    FORBIDDEN_TERRAFORM_PREFIX,
)


def _load_script(name: str) -> Any:
    path = ROOT / "scripts" / f"{name}.py"
    scripts_dir = str(path.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _is_path_at_or_under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def test_oss_export_excludes_private_and_local_thread_paths_from_manifest(
    tmp_path: Path,
) -> None:
    exporter = _load_script("export_oss_tree")
    output = tmp_path / "velvet"

    def _skip_release_artifact_regeneration(_export_root: Path, **_kwargs: Any) -> None:
        return None

    exporter.regenerate_agent_authorization_comparison = _skip_release_artifact_regeneration
    assert exporter.main(["--out", str(output)]) == 0

    assert not (output / FORBIDDEN_PRIVATE_SOURCE).exists()
    assert not (output / FORBIDDEN_AWS_SHARED_SAAS_MIGRATION).exists()
    assert not (output / FORBIDDEN_TERRAFORM_PREFIX).exists()
    assert not (output / FORBIDDEN_CODEX_THREADS_PREFIX).exists()
    assert not (output / "tests" / "test_enterprise_api.py").exists()
    assert not (output / "tests" / "test_enterprise_repository.py").exists()
    assert not (output / "scripts" / "hooks").exists()

    # The Certified Decisions layer ships in the open core.
    assert (output / "src" / "velvet" / "verdict" / "__init__.py").exists()
    assert (output / "src" / "velvet" / "verdict" / "UPSTREAM.md").exists()
    assert (output / "schemas" / "velvet_rope" / "verdict_certificate.schema.json").exists()
    assert (output / "docs" / "verdicts" / "certified-decisions.md").exists()
    assert (output / "docs" / "math" / "theorem_v_finite_horizon_verdict.txt").exists()
    certified_decision_paths = {
        path.relative_to(ROOT).as_posix()
        for source_root in (ROOT / "src" / "velvet" / "verdict", ROOT / "docs" / "verdicts")
        for path in source_root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    certified_decision_paths.update(
        {
            "docs/math/theorem_v_finite_horizon_verdict.txt",
            "schemas/velvet_rope/verdict_certificate.schema.json",
            "scripts/generate_moonshot_parity.py",
            "tests/fixtures/moonshot_parity_v1.json",
            "tests/test_verify_certificate.py",
        }
    )
    certified_decision_paths.update(
        path.relative_to(ROOT).as_posix()
        for pattern in ("test_verdict*.py", "verdict*.py")
        for path in (ROOT / "tests").glob(pattern)
        if path.is_file()
    )
    assert all((output / path).is_file() for path in certified_decision_paths)
    assert all(
        (output / path).read_bytes() == (ROOT / path).read_bytes()
        for path in certified_decision_paths
    )
    assert not any(path.name == "__pycache__" for path in output.rglob("__pycache__"))

    manifest_text = (output / "OSS_EXPORT_MANIFEST.json").read_text(encoding="utf-8")
    for fragment in FORBIDDEN_FRAGMENTS:
        assert fragment not in manifest_text
    assert f'"{FORBIDDEN_CODEX_THREADS_PREFIX}/' not in manifest_text

    manifest = json.loads(manifest_text)
    copied_paths = manifest["copied_paths"]
    assert certified_decision_paths <= set(copied_paths)
    assert all(
        path != FORBIDDEN_PRIVATE_SOURCE
        and not path.startswith(FORBIDDEN_PRIVATE_SOURCE + "/")
        for path in copied_paths
    )
    assert FORBIDDEN_AWS_SHARED_SAAS_MIGRATION not in copied_paths
    assert all(not path.startswith(FORBIDDEN_TERRAFORM_PREFIX + "/") for path in copied_paths)
    assert all(
        not _is_path_at_or_under(path, FORBIDDEN_CODEX_THREADS_PREFIX)
        for path in copied_paths
    )

    leaks: list[str] = []
    for path in sorted(output.rglob("*")):
        if path.is_dir() or path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in text:
                leaks.append(f"{path.relative_to(output)} contains {fragment}")
    assert leaks == []

    # The checker ships in the public tree and must remain runnable after the
    # exporter's text scrub. In particular, the private ``docs/public`` path must
    # not be rewritten into the legitimate public docs directory.
    checker_path = output / "scripts" / "check_publish_safety.py"
    checker_spec = importlib.util.spec_from_file_location(
        "exported_check_publish_safety", checker_path
    )
    assert checker_spec is not None and checker_spec.loader is not None
    exported_checker = importlib.util.module_from_spec(checker_spec)
    checker_spec.loader.exec_module(exported_checker)
    assert exported_checker.check(output) == []


def test_oss_export_failure_preserves_previous_complete_tree(tmp_path: Path) -> None:
    exporter = _load_script("export_oss_tree")
    output = tmp_path / "velvet"
    output.mkdir()
    sentinel = output / "previous-export.txt"
    sentinel.write_text("complete\n", encoding="utf-8")

    def _fail_release_artifact_regeneration(_export_root: Path, **_kwargs: Any) -> None:
        raise SystemExit("synthetic regeneration failure")

    exporter.regenerate_agent_authorization_comparison = _fail_release_artifact_regeneration
    with pytest.raises(SystemExit, match="synthetic regeneration failure"):
        exporter.main(["--out", str(output), "--check"])

    assert sentinel.read_text(encoding="utf-8") == "complete\n"
    assert list(tmp_path.glob(".velvet.tmp-*")) == []


def test_oss_export_refuses_symlinked_source_file(tmp_path: Path) -> None:
    exporter = _load_script("export_oss_tree")
    private = tmp_path / "private.txt"
    private.write_text("not public\n", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    linked.symlink_to(private)

    with pytest.raises(SystemExit, match="refusing symlink in OSS export"):
        exporter._copy_file(linked, tmp_path / "velvet" / "linked.txt")


def test_oss_export_refuses_symlinked_output_tree(tmp_path: Path) -> None:
    exporter = _load_script("export_oss_tree")
    existing = tmp_path / "existing-export"
    existing.mkdir()
    sentinel = existing / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    output = tmp_path / "velvet"
    output.symlink_to(existing, target_is_directory=True)

    with pytest.raises(SystemExit, match="refusing unsafe output path"):
        exporter.main(["--out", str(output), "--allow-dirty"])

    assert sentinel.read_text(encoding="utf-8") == "keep\n"


def test_publish_safety_fails_loudly_for_aws_shared_saas_leaks(tmp_path: Path) -> None:
    checker = _load_script("check_publish_safety")
    exporter = _load_script("export_oss_tree")

    leaked = tmp_path / "leaked"
    (leaked / FORBIDDEN_PRIVATE_SOURCE).mkdir(parents=True)
    (leaked / "db" / "migrations").mkdir(parents=True)
    (leaked / FORBIDDEN_AWS_SHARED_SAAS_MIGRATION).write_text(
        'revision = "0002_" "aws_shared" "_saas_mvp"\n',
        encoding="utf-8",
    )
    (leaked / FORBIDDEN_TERRAFORM_PREFIX).mkdir(parents=True)
    (leaked / FORBIDDEN_TERRAFORM_PREFIX / "main.tf").write_text(
        'locals { surface = "shared-saas-mvp" }\n',
        encoding="utf-8",
    )
    (leaked / FORBIDDEN_CODEX_THREADS_PREFIX).mkdir(parents=True)
    (leaked / FORBIDDEN_CODEX_THREADS_PREFIX / "codex-thread.jsonl").write_text(
        '{"role": "user", "content": "local transcript"}\n',
        encoding="utf-8",
    )
    (leaked / "OSS_EXPORT_MANIFEST.json").write_text(
        json.dumps(
            {
                "copied_paths": [
                    FORBIDDEN_PRIVATE_SOURCE + "/__init__.py",
                    FORBIDDEN_AWS_SHARED_SAAS_MIGRATION,
                    FORBIDDEN_TERRAFORM_PREFIX + "/main.tf",
                    FORBIDDEN_CODEX_THREADS_PREFIX + "/codex-thread.jsonl",
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )

    (leaked / "velvet-v0.9.0.zip.manifest.json").write_text(
        json.dumps(
            {
                "files": [
                    {"path": FORBIDDEN_PRIVATE_SOURCE + "/api.py"},
                    {"path": FORBIDDEN_AWS_SHARED_SAAS_MIGRATION},
                    {"path": FORBIDDEN_TERRAFORM_PREFIX + "/providers.tf"},
                    {"path": FORBIDDEN_CODEX_THREADS_PREFIX + "/codex-thread.jsonl"},
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (leaked / "README.md").write_text(
        f"leaked fragment: {FORBIDDEN_TERRAFORM_PREFIX}\n",
        encoding="utf-8",
    )

    problems = checker.check(leaked)
    assert f"forbidden OSS export path present: {FORBIDDEN_PRIVATE_SOURCE}" in problems
    assert (
        f"forbidden OSS export path present: {FORBIDDEN_AWS_SHARED_SAAS_MIGRATION}"
        in problems
    )
    assert (
        f"forbidden OSS export path present: {FORBIDDEN_TERRAFORM_PREFIX}/main.tf"
        in problems
    )
    assert (
        "forbidden OSS export path present: "
        f"{FORBIDDEN_CODEX_THREADS_PREFIX}/codex-thread.jsonl"
        in problems
    )
    assert (
        f"OSS export manifest references forbidden private path: {FORBIDDEN_PRIVATE_SOURCE}"
        in problems
    )
    assert (
        "OSS export manifest references forbidden private path: "
        f"{FORBIDDEN_AWS_SHARED_SAAS_MIGRATION}"
        in problems
    )
    assert (
        "OSS export manifest references forbidden private path: "
        f"{FORBIDDEN_TERRAFORM_PREFIX}/*"
        in problems
    )
    assert (
        "OSS export manifest references forbidden private path: "
        f"{FORBIDDEN_CODEX_THREADS_PREFIX}/*"
        in problems
    )
    assert any(
        problem
        == "release manifest velvet-v0.9.0.zip.manifest.json references forbidden "
        f"private path: {FORBIDDEN_PRIVATE_SOURCE}"
        for problem in problems
    )
    assert any(
        problem
        == "release manifest velvet-v0.9.0.zip.manifest.json references forbidden "
        f"private path: {FORBIDDEN_CODEX_THREADS_PREFIX}/*"
        for problem in problems
    )
    assert any(
        problem
        == f"README.md contains forbidden private fragment: {FORBIDDEN_TERRAFORM_PREFIX}"
        for problem in problems
    )

    with pytest.raises(SystemExit) as error:
        exporter._assert_publish_safe(leaked)

    message = str(error.value)
    assert "OSS export publish-safety failed:" in message
    assert f"forbidden OSS export path present: {FORBIDDEN_PRIVATE_SOURCE}" in message
    assert f"forbidden OSS export path present: {FORBIDDEN_AWS_SHARED_SAAS_MIGRATION}" in message
    assert f"forbidden OSS export path present: {FORBIDDEN_TERRAFORM_PREFIX}/main.tf" in message
    assert (
        "forbidden OSS export path present: "
        f"{FORBIDDEN_CODEX_THREADS_PREFIX}/codex-thread.jsonl"
    ) in message
    assert (
        "OSS export manifest references forbidden private path: "
        f"{FORBIDDEN_TERRAFORM_PREFIX}/*"
    ) in message
    assert (
        "OSS export manifest references forbidden private path: "
        f"{FORBIDDEN_CODEX_THREADS_PREFIX}/*"
    ) in message
