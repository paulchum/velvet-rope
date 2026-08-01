from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_export_benchmark_tree() -> Any:
    path = ROOT / "scripts" / "export_benchmark_tree.py"
    scripts_dir = str(path.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("export_benchmark_tree", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["export_benchmark_tree"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_export_oss_tree() -> Any:
    path = ROOT / "scripts" / "export_oss_tree.py"
    scripts_dir = str(path.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("export_oss_tree", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["export_oss_tree"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_export_benchmark_tree_builds_standalone_package(tmp_path: Path) -> None:
    output = tmp_path / "agent-authorization-benchmark"
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts" / "export_benchmark_tree.py"),
            "--out",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "AAB_EXPORT_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["vendored_modules"] == [
        "agent_authorization_benchmark",
        "agent_authorization_comparison",
        "passk",
        "serialization",
        "shadowpath",
        "shadowpath_openai_adapter",
        "signing",
        "validate_submission",
        "verify_certificate",
    ]
    assert (output / "pyproject.toml").exists()
    pyproject = (output / "pyproject.toml").read_text(encoding="utf-8")
    assert 'aab-verify-cert = "aab.verify_certificate:main"' in pyproject
    assert 'aab-shadowpath = "aab.shadowpath:main"' in pyproject
    assert '"playwright>=1.55,<2"' in pyproject
    assert "[project.optional-dependencies]" in pyproject
    assert (output / "verifier" / "pyproject.toml").exists()
    assert (output / "tests" / "test_certificate_verifies.py").exists()
    assert (output / "tests" / "fixtures" / "keys" / "velvet_demo_ed25519.pub").exists()
    assert not (output / "tests" / "fixtures" / "keys" / "velvet_demo_ed25519.key").exists()
    assert (output / "scripts" / "check_evidence_pointers.py").exists()
    assert (output / "verifier" / "sample_bundle" / "attestations.jsonl").exists()
    assert (output / "comparison" / "COMPARISON_RESULTS.md").exists()
    assert (output / "shadowpath" / "SHADOWPATH_RESULTS.md").exists()
    assert (
        output / "shadowpath" / "fixtures" / "effect_inventory.json"
    ).exists()
    assert "Relationship to Velvet" in (output / "README.md").read_text(encoding="utf-8")
    assert "benchmarks/agent_authorization" not in (output / "README.md").read_text(
        encoding="utf-8"
    )
    assert len((output / "LICENSE").read_text(encoding="utf-8").splitlines()) > 170
    workflow = (output / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pytest -q" in workflow
    assert 'grep -RI "benchmarks/agent_authorization/"' in workflow
    assert 'grep -RI ""' not in workflow
    assert "paul" "chumbe" not in workflow
    assert "AAB_EXPORT_MANIFEST.json" in (
        output / "CONTRIBUTING.md"
    ).read_text(encoding="utf-8")
    assert not list((output / "src" / "aab").rglob("*.pyc"))
    for path in (output / "src" / "aab").rglob("*.py"):
        assert "velvet." not in path.read_text(encoding="utf-8")
        assert "benchmarks/agent_authorization" not in path.read_text(encoding="utf-8")

    env = {**os.environ, "PYTHONPATH": str(output / "src")}
    validate = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "aab.validate_submission",
            *[str(path) for path in sorted((output / "results").glob("*.json"))],
            *[str(path) for path in sorted((output / "comparison" / "results").glob("*.json"))],
            *[str(path) for path in sorted((output / "shadowpath" / "results").glob("*.json"))],
        ],
        cwd=output,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate.returncode == 0, validate.stderr


def test_vendoring_fails_loudly_for_router_import_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exporter = _load_export_benchmark_tree()
    (tmp_path / "bad.py").write_text(
        "from __future__ import annotations\n\nfrom velvet.router import Router\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(exporter, "SOURCE_PACKAGE_ROOT", tmp_path)

    with pytest.raises(exporter.VendoringError) as error:
        exporter.resolve_vendored_modules(("bad",))

    assert "bad -> router" in str(error.value)


def test_core_export_keeps_agent_authorization_comparison_outputs_unblocked() -> None:
    exporter = _load_export_oss_tree()

    assert "benchmarks/agent_authorization/comparison/COMPARISON_RESULTS.md" not in (
        exporter.BLOCKLIST_PATTERNS
    )
    assert "benchmarks/agent_authorization/comparison/evidence" not in (
        exporter.BLOCKLIST_PATTERNS
    )
    assert "benchmarks/agent_authorization/comparison/results" not in (
        exporter.BLOCKLIST_PATTERNS
    )
