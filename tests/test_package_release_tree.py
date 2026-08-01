from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


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


def _write_release_tree(root: Path, *, version: str = "1.2.3") -> None:
    root.mkdir(parents=True)
    (root / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {version}\n")
    (root / "b.txt").write_text("b\n", encoding="utf-8")
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    executable = root / "bin" / "tool"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)


def test_package_release_tree_is_deterministic_and_writes_manifest(tmp_path: Path) -> None:
    packager = _load_script("package_release_tree")
    tree = tmp_path / "velvet"
    out_one = tmp_path / "out-one"
    out_two = tmp_path / "out-two"
    _write_release_tree(tree, version="7.8.9")

    assert packager.main(["--tree", str(tree), "--name", "velvet", "--out-dir", str(out_one)]) == 0
    assert packager.main(["--tree", str(tree), "--name", "velvet", "--out-dir", str(out_two)]) == 0

    zip_one = out_one / "velvet-v7.8.9.zip"
    zip_two = out_two / "velvet-v7.8.9.zip"
    manifest_one = out_one / "velvet-v7.8.9.zip.manifest.json"
    manifest_two = out_two / "velvet-v7.8.9.zip.manifest.json"
    sha_one = out_one / "velvet-v7.8.9.zip.sha256"

    assert zip_one.read_bytes() == zip_two.read_bytes()
    assert manifest_one.read_bytes() == manifest_two.read_bytes()
    archive_sha = hashlib.sha256(zip_one.read_bytes()).hexdigest()
    assert sha_one.read_text(encoding="utf-8") == f"{archive_sha}  {zip_one.name}\n"

    manifest = json.loads(manifest_one.read_text(encoding="utf-8"))
    assert manifest["version"] == "7.8.9"
    assert manifest["file_count"] == 4
    assert [entry["path"] for entry in manifest["files"]] == [
        "CITATION.cff",
        "a.txt",
        "b.txt",
        "bin/tool",
    ]
    modes = {entry["path"]: entry["mode"] for entry in manifest["files"]}
    assert modes["a.txt"] == f"{stat.S_IFREG | 0o644:06o}"
    assert modes["bin/tool"] == f"{stat.S_IFREG | 0o755:06o}"

    with zipfile.ZipFile(zip_one) as archive:
        assert archive.namelist() == ["CITATION.cff", "a.txt", "b.txt", "bin/tool"]
        for info in archive.infolist():
            assert info.date_time == packager.ZIP_EPOCH
        tool_info = archive.getinfo("bin/tool")
        assert ((tool_info.external_attr >> 16) & 0o777) == 0o755


@pytest.mark.parametrize(
    "relpath, message",
    [
        ("__pycache__/module.pyc", "refusing __pycache__ entry"),
        (".hypothesis/examples/data", "refusing .hypothesis entry"),
        (".venv/pyvenv.cfg", "refusing .venv entry"),
        (".uv-cache/archive", "refusing uv cache entry"),
        ("dist/artifact.whl", "refusing dist entry"),
        ("build/output.txt", "refusing build entry"),
        ("target/debug/lib", "refusing target entry"),
        ("node_modules/package/index.js", "refusing node_modules entry"),
        (".DS_Store", "refusing .DS_Store entry"),
    ],
)
def test_package_release_tree_refuses_generated_artifacts(
    tmp_path: Path,
    relpath: str,
    message: str,
) -> None:
    packager = _load_script("package_release_tree")
    tree = tmp_path / "tree"
    _write_release_tree(tree)
    leaked = tree / relpath
    leaked.parent.mkdir(parents=True, exist_ok=True)
    leaked.write_text("generated\n", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        packager.main(["--tree", str(tree), "--out-dir", str(tmp_path / "out")])

    assert message in str(error.value)


def test_package_benchmark_release_shim_defaults_and_allows_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = _load_script("package_benchmark_release")
    default_tree = tmp_path / "build" / "oss" / "agent-authorization-benchmark"
    custom_tree = tmp_path / "custom-benchmark"
    _write_release_tree(default_tree, version="0.2.1")
    _write_release_tree(custom_tree, version="9.9.9")
    monkeypatch.chdir(tmp_path)

    assert shim.main(["--out-dir", str(tmp_path / "default-out")]) == 0
    assert (tmp_path / "default-out" / "agent-authorization-benchmark-v0.2.1.zip").exists()

    assert (
        shim.main(
            [
                "--tree",
                str(custom_tree),
                "--out-dir",
                str(tmp_path / "custom-out"),
            ]
        )
        == 0
    )
    assert (tmp_path / "custom-out" / "custom-benchmark-v9.9.9.zip").exists()
