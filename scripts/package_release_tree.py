#!/usr/bin/env python3
"""Create a deterministic release archive from a curated source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import zipfile
from collections.abc import Sequence
from pathlib import Path

DEFAULT_TREE = "build/oss/velvet"
DEFAULT_OUT_DIR = "build/release"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", default=DEFAULT_TREE)
    parser.add_argument("--name")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    tree = Path(args.tree).resolve()
    out_dir = Path(args.out_dir).resolve()
    if not tree.is_dir():
        raise SystemExit(f"release tree does not exist: {tree}")
    name = args.name or tree.name

    version = _read_version(tree / "CITATION.cff")
    files = _collect_files(tree)
    manifest_files = [_manifest_entry(tree, path) for path in files]
    total_bytes = sum(path.stat().st_size for path in files)

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{name}-v{version}.zip"
    _write_zip(tree, files, zip_path)

    archive_sha256 = _sha256_file(zip_path)
    sha_path = zip_path.with_name(f"{zip_path.name}.sha256")
    sha_path.write_text(f"{archive_sha256}  {zip_path.name}\n", encoding="utf-8")

    manifest_path = zip_path.with_name(f"{zip_path.name}.manifest.json")
    manifest = {
        "version": version,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "files": manifest_files,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"wrote {zip_path}")
    print(f"wrote {sha_path}")
    print(f"wrote {manifest_path}")
    return 0


def _read_version(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing CITATION.cff: {path}")
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("version:"):
            continue
        version = stripped.split(":", 1)[1].strip().strip("\"'")
        if version:
            return version
        raise SystemExit(f"empty version in {path}")
    raise SystemExit(f"missing version line in {path}")


def _collect_files(tree: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(tree.rglob("*"), key=lambda item: _relative_posix(tree, item)):
        rel = _relative_posix(tree, path)
        _assert_valid_relative_path(rel, path)
        _assert_allowed_entry(rel, path)
        if path.is_symlink():
            raise SystemExit(f"refusing symlink: {rel}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit(f"refusing non-regular file: {rel}")
        files.append(path)
    return files


def _assert_valid_relative_path(rel: str, path: Path) -> None:
    try:
        if rel.encode("utf-8").decode("utf-8") != rel:
            raise UnicodeError
    except UnicodeError as exc:
        raise SystemExit(f"refusing non-UTF-8 path: {path}") from exc


def _assert_allowed_entry(rel: str, path: Path) -> None:
    names = Path(rel).parts
    name = path.name
    if ".git" in names:
        raise SystemExit(f"refusing .git entry: {path}")
    if "__pycache__" in names:
        raise SystemExit(f"refusing __pycache__ entry: {path}")
    if ".hypothesis" in names:
        raise SystemExit(f"refusing .hypothesis entry: {path}")
    if ".venv" in names:
        raise SystemExit(f"refusing .venv entry: {path}")
    if ".uv-cache" in names:
        raise SystemExit(f"refusing uv cache entry: {path}")
    if "uv-cache" in names:
        raise SystemExit(f"refusing uv cache entry: {path}")
    if len(names) >= 2 and names[-2:] == (".cache", "uv"):
        raise SystemExit(f"refusing uv cache entry: {path}")
    if "dist" in names:
        raise SystemExit(f"refusing dist entry: {path}")
    if "build" in names:
        raise SystemExit(f"refusing build entry: {path}")
    if "target" in names:
        raise SystemExit(f"refusing target entry: {path}")
    if "node_modules" in names:
        raise SystemExit(f"refusing node_modules entry: {path}")
    if name == ".DS_Store":
        raise SystemExit(f"refusing .DS_Store entry: {path}")
    if name.endswith(".pyc"):
        raise SystemExit(f"refusing pyc entry: {path}")
    if name.endswith(".egg-info"):
        raise SystemExit(f"refusing egg-info entry: {path}")


def _manifest_entry(tree: Path, path: Path) -> dict[str, str]:
    st_mode = path.stat().st_mode
    return {
        "path": _relative_posix(tree, path),
        "sha256": _sha256_file(path),
        "mode": f"{stat.S_IFMT(st_mode) | stat.S_IMODE(st_mode):06o}",
    }


def _write_zip(tree: Path, files: list[Path], zip_path: Path) -> None:
    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in files:
            rel = _relative_posix(tree, path)
            info = zipfile.ZipInfo(rel, ZIP_EPOCH)
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _relative_posix(tree: Path, path: Path) -> str:
    return os.path.relpath(path, tree).replace(os.sep, "/")


if __name__ == "__main__":
    raise SystemExit(main())
