from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPRECATED_PRODUCT_NAME = re.compile(r"Velvet Gate(?!way)")
PUBLIC_TEXT_ROOTS = (
    ROOT / "README.md",
    ROOT / "IMPLEMENTATION_STATUS.md",
    ROOT / "docs",
    ROOT / "reports",
)
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".json",
    ".jsonl",
    ".md",
    ".txt",
}


def _public_text_files() -> list[Path]:
    files: list[Path] = []
    for root in PUBLIC_TEXT_ROOTS:
        if root.is_file():
            files.append(root)
            continue
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in TEXT_SUFFIXES
        )
    return sorted(files)


def test_public_docs_and_reports_do_not_brand_velvet_gate() -> None:
    offenders: list[str] = []
    for path in _public_text_files():
        text = path.read_text(encoding="utf-8")
        if DEPRECATED_PRODUCT_NAME.search(text):
            offenders.append(str(path.relative_to(ROOT)))

    assert offenders == []
