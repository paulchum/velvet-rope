#!/usr/bin/env python3
"""Build the Max-DE preprint PDF with System TeX."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

PAPER_DIR = Path(__file__).resolve().parent


def main() -> int:
    generator = PAPER_DIR / "generate_assets.py"
    generated = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, str(generator)],
        cwd=PAPER_DIR.parents[1],
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        return generated.returncode

    latexmk = shutil.which("latexmk")
    xelatex = shutil.which("xelatex")
    if latexmk is not None and xelatex is not None:
        return subprocess.run(  # noqa: S603  # nosec B603
            [latexmk, "-xelatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        ).returncode
    if latexmk is not None:
        return subprocess.run(  # noqa: S603  # nosec B603
            [latexmk, "-pdf", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        ).returncode

    if xelatex is not None:
        first = subprocess.run(  # noqa: S603  # nosec B603
            [xelatex, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        )
        if first.returncode != 0:
            return first.returncode
        return subprocess.run(  # noqa: S603  # nosec B603
            [xelatex, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        ).returncode

    pdflatex = shutil.which("pdflatex")
    if pdflatex is not None:
        first = subprocess.run(  # noqa: S603  # nosec B603
            [pdflatex, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        )
        if first.returncode != 0:
            return first.returncode
        return subprocess.run(  # noqa: S603  # nosec B603
            [pdflatex, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=PAPER_DIR,
            check=False,
        ).returncode

    print(
        "System TeX not found: install latexmk, xelatex, or pdflatex, then rerun "
        "`uv run python docs/paper/build.py`.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
