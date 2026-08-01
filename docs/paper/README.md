# Max-DE Certified Authorization Preprint

This directory contains the LaTeX companion preprint and deterministic asset generation scripts.

Regenerate all paper figures, tables, and generated appendices:

```bash
uv run python docs/paper/generate_assets.py
```

Build the PDF with System TeX:

```bash
uv run python docs/paper/build.py
```

`build.py` runs `generate_assets.py`, then uses `latexmk` with XeLaTeX when available, falls back to `latexmk -pdf`, then to direct `xelatex` or `pdflatex`. A System TeX installation is required; TeX binaries are intentionally not vendored into this repository.

Generated files are committed so the paper can be reviewed without rerunning the scripts.
