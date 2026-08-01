from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "docs" / "paper"


def test_paper_generated_assets_and_honesty_sections_are_present() -> None:
    audit = json.loads((PAPER / "generated" / "source_audit.json").read_text(encoding="utf-8"))
    assert isinstance(audit, dict)
    checks = audit["checks"]
    assert checks["all_mc_estimates_within_bounds"] is True
    assert checks["all_benchmark_capabilities_have_evidence"] is True

    for relative in (
        "generated/benchmark_table.tex",
        "generated/non_win_table.tex",
        "generated/mc_bounds_table.tex",
        "generated/math_appendix.tex",
        "figures/mc_bounds.pdf",
    ):
        assert (PAPER / relative).exists()

    manuscript = (PAPER / "main.tex").read_text(encoding="utf-8")
    assert "Ville's inequality" in manuscript
    assert "Doob's $L^2$ maximal inequality" in manuscript
    assert "layer-cake/Markov-chain" in manuscript
    assert "\\section{Limitations}" in manuscript
    assert "The contribution is a synthesis" in manuscript
