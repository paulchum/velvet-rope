#!/usr/bin/env python3
"""Regenerate paper tables, figures, and proof appendices from repo sources."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import matplotlib.pyplot as plt
import numpy as np
from scipy.special import betainc  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from velvet.research.bernoulli import (  # type: ignore[import-untyped]  # noqa: E402,I001
    BetaBernoulliPosterior,
)

JsonObject = dict[str, Any]

PAPER_DIR = Path(__file__).resolve().parent
GENERATED_DIR = PAPER_DIR / "generated"
FIGURES_DIR = PAPER_DIR / "figures"
MATH_DIR = ROOT / "docs" / "math"
BENCHMARK_RESULTS = ROOT / "benchmarks" / "agent_authorization" / "results" / "v0.2.1.json"
BERNOULLI_SOURCE = ROOT / "src" / "velvet" / "research" / "bernoulli.py"
FIXED_GENERATED_AT = "1970-01-01T00:00:00Z"
MC_PATHS = 10_000
MC_HORIZON = 200
LOWER_HORIZON = 5

MATH_FILES = (
    "exact_max_de_theorem.txt",
    "lower_certificates_for_max_de_inspection_theorem.txt",
    "O1_Martingale_Maximal_Certificates_for_Safe_Lockout.txt",
    "certified_max_de_theorem.txt",
    "beta_1_2_recovery_window_final_theorem.txt",
    "information_budget_for_martingale_supremum_exploration.txt",
    "moving_baseline_hard_shutoff_theorem.txt",
    "fixed_price_max_de_regret_theorem.txt",
    "budget_safety_deterministic_theorem.txt",
)

MC_PARAMETER_GRID = (
    (1.0, 2.0, 0.55),
    (1.0, 3.0, 0.55),
    (2.0, 2.0, 0.50),
    (3.0, 5.0, 0.45),
    (5.0, 2.0, 0.65),
    (2.0, 6.0, 0.40),
    (8.0, 4.0, 0.60),
)


def main() -> int:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    benchmark = _load_json(BENCHMARK_RESULTS)
    mc_rows = _monte_carlo_rows()
    _write_json(GENERATED_DIR / "mc_bounds.json", {"rows": mc_rows})
    _write_text(GENERATED_DIR / "mc_bounds_table.tex", _render_mc_table(mc_rows))
    _write_mc_figure(mc_rows, FIGURES_DIR / "mc_bounds.pdf")
    _write_text(GENERATED_DIR / "benchmark_table.tex", _render_benchmark_table(benchmark))
    _write_text(GENERATED_DIR / "non_win_table.tex", _render_non_win_table(benchmark))
    _write_text(GENERATED_DIR / "math_appendix.tex", _render_math_appendix())
    _write_text(GENERATED_DIR / "reproducibility_commands.tex", _render_repro_commands())
    _write_text(GENERATED_DIR / "macros.tex", _render_macros(benchmark))
    _write_json(GENERATED_DIR / "source_audit.json", _source_audit(mc_rows, benchmark))
    return 0


def _monte_carlo_rows() -> list[JsonObject]:
    rows = []
    for index, (alpha, beta, baseline) in enumerate(MC_PARAMETER_GRID, start=1):
        posterior = BetaBernoulliPosterior(
            alpha=np.array([alpha], dtype=np.float64),
            beta=np.array([beta], dtype=np.float64),
        )
        lower = float(posterior.lower_certificate(baseline, LOWER_HORIZON)[0])
        upper = float(posterior.upper_certificate(baseline)[0])
        estimate, half_width = _mc_phi_estimate(
            alpha,
            beta,
            baseline,
            seed=_seed_for(alpha, beta, baseline),
        )
        if not lower <= estimate <= upper:
            raise RuntimeError(
                "Monte-Carlo estimate fell outside certificate bracket for "
                f"Beta({alpha:g},{beta:g}), v={baseline:g}: "
                f"L={lower}, estimate={estimate}, U={upper}"
            )
        rows.append(
            {
                "index": index,
                "alpha": alpha,
                "beta": beta,
                "baseline": baseline,
                "lower_horizon": LOWER_HORIZON,
                "lower_certificate": lower,
                "mc_paths": MC_PATHS,
                "mc_horizon": MC_HORIZON,
                "mc_phi_estimate": estimate,
                "mc_95_half_width": half_width,
                "upper_certificate": upper,
            }
        )
    return rows


def _mc_phi_estimate(
    alpha: float,
    beta: float,
    baseline: float,
    *,
    seed: int,
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    theta = rng.beta(alpha, beta, size=MC_PATHS)
    path_alpha = np.full(MC_PATHS, alpha, dtype=np.float64)
    path_beta = np.full(MC_PATHS, beta, dtype=np.float64)
    running = _expected_improvement(path_alpha, path_beta, baseline)
    for _ in range(MC_HORIZON):
        success = rng.random(MC_PATHS) < theta
        path_alpha += success
        path_beta += ~success
        running = np.maximum(running, _expected_improvement(path_alpha, path_beta, baseline))
    terminal = np.maximum(theta - baseline, 0.0)
    samples = np.maximum(running, terminal)
    estimate = float(samples.mean())
    half_width = float(1.96 * samples.std(ddof=1) / np.sqrt(MC_PATHS))
    return estimate, half_width


def _expected_improvement(
    alpha: np.ndarray,
    beta: np.ndarray,
    baseline: float,
) -> np.ndarray:
    posterior_mean = alpha / (alpha + beta)
    tail_probability = 1.0 - betainc(alpha, beta, baseline)
    tail_first_moment = 1.0 - betainc(alpha + 1.0, beta, baseline)
    return cast(
        np.ndarray,
        np.maximum(posterior_mean * tail_first_moment - baseline * tail_probability, 0.0),
    )


def _seed_for(alpha: float, beta: float, baseline: float) -> int:
    payload = f"{alpha:.6f}:{beta:.6f}:{baseline:.6f}".encode("ascii")
    return int(hashlib.sha256(payload).hexdigest()[:8], 16)


def _write_mc_figure(rows: list[JsonObject], path: Path) -> None:
    x = np.arange(len(rows))
    lower = np.array([row["lower_certificate"] for row in rows], dtype=np.float64)
    estimate = np.array([row["mc_phi_estimate"] for row in rows], dtype=np.float64)
    half_width = np.array([row["mc_95_half_width"] for row in rows], dtype=np.float64)
    upper = np.array([row["upper_certificate"] for row in rows], dtype=np.float64)
    labels = [
        rf"$\mathrm{{Beta}}({row['alpha']:g},{row['beta']:g}), v={row['baseline']:.2f}$"
        for row in rows
    ]

    plt.rcParams.update({"font.size": 9})
    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    ax.plot(x, lower, marker="o", color="#276fbf", label=r"lower certificate $L$")
    ax.errorbar(
        x,
        estimate,
        yerr=half_width,
        marker="s",
        color="#111111",
        linestyle="none",
        capsize=3,
        label=r"Monte-Carlo $\hat{\Phi}$",
    )
    ax.plot(x, upper, marker="^", color="#c44536", label=r"upper certificate $U$")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylabel("expected supremum value")
    ax.set_title("Monte-Carlo Max-DE supremum estimates bracketed by certificates")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="upper left", frameon=False, ncols=3)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def _render_mc_table(rows: list[JsonObject]) -> str:
    lines = [
        r"\begin{tabular}{rrrrrrr}",
        r"\toprule",
        r"$\alpha$ & $\beta$ & $v$ & $L^{(5)}$ & $\hat{\Phi}$ & 95\% half-width & $U$ \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            " & ".join(
                [
                    f"{row['alpha']:.0f}",
                    f"{row['beta']:.0f}",
                    f"{row['baseline']:.2f}",
                    _fmt(row["lower_certificate"]),
                    _fmt(row["mc_phi_estimate"]),
                    _fmt(row["mc_95_half_width"]),
                    _fmt(row["upper_certificate"]),
                ]
            )
            + r" \\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    return "\n".join(lines)


def _render_benchmark_table(benchmark: JsonObject) -> str:
    lines = [
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        "System & Cert. & Det. & Replay & Public verify & Tamper \\\\",
        r"\midrule",
    ]
    for row in benchmark["capability_matrix"]:
        caps = row["capabilities"]
        lines.append(
            " & ".join(
                [
                    _latex_escape(str(row["system"])),
                    _paper_cell(caps["certificate_emission"]),
                    _paper_cell(caps["determinism"]),
                    _paper_cell(caps["replayability"]),
                    _paper_cell(caps["independent_verifiability"]),
                    _paper_cell(caps["tamper_evidence"]),
                ]
            )
            + r" \\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    return "\n".join(lines)


def _render_non_win_table(benchmark: JsonObject) -> str:
    rows = benchmark.get("velvet_non_win_cases", [])
    lines = [
        r"\begin{tabular}{ll}",
        r"\toprule",
        r"Case & Matching or lower benchmark liability cost \\",
        r"\midrule",
    ]
    for row in rows:
        peers = ", ".join(
            f"{item['system']} ({item['decision']}, cost={item['liability_cost']})"
            for item in row["systems_matching_or_beating_velvet"]
        )
        lines.append(f"{_latex_escape(str(row['case_id']))} & {_latex_escape(peers)} " + r"\\")
    if not rows:
        lines.append(r"None & None \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    return "\n".join(lines)


def _render_math_appendix() -> str:
    lines = [
        "% Generated verbatim from docs/math/*.txt by docs/paper/generate_assets.py.",
        r"\section{Verbatim Proof Source Notes}",
        r"\label{app:proofs}",
        (
            "The following source notes are included verbatim from the repository. "
            "They are not retyped in this paper."
        ),
    ]
    for name in MATH_FILES:
        path = MATH_DIR / name
        title = _latex_escape(path.stem.replace("_", " "))
        text = path.read_text(encoding="utf-8")
        if r"\end{verbatim}" in text:
            raise RuntimeError(f"{path} contains an unsupported verbatim terminator")
        lines.extend(
            [
                rf"\subsection{{{title}}}",
                r"\begin{small}",
                r"\begin{verbatim}",
                text.rstrip(),
                r"\end{verbatim}",
                r"\end{small}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def _render_repro_commands() -> str:
    return "\n".join(
        [
            r"\begin{verbatim}",
            "uv run velvet agent-auth-benchmark --report-dir reports/agent_auth",
            "uv run python docs/paper/generate_assets.py",
            "uv run python docs/paper/build.py",
            "uv run pytest",
            "uv run ruff check .",
            "uv run mypy src tests",
            "cargo fmt --check",
            "cargo clippy --workspace --all-targets -- -D warnings",
            "cargo test --workspace",
            r"\end{verbatim}",
            "",
        ]
    )


def _render_macros(benchmark: JsonObject) -> str:
    rows = benchmark["capability_matrix"]
    velvet = next(row for row in rows if row["system"] == "Velvet Certified Max-DE")
    non_win_count = len(benchmark.get("velvet_non_win_cases", []))
    return "\n".join(
        [
            "% Generated by docs/paper/generate_assets.py.",
            rf"\newcommand{{\PaperGeneratedAt}}{{{FIXED_GENERATED_AT}}}",
            rf"\newcommand{{\BenchmarkVersion}}{{{benchmark['benchmark_version']}}}",
            rf"\newcommand{{\BenchmarkRepeatCount}}{{{benchmark['repeat_count']}}}",
            rf"\newcommand{{\BenchmarkSystemCount}}{{{len(rows)}}}",
            rf"\newcommand{{\BenchmarkNonWinCount}}{{{non_win_count}}}",
            rf"\newcommand{{\MonteCarloPathCount}}{{{MC_PATHS}}}",
            rf"\newcommand{{\MonteCarloHorizon}}{{{MC_HORIZON}}}",
            rf"\newcommand{{\LowerCertificateHorizon}}{{{LOWER_HORIZON}}}",
            rf"\newcommand{{\VelvetMeasuredCases}}{{{velvet['completed_case_count']}}}",
            "",
        ]
    )


def _source_audit(mc_rows: list[JsonObject], benchmark: JsonObject) -> JsonObject:
    math_hashes = {
        name: _sha256(MATH_DIR / name)
        for name in MATH_FILES
    }
    return {
        "generated_at": FIXED_GENERATED_AT,
        "bernoulli_source": str(BERNOULLI_SOURCE.relative_to(ROOT)),
        "bernoulli_source_sha256": _sha256(BERNOULLI_SOURCE),
        "math_file_sha256": math_hashes,
        "benchmark_results": str(BENCHMARK_RESULTS.relative_to(ROOT)),
        "benchmark_results_sha256": _sha256(BENCHMARK_RESULTS),
        "monte_carlo_grid": mc_rows,
        "checks": {
            "all_mc_estimates_within_bounds": all(
                row["lower_certificate"] <= row["mc_phi_estimate"] <= row["upper_certificate"]
                for row in mc_rows
            ),
            "all_benchmark_capabilities_have_evidence": all(
                bool(capability.get("evidence_pointer"))
                for row in benchmark["capability_matrix"]
                for capability in row["capabilities"].values()
            ),
        },
    }


def _paper_cell(capability: JsonObject) -> str:
    status = capability["status"]
    if status == "pass":
        return "Y"
    if status == "fail":
        return "N"
    return "NR"


def _fmt(value: Any) -> str:
    return f"{float(value):.4f}"


def _latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in value)


def _load_json(path: Path) -> JsonObject:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
