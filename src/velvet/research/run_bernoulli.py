"""Run Phase 0 Bernoulli-bandit comparisons."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from velvet.research.experiment import (
    RunTrace,
    group_curves,
    run_grid,
    standard_error,
    standard_error_axis,
    write_curves_csv,
    write_summary_csv,
)
from velvet.research.policies import (
    BanditPolicy,
    DelightGatedPolicy,
    EpsilonGreedyPolicy,
    ThompsonSamplingPolicy,
)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir)

    factories = make_policy_factories(args)
    traces = run_grid(
        num_arms_values=args.arms,
        horizon=args.horizon,
        seeds=range(args.seeds),
        policy_factories=factories,
    )

    write_summary_csv(traces, output_dir / "summary.csv")
    write_curves_csv(traces, output_dir / "curves.csv")
    if not args.no_plots:
        plot_regret_vs_arms(traces, output_dir / "regret_vs_arms.png")
        plot_learning_curves(traces, output_dir / "learning_curves.png")

    print(f"Wrote Phase 0 Bernoulli outputs to {output_dir}")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arms", nargs="+", type=int, default=[10, 100, 1000])
    parser.add_argument("--horizon", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--half-life", type=float, default=100.0)
    parser.add_argument("--gate-price", type=float, default=0.1)
    parser.add_argument("--surprisal-cap", type=float, default=10.0)
    parser.add_argument(
        "--host-temperature",
        type=float,
        default=None,
        help="Use a Boltzmann host at this temperature; omitted means greedy host.",
    )
    parser.add_argument(
        "--policies",
        nargs="+",
        choices=["delight", "epsilon_greedy", "thompson_sampling"],
        default=["delight", "epsilon_greedy", "thompson_sampling"],
    )
    parser.add_argument("--output-dir", default="results/phase0_bernoulli")
    parser.add_argument("--no-plots", action="store_true")
    return parser.parse_args(argv)


def make_policy_factories(args: argparse.Namespace) -> list[Callable[[], BanditPolicy]]:
    factories: list[Callable[[], BanditPolicy]] = []
    for policy in args.policies:
        if policy == "delight":
            factories.append(make_delight_factory(args))
        elif policy == "epsilon_greedy":
            factories.append(make_epsilon_greedy_factory(args))
        elif policy == "thompson_sampling":
            factories.append(ThompsonSamplingPolicy)
        else:  # pragma: no cover - argparse enforces choices.
            raise ValueError(f"unknown policy: {policy}")
    return factories


def make_delight_factory(args: argparse.Namespace) -> Callable[[], BanditPolicy]:
    def factory() -> BanditPolicy:
        return DelightGatedPolicy(
            half_life=args.half_life,
            gate_price=args.gate_price,
            surprisal_cap=args.surprisal_cap,
            host_temperature=args.host_temperature,
        )

    return factory


def make_epsilon_greedy_factory(args: argparse.Namespace) -> Callable[[], BanditPolicy]:
    def factory() -> BanditPolicy:
        return EpsilonGreedyPolicy(half_life=args.half_life)

    return factory


def plot_regret_vs_arms(traces: Sequence[RunTrace], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    policies = sorted({trace.policy_name for trace in traces})
    arms = sorted({trace.num_arms for trace in traces})

    _, ax = plt.subplots(figsize=(7, 4.5))
    for policy in policies:
        means: list[float] = []
        errors: list[float] = []
        for num_arms in arms:
            regrets = np.array(
                [
                    trace.total_regret
                    for trace in traces
                    if trace.policy_name == policy and trace.num_arms == num_arms
                ],
                dtype=np.float64,
            )
            means.append(float(np.mean(regrets)))
            errors.append(float(standard_error(regrets)))
        ax.errorbar(arms, means, yerr=errors, marker="o", capsize=3, label=policy)

    ax.set_xscale("log")
    ax.set_xlabel("Number of arms K")
    ax.set_ylabel("Cumulative regret")
    ax.set_title("Bernoulli bandits: regret after T rounds")
    ax.grid(True, which="both", linewidth=0.4, alpha=0.35)
    ax.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def plot_learning_curves(traces: Sequence[RunTrace], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    curves = group_curves(traces)
    policies = sorted({policy for _, policy in curves})
    arms = sorted({num_arms for num_arms, _ in curves})

    fig, axes = plt.subplots(1, len(arms), figsize=(5 * len(arms), 4), sharey=False)
    axes_array = np.atleast_1d(axes)
    for ax, num_arms in zip(axes_array, arms, strict=True):
        for policy in policies:
            arrays = curves.get((num_arms, policy))
            if not arrays:
                continue
            stacked = np.vstack(arrays)
            mean = np.mean(stacked, axis=0)
            stderr = standard_error_axis(stacked, axis=0)
            rounds = np.arange(1, mean.shape[0] + 1)
            ax.plot(rounds, mean, label=policy)
            ax.fill_between(rounds, mean - stderr, mean + stderr, alpha=0.16)
        ax.set_title(f"K={num_arms}")
        ax.set_xlabel("Round")
        ax.set_ylabel("Cumulative regret")
        ax.grid(True, linewidth=0.4, alpha=0.35)
    axes_array[0].legend()
    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


if __name__ == "__main__":
    raise SystemExit(main())
