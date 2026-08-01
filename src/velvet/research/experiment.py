"""Experiment loop and aggregation utilities for bandit reproductions."""

from __future__ import annotations

import csv
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast, overload

import numpy as np
from numpy.typing import NDArray

from velvet.research.bernoulli import BernoulliBandit, BetaBernoulliPosterior, FloatArray
from velvet.research.policies import BanditPolicy


@dataclass(frozen=True)
class RunTrace:
    """Diagnostics from one policy on one bandit instance."""

    policy_name: str
    num_arms: int
    horizon: int
    seed: int
    best_mean: float
    total_regret: float
    override_rate: float
    gated_override_rate: float
    gate_open_rate: float
    mean_gate_size: float
    cumulative_regret: FloatArray


PolicyFactory = Callable[[], BanditPolicy]
CurveMap = dict[tuple[int, str], list[FloatArray]]


def run_policy(
    *,
    bandit: BernoulliBandit,
    policy: BanditPolicy,
    horizon: int,
    seed: int,
) -> RunTrace:
    if horizon <= 0:
        raise ValueError("horizon must be positive")

    rng = np.random.default_rng(seed)
    posterior = BetaBernoulliPosterior.uniform_prior(bandit.num_arms)
    cumulative_regret = np.empty(horizon, dtype=np.float64)
    regret = 0.0
    override_count = 0
    gated_override_count = 0
    gate_open_count = 0
    gate_size_total = 0

    for round_index in range(horizon):
        decision = policy.select(posterior, rng, round_index)
        reward = bandit.pull(decision.action, rng)
        posterior.update(decision.action, reward)

        regret += bandit.instantaneous_regret(decision.action)
        cumulative_regret[round_index] = regret

        override_count += int(decision.used_override)
        gated_override_count += int(decision.override_had_open_gate)
        gate_open_count += int(decision.gate_size > 0)
        gate_size_total += decision.gate_size

    return RunTrace(
        policy_name=policy.name,
        num_arms=bandit.num_arms,
        horizon=horizon,
        seed=seed,
        best_mean=bandit.best_mean,
        total_regret=regret,
        override_rate=override_count / horizon,
        gated_override_rate=gated_override_count / horizon,
        gate_open_rate=gate_open_count / horizon,
        mean_gate_size=gate_size_total / horizon,
        cumulative_regret=cumulative_regret,
    )


def run_grid(
    *,
    num_arms_values: Sequence[int],
    horizon: int,
    seeds: Iterable[int],
    policy_factories: Sequence[PolicyFactory],
) -> list[RunTrace]:
    traces: list[RunTrace] = []
    for num_arms in num_arms_values:
        for seed in seeds:
            instance_rng = np.random.default_rng(seed_for(seed, num_arms, 0))
            bandit = BernoulliBandit.random(num_arms, instance_rng)
            for policy_index, make_policy in enumerate(policy_factories, start=1):
                policy = make_policy()
                trace = run_policy(
                    bandit=bandit,
                    policy=policy,
                    horizon=horizon,
                    seed=seed_for(seed, num_arms, policy_index),
                )
                traces.append(trace)
    return traces


def write_summary_csv(traces: Sequence[RunTrace], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    grouped: dict[tuple[int, str], list[RunTrace]] = {}
    for trace in traces:
        grouped.setdefault((trace.num_arms, trace.policy_name), []).append(trace)

    fieldnames = [
        "num_arms",
        "policy",
        "horizon",
        "seeds",
        "mean_total_regret",
        "stderr_total_regret",
        "mean_best_arm",
        "mean_override_rate",
        "mean_gated_override_rate",
        "mean_gate_open_rate",
        "mean_gate_size",
    ]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for (num_arms, policy_name), group in sorted(grouped.items()):
            regrets = np.array([trace.total_regret for trace in group], dtype=np.float64)
            writer.writerow(
                {
                    "num_arms": num_arms,
                    "policy": policy_name,
                    "horizon": group[0].horizon,
                    "seeds": len(group),
                    "mean_total_regret": f"{float(np.mean(regrets)):.6f}",
                    "stderr_total_regret": f"{standard_error(regrets):.6f}",
                    "mean_best_arm": f"{float(np.mean([t.best_mean for t in group])):.6f}",
                    "mean_override_rate": f"{float(np.mean([t.override_rate for t in group])):.6f}",
                    "mean_gated_override_rate": (
                        f"{float(np.mean([t.gated_override_rate for t in group])):.6f}"
                    ),
                    "mean_gate_open_rate": (
                        f"{float(np.mean([t.gate_open_rate for t in group])):.6f}"
                    ),
                    "mean_gate_size": f"{float(np.mean([t.mean_gate_size for t in group])):.6f}",
                }
            )


def write_curves_csv(traces: Sequence[RunTrace], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    curves = group_curves(traces)
    fieldnames = ["num_arms", "policy", "round", "mean_cumulative_regret", "stderr"]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for (num_arms, policy_name), arrays in sorted(curves.items()):
            stacked = np.vstack(arrays)
            means = np.mean(stacked, axis=0)
            stderrs = standard_error_axis(stacked, axis=0)
            for round_index, (mean, stderr) in enumerate(zip(means, stderrs, strict=True), start=1):
                writer.writerow(
                    {
                        "num_arms": num_arms,
                        "policy": policy_name,
                        "round": round_index,
                        "mean_cumulative_regret": f"{float(mean):.6f}",
                        "stderr": f"{float(stderr):.6f}",
                    }
                )


def group_curves(traces: Sequence[RunTrace]) -> CurveMap:
    curves: CurveMap = {}
    for trace in traces:
        curves.setdefault((trace.num_arms, trace.policy_name), []).append(trace.cumulative_regret)
    return curves


def seed_for(seed: int, num_arms: int, stream: int) -> int:
    sequence = np.random.SeedSequence([seed, num_arms, stream])
    return int(sequence.generate_state(1, dtype=np.uint32)[0])


@overload
def standard_error(values: NDArray[np.float64], axis: None = None) -> float: ...


@overload
def standard_error(values: NDArray[np.float64], axis: int) -> NDArray[np.float64]: ...


def standard_error(
    values: NDArray[np.float64], axis: int | None = None
) -> float | NDArray[np.float64]:
    count = values.shape[axis] if axis is not None else values.size
    if count <= 1:
        zeros = np.zeros_like(np.mean(values, axis=axis), dtype=np.float64)
        if axis is None:
            return float(zeros)
        return zeros
    result = np.std(values, axis=axis, ddof=1) / np.sqrt(count)
    if axis is None:
        return float(result)
    return cast(NDArray[np.float64], result)


def standard_error_axis(values: NDArray[np.float64], axis: int) -> NDArray[np.float64]:
    return standard_error(values, axis=axis)
