"""Bandit policies used by the Phase 0 reproduction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np
from numpy.typing import NDArray

from velvet.research.bernoulli import BetaBernoulliPosterior, FloatArray

BoolArray = NDArray[np.bool_]


@dataclass(frozen=True)
class PolicyDecision:
    """One policy decision plus diagnostics needed for experiment summaries."""

    action: int
    epsilon: float = 0.0
    used_override: bool = False
    override_had_open_gate: bool = False
    gate_size: int = 0
    baseline: float = 0.0
    selected_delight: float = 0.0


class BanditPolicy(Protocol):
    @property
    def name(self) -> str:
        """Stable policy label for outputs."""
        ...

    def select(
        self,
        posterior: BetaBernoulliPosterior,
        rng: np.random.Generator,
        round_index: int,
    ) -> PolicyDecision:
        """Select an action from the current posterior."""


@dataclass(frozen=True)
class EpsilonGreedyPolicy:
    """Annealed epsilon-greedy baseline with the paper's half-life schedule."""

    half_life: float = 100.0
    name: str = "epsilon_greedy"

    def select(
        self,
        posterior: BetaBernoulliPosterior,
        rng: np.random.Generator,
        round_index: int,
    ) -> PolicyDecision:
        epsilon = schedule_epsilon(self.half_life, round_index)
        means = posterior.means()
        use_override = bool(rng.random() < epsilon)
        if use_override:
            action = int(rng.integers(posterior.num_arms))
        else:
            action = int(np.argmax(means))
        return PolicyDecision(action=action, epsilon=epsilon, used_override=use_override)


@dataclass(frozen=True)
class ThompsonSamplingPolicy:
    """Exact Thompson Sampling for independent Beta-Bernoulli arms."""

    name: str = "thompson_sampling"

    def select(
        self,
        posterior: BetaBernoulliPosterior,
        rng: np.random.Generator,
        round_index: int,
    ) -> PolicyDecision:
        del round_index
        return PolicyDecision(action=int(np.argmax(posterior.sample_means(rng))))


@dataclass(frozen=True)
class DelightScores:
    """Prospective-delight quantities for a posterior snapshot."""

    host_probabilities: FloatArray
    expected_improvement: FloatArray
    surprisal: FloatArray
    delight: FloatArray
    gate_mask: BoolArray
    baseline: float

    @property
    def gate_size(self) -> int:
        return int(np.count_nonzero(self.gate_mask))


@dataclass(frozen=True)
class CertifiedDelightScores:
    """Max-DE certificate diagnostics for a posterior snapshot."""

    host_probabilities: FloatArray
    expected_improvement: FloatArray
    lower_certificate: FloatArray
    upper_certificate: FloatArray
    surprisal: FloatArray
    certified_delight: FloatArray
    upper_delight: FloatArray
    inspect_mask: BoolArray
    lockout_mask: BoolArray
    refinement_mask: BoolArray
    baseline: float
    threshold: float

    @property
    def gate_mask(self) -> BoolArray:
        return self.inspect_mask

    @property
    def gate_size(self) -> int:
        return int(np.count_nonzero(self.inspect_mask))

    @property
    def lockout_size(self) -> int:
        return int(np.count_nonzero(self.lockout_mask))

    @property
    def refinement_size(self) -> int:
        return int(np.count_nonzero(self.refinement_mask))


@dataclass(frozen=True)
class DelightGatedPolicy:
    """Delight-gated exploration for Bernoulli bandits.

    The default host is the greedy-host version shown in Appendix J of the paper. Passing a
    positive host_temperature switches to the near-greedy Boltzmann host described in Section 2.
    """

    half_life: float = 100.0
    gate_price: float = 0.1
    surprisal_cap: float = 10.0
    host_temperature: float | None = None
    name: str = "delight_gated"

    def select(
        self,
        posterior: BetaBernoulliPosterior,
        rng: np.random.Generator,
        round_index: int,
    ) -> PolicyDecision:
        epsilon = schedule_epsilon(self.half_life, round_index)
        scores = self.score(posterior)
        host_action = sample_categorical(scores.host_probabilities, rng)

        gated_delight = np.where(scores.gate_mask, scores.delight, 0.0)
        if scores.gate_size > 0:
            override_probabilities = normalize(gated_delight)
        else:
            override_probabilities = scores.host_probabilities

        use_override = bool(rng.random() < epsilon)
        action = sample_categorical(override_probabilities, rng) if use_override else host_action
        return PolicyDecision(
            action=action,
            epsilon=epsilon,
            used_override=use_override,
            override_had_open_gate=use_override and scores.gate_size > 0,
            gate_size=scores.gate_size,
            baseline=scores.baseline,
            selected_delight=float(scores.delight[action]),
        )

    def score(self, posterior: BetaBernoulliPosterior) -> DelightScores:
        means = posterior.means()
        host_probabilities = host_distribution(means, self.host_temperature)
        baseline = float(np.max(means))
        expected_improvement = posterior.expected_improvement(baseline)
        surprisal = relative_surprisal(host_probabilities, self.surprisal_cap)
        delight = expected_improvement * surprisal
        gate_mask = delight >= self.gate_price
        return DelightScores(
            host_probabilities=host_probabilities,
            expected_improvement=expected_improvement,
            surprisal=surprisal,
            delight=delight,
            gate_mask=gate_mask,
            baseline=baseline,
        )


@dataclass(frozen=True)
class CertifiedMaxDEPolicy:
    """Max-DE certificate gate for Bernoulli posterior arms.

    `inspect_mask` is opened only by a finite-horizon lower certificate.
    `lockout_mask` is closed only by the O(1) upper certificate. Arms between
    those bounds remain in the refinement zone instead of being treated as
    permanent failures.
    """

    half_life: float = 100.0
    gate_price: float = 0.1
    lookback_horizon: int = 3
    surprisal_cap: float = 10.0
    host_temperature: float | None = None
    name: str = "certified_max_de"

    def select(
        self,
        posterior: BetaBernoulliPosterior,
        rng: np.random.Generator,
        round_index: int,
    ) -> PolicyDecision:
        epsilon = schedule_epsilon(self.half_life, round_index)
        scores = self.score(posterior)
        host_action = sample_categorical(scores.host_probabilities, rng)

        inspected_delight = np.where(scores.inspect_mask, scores.certified_delight, 0.0)
        if scores.gate_size > 0:
            override_probabilities = normalize(inspected_delight)
        else:
            override_probabilities = scores.host_probabilities

        use_override = bool(rng.random() < epsilon)
        action = sample_categorical(override_probabilities, rng) if use_override else host_action
        return PolicyDecision(
            action=action,
            epsilon=epsilon,
            used_override=use_override,
            override_had_open_gate=use_override and scores.gate_size > 0,
            gate_size=scores.gate_size,
            baseline=scores.baseline,
            selected_delight=float(scores.certified_delight[action]),
        )

    def score(self, posterior: BetaBernoulliPosterior) -> CertifiedDelightScores:
        if self.lookback_horizon < 0:
            raise ValueError("lookback_horizon must be non-negative")
        means = posterior.means()
        host_probabilities = host_distribution(means, self.host_temperature)
        baseline = float(np.max(means))
        expected_improvement = posterior.expected_improvement(baseline)
        lower = posterior.lower_certificate(baseline, self.lookback_horizon)
        upper = posterior.upper_certificate(baseline)
        surprisal = relative_surprisal(host_probabilities, self.surprisal_cap)
        certified_delight = lower * surprisal
        upper_delight = upper * surprisal
        inspect_mask = certified_delight >= self.gate_price
        lockout_mask = upper_delight < self.gate_price
        refinement_mask = ~(inspect_mask | lockout_mask)
        return CertifiedDelightScores(
            host_probabilities=host_probabilities,
            expected_improvement=expected_improvement,
            lower_certificate=lower,
            upper_certificate=upper,
            surprisal=surprisal,
            certified_delight=certified_delight,
            upper_delight=upper_delight,
            inspect_mask=inspect_mask,
            lockout_mask=lockout_mask,
            refinement_mask=refinement_mask,
            baseline=baseline,
            threshold=self.gate_price,
        )


def schedule_epsilon(half_life: float, round_index: int) -> float:
    if half_life <= 0:
        raise ValueError("half_life must be positive")
    if round_index < 0:
        raise ValueError("round_index must be non-negative")
    return float(half_life / (half_life + round_index))


def host_distribution(means: FloatArray, temperature: float | None = None) -> FloatArray:
    if temperature is None or temperature <= 0.0:
        probabilities = np.zeros_like(means, dtype=np.float64)
        probabilities[int(np.argmax(means))] = 1.0
        return probabilities

    logits = means / temperature
    logits = logits - float(np.max(logits))
    unnormalized = np.exp(logits)
    return normalize(unnormalized)


def relative_surprisal(host_probabilities: FloatArray, cap: float) -> FloatArray:
    if cap <= 0:
        raise ValueError("surprisal cap must be positive")
    if np.count_nonzero(host_probabilities) == 1:
        surprisal = np.full_like(host_probabilities, cap, dtype=np.float64)
        surprisal[int(np.argmax(host_probabilities))] = 0.0
        return surprisal

    tiny = np.finfo(np.float64).tiny
    negative_log = -np.log(np.clip(host_probabilities, tiny, 1.0))
    shifted = np.maximum(negative_log - float(np.min(negative_log)), 0.0)
    return np.minimum(shifted, cap).astype(np.float64, copy=False)


def normalize(weights: FloatArray) -> FloatArray:
    total = float(np.sum(weights))
    if total <= 0.0 or not np.isfinite(total):
        raise ValueError("cannot normalize non-positive or non-finite weights")
    return (weights / total).astype(np.float64, copy=False)


def sample_categorical(probabilities: FloatArray, rng: np.random.Generator) -> int:
    return int(rng.choice(probabilities.shape[0], p=probabilities))
