"""Bernoulli bandit primitives for the Phase 0 reproduction."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from math import log, sqrt
from typing import cast

import numpy as np
from numpy.typing import NDArray
from scipy.special import betainc  # type: ignore[import-untyped]

FloatArray = NDArray[np.float64]


@dataclass(frozen=True)
class BernoulliBandit:
    """A fixed K-armed Bernoulli bandit instance."""

    means: FloatArray

    @classmethod
    def random(cls, num_arms: int, rng: np.random.Generator) -> BernoulliBandit:
        if num_arms <= 0:
            raise ValueError("num_arms must be positive")
        return cls(means=rng.random(num_arms, dtype=np.float64))

    @property
    def num_arms(self) -> int:
        return int(self.means.shape[0])

    @property
    def best_mean(self) -> float:
        return float(np.max(self.means))

    def pull(self, action: int, rng: np.random.Generator) -> int:
        self._validate_action(action)
        return int(rng.random() < self.means[action])

    def instantaneous_regret(self, action: int) -> float:
        self._validate_action(action)
        return self.best_mean - float(self.means[action])

    def _validate_action(self, action: int) -> None:
        if action < 0 or action >= self.num_arms:
            raise IndexError(f"action {action} is outside [0, {self.num_arms})")


@dataclass(frozen=True)
class CompensatorStep:
    """One upper-envelope refinement ledger entry for a posterior arm."""

    arm: int
    baseline: float
    horizon: int
    z_current: float
    expected_z_next: float
    increment: float
    initial_optionality: float
    cumulative_increment: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "arm": self.arm,
            "baseline": self.baseline,
            "horizon": self.horizon,
            "z_current": self.z_current,
            "expected_z_next": self.expected_z_next,
            "increment": self.increment,
            "initial_optionality": self.initial_optionality,
            "cumulative_increment": self.cumulative_increment,
        }


@dataclass
class BetaBernoulliPosterior:
    """Independent Beta posteriors for Bernoulli arm means."""

    alpha: FloatArray
    beta: FloatArray

    @classmethod
    def uniform_prior(cls, num_arms: int) -> BetaBernoulliPosterior:
        if num_arms <= 0:
            raise ValueError("num_arms must be positive")
        return cls(
            alpha=np.ones(num_arms, dtype=np.float64),
            beta=np.ones(num_arms, dtype=np.float64),
        )

    @property
    def num_arms(self) -> int:
        return int(self.alpha.shape[0])

    @property
    def pulls(self) -> FloatArray:
        return self.alpha + self.beta - 2.0

    def means(self) -> FloatArray:
        return self.alpha / (self.alpha + self.beta)

    def sample_means(self, rng: np.random.Generator) -> FloatArray:
        return rng.beta(self.alpha, self.beta)

    def update(self, action: int, reward: int) -> None:
        if reward not in {0, 1}:
            raise ValueError("Bernoulli reward must be 0 or 1")
        if action < 0 or action >= self.num_arms:
            raise IndexError(f"action {action} is outside [0, {self.num_arms})")
        if reward == 1:
            self.alpha[action] += 1.0
        else:
            self.beta[action] += 1.0

    def expected_improvement(self, baseline: float) -> FloatArray:
        """Compute E[(theta_a - baseline)+] exactly for each Beta posterior.

        For theta ~ Beta(a, b),
        EI(v) = E[theta 1{theta > v}] - v P(theta > v)
              = a/(a+b) * (1 - I_v(a+1, b)) - v * (1 - I_v(a, b)).
        """

        v = float(np.clip(baseline, 0.0, 1.0))
        posterior_mean = self.means()
        tail_probability = 1.0 - betainc(self.alpha, self.beta, v)
        tail_first_moment = 1.0 - betainc(self.alpha + 1.0, self.beta, v)
        ei = posterior_mean * tail_first_moment - v * tail_probability
        return cast(FloatArray, np.maximum(ei, 0.0).astype(np.float64, copy=False))

    def lower_certificate(self, baseline: float, horizon: int) -> FloatArray:
        """Compute finite-horizon Max-DE lower certificates for each arm.

        The recursion evaluates E[max{Y, M_0, ..., M_r}], where
        Y=(theta-baseline)+ and M_t is the posterior expected-improvement
        martingale after t future Bernoulli observations. This is the
        terminal-augmented lower certificate described in the Max-DE notes.
        """

        if horizon < 0:
            raise ValueError("horizon must be non-negative")
        v = float(np.clip(baseline, 0.0, 1.0))
        values = [
            _lower_certificate_scalar(float(alpha), float(beta), v, horizon)
            for alpha, beta in zip(self.alpha, self.beta, strict=True)
        ]
        return np.array(values, dtype=np.float64)

    def upper_certificate(self, baseline: float) -> FloatArray:
        """Compute O(1) Max-DE upper certificates for each arm."""

        v = float(np.clip(baseline, 0.0, 1.0))
        values = [
            _upper_certificate_scalar(float(alpha), float(beta), v)
            for alpha, beta in zip(self.alpha, self.beta, strict=True)
        ]
        return np.array(values, dtype=np.float64)

    def refined_upper_certificate(self, baseline: float, horizon: int) -> FloatArray:
        """Compute path-conditioned finite-horizon upper certificates for each arm."""

        if horizon < 0:
            raise ValueError("horizon must be non-negative")
        v = float(np.clip(baseline, 0.0, 1.0))
        values = [
            _refined_upper_certificate_scalar(float(alpha), float(beta), v, int(horizon))
            for alpha, beta in zip(self.alpha, self.beta, strict=True)
        ]
        return np.array(values, dtype=np.float64)

    def compensator_step(
        self,
        arm: int,
        baseline: float,
        horizon: int,
        *,
        initial_optionality: float | None = None,
        cumulative_increment: float = 0.0,
    ) -> CompensatorStep:
        """Return an auditable upper-envelope refinement ledger step.

        This uses the O(1) upper certificate as a conservative finite ledger
        envelope. The increment is the predictable drop from the current upper
        envelope to the posterior-predictive next upper envelope.
        """

        if arm < 0 or arm >= self.num_arms:
            raise IndexError(f"arm {arm} is outside [0, {self.num_arms})")
        if horizon < 0:
            raise ValueError("horizon must be non-negative")
        alpha = float(self.alpha[arm])
        beta = float(self.beta[arm])
        v = float(np.clip(baseline, 0.0, 1.0))
        current = _upper_certificate_scalar(alpha, beta, v)
        success_probability = alpha / (alpha + beta)
        expected_next = (
            success_probability * _upper_certificate_scalar(alpha + 1.0, beta, v)
            + (1.0 - success_probability) * _upper_certificate_scalar(alpha, beta + 1.0, v)
        )
        increment = max(current - expected_next, 0.0)
        option_budget = (
            max(current - _expected_improvement_scalar(alpha, beta, v), 0.0)
            if initial_optionality is None
            else float(initial_optionality)
        )
        return CompensatorStep(
            arm=arm,
            baseline=v,
            horizon=horizon,
            z_current=current,
            expected_z_next=expected_next,
            increment=increment,
            initial_optionality=option_budget,
            cumulative_increment=float(cumulative_increment) + increment,
        )


def _expected_improvement_scalar(alpha: float, beta: float, baseline: float) -> float:
    v = float(np.clip(baseline, 0.0, 1.0))
    posterior_mean = alpha / (alpha + beta)
    tail_probability = 1.0 - float(betainc(alpha, beta, v))
    tail_first_moment = 1.0 - float(betainc(alpha + 1.0, beta, v))
    return max(posterior_mean * tail_first_moment - v * tail_probability, 0.0)


def _tail_second_moment(alpha: float, beta: float, threshold: float) -> float:
    x = float(np.clip(threshold, 0.0, 1.0))
    scale = alpha * (alpha + 1.0) / ((alpha + beta) * (alpha + beta + 1.0))
    return scale * (1.0 - float(betainc(alpha + 2.0, beta, x)))


def _tail_first_moment(alpha: float, beta: float, threshold: float) -> float:
    x = float(np.clip(threshold, 0.0, 1.0))
    return alpha / (alpha + beta) * (1.0 - float(betainc(alpha + 1.0, beta, x)))


def _tail_probability(alpha: float, beta: float, threshold: float) -> float:
    x = float(np.clip(threshold, 0.0, 1.0))
    return 1.0 - float(betainc(alpha, beta, x))


def _positive_part_second_moment_scalar(alpha: float, beta: float, threshold: float) -> float:
    x = float(np.clip(threshold, 0.0, 1.0))
    tail_second = _tail_second_moment(alpha, beta, x)
    tail_first = _tail_first_moment(alpha, beta, x)
    tail_prob = _tail_probability(alpha, beta, x)
    return max(tail_second - 2.0 * x * tail_first + x**2 * tail_prob, 0.0)


def _terminal_augmented_payoff(alpha: float, beta: float, baseline: float, z_value: float) -> float:
    return z_value + _expected_improvement_scalar(alpha, beta, baseline + z_value)


def _lower_certificate_scalar(alpha: float, beta: float, baseline: float, horizon: int) -> float:
    m0 = _expected_improvement_scalar(alpha, beta, baseline)

    @cache
    def recurse(a: float, b: float, remaining: int, z_value: float) -> float:
        if remaining == 0:
            return _terminal_augmented_payoff(a, b, baseline, z_value)
        success_probability = a / (a + b)
        success_z = max(z_value, _expected_improvement_scalar(a + 1.0, b, baseline))
        failure_z = max(z_value, _expected_improvement_scalar(a, b + 1.0, baseline))
        return (
            success_probability * recurse(a + 1.0, b, remaining - 1, success_z)
            + (1.0 - success_probability) * recurse(a, b + 1.0, remaining - 1, failure_z)
        )

    return recurse(alpha, beta, horizon, m0)


def _upper_certificate_scalar(alpha: float, beta: float, baseline: float) -> float:
    v = float(np.clip(baseline, 0.0, 1.0))
    max_payoff = max(1.0 - v, 0.0)
    if max_payoff == 0.0:
        return 0.0
    m_v = _expected_improvement_scalar(alpha, beta, v)
    if m_v <= 0.0:
        return 0.0

    log_envelope = m_v * (1.0 + log(max_payoff / m_v))
    threshold = v + m_v
    q_v = 0.0 if threshold >= 1.0 else _positive_part_second_moment_scalar(alpha, beta, threshold)
    l2_envelope = m_v + 2.0 * sqrt(q_v)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _path_conditioned_upper_base_scalar(
    alpha: float,
    beta: float,
    baseline: float,
    z_value: float,
) -> float:
    max_payoff = max(1.0 - baseline, 0.0)
    if max_payoff == 0.0:
        return 0.0
    if z_value >= max_payoff:
        return max_payoff
    if z_value <= 0.0:
        log_envelope = 0.0
    else:
        current_mean = _expected_improvement_scalar(alpha, beta, baseline)
        log_envelope = z_value + current_mean * log(max_payoff / z_value)
    h2 = _positive_part_second_moment_scalar(alpha, beta, baseline + z_value)
    l2_envelope = z_value + 2.0 * sqrt(h2)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _refined_upper_certificate_scalar(
    alpha: float,
    beta: float,
    baseline: float,
    horizon: int,
) -> float:
    initial = _expected_improvement_scalar(alpha, beta, baseline)
    horizon_free = _upper_certificate_scalar(alpha, beta, baseline)

    @cache
    def recurse(a: float, b: float, remaining: int, z_value: float) -> float:
        if remaining == 0:
            return _path_conditioned_upper_base_scalar(a, b, baseline, z_value)
        success_probability = a / (a + b)
        success_z = max(z_value, _expected_improvement_scalar(a + 1.0, b, baseline))
        failure_z = max(z_value, _expected_improvement_scalar(a, b + 1.0, baseline))
        return (
            success_probability * recurse(a + 1.0, b, remaining - 1, success_z)
            + (1.0 - success_probability) * recurse(a, b + 1.0, remaining - 1, failure_z)
        )

    candidates = [horizon_free]
    candidates.extend(recurse(alpha, beta, depth, initial) for depth in range(horizon + 1))
    return max(min(candidates), 0.0)
