"""Actual one-arm-per-round Bernoulli/Beta transition kernel.

This module implements Bayesian-predictive research objects only. It does not
encode artificial clocks, fixed-mu regret claims, or infinite-horizon lockout
logic.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from velvet.research.beta_ei import beta_expected_improvement


@dataclass(frozen=True)
class BetaPosterior:
    """Integer-shape Beta posterior for a Bernoulli arm."""

    alpha: int
    beta: int

    def __post_init__(self) -> None:
        if not isinstance(self.alpha, int) or self.alpha <= 0:
            raise ValueError("alpha must be a positive integer")
        if not isinstance(self.beta, int) or self.beta <= 0:
            raise ValueError("beta must be a positive integer")

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def update(self, reward: int | bool) -> BetaPosterior:
        if reward in (1, True):
            return BetaPosterior(self.alpha + 1, self.beta)
        if reward in (0, False):
            return BetaPosterior(self.alpha, self.beta + 1)
        raise ValueError("reward must be 0/False or 1/True")


BetaPosteriorInput = BetaPosterior | tuple[int, int]


@dataclass(frozen=True, init=False)
class BernoulliState:
    """Finite independent Bernoulli/Beta posterior state."""

    arms: tuple[BetaPosterior, ...]

    def __init__(self, arms: Sequence[BetaPosteriorInput]) -> None:
        converted: list[BetaPosterior] = []
        for arm in arms:
            if isinstance(arm, BetaPosterior):
                converted.append(arm)
            else:
                alpha, beta = arm
                converted.append(BetaPosterior(alpha, beta))
        if not converted:
            raise ValueError("state must contain at least one arm")
        object.__setattr__(self, "arms", tuple(converted))

    def __len__(self) -> int:
        return len(self.arms)

    def update(self, arm: int, reward: int | bool) -> BernoulliState:
        _require_arm_index(self, arm)
        updated = list(self.arms)
        updated[arm] = updated[arm].update(reward)
        return BernoulliState(tuple(updated))

    @property
    def means(self) -> tuple[float, ...]:
        return tuple(arm.mean for arm in self.arms)


OverrideRule = Callable[[int, BernoulliState], Sequence[float]]
ValueFunction = Callable[[BernoulliState], float]


@dataclass(frozen=True)
class Transition:
    """One branch of the actual Bayesian-predictive kernel."""

    probability: float
    action: int
    reward: int
    state: BernoulliState


def _require_arm_index(state: BernoulliState, arm: int) -> None:
    if not isinstance(arm, int) or arm < 0 or arm >= len(state):
        raise IndexError("arm index out of range")


def _require_time(t: int) -> None:
    if not isinstance(t, int) or t < 0:
        raise ValueError("t must be a nonnegative integer")


def host_arm(state: BernoulliState) -> int:
    """Return the greedy host arm, breaking ties by smallest index."""

    best_index = 0
    best_mean = state.arms[0].mean
    for index, arm in enumerate(state.arms[1:], start=1):
        if arm.mean > best_mean:
            best_index = index
            best_mean = arm.mean
    return best_index


def candidate_excluded_baseline(state: BernoulliState, candidate: int) -> float:
    """Return ``V^a(x) = max_{b != a} m_b(x)``."""

    _require_arm_index(state, candidate)
    if len(state) < 2:
        raise ValueError("candidate-excluded baseline requires at least two arms")
    return max(arm.mean for index, arm in enumerate(state.arms) if index != candidate)


def moving_certificate(state: BernoulliState, candidate: int) -> float:
    """Return ``N^a(x) = psi(Pi_a(x), V^a(x))``."""

    _require_arm_index(state, candidate)
    candidate_arm = state.arms[candidate]
    baseline = candidate_excluded_baseline(state, candidate)
    return beta_expected_improvement(candidate_arm.alpha, candidate_arm.beta, baseline)


def host_delta_override(t: int, state: BernoulliState) -> tuple[float, ...]:
    """A fallback override rule that puts all override mass on the host."""

    _require_time(t)
    host = host_arm(state)
    return tuple(1.0 if index == host else 0.0 for index in range(len(state)))


def host_override_probabilities(
    state: BernoulliState,
    t: int,
    exploration_mass: float,
    override_rule: OverrideRule,
) -> tuple[float, ...]:
    """Return actual action probabilities under the host-override mixture.

    ``p_i = (1 - epsilon_t) 1{i=h(x)} + epsilon_t q_i`` with
    ``epsilon_t = M / (M + t)``. The supplied ``override_rule`` is responsible
    for gate eligibility and fallback behavior.
    """

    _require_time(t)
    exploration_mass = float(exploration_mass)
    if not math.isfinite(exploration_mass) or exploration_mass < 0.0:
        raise ValueError("exploration_mass must be finite and nonnegative")

    epsilon = 0.0
    if exploration_mass > 0.0:
        epsilon = exploration_mass / (exploration_mass + t)

    q = tuple(float(value) for value in override_rule(t, state))
    if len(q) != len(state):
        raise ValueError("override_rule must return one probability per arm")
    if any((not math.isfinite(value)) or value < 0.0 for value in q):
        raise ValueError("override probabilities must be finite and nonnegative")
    if not math.isclose(math.fsum(q), 1.0, rel_tol=1e-12, abs_tol=1e-12):
        raise ValueError("override probabilities must sum to 1")

    host = host_arm(state)
    probabilities = tuple(
        (1.0 - epsilon) * (1.0 if index == host else 0.0) + epsilon * q_i
        for index, q_i in enumerate(q)
    )
    if not math.isclose(math.fsum(probabilities), 1.0, rel_tol=1e-12, abs_tol=1e-12):
        raise ArithmeticError("action probabilities do not sum to 1")
    return probabilities


def enumerate_transitions(
    state: BernoulliState,
    t: int,
    exploration_mass: float,
    override_rule: OverrideRule = host_delta_override,
) -> tuple[Transition, ...]:
    """Enumerate one-step actual-kernel transitions.

    Exactly one arm is updated on each branch. Rewards are Bayesian-predictive:
    a success on arm ``i`` has probability equal to its posterior mean.
    """

    action_probabilities = host_override_probabilities(
        state=state,
        t=t,
        exploration_mass=exploration_mass,
        override_rule=override_rule,
    )
    transitions: list[Transition] = []
    for arm_index, action_probability in enumerate(action_probabilities):
        if action_probability == 0.0:
            continue
        mean = state.arms[arm_index].mean
        success_probability = action_probability * mean
        failure_probability = action_probability * (1.0 - mean)
        if success_probability > 0.0:
            transitions.append(
                Transition(success_probability, arm_index, 1, state.update(arm_index, 1))
            )
        if failure_probability > 0.0:
            transitions.append(
                Transition(failure_probability, arm_index, 0, state.update(arm_index, 0))
            )
    return tuple(transitions)


def kernel_expectation(
    state: BernoulliState,
    t: int,
    exploration_mass: float,
    override_rule: OverrideRule,
    value_function: ValueFunction,
) -> float:
    """Compute ``K_t f(x)`` under the actual one-arm-per-round kernel."""

    return math.fsum(
        transition.probability * value_function(transition.state)
        for transition in enumerate_transitions(state, t, exploration_mass, override_rule)
    )
