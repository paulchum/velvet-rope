"""Dirichlet-categorical Max-DE primitives for bounded payoff vectors."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache, lru_cache
from math import exp, log, sqrt
from typing import cast

import numpy as np
from numpy.typing import NDArray
from scipy.special import betainc, betaln, roots_jacobi  # type: ignore[import-untyped]

FloatArray = NDArray[np.float64]

DEFAULT_QUADRATURE_ORDER = 192
DIRICHLET_EXACT_LOWER_THEOREM_REFS = (
    "docs/math/lower_certificates_for_max_de_inspection_theorem.txt",
    "docs/math/dirichlet_categorical_max_de_certificates.txt",
)
DIRICHLET_SCALABLE_LOWER_THEOREM_REFS = (
    *DIRICHLET_EXACT_LOWER_THEOREM_REFS,
    "docs/math/dirichlet_categorical_scalable_lower_certificate.txt",
)


@dataclass(frozen=True)
class DirichletLowerCertificateDetails:
    """Metadata for a Dirichlet-categorical lower-certificate computation."""

    method: str
    value: float
    deterministic: bool
    confidence_delta: float | None
    sample_count: int | None
    horizon: int
    terminal_augmented: bool
    grouped_level_count: int
    theorem_refs: tuple[str, ...]


@dataclass(frozen=True)
class DirichletCategoricalPosterior:
    """Dirichlet posterior over categorical probabilities with bounded payoffs."""

    alpha: FloatArray
    payoffs: FloatArray
    quadrature_order: int = DEFAULT_QUADRATURE_ORDER

    @classmethod
    def from_sequences(
        cls,
        alpha: Sequence[float],
        payoffs: Sequence[float],
        *,
        quadrature_order: int = DEFAULT_QUADRATURE_ORDER,
    ) -> DirichletCategoricalPosterior:
        return cls(
            alpha=np.array(alpha, dtype=np.float64),
            payoffs=np.array(payoffs, dtype=np.float64),
            quadrature_order=quadrature_order,
        )

    @property
    def num_categories(self) -> int:
        return int(self.alpha.shape[0])

    def grouped_parameters(self) -> tuple[FloatArray, FloatArray]:
        """Return payoff-level Dirichlet masses and sorted distinct payoff levels."""

        alpha, payoffs = _validated_arrays(self.alpha, self.payoffs)
        return _group_payoff_levels(alpha, payoffs)

    def expected_payoff(self) -> float:
        alpha, payoffs = _validated_arrays(self.alpha, self.payoffs)
        return float(np.dot(alpha, payoffs) / np.sum(alpha))

    def expected_improvement(self, baseline: float) -> float:
        gamma, levels = self.grouped_parameters()
        return grouped_positive_part_moment(
            gamma,
            levels,
            baseline,
            power=1,
            quadrature_order=self.quadrature_order,
        )

    def second_moment(self, baseline: float) -> float:
        gamma, levels = self.grouped_parameters()
        return grouped_positive_part_moment(
            gamma,
            levels,
            baseline,
            power=2,
            quadrature_order=self.quadrature_order,
        )

    def lower_certificate(
        self,
        baseline: float,
        horizon: int,
        *,
        terminal_augmented: bool = True,
        method: str = "exact",
        delta: float | None = None,
        sample_count: int = 10_000,
        rng: np.random.Generator | None = None,
    ) -> float:
        """Compute a finite-horizon lower Max-DE certificate.

        By default, ``method="exact"`` uses the stronger terminal-augmented certificate
        E[max{X_v, M_0, ..., M_r}], matching the existing Beta-Bernoulli runtime
        implementation. Set terminal_augmented=False for E[max{M_0, ..., M_r}].

        ``method="cheap"`` returns the deterministic Jensen floor
        ``max(E[X] - baseline, 0)``. ``method="mc_lcb"`` returns a probabilistic
        Hoeffding lower confidence bound for a sampled pathwise lower process
        and requires ``delta``.
        """

        return self.lower_certificate_details(
            baseline,
            horizon,
            terminal_augmented=terminal_augmented,
            method=method,
            delta=delta,
            sample_count=sample_count,
            rng=rng,
        ).value

    def cheap_lower_certificate(self, baseline: float) -> float:
        """Compute the deterministic quadrature-free Jensen lower certificate."""

        gamma, levels = self.grouped_parameters()
        return _cheap_lower_certificate_grouped(_tuple(gamma), _tuple(levels), float(baseline))

    def monte_carlo_lower_certificate(
        self,
        baseline: float,
        horizon: int,
        *,
        delta: float,
        sample_count: int = 10_000,
        terminal_augmented: bool = True,
        rng: np.random.Generator | None = None,
    ) -> float:
        """Compute a probabilistic Monte Carlo lower confidence bound."""

        return self.lower_certificate(
            baseline,
            horizon,
            terminal_augmented=terminal_augmented,
            method="mc_lcb",
            delta=delta,
            sample_count=sample_count,
            rng=rng,
        )

    def lower_certificate_details(
        self,
        baseline: float,
        horizon: int,
        *,
        terminal_augmented: bool = True,
        method: str = "exact",
        delta: float | None = None,
        sample_count: int = 10_000,
        rng: np.random.Generator | None = None,
    ) -> DirichletLowerCertificateDetails:
        """Compute a lower certificate and return method metadata."""

        if horizon < 0:
            raise ValueError("horizon must be non-negative")
        gamma, levels = self.grouped_parameters()
        gamma_tuple = _tuple(gamma)
        levels_tuple = _tuple(levels)
        method_value = str(method)
        if method_value == "exact":
            value = _lower_certificate_grouped(
                gamma_tuple,
                levels_tuple,
                float(baseline),
                int(horizon),
                bool(terminal_augmented),
                int(self.quadrature_order),
            )
            return DirichletLowerCertificateDetails(
                method=method_value,
                value=float(value),
                deterministic=True,
                confidence_delta=None,
                sample_count=None,
                horizon=int(horizon),
                terminal_augmented=bool(terminal_augmented),
                grouped_level_count=len(levels_tuple),
                theorem_refs=DIRICHLET_EXACT_LOWER_THEOREM_REFS,
            )
        if method_value == "cheap":
            value = _cheap_lower_certificate_grouped(
                gamma_tuple,
                levels_tuple,
                float(baseline),
            )
            return DirichletLowerCertificateDetails(
                method=method_value,
                value=float(value),
                deterministic=True,
                confidence_delta=None,
                sample_count=None,
                horizon=int(horizon),
                terminal_augmented=bool(terminal_augmented),
                grouped_level_count=len(levels_tuple),
                theorem_refs=DIRICHLET_SCALABLE_LOWER_THEOREM_REFS,
            )
        if method_value == "mc_lcb":
            if delta is None:
                raise ValueError("delta is required for method='mc_lcb'")
            confidence_delta = _validate_confidence_delta(float(delta))
            count = _validate_sample_count(sample_count)
            value = _monte_carlo_lower_certificate_grouped(
                gamma_tuple,
                levels_tuple,
                float(baseline),
                int(horizon),
                delta=confidence_delta,
                sample_count=count,
                rng=rng,
            )
            return DirichletLowerCertificateDetails(
                method=method_value,
                value=float(value),
                deterministic=False,
                confidence_delta=confidence_delta,
                sample_count=count,
                horizon=int(horizon),
                terminal_augmented=bool(terminal_augmented),
                grouped_level_count=len(levels_tuple),
                theorem_refs=DIRICHLET_SCALABLE_LOWER_THEOREM_REFS,
            )
        raise ValueError("method must be 'exact', 'cheap', or 'mc_lcb'")

    def upper_certificate(self, baseline: float, *, method: str = "exact") -> float:
        """Compute a bounded-payoff O(1) Max-DE upper certificate.

        ``method="exact"`` preserves the original quadrature-backed certificate.
        ``method="moment"`` uses the deterministic moment path used by
        :meth:`scalable_upper_certificate`.
        """

        gamma, levels = self.grouped_parameters()
        gamma_tuple = _tuple(gamma)
        levels_tuple = _tuple(levels)
        if method == "exact":
            return _upper_certificate_grouped(
                gamma_tuple,
                levels_tuple,
                float(baseline),
                int(self.quadrature_order),
            )
        if method == "moment":
            return _moment_upper_certificate_grouped(
                gamma_tuple,
                levels_tuple,
                float(baseline),
                int(self.quadrature_order),
            )
        raise ValueError("method must be 'exact' or 'moment'")

    def scalable_upper_certificate(self, baseline: float) -> float:
        """Compute the deterministic scalable moment upper certificate."""

        return self.upper_certificate(baseline, method="moment")

    def refined_upper_certificate(self, baseline: float, horizon: int) -> float:
        """Compute a path-conditioned finite-horizon upper Max-DE certificate."""

        if horizon < 0:
            raise ValueError("horizon must be non-negative")
        gamma, levels = self.grouped_parameters()
        return _refined_upper_certificate_grouped(
            _tuple(gamma),
            _tuple(levels),
            float(baseline),
            int(horizon),
            int(self.quadrature_order),
        )

    def martingale_residual(self, baseline: float, max_depth: int) -> float:
        """Return the largest one-step harmonic-identity residual up to a depth."""

        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        gamma, levels = self.grouped_parameters()
        gamma_tuple = _tuple(gamma)
        levels_tuple = _tuple(levels)
        residual = 0.0

        def visit(state: tuple[float, ...], remaining: int) -> None:
            nonlocal residual
            total = sum(state)
            current = _positive_part_moment_cached(
                state,
                levels_tuple,
                float(baseline),
                1,
                int(self.quadrature_order),
            )
            expected_next = 0.0
            for index, value in enumerate(state):
                next_state = _increment_tuple(state, index)
                expected_next += value / total * _positive_part_moment_cached(
                    next_state,
                    levels_tuple,
                    float(baseline),
                    1,
                    int(self.quadrature_order),
                )
            residual = max(residual, abs(current - expected_next))
            if remaining == 0:
                return
            for index in range(len(state)):
                visit(_increment_tuple(state, index), remaining - 1)

        visit(gamma_tuple, max_depth)
        return residual


def grouped_positive_part_moment(
    gamma: Sequence[float] | FloatArray,
    levels: Sequence[float] | FloatArray,
    baseline: float,
    *,
    power: int,
    quadrature_order: int = DEFAULT_QUADRATURE_ORDER,
) -> float:
    """Evaluate E[(sum_j c_j W_j - v)_+^power] for grouped Dirichlet masses."""

    gamma_array, levels_array = _validated_arrays(
        np.array(gamma, dtype=np.float64),
        np.array(levels, dtype=np.float64),
    )
    if power not in {1, 2}:
        raise ValueError("power must be 1 or 2")
    grouped_gamma, grouped_levels = _group_payoff_levels(gamma_array, levels_array)
    return _positive_part_moment_cached(
        _tuple(grouped_gamma),
        _tuple(grouped_levels),
        float(baseline),
        power,
        int(quadrature_order),
    )


def _validated_arrays(alpha: FloatArray, payoffs: FloatArray) -> tuple[FloatArray, FloatArray]:
    if alpha.ndim != 1 or payoffs.ndim != 1:
        raise ValueError("alpha and payoffs must be one-dimensional")
    if alpha.shape != payoffs.shape:
        raise ValueError("alpha and payoffs must have the same length")
    if alpha.size == 0:
        raise ValueError("at least one category is required")
    if not np.all(np.isfinite(alpha)):
        raise ValueError("alpha values must be finite")
    if not np.all(alpha > 0.0):
        raise ValueError("alpha values must be positive")
    if not np.all(np.isfinite(payoffs)):
        raise ValueError("payoff values must be finite")
    return (
        alpha.astype(np.float64, copy=False),
        payoffs.astype(np.float64, copy=False),
    )


def _group_payoff_levels(alpha: FloatArray, payoffs: FloatArray) -> tuple[FloatArray, FloatArray]:
    order = np.argsort(payoffs, kind="stable")
    sorted_alpha = alpha[order]
    sorted_payoffs = payoffs[order]
    levels: list[float] = []
    masses: list[float] = []
    for mass, payoff in zip(sorted_alpha, sorted_payoffs, strict=True):
        value = float(payoff)
        if levels and value == levels[-1]:
            masses[-1] += float(mass)
        else:
            levels.append(value)
            masses.append(float(mass))
    return (
        np.array(masses, dtype=np.float64),
        np.array(levels, dtype=np.float64),
    )


def _tuple(values: FloatArray) -> tuple[float, ...]:
    return tuple(float(value) for value in values)


def _raw_first_second_moments(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
) -> tuple[float, float]:
    total = sum(gamma)
    first_raw = sum(mass * level for mass, level in zip(gamma, levels, strict=True))
    mean = first_raw / total
    second_raw = first_raw**2 + sum(
        mass * level**2 for mass, level in zip(gamma, levels, strict=True)
    )
    second = second_raw / (total * (total + 1.0))
    return mean, second


def _max_payoff_above_baseline(levels: tuple[float, ...], baseline: float) -> float:
    if not np.isfinite(baseline):
        raise ValueError("baseline must be finite")
    return max(levels[-1] - baseline, 0.0)


def _cheap_lower_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
) -> float:
    max_payoff = _max_payoff_above_baseline(levels, baseline)
    if max_payoff == 0.0:
        return 0.0
    mean, _ = _raw_first_second_moments(gamma, levels)
    return max(min(mean - baseline, max_payoff), 0.0)


def _validate_sample_count(sample_count: int) -> int:
    if isinstance(sample_count, bool) or not isinstance(sample_count, int):
        raise ValueError("sample_count must be a positive integer")
    if sample_count <= 0:
        raise ValueError("sample_count must be positive")
    return sample_count


def _validate_confidence_delta(delta: float) -> float:
    if not np.isfinite(delta):
        raise ValueError("delta must be finite")
    if not 0.0 < delta < 1.0:
        raise ValueError("delta must be in (0, 1)")
    return delta


def _pathwise_cheap_lower_sample(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    horizon: int,
    max_payoff: float,
    rng: np.random.Generator,
) -> float:
    state = np.array(gamma, dtype=np.float64)
    level_array = np.array(levels, dtype=np.float64)
    total = float(np.sum(state))
    mean = float(np.dot(state, level_array) / total)
    best = max(min(mean - baseline, max_payoff), 0.0)
    for _ in range(horizon):
        probabilities = state / total
        index = int(rng.choice(len(state), p=probabilities))
        state[index] += 1.0
        total += 1.0
        mean = float(np.dot(state, level_array) / total)
        best = max(best, max(min(mean - baseline, max_payoff), 0.0))
    return max(min(best, max_payoff), 0.0)


def _monte_carlo_lower_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    horizon: int,
    *,
    delta: float,
    sample_count: int,
    rng: np.random.Generator | None,
) -> float:
    confidence_delta = _validate_confidence_delta(delta)
    count = _validate_sample_count(sample_count)
    max_payoff = _max_payoff_above_baseline(levels, baseline)
    if max_payoff == 0.0:
        return 0.0
    generator = rng if rng is not None else np.random.default_rng()
    total = 0.0
    for _ in range(count):
        total += _pathwise_cheap_lower_sample(
            gamma,
            levels,
            baseline,
            horizon,
            max_payoff,
            generator,
        )
    sample_mean = total / count
    penalty = max_payoff * sqrt(log(1.0 / confidence_delta) / (2.0 * count))
    return max(min(sample_mean - penalty, max_payoff), 0.0)


@lru_cache(maxsize=65_536)
def _positive_part_moment_cached(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    power: int,
    quadrature_order: int,
) -> float:
    if power not in {1, 2}:
        raise ValueError("power must be 1 or 2")
    if quadrature_order <= 0:
        raise ValueError("quadrature_order must be positive")
    if not np.isfinite(baseline):
        raise ValueError("baseline must be finite")
    if len(gamma) != len(levels):
        raise ValueError("gamma and levels must have the same length")

    minimum = levels[0]
    maximum = levels[-1]
    if baseline >= maximum:
        return 0.0

    total = sum(gamma)
    first_raw = sum(mass * level for mass, level in zip(gamma, levels, strict=True))
    mean = first_raw / total

    if baseline <= minimum:
        if power == 1:
            return max(mean - baseline, 0.0)
        second_raw = first_raw**2 + sum(
            mass * level**2 for mass, level in zip(gamma, levels, strict=True)
        )
        second_moment = second_raw / (total * (total + 1.0))
        value = second_moment - 2.0 * baseline * mean + baseline**2
        return max(value, 0.0)

    if len(gamma) == 1:
        return max(levels[0] - baseline, 0.0) ** power
    if len(gamma) == 2:
        return _two_level_positive_part_moment(gamma, levels, baseline, power)

    largest_mass = gamma[-1]
    remaining_mass = sum(gamma[:-1])
    largest_level = levels[-1]
    previous_gamma = gamma[:-1]
    previous_levels = levels[:-1]
    nodes, weights = _beta_quadrature_nodes_weights(
        largest_mass,
        remaining_mass,
        quadrature_order,
    )
    total_value = 0.0
    for node, weight in zip(nodes, weights, strict=True):
        denominator = 1.0 - node
        shifted_baseline = (baseline - node * largest_level) / denominator
        inner = _positive_part_moment_cached(
            previous_gamma,
            previous_levels,
            shifted_baseline,
            power,
            quadrature_order,
        )
        total_value += weight * denominator**power * inner
    return max(float(total_value), 0.0)


def _two_level_positive_part_moment(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    power: int,
) -> float:
    lower_level, upper_level = levels
    width = upper_level - lower_level
    if width <= 0.0:
        raise ValueError("payoff levels must be strictly increasing")
    t = (baseline - lower_level) / width
    if t >= 1.0:
        return 0.0
    if t <= 0.0:
        return _positive_part_moment_cached(gamma, levels, baseline, power, 1)

    upper_mass, lower_mass = gamma[1], gamma[0]
    tail_probability = 1.0 - float(betainc(upper_mass, lower_mass, t))
    tail_first = upper_mass / (upper_mass + lower_mass) * (
        1.0 - float(betainc(upper_mass + 1.0, lower_mass, t))
    )
    if power == 1:
        value = width * (tail_first - t * tail_probability)
        return max(value, 0.0)

    tail_second = upper_mass * (upper_mass + 1.0) / (
        (upper_mass + lower_mass) * (upper_mass + lower_mass + 1.0)
    ) * (1.0 - float(betainc(upper_mass + 2.0, lower_mass, t)))
    value = width**2 * (tail_second - 2.0 * t * tail_first + t**2 * tail_probability)
    return max(value, 0.0)


@lru_cache(maxsize=512)
def _beta_quadrature_nodes_weights(
    alpha: float,
    beta: float,
    order: int,
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    roots, jacobi_weights = roots_jacobi(order, beta - 1.0, alpha - 1.0)
    nodes = cast(FloatArray, (roots + 1.0) / 2.0)
    log_factor = -(alpha + beta - 1.0) * log(2.0) - float(betaln(alpha, beta))
    beta_weights = cast(FloatArray, jacobi_weights * exp(log_factor))
    return _tuple(nodes), _tuple(beta_weights)


def _lower_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    horizon: int,
    terminal_augmented: bool,
    quadrature_order: int,
) -> float:
    initial = _positive_part_moment_cached(
        gamma,
        levels,
        baseline,
        1,
        quadrature_order,
    )

    @cache
    def recurse(state: tuple[float, ...], remaining: int, z_value: float) -> float:
        if remaining == 0:
            if terminal_augmented:
                terminal_tail = _positive_part_moment_cached(
                    state,
                    levels,
                    baseline + z_value,
                    1,
                    quadrature_order,
                )
                return z_value + terminal_tail
            return z_value
        state_total = sum(state)
        expected = 0.0
        for index, mass in enumerate(state):
            next_state = _increment_tuple(state, index)
            next_m = _positive_part_moment_cached(
                next_state,
                levels,
                baseline,
                1,
                quadrature_order,
            )
            expected += mass / state_total * recurse(
                next_state,
                remaining - 1,
                max(z_value, next_m),
            )
        return expected

    return recurse(gamma, horizon, initial)


def _upper_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    quadrature_order: int,
) -> float:
    max_payoff = max(levels[-1] - baseline, 0.0)
    if max_payoff == 0.0:
        return 0.0
    mean = _positive_part_moment_cached(gamma, levels, baseline, 1, quadrature_order)
    if mean <= 0.0:
        return 0.0
    second = _positive_part_moment_cached(gamma, levels, baseline, 2, quadrature_order)
    variance = max(second - mean**2, 0.0)
    log_envelope = mean * (1.0 + log(max_payoff / mean))
    l2_envelope = mean + 2.0 * sqrt(variance)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _one_sided_upper_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    quadrature_order: int,
) -> float:
    max_payoff = max(levels[-1] - baseline, 0.0)
    if max_payoff == 0.0:
        return 0.0
    mean = _positive_part_moment_cached(gamma, levels, baseline, 1, quadrature_order)
    if mean <= 0.0:
        return 0.0
    q_v = _positive_part_moment_cached(
        gamma,
        levels,
        baseline + mean,
        2,
        quadrature_order,
    )
    log_envelope = mean * (1.0 + log(max_payoff / mean))
    l2_envelope = mean + 2.0 * sqrt(q_v)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _raw_moment_upper_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
) -> float:
    max_payoff = max(levels[-1] - baseline, 0.0)
    if max_payoff == 0.0:
        return 0.0
    raw_mean, raw_second = _raw_first_second_moments(gamma, levels)
    shifted_second = max(raw_second - 2.0 * baseline * raw_mean + baseline**2, 0.0)
    mean_majorant = min(max_payoff, sqrt(shifted_second))
    if mean_majorant <= 0.0:
        return 0.0
    q_majorant = min(max_payoff**2, shifted_second)
    log_envelope = mean_majorant * (1.0 + log(max_payoff / mean_majorant))
    l2_envelope = mean_majorant + 2.0 * sqrt(q_majorant)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _moment_upper_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    quadrature_order: int,
) -> float:
    if not np.isfinite(baseline):
        raise ValueError("baseline must be finite")
    if len(gamma) <= 3:
        return _one_sided_upper_certificate_grouped(gamma, levels, baseline, quadrature_order)
    return _raw_moment_upper_certificate_grouped(gamma, levels, baseline)


def _path_conditioned_upper_base_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    z_value: float,
    quadrature_order: int,
) -> float:
    max_payoff = max(levels[-1] - baseline, 0.0)
    if max_payoff == 0.0:
        return 0.0
    if z_value >= max_payoff:
        return max_payoff
    if z_value <= 0.0:
        log_envelope = 0.0
    else:
        current_mean = _positive_part_moment_cached(
            gamma,
            levels,
            baseline,
            1,
            quadrature_order,
        )
        log_envelope = z_value + current_mean * log(max_payoff / z_value)
    h2 = _positive_part_moment_cached(
        gamma,
        levels,
        baseline + z_value,
        2,
        quadrature_order,
    )
    l2_envelope = z_value + 2.0 * sqrt(h2)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


def _refined_upper_certificate_grouped(
    gamma: tuple[float, ...],
    levels: tuple[float, ...],
    baseline: float,
    horizon: int,
    quadrature_order: int,
) -> float:
    initial = _positive_part_moment_cached(
        gamma,
        levels,
        baseline,
        1,
        quadrature_order,
    )
    horizon_free = _one_sided_upper_certificate_grouped(
        gamma,
        levels,
        baseline,
        quadrature_order,
    )

    @cache
    def recurse(state: tuple[float, ...], remaining: int, z_value: float) -> float:
        if remaining == 0:
            return _path_conditioned_upper_base_grouped(
                state,
                levels,
                baseline,
                z_value,
                quadrature_order,
            )
        state_total = sum(state)
        expected = 0.0
        for index, mass in enumerate(state):
            next_state = _increment_tuple(state, index)
            next_m = _positive_part_moment_cached(
                next_state,
                levels,
                baseline,
                1,
                quadrature_order,
            )
            expected += mass / state_total * recurse(
                next_state,
                remaining - 1,
                max(z_value, next_m),
            )
        return expected

    candidates = [horizon_free]
    candidates.extend(recurse(gamma, depth, initial) for depth in range(horizon + 1))
    return max(min(candidates), 0.0)


def _increment_tuple(values: tuple[float, ...], index: int) -> tuple[float, ...]:
    mutable = list(values)
    mutable[index] += 1.0
    return tuple(mutable)
