"""Experimental finite-horizon Gamma-rate Max-DE dynamic program.

This module is intentionally separate from :mod:`velvet.research.gamma_rate`.
It is a numerical continuation-value approximation under exponential-rate
updating, not a replacement for the verified closed-form Gamma-rate L2 core.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from math import exp, isfinite, log, sqrt
from typing import cast

import numpy as np
from numpy.typing import NDArray
from scipy.special import gammaincc, roots_laguerre  # type: ignore[import-untyped]

from velvet.research.gamma_rate import GammaRatePosteriorSpec, m_v_plus

FloatArray = NDArray[np.float64]


@dataclass(frozen=True)
class GammaRateDPConfig:
    """Configuration for the experimental finite-horizon Gamma-rate DP."""

    alpha: float
    beta: float
    baseline: float
    horizon: int
    quadrature_order: int = 16
    u_grid_size: int = 41
    zeta_grid_size: int = 31

    def __post_init__(self) -> None:
        GammaRatePosteriorSpec(
            alpha=float(self.alpha),
            beta=float(self.beta),
            baseline=float(self.baseline),
        )
        if self.horizon < 0:
            raise ValueError("horizon must be non-negative")
        if self.quadrature_order <= 0:
            raise ValueError("quadrature_order must be positive")
        if self.u_grid_size < 2:
            raise ValueError("u_grid_size must be at least 2")
        if self.zeta_grid_size < 2:
            raise ValueError("zeta_grid_size must be at least 2")

    @property
    def initial_incumbent(self) -> float:
        return m_v_plus(float(self.alpha), float(self.beta), float(self.baseline))

    @property
    def final_shape(self) -> float:
        return float(self.alpha) + float(self.horizon)

    def shape_for_layer(self, layer: int) -> float:
        if layer < 0 or layer > self.horizon:
            raise ValueError("layer must be in [0, horizon]")
        return float(self.alpha) + float(layer)


@dataclass(frozen=True)
class GammaRateDPState:
    """Finite-horizon DP state under exponential-rate updating."""

    layer: int
    remaining: int
    shape: float
    rate: float
    incumbent: float

    def __post_init__(self) -> None:
        if self.layer < 0:
            raise ValueError("layer must be non-negative")
        if self.remaining < 0:
            raise ValueError("remaining must be non-negative")
        if not isfinite(self.shape) or self.shape <= 0.0:
            raise ValueError("shape must be positive")
        if not isfinite(self.rate) or self.rate <= 0.0:
            raise ValueError("rate must be positive")
        if not isfinite(self.incumbent) or self.incumbent < 0.0:
            raise ValueError("incumbent must be non-negative")


@dataclass(frozen=True)
class GammaRateDPResult:
    """Experimental finite-horizon DP output."""

    value: float
    horizon: int
    quadrature_order: int
    method: str
    experimental: bool = True


@dataclass(frozen=True)
class GammaRateCompactifiedState:
    """Compactified coordinates for a rate/incumbent state."""

    u: float
    zeta: float
    boundary: float


@dataclass(frozen=True)
class GammaRateLongHorizonMCResult:
    """Independent long-horizon Monte Carlo diagnostic for Phi."""

    mean: float
    standard_error: float
    sample_count: int
    horizon: int
    seed: int


@dataclass(frozen=True)
class GammaRateSurfaceCache:
    """Deterministic compactified value surfaces for interpolation diagnostics."""

    config: GammaRateDPConfig
    u_grid: FloatArray
    zeta_grid: FloatArray
    surfaces: tuple[FloatArray, ...]

    @classmethod
    def build(cls, config: GammaRateDPConfig) -> GammaRateSurfaceCache:
        cfg = GammaRateDPConfig(
            alpha=float(config.alpha),
            beta=float(config.beta),
            baseline=float(config.baseline),
            horizon=int(config.horizon),
            quadrature_order=int(config.quadrature_order),
            u_grid_size=int(config.u_grid_size),
            zeta_grid_size=int(config.zeta_grid_size),
        )
        nodes, weights = gauss_laguerre_nodes_weights(cfg.quadrature_order)
        u_grid = _u_grid(cfg, nodes)
        zeta_grid = np.linspace(0.0, 1.0, cfg.zeta_grid_size, dtype=np.float64)
        surfaces: list[FloatArray] = [
            np.zeros((cfg.u_grid_size, cfg.zeta_grid_size), dtype=np.float64)
            for _ in range(cfg.horizon + 1)
        ]
        terminal = surfaces[cfg.horizon]
        for i in range(cfg.u_grid_size):
            terminal[i, :] = zeta_grid
        for layer in range(cfg.horizon - 1, -1, -1):
            shape = cfg.shape_for_layer(layer)
            final_shape = cfg.final_shape
            surface = surfaces[layer]
            next_surface = surfaces[layer + 1]
            for u_index, u in enumerate(u_grid):
                rate = exp(float(u))
                boundary = compactification_boundary(final_shape, rate, cfg.baseline)
                for zeta_index, zeta in enumerate(zeta_grid):
                    if boundary <= 1e-200:
                        surface[u_index, zeta_index] = float(zeta)
                        continue
                    incumbent = float(zeta) * boundary
                    total = 0.0
                    for node, weight in zip(nodes, weights, strict=True):
                        next_rate = rate_transition(shape, rate, float(node))
                        next_u = log(next_rate)
                        next_incumbent = incumbent_update(
                            incumbent,
                            shape + 1.0,
                            next_rate,
                            cfg.baseline,
                        )
                        next_boundary = compactification_boundary(
                            final_shape,
                            next_rate,
                            cfg.baseline,
                        )
                        if next_boundary <= 1e-200:
                            total += float(weight) * next_incumbent
                            continue
                        next_zeta = next_incumbent / next_boundary
                        normalized = _interpolate_normalized_surface(
                            next_surface,
                            u_grid,
                            zeta_grid,
                            next_u,
                            next_zeta,
                        )
                        total += float(weight) * next_boundary * normalized
                    surface[u_index, zeta_index] = total / boundary
        return cls(
            config=cfg,
            u_grid=u_grid,
            zeta_grid=zeta_grid,
            surfaces=tuple(surfaces),
        )

    def normalized_surface(self, layer: int) -> FloatArray:
        if layer < 0 or layer > self.config.horizon:
            raise ValueError("layer must be in [0, horizon]")
        return self.surfaces[layer].copy()

    def evaluate_normalized(self, layer: int, u: float, zeta: float) -> float:
        if layer < 0 or layer > self.config.horizon:
            raise ValueError("layer must be in [0, horizon]")
        return _interpolate_normalized_surface(
            self.surfaces[layer],
            self.u_grid,
            self.zeta_grid,
            float(u),
            float(zeta),
        )

    def evaluate_state(self, state: GammaRateDPState) -> float:
        compact = compactify_state(
            rate=state.rate,
            incumbent=state.incumbent,
            final_shape=self.config.final_shape,
            baseline=self.config.baseline,
        )
        normalized = self.evaluate_normalized(state.layer, compact.u, compact.zeta)
        return compact.boundary * normalized


def gauss_laguerre_nodes_weights(order: int) -> tuple[FloatArray, FloatArray]:
    if order <= 0:
        raise ValueError("order must be positive")
    nodes, weights = _gauss_laguerre_nodes_weights_cached(int(order))
    return (
        np.array(nodes, dtype=np.float64),
        np.array(weights, dtype=np.float64),
    )


def initial_state(config: GammaRateDPConfig) -> GammaRateDPState:
    return GammaRateDPState(
        layer=0,
        remaining=int(config.horizon),
        shape=float(config.alpha),
        rate=float(config.beta),
        incumbent=config.initial_incumbent,
    )


def rate_transition(shape: float, rate: float, node: float) -> float:
    if shape <= 0.0:
        raise ValueError("shape must be positive")
    if rate <= 0.0:
        raise ValueError("rate must be positive")
    next_rate = float(rate) * exp(float(node) / float(shape))
    if not isfinite(next_rate) or next_rate <= 0.0:
        raise ValueError("rate transition produced a non-positive rate")
    return next_rate


def incumbent_update(incumbent: float, shape: float, rate: float, baseline: float) -> float:
    if incumbent < 0.0:
        raise ValueError("incumbent must be non-negative")
    return max(float(incumbent), m_v_plus(float(shape), float(rate), float(baseline)))


def transition_state(
    state: GammaRateDPState,
    *,
    node: float,
    baseline: float,
) -> GammaRateDPState:
    if state.remaining <= 0:
        raise ValueError("cannot transition terminal state")
    next_shape = state.shape + 1.0
    next_rate = rate_transition(state.shape, state.rate, node)
    return GammaRateDPState(
        layer=state.layer + 1,
        remaining=state.remaining - 1,
        shape=next_shape,
        rate=next_rate,
        incumbent=incumbent_update(state.incumbent, next_shape, next_rate, baseline),
    )


def bellman_update(
    state: GammaRateDPState,
    *,
    baseline: float,
    quadrature_order: int,
    continuation: Callable[[GammaRateDPState], float],
) -> float:
    if state.remaining <= 0:
        return state.incumbent
    nodes, weights = gauss_laguerre_nodes_weights(quadrature_order)
    total = 0.0
    for node, weight in zip(nodes, weights, strict=True):
        total += float(weight) * continuation(
            transition_state(state, node=float(node), baseline=baseline)
        )
    return max(float(total), 0.0)


def finite_horizon_dp(config: GammaRateDPConfig) -> GammaRateDPResult:
    cfg = GammaRateDPConfig(
        alpha=float(config.alpha),
        beta=float(config.beta),
        baseline=float(config.baseline),
        horizon=int(config.horizon),
        quadrature_order=int(config.quadrature_order),
        u_grid_size=int(config.u_grid_size),
        zeta_grid_size=int(config.zeta_grid_size),
    )
    value = _recursive_value(
        float(cfg.baseline),
        int(cfg.quadrature_order),
        int(cfg.horizon),
        float(cfg.alpha),
        float(cfg.beta),
        cfg.initial_incumbent,
    )
    return GammaRateDPResult(
        value=float(value),
        horizon=int(cfg.horizon),
        quadrature_order=int(cfg.quadrature_order),
        method="experimental_gauss_laguerre_recursive",
    )


def compactification_boundary(final_shape: float, rate: float, baseline: float) -> float:
    return m_v_plus(float(final_shape), float(rate), float(baseline))


def compactify_state(
    *,
    rate: float,
    incumbent: float,
    final_shape: float,
    baseline: float,
) -> GammaRateCompactifiedState:
    if rate <= 0.0:
        raise ValueError("rate must be positive")
    if incumbent < 0.0:
        raise ValueError("incumbent must be non-negative")
    boundary = compactification_boundary(final_shape, rate, baseline)
    if boundary <= 0.0:
        raise ValueError("compactification boundary must be positive")
    return GammaRateCompactifiedState(
        u=log(float(rate)),
        zeta=float(incumbent) / boundary,
        boundary=boundary,
    )


def uncompactify_state(compact: GammaRateCompactifiedState) -> tuple[float, float]:
    if compact.boundary <= 0.0:
        raise ValueError("compactification boundary must be positive")
    return exp(float(compact.u)), float(compact.zeta) * float(compact.boundary)


def long_horizon_monte_carlo_phi(
    *,
    alpha: float,
    beta: float,
    baseline: float,
    sample_count: int,
    horizon: int,
    seed: int,
) -> GammaRateLongHorizonMCResult:
    GammaRatePosteriorSpec(alpha=float(alpha), beta=float(beta), baseline=float(baseline))
    if sample_count <= 1:
        raise ValueError("sample_count must be greater than 1")
    if horizon < 0:
        raise ValueError("horizon must be non-negative")
    rng = np.random.default_rng(seed)
    theta = rng.gamma(shape=float(alpha), scale=1.0 / float(beta), size=int(sample_count))
    shape = float(alpha)
    rates = np.full(int(sample_count), float(beta), dtype=np.float64)
    best = np.full(
        int(sample_count),
        m_v_plus(float(alpha), float(beta), float(baseline)),
        dtype=np.float64,
    )
    for _ in range(int(horizon)):
        observations = rng.exponential(scale=1.0 / theta)
        shape += 1.0
        rates += observations
        best = np.maximum(best, _gamma_rate_ei_vector(shape, rates, float(baseline)))
    terminal = np.maximum(theta - float(baseline), 0.0)
    path_values = np.maximum(best, terminal)
    mean = float(np.mean(path_values, dtype=np.float64))
    standard_error = float(np.std(path_values, ddof=1) / sqrt(float(sample_count)))
    return GammaRateLongHorizonMCResult(
        mean=mean,
        standard_error=standard_error,
        sample_count=int(sample_count),
        horizon=int(horizon),
        seed=int(seed),
    )


@lru_cache(maxsize=128)
def _gauss_laguerre_nodes_weights_cached(
    order: int,
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    nodes, weights = roots_laguerre(order)
    return (
        tuple(float(value) for value in nodes),
        tuple(float(value) for value in weights),
    )


@lru_cache(maxsize=262_144)
def _recursive_value(
    baseline: float,
    quadrature_order: int,
    remaining: int,
    shape: float,
    rate: float,
    incumbent: float,
) -> float:
    if remaining <= 0:
        return max(float(incumbent), 0.0)
    nodes, weights = gauss_laguerre_nodes_weights(quadrature_order)
    total = 0.0
    for node, weight in zip(nodes, weights, strict=True):
        next_shape = float(shape) + 1.0
        next_rate = rate_transition(float(shape), float(rate), float(node))
        next_incumbent = incumbent_update(float(incumbent), next_shape, next_rate, baseline)
        total += float(weight) * _recursive_value(
            float(baseline),
            int(quadrature_order),
            int(remaining) - 1,
            next_shape,
            next_rate,
            next_incumbent,
        )
    return max(float(total), 0.0)


def _u_grid(config: GammaRateDPConfig, nodes: FloatArray) -> FloatArray:
    lower = log(float(config.beta))
    if config.horizon == 0:
        upper = lower + 1.0
    else:
        max_node = min(float(np.max(nodes)), 2.5)
        upper = lower + sum(
            max_node / config.shape_for_layer(layer) for layer in range(config.horizon)
        )
        upper = max(upper, lower + 1e-6)
        while upper > lower + 1e-6 and compactification_boundary(
            config.final_shape,
            exp(upper),
            config.baseline,
        ) <= 0.0:
            upper = 0.5 * (lower + upper)
    return np.linspace(lower, upper, config.u_grid_size, dtype=np.float64)


def _interpolate_normalized_surface(
    surface: FloatArray,
    u_grid: FloatArray,
    zeta_grid: FloatArray,
    u: float,
    zeta: float,
) -> float:
    if zeta >= 1.0:
        return float(zeta)
    clipped_u = float(np.clip(u, float(u_grid[0]), float(u_grid[-1])))
    clipped_zeta = float(np.clip(zeta, float(zeta_grid[0]), float(zeta_grid[-1])))
    u_hi = int(np.searchsorted(u_grid, clipped_u, side="right"))
    z_hi = int(np.searchsorted(zeta_grid, clipped_zeta, side="right"))
    u_hi = min(max(u_hi, 1), len(u_grid) - 1)
    z_hi = min(max(z_hi, 1), len(zeta_grid) - 1)
    u_lo = u_hi - 1
    z_lo = z_hi - 1
    u0 = float(u_grid[u_lo])
    u1 = float(u_grid[u_hi])
    z0 = float(zeta_grid[z_lo])
    z1 = float(zeta_grid[z_hi])
    u_weight = 0.0 if u1 == u0 else (clipped_u - u0) / (u1 - u0)
    z_weight = 0.0 if z1 == z0 else (clipped_zeta - z0) / (z1 - z0)
    lower = (1.0 - z_weight) * surface[u_lo, z_lo] + z_weight * surface[u_lo, z_hi]
    upper = (1.0 - z_weight) * surface[u_hi, z_lo] + z_weight * surface[u_hi, z_hi]
    value = (1.0 - u_weight) * lower + u_weight * upper
    return max(float(value), 0.0)


def _gamma_rate_ei_vector(shape: float, rates: FloatArray, baseline: float) -> FloatArray:
    x = rates * float(baseline)
    values = shape / rates * gammaincc(shape + 1.0, x) - baseline * gammaincc(shape, x)
    return cast(FloatArray, np.maximum(values, 0.0).astype(np.float64, copy=False))
