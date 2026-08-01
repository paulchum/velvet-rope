from __future__ import annotations

import numpy as np

from velvet.research.gamma_rate import m_v_plus
from velvet.research.gamma_rate_dp import (
    GammaRateDPConfig,
    GammaRateSurfaceCache,
    bellman_update,
    compactify_state,
    finite_horizon_dp,
    gauss_laguerre_nodes_weights,
    incumbent_update,
    initial_state,
    long_horizon_monte_carlo_phi,
    rate_transition,
    transition_state,
    uncompactify_state,
)


def test_gauss_laguerre_nodes_weights_are_deterministic() -> None:
    nodes, weights = gauss_laguerre_nodes_weights(16)
    repeated_nodes, repeated_weights = gauss_laguerre_nodes_weights(16)

    assert np.allclose(nodes, repeated_nodes)
    assert np.allclose(weights, repeated_weights)
    assert np.all(np.isfinite(nodes))
    assert np.all(np.isfinite(weights))
    assert np.all(nodes > 0.0)
    assert np.all(weights > 0.0)
    assert np.isclose(float(np.sum(weights)), 1.0, atol=1e-14)


def test_bellman_update_and_recursion_are_finite_nonnegative() -> None:
    config = GammaRateDPConfig(
        alpha=2.0,
        beta=1.0,
        baseline=1.0,
        horizon=1,
        quadrature_order=16,
    )
    state = initial_state(config)
    one_step = bellman_update(
        state,
        baseline=config.baseline,
        quadrature_order=config.quadrature_order,
        continuation=lambda next_state: next_state.incumbent,
    )
    result = finite_horizon_dp(config)

    assert np.isfinite(one_step)
    assert np.isfinite(result.value)
    assert one_step >= 0.0
    assert result.value >= 0.0
    assert np.isclose(one_step, result.value)


def test_compactified_coordinates_round_trip_without_clipping() -> None:
    config = GammaRateDPConfig(alpha=2.0, beta=1.0, baseline=1.0, horizon=3)
    rate = 1.75
    incumbent = 0.25

    compact = compactify_state(
        rate=rate,
        incumbent=incumbent,
        final_shape=config.final_shape,
        baseline=config.baseline,
    )
    recovered_rate, recovered_incumbent = uncompactify_state(compact)

    assert np.isclose(recovered_rate, rate, rtol=1e-14, atol=1e-14)
    assert np.isclose(recovered_incumbent, incumbent, rtol=1e-14, atol=1e-14)


def test_surface_cache_is_deterministic_finite_and_nonnegative() -> None:
    config = GammaRateDPConfig(
        alpha=2.0,
        beta=1.0,
        baseline=1.0,
        horizon=2,
        quadrature_order=8,
        u_grid_size=13,
        zeta_grid_size=9,
    )
    first = GammaRateSurfaceCache.build(config)
    second = GammaRateSurfaceCache.build(config)
    state = initial_state(config)
    first_value = first.evaluate_state(state)
    second_value = first.evaluate_state(state)

    assert np.allclose(first.u_grid, second.u_grid)
    assert np.allclose(first.zeta_grid, second.zeta_grid)
    assert np.allclose(first.normalized_surface(0), second.normalized_surface(0))
    assert np.isfinite(first_value)
    assert first_value >= 0.0
    assert first_value == second_value
    assert np.all(np.isfinite(first.normalized_surface(0)))
    assert np.min(first.normalized_surface(0)) >= 0.0


def test_shape_layer_indexing_and_transition() -> None:
    config = GammaRateDPConfig(alpha=2.0, beta=1.0, baseline=1.0, horizon=3)
    state = initial_state(config)
    next_state = transition_state(state, node=0.5, baseline=config.baseline)

    assert config.shape_for_layer(0) == 2.0
    assert config.shape_for_layer(1) == 3.0
    assert config.shape_for_layer(3) == 5.0
    assert next_state.layer == 1
    assert next_state.remaining == 2
    assert next_state.shape == config.shape_for_layer(1)


def test_rate_transition_stays_positive() -> None:
    nodes, _ = gauss_laguerre_nodes_weights(16)
    next_rates = [rate_transition(2.0, 1.0, float(node)) for node in nodes]

    assert all(np.isfinite(value) for value in next_rates)
    assert all(value > 0.0 for value in next_rates)


def test_incumbent_update_uses_max_and_is_monotone_in_z() -> None:
    shape = 3.0
    rate = 1.4
    baseline = 1.0
    next_value = m_v_plus(shape, rate, baseline)

    assert incumbent_update(0.0, shape, rate, baseline) == next_value
    assert incumbent_update(next_value + 0.5, shape, rate, baseline) == next_value + 0.5
    assert incumbent_update(0.25, shape, rate, baseline) <= incumbent_update(
        0.5,
        shape,
        rate,
        baseline,
    )


def test_finite_horizon_dp_is_non_decreasing_for_fixture() -> None:
    values = [
        finite_horizon_dp(
            GammaRateDPConfig(
                alpha=2.0,
                beta=1.0,
                baseline=1.0,
                horizon=horizon,
                quadrature_order=16,
            )
        ).value
        for horizon in (1, 2, 3)
    ]

    assert values[0] <= values[1] <= values[2]


def test_dp_lower_does_not_exceed_independent_long_horizon_mc_estimate() -> None:
    config = GammaRateDPConfig(
        alpha=2.0,
        beta=1.0,
        baseline=1.0,
        horizon=3,
        quadrature_order=16,
    )
    dp_value = finite_horizon_dp(config).value
    mc = long_horizon_monte_carlo_phi(
        alpha=2.0,
        beta=1.0,
        baseline=1.0,
        sample_count=30_000,
        horizon=120,
        seed=202606,
    )

    assert dp_value <= mc.mean + 5.0 * mc.standard_error + 0.05
