from __future__ import annotations

import math

import pytest

from velvet.research.anchor_tail import (
    beta_anchor_drop_log_bound,
    beta_negative_mgf,
    product_anchor_drop_log_bound,
)


def _product_martingale_value(
    anchors: tuple[tuple[int, int], ...],
    lambdas: tuple[float, ...],
    r: float,
) -> float:
    log_value = math.fsum(
        lam * r + math.log(beta_negative_mgf(alpha, beta, lam))
        for (alpha, beta), lam in zip(anchors, lambdas, strict=True)
    )
    return math.exp(log_value)


def test_product_anchor_bound_adds_separated_anchor_exponents() -> None:
    r = 1.0 - (4.0 * 0.01) ** 0.25
    anchors = ((40, 20), (30, 15), (24, 12))

    product = product_anchor_drop_log_bound(anchors, r)
    singles = tuple(beta_anchor_drop_log_bound(alpha, beta, r) for alpha, beta in anchors)

    assert product.anchor_indexes == (0, 1, 2)
    assert product.component_log_errors == pytest.approx(
        tuple(single.log_error for single in singles),
    )
    assert product.log_error == pytest.approx(
        math.fsum(single.log_error for single in singles),
    )
    assert math.exp(product.log_error) < min(math.exp(single.log_error) for single in singles)
    assert math.exp(product.log_error) == pytest.approx(0.0207, rel=5e-2)


def test_product_anchor_ignores_nonseparated_anchors() -> None:
    r = 0.6
    anchors = ((40, 20), (3, 3), (1, 4))

    product = product_anchor_drop_log_bound(anchors, r)

    assert product.anchor_indexes == (0,)
    assert product.log_error == pytest.approx(
        beta_anchor_drop_log_bound(40, 20, r).log_error,
    )


def test_product_anchor_martingale_identity_under_actual_mixed_kernel() -> None:
    r = 1.0 - (4.0 * 0.01) ** 0.25
    anchors = ((40, 20), (30, 15), (24, 12))
    lambdas = (12.0, 9.0, 7.0)
    policy = (0.35, 0.30, 0.25, 0.10)

    current = _product_martingale_value(anchors, lambdas, r)
    expected_next = 0.0
    for index, action_probability in enumerate(policy):
        if index == len(anchors):
            expected_next += action_probability * current
            continue
        alpha, beta = anchors[index]
        mean = alpha / (alpha + beta)
        success_state = list(anchors)
        success_state[index] = (alpha + 1, beta)
        failure_state = list(anchors)
        failure_state[index] = (alpha, beta + 1)
        expected_next += action_probability * (
            mean * _product_martingale_value(tuple(success_state), lambdas, r)
            + (1.0 - mean) * _product_martingale_value(tuple(failure_state), lambdas, r)
        )

    assert expected_next == pytest.approx(current, abs=1e-12)
