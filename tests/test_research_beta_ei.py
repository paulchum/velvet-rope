from __future__ import annotations

import math

import pytest

from velvet.research.beta_ei import beta_expected_improvement, beta_mean


def _integrated_expected_improvement(alpha: int, beta: int, baseline: float) -> float:
    points = 4001
    step = 1.0 / (points - 1)
    log_norm = math.lgamma(alpha) + math.lgamma(beta) - math.lgamma(alpha + beta)
    total = 0.0
    for index in range(points):
        x = index * step
        if x <= 0.0 or x >= 1.0:
            density_part = 0.0 if alpha > 1 and beta > 1 else 1.0
        else:
            density_part = math.exp(
                (alpha - 1) * math.log(x)
                + (beta - 1) * math.log1p(-x)
                - log_norm,
            )
        weight = 1 if index in (0, points - 1) else (4 if index % 2 else 2)
        total += weight * max(x - baseline, 0.0) * density_part
    return total * step / 3.0


def test_beta_expected_improvement_matches_small_case_quadrature() -> None:
    for alpha, beta, baseline in ((2, 3, 0.35), (4, 2, 0.55), (3, 5, 0.2)):
        assert beta_expected_improvement(alpha, beta, baseline) == pytest.approx(
            _integrated_expected_improvement(alpha, beta, baseline),
            rel=1e-6,
        )


def test_beta_expected_improvement_boundary_values() -> None:
    assert beta_expected_improvement(2, 3, 0.0) == pytest.approx(beta_mean(2, 3))
    assert beta_expected_improvement(2, 3, 1.0) == pytest.approx(0.0)
