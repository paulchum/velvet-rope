from __future__ import annotations

import pytest

from velvet.passk import pass_k_curve, pass_k_estimate


def test_pass_k_estimate_requires_all_sampled_runs_successful() -> None:
    assert pass_k_estimate(10, 10, 1) == 1.0
    assert pass_k_estimate(10, 10, 10) == 1.0
    assert pass_k_estimate(5, 10, 1) == 0.5
    assert pass_k_estimate(5, 10, 2) == pytest.approx(2 / 9)
    assert pass_k_estimate(1, 10, 2) == 0.0
    assert pass_k_estimate(1, 1, 2) is None


def test_pass_k_curve_uses_supported_sample_sizes() -> None:
    curve = pass_k_curve([True, True, False, False, False], k_values=(1, 2, 5, 10))

    assert curve == {"1": 0.4, "2": 0.1, "5": 0.0}
