from __future__ import annotations

from math import comb

import pytest
from aab.passk import pass_k_estimate


def test_passk_known_values() -> None:
    assert pass_k_estimate(10, 20, 1) == 0.5
    assert pass_k_estimate(20, 20, 10) == 1.0
    assert pass_k_estimate(10, 20, 10) == comb(10, 10) / comb(20, 10)
    assert pass_k_estimate(9, 20, 10) == 0.0
    assert pass_k_estimate(9, 9, 10) is None


@pytest.mark.parametrize(
    ("success_count", "sample_count", "k"),
    [
        (10, 20, 0),
        (10, -1, 1),
        (-1, 20, 1),
        (21, 20, 1),
    ],
)
def test_passk_rejects_invalid_inputs(success_count: int, sample_count: int, k: int) -> None:
    with pytest.raises(ValueError):
        pass_k_estimate(success_count, sample_count, k)
