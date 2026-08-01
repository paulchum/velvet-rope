from __future__ import annotations

import math
import random

import pytest

from velvet.verdict.fleet import (
    FleetCertificate,
    anchor_tail_fleet_certificate,
    fleet_verdict,
    refusal_fleet_certificate,
)
from velvet.verdict.rescue import rescue_risk_log_bound


def _cert(certificate_id: str, log_e_value: float, snapshot_id: str = "snap-1") -> FleetCertificate:
    return FleetCertificate(
        certificate_id=certificate_id,
        snapshot_id=snapshot_id,
        status="anchor_tail",
        log_e_value=log_e_value,
        mgf_path="quadrature",
    )


def test_ebh_threshold_selects_in_input_order_with_rank_metadata() -> None:
    verdict = fleet_verdict(
        [
            _cert("third", math.log(7.0)),
            _cert("first", math.log(50.0)),
            _cert("fourth", math.log(1.0)),
            _cert("second", math.log(20.0)),
        ],
        target_fraction=0.2,
    )

    assert verdict.snapshot_id == "snap-1"
    assert verdict.family_size == 4
    assert verdict.cutoff_log_e_value == pytest.approx(math.log(4 / (0.2 * 3)))
    assert verdict.selected_count == 3
    assert verdict.selected_ids == ("third", "first", "second")
    assert [decision.certificate_id for decision in verdict.decisions] == [
        "third",
        "first",
        "fourth",
        "second",
    ]
    assert [decision.rank for decision in verdict.decisions] == [3, 1, 4, 2]


def test_tied_e_values_at_the_selection_boundary_are_selected() -> None:
    verdict = fleet_verdict(
        [
            _cert("a", math.log(10.0)),
            _cert("b", math.log(4.0)),
            _cert("c", math.log(4.0)),
            _cert("d", math.log(1.0)),
        ],
        target_fraction=0.5,
    )

    assert verdict.selected_ids == ("a", "b", "c")
    assert [d.selected for d in verdict.decisions] == [True, True, True, False]


def test_refusals_count_in_k_but_are_never_selected() -> None:
    with_refusal = fleet_verdict(
        [
            _cert("strong", math.log(5.0)),
            _cert("middle", math.log(2.5)),
            refusal_fleet_certificate("refused", "snap-1", "finite-H DP verdict"),
        ],
        target_fraction=0.5,
    )
    without_refusal = fleet_verdict(
        [_cert("strong", math.log(5.0)), _cert("middle", math.log(2.5))],
        target_fraction=0.5,
    )

    assert with_refusal.family_size == 3
    assert with_refusal.selected_ids == ()
    assert [d.selected for d in with_refusal.decisions] == [False, False, False]
    assert without_refusal.selected_ids == ("strong", "middle")


def test_snapshot_and_identifier_validation() -> None:
    with pytest.raises(ValueError, match="snapshot_id"):
        fleet_verdict([_cert("a", 2.0, "snap-1"), _cert("b", 2.0, "snap-2")], 0.2)
    with pytest.raises(ValueError, match="duplicate"):
        fleet_verdict([_cert("a", 2.0), _cert("a", 3.0)], 0.2)
    with pytest.raises(ValueError, match="target_fraction"):
        fleet_verdict([_cert("a", 2.0)], 0.0)
    with pytest.raises(ValueError, match="NaN"):
        _cert("bad", float("nan"))


def test_empty_fleet_has_no_snapshot_or_cutoff() -> None:
    verdict = fleet_verdict([], target_fraction=0.2)

    assert verdict.snapshot_id is None
    assert verdict.family_size == 0
    assert verdict.selected_count == 0
    assert verdict.cutoff_log_e_value is None
    assert verdict.decisions == ()


def test_log_space_extremes_do_not_underflow_selection() -> None:
    verdict = fleet_verdict(
        [
            _cert("huge", math.log(1e300)),
            _cert("tiny", math.log(1e-300)),
            _cert("zero", float("-inf")),
        ],
        target_fraction=1.0,
    )

    assert verdict.selected_ids == ("huge",)
    assert verdict.decisions[0].selected is True
    assert verdict.decisions[1].selected is False
    assert verdict.decisions[2].selected is False


def test_anchor_tail_fleet_certificate_uses_quadrature_log_bound() -> None:
    arms = [(700, 300), (100, 150)]
    expected_log_risk = rescue_risk_log_bound(arms, 1, quadrature_points=101)

    cert = anchor_tail_fleet_certificate(
        arms,
        1,
        certificate_id="kill-1",
        snapshot_id="snap-1",
        quadrature_points=101,
    )

    assert cert.status == "anchor_tail"
    assert cert.mgf_path == "quadrature"
    assert cert.refusal_reason is None
    assert cert.log_e_value == pytest.approx(-expected_log_risk)
    assert cert.metadata["log_rescue_bound"] == pytest.approx(expected_log_risk)
    assert cert.as_dict()["metadata"]["quadrature_points"] == 101


def test_refusal_certificate_serializes_as_nonselectable() -> None:
    cert = refusal_fleet_certificate(
        "dp-only",
        "snap-1",
        "finite-H DP verdicts are excluded from fleet e-BH",
        metadata={"source": "finite_horizon_verdict"},
    )
    verdict = fleet_verdict([cert], target_fraction=1.0)

    assert cert.log_e_value == float("-inf")
    assert cert.mgf_path is None
    assert cert.as_dict()["metadata"]["source"] == "finite_horizon_verdict"
    assert verdict.as_dict()["selected_count"] == 0
    assert verdict.decisions[0].status == "refusal"


def test_predictive_select_then_observe_simulation_controls_mean_fdp() -> None:
    rng = random.Random(20260705)
    q = 0.2
    repetitions = 30_000
    family_size = 12
    total_fdp = 0.0

    for rep in range(repetitions):
        certs: list[FleetCertificate] = []
        rescue_probabilities: dict[str, float] = {}
        for index in range(family_size):
            log_e = rng.uniform(-2.0, 5.0)
            cert_id = f"rep-{rep}-cert-{index}"
            certs.append(_cert(cert_id, log_e, snapshot_id=f"snap-{rep}"))
            rescue_probabilities[cert_id] = min(1.0, 1.0 / math.exp(log_e))

        verdict = fleet_verdict(certs, target_fraction=q)
        if verdict.selected_count == 0:
            continue
        false_selected = 0
        for cert_id in verdict.selected_ids:
            if rng.random() < rescue_probabilities[cert_id]:
                false_selected += 1
        total_fdp += false_selected / verdict.selected_count

    assert total_fdp / repetitions <= q + 0.01
