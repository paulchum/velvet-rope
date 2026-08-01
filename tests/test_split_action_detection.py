from __future__ import annotations

from velvet.actions import ProofDecision
from velvet.contracts import AdmissionContract
from velvet.replay import run_replay


def _split_refund_trace() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "action_id": f"split-{index}",
            "surface": "function",
            "name": "coupon",
            "operation": "coupon",
            "coupon_amount": 50,
            "customer_id": "cust-1",
            "refund_case_id": "case-1",
            "boundary_key": "customer:cust-1:refund_case:case-1",
        }
        for index in range(10)
    )


def test_split_refunds_aggregate_into_one_boundary_exposure() -> None:
    replay = run_replay(
        _split_refund_trace(),
        AdmissionContract(spend_cap=500, default_authority_budget=500),
    )

    first = replay.outcomes[0]
    assert first.canonical_action.aggregated_economic_exposure == 500
    assert first.envelope.appraisal_coverage["split_bundle_reserve"] == 675
    assert first.envelope.appraisal_coverage["split_preauthorization_blocked"] is True
    assert all(outcome.decision is not ProofDecision.ADMITTED for outcome in replay.outcomes)
    state = replay.final_ledger_state["customer:cust-1:refund_case:case-1"]
    assert state["denial_pressure"] == 10


def test_split_preauthorization_above_bundle_reserve_admits_bundle() -> None:
    replay = run_replay(
        _split_refund_trace(),
        AdmissionContract(spend_cap=500, default_authority_budget=800),
    )

    assert replay.outcomes[0].envelope.appraisal_coverage["split_bundle_reserve"] == 675
    assert replay.outcomes[0].appraisal.admission_price == 675
    assert replay.outcomes[1].appraisal.admission_price == 0
    assert all(outcome.decision is ProofDecision.ADMITTED for outcome in replay.outcomes)
    state = replay.final_ledger_state["customer:cust-1:refund_case:case-1"]
    assert state["remaining_authority"] == 125
    assert list(state["split_reservations"].values()) == [675]


def test_large_split_refunds_are_blocked_by_bundle_reserve() -> None:
    trace = tuple(
        {
            "action_id": f"split-{index}",
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 500,
            "customer_id": "cust-1",
            "refund_case_id": "case-1",
            "boundary_key": "customer:cust-1:refund_case:case-1",
        }
        for index in range(10)
    )

    replay = run_replay(trace, AdmissionContract(spend_cap=500, default_authority_budget=1000))

    first = replay.outcomes[0]
    assert first.canonical_action.aggregated_economic_exposure == 5000
    assert all(outcome.decision is not ProofDecision.ADMITTED for outcome in replay.outcomes)
    state = replay.final_ledger_state["customer:cust-1:refund_case:case-1"]
    assert state["denial_pressure"] == 10
