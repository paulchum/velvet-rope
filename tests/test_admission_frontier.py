from __future__ import annotations

from velvet.contracts import AdmissionContract
from velvet.frontier import build_admission_frontier


def test_admission_frontier_is_generated_from_replay() -> None:
    trace = (
        {
            "action_id": "f1",
            "surface": "function",
            "name": "read_rows",
            "operation": "read_rows",
            "boundary_key": "case:frontier",
        },
        {
            "action_id": "f2",
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:frontier",
        },
        {
            "action_id": "f3",
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 1200,
            "boundary_key": "case:frontier",
        },
    )
    frontier = build_admission_frontier(
        trace,
        AdmissionContract(spend_cap=500),
        budgets=(0, 100, 1000, 5000),
        replay_id_prefix="frontier_test",
    )
    report = frontier.to_dict()

    assert report["report_type"] == "Admission Frontier"
    assert report["Budget@50 Admission"] is not None
    assert len(report["rows"]) == 4
    assert report["rows"][0]["budget"] == 0
