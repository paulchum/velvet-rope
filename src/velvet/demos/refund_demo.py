"""Customer refund and support demo for the Velvet Admission Layer."""

from __future__ import annotations

from pathlib import Path

from velvet.contracts import AdmissionContract
from velvet.frontier import AdmissionFrontier, build_admission_frontier, write_frontier_artifacts
from velvet.replay import ReplayResult, run_replay
from velvet.serialization import JsonObject


def refund_trace() -> tuple[JsonObject, ...]:
    boundary = "customer:cust-77:refund_case:case-900"
    common = {
        "actor_id": "support-lead",
        "agent_id": "support-agent",
        "customer_id": "cust-77",
        "refund_case_id": "case-900",
        "boundary_key": boundary,
        "timestamp": "2026-05-26T12:00:00Z",
    }
    return (
        {**common, "action_id": "rf-001", "operation": "coupon", "coupon_amount": 25},
        {**common, "action_id": "rf-002", "operation": "refund", "refund_amount": 150},
        {**common, "action_id": "rf-003", "operation": "refund", "refund_amount": 1200},
        {
            **common,
            "action_id": "rf-004",
            "operation": "refund",
            "refund_amount": 200,
            "fraud_flagged": True,
        },
        {
            **common,
            "action_id": "rf-005",
            "operation": "address_update",
            "target_resource": "customer:cust-77",
            "email_to": "customer@example.com",
            "binds_external": True,
        },
        {
            **common,
            "action_id": "rf-006",
            "operation": "delete",
            "target_resource": "account:cust-77",
        },
        {
            **common,
            "action_id": "rf-007",
            "operation": "send_email",
            "email_to": "customer@example.com",
            "commitment": "We will refund your annual plan today.",
        },
    )


def refund_contract(default_budget: int = 800) -> AdmissionContract:
    return AdmissionContract(
        contract_id="velvet_refund_demo",
        default_authority_budget=default_budget,
        spend_cap=500,
    )


def run_refund_demo(
    output_dir: str | Path = "reports/velvet_admission_layer",
) -> tuple[ReplayResult, AdmissionFrontier]:
    contract = refund_contract()
    trace = refund_trace()
    replay = run_replay(
        trace, contract, initial_world_state={"support_case": "case-900"}, replay_id="refund_demo"
    )
    frontier = build_admission_frontier(
        trace,
        contract,
        budgets=(0, 50, 200, 500, 800, 1500, 3000, 6000),
        initial_world_state={"support_case": "case-900"},
        replay_id_prefix="refund_demo_frontier",
    )
    write_frontier_artifacts(frontier, output_dir=output_dir, basename="refund_admission_frontier")
    return replay, frontier


if __name__ == "__main__":
    run_refund_demo()
