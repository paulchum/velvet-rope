from __future__ import annotations

from velvet.contracts import AdmissionContract
from velvet.replay import run_replay


def test_same_trace_replay_is_byte_identical() -> None:
    trace = (
        {"action_id": "r1", "operation": "read_rows", "boundary_key": "case:replay"},
        {
            "action_id": "r2",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:replay",
        },
        {
            "action_id": "r3",
            "operation": "raw_sql",
            "sql": "DROP TABLE old",
            "boundary_key": "case:replay",
        },
    )
    contract = AdmissionContract(default_authority_budget=1_000)

    first = run_replay(trace, contract, initial_world_state={"state": 1}, replay_id="same")
    second = run_replay(trace, contract, initial_world_state={"state": 1}, replay_id="same")

    assert first.to_json_bytes() == second.to_json_bytes()
    assert first.final_ledger_state == second.final_ledger_state
