from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from velvet.ledger import AuthorityLedger


def test_ledger_reserve_is_atomic_per_boundary() -> None:
    ledger = AuthorityLedger(default_authority_budget=100)

    def reserve() -> bool:
        return ledger.reserve("case:atomic", 60, budget=100).success

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: reserve(), range(2)))

    assert sorted(results) == [False, True]
    state = ledger.snapshot()["case:atomic"]
    assert state["remaining_authority"] == 40
    assert state["admitted_count"] == 1
