"""Deterministic replay harness for Velvet admission traces."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from velvet.contracts import AdmissionContract
from velvet.envelope import ProofEnvelope
from velvet.executor import AdmissionOutcome, VelvetAdmissionLayer
from velvet.ledger import AuthorityLedger
from velvet.serialization import JsonObject, canonical_json_bytes, stable_int, stable_json_object

REPLAY_PROOF_SIGNED_AT = "1970-01-01T00:00:00Z"


@dataclass(frozen=True)
class ReplayResult:
    replay_id: str
    envelopes: tuple[ProofEnvelope, ...]
    outcomes: tuple[AdmissionOutcome, ...]
    final_ledger_state: JsonObject
    contract: JsonObject

    def to_dict(self) -> JsonObject:
        return {
            "replay_id": self.replay_id,
            "contract": self.contract,
            "envelopes": [envelope.to_dict() for envelope in self.envelopes],
            "final_ledger_state": self.final_ledger_state,
        }

    def to_json_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def run_replay(
    trace: Iterable[Mapping[str, Any]],
    contract: AdmissionContract,
    *,
    initial_world_state: Mapping[str, Any] | None = None,
    replay_id: str = "velvet_replay",
) -> ReplayResult:
    prepared_trace = _annotate_split_bundles(tuple(stable_json_object(item) for item in trace))
    ledger = AuthorityLedger(
        default_authority_budget=contract.default_authority_budget,
        initial_budgets=contract.authority_budgets,
    )
    layer = VelvetAdmissionLayer(contract=contract, ledger=ledger)
    outcomes: list[AdmissionOutcome] = []
    envelopes: list[ProofEnvelope] = []
    for index, proposed_action in enumerate(prepared_trace, start=1):
        outcome = layer.evaluate(
            proposed_action,
            world_state=initial_world_state or {},
            logical_step=index,
            replay_id=replay_id,
            proof_signed_at=REPLAY_PROOF_SIGNED_AT,
        )
        outcomes.append(outcome)
        envelopes.append(outcome.envelope)
    return ReplayResult(
        replay_id=replay_id,
        envelopes=tuple(envelopes),
        outcomes=tuple(outcomes),
        final_ledger_state=ledger.snapshot(),
        contract=contract.to_dict(),
    )


def read_trace_jsonl(path: str | Path) -> tuple[JsonObject, ...]:
    actions: list[JsonObject] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                loaded = json.loads(stripped)
                if not isinstance(loaded, dict):
                    raise ValueError(f"trace line is not an object: {path}")
                actions.append(stable_json_object(loaded))
    return tuple(actions)


def _annotate_split_bundles(trace: tuple[JsonObject, ...]) -> tuple[JsonObject, ...]:
    totals: dict[str, int] = defaultdict(int)
    counts: dict[str, int] = defaultdict(int)
    exposures: list[tuple[str | None, int]] = []
    for action in trace:
        key, exposure = _batch_split_key_and_exposure(action)
        exposures.append((key, exposure))
        if key is not None:
            totals[key] += exposure
            counts[key] += 1
    annotated: list[JsonObject] = []
    for action, (key, exposure) in zip(trace, exposures, strict=True):
        item = dict(action)
        if key is not None and counts[key] > 1:
            item["_velvet_batch_aggregate_exposure"] = max(totals[key], exposure)
            item["_velvet_batch_count"] = counts[key]
        annotated.append(stable_json_object(item))
    return tuple(annotated)


def _batch_split_key_and_exposure(action: Mapping[str, Any]) -> tuple[str | None, int]:
    amount = _amount(action)
    if amount > 0 and (
        action.get("customer_id") is not None or action.get("refund_case_id") is not None
    ):
        return (
            "money:"
            + str(action.get("boundary_key"))
            + ":"
            + str(action.get("customer_id"))
            + ":"
            + str(action.get("refund_case_id")),
            amount,
        )
    operation = _operation(action)
    sql = str(action.get("sql", action.get("query", ""))).upper()
    destructive = operation in {
        "delete",
        "delete_row",
        "delete_rows",
        "drop",
        "drop_table",
        "truncate",
    }
    destructive = destructive or any(
        marker in sql for marker in ("DROP TABLE", "TRUNCATE TABLE", "DELETE FROM")
    )
    if destructive:
        return (
            "destroy:"
            + str(action.get("boundary_key"))
            + ":"
            + str(action.get("database_id"))
            + ":"
            + str(action.get("migration_task_id"))
            + ":"
            + str(action.get("table", action.get("target_resource"))),
            100,
        )
    return None, 0


def _operation(action: Mapping[str, Any]) -> str:
    for key in ("operation", "action", "tool_name", "tool", "name", "type"):
        value = action.get(key)
        if isinstance(value, str):
            return value.strip().lower().replace("-", "_").replace(".", "_")
    return ""


def _amount(action: Mapping[str, Any]) -> int:
    for key in ("economic_exposure", "amount", "refund_amount", "coupon_amount", "payment_amount"):
        if key in action:
            return stable_int(action.get(key))
    return 0
