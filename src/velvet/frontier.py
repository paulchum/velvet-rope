"""Admission Frontier reports generated from deterministic Velvet replay."""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from velvet.actions import ProofDecision
from velvet.contracts import AdmissionContract
from velvet.replay import ReplayResult, run_replay
from velvet.serialization import JsonObject, canonical_json_bytes, stable_json_object


@dataclass(frozen=True)
class AdmissionFrontier:
    report: JsonObject

    def to_dict(self) -> JsonObject:
        return stable_json_object(self.report)

    def to_json_bytes(self) -> bytes:
        return canonical_json_bytes(self.report)


def build_admission_frontier(
    trace: Iterable[Mapping[str, Any]],
    contract: AdmissionContract,
    budgets: Iterable[int],
    *,
    initial_world_state: Mapping[str, Any] | None = None,
    replay_id_prefix: str = "admission_frontier",
) -> AdmissionFrontier:
    trace_tuple = tuple(stable_json_object(item) for item in trace)
    budget_grid = tuple(sorted({int(budget) for budget in budgets}))
    full_contract = contract.with_budget(max(max(budget_grid, default=0), 1_000_000_000))
    full_replay = run_replay(
        trace_tuple,
        full_contract,
        initial_world_state=initial_world_state,
        replay_id=f"{replay_id_prefix}:full",
    )
    full_authority = max(1, _admitted_authority(full_replay))
    full_class_counts = _admitted_class_counts(full_replay)

    rows: list[JsonObject] = []
    for budget in budget_grid:
        replay = run_replay(
            trace_tuple,
            contract.with_budget(budget),
            initial_world_state=initial_world_state,
            replay_id=f"{replay_id_prefix}:budget:{budget}",
        )
        admitted_authority = _admitted_authority(replay)
        decision_counts = _decision_counts(replay)
        class_counts = _admitted_class_counts(replay)
        rows.append(
            {
                "budget": budget,
                "admitted_authority_fraction": round(admitted_authority / full_authority, 6),
                "realized_loss_proxy": admitted_authority,
                "fallback_count": decision_counts[ProofDecision.FALLBACK_EXECUTED.value],
                "escalation_count": decision_counts[ProofDecision.ESCALATED.value],
                "refusal_count": decision_counts[ProofDecision.REFUSED.value]
                + decision_counts[ProofDecision.MASKED_ACTION_FAILURE.value],
                "denial_pressure": _denial_pressure(replay),
                "class_specific_authority_release": {
                    authority_class: round(
                        class_counts[authority_class] / max(1, full_class_counts[authority_class]),
                        6,
                    )
                    for authority_class in sorted(full_class_counts)
                },
            }
        )
    report = {
        "report_type": "Admission Frontier",
        "contract": contract.to_dict(),
        "budgets": list(budget_grid),
        "full_authority": full_authority,
        "rows": rows,
        "Budget@50 Admission": _budget_at(rows, 0.50),
        "Budget@75 Admission": _budget_at(rows, 0.75),
        "Budget@90 Admission": _budget_at(rows, 0.90),
    }
    return AdmissionFrontier(stable_json_object(report))


def write_frontier_artifacts(
    frontier: AdmissionFrontier,
    *,
    output_dir: str | Path,
    basename: str = "admission_frontier",
) -> tuple[Path, Path, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = frontier.to_dict()
    json_path = destination / f"{basename}.json"
    markdown_path = destination / f"{basename}.md"
    csv_path = destination / f"{basename}.csv"
    json_path.write_bytes(frontier.to_json_bytes() + b"\n")
    markdown_path.write_text(render_frontier_markdown(report), encoding="utf-8")
    _write_frontier_csv(report, csv_path)
    return json_path, markdown_path, csv_path


def render_frontier_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Admission Frontier",
        "",
        f"- Budget@50 Admission: `{report.get('Budget@50 Admission')}`",
        f"- Budget@75 Admission: `{report.get('Budget@75 Admission')}`",
        f"- Budget@90 Admission: `{report.get('Budget@90 Admission')}`",
        "",
        "| Budget | Admitted Authority Fraction | Loss Proxy | Fallbacks | "
        "Escalations | Refusals | Denial Pressure |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report.get("rows", []):
        if not isinstance(row, Mapping):
            continue
        lines.append(
            "| {budget} | {admitted_authority_fraction} | {realized_loss_proxy} | "
            "{fallback_count} | {escalation_count} | {refusal_count} | {denial_pressure} |".format(
                **row
            )
        )
    return "\n".join(lines) + "\n"


def _write_frontier_csv(report: Mapping[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "budget",
                "admitted_authority_fraction",
                "realized_loss_proxy",
                "fallback_count",
                "escalation_count",
                "refusal_count",
                "denial_pressure",
            ],
        )
        writer.writeheader()
        for row in report.get("rows", []):
            if not isinstance(row, Mapping):
                continue
            writer.writerow({key: row[key] for key in writer.fieldnames})


def _admitted_authority(replay: ReplayResult) -> int:
    return sum(
        outcome.appraisal.admission_price
        for outcome in replay.outcomes
        if outcome.decision is ProofDecision.ADMITTED
    )


def _admitted_class_counts(replay: ReplayResult) -> Counter[str]:
    counts: Counter[str] = Counter()
    for outcome in replay.outcomes:
        if outcome.decision is ProofDecision.ADMITTED:
            counts[outcome.canonical_action.authority_class.value] += 1
    return counts


def _decision_counts(replay: ReplayResult) -> Counter[str]:
    return Counter(outcome.decision.value for outcome in replay.outcomes)


def _denial_pressure(replay: ReplayResult) -> int:
    total = 0
    for state in replay.final_ledger_state.values():
        if isinstance(state, Mapping):
            total += int(state.get("denial_pressure", 0))
    return total


def _budget_at(rows: list[JsonObject], threshold: float) -> int | None:
    for row in rows:
        if float(row["admitted_authority_fraction"]) >= threshold:
            return int(row["budget"])
    return None
