from __future__ import annotations

from pathlib import Path

from velvet.contracts import AdmissionContract
from velvet.frontier import build_admission_frontier, write_frontier_artifacts
from velvet.replay import read_trace_jsonl, run_replay

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    output_dir = ROOT / "reports" / "velvet_admission_layer"
    contract = AdmissionContract(default_authority_budget=800, spend_cap=500)
    for name, budgets in {
        "database": (0, 25, 100, 250, 500, 750, 1200, 2500),
        "refund": (0, 50, 200, 500, 800, 1500, 3000, 6000),
    }.items():
        trace = read_trace_jsonl(ROOT / "examples" / f"{name}_trace.jsonl")
        replay = run_replay(
            trace,
            contract,
            initial_world_state={"demo": name},
            replay_id=f"{name}_example",
        )
        (output_dir / f"{name}_replay.json").write_bytes(replay.to_json_bytes() + b"\n")
        frontier = build_admission_frontier(
            trace,
            contract,
            budgets,
            initial_world_state={"demo": name},
            replay_id_prefix=f"{name}_example_frontier",
        )
        write_frontier_artifacts(
            frontier,
            output_dir=output_dir,
            basename=f"{name}_admission_frontier",
        )


if __name__ == "__main__":
    main()
