# Velvet Rope Dataset Contract

Each evaluated system must emit the same action-path artifacts:

- Candidate Action Set
- Admission Decision
- Execution Context
- Internal proof record
- Velvet Seal
- Ledger Replay

Live competitor adapters are scored under the exact same contract. A human approval flow,
guardrail, allowlist, trace, or final refusal does not receive proof/seal credit unless
it serializes to the Velvet Rope artifact schemas before execution. If the adapter cannot
run because a command, package, or credential is absent, the result is `not_run` and no
failure is claimed.

The canonical suite is `velvet_rope_liability` and writes:

- `run_manifest.json`
- `query_traces.jsonl`
- `summary.json`
- `failure_cards.jsonl`
- `result_failure_bindings.jsonl`
- `competitor_results.json`
- `raw_traces/<system>/<query_id>.json`
- `auditability_report.md`
- `eval/index.html`
- `liability_benchmark.md`

Schemas live under `schemas/velvet_rope/`. The current repo uses Velvet naming and schema 9.0 thread records for the liability benchmark; Velvet Rope uses separate action-path artifacts so it does not break the existing `liability` suite.
