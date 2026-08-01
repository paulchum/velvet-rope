# Velvet Rope Implementation Report

## Files Changed

- `src/velvet/velvet_rope_liability.py`
- `pyproject.toml`
- `uv.lock`
- `crates/velvet-eval/src/integrity.rs`
- `crates/velvet-eval/src/report.rs`
- `schemas/velvet_rope/*.schema.json`
- `tests/test_velvet_rope_liability.py`
- `reports/liability/velvet_rope/`

## Schemas Added / Updated

Updated closed JSON Schemas:

- `candidate_action.schema.json`
- `admission_decision.schema.json`
- `execution_context.schema.json`
- `liability_warrant.schema.json`
- `velvet_seal.schema.json`
- `velvet_rope_trace.schema.json`
- `velvet_rope_run_summary.schema.json`
- `velvet_failure_card.schema.json`
- `competitor_action_result.schema.json`
- `result_failure_binding.schema.json`
- `competitor_research_record.schema.json`

Added schemas:

- `run_manifest.schema.json`
- `competitor_results.schema.json`

## Commands Run

```bash
uv lock
uv run pytest tests/test_velvet_rope_liability.py
uv run pytest
uv run ruff check src tests
cargo fmt
cargo fmt --check
cargo test -p velvet-eval integrity
cargo test --workspace
uv run python -m velvet.liability_benchmark --suite velvet_rope_liability --out reports/liability/velvet_rope --json
cargo run -q -p velvet-eval -- bench --suite liability
cargo run -q -p velvet-eval -- bench --suite velvet_rope_liability
cargo run -q -p velvet-eval -- report --run-id bench_velvet_rope_liability --output reports/liability/velvet_rope/eval
cargo run -q -p velvet-eval -- query --recipe market_claim_support --run-id bench_velvet_rope_liability
cargo run -q -p velvet-eval -- verify-report-integrity --run-id bench_velvet_rope_liability --report reports/liability/velvet_rope/eval
```

## Test Results

- `uv run pytest`: 68 passed, 3 skipped.
- `uv run ruff check src tests`: passed.
- `cargo fmt --check`: passed.
- `cargo test --workspace`: passed.
- `verify-report-integrity`: `report_integrity=valid run_id=bench_velvet_rope_liability checked=2557`.

## Local Baseline Results

The regenerated arena emits 252 traces, 1268 failure cards, 1268 result failure bindings, and 21 system/category result rows.

- `Velvet native gate`: `WARRANTED AND AUDITABLE`, Action Path Integrity pass, 0 critical/high failures, liability multiplier 0.
- `Lockout-only baseline`: `PARTIAL`, Action Path Integrity pass, opportunity cost bound to failure evidence.
- `Inspect-only baseline`: `PARTIAL`, Action Path Integrity fail on certifiable-waste execution paths.
- `Naive tool router`, `Prompt-only agent`, `Final-output guardrail`, `Observability-only tracing system`, `MCP allowlist-only gateway`, and `Generic workflow automation agent`: classified only from fixture traces with bound failure cards and raw trace hashes.

## Velvet Native Results

Velvet native emits candidate actions, admission decisions, execution contexts, pre-execution warrants, replay seals, and deterministic replay commands. Consequential denials remain `denied_at_rope` or concierge escalation without execution, and Action Path Integrity passes across the fixture suite.

## Ablation Results

- `Velvet without warrants ablation`: classified as `PARTIAL`; missing-warrant and executed-without-warrant liabilities are bound to failure cards and result bindings.
- `Velvet without seals ablation`: classified as `PARTIAL`; missing-seal and missing-replay liabilities are bound to failure cards and result bindings.

## Competitor / Adversary Matrix Status

Named competitor rows remain `trace_audit_only` and `internal_only`; no named competitor is described as having failed live. Optional live adapter stubs exist for OpenAI Agents SDK, LangGraph / LangChain, CrewAI, AutoGen, and Google ADK, but live/cloud execution is opt-in via `VELVET_ROPE_ENABLE_LIVE_ADAPTERS=1` and no stub wraps a competitor in Velvet for safety credit.

Tier 1 dossier status: dossiers are present for OpenAI Agents SDK, LangGraph / LangChain agents, Microsoft Agent Framework, AutoGen, Semantic Kernel Agent Framework, Google ADK, CrewAI, LlamaIndex agents/workflows, Zapier Agents / Zapier MCP, and n8n AI agents/workflows.

Source-log status: source log remains in `docs/liability/VELVET_ROPE_COMPETITOR_SOURCE_LOG.md`.

## Report Integrity

`verify-report-integrity` now rejects nonzero metrics without matching bindings, orphan failure cards, bindings with missing raw traces or missing failure cards, missing public auditability/status fields, unsafe rankings above warranted systems, and live-failure wording for named competitors without `result_type = live`.

Public reports now include verdict, Action Path Integrity, result type, auditability status, critical/high/medium/opportunity/cost failures, bound failure tables, nonzero metric drilldowns, trace hashes, reproduction commands, and the required line:

Task success does not offset unauthorized execution.

## Remaining Limitations

- Velvet Rope remains fixtures-first by default.
- Live adapters are stubs until optional SDKs are installed and explicitly enabled.
- Research rows classify missing native proof artifacts; they do not claim live execution failures.
- JSON artifacts are schema-validated; Markdown/HTML reports are checked by tests for required sections rather than JSON Schema.

## Public-Claim-Safe Wording

Velvet Rope classifies systems by whether they can prove the pre-execution action path. Systems that cannot emit candidate actions, admission decisions, execution contexts, warrants, and replay seals are classified as partial or non-auditable under the Velvet Rope contract.

## Risky Changes / Naming Conflicts

- Added runtime dependency `jsonschema>=4,<5`.
- The local eval-store entry `~/.velvet/evals/bench_velvet_rope_liability` had an old digest and was renamed to a timestamped `.pre_hardening.*` backup before rerunning the canonical bench command.
- No prior project-name package naming was introduced; Python remains `velvet`, Rust eval crate remains `velvet-eval`, and thread schema remains `9.0`.
