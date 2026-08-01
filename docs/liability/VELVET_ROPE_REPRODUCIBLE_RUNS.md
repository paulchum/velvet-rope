# Velvet Rope Reproducible Runs

Run the arena:

```bash
uv run python -m velvet.liability_benchmark \
  --suite velvet_rope_liability \
  --out reports/liability/velvet_rope
```

Run strict top-5 live adapters:

```bash
VELVET_ROPE_ENABLE_LIVE_ADAPTERS=1 \
VELVET_ROPE_OPENAI_AGENTS_CMD='python harnesses/openai_agents.py --scenario {scenario_json}' \
VELVET_ROPE_LANGGRAPH_CMD='python harnesses/langgraph.py --scenario {scenario_json}' \
VELVET_ROPE_CREWAI_CMD='python harnesses/crewai.py --scenario {scenario_json}' \
VELVET_ROPE_LLAMA_INDEX_CMD='python harnesses/llama_index.py --scenario {scenario_json}' \
VELVET_ROPE_N8N_CMD='python harnesses/n8n.py --scenario {scenario_json}' \
uv run python -m velvet.liability_benchmark \
  --suite velvet_rope_liability \
  --live-competitors top5 \
  --out reports/liability/velvet_rope
```

Each live command receives a scenario JSON path and must print or write a JSON object with
Velvet-compatible `candidate_actions`, `admission_decisions`, `execution_contexts`,
`warrants`, and `seals`. Missing live commands or packages produce `not_run` rows, not
synthetic competitor failures.

Run eval:

```bash
cargo run -q -p velvet-eval -- bench --suite velvet_rope_liability
cargo run -q -p velvet-eval -- report \
  --run-id bench_velvet_rope_liability \
  --output reports/liability/velvet_rope/eval
cargo run -q -p velvet-eval -- verify-report-integrity \
  --run-id bench_velvet_rope_liability \
  --report reports/liability/velvet_rope/eval
```

Failure cards and result bindings use deterministic fingerprints. The same deterministic fixture failure should reproduce the same fingerprint.
