# Liability Benchmark Methodology

This benchmark compares Velvet against local baselines and named guardrail systems on a fixed liability case set. It is designed to be reproducible offline and honest about systems that were not executed.

## Default Reproduction

```bash
uv run velvet liability-benchmark --report-dir reports/liability
```

The default no-credential path is deterministic. When a competitor package, credential, or config is absent, the report records `status: not_run` and a concrete `not_run_reason`. A not-run row is not a competitor failure.

## Case Set

- Max-DE liability cases: `benchmarks/liability/false_lockout_beta_1_2.json` and `benchmarks/liability/certifiable_waste_beta_1_3.json`.
- Real-world incident templates: all JSON files under `benchmarks/liability/real_world_incidents/`.
- Agent-task subset: `benchmarks/tau_bench/airline_retail_subset.json`, pinned to upstream `sierra-research/tau-bench` commit `59a200c6d575d595120f1cb70fea53cef0632f6b`.

## Capability Facts

Every system result has three machine-checkable fields:

- `emitted_decision_certificate`: true only when the system emits a first-class decision certificate.
- `deterministic_across_repeated_runs`: true only when repeated identical inputs produce the same normalized decision.
- `replayable_seal_reproduces_decision`: true only when the system emits stable replay material that reproduces the same decision.

The default repeat count is `3`. Provider request ids, trace ids, moderation scores, and natural-language explanations are not counted as certificates or replay seals.

## Competitor Adapter Configuration

OpenAI Agents SDK guardrails:

```bash
uv sync --extra live-openai
export OPENAI_API_KEY=...
```

NVIDIA NeMo Guardrails:

```bash
uv pip install nemoguardrails
export NEMO_GUARDRAILS_CONFIG=/path/to/nemo/config
export NVIDIA_API_KEY=... # if required by the config
```

Guardrails AI:

```bash
uv pip install guardrails-ai
```

Amazon Bedrock Guardrails:

```bash
uv sync --extra live-bedrock
export AWS_REGION=...
export BEDROCK_GUARDRAIL_ID=...
export BEDROCK_GUARDRAIL_VERSION=...
```

Azure AI Content Safety:

```bash
export AZURE_CONTENT_SAFETY_ENDPOINT=https://<resource>.cognitiveservices.azure.com
export AZURE_CONTENT_SAFETY_KEY=...
export AZURE_CONTENT_SAFETY_BLOCK_SEVERITY=4
```

Lakera Guard:

```bash
export LAKERA_API_KEY=...
export LAKERA_PROJECT_ID=... # optional
export LAKERA_GUARD_URL=https://api.lakera.ai/v2/guard # optional override
```

## Report Outputs

The command writes:

- `reports/liability/liability_benchmark.json`
- `reports/liability/liability_benchmark.md`
- `reports/liability/liability_thread.jsonl`

The JSON report includes the exact git commit hash, dirty worktree flag, adapter versions, run/not-run status, capability matrix, and any case where another completed local baseline matches or beats Velvet on liability cost.
