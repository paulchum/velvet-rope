# Agent Authorization Benchmark

Route: `/agent-authorization-benchmark`

## Hero

Your agent can pass the task and still be unsafe for consequential action.

The Agent Authorization Benchmark asks one narrow question: for a proposed
autonomous-agent action, did the system produce a pre-execution authorization
artifact that is deterministic, replayable, independently verifiable with public
material, and tamper-evident?

## Why This Exists

Most agent evaluations measure task success, refusal quality, or post-hoc trace
coverage. Those are useful, but they do not answer whether a tool call, memory
write, spend decision, code execution, or external send had authority before it
happened.

Velvet's public benchmark makes that boundary visible. It separates:

- certificate emission,
- determinism,
- replayability,
- independent public verification,
- tamper evidence.

## Run It

```bash
uv run velvet agent-auth-benchmark --report-dir reports/agent_auth
```

The offline run writes aggregate results, per-system result records,
verification artifacts, and a rendered `RESULTS.md` file.

Build the standalone public benchmark repository tree:

```bash
uv run python scripts/export_benchmark_tree.py --out build/oss/agent-authorization-benchmark
```

That export vendors the pure-Python benchmark validation/comparison package,
copies the offline verifier SDK, regenerates comparison evidence in the export
tree, and gate-checks for local absolute path leakage. The Velvet core OSS
export also regenerates and includes the comparison evidence under
`benchmarks/agent_authorization/comparison/`.

Start with the canonical repo artifacts:

- Benchmark overview: [`../../benchmarks/agent_authorization/README.md`](../../benchmarks/agent_authorization/README.md)
- Current results: [`../../benchmarks/agent_authorization/RESULTS.md`](../../benchmarks/agent_authorization/RESULTS.md)
- Submission protocol: [`../../benchmarks/agent_authorization/SUBMISSION.md`](../../benchmarks/agent_authorization/SUBMISSION.md)
- Public claims boundary: [`../liability/VELVET_ROPE_PUBLIC_CLAIMS_POLICY.md`](../liability/VELVET_ROPE_PUBLIC_CLAIMS_POLICY.md)

## What The Benchmark Is Not

This benchmark does not claim that Velvet solves agent safety. It does not
measure general model quality, task success, conversational quality, or
production readiness. Not-run entries are not failures; they mean the adapter
could not execute offline because a package, credential, or configuration value
was absent.

## Community Submission CTA

If your agent stack can emit pre-execution authorization evidence, submit a row.
If it cannot, the failure mode is useful too: it shows which evidence boundary
is missing before consequential execution.

```bash
uv run python benchmarks/agent_authorization/scripts/validate_submission.py \
  --submission third_party_result.json \
  --append-to benchmarks/agent_authorization/results/community_leaderboard.json
```

## Buyer CTA

Bring one agent workflow with consequential tool calls. Velvet will map the
workflow into candidate actions, admission decisions, warrants, replay seals, and
a short evidence report in a bounded pilot.
