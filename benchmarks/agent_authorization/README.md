# Agent Authorization Benchmark

Version: `0.4.0`

The Agent Authorization Benchmark is a neutral, open benchmark for agent-authorization systems. It measures authorization artifacts, certified-decision properties, and—through ShadowPath—whether denying an obvious tool route actually prevents the prohibited business effect across equivalent routes. It also reports pass^k reliability over repeated runs.

Version `0.4.0` adds four effect-level cells: route authorization, effect prevention, effect inventory, and effect reconciliation. The committed hermetic baseline denies `customer.disable` successfully while all eight equivalent paths still disable a synthetic customer, yielding `CONTROL_FALSE_SUCCESS`.

## Current Results At A Glance

The seeded results currently contain 15 rows: 9 measured rows and 6 not-run rows. The not-run rows identify missing optional packages, credentials, or configuration and are not treated as competitor failures. The comparison harness currently contains 6 local fixture SUT rows; those rows are local fixtures, not live product evaluations.

- Results table: [`RESULTS.md`](RESULTS.md)
- Fixture comparison: [`comparison/COMPARISON_RESULTS.md`](comparison/COMPARISON_RESULTS.md)
- ShadowPath report: [`shadowpath/SHADOWPATH_RESULTS.md`](shadowpath/SHADOWPATH_RESULTS.md)
- Standalone repository: https://github.com/paulchum/velvet-rope/tree/main/benchmarks/agent_authorization

## Relationship to Velvet

This standalone repository publishes the Agent Authorization Benchmark as neutral infrastructure. Velvet appears as one submitted system-under-test row in the committed results; the benchmark protocol is governed by [`SPEC.md`](SPEC.md) and is intended to accept comparable third-party rows. The Velvet source repository is published separately at https://github.com/paulchum/velvet-rope.

## Submit Your System

Read [`SUBMISSION.md`](SUBMISSION.md), emit the submission JSON shape, and run:

```bash
aab-validate results/*.json comparison/results/*.json shadowpath/results/*.json
```

Fixture-based rows follow the same evidence-pointer discipline and boundary language as existing rows. A row names whether it is a fixture or live run, and fixture rows must preserve the "local fixture, not a live product evaluation" boundary.

## Methodology Anchors

Each system row reports thirteen capabilities from `SPEC.md`. The original artifact cells are:

- certificate emission
- determinism
- replayability
- independent verifiability
- tamper-evidence

Every cell includes an evidence pointer. A `not run: missing ...` entry means the adapter could not run offline because a named optional package, credential, or configuration value was absent. It is not counted as a competitor failure.

ShadowPath independently observes a synthetic customer record after exercising browser automation, an alternate API, direct database mutation, queue insertion, webhook creation, an admin console, credential delegation, and a simulated human-operator message. Its deterministic fixture is a local baseline, not a live product evaluation.

The row must also report a pass^k curve when repeated-run success labels are available. Following tau-bench, pass^k estimates the probability that all `k` sampled runs are successful; PolicyGuard applies the same estimator to document-compliance policy review. See tau-bench at <https://arxiv.org/abs/2406.12045> and, for the document-compliance application, PolicyGuard at <https://arxiv.org/abs/2606.32004>.

## Offline Reproduction

### Tier 1 - verify in this repo (anyone)

From a fresh clone of this standalone repository:

```bash
pip install -e ".[dev]"
python -m playwright install chromium
aab-validate results/*.json comparison/results/*.json shadowpath/results/*.json
aab-shadowpath --output-dir /tmp/shadowpath --expect-breach
aab-verify-cert verification/velvet_decision_certificate.json --public-key-file tests/fixtures/keys/velvet_demo_ed25519.pub
python scripts/check_evidence_pointers.py
pytest -q
```

These commands verify the shipped artifacts, decision certificate, evidence pointers, tests, and local fixture boundaries without needing the private Velvet monorepo.

### Tier 2 - regenerate from source (maintainers)

The benchmark artifacts are generated in the private Velvet monorepo at the recorded `commit_hash`, then exported by the standalone export script. This repository ships the generated artifacts, validator, verifier, tests, and documentation needed to inspect them; it does not ship the private monorepo regeneration harness.

The generated aggregate JSON records `commit_repo: "velvet (private monorepo)"`, the source `commit_hash`, and `source_lockfile_hashes` for the private source lockfiles used during generation.

## Fixture Comparison Harness

The comparison fixture uses one fixed MCP-style tool call. It proves only local artifact properties: Velvet Inline Gateway passes replayable-artifact, measured binding-depth, and drift-rejection checks for that fixture; the OAP/APort, Pipelock, Attested Intelligence, Cerbos, and gateway rows are local fixtures, not live product evaluations or competitor failure claims.

Standalone verification uses:

```bash
aab-validate comparison/results/*.json
python scripts/check_evidence_pointers.py
```

Maintainers regenerate comparison artifacts from the private Velvet monorepo at the recorded `commit_hash` and export them into `comparison/`.

## Limitations / Where Velvet Loses / When Not To Use This

- The seeded external guardrail adapters are not live provider evaluations unless their optional packages and credentials are present.
- Local algorithmic baselines are benchmark baselines, not claims about commercial competitors.
- ShadowPath uses synthetic local routes and does not assert that a named production vendor exposes those routes.
- Velvet does not win every seeded cost row. The results table reports rows where `human_review_queue` or `myopic_delight_gate` matches or beats Velvet on benchmark liability cost, while lacking Velvet's certificate/seal evidence.
- Max-DE certificate rows apply to posterior-typed Bernoulli decisions. Do not use those rows as evidence for arbitrary runtime actions.
- Do not use this benchmark as a production compliance claim, a benchmark-dominance claim, or a claim that any system solves agent safety.

## Citation

Use [`CITATION.cff`](CITATION.cff) when citing the benchmark package.
