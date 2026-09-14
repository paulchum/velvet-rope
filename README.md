# Velvet

[![CI](https://img.shields.io/github/actions/workflow/status/paulchum/velvet-rope/ci.yml?branch=main&style=flat-square&label=tests)](https://github.com/paulchum/velvet-rope/actions/workflows/ci.yml)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-7c3aed?style=flat-square)](LICENSE)

## Outcome assurance for autonomous agents

**Your agent passed policy. What happened next?**

Velvet tests whether agent controls prevent the business outcome, not just one tool call.
It assesses declared routes, gates supported execution paths, and preserves evidence your
team can verify independently of the agent's own account.

Today this is **local, self-hosted software and assisted evaluations**, not a hosted service.

[Website](https://shadowpath.coriolislabs.ca/) ·
[Scope a paid pilot](https://shadowpath.coriolislabs.ca/pilot/) ·
[Evidence and boundaries](docs/public/claims-evidence.md) ·
[Investor brief](docs/public/investor-brief.md) ·
[Contact Paul](mailto:paulchum1@gmail.com)

## Start here

| You are evaluating | Start with |
| --- | --- |
| A customer workflow | [Paid pilot scope](docs/public/pilot.md) and [customer onboarding](docs/public/customer-onboarding.md) |
| The engineering | [Quickstart](docs/public/shadowpath-quickstart.md), [technical overview](TECHNICAL_OVERVIEW.md), and [implementation status](IMPLEMENTATION_STATUS.md) |
| The evidence | [Claims register](docs/public/claims-evidence.md), [recorded replay](https://shadowpath.coriolislabs.ca/replay/), and [protected-refund contract](docs/public/protected-refunds.md) |
| A pre-seed conversation | [Investor memo](docs/public/investor-brief.md): implemented surfaces, product thesis, and validation milestones |
| A security concern | [Security policy](SECURITY.md) and [private reporting](https://github.com/paulchum/velvet-rope/security/advisories/new), not a public issue |

## Three connected jobs

| Component | What it does | Boundary |
| --- | --- | --- |
| **ShadowPath** | Run isolated trials across declared routes to a prohibited state change and reconcile the state. | Does not infer safety for unknown or undeclared paths. |
| **Velvet Gateway** | Admit, block, or escalate supported typed actions before dispatch; bind permits to exact requests and authorization context. | Does not control execution paths outside the integration. |
| **Velvet Vault** | Preserve tamper-evident records and portable verification artifacts. | An authentic receipt is not itself proof of an external business effect. |

The [protected-refund reference](docs/public/protected-refunds.md) combines exact-command
authorization, order limits, shared budget, operation identity, and journal evidence in one
PostgreSQL transaction. Its claim is bounded to that ledger. External payment settlement,
privileged out-of-band writes, and independent operation of the whole system are not implied.

## Inspect a recorded result

[Open the browser replay](https://shadowpath.coriolislabs.ca/replay/) without installing anything.
It visualizes the committed synthetic fixture; it is not a fresh test or a vendor evaluation.

To replay from a reviewed source revision, with `uv` and the source-build prerequisites available:

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git@7e15bc954d70654d008385ca8684902c0ed72ce5 velvet-rope shadowpath demo
```

This pins the reviewed evaluation code with the launch dependency repairs. Public evidence pages
retain their original source provenance. Review changes before choosing a newer revision.
The replay writes artifacts under `reports/shadowpath/`; it is not presented as fresh measurement.

For a fresh **local synthetic fixture**, use the [source quickstart](docs/public/shadowpath-quickstart.md).
Use only owned or explicitly authorized isolated environments. No production records, balances,
or third-party credentials belong in this first evaluation.

## Evaluate your own workflow

The starting [Outcome Assurance Pilot](docs/public/pilot.md) is one staging workflow and two
or three explicit business constraints. The indicative starting price is **C$7,500**, with
scope, schedule, applicable taxes, and payment terms agreed before work begins.

The deliverable is a customer-owned effect project, explicit route/observer inventory,
readable and machine-readable evidence, a prioritized remediation plan, one agreed retest,
and an engineer-led rerun. A clean result can be useful; vulnerability discovery is not promised.

Ongoing regression coverage and supported enforcement are separately scoped. There is no
automatic renewal or claim of an already operating hosted service.

## Trust and evidence discipline

The public synthetic fixture's `CONTROL_FALSE_SUCCESS` verdict describes its local workload,
not a named vendor or market prevalence. The reference refund evidence uses synthetic orders
in one PostgreSQL database. Do not combine these into a universal prevention claim.

Results depend on the declared routes, adapter correctness, trustworthy observation, independently
pinned keys, executor permissions, and the reviewed deployment. Missing coverage and inconclusive
observations must remain visible. Private disclosures and customer artifacts stay out of public PRs.

See [trust and data handling](https://shadowpath.coriolislabs.ca/trust/),
[the claims register](docs/public/claims-evidence.md),
[public claims policy](docs/liability/VELVET_ROPE_PUBLIC_CLAIMS_POLICY.md), and
[implementation status](IMPLEMENTATION_STATUS.md).

## Development and contribution

```bash
git clone https://github.com/paulchum/velvet-rope.git
cd velvet-rope
uv sync --locked --dev
uv run ruff check .
uv run mypy src tests
uv run pytest
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Some fixture tests require additional browser, container, or database setup; follow the relevant
guide and CI configuration. These commands are not a claim that all prerequisites are preinstalled.

The marketing site is an independent Astro application:

```bash
cd site
npm ci
npm test
npm run deploy:dry-run
```

Use a Node version satisfying `site/package.json`. Production deployment uses the existing
Cloudflare configuration and requires separately authorized credentials; a source commit is
not evidence that the domain has been deployed. Follow the [launch operations runbook](docs/public/launch-operations.md)
for the main-branch deployment workflow, scoped authorization, and public-revision verification.

Start with [CONTRIBUTING.md](CONTRIBUTING.md) or the
[effect-path contribution guide](docs/public/SHADOWPATH_CONTRIBUTING.md).
The prior detailed repository overview is preserved at [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

Apache-2.0. Maintained by Paul Chumbe at Coriolis Labs.
