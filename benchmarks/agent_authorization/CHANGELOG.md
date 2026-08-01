# Changelog

## 0.4.0 - 2026-07-28

- Added ShadowPath, a hermetic effect-level authorization suite in which the
  protected `customer.disable` tool is denied while the same synthetic effect
  remains reachable through browser, API, database, queue, webhook, admin,
  delegation, and human-operator paths.
- Added `route_authorization`, `effect_prevention`, `effect_inventory`, and
  `effect_reconciliation` capability cells. The committed route-only baseline
  reports `CONTROL_FALSE_SUCCESS` and exits nonzero unless
  `--expect-breach` is explicit.
- Added independent final-state reconciliation, `UNATTRIBUTED_EFFECT`
  detection, strict effect-inventory validation, a provider-neutral interactive
  JSONL agent protocol, and an optional OpenAI Agents SDK reference adapter.
- Bumped results, submission, and leaderboard schemas to v0.3.

## 0.3.0 - 2026-07-10

- Added four certified-decision capability cells: `certificate_expiry`,
  `fleet_false_lockout_accounting`, `refusal_as_output`, and
  `priced_inspection`, measured by a dedicated probe adapter
  (`velvet_verdict_measurements.json`). Systems without a probe adapter are
  reported `not_measured` with a reason, never `fail`; the submission protocol
  accepts self-measured cells with evidence.
- Bumped the results and submission schemas to
  `velvet.agent_authorization.results.v0.2` and
  `velvet.agent_authorization.submission.v0.2` (nine required capability
  keys).
- Corrected external prior-art citations in the spec and scoped the
  PolicyGuard pass^k reference to document-compliance policy review.

## 0.2.1 - 2026-07-02

- Fixed standalone evidence pointers so exported JSON and Markdown resolve from the repository root.
- Added clean-worktree release gating, private-monorepo commit provenance, and source lockfile notes.
- Replaced monorepo-only reproduction instructions with standalone verification and maintainer regeneration tiers.
- Shipped the full Apache-2.0 license text.
- Added exported pytest coverage, CI test execution, evidence-pointer validation, and certificate verification.
- Deduplicated README relationship language and normalized public GitHub URLs to `velvet-project`.
- Documented the decision-certificate verification byte construction and added `aab-verify-cert`.
- Added a sample assurance verifier bundle with pass and tamper-fail cases.
- Clarified security reporting, export manifest purpose, validation shim behavior, and stale-path CI checks.

## 0.2.0 - 2026-07-01

- Initial standalone Agent Authorization Benchmark export with seeded leaderboard rows, comparison fixtures, validator, verifier, and committed evidence artifacts.
