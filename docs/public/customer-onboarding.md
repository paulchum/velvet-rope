# Customer onboarding and acceptance

Use this with the [pilot scope](pilot.md). It is a practical checklist, not a signed agreement,
security certification, or authorization to operate on an unspecified system.

## Before accepting a pilot

- [ ] Name the customer engineering owner and scope approver.
- [ ] Write one protected outcome and two or three precise constraints, including allowed actions.
- [ ] Agree the route inventory, expected observer, reset procedure, and adapter feasibility.
- [ ] Restrict the work to the customer's authorized staging environment or a hermetic fixture.
- [ ] Agree price, deliverables, exclusions, acceptance, schedule, and payment terms in writing.
- [ ] Confirm any customer-specific procurement or data obligations before receiving access.

## Before running anything

- [ ] Pin the reviewed source revision, dependency versions, policy, and adapter configuration.
- [ ] Verify installation on the customer's target environment; record actual commands and prerequisites.
- [ ] Use synthetic records and narrow test credentials; do not request production balances or records.
- [ ] Name the owner of every credential, executor permission, observer role, and signing key.
- [ ] Never use committed demo keys as trusted signing keys for customer evidence.
- [ ] Pin observer public keys through a separate trusted channel; do not trust a bundle solely because its included keys agree.
- [ ] Confirm allowed targets, boundaries, rate limits, stop conditions, and the reset/cleanup procedure.
- [ ] Agree artifact storage, access, redaction, retention, deletion, and access-removal steps.

## Baseline and retest

Record the route, attempted action, dispatch evidence, independent state observation, and
result for each agreed trial. Keep useful allowed-action controls. Missing observations,
unknown routes, timeouts, and unresolved outcomes must not silently become successful prevention.

A signed decision record and an independently observed business effect answer different questions.
Use the applicable implementation's documented semantics and exit codes rather than rewriting
its results into a more flattering status.

## Acceptance handoff

- [ ] Deliver the route/observer inventory, pinned configuration, JSON, and readable report.
- [ ] Explain precisely what the observations establish and where they are inconclusive.
- [ ] Deliver the prioritized remediation plan and one agreed retest.
- [ ] Have the customer's engineer rerun the project without undocumented operator steps.
- [ ] Record integration effort, rerun friction, remaining gaps, and the customer's next decision.
- [ ] Remove temporary access and handle retained artifacts according to the written scope.
- [ ] Decide separately whether to buy maintained coverage or another integration; no automatic renewal.

## Before any later production deployment

A staging pilot is not a production go-live approval. Review the specific integration's route
coverage, executor privileges, observer trust, key management, lifecycle and replay semantics,
concurrency, recovery from unresolved commits, monitoring, rollback, and operational ownership.
Unimplemented controls must remain explicit. Seek any independent review the use case requires.

## Public communication

No customer name, logo, environment identifier, result, screenshot, or quote is published without
specific permission. Private third-party disclosures stay private until publication is cleared.
Report vulnerabilities through the [private security channel](../../SECURITY.md).
