# Velvet Outcome Assurance Pilot

A paid, assisted evaluation of one consequential staging workflow. The goal is a bounded,
independently observed baseline and a customer-owned project an engineer can rerun.

**Indicative starting price: C$7,500.** Final scope, applicable taxes, payment terms, and
schedule are agreed in writing before work begins. The planning target is 10 business days
after prerequisites are met, not a service-level commitment or guaranteed availability.

[Discuss a workflow](https://shadowpath.coriolislabs.ca/contact/?intent=pilot) or email
[Paul Chumbe](mailto:paulchum1@gmail.com).

## Starting scope

One customer-owned staging workflow, two or three explicit business constraints, an agreed
route inventory, one baseline, and one agreed remediation retest. Examples include a refund
limit, an account-state change, or authority that must expire after cancellation. Adapter and
observer feasibility are established during scoping, not assumed from a marketing example.

This is not a broad platform rollout or a promise to discover a vulnerability. A clean result
is useful when the covered routes, useful allowed controls, and independent observations are clear.

## Pilot loop

1. **Define the effect.** Specify safe and prohibited states, owner, acceptance criteria,
   authorized environment, routes, and a state observer independent of the agent's explanation.
2. **Establish the baseline.** Reset the fixture, exercise the agreed isolated trials, observe
   the resulting state, and retain route evidence. Mark absent coverage and inconclusive results.
3. **Remediate and retest.** Rank observed gaps and perform one agreed remediation retest.
   Implementation beyond the written scope is separately estimated.
4. **Hand over and rerun.** The customer's engineer runs the project and receives limitations,
   evidence, a remediation backlog, and CI handoff instructions.

## Deliverables

- One customer-owned ShadowPath effect project and explicit route/observer inventory.
- Machine-readable baseline and readable report with configuration and source provenance.
- Useful allowed-action controls as well as prohibited-action checks.
- Prioritized remediation plan and one agreed retest.
- Rerun instructions, an engineer-led handoff, and the next coverage decision.

## Required customer inputs

An engineering owner for the business workflow and a person authorized to approve testing;
these may be the same person. A customer-controlled isolated environment or representative
hermetic fixture, synthetic data, scoped test credentials, a reset procedure, and an agreed
independent observation method are required. Read-only observation is preferred.

Agree artifact location, authorized access, redaction, retention, deletion, and credential
revocation before sharing data. Never send secrets through the website or a public issue.
Use the [onboarding checklist](customer-onboarding.md) during scoping.

## Success criteria

The customer's engineer can state the protected outcome, enumerate the tested routes,
distinguish observed effects from prevented effects and inconclusive trials, identify the
observer, and rerun the project after a relevant change. A report explicitly identifies
uncovered routes and what its evidence does not establish.

## After the pilot

Choose whether to maintain checks for future releases, add another workflow, or integrate
supported enforcement. Assessment does not require replacing the existing gateway. Inline
enforcement requires a supported integration and is not silently included for every route.
Ongoing coverage is separately scoped; no automatic subscription or renewal is created.

## Out of scope

Production experimentation, unrestricted third-party testing, guaranteed discovery, broad
penetration testing, production rollout, certification, insurance decisions, and round-the-clock
incident response are outside the starting offer. No claim is made for undeclared routes.

Velvet currently provides local, self-hosted code and evidence artifacts. Read the
[claims register](claims-evidence.md) and [trust boundaries](https://shadowpath.coriolislabs.ca/trust/).
