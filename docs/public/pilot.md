# Velvet Outcome Assurance Pilot

The design-partner pilot starts with one consequential business outcome.
The goal is to leave with an executable effect inventory, an independently observed baseline, and a
prioritized control plan that the customer's team can rerun.

## Start with a scoping conversation

[Discuss your workflow](https://shadowpath.coriolislabs.ca/pilot/) or email
[paul@coriolislabs.ca](mailto:paul@coriolislabs.ca?subject=Velvet%20pilot%20inquiry).
Tell us what your agent can do, which business constraint must hold, and whether you have a test
environment and an engineering owner. A short description is enough to start; keep credentials,
customer records, and sensitive system details out of the inquiry.

We first discuss fit, then agree on one isolated workflow, the deliverables, timeline, and any fee
before work begins. Sending an inquiry does not book or purchase a pilot.

## First focus: agents that issue refunds

The initial offer is for agent and platform teams adding refund authority to support or payments
workflows. A useful first scope is an approved refund amount, an order limit, and a shared refund
budget. Test altered amounts, repeated deliveries, and concurrent requests against those constraints,
then reconcile the resulting state with an independent observer.

Velvet's [protected refund contract](protected-refunds.md) is a reproducible starting point. It
enforces the declared constraints in a single PostgreSQL reference ledger; it does not establish that
an external payment provider or your deployment is protected. The scoping conversation identifies
the actual system, routes, observers, and integration work needed for your workflow.

## A good first outcome

Choose a state change that is both valuable to automate and expensive to get wrong, for example:

- releasing a payment above a defined threshold;
- issuing a refund beyond its approved amount or shared budget;
- disabling a customer or employee account;
- approving a production deployment;
- changing a regulated record;
- exporting a sensitive dataset.

The pilot should run against an isolated environment or a hermetic fixture. It should not experiment
on production customers, credentials, balances, or records.

## Pilot loop

### 1. Define the effect

Name the safe and prohibited substrate states precisely. Select an observer that is independent of the
agent and the control being tested.

### 2. Inventory equivalent routes

Map every reachable path to the same effect: canonical API, alternate API, browser or admin UI,
database, queue, webhook, delegated credential, scheduled job, and human-operator path where relevant.

### 3. Execute isolated trials

Reset the subject, observe the safe state, dispatch one route, and reconcile the substrate. Retain the
route evidence and exact adapter used for every trial.

### 4. Close and retest

Rank escaped paths by effect criticality and authority depth. Add or move enforcement to the relevant
substrate, rerun the same portfolio, and compare the machine-readable results.

## Deliverables

- one user-owned ShadowPath effect project;
- an explicit route and observer inventory;
- a machine-readable baseline plus Markdown report;
- a portfolio manifest ready for the next protected outcome;
- a remediation backlog tied to observed paths;
- a rerun command suitable for CI or a controlled assurance job.

## Required customer inputs

- an engineering owner for the affected business system;
- a security or AI-platform owner for the agent control;
- an isolated test environment or a representative hermetic fixture;
- read access for an independent state observer;
- agreement on the prohibited effect and claim boundary.

## Success criteria

The pilot is useful when the customer can answer, with reviewable evidence:

1. What exact outcome are we protecting?
2. Which routes can reach it?
3. Which routes did the current control actually prevent?
4. Which independent observer confirmed the final state?
5. Can our team rerun the same test after a control or architecture change?

Velvet currently provides local, self-hosted code and evidence artifacts. A pilot is not a legal
compliance determination, audit signoff, insurance decision, or claim that undeclared routes are safe.
