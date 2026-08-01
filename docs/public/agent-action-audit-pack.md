# Agent Action Audit Pack

Route: `/agent-action-audit-pack`

## Hero

Logs answer what happened. Warrants answer why an agent action was allowed to
happen.

The Agent Action Audit Pack is a bounded pilot for security, GRC, and internal
audit teams reviewing agent workflows with tool calls, model escalation, memory
writes, code execution, or external side effects.

## What The Pilot Produces

- A scoped workflow inventory.
- Typed consequential-action records.
- Velvet warrants for allow/block/escalate decisions.
- Replay seals tied to thread and ledger records.
- A summary of policy denials, escalations, approvals, and replay outcomes.
- Claim-boundary notes suitable for internal review.

## Best Fit

Use this pilot when:

- an agent pilot touches internal tools, customer data, money, messages, code,
  memory, or production workflows;
- security can inspect logs but cannot prove pre-execution authorization;
- audit or compliance teams need compact evidence without re-running external
  providers;
- the team accepts a local-first pilot instead of a hosted shared-tenant claim.

## 21-30 Day Pilot Shape

1. Pick one bounded agent workflow.
2. Identify consequential action classes.
3. Route representative actions through Velvet.
4. Capture warrants, seals, ledger records, and approval receipts.
5. Review the final audit pack with platform, security, and risk owners.

## Success Criteria

- Every consequential action in scope has a typed warrant or explicit block.
- Policy reasons and jurisdiction evidence are inspectable by non-authors.
- Replay seals map back to thread records without re-running external providers.

## CTA

Scope one agent workflow and produce an audit pack that a security reviewer can
read in one sitting.
