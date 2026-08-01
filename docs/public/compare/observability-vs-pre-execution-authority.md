# Observability Vs Pre-Execution Authority

Route: `/compare/observability-vs-pre-execution-authority`

## Hero

Observability shows what happened. Pre-execution authority decides whether the
action earned the right to happen.

Agent logs, traces, evals, and monitoring are necessary. They are not a
substitute for a warrant attached before a consequential action executes.

## Comparison

| Question | Observability | Pre-execution authority |
| --- | --- | --- |
| What does it inspect? | Events after or during execution | Proposed actions before execution |
| Primary artifact | Log, trace, span, dashboard | Warrant, seal, ledger record |
| Buyer pain | Debugging and incident review | Authorization, liability, audit readiness |
| Failure mode | You know what went wrong late | Unsafe action is blocked or escalated early |
| Velvet position | Integrates with evidence trails | Owns the admission boundary |

## Why This Matters For Agents

LLM agents can call tools, send messages, run code, write memory, retrieve data,
modify records, and spend money. A beautiful trace does not prove the action was
authorized. For consequential workflows, the control point has to sit before the
tool call.

## Category Language

Use this distinction consistently:

- Guardrails inspect or constrain behavior.
- Observability records behavior.
- Velvet admits, blocks, escalates, defers, or skips proposed actions before
  execution.

## CTA

If your agent stack already has logs, ask one more question: can it prove why a
specific tool call was allowed before it happened?
