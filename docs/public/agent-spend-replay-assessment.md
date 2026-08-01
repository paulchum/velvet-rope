# Agent Spend And Replay Assessment

Route: `/agent-spend-replay-assessment`

## Hero

Agent spend is not only a billing problem. It is an authority problem: which
actions deserved tool calls, model escalation, retrieval, memory writes, or
human review before they happened?

Velvet ties spend and risk decisions to typed action choices, admission trace
objective components, policy evidence, and replayable warrants.

## What The Assessment Answers

- Which action classes are driving spend or escalation?
- Which tool calls lacked enough evidence to execute automatically?
- Which actions were blocked, escalated, deferred, or skipped?
- Which cheaper routes could have satisfied the same policy boundary?
- Which budget or approval states should change before the second run?

## Input

Bring representative traces, candidate actions, or a bounded live workflow. The
assessment works best when the team can name the tools, MCP servers, model
routes, memory writes, or external-send actions in scope.

## Output

- Action-cost attribution by class.
- Entry-price and scarcity-pressure summaries.
- Denial and escalation rates.
- Replayable warrant samples.
- Policy recommendations for a second run.

## Success Criteria

- Leadership sees which action classes drive spend and risk.
- Platform owners can explain why selected actions deserved spend.
- The second run has fewer unjustified escalations or tool calls.

## CTA

Run a 14-21 day assessment over one workflow with unclear agent spend or tool
ROI.
