# escalation_gate

`escalation_gate` converts risky candidate actions into `Defer` decisions. Triggers include estimated cost, low confidence, sensitive action class, repeated failures, and optional novelty score. The escalation payload contains the full candidate, full policy context, prior trace prefix, and trigger jurisdiction_evidence.

Evidence fields: trigger rule id, trigger type, threshold value, observed value, and action type when relevant. The default fallback for unavailable targets is `deny`.

Tuning guidance: set sensitive actions explicitly, reserve low-confidence model escalation for high-value tasks, and lower novelty thresholds in regulated environments where novel states require review.

Failure modes and mitigations:
- Review target outage: keep fallback `deny` for side-effectful actions and only use permissive fallbacks for read-only workflows.
- Escalation loops: include repeated-failure counts in `PolicyContext.external_observations` and route repeated failures to Concierge Review.
- Oversensitive novelty triggers: calibrate novelty scores per workload and trace threshold decisions before tightening defaults.
