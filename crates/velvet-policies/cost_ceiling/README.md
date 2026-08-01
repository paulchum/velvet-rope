# cost_ceiling

`cost_ceiling` is a soft estimate policy. It estimates per-action spend in canonical USD and compares projected spend against independent task, user, and organization ledgers from `PolicyContext`. It prefers provider-normalized `usd_estimate`; configured token, call, and volume models are fallback estimates only. Deterministic no-overspend claims require a separate deterministic budget certificate.

Evidence fields: `scope`, `usd_estimate`, `spent_usd`, `projected_spent_usd`, and `limit_usd`. Soft ceilings emit a warning mutation; hard ceilings deny the action.

Tuning guidance: set task limits low enough to catch loops, user limits high enough for normal sessions, and organization limits for incident containment. Keep `soft_ceiling_fraction` below 0.8 for regulated workloads where review should start early.

Failure modes and mitigations:
- Underestimated provider cost: enforce `CostObserver` reporting in integrations and treat missing realized cost as fail-closed for certified admissions.
- Overly broad org ceilings: combine org ceilings with per-user ceilings to avoid one active user starving others.
- Unit drift from providers: consume only normalized `usd_estimate`; do not feed native token or credit units directly into ledgers.
