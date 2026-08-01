# rate_limiter

`rate_limiter` enforces per-user rolling-window limits with independent aggregate and per-action limits. The shipped in-memory store is deterministic within a process. The Redis feature exposes a store type for deployments that want an external state adapter, but live store snapshots must still be traced by callers.

Evidence fields: action and aggregate snapshots with key, current time, window start, request count, and configured limit. Allowed decisions record snapshots as a no-op mutation so replay has the state used by the limiter.

Tuning guidance: use a short window for bursty tools, a longer aggregate window for cost containment, and reduce `burst_multiplier` to 1.0 for dangerous actions.

Failure modes and mitigations:
- Hidden store state breaks replay: feed store snapshots through trace-aware contexts for replay, or use deterministic in-memory state in tests.
- Shared anonymous users collide: always set `PolicyContext.user_id` in production.
- Thundering herd after resets: windows are rolling from decision time, never midnight-aligned.

