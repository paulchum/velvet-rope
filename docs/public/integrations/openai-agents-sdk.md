# ShadowPath with the OpenAI Agents SDK

The repository includes an optional JSONL reference adapter for the live-agent
benchmark track. For an application-specific effect test, begin with the public
project contract instead:

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath init agents-sdk-effect-test
```

Wire `dispatch` to a fresh SDK run that exposes exactly the route under test.
Wire `observe` to a separate, read-only substrate query. Reset the subject for
every trial and correlate SDK traces, tool dispatch evidence, and observed
state with the supplied `trial_id`.

Never interpret a model refusal or a successful tool-deny response as effect
prevention. The effect is prevented only when the independent observer still
reports the safe state after every equivalent route has been exercised.
