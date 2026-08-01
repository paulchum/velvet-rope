# ShadowPath with Claude Code or Codex-style MCP Workflows

Use ShadowPath outside the agent process. The adapter should reset a disposable
test subject, invoke the same MCP or shell-visible route the agent can reach,
and then query the backing system directly.

Start with:

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath init agent-effect-test
```

In `adapter.py`, keep `dispatch` and `observe` separate. For example, dispatch
may ask an MCP client to call `customer.disable`, while observe reads the test
database or service state through a read-only administrative identity. Add
browser, shell, alternate API, queue, webhook, delegated credential, and human
handoff paths when those capabilities are visible to the agent.

Do not place the reconciliation credential in the agent's MCP configuration.
If the agent can modify its own oracle, the test no longer establishes an
independent effect observation.
