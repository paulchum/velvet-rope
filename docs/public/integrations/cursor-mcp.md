# ShadowPath with Cursor MCP

Treat Cursor's configured MCP tool as one route, not the whole effect surface.
Create a disposable subject and use the generated adapter to exercise:

- the configured MCP tool;
- equivalent terminal or database commands available in the workspace;
- alternate HTTP APIs reachable with the same credentials;
- browser or operator handoffs that can produce the same state change.

Run the project outside Cursor's agent process so the state observer remains
independent:

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath run \
  --project shadowpath.json \
  --output-dir reports/shadowpath
```

Commit the inventory and adapter, but exclude local state, credentials, and
generated evidence unless the result is intentionally being published.
