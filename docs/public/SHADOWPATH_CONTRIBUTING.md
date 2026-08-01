# Add an Effect Path to ShadowPath

ShadowPath is useful when it finds routes the protected tool does not describe.
The best contribution is a small, reproducible path to the same prohibited
business effect.

## Good effect paths

A path should:

- reach the existing `customer.disable` effect through a meaningfully different
  ingress or authority boundary;
- run locally without paid credentials or external side effects;
- start from a fresh fixture state and leave evidence tied to its trial ID;
- be observable through independent substrate reconciliation;
- state whether the system under test could attribute the effect;
- avoid claims about vendors that were not actually tested.

Examples include a scheduled workflow, an import job, a second data plane, a
support escalation, or a credential handoff. Renaming an existing HTTP route is
not a new effect path.

## Where to change the code

1. Add the route to
   [`benchmarks/agent_authorization/shadowpath/fixtures/effect_inventory.json`](../../benchmarks/agent_authorization/shadowpath/fixtures/effect_inventory.json).
2. Implement the hermetic dispatch in
   [`src/velvet/shadowpath.py`](../../src/velvet/shadowpath.py).
3. Add route evidence and reconciliation assertions to
   [`tests/test_shadowpath.py`](../../tests/test_shadowpath.py).
4. Regenerate the result with a clean worktree before proposing a measured
   benchmark change.

## Verify it

```bash
uv sync --dev
uv run maturin develop
uv run playwright install chromium
uv run pytest tests/test_shadowpath.py -q
uv run velvet shadowpath run --output-dir /tmp/shadowpath-check --allow-dirty
```

The final command is expected to exit `3` when the fixture observes a prohibited
effect. During development, `--allow-dirty` marks that provenance honestly.
Publishable results must come from a clean commit without that flag.

## Pull request checklist

- [ ] The path is effect-equivalent, not just a renamed endpoint.
- [ ] The fixture is local, deterministic, and safe.
- [ ] Evidence is correlated to a unique trial.
- [ ] Reconciliation observes the substrate independently.
- [ ] Tests cover dispatch, effect observation, attribution, and cleanup.
- [ ] Documentation describes the boundary without naming untested products.

If you are unsure whether a route is distinct enough, open an issue with a
two-sentence sketch. Skeptical edge cases are welcome.
