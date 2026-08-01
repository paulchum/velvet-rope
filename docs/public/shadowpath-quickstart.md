# Test Your First Effect in 15 Minutes

ShadowPath asks whether blocking a named tool also prevented the business
outcome through every equivalent route. Its observer is deliberately separate
from the route control being tested.

## 1. See the result immediately

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath demo
```

This replays the committed hermetic fixture and generates exact SVG, PNG,
Markdown, HTML, and badge artifacts under `reports/shadowpath/share/`. It does
not present a replay as a fresh measurement.

To execute the Playwright-backed fixture from source instead:

```bash
git clone https://github.com/paulchum/velvet-rope.git
cd velvet-rope
uv sync --dev
uv run maturin develop
uv run playwright install chromium
uv run velvet shadowpath demo --execute
```

## 2. Scaffold your effect

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath init my-effect
cd my-effect
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath run \
  --project shadowpath.json \
  --output-dir reports/shadowpath
```

The starter deliberately fails: its protected route denies the request while
three equivalent paths still mutate the independently observed state. Exit `3`
means the prohibited effect was observed.

## 3. Connect your system

Edit `shadowpath.json` to name the effect, safe state, prohibited state, and
known equivalent routes. Replace four operations in `adapter.py`:

- `reset`: restore an isolated test subject;
- `observe`: read the substrate independently of the control;
- `dispatch`: exercise the requested route;
- protected `dispatch`: return the control's decision and whether dispatch was
  attempted.

The adapter reads one JSON request from stdin and writes one JSON object to
stdout. Keep credentials in the surrounding environment; never place them in
the project file or generated evidence.

## 4. Put it in CI

Copy [`examples/shadowpath/github-action.yml`](../../examples/shadowpath/github-action.yml).
The action keeps exit `3` strict, writes the Markdown result into the job
summary, and leaves the complete evidence directory available for upload.

## 5. Share the evidence, not a slogan

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath render \
  reports/shadowpath/results/shadowpath-project.json \
  --output-dir reports/shadowpath/share
```

Every card carries exact result values. The manifest records its source schema
and renderer version. Review the adapter, route inventory, and claim boundary
before publishing a custom result.
