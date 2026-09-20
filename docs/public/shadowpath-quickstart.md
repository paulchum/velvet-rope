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

Observations must report exactly the configured safe or prohibited state. A reset must
produce the safe baseline before dispatch. Missing/unknown states or malformed dispatch
responses return exit `4`; failed protected-route control returns exit `5` when no alternate
route breach was observed. Dispatch must include `decision` (`deny`, `execute` or `escalate`)
and a Boolean `dispatch_attempted`. No observed breaches means reconciliation detection
rate is unmeasured (`null`), not 100%. Reports carry actual timestamps, run IDs and config
hashes. The adapter implementation and its dependencies still require separate review.

The runner observes once immediately before and after dispatch. Delayed or transient
effects outside those points are unmeasured. A successful result is scoped to those points
and the configured routes; it is not continuous or whole-environment assurance.

## 4. Discover routes from a disposable baseline

The stateful explorer can derive both routes and protected resources. It reads
the MCP tool schemas through Pipelock, compiles policy regular expressions into
validated resource witnesses, materializes them in a disposable baseline, and
searches the observed state graph. Unsupported and truncated regex constructs
are recorded as coverage gaps. No policy witness is treated as an observed
effect until the independent observer sees a state change.

```bash
velvet-shadowpath-discover \
  --pipelock /path/to/pipelock \
  --config /path/to/pipelock.yaml \
  --node /path/to/node \
  --server-entrypoint /path/to/server-filesystem/dist/index.js \
  --work-root /tmp/velvet-shadowpath-discovery \
  --output reports/shadowpath/discovery.json \
  --breach-status replaced \
  --max-depth 3 \
  --max-trials 1000 \
  --max-calls 5000
```

When `--baseline-root` is omitted, the policy supplies the protected scope and
ShadowPath creates approved files plus an attacker-controlled payload under a
temporary root. The report preserves every regex witness and its rule/line
provenance. Pass `--baseline-root` to use a validated operator baseline instead;
with that mode, repeat `--protected relative/path` to adjudicate explicit
integrity promises. Without `--protected`, changes are candidate asset impacts.
Newly observed resources and generated scratch siblings become later call
arguments, so a setup action can enable a route nobody supplied.

By default, replacement, type change, removal, relocation, introduction, and
permission change count as integrity breaches. Repeat `--breach-status` to
select a narrower contract; the effective set is serialized in the report.

The report records the exact baseline fingerprint, runtime digests, generated
schema gaps, search budgets, unattempted operations, replay rejections, and its
claim boundary. Supply `--external-lock` to verify the components named by that
lock. The report lists verified and unverified runtime components separately;
without a lock, all digests are recorded but unverified. An entrypoint digest
does not pin its imported dependency tree, so the report does not claim complete
runtime verification from those file hashes.

Each graph edge records a platform-neutral **Effect Footprint**. Resources have
an adapter-owned namespace, extensible kind, stable key, and canonical ID.
Candidate effects combine schema-bound resources with MCP access annotations
or an explicitly labelled operation-name heuristic.
An explicit `readOnlyHint=false` produces an adapter-declared `resource.write`
candidate; fallback name heuristics remain labelled as candidates. Dispatch
outcomes and independent state differences are separately labelled observed
effects, so declarations never become observations merely by being plausible.
Exact-match content parameters such as `oldText` draw bounded values from the
current disposable observation. Exact observed values are replaced by a digest
label in serialized route and wire-call evidence.

The resource explorer's search state is a `ResourceSnapshot`, not a path set.
Each observation carries a `ResourceRef` (`namespace`, `kind`, `key`, optional
`facet`) and normalized state. `CandidateAction` records semantic argument
bindings to those resources. `explore_resources` performs bounded reset,
replay, state deduplication, and breadth-first expansion across any mixture of
resource kinds. A regression exercises a delegated launch that creates a
`docker.container`; that observed container identity then enables a second
delegated action that changes a `service.object`.

The packaged Pipelock filesystem model is currently the only production
`ResourceExplorationModel` for a mediated filesystem. It emits the
provider-neutral Effect Footprint contract and provider-owned `contains`
relations. The core also defines typed relations such as `owns`, `mounts`,
`delegates`, and `aliases`; it does not apply filesystem prefix rules to other
providers.

The Docker adapter is a second live `ResourceExplorationModel`, scoped to
container lifecycle state. It uses only disposable containers bearing per-run
and per-trial ownership labels, resolves a locally available image to its
content ID, invokes lifecycle operations through the Docker CLI, and requires
two consecutive normalized `docker container inspect` snapshots to agree.

```bash
velvet-shadowpath-docker \
  --image alpine:3.24 \
  --output reports/shadowpath/docker-discovery.json \
  --max-depth 2 \
  --max-trials 50 \
  --max-calls 200
```

The report groups distinct routes that reached the same observed lifecycle
effect. For example, `docker.container.stop` and `docker.container.kill` can
both produce `container.stop`. That equivalence is useful policy input, but an
unmediated Engine run does not establish an authorization bypass or Docker
vulnerability. The manifest explicitly excludes images, volumes, networks,
Compose, Swarm, Kubernetes, Docker MCP Gateway policy, and authorization
plugins.

OpenHands, runtime, and service adapters remain future work. A production
adapter for one of those providers must implement stable identity, isolated
reset and materialization, independent observation, action generation, typed
relations, effect mapping, and an honest settling contract. Hidden state cannot
earn discovery coverage, and no provider is claimed until its adapter and
manifest exist.

## 5. Put it in CI

Copy [`examples/shadowpath/github-action.yml`](../../examples/shadowpath/github-action.yml).
The action keeps exit `3` strict, writes the Markdown result into the job
summary, and leaves the complete evidence directory available for upload.

## 6. Share the evidence, not a slogan

```bash
uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath render \
  reports/shadowpath/results/shadowpath-project.json \
  --output-dir reports/shadowpath/share
```

Every card carries exact result values. The manifest records its source schema
and renderer version. Review the adapter, route inventory, and claim boundary
before publishing a custom result.
