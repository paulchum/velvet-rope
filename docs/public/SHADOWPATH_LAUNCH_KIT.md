# ShadowPath Launch Kit

ShadowPath tests whether blocking a named agent route also prevented the
prohibited outcome through every equivalent path. The launch claim is narrow:
the committed public result is a synthetic, local, hermetic fixture—not a live
vendor evaluation.

## Primary links

- [Interactive replay](https://shadowpath.coriolislabs.ca)
- [Repository](https://github.com/paulchum/velvet-rope)
- [Committed result](../../benchmarks/agent_authorization/shadowpath/SHADOWPATH_RESULTS.md)
- [15-minute custom-effect guide](shadowpath-quickstart.md)
- [Add an effect path](SHADOWPATH_CONTRIBUTING.md)

## Ready-to-use assets

All export copy and values are generated from the committed result. The
[`manifest.json`](assets/shadowpath/launch/manifest.json) records dimensions,
source schema, and renderer provenance.

- [`shadowpath-breach-loop.mp4`](assets/shadowpath/launch/shadowpath-breach-loop.mp4):
  six-second 1080×1920 route reveal for TikTok, Reels, and Shorts.
- [`shadowpath-breach-loop.gif`](assets/shadowpath/launch/shadowpath-breach-loop.gif):
  compact animated preview.
- [`shadowpath-card-x.png`](assets/shadowpath/launch/shadowpath-card-x.png):
  1600×900 launch card for X, Reddit, LinkedIn, and link posts.
- [`shadowpath-card-tiktok.png`](assets/shadowpath/launch/shadowpath-card-tiktok.png):
  1080×1920 static vertical result.
- [`shadowpath-carousel-01.png`](assets/shadowpath/launch/shadowpath-carousel-01.png)
  through [`shadowpath-carousel-05.png`](assets/shadowpath/launch/shadowpath-carousel-05.png):
  five-slide explanation and run CTA.
- [`shadowpath-badge.svg`](assets/shadowpath/launch/shadowpath-badge.svg):
  embeddable result badge.

Regenerate exact assets:

```bash
uv run velvet shadowpath render \
  benchmarks/agent_authorization/shadowpath/results/v0.4.0--shadowpath.json \
  --output-dir docs/public/assets/shadowpath/launch

uv run python scripts/build_shadowpath_launch_video.py \
  benchmarks/agent_authorization/shadowpath/results/v0.4.0--shadowpath.json \
  --output docs/public/assets/shadowpath/launch/shadowpath-breach-loop.mp4 \
  --gif docs/public/assets/shadowpath/launch/shadowpath-breach-loop.gif
```

## Launch copy

### Hacker News

Title:

> Show HN: ShadowPath – Did blocking the agent tool block the outcome?

Body:

> I built a hermetic test for a blind spot in agent authorization. The protected
> `customer.disable` tool is denied before dispatch, but the same synthetic
> outcome is still reachable through a browser, alternate API, database, queue,
> webhook, admin console, delegated credential, and human operator path.
>
> The committed fixture reports `CONTROL_FALSE_SUCCESS`: the route control
> worked, but independent state reconciliation observed the prohibited effect
> through 8/8 equivalent paths.
>
> This is deliberately not a vendor benchmark. It is a reproducible local
> fixture and a small adapter contract for testing your own effect surface.
>
> Live replay: https://shadowpath.coriolislabs.ca
>
> Source: https://github.com/paulchum/velvet-rope

### X launch thread

1. Your agent blocked the tool. Did it block the outcome?

   We denied `customer.disable` before dispatch. Then ShadowPath tried eight
   equivalent paths to the same synthetic effect.

2. Browser. Alternate API. Database. Queue. Webhook. Admin console. Delegated
   credential. Human operator.

   The customer still became disabled through 8/8 paths.

3. The verdict is `CONTROL_FALSE_SUCCESS`.

   The deny was real. The conclusion was false. Route authorization is not
   effect prevention.

4. The result is a hermetic fixture—not a named-vendor evaluation. Every path
   starts from fresh state, produces evidence, and ends at an independent
   substrate observer.

5. Replay it, inspect the JSON, then scaffold your own effect:

   `uvx --from git+https://github.com/paulchum/velvet-rope.git velvet-rope shadowpath demo`

   https://shadowpath.coriolislabs.ca

### Technical Reddit post

Title:

> I denied the destructive MCP tool, then reached the same effect through 8 other paths

Body:

> I have been working on a narrow authorization-testing problem: controls often
> watch a named tool or route, while agents can reach the same business effect
> through other authority surfaces.
>
> In the committed local fixture, `customer.disable` is denied before dispatch.
> The harness resets state and independently tests browser automation, an
> alternate API, direct database mutation, a queue, webhook creation, an admin
> console, delegated credentials, and a simulated human-operator message. The
> prohibited state change is observed after all eight.
>
> The useful part is not the synthetic 8/8 result; it is the project contract:
> define the prohibited state, list every equivalent route, reset an isolated
> subject, dispatch each route, and reconcile through an observer the control
> cannot rewrite.
>
> I would especially value skeptical feedback on missing route classes and on
> where independent reconciliation becomes unrealistic. Source and exact
> evidence: https://github.com/paulchum/velvet-rope

### TikTok/Reels voiceover

> Your AI agent tried to disable a customer. The protected tool was blocked.
> Success? Not quite. The same outcome was still reachable through a browser,
> another API, the database, a queue, a webhook, an admin console, delegated
> credentials, and a human operator. Eight paths tested. Eight breaches. We call
> that control false success. Blocking a route is not the same as preventing an
> outcome. ShadowPath is open source; replay the evidence and test your own
> effect.

On-screen caption:

> The tool was blocked. The outcome was not. Open-source replay in bio.

## Use rules

- Link awareness posts to the interactive replay, not directly to a star ask.
- Ask for a star only after the viewer sees or runs the result.
- Use one CTA per post: replay, inspect, run, or contribute.
- Do not imply that the fixture tested or defeated a named product.
- Do not call a replay a fresh measurement.
- Answer technical questions before linking back to the project.
