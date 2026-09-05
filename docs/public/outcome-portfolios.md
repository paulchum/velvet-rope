# ShadowPath Outcome Portfolios

One ShadowPath project tests one prohibited business effect. An outcome portfolio groups many
projects into one conservative estate-level report: which outcomes were tested, how many equivalent
routes were exercised, where the effect still occurred, and who owns the control.

This is a local orchestration and reporting surface. It does not discover undeclared outcomes or
routes automatically, and it does not turn incomplete effect inventories into assurance claims.

## Portfolio manifest

Create `shadowpath-portfolio.json` next to the effect projects it references:

```json
{
  "schema_version": "velvet.shadowpath.portfolio.v0.1",
  "name": "Production agent outcomes",
  "effects": [
    {
      "id": "customer-lockout",
      "name": "Customer account lockout",
      "criticality": "critical",
      "owner": "Identity platform",
      "project": "effects/customer-lockout/shadowpath.json"
    },
    {
      "id": "payment-release",
      "name": "Payment release",
      "criticality": "high",
      "owner": "Payments platform",
      "project": "effects/payment-release/shadowpath.json"
    }
  ]
}
```

Each referenced project uses the existing
[`velvet.shadowpath.project.v0.1`](shadowpath-quickstart.md) adapter contract. Paths are resolved
relative to the portfolio manifest.

## Run the portfolio

```bash
uv run velvet shadowpath portfolio \
  --manifest shadowpath-portfolio.json \
  --output-dir reports/outcome-portfolio
```

The command writes:

- `results/shadowpath-portfolio.json`: machine-readable aggregate result;
- `SHADOWPATH_PORTFOLIO.md`: executive-readable outcome table;
- `effects/<effect-id>/`: the underlying result and report for every effect.

Exit codes stay conservative:

| Exit | Meaning |
| ---: | --- |
| `0` | Every declared effect project completed without an observed breach. |
| `2` | The portfolio or a referenced project was invalid. |
| `3` | At least one equivalent route reached a prohibited effect, or a protected route control failed. |
| `4` | At least one configured adapter failed to execute. |

Use `--expect-breach` only for a fixture whose breach is deliberate. It changes the process exit for
that invocation; it does not change the recorded verdict.

## Aggregate statuses

`ASSURED` means all declared effect projects completed with `EFFECT_PREVENTED` during this run.
`DEGRADED` means a medium- or low-criticality effect breach was observed. `ACTION_REQUIRED` means a
critical or high-criticality breach, route-control failure, invalid project, or adapter error was
present.

Every status is bounded by the manifest. A green portfolio says nothing about an effect or route the
owner did not declare, an observer that can be rewritten by the system under test, or a control that
changed after the run.
