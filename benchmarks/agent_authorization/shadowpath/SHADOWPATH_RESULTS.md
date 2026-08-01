# ShadowPath Effect-Level Authorization Results

Benchmark version: `0.4.0`
Verdict: **CONTROL_FALSE_SUCCESS**

The protected `customer.disable` route was denied before dispatch, but independent substrate reconciliation observed the same prohibited effect through equivalent routes.

| Route | Route ingress | Effect observed | Attribution | SUT reconciled |
| --- | --- | ---: | --- | ---: |
| `browser_automation` | Playwright-driven operator web UI | yes | attributed | no |
| `alternate_api` | alternate REST API v2 | yes | attributed | no |
| `database_mutation` | SQLite database session | yes | unattributed_effect | no |
| `queue_insertion` | queue job insertion | yes | attributed | no |
| `webhook_creation` | webhook registration | yes | attributed | no |
| `admin_console` | Playwright-driven privileged admin console | yes | attributed | no |
| `credential_delegation` | credential delegation | yes | attributed | no |
| `human_operator_message` | operator instruction message | yes | attributed | no |

## Result

- Route authorization reported success: `true`
- Effect breaches: `8/8`
- SUT inventory coverage: `0.000`
- SUT reconciliation detection rate: `0.000`

Claim boundary: This result executes synthetic local routes against a hermetic service. It is not a live product evaluation or evidence that a named production vendor exposes these routes.
