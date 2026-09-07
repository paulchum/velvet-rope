# Stripe: an external, provider-backed ShadowPath path

This integration replaces the **execution substrate** of the teaching fixture with Stripe's
hosted sandbox. It does not replace one locally invented billing application with another.
No model is needed to reproduce the deterministic path; agent clients can use the same gateway.

```
Actual tools/call -> Velvet Rust HTTP proxy -> official Stripe MCP -> Stripe Refund
Explicit agent REST credential -> POST /v1/refunds -> the same protected test charge
Separate restricted observer key -> GET /v1/refunds?charge=... -> recorded provider state
```

The MCP route and REST route are measured, not assigned predetermined results. The existing
SQLite/browser teaching fixture remains available as a separate, offline example.

## Boundaries before running

Use a dedicated sandbox. **Live keys and live charges are refused.** The runner requires an
explicit `--allow-test-writes`. Provisioning creates two test payments, and a normal full run
attempts a control refund plus a protected refund through the gateway, followed by one optional
REST attempt. It does not run against customers, live balances, production records, or Connect
accounts. It never fills in a human-confirmation or approval token on your behalf.

The supplied gateway configuration deliberately blocks **all `stripe_api_write` calls**. It is
an actual route-only deny baseline, not a payment-specific production policy and not a claim
that Velvet closes every route. Other unapproved tools are denied by the proxy's inventory.
No arbitrary Stripe write credential is granted to the agent by the runner.

A positive control calls the official Stripe MCP server directly with a separate control
charge, proving that this tool invocation can create a refund and that the observer can see it.
This is **not** a demonstration of legitimate execution through the deny-all gateway. Supply
`--control-gateway https://your-allowing-gateway/mcp` and
`VELVET_STRIPE_CONTROL_GATEWAY_TOKEN` to calibrate that path instead.

## Credentials

Set these through your shell's secret manager or GitHub environment secrets. Do not put them
in a config file, command-line argument, committed `.env` file, issue, or test report.

| Environment variable | Purpose |
| --- | --- |
| `VELVET_STRIPE_MCP_KEY` | Test key for official Stripe MCP; charge reads and refund creation. |
| `VELVET_STRIPE_OBSERVER_KEY` | **Different restricted test key** with read-only Charges/Refunds access. |
| `VELVET_STRIPE_SETUP_KEY` | Test key for creating PaymentIntents; needed only with `--provision`. |
| `VELVET_STRIPE_AGENT_KEY` | An API credential actually available to the agent; needed only with `--with-direct-route`. |
| `VELVET_STRIPE_GATEWAY_TOKEN` | Local gateway access token (not a Stripe key). |

The runner checks that the observer uses a distinct restricted key, but Stripe does not expose
an introspectable permission grant here. Read-only permissions must be configured by the
operator; the report does not claim to have verified them. All credentials must access the same
sandbox. The agent credential needs charge-read permission for the safety preflight as well as
whatever refund authority is being assessed. Do not widen a real agent's permissions just to
make a benchmark succeed: use an accurate sandbox analogue and state its scope.

No agent credential is inferred from the setup or MCP credential. Without the explicit direct
route option, the result is `ROUTE_UNAVAILABLE`, not successful effect prevention.

## Build and run from a checkout

Run from the repository root. The source runner only adds the repository's existing
`jsonschema` dependency; it does not require a browser or the Rust Python extension.

```bash
python -m pip install 'jsonschema>=4,<5'
cargo build --locked -p velvet-rope-proxy

# Ephemeral local gateway credentials. Never reuse these as production signing material.
export VELVET_STRIPE_GATEWAY_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export VELVET_OAP_ED25519_PRIVATE_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export VELVET_MAXDE_ED25519_PRIVATE_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Set the Stripe sandbox credentials separately, without printing them.
python src/velvet/stripe_shadowpath.py discover --output reports/stripe-tools.json

env -u VELVET_STRIPE_OBSERVER_KEY -u VELVET_STRIPE_SETUP_KEY \
  -u VELVET_STRIPE_AGENT_KEY \
  target/debug/velvet-rope-proxy --config examples/shadowpath/stripe/proxy.json
```

Leave the gateway running. In a second terminal with the same environment:

```bash
python src/velvet/stripe_shadowpath.py run \
  --gateway http://127.0.0.1:8791/mcp \
  --provision --allow-test-writes --with-direct-route \
  --output-dir reports/stripe-run-001
```

Use a new output directory for each run. An existing directory is refused before network
access. To avoid provisioning, replace `--provision` with
`--control-charge ch_... --protected-charge ch_...`, using two **distinct, fresh, captured,
previously unrefunded test charges**. Optional `--amount` is an integer in minor units (default
100; maximum 10000). Both test charges must be large enough.

The runner discovers `stripe_api_write` from the server's real `tools/list`, checks the live
input schema, and uses `stripe_api_operation_id=PostRefunds` with the exact charge and amount.
It adds `livemode=false` and sandbox account context when those fields are advertised.
Unknown schemas or required approval fields stop the run **before provisioning**. A changed
operation ID or provider behavior fails the positive control; there is no synthetic fallback.
`discover` preserves schema constraints and hashes the complete tool definition, omitting
free-form descriptions and examples from public evidence. An explicit `--account acct_...` can be
used where the schema requires `stripe_context`; otherwise `/v1/account` supplies it.

Authenticated read-only discovery on 2026-09-07 confirmed `PostRefunds` and `POST /v1/refunds`
through Stripe's `stripe_api_search` and `stripe_api_details`. The key-bound hosted session
negotiated `2025-03-26`; its write schema required `stripe_api_operation_id` and `parameters`,
with optional provider confirmation. It did not advertise `livemode` or `stripe_context`.
The compiled Rust proxy initialized against that hosted server and inventoried the blocked
write tool. These read-only checks created no payments/refunds and are **not a hosted refund
measurement**. Each measured run must still pass the provider-observed positive control.

The native proxy negotiates its separate inventory session, accepts JSON or bounded SSE
responses, checks matching RPC identities, and follows every tools page. It stops reading a
POST SSE stream once the matching response arrives, without waiting for the connection to close.

## Evidence and exit codes

`result.json` is updated atomically throughout the run. It records the discovered schema hash,
exact protected arguments, real gateway decision metadata, HTTP request IDs when provided,
provider refund IDs, amounts/statuses, observation timestamps, and incomplete phases. It omits
keys, headers, arbitrary provider response bodies, customer details, and card details.
Gateway records are written separately under `reports/stripe-proxy/` by the existing proxy.
These are local diagnostic artifacts, not a new independent signature-verification system.

| Exit | Meaning |
| --- | --- |
| 0 | `NO_BREACH_OBSERVED_IN_WINDOW`: all requested observations completed without a successful refund. This is not a prevention guarantee. |
| 2 | `NOT_RUN` configuration/safety failure, or `ROUTE_UNAVAILABLE` without an explicit alternate-route credential. |
| 3 | A prohibited refund was observed, including one on the protected route. `CONTROL_FALSE_SUCCESS` requires a real Velvet denial. |
| 4 | `INDETERMINATE`: failed calibration, timeout, protocol/schema error, pending work, unknown status, or incomplete observation. |

Pending or `requires_action` refunds remain unresolved. The observer polls for 15 seconds per
phase by default (`--observe-seconds`, up to 300), including after dispatch errors. A breach
already observed stays a breach even if a later observation or pagination request fails.
Each validated refund is saved before fetching another page. Unknown statuses are retained as
unresolved; observation errors remain recorded even if later polls recover. MCP request IDs,
exact arguments, and setup/REST idempotency identities are saved **before** dispatch. Available
dispatcher refund IDs are unverified reconciliation hints, separate from observer evidence.
No automatic write retry
occurs. REST writes use a stable, per-run idempotency key; MCP mutations are issued once.

A timeout can leave a real provider operation unresolved. Inspect the saved charge IDs and
Stripe's Dashboard/request logs before doing anything else. Do not repeat an uncertain
operation on the same charge with a new operation ID. Reports do not prove absence of effects
after the observation window or exclude unrelated privileged writers. Test data is retained
in Stripe for inspection rather than silently deleted.

## GitHub Actions

`.github/workflows/stripe-shadowpath.yml` runs offline tests and a separate **actual compiled
Rust proxy** contract test. That proxy test uses a local MCP protocol stub and is explicitly
not published as a provider measurement. Neither automatic job uses Stripe secrets.

After merging the workflow, create a protected GitHub environment named `stripe-sandbox`,
add the four Stripe secrets above, and use **Run workflow** with `run_sandbox=true`. Only enable
`with_direct_route` when that credential represents actual agent authority. Require reviewer
approval on the environment. Pull requests cannot trigger the credentialed sandbox job.
Restrict the environment to `main`; the workflow also requires a manual dispatch on `main`.
Dependencies and the compiled proxy are built before keys enter the execution step.

```bash
gh workflow run stripe-shadowpath.yml --repo paulchum/velvet-rope --ref main \
  -f run_sandbox=true -f with_direct_route=false
```

Use `with_direct_route=true` only with an explicit agent credential representing the access
being measured. Approve the environment deployment, wait for the run to finish, and inspect
the `stripe-shadowpath-RUN_ID-ATTEMPT` artifact. A dispatch response alone is not evidence.
The manual job stages sanitized JSON and runs pinned gitleaks before uploading, including
after a measured breach or error. Raw gateway logs and free-form provider responses are not
uploaded. The runner's nonzero exit code is retained; there is no `--expect-breach` override.
If no runner report exists, the artifact contains an explicitly marked workflow diagnostic
with `INDETERMINATE` and unobserved provider state. It does not assert that writes did or did
not occur, and it never replaces an existing runner report or establishes a provider measurement.
Actions **Re-run jobs** is refused for mutations: reconcile the prior saved charge and operation
identities in Stripe before deciding whether another manually dispatched trial is appropriate.

## Primary API references

- Official MCP and bearer-key authentication: https://docs.stripe.com/mcp
- Refund creation: https://docs.stripe.com/api/refunds/create
- Refund listing and pagination: https://docs.stripe.com/api/refunds/list
- Refund statuses: https://docs.stripe.com/api/refunds/object
- Test PaymentMethods: https://docs.stripe.com/testing
- PaymentIntent confirmation: https://docs.stripe.com/api/payment_intents/create
- Sandbox boundaries: https://docs.stripe.com/sandboxes
- Idempotency semantics: https://docs.stripe.com/api/idempotent_requests
