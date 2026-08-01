# Five-Minute Live Demo Script

Audience: underwriter, design partner, or VC associate.

## Setup

Run:

```sh
make live-demo
```

The target runtime starts a Docker Postgres container, seeds realistic customers/orders/refund budget data, builds the real Rust MCP proxy, runs the five attacks, packages the argument-drift incident, and runs the offline verifier.

Expected final line:

```json
{"status":"pass", ...}
```

## Walkthrough

1. Argument drift

Velvet admits a small refund: `$20.00`. The dispatch layer then tries to execute `$2000.00`. The executor refuses before the refund SQL runs. The report shows different admitted and attempted hashes, and the database has zero refund rows.

2. Schema drift

The target server changes the `update_order_status` tool schema after admission. Dispatch refuses because the live schema hash no longer matches the admitted schema hash. The order remains unchanged.

3. Approval replay

A valid approval receipt for deleting one customer is replayed against a different customer. Dispatch refuses because the receipt binds the canonical action hash. The second customer remains present.

4. Policy swap

The policy bundle hash is changed after admission. Dispatch refuses on policy-hash mismatch. The order remains unchanged.

5. Budget overshoot

Three refund attempts race the live refund cap. Two can commit under the cap; the over-cap attempt is refused. Total committed spend never exceeds the cap.

6. Signing provider fail-closed

The proxy starts without the signing keys. It refuses to issue a decision and never forwards execution. The database state hash is unchanged.

## Evidence

Primary artifacts are written under:

```text
reports/live-demo/
```

The canonical incident bundle is:

```text
reports/live-demo/incident/argument_drift_forensic_bundle.tar.gz
```

The offline verifier output is:

```text
reports/live-demo/incident/offline_verification_report.json
```

The asciinema-compatible walkthrough recording is:

```text
reports/live-demo/incident/argument_drift.cast
```

The honest boundary report is:

```text
demo/BOUNDARIES.md
```
