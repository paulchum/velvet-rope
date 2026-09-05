# Protected refunds: the commit contract

Velvet's PostgreSQL reference ledger binds an authorized refund to an exact operation,
checks its order revision and shared budget while holding a transaction lock, and commits
the operation identity, state change and journal entry together. A separate database
identity exports a signed snapshot that another engineer can verify offline.

**The claim:** through `RefundLedger.refund`, a participating ledger commits at most one
refund for an operation ID; each new refund requires a valid exact-command permit at its
serialized authorization decision, respects the order total and shared budget, and precedes
terminal workflow closure. This is a bookkeeping ledger in one PostgreSQL database.

[Inspect the recorded reference run](https://shadowpath.coriolislabs.ca/protected-refunds/).
The sample is a local workload with synthetic orders, not a payment-provider integration,
performance benchmark, customer deployment, or competitor comparison.

## Reproduce from source

Python 3.12+, Rust (the repository's pinned toolchain), uv and PostgreSQL 17 are required.
Source installation works without a PyPI release or a `v1` action tag. For reproducibility,
check out the exact commit you are evaluating before running these commands.

```bash
git clone https://github.com/paulchum/velvet-rope.git
cd velvet-rope
uv sync --locked --dev
```

Use a disposable local PostgreSQL database. The demo requires an owner that can create
roles and schemas; it creates a uniquely named schema and three temporary identities,
then removes only those objects on normal exit. It never resets an existing ledger.
For example, with Docker:

```bash
docker run --rm --name velvet-refunds-reference \
  -e POSTGRES_PASSWORD=disposable-reference-only \
  -p 127.0.0.1:55439:5432 postgres:17.9-alpine
```

In another terminal, after PostgreSQL reports readiness:

```bash
export VELVET_REFUNDS_DEMO_DSN='host=127.0.0.1 port=55439 dbname=postgres user=postgres password=disposable-reference-only'
uv run python -m velvet.refunds demo --output-dir reports/protected-refunds
export VELVET_REFUNDS_TEST_DSN="$VELVET_REFUNDS_DEMO_DSN"
uv run pytest tests/test_protected_refunds.py tests/test_shadowpath_measurement.py -q --no-cov
```

No external agent or payment system is contacted. The useful workload issues a $10 refund,
retries it, concurrently issues two $40 refunds, and submits two $10 refunds competing for
the remaining $10. Exactly one of the last pair can commit. It then closes the workflow
and records a rejected post-closure request. The observer checks four committed refunds,
$100 spent, and six journal records including opening and closure.

The budget rejection and closure rejection are local caller observations in `report.json`.
Only committed transitions belong to the signed database checkpoint. Five measured calls
include connection setup, lock waiting, validation and the transaction; this tiny local
sample supplies no throughput, tail-latency or competitor-performance claim.

## Verify without PostgreSQL

`evidence.json` carries the snapshot and observer checkpoint. Pin the observer public key
and expected contract hash through a separate trusted channel. The sample's key and hash
are committed in this repository for reproducibility; trusting both from an untrusted
download would only establish that the files agree with each other.

```bash
uv run python -m velvet.refunds verify site/public/proofs/refunds/evidence.json \
  --observer-key site/public/proofs/refunds/observer-public-key.pem \
  --observer-key-id reference-observer \
  --contract-hash "$(cat site/public/proofs/refunds/contract.sha256)"
```

To verify your fresh demo, substitute `reports/protected-refunds` for that directory.
The verifier requires no database connection. It validates the pinned signature and
contract, ordered journal hashes, exact permit bindings and validity at recorded decision
times, operation and permit uniqueness, the business-state replay, and equality with the
observer's materialized operation table and final ledger state.

| Verdict | Meaning | CLI exit |
| --- | --- | --- |
| `COMPLETE` | The closed ledger's observed state, operations and complete opening-to-closure journal reconcile under the pinned contract and key. | 0 |
| `OPEN_INTERVAL` | The signed snapshot reconciles but the workflow can still change. | 2 |
| `INVALID` | A required record, signature, identity, invariant or reconciliation check failed. | 2 |

A checkpoint authenticates a historical observation. It does not establish that it is the
latest checkpoint, that the database has no hidden privileged writers, or that events in
another database or payment provider were captured. Keep a checkpoint externally if
rollback/equivocation detection is required. The receipt journal is append-only to the
executor role; database owners remain trusted.

## State machine and implementation correspondence

The immutable contract `C` includes ledger ID, tenant, environment, audience, currency,
budget `B`, initial order totals `T`, and the authorization public key. A signed permit
binds `hash(C)` and the complete command `(operation_id, ledger_id, order_id, amount,
expected_revision, expected_epoch)`. No floating-point money or implicit unit conversion
is accepted. One currency and one budget apply to the whole ledger.

State consists of spent amount `S`, per-order refunded amount `R` and revision `V`,
lifecycle epoch `E`, closed flag `X`, operation identities, consumed permit identities,
and the journal head. Genesis has zero spending/refunds/revisions, epoch zero and `X=false`.

| Transition | Preconditions and result | Code |
| --- | --- | --- |
| Refund | Valid exact-command permit; matching ledger, revision and epoch; open workflow; positive integer amount `a`; `R[o]+a <= T[o]`; `S+a <= B`. Atomically increment balances/revision, consume identities and append the journal. | `contract.transition`, `RefundLedger.refund` |
| Identical retry | Same operation ID, command hash, permit ID and complete permit. Return the previously committed record with `replayed=true`. No new effect or journal entry. | `RefundLedger.refund` |
| Conflicting retry | Same operation ID with another command or permit. Reject. | `RefundLedger.refund` |
| Close | Under the same ledger lock, set `X=true`, increment `E`, append closure. Repeated closure returns the existing closed state. There is no reopen operation. | `close_transition`, `RefundLedger.close` |
| Observe | One read-only, repeatable-read transaction under a distinct database identity. Read all state, operations and journal rows. | `RefundLedger.observe` |

All writes serialize on `SELECT ... FOR UPDATE` of the ledger singleton. The lock remains
held through commit/rollback. The authorizer checks database wall time **after** waiting
for this lock; permit expiry applies to that decision, not a claim about the precise
physical instant the commit reaches storage. Refund mutation, identities and journal share
the same transaction. A journal-write failure rolls the mutation back. Closure obtains
the same lock: an earlier successful refund finishes first, or closure prevents the refund.
This is a database-local epoch; it does not connect distributed Rust closure stores or
provide cross-database revocation.
The executor explicitly selects read-committed isolation and synchronous commit; the
observer selects repeatable-read isolation. See PostgreSQL's
[row-lock semantics](https://www.postgresql.org/docs/17/explicit-locking.html) and
[transaction isolation documentation](https://www.postgresql.org/docs/17/transaction-iso.html).

Inductive invariant argument: genesis satisfies `0 <= S <= B`, `0 <= R[o] <= T[o]`, and
`S = sum(R)`. Every successful refund checks both upper bounds before adding the same
positive amount to `S` and one `R[o]`; retries/rejections/closure leave balances unchanged.
The ledger lock reduces concurrent commits to that serial transition order. Unique
operation and permit keys plus atomic writes preserve identity uniqueness. A closed state
admits no new refund transition. These arguments depend on the trusted implementation and
the documented database transaction behavior.

The test suite exhaustively visits a **bounded state space** (two orders of two units and
a three-unit budget) and checks arithmetic invariants, then exercises the actual database
under concurrency, retries, rollback, closure and evidence failures. This is a specification,
an invariant argument and implementation conformance testing—not a machine-checked proof
of the deployed system. The offline verifier shares the pure transition implementation;
it is independently runnable, not an independent second implementation.

## Integrating the package

Use `velvet.refunds.RefundLedger` in a trusted execution service. Install once with
`install(config, executor_role=..., observer_role=...)` under a separate owner credential.
Existing schemas are refused; the contract version is immutable. A later version needs an
explicit migration/rollover design. Pass the executor credential only to that service.

`issue_permit(config, command, signer)` belongs to the operator/authorization service after
its own approval decision. It uses Velvet's existing execution-permit and signing formats;
it does not infer approval from agent text, prove human intent, run an external policy
engine, or automatically verify another system's approval records. The executor needs only
the public authorization key pinned in its contract. Permits are bearer authority for the
exact command; caller authentication and tenant routing belong to the integrating service.

Run `observe` and `seal_snapshot` with the observer credential and a separately managed
observer signing key. The reference demo co-locates those components in one process with
fresh ephemeral keys; it demonstrates database-role separation, not an independently
operated observer organization. Export/signing failures leave the committed journal
available for another export and cannot create a `COMPLETE` artifact.

| Identity | Access |
| --- | --- |
| Database owner | Installs the schema and immutable contract; trusted administration. |
| Executor | Reads tables, updates ledger state/head, inserts journal and operation rows. Cannot update the contract or delete/update journal rows through the supplied grants. Trusted to run the enforcing code. |
| Observer | Schema usage and table reads; the observer method refuses identities with write privileges. |
| Agent | No schema access. Calls a service that validates the request and invokes the protected method. |

There is one supported refund entry point and one trusted lifecycle entry point. MCP,
HTTP, queue and browser transports are not additional implemented routes in this package.
Any future adapter must invoke the same boundary and must not receive direct mutation
credentials. Privileged DBA/OS access, executor compromise, signing-key compromise,
deployment permission drift and writes outside this ledger invalidate the corresponding
claim assumptions.

A lost connection at commit is **unresolved** for the caller, not a definite rejection.
Reconnect and retry the identical operation/permit to retrieve a committed result. A new
operation ID authorizes a different operation; never invent one to recover a timeout.
Uncommitted work rolls back; an expired uncommitted permit requires a new authorization.
Historical retrieval remains available after expiry/closure without authorizing a new effect.

The implementation opens a connection per call and serializes one whole ledger, storing
the small order state as JSON. Connection pooling, sharding, durable external anchoring,
automated key rotation, long-run contention benchmarks, external technical review and
real payment-provider reconciliation remain future work. None is implied by `COMPLETE`.
