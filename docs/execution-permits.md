# Execution Permits And Receipts

Velvet separates admission evidence from execution authority.

The protocol is:

proposal -> admission decision -> durable pre-execution record -> Execution
Permit -> atomic dispatch claim -> side-effect boundary -> Execution Receipt ->
post-execution ledger observation.

## Artifact Roles

A warrant or proof envelope explains why an action was admitted. It is not
execution authority.

`delay`, `ask_approval`, and `escalate` are non-executable admission states.
They can produce approval or review work, but they do not authorize dispatch.
Approval cannot bypass budget, warrant, tenant-state, permit, schema, policy, or
source-to-sink constraints; a later execution still needs a fresh admitted
decision with every hard constraint passing.

An Execution Permit is a short-lived, single-use, signed authority artifact. It
authorizes exactly one dispatch chain after the admission decision has already
been durably recorded.

An Execution Receipt is a signed observation about what the executor or
substrate saw after a claimed dispatch. A gateway-observed receipt does not
prove that a business-level side effect completed.

## Permit Scope

`schemas/velvet_rope/execution_permit.schema.json` defines the current contract
with `schema_version: "velvet.execution_permit.v1"` and canonicalization
`"velvet.canonical_json.v1.sha256.unsigned_payload"`.

The permit binds tenant, environment, audience, product surface, method, tool or
operation, request hash, canonical action hash, arguments hash, tool schema
hash, policy hash and version, optional read-set or resource scope, privacy-safe
subject/client/session identifiers, the signed decision artifact, supporting
proof artifacts, and the durable pre-execution ledger record.

Velvet recomputes the request binding immediately before dispatch. If the
outbound request, arguments, policy, schema, audience, tenant, environment, or
identity context has drifted, the permit is rejected and no dispatch occurs.

Models are treated as untrusted request authors. A model-supplied
`params._meta.velvet_execution` or legacy `params._meta.velvet_admission`
field is reserved metadata, not evidence or authority. Velvet strips those
fields before admission, request hashing, ledgering, and permit issuance, then
injects its own compact execution metadata only after the permit has been
signed, verified, and claimed.

## Claim Model

Permits are single-use. The claim state machine is:

issued -> claimed -> succeeded, failed_before_dispatch, or indeterminate.

The claim must be durable before the side-effect boundary is crossed. Python
SQLite-backed stores use transactional state transitions keyed by permit ID.
The Rust MCP proxy uses an atomic filesystem create operation in a claim store
beside the configured ledger path. A claimed permit never returns to issued, and
automatic retry after a claimed dispatch is forbidden; retry requires a new
admission decision and a new permit.

If the process crashes after claim but before a conclusive receipt, the result
is incomplete or indeterminate rather than unused.

## Trust Boundary

Permits and receipts use distinct signing purposes:

- `velvet.execution_permit.v1`
- `velvet.execution_receipt.v1`

Verification requires an externally configured trusted Ed25519 public key or
trust store. Embedded public verification material is descriptive only and is
not trusted by itself.

HMAC remains only for explicitly labeled deterministic local-demo or historical
verification paths. A downstream verifier must not need Velvet's signing
secret.

## Receipt Semantics

`schemas/velvet_rope/execution_receipt.schema.json` defines the receipt contract
with `schema_version: "velvet.execution_receipt.v1"`.

A receipt binds the permit ID and hash, dispatch-claim record hash,
pre-execution record hash, request hash, canonical action hash, executor
identity, timestamps, outcome, response hash when available, sanitized error
code and error-detail hash when applicable, optional substrate receipt hash, and
attestation level.

Outcome semantics are conservative:

- `succeeded`: a successful protocol or application response was observed.
- `failed_before_dispatch`: failure is known to have occurred before the
  request left the enforcing boundary.
- `rejected`: an enforcing verifier rejected the request before execution.
- `indeterminate`: dispatch may have occurred but the outcome cannot be
  conclusively established, including timeouts or connection loss after dispatch
  began.

`gateway_observed` proves only gateway observation. `substrate_attested` may
carry a substrate acknowledgment hash, but the substrate defines what that
acknowledgment means.

## External Enforcement

A signed permit is not self-enforcing. External enforcement requires a
cooperating verifier, adapter, credential broker, or substrate integration at
the execution boundary.

The reference live target verifies permits independently against a configured
trusted Velvet public key, recomputes the received request binding, rejects
missing, invalid, stale, mismatched, self-signed, or replayed permits, and only
then executes the protected operation.

Without such a verifier, Velvet enforces at the proxy or gateway boundary.
Request binding and one-time claiming reduce replay and transfer risk, but they
are not proof-of-possession or channel binding. Arbitrary external side effects
are not universally exactly-once, and a crash after a side effect but before
receipt persistence remains an indeterminate window unless the substrate
participates transactionally.
