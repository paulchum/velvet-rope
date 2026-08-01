# OAP Spec Consistency Review

Pinned source:

- Repo: https://github.com/aporthq/aport-spec
- Commit: `a706c64b0b7ef4bcff9756a926f9a278e577e8b0`
- Lock file: `third_party/oap/OAP_SPEC_LOCK.json`
- Vendored root: `third_party/oap/a706c64b0b7ef4bcff9756a926f9a278e577e8b0/`

Canonical files pinned for this integration:

- Passport schema: `oap/passport-schema.json`
- Decision schema: `oap/decision-schema.json`
- Error schema: `error-schema.json`
- Security rules: `oap/security.md`
- Capability registry: `oap/capability-registry.md`
- Conformance docs: `oap/conformance.md`
- VC context and mapping: `oap/vc/context-oap-v1.jsonld`, `oap/vc/vc-mapping.md`
- Examples: `oap/examples/decision.allow.sample.json`, `oap/examples/decision.deny.sample.json`
- Runner source: `conformance/src/runner.ts`, `validators.ts`, `ed25519.ts`, `jcs.ts`, `cases.ts`

## Findings

| Topic | Resolution |
|---|---|
| Canonical repo and commit | `github.com/aporthq/aport-spec` at `a706c64b0b7ef4bcff9756a926f9a278e577e8b0`. |
| Canonical Passport schema | `oap/passport-schema.json`. No competing top-level passport schema was present in the pinned files. |
| Canonical Decision schema | `oap/decision-schema.json`, but it is internally inconsistent. |
| `allow=true` reasons | `reasons` has `minItems: 1`; `reasons=[]` is not schema-valid. Velvet emits `oap.allowed`. |
| Required Decision fields | BLOCKED: schema `required` lists `passport_id`, `issued_at`, `expires_at`; schema `properties`, examples, VC mapping, and runner fallback use `agent_id`, `created_at`, `expires_in`. |
| Strict Decision schema validity | BLOCKED: `additionalProperties: false` plus missing `passport_id`, `issued_at`, and `expires_at` property definitions makes the pinned Decision schema unsatisfiable for strict JSON Schema validation. |
| Passport digest format | CONFLICT: schema requires `sha256:` plus 64 lowercase hex chars; `security.md` says base64-encoded hash. Velvet uses the schema pattern, `sha256:<hex>`. |
| Signing payload and canonicalization | `security.md` requires Ed25519 over RFC 8785 JCS-canonicalized Decision payloads. It does not explicitly state whether the `signature` field is excluded before signing. Velvet signs the JCS-canonicalized object with `signature` omitted, because signing an object that contains its own signature is not constructible. |
| In-object Max-DE extension | Not possible against the pinned Decision schema: `additionalProperties: false` and no `ext`, `x-*`, linked proof, detached proof, or VC extension field is defined for native OAP Decisions. |
| OAP sanctioned extension mechanism | None found for native Decision JSON in the pinned schema/docs. VC mapping is optional export/import, not a native signed extension mechanism. |
| Official conformance runner verification | The TypeScript runner uses fallback schemas rather than the pinned JSON Schema files, ships zero test cases at this commit, and `ed25519.ts` performs format/length checks rather than real Ed25519 verification. |

## Blocker

The pinned OAP Decision schema cannot be satisfied by any object under strict validation because it requires fields that are not allowed by its own `properties` set while `additionalProperties` is false. The examples and runner drift toward `agent_id` / `created_at` / `expires_in`, while the schema required set names `passport_id` / `issued_at` / `expires_at`.

Velvet therefore does not modify or relax the vendored OAP schemas. The implemented external artifact boundary is:

`OAP draft-compatible Decision shape at pinned commit + Velvet-signed Max-DE Certificate Envelope`

The Decision is emitted using the pinned draft field set and Velvet local structural/signature checks while strict upstream schema conformance remains blocked. Pure OAP verification ends at the Passport/Decision boundary and whatever the pinned runner can actually verify. Velvet verification begins at the separately signed Max-DE Certificate Envelope, exact arithmetic, full action digest binding, fail-closed state machine, and hash-chained ledger.
