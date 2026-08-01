# OAP Velvet Mapping

Velvet emits OAP draft-compatible Passport and Decision objects at pinned commit `a706c64b0b7ef4bcff9756a926f9a278e577e8b0`, using the pinned draft field set, JCS canonicalization, Passport digest, and production Ed25519 Decision signature checks to the extent those pinned files are internally satisfiable. A pure OAP verifier may accept the Decision without understanding Velvet, subject to the pinned Decision schema conflict documented in `SPEC_CONSISTENCY.md`. Velvet's Max-DE certificate is not claimed as a core OAP field because the pinned OAP spec does not define a sanctioned signed extension mechanism. Velvet carries the Max-DE certificate in a separately signed Velvet envelope and stores it in the pre-execution ledger record. That envelope, exact theorem arithmetic, full action binding, fail-closed ordering, and the two-record ledger model are Velvet extensions.

## Decision Mapping

| Velvet decision | OAP Decision mapping |
|---|---|
| `inspect` / `execute` | `allow=true`; `reasons=[{"code":"oap.allowed","message":"Action admitted by Velvet"}]` because the pinned schema requires at least one reason. |
| `lockout` / `block` | `allow=false`; `reasons=[{"code":"velvet.certified_lockout","message":"Max-DE certified lockout"}]` when Max-DE produced a certified lockout. |
| refinement zone / `escalate` | `allow=false`; `reasons=[{"code":"velvet.certificate_indeterminate","message":"Escalation required; not a silent denial"}]`. |

Refinement is an escalation path, not a silent denial. OAP Decision is binary, so Velvet encodes refinement as `allow=false` with a Velvet-namespaced reason and mirrors the richer trichotomy in the signed Max-DE certificate envelope.

## Passport Mapping

| Velvet identity/config | OAP Passport field |
|---|---|
| `identity.agent_id` | `passport_id` when no explicit OAP passport ID is configured. |
| `oap.passport_id` | `passport_id` override. |
| `identity.tenant_id` / `oap.owner_id` | `owner_id`. |
| `oap.owner_type` | `owner_type`. |
| `oap.assurance_level` | `assurance_level`. |
| `oap.status` | `status`. |
| approved tools | `capabilities[]` as OAP capability identifiers. |
| tool metadata / configured limits | `limits`. |
| `oap.regions` | `regions`. |
| `oap.passport_created_at`, `oap.passport_updated_at` | `created_at`, `updated_at`. |
| `oap.passport_version` | `version`. |
| `oap.oap_kid` | key metadata used by Decisions through `kid`. |

`passport_digest` is computed as `sha256:<hex>` over the RFC 8785 JCS-canonicalized Passport. The hex form follows the pinned schema pattern; `security.md` conflicts by describing base64.

## Decision Fields Velvet Populates

Velvet populates the following fields:

- `decision_id`: UUID v4.
- `passport_id`: Passport identifier.
- `agent_id`: Agent identifier, included for compatibility with examples and runner fallback.
- `policy_id`: `oap.policy_id`.
- `owner_id`: Passport owner.
- `allow`: binary decision.
- `reasons`: one or more OAP/Velvet reason objects.
- `issued_at` and `expires_at`: included for the schema required set.
- `created_at` and `expires_in`: included for examples, VC mapping, and runner fallback.
- `assurance_level`: copied from the Passport.
- `passport_digest`: digest of the exact Passport.
- `kid`: OAP signing key id.
- `signature`: Ed25519 signature over the JCS-canonicalized Decision payload with `signature` omitted.

Because the pinned schema has `additionalProperties: false` and no extension field, the Max-DE certificate is not placed inside the OAP Decision. Velvet signs a separate `velvet.maxde.certificate.v1` envelope with `schema_version=velvet.maxde.certificate_envelope.v2` over its JCS-canonicalized payload with `signature` omitted. That envelope binds the OAP Decision payload digest, signed Decision digest, raw Decision signature hash, Passport digest, policy id/hash/version, hashed identity fields, MCP tool key/name, tool schema hash, arguments hash, request hash, expiry, and optional hashed Secure MCP Tunnel metadata.

## Max-DE Envelope

Velvet envelope type: `velvet.maxde.certificate.v1`.

Rules:

- `decision` is one of `inspect`, `lockout`, or `refinement`.
- `certified_lockout` is true only when `L * U_cert < lambda`.
- `refinement` means escalation required.
- Numeric certificate values are encoded as fixed-scale decimal objects, not JSON floats.
- The envelope signature is Ed25519 over the RFC 8785 JCS-canonicalized envelope payload with `signature` omitted.
- The pre-execution ledger stores the OAP Decision, Passport, explicit digest fields, envelope, envelope digest, policy/action hashes, and certificate-required flag before any upstream forwarding.
