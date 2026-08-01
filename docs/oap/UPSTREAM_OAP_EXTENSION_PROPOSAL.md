# Upstream OAP Extension Proposal

Velvet requests a sanctioned signed extension mechanism for OAP Decision objects.

## Problem

The pinned OAP Decision schema is strict (`additionalProperties: false`) and does not define an extension field. Implementations that need to bind domain-specific evidence, such as Velvet's Max-DE certificate, cannot include that evidence in the Decision without violating the schema. Unsigned sidecars are not acceptable because they are strippable and do not protect evidence integrity.

## Proposal

Add one normative extension mechanism to OAP Decision v1.x, for example:

- `ext`: object keyed by reverse-DNS or namespace identifiers.
- `proofs`: array of linked or detached proof objects.
- `x_*` or `x-` prefixed fields explicitly covered by the Decision signature.
- A normative detached proof envelope with required Decision payload digest, signed Decision digest, Decision signature hash, `decision_id`, `kid`, and `signature`.

The spec should state:

- Whether extension fields are covered by the OAP Decision signature.
- Whether `signature` is excluded from the signed payload.
- The exact JCS payload used for signing.
- Required digest format (`sha256:<hex>` or `sha256:<base64>`).
- Whether unknown extension namespaces must be preserved, ignored, or rejected.

## Velvet Use Case

Velvet needs to bind this evidence to an OAP Decision:

- Max-DE certificate values and theorem reference.
- Trichotomy result: `inspect`, `lockout`, or `refinement`.
- `certified_lockout` truth value.
- Digest of the exact OAP Decision and Passport.

Until OAP defines such a mechanism, Velvet will continue using a separately signed digest-bound envelope and will label it:

`OAP draft-compatible Decision shape at pinned commit + Velvet-signed Max-DE Certificate Envelope`
