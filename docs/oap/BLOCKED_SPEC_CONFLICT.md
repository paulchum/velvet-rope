# Blocked OAP Spec Conflict

Strict OAP Decision schema conformance is blocked at pinned commit `a706c64b0b7ef4bcff9756a926f9a278e577e8b0`.

The pinned `oap/decision-schema.json` has this conflict:

- `required` includes `passport_id`, `issued_at`, and `expires_at`.
- `properties` does not define `passport_id`, `issued_at`, or `expires_at`.
- `additionalProperties` is false.
- The allow/deny examples, VC mapping, and conformance runner fallback schema use `agent_id`, `created_at`, and `expires_in`.

No JSON object can both include the required fields and satisfy `additionalProperties: false` under the pinned schema. Velvet does not patch or relax the vendored schema and does not claim strict upstream schema conformance until the upstream conflict is resolved.

Velvet's implemented fallback is:

`OAP draft-compatible Decision shape at pinned commit + Velvet-signed Max-DE Certificate Envelope`

The fallback keeps the OAP Decision free of Velvet extension fields and carries the Max-DE certificate in a separate signed Velvet envelope bound to the exact OAP Decision payload digest, signed Decision digest, raw Decision signature hash, Passport digest, policy, identity hashes, tool schema hash, argument hash, and request hash. The envelope is a Velvet extension, not pure OAP.
