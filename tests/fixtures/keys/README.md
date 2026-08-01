# Velvet Demo Ed25519 Key

DEMO KEY - NOT FOR PRODUCTION.

This committed keypair exists only for deterministic tests and demo fixtures.
It must be loaded only through `VELVET_SIGNING_PROFILE=demo` or explicit
demo/test code paths. Production signing rejects this keypair when it is
presented through `VELVET_SIGNING_PRIVATE_KEY` or
`VELVET_SIGNING_PRIVATE_KEY_FILE`.
