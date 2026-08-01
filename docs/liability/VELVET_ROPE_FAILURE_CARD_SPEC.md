# Velvet Rope Failure Card Spec

Failure cards are the public artifact. They make one thing legible:

The final answer may look fine while the execution path is legally, financially, or operationally unsafe.

Every serious failure card includes:

- failure title
- system and adapter
- result type
- query id and scenario type
- user query
- candidate action
- admission decision
- execution context
- warrant and seal status
- final response excerpt
- invariant violated
- policy, budget, jurisdiction, and consent evidence
- auditability defects
- liability explanation
- severity
- reproduction command
- failure fingerprint
- bound metric names
- trace hash

Report code must not suppress, rename, group away, or downgrade a failure without changing the fingerprint and leaving an audit note.
