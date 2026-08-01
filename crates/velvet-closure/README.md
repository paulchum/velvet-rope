# velvet-closure

`velvet-closure` is a lifecycle controller for Velvet Execution Permits. It binds
closure-issued permits to a signed `subgoal_id_hash` and a subgoal epoch. A
permit must pass the existing signature, scope, claim, receipt, and wall-clock
checks, plus the current epoch check, before dispatch.

The crate does not add a new gateway, ledger, or signing system. It reuses
`velvet-rope-proxy` issuance, binary ledger records, and OAP pre/post records.
Lifecycle records are appended to the same binary ledger and carry normal
`record_hash` values, so Vault segments built over that ledger's record-hash list
cover closure events alongside pre/post execution records.

Closure epochs are host-controlled. The only control message shape reserved for
transport integration is `velvet.closure.close`; there is no planner-reachable
open/reset/advance/rewind verb. A trusted close signal can remove authority early,
but cannot grant or extend authority.

`MaxDeRiskGate` denies `irreversible` grants unless a real signed Max-DE envelope
is supplied. It intentionally does not fake a passing certificate.
