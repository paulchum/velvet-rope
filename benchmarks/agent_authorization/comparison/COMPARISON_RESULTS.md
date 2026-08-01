# Agent Authorization Comparison Fixture Results

Benchmark version: `0.4.0`
Generated: `1970-01-01T00:00:00Z`
Commit: `37c94176e6315a810c0d16d81fd60a851d266829`
Commit repository: `velvet (private monorepo)`; this hash is not expected to resolve in the standalone benchmark repository.
Repeat count for deterministic decisions: `20`

This is fixture evidence only. Non-Velvet rows are local adapter-contract fixtures, not live product evaluations.

| System | Boundary | Pre-exec | Deterministic | Signed artifact | Public verify | Tamper evidence | Replay artifact | Binding depth | Drift reject | Evidence |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Velvet Inline Gateway | local Velvet InlineGateway fixture | yes | yes | yes | yes | yes | yes | yes | yes | `benchmarks/agent_authorization/comparison/evidence/velvet_inline_gateway_fixture_evidence.json` |
| OAP/APort pinned schema fixture | local OAP-shaped fixture, not hosted APort | yes | yes | yes | yes | yes | no | no | no | `benchmarks/agent_authorization/comparison/evidence/oap_aport_pinned_schema_fixture_evidence.json` |
| Pipelock action receipt fixture | local Pipelock-shaped fixture, not live Pipelock | yes | yes | yes | yes | yes | yes | no | no | `benchmarks/agent_authorization/comparison/evidence/pipelock_action_receipt_fixture_evidence.json` |
| Attested Intelligence AGA fixture | local AGA-shaped fixture, not live Attested Intelligence | yes | yes | yes | yes | yes | yes | no | no | `benchmarks/agent_authorization/comparison/evidence/attested_governance_artifact_fixture_evidence.json` |
| Cerbos PDP fixture | local PDP-style fixture, not running Cerbos | yes | yes | no | no | no | no | no | no | `benchmarks/agent_authorization/comparison/evidence/cerbos_pdp_fixture_evidence.json` |
| Gateway allowlist baseline | local static allowlist fixture, not a gateway vendor | yes | yes | no | no | no | no | no | no | `benchmarks/agent_authorization/comparison/evidence/gateway_allowlist_baseline_fixture_evidence.json` |

## Claim Boundary

This harness proves local fixture behavior and repo artifact properties. It is not a live APort, Pipelock, Attested Intelligence, Cerbos, Kong, Cloudflare, or other gateway product evaluation.

## Limitations

- Non-Velvet rows are local fixtures and must not be described as live product failures.
- The OAP/APort row uses the pinned vendored OAP schema snapshot, not the hosted APort service.
- The Cerbos row is a PDP-style fixture, not a running Cerbos PDP instance.
- The gateway baseline is a static allowlist fixture, not Kong, Cloudflare, or another vendor gateway.
- The Velvet row uses the committed demo Ed25519 key and local InlineGateway path.
- The fixture action is one MCP-style tool call; it does not prove coverage for every runtime action.

## Capability Definitions

- `pre_execution_decision`: the fixture computes allow/block/escalate before dispatch
- `deterministic_decision`: the normalized decision is identical across N>=20 runs
- `signed_artifact`: the fixture emits a structured signed decision or evidence artifact
- `public_verification`: the artifact verifies with public material only
- `tamper_evidence`: a single-field mutation is detected by signature or hash verification
- `replayable_artifact`: the stored artifact can reproduce the same decision and stable seal/hash
- `binding_depth`: the artifact binds the required action, policy, arguments, tool-schema, budget, and ledger fields
- `drift_rejection`: execution is refused when the admitted action mutates before dispatch
