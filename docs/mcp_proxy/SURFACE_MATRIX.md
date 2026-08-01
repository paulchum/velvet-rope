# MCP Proxy Surface Matrix

This matrix is the scoped boundary for the MCP pilot gateway. `tools/call` and
`tools/list` are enforced. Connection lifecycle methods are forwarded. Every
other MCP method is bounded-governed: it resolves to an explicit disposition and
is recorded before any forwarding decision.

| MCP method or group | disposition | strict-mode default | recorded? | notes |
|---|---|---|---|---|
| `tools/call` | enforced | policy decision | yes | Emits the pre-execution OAP Decision, policy-required Velvet-signed Max-DE Certificate Envelope, and two-record Ledger flow. |
| `tools/list` | enforced | filtered inventory | yes | Fetches upstream inventory, hashes schemas, classifies tools, exposes only approved non-drifted tools, and writes redacted inventory evidence. |
| `initialize` | lifecycle-forwarded | forward | no | Required for connection setup; IDs and upstream server details are preserved. |
| `notifications/initialized` | lifecycle-forwarded | forward | no | Required lifecycle notification; no proxy response is emitted. |
| `ping` | lifecycle-forwarded | forward | no | Required liveness path. |
| `resources/*` | bounded-governed | block | yes | Resource methods are not semantically inspected in this pass; recorded passthrough requires explicit deployment config. |
| `prompts/*` | bounded-governed | block | yes | Prompt methods are default-deny because they are a prompt-injection surface; recorded passthrough requires explicit deployment config. |
| `tasks/*` | bounded-governed | block | yes | Task methods are outside this scoped gateway and default to a recorded block. |
| `notifications/*` except `notifications/initialized` | bounded-governed | block | yes | Non-lifecycle notifications are governed; notification response rules are preserved after recording. |
| `*` unknown methods | bounded-governed | block | yes | Unknown methods fail closed unless explicitly configured for recorded passthrough. |

Explicit passthrough is configured through `method_dispositions` and is never
implicit. The gateway does not perform semantic content enforcement for
resources or prompts in this pass.
