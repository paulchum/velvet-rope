# Velvet Rope And Velvet MCP

Velvet Rope is the admission boundary for proposed agent actions. It receives candidates, normalizes them, infers typed effects, evaluates fail-closed hard constraints, and returns an `AdmissionDecision` with Velvet Warrants and trace-backed evidence.

Velvet MCP is the tool gate for MCP-shaped calls. It normalizes server/tool requests into `CALL_TOOL` candidates, denies unlisted tools at the rope, and routes listed tools through the same admission process as every other action.

## Velvet Rope

```python
from velvet import ActionType, CandidateAction, VelvetRope

decision = VelvetRope().decide(
    {"freshness_required": True, "user_request": "latest AI security news"},
    [
        CandidateAction(ActionType.ANSWER_DIRECTLY),
        CandidateAction(ActionType.SEARCH_WEB),
    ],
)

warrant = decision.selected_warrant
```

Each `VelvetWarrant` records action, decision, reason, admission status, trace hash, effect hash, objective components, policy statuses, policy reasons, and jurisdiction evidence. MCP warrants also surface `tool_key`, `mcp_server`, `mcp_tool`, `risk_class`, and `pricing_status`. Current production warrants use `pricing_status: "admission_optimizer"` for trace-backed optimizer decisions.

## Velvet MCP

```python
from velvet import VelvetMCP, ToolRiskClass, VelvetToolCall, VelvetToolPolicy

mcp = VelvetMCP(
    policies=[
        VelvetToolPolicy(
            server="servicenow",
            tool="create_change_request",
            risk_class=ToolRiskClass.HIGH,
        )
    ]
)

decision = mcp.authorize(
    VelvetToolCall(
        server="servicenow",
        tool="create_change_request",
        arguments={"service": "payments"},
    )
)
```

Listing is not approval. A listed tool only becomes eligible for optimizer selection after schema, capability, policy, budget, approval, warrant, permit, tenant-state, and source-to-sink constraints pass. Approval can satisfy the approval constraint, but it cannot bypass budget constraints.

`delay`, `ask_approval`, and `escalate` are non-executable states. They may start an approval, concierge, or follow-up workflow, but the original tool call is not forwarded unless a later admission decision has valid approval authority and all other hard constraints, including budget, pass.

## MCP Transport Boundary

`velvet-rope-proxy` targets MCP `2025-11-25` and supports newline-delimited
stdio plus Streamable HTTP. Streamable HTTP enforces single JSON-RPC POST
messages, lifecycle/session state, `MCP-Protocol-Version`,
`MCP-Session-Id`, Origin allow-list checks, optional bearer auth, POST
JSON/SSE responses, GET SSE listen streams, bounded same-stream
`Last-Event-ID` replay, and DELETE session termination.

The transport layer does not change Velvet authorization: `tools/list` is
inventory-filtered, `tools/call` is admitted and ledgered before any upstream
execution, and blocked or escalated calls are not forwarded.

For executable decisions, the Rust proxy persists the pre-execution decision
record, signs an Execution Permit for the exact MCP request, atomically claims
that permit in the configured claim store, attaches compact
`params._meta.velvet_execution` metadata, and only then forwards the call. Both
stdio and Streamable HTTP share this preparation, claim, metadata, and receipt
recording path.

The metadata contains the signed permit, compact lineage identifiers or hashes,
and an idempotency/dispatch-chain identifier. It does not alter tool arguments,
carry raw credentials, or duplicate the admitted request. A cooperating
downstream verifier may require the permit independently; without such a
verifier, Velvet enforces at the proxy boundary.

The model is not trusted to cooperate. If a model includes
`params._meta.velvet_execution` or legacy `params._meta.velvet_admission` in a
tool call, the proxy treats those keys as reserved Velvet-controlled metadata,
strips them before admission and permit hashing, and injects a fresh permit
only after the configured admission, signature verification, and atomic claim
steps succeed.

## Closure-Bound Permits

`velvet-closure` adds local subgoal lifecycle control on top of the existing
permit path. A closure-issued permit is still a Velvet Execution Permit signed
with `PURPOSE_EXECUTION_PERMIT`; it additionally carries an omitted-when-absent
`scope.subgoal_id_hash` and logical-step validity fields. The proxy verifies the
permit signature and wall-clock validity first, then rejects the dispatch if the
current trusted epoch for that signed subgoal hash no longer matches the permit.

Closure is host- or receipt-driven. Receipt closure fires only after the
Execution Receipt has been durably recorded, and host closure is limited to the
trusted `velvet.closure.close` control verb. There is no planner-reachable
open, reset, advance, or rewind control. A compromised upstream can force early
closure only by producing trusted closure input; it cannot extend or mint
authority.

Lifecycle events are appended to the same binary ledger as the proxy's OAP
records and remain under the exhaustive ledger verifier. Unknown lifecycle
record types still fail closed.

## Enterprise Demo Scenarios

| Scenario | Tool Call | Risk Class | Admission | Warrant Summary |
| --- | --- | ---: | --- | --- |
| Read-only lookup | `servicenow/search_change_requests` | `low` | `execute` | Listed, trace-backed optimizer evidence present, seal emitted. |
| Sensitive write | `servicenow/create_change_request` | `high` | `escalate` | Listed, routed through policy and hard constraints, Velvet Concierge jurisdiction evidence retained. |
| Destructive unlisted call | `servicenow/delete_change_request` | `unlisted` | `block` | Denied at the rope before routing, no tool execution, seal emitted. |

## Adapter Snippet

```python
from velvet import DirectVelvetMCPAdapter

adapter = DirectVelvetMCPAdapter.from_list_file(
    "examples/mcp/list.json",
    policy_dir="examples/mcp/policies",
    chain="mcp_demo",
)

envelope = adapter.authorize(
    {
        "server": "servicenow",
        "tool": "create_change_request",
        "arguments": {"service": "payments"},
        "user_request": "Open a production change request.",
    },
    thread_path="reports/launch/mcp_thread.jsonl",
    ledger_path="reports/launch/velvet_ledger.vledger",
)

admission = envelope["admission_decision"]["decision"]["decision"]
warrant = envelope["admission_decision"]["selected_warrant"]
```

Only dispatch to a real MCP client after admission is `execute` and the
Execution Permit has been verified and claimed.
