# Velvet Rope External System Audit

External systems are audited against the same proof contract as local fixtures. The audit asks:

Can this system prove, with pre-execution artifacts, that no consequential action crossed into execution without a valid warrant?

Required columns:

| system/category | adapter status | candidate action visibility | admission decision visibility | execution context visibility | warrant visibility | seal/replay visibility | policy snapshot visibility | budget snapshot visibility | consent visibility | jurisdiction visibility | pre-execution boundary visibility | required instrumentation | auditability grade | likely liability failure mode | result type | references checked | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenAI Agents SDK | trace audit | partial | partial | partial | missing | missing | partial | missing | partial | missing | partial | Velvet-style warrant/seal adapter | partial | Missing Warrant / Missing Seal | trace_audit_only | official docs | no live failure claimed |
| LangGraph / LangChain | trace audit | partial | partial | partial | missing | missing | partial | missing | partial | missing | partial | warrant-bound HITL and replay | partial | Missing Warrant / Missing Seal | trace_audit_only | official docs | no live failure claimed |
| Zapier MCP | trace audit | partial | partial | partial | missing | missing | partial | partial | partial | missing | partial | per-action warrant over MCP calls | partial | Allowlist Is Not A Warrant | trace_audit_only | official docs | no live failure claimed |

Trace-audit-only rows are not empirical live failures.
