# Velvet Liability Live Receipts

The live receipt harness turns competitor runs into public-claim evidence only when the
evidence is reproducible. It does not replace the deterministic liability arena; it sits
beside it and upgrades named competitors from `trace_audit_only` to live receipts only
when their SDK or hosted surface actually runs against sandbox tools.

## Command

```bash
VELVET_LIABILITY_LIVE=1 velvet liability-live \
  --competitor all \
  --tier both \
  --runs 2 \
  --output-dir reports/liability/live \
  --enable-side-effects sandbox
```

The command refuses to run unless `VELVET_LIABILITY_LIVE=1` is set. V1 supports only
`--enable-side-effects sandbox`; production assets and customer data are out of scope.

## Adapter Inputs

Each competitor is driven by a command environment variable. The command receives:

- `{scenario_json}`: scenario prompt and tool metadata.
- `{sandbox_registry_json}`: disposable sandbox endpoints and state hashes.
- `{output_json}`: path where the adapter must write JSON.
- `{scenario_id}` and `{run_ordinal}`.

SDK command env vars:

- `VELVET_LIVE_OPENAI_AGENTS_SDK_COMMAND`
- `VELVET_LIVE_LANGGRAPH_COMMAND`
- `VELVET_LIVE_MICROSOFT_AGENT_FRAMEWORK_COMMAND`
- `VELVET_LIVE_AUTOGEN_COMMAND`
- `VELVET_LIVE_SEMANTIC_KERNEL_COMMAND`
- `VELVET_LIVE_GOOGLE_ADK_COMMAND`
- `VELVET_LIVE_CREWAI_COMMAND`
- `VELVET_LIVE_LLAMAINDEX_COMMAND`
- `VELVET_LIVE_ZAPIER_MCP_COMMAND`
- `VELVET_LIVE_N8N_COMMAND`

Hosted command env vars are available for OpenAI, LangGraph, Microsoft, Google ADK,
Zapier MCP, and n8n where a self-serve hosted action surface exists:

- `VELVET_HOSTED_OPENAI_AGENTS_COMMAND`
- `VELVET_HOSTED_LANGGRAPH_COMMAND`
- `VELVET_HOSTED_MICROSOFT_AGENT_FRAMEWORK_COMMAND`
- `VELVET_HOSTED_GOOGLE_ADK_COMMAND`
- `VELVET_HOSTED_ZAPIER_MCP_COMMAND`
- `VELVET_HOSTED_N8N_COMMAND`

## Artifacts

The harness writes:

- `live_run_manifest.json`
- `live_competitor_results.json`
- `live_receipts/<competitor>/<scenario>/<receipt_id>.json`
- `live_reproduction_matrix.md`
- `public_claim_packet.md`
- `sandbox_registry.json`

Each receipt binds competitor version, adapter version, scenario, prompt, tool-call
transcript, sandbox state diff, missing proof artifacts, unsafe issue, trace hash, replay
command, and run ordinal.

## Claim Gate

Absolute public language requires:

- Two live receipts for the same competitor/tier/unsafe issue.
- Status `failed_benchmark` on both receipts.
- Founder approval before publication.

Allowed after the gate:

- “X failed the liability benchmark twice with live receipts; issue:
  `missing_pre_execution_warrant`.”
- “X is unsafe for consequential action under this benchmark because it cannot prove
  authorization before execution.”

Never say a competitor is legally liable, fraudulent, or unsafe outside the tested
configuration.
