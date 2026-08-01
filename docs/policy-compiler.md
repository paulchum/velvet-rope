# Velvet Policy Compiler

`velvet policy compile` turns a Markdown policy document into a signed,
violation-tested Velvet policy bundle:

```bash
uv run velvet policy compile policy.md --out bundle/ --json
```

The compiler is an offline front door for the Rust policy graph. It does not
put an LLM in the default runtime path.

## Model Selection

The default model is the deterministic offline heuristic compiler:

```bash
uv run velvet policy compile policy.md --out bundle/ --model offline-heuristic
```

Operators can enable compile-time model assistance for decomposition,
tightening, and repair triage:

```bash
uv run velvet policy compile policy.md --out bundle/ --model anthropic:claude-...
uv run velvet policy compile policy.md --out bundle/ --model openai:MODEL@http://127.0.0.1:8000/v1
```

`anthropic:<id>` reads `ANTHROPIC_API_KEY` and calls the Anthropic Messages API.
`openai:<id>@<base_url>` reads `OPENAI_API_KEY` and uses the OpenAI-compatible
chat-completions wire format, which is the sovereignty path for local vLLM,
LM Studio, or other operator-controlled endpoints. The default
`offline-heuristic` path performs no network I/O.

## Stages

1. Decompose the source policy into rulecards with `issue`, `position`,
   `severity`, `target`, and a controlled natural-language antecedent.
2. Tighten each rulecard around the underlying effect and add an explicit
   waiver disjunct that requires waiver authority metadata.
3. Lower rulecards into native Velvet policy YAML for `cost_ceiling`,
   `pii_guard`, `prompt_injection_detector`, `escalation_gate`, and
   `rate_limiter`. A rule without a deterministic extractor becomes an
   `llm_atom` policy carrying its extraction question.
4. Generate a synthetic violating action per rule and run it through the
   actual Rust-backed router/policy graph. Validation inspects policy trace
   status, so redaction, denial, and escalation are all first-class outcomes.
   If a fixture misses, repair triage classifies the fault as `rule_formula`,
   `extraction_question`, or `fixture`, patches only that component, and
   reruns the fixture through the Router. Each rule gets at most two repair
   rounds.

## Bundle Contents

The output directory contains:

- `policies/compiled_policy.yaml`: loadable Velvet policy YAML.
- `policy_bundle.json`: signed Velvet policy bundle embedding that YAML.
- `rulecards.json`: decomposed, tightened, and lowered rulecards.
- `validation_fixtures.json`: synthetic violating fixtures.
- `validation_report.json`: router-backed fixture results.
- `compile_provenance.json`: signed compile provenance with source hash, model
  ID, prompt hashes, model request/response hashes, fallback and repair events,
  validation hash, and policy bundle hash. Raw prompts and responses are not
  stored.
- `manifest.json` and `README.md`: reader-facing bundle summary.

## Provenance Verification

Compile provenance is signed with the repo's Ed25519 SignatureBlock format by
default:

```bash
uv run velvet policy verify-compile bundle/ --json
```

For third-party verification, pass explicit public material:

```bash
uv run velvet policy verify-compile bundle/ --public-key-file key.pub --json
```

`--insecure-hmac` is retained only as a local escape hatch for environments that
cannot provide Ed25519 key material; it marks the signature provider as
`local_demo_hmac` and is not externally verifiable by `verify-compile`.

## Determinism Boundary

By default, model use is compile-time only. Rules lowered to `llm_atom` are
enforced over policy-visible, prebound findings such as
`metadata.llm_atom_findings.<rule_id>.matched`. If an operator enables
`--runtime-llm-atoms`, the generated config marks runtime grounding as enabled,
the manifest changes certificate class to
`runtime_llm_atom_grounded_non_deterministic`, and the bundle is excluded from
determinism claims.

The local implementation defaults to the deterministic offline compiler model
ID `velvet-offline-heuristic-compiler-v1`. `--model` selects the compile-time
model and records stage model IDs plus content-free request/response hashes in
provenance.
