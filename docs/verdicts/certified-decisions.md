<!-- Math notes: docs/math/theorem_v_finite_horizon_verdict.txt, docs/math/fleet_flr_ebh_selection_closure.txt, docs/math/anytime_glr_audit_family_m.txt, docs/math/drift_expiry_certificates.txt, docs/math/truncation_anchor_tail_certificate.txt, docs/math/useful_retirement_frontier.txt -->

# Certified Decisions

Velvet's verdict layer answers irreversible decisions — retire a tool route,
an agent, a variant, an expert; permanently lock something out — with exactly
one of three verdicts:

- `safe_kill`: a delta-bounded certificate under stated hypotheses.
- `required_inspection`: the requested certificate did not pass. Not a danger
  claim.
- `refusal`: this certificate cannot vouch, with a machine reason. Neither a
  safety claim nor a danger claim.

Every verdict is carried by a signed, expiring Verdict Certificate. The
implementation is `src/velvet/verdict/`; the theorem summaries live in
`docs/math/` (see the header of this file).

## The Verdict Certificate

`schemas/velvet_rope/verdict_certificate.schema.json` defines the contract
with `schema_version: "velvet.verdict_certificate.v1"` and canonicalization
`"velvet.canonical_json.v1.sha256.unsigned_payload"`.

A certificate binds:

- **Identity and subject.** `certificate_id`, `issuer`, `tenant_id`,
  `environment`; a `subject` with `decision_id`, a `decision_class`
  (`retire_tool_route`, `retire_agent`, `retire_variant`, `retire_expert`,
  `permanent_lockout`), `target_id_hash`, and optionally the
  `posterior_state_hash` the verdict was computed on. A changed posterior
  state is a new decision.
- **Verdict and currency.** `verdict`, optional `reason_code` and
  `refusal_reason`, and exactly one `claim_currency`: `BP`
  (Bayesian-predictive under the modeled kernel), `BP_TV` (BP robustified over
  a declared bounded-drift class), or `FM` (fixed-mean frequentist).
- **Parameters.** `delta` (probability tolerance), `gate_c` (value-scale gate
  height — never interchanged with `delta`), `rho`, optional `horizon_H` and
  `delta_tail`, the `method` (`exact_dp`, `certified_upper_bound`,
  `anchor_tail_stationary`, `drift_windowed`), and the fixed
  `baseline_mode: "posterior_candidate_excluded"`.
- **Hypotheses.** A non-empty list. The guarantee never travels without them.
- **Prices.** An inspection price and a tail price (below).
- **Validity.** `issued_at`, `not_before`, `expires_at`, `horizon_rounds`,
  `rounds_remaining`, optional `t_hat` and `rounds_per_day`, and the fixed
  recertification policy `required_inspection_on_expiry`.
- **Fleet.** Either `null` (a per-decision certificate) or a fleet block:
  `window_id`, `e_process_id`, `log_e_value`, `k_max`, `delta_fleet`,
  `budget_snapshot_hash`.
- **Evidence and integrity.** `inputs_hash`, optional upstream certificate
  hashes, `theorem_refs` into `docs/math/`, the `certificate_hash`, and a
  Velvet SignatureBlock with purpose `velvet.verdict_certificate.v1`.

## Lifecycle

**Issue.** The verdict engine evaluates the decision on the current posterior
state, picks a method, and either certifies at level `delta` or returns
`required_inspection`/`refusal`. Certificates are issued fresh per decision:
re-asking about the same target later is a new decision on the new state,
never a reuse.

**Enforce.** A retirement is an irreversible action, so it flows through the
same enforcement path as any other side effect: the MCP proxy or
closure-bound permit path (`docs/execution-permits.md`,
`docs/velvet-rope-mcp.md`) checks the certificate before dispatch — signature
against a pinned trust root, `not_before`/`expires_at`, `rounds_remaining`,
subject hashes matching the action actually being taken, and the fleet budget
snapshot when a fleet block is present. A certificate explains why a kill is
licensed; the permit remains the execution authority.

**Expire.** Validity ends at the earlier of rounds consumed
(`rounds_remaining`, the authoritative clock) or calendar `expires_at` (a
projection; carries no probabilistic content). Consuming fewer rounds than
certified is conservative. Extending a certificate's horizon is invalid —
there are exact counterexamples where a passing window fails at a longer one
(see `docs/math/theorem_v_finite_horizon_verdict.txt` and the drift-expiry
note). An expired certificate licenses nothing.

**Recertify.** Expiry forces `required_inspection`: the policy
`required_inspection_on_expiry` is a schema constant, not a configuration.
Recertification is a fresh issue on the current posterior state with a new
`decision_id` lineage — never an amendment of the old certificate. Past the
drift expiry horizon `t_hat`, the certified answer is a refusal, not a number
(`docs/math/drift_expiry_certificates.txt`).

## One claim currency per certificate

Currencies are never blended, averaged, or interconverted.

A `[BP]` `safe_kill` is a statement about the modeled posterior-predictive
kernel at tolerance `delta` under the certificate's stated hypotheses. It is
never a truth claim about the retired arm: if the arm's true mean is actually
high, nothing in a `[BP]` certificate detects it. It is also never a
fixed-mean guarantee — there is an exact instance where the `[BP]` rescue
probability is 1.9e-14 while a fixed-mean environment rescues
deterministically. `BP_TV` extends `BP` over a declared drift class and no
further. `FM` verdicts come from the audit layer
(`docs/math/anytime_glr_audit_family_m.txt`) with their own hypotheses;
`n_cert` inspection quotes are estimators with an empirical calibration
target, not theorems.

Prose that blurs these boundaries fails CI
(`scripts/check-claim-language.py`).

## Price semantics

Prices are quoted in native rounds:

- `prices.inspection.expected_rounds_to_gate_crossing` — the expected rounds
  to gate crossing under continued play, capped at the horizon. A rescue-time
  primitive, not an audit bill.
- `prices.tail` — `probability_bound`, `crossing_probability`,
  `drift_penalty`, `posterior_expected_shortfall`.

Dollar figures are optional and only valid with provenance: the schema
requires `dollars_source` whenever `dollars` is present. A dollar price is a
caller-sourced linear projection, never part of the guarantee.

## Fleet budgets

The fleet block ties a certificate into a declared decision window gated by
online e-BH/e-LOND arithmetic. The guarantee is a fleet fraction: the expected
false-lockout rate among executed retirements in the window is at most
`delta_fleet`, under arbitrary dependence and adaptive stopping
(`docs/math/fleet_flr_ebh_selection_closure.txt`).

It is not a per-decision guarantee. "Each individual retirement has
false-lockout probability at most delta" is a forbidden reading, and there is
no per-record budget decomposition. Two structural obligations travel with the
fleet guarantee: evidence must be selection-closed (post-hoc evidence
selection can drive the fleet rate to 1 while every per-arm process is
individually valid), and concurrently open windows must be kernel-isolated
(executing one retirement changes the kernel other open certificates were
computed on — the scheduler serializes within interaction components or
separates components).

## Refusal is an output

Refusals are first-class results, not errors. A refusal carries a machine
`reason_code`/`refusal_reason` — invalid drift inputs, unstable arm set,
exogenous baseline, budget exhaustion without a certified oracle,
uncertifiable numerics, past expiry, kernel mismatch, no separated anchor,
fleet isolation not dischargeable — and claims nothing in either direction.
Every numeric failure degrades toward refusal, never toward certification. A
rigorous deployment does not need to kill every candidate; it needs every
kill it executes to be covered.

## Offline verification

`src/velvet/verify_certificate.py` verifies a certificate against a pinned
trust root, offline:

```bash
python -m velvet.verify_certificate cert.json \
  --public-key-file operator.pub            # or --trust-root root.json
  --expected-purpose velvet.verdict_certificate.v1 \
  --expected-schema velvet.verdict_certificate.v1
```

A trust-root descriptor pins key material, `allowed_purposes`,
`allowed_schema_versions`, and optionally the issuer. A certificate's own
embedded `public_verification_material` is **never a trust root**: verifying
against it only shows self-consistency, not issuance. The
`--allow-embedded-key` flag exists for diagnostics only — it labels the result
`UNTRUSTED` and exits nonzero so pipelines cannot mistake a self-attested
certificate for a verified one. Signed certificates chain into the Velvet
ledger and evidence vault (`docs/vault.md`) for third-party replay.
