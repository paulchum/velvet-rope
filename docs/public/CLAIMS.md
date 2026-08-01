# Velvet Claim Boundaries

Use this file before forwarding the repo or copying language into outbound material. Every capability statement should map to [`../../DOC_SYNC_INVENTORY.md`](../../DOC_SYNC_INVENTORY.md).

## Safe Public Claims

- Velvet is a local, self-hosted pre-execution admission and evidence system for autonomous-agent actions.
- Velvet Gateway can admit, block, escalate, defer, or skip typed candidate actions before execution.
- Velvet emits warrants, seals, ledger records, OAP draft-shaped proxy artifacts, and evidence packs on tested local paths.
- Velvet Vault provides tamper-evident evidence under stated canonicalization, hashing, signature, Merkle, and external-anchor hypotheses.
- Velvet can produce a technical record-keeping bundle relevant to EU AI Act Article 12. It is not a legal conclusion, audit outcome, or substitute for counsel review.
- Velvet Assurance can emit signed, aggregate-only control-state attestations for auditor or underwriter review. The attestation omits prompts, action arguments, tool names, customer identities, and per-action records.
- Velvet includes offline verifier packages for Assurance attestations.
- Velvet includes a Claims Pack CLI for vault-backed incident windows when the required ledger, Signed Tree Head, public key, and signing configuration are supplied.
- Velvet Certified Spend is a deterministic budget-safety helper under H1 true hard caps and H2 single-writer atomic accounting.
- Velvet Certified Lockout is a Max-DE helper for posterior-typed classes only.
- Velvet Certified Decisions issues signed, expiring Verdict Certificates (`safe_kill`, `required_inspection`, `refusal`) for posterior-typed irreversible decisions, delta-bounded under the stated hypotheses in exactly one claim currency, with quoted inspection and tail prices in native units.
- Velvet fleet gating can hold the fleet false-lockout rate at or below delta via online e-BH under the documented e-value contract. This is a fleet-fraction guarantee, never a per-decision guarantee.

## Diligence-Supported Claims

- The repo includes deterministic routing, policy, pricing, scoring, and trace primitives.
- The Python admission layer includes warrant, seal, ledger, replay, approval, signing, and evidence-pack helpers.
- The Rust MCP proxy is decomposed by config, transport, enforcement, ledger, OAP artifacts, policy bundle, inventory, and approvals.
- The proxy tests cover pre-execution `tools/call` enforcement, drift rejection, signer fail-closed behavior, approval receipt binding, Streamable HTTP sessions, SSE, replay, and ledger chaining.
- Vault tests cover Merkle inclusion and consistency proofs, STH signing and verification, file and webhook anchoring adapters, recording modes, retention tombstones, and offline verification.
- Attestation tests cover coverage reporting, bundle generation, hash-only records, and refusal of tampered STH input.
- Assurance tests cover deterministic content-free payloads, signature tamper detection, offline Python and JS verifier behavior, scheduled issuance, webhook spooling, and Claims Pack CLI output.
- Budget-safety tests cover the H1/H2 certifying predicate and integer authority boundaries.
- Max-DE tests cover posterior-typed Bernoulli, bounded Dirichlet-categorical, Gamma-rate certificate helpers, and invalid-certificate rejection.

## Surface-Specific Boundaries

| Surface | Safe wording | Do not imply |
| --- | --- | --- |
| Gate | Local pre-execution admission, evidence-bearing decisions, MCP proxy enforcement. | Hosted shared-tenant enterprise governance or complete protocol coverage. |
| Vault | Tamper-evident evidence under stated hypotheses. | Impossible-to-alter storage or public transparency service operated by this repo. |
| Attestation | Technical record-keeping capability relevant to Article 12. | Legal compliance, audit signoff, or regulatory certification. |
| Assurance | Aggregate control-state telemetry for review, offline-verifiable with a public key. | Coverage approval, coverage terms, or pricing effects. |
| Claims Pack | Incident-window pack from vault artifacts plus Assurance verification; the live demo invokes it through a derived Vault bridge. | Full forensic root-cause analysis or coverage outside the supplied artifact window. |
| Certified Spend | Pathwise zero-overshoot only under H1/H2. | Provider-wide billing guarantee or estimate-only cost guarantee. |
| Certified Lockout | Max-DE certificates for posterior-typed classes. | Certificates for every agent action or every irreversible decision. |
| Certified Decisions | Signed, expiring verdict at level delta under the modeled kernel and stated hypotheses; one claim currency per certificate; priced inspection quote in native rounds (dollars only with a stated `dollars_source`). | That a `safe_kill` shows the retired option performed worse in truth; any fixed-mean guarantee from a Bayesian-predictive certificate; insurance pricing, premium effects, or underwriting eligibility. |
| Fleet Gating | Fleet false-lockout rate at or below delta via e-BH under the documented selection-closure contract. | Per-decision error control; validity under evidence-selected submission outside the contract. |

## Forbidden Language Guide

Avoid language that claims:

- impossible alteration of evidence,
- legal compliance or regulatory certification,
- insurance eligibility, coverage, endorsement, or pricing effects,
- a general solution to agent safety,
- market exclusivity or invention of the category,
- complete provider-wide spend protection,
- formal certificates for all runtime decisions,
- hosted enterprise governance unless and until that product exists.

## Experimental Or Roadmap

- Hosted gateway productization.
- Rich enterprise registry, policy UI, and approval workflow orchestration.
- Provider spend normalization beyond explicit hard-cap integrations.
- Live external integration coverage beyond credentialed, explicitly configured demos.
- Independent benchmark claims against live competitor products.

## Competitive Reality

The category is populated. OAP/APort, Diagrid, Permit.io, Cerbos, Okta/Auth0, AP2/x402, Kong, Cloudflare, and related gateway or identity systems cover parts of pre-execution authorization, proof, delegation, policy, and signed spend authority. Velvet should be positioned by verified execution depth, deterministic replay, binding richness, and bounded certificate helpers, not by category invention.
