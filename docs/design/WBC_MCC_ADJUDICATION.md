# WBC/MCC Adjudication — Fable 5 Max vs GPT-5.5 Pro Extended
**2026-07-01. Method: full read of both runs + independent verification of load-bearing disputed claims (2 web searches + 1 primary-source fetch). This file supersedes conflicting statements in either run. Design authority order: this file → earlier Fable design run → earlier GPT design run.**

---

## 1. Citation integrity audit (read this first)

### 1.1 GPT confabulated a standards draft — and marked it [verified]
GPT's design and memo lean heavily on a fabricated OAuth intent-admission draft citation, rated "Extremely high" closeness, cited with a datatracker URL, and used in the executive verdict and moat stack. **That draft does not exist.** Searches return nothing; the OAuth WG mailing-list message announcing the relevant Liu draft family (2026-06-22, "Call for topics for Vienna") lists exactly three drafts split from Agent Operation Authorization — chain-delegation, rego-policy, authorization-evidence — and no intent-admission draft or matching author.

**However, the underlying concept GPT described is real** — it lives in the parent draft it apparently blurred:

### 1.2 The Liu draft family is real, and it's the finding of the review (verified via oauth@ietf.org archive + datatracker)
- **draft-liu-agent-operation-authorization-02** (Mar 2026): defines an "Agent Operation Authorization Token — a JWT representing confirmed authorization for a **specific agent operation**, enforceable at runtime by agents and verifiers… cryptographically verifies user intent, prevents unauthorized or hallucinated actions, and ensures auditable traceability." New JWT claims: `agent_operation_proposal`, `agent_operation_authorization`, `agent_identity`, `evidence`, `context`.
- Split (per expert review) into three drafts, **co-authored with Aaron Parecki and Suresh Krishnan**: `draft-liu-oauth-chain-delegation` (delegation_chain claim: per-hop policy constraints + cryptographic confirmation + consent), `draft-liu-oauth-rego-policy` (Rego policies in OAuth; RS-side logging of policy evaluations for "behavioral authorization… evidence of what behaviors were actually performed"), `draft-liu-oauth-authorization-evidence` (GPT cited this one correctly).
- Slot requested at **IETF 126 (Vienna, this month)**.

**Impact:** This is the closest standards object to the Execution Permit — closer than Transaction Tokens. Fable's run **missed the entire family** (its biggest hole). GPT **detected the signal but laundered part of it through an invented citation** (its biggest hole). Neither run's standards section is complete without §4 below.

### 1.3 Label reliability scoreboard
- **Fable [V] labels:** every one I spot-checked held (Strata 5-second per-tool tokens, PANW/Idira + Portkey acquisition, Okta XAA GA timing, AIUC-1/ElevenLabs underwriting precedent, EU dates matching the June 2026 Parliament/Council votes, AWS SourceIdentity-in-`sessionContext` semantics). No fabrications found. Miss type: **recall** (Liu family, Arcade round, Aembit public pricing).
- **GPT [verified] labels:** one outright fabrication (above); one imprecision with engineering consequences (§2.1); one unverified RFC number (cites "RFC 9943" for SCITT — treat as unconfirmed until checked). Miss type: **precision**. All GPT [verified] claims not independently corroborated by Fable's run or this session must be re-verified before entering any external document. GPT genuinely found real items Fable missed: Liu family (via the real authorization-evidence draft), **Arcade $60M Series A** (SYN Ventures, Morgan Stanley, Wipro — WSJ), **Aembit AI Teams public pricing $20/agent/mo** (verify before quoting), Cequence Agent Access Keys, Auth0 May-2026 agent identity releases.

---

## 2. Technical corrections both runs need

### 2.1 CloudTrail channel semantics — Fable is right, GPT is imprecise
GPT: session tags "appear as principal tags in CloudTrail logs" (implying per-event). Correct model (Fable, matching AWS docs): **per-event** channels are `sessionContext.sourceIdentity` and the session ARN/`RoleSessionName` inside `userIdentity`; **session tags land in the AssumeRole event only** (transitive tags persist through chaining). All reconciliation join logic keys on SourceIdentity + session name; tags are the per-session enrichment channel. GPT's fixture and extractor specs must be adjusted accordingly.

### 2.2 GPT's trust-policy bug
GPT's generated trust policy pins `"aws:RequestTag/vlt:ph8" = ${EXPECTED_POLICY_HASH8}` — this **breaks every mint on every policy-bundle update** and couples IAM state to policy releases. Drop the exact-hash condition; keep Fable's version: `sts:SourceIdentity` StringLike `vlt.1.*`, VMS-only principal, `ForAllValues` tag-key allowlist, SCP backstop. **Adopt from GPT:** the EventBridge alert (role assumed without `vlt.` SourceIdentity prefix) and IAM Access Analyzer check as part of the pilot setup validator.

### 2.3 SERVICE_ACTOR carve-out — Fable only
AWS does not capture SourceIdentity when a service/service-linked role acts on the principal's behalf. Fable's MCC partition therefore defines `SERVICE_ACTOR` (excluded from the coverage denominator, count disclosed). GPT's "provider background service calls" default exclusion gestures at this without the mechanism. **Fable's treatment is mandatory** — without it the coverage denominator is wrong and an auditor will find it.

### 2.4 Both correct, keep: 900 s STS floor ⇒ single-use is enforced by atomic claim + policy narrowness, never by expiry; never market short-lived-credential claims on AWS. PackedPolicySize headroom assertion (Fable WO-2) stays a kill-tripwire.

---

## 3. Merge decisions (per axis; the losing text is not used)

| Axis | Winner | Adopt from the other side |
|---|---|---|
| Executive verdict | **Merge**: Fable's "kill not triggered; L5 bundle unoccupied" + GPT's honest "~70% of primitives commoditized" framing | The claim is the bundle, never the primitives |
| External name | **Fable: Warrant-Bound Credentials** — ties to Velvet's warrant vocabulary, collision-free, distinctive. GPT's "Decision-Bound Credentials" is clearer but generic — a name Strata could adopt next quarter, which is a gift | Keep "Decision-Bound" as the plain-English explainer line, not the name |
| Category | Fable: **Provable Mediation** (GPT's "Verifiable Agent Mediation" acceptable alternate; decide in WO-0 and never revisit) | — |
| Binding scale | **Merge into 0–7**: 0 static · 1 identity · 2 scope · 3 request-bound · 4 decision-bound (signed, offline-verifiable permit + atomic claim) · 5 ledger-included · 6 upstream-log-carried · 7 coverage-certified. GPT's granularity, Fable's per-backend scoring + evidence-pointer discipline. Map: gateways 1–2, Strata ≈3, Pipelock ≈4 (evidence axis), Velvet AWS target = 7 | — |
| Object model | Fable's PermitLineage (CBOR, delta-on-permit) | **GPT's `CredentialMintReceipt`** — adopt wholesale. Separate signed, ledger-included mint artifact enables mint-vs-use reconciliation (mint with no service events; events with no mint receipt) and its fixture class. Fold into WO-2 |
| Derivation fn | Fable §6.2.2 (incl. `compile()` as total function per tool class, fail-closed) | GPT's generic 13-step ordering as doc structure |
| Verification protocol | **Fable** (exit codes; INDETERMINATE never coerced; decidable projection-table semantic check; mutation testing ≥90%) | GPT's `log_integrity_insufficient` verdict class; extra fixtures: retired-key-after-compromise-cutover, CloudTrail delivery delay across window boundary, API-without-resource-level-IAM |
| MCC math | **Fable** (stratified, never-blended, CP one-sided lower bound headline, SERVICE_ACTOR, degraded=UNMATCHED, dual-chain binding to STH + CloudTrail digests) | GPT: k=10 minimum-bucket suppression; `zero_event_window` flag; hard log-completeness gate (no completeness ⇒ no exact coverage claim, sampled interval only); log-watermark "window pending" semantics for delayed delivery |
| Certificate calculus | Both agree MCC ≠ Max-DE; Fable's composition rules (pooled-count CP; disjoint-scope-only fleet aggregation) | GPT's name for the type: "observational boundary certificate" — good vocabulary |
| Threat model | Fable's table | GPT: explicit **three-key separation** (admission / mint / STH signer; VMS verifies admissions but cannot sign them) + the no-resource-level-IAM row (⇒ broad-scope classification + tier escalation) |
| Failure/friction | Fable (tiered fail-closed; measure-before-market latency) | GPT: `credential_process` helper + metadata-endpoint sidecar as delivery paths; "verifier down = zero runtime impact" as an explicit doc line; reconciliation throughput target (100k events ≤10 min) and verify ≤25 ms/event as bench targets. Reject GPT's ≤750 ms p95 mint target as too lax; keep Fable's ≤150 ms target-with-honesty-clause |
| Pricing | Identical ladders ($7.5k/$15k/$25k) — convergent validation | GPT's hybrid platform pricing structure (base + per-account + per-1k-actions + per-agent) is more VC-legible than pure metering; keep Fable's 30%-services tripwire. Design-partner ACV band: $50–100k |
| Milestones | Fable's (incl. underwriter-letter definition + vendor-scan tripwire at every gate) | GPT's dated-table format. **Correction to both:** neither knew the real calendar — DIANA Jul 3, NorthArrow Jul 14. Shift all pre-Jul-15 external milestones right ~2 weeks; scrub/build work proceeds in background per the existing launch plan |
| Work orders | **Fable's WO-0…8** (gates G1–G3, chaos check, mutation testing, kill-tripwire re-scan at gates, 11–14-day critical path) | GPT: standalone **IAM/Terraform generator** WO (split out of Fable WO-6); **credential delivery path** WO (proxy injection + credential_process + sidecar); the **"ruthless cuts if behind"** section verbatim; mint-receipt work folded into WO-2 |
| Objection bank | Merge (Fable's 8 + GPT's #3 Aembit, #7 offline-verification-demand, #10 malicious-admin) — 11 total | — |

## 4. New section neither run had: the Liu-draft play (time-boxed to this month)
1. **Read all four Liu drafts** (agent-operation-authorization-02 + the three splits) before any external claim about "nobody standardizes admission." The honest sentence becomes: *"IETF work is emerging on agent operation authorization tokens; none of it defines credential derivation from admission proofs, transparency-log inclusion, upstream audit-plane lineage, or coverage certification — Velvet implements the emerging vocabulary and adds the evidence layer."*
2. **Engage at IETF 126 (Vienna, this month):** submit review comments on `draft-liu-oauth-authorization-evidence` + the parent draft; position the Execution Permit as a concrete implementation profile; note the gaps (ledger inclusion, offline verification, provider-log landing) as proposed considerations. Remote participation is fine. This is simultaneously: distribution channel, prior-art timestamp, and the strongest possible answer to the "Okta ships it in a quarter" objection — **Parecki co-authoring these drafts means Okta-ecosystem energy is already behind the envelope**; Velvet's move is to be the reference implementation underneath it, not a parallel format. (This also retroactively fixes GPT moat item #4, which cited the fabricated draft.)
3. Add all four drafts to the standing kill-tripwire vendor scan.

## 5. Scoreboard and meta-lesson
- **Research recall:** GPT. **Research precision & honesty:** Fable (no fabrications found; per-event/per-session CloudTrail distinction; SERVICE_ACTOR; refused unmeasured marketing numbers). **Design rigor:** Fable. **Artifact completeness:** GPT (mint receipt, wire format, DX paths, dated milestone table). **Strategic verdict:** convergent — two frontier models under adversarial prompts independently landed on the same answer (L5/B7 bundle unoccupied; adopt standards; AWS-first; $15k pilot; benchmark capability #6). Convergence across model families is the strongest validation this concept has received.
- **Meta-lesson for the workflow:** max-compute produced 5× the volume with a fabricated [verified] citation inside it; the compressed run had a recall gap. Neither alone was sufficient; the two-model-plus-adjudication pattern caught both failure modes. Standing rule going forward: **any [verified]/[V] claim that is load-bearing (enters a pitch, a spec, a public doc, or a kill decision) gets independently re-verified regardless of which model produced it.**

## 6. Immediate actions
1. Apply §2 corrections + §3 merge into a single `WBC_MCC_DESIGN_v0.2.md` (mechanical edit — one Codex pass using this file as the diff spec).
2. Read the four Liu drafts; draft IETF review comments (≤1 page each); check the IETF 126 remote-participation deadline this week — it's the only calendar-urgent item.
3. Purge the fabricated draft from every GPT-derived artifact before anything ships externally.
4. Everything else holds the existing sequence: DIANA Jul 3 → NorthArrow Jul 14 → OSS launch window → WBC build (Fable's WO gates + GPT's three adopted WOs).
