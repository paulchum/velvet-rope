# Warrant-Bound Credentials (WBC) + Mediation Coverage Certificates (MCC)
## Canonical Design v0.2 — MERGED
**2026-07-01 · Coriolis Labs / Velvet · Supersedes both model runs. Provenance: Fable 5 design as base (rigor winner), GPT-5.5 Pro components adopted per WBC_MCC_ADJUDICATION.md §3, all §2 corrections applied, §4 Liu-draft strategy added. Claim labels: [V] verified via primary/secondary source · [K] stable knowledge · [I] inferred · [S] speculative · [verify] must be re-checked before external use.**

---

## 0. Verdict and claim boundary

~70% of the primitives are commoditized: credential brokering, JIT/ephemeral minting, per-invocation policy checks, delegation-chain integrity, centralized audit logs (Strata mints 5-second per-tool tokens [V]; PANW/Idira brokers agent identity, Portkey acquisition Apr 2026 [V]; Okta XAA is a formal MCP authorization extension, OIN GA Aug 2026 [V]; AWS's own blog prescribes session tags for agent distinguishability [V]; Aembit agentic IAM GA at $20/agent/mo public pricing [verify]).

**The unoccupied position is the bundle (binding level 7):** a credential **derived from a signed, per-action admission proof**, whose lineage **lands in the upstream provider's own audit plane**, verifiable **offline by a third party who trusts neither the operator nor Velvet's database**, rolled into a **signed coverage metric with exact statistical bounds**. No vendor, standard, or OSS project ships that bundle [V-scan, 2026-07-01]. Kill-check: **not triggered.** Standing tripwires in §15.

The claim, verbatim, everywhere: **mediation made provable and measurable** — never solved-bypass framing.

## 1. Standards posture

### 1.1 The Liu draft family (closest standards object — engage this month)
`draft-liu-agent-operation-authorization-02` (Mar 2026) defines an **Agent Operation Authorization Token**: a JWT representing "confirmed authorization for a specific agent operation, enforceable at runtime by agents and verifiers," with claims `agent_operation_proposal`, `agent_operation_authorization`, `agent_identity`, `evidence`, `context` [V]. Split per expert review into three drafts co-authored with **Aaron Parecki** (Okta) and Suresh Krishnan [V]: `draft-liu-oauth-chain-delegation`, `draft-liu-oauth-rego-policy`, `draft-liu-oauth-authorization-evidence`. Slot requested at **IETF 126, Vienna, July 2026** [V].

What none of them define [V, by omission]: credential **derivation** from the admission artifact, transparency-log inclusion/consistency, upstream cloud-audit-plane lineage, single-use claim semantics, or coverage certification. **Posture: implement, extend, and comment — never compete.** The Execution Permit is positioned publicly as a concrete implementation profile of the emerging vocabulary; review comments filed on authorization-evidence + parent draft before/at IETF 126. This is distribution, prior-art timestamping, and the "Okta ships it in a quarter" rebuttal in one move. NOTE: a fourth draft cited in one research run ("intent-admission", author Jiang) **does not exist** — purge from all artifacts.

### 1.2 OAuth Transaction Tokens — ally, not killer
draft-ietf-oauth-transaction-tokens-08 (+ Transaction Tokens for Agents extension) carries identity/purpose/context + `txn` correlation ID; binds no policy hash, no request hash, no ledger inclusion, no offline verification, no single-use state [V]. **WBC ships a Txn-Token-compatible JWT profile** for OAuth-speaking backends (§6.5). Line: "A Txn-Token says *what transaction this is*; a WBC proves *that this exact action was admitted, by which policy, and where that proof lives*."

### 1.3 Capability tokens and PCA
Biscuit/Macaroons/UCAN/ZCAP-LD prove **standing delegated authority under constraints**; a WBC proves **a single adjudicated event** (request hash h admitted under policy p at time t, ledger entry n) [K]. Composable, not competitive; Biscuit as transport = v2 option. Historical/deprecated terminology note: Appel-Felten Proof-Carrying Authorization and Necula's Proof-Carrying Code are cited only as intellectual ancestry; the acronym "PCC" is retired everywhere because it also collides with Apple Private Cloud Compute [K].

### 1.4 Adjacent machinery
SPIFFE/WIMSE supply workload identity as an admission *input*. SCITT-compatible receipt export is roadmap (WO-B10 stretch). DPoP (RFC 9449) / mTLS (RFC 8705) bind token→holder; WBC binds credential→decision — orthogonal axes, compose where the backend supports it. RFC 8693 is the mint mechanism for OAuth backends.

## 2. Cloud mechanics — corrected channel model

### 2.1 AWS (reference backend) [V]
| Channel | Limits | Where it lands in CloudTrail |
|---|---|---|
| `SourceIdentity` | 2–64 chars, `[\w+=,.@-]`, not `aws:`-prefixed; **immutable for session**; persists through chaining | `requestParameters.sourceIdentity` in AssumeRole event **and** `sessionContext.sourceIdentity` in **every subsequent service event** |
| `RoleSessionName` | 2–64 chars, same charset | Embedded in `userIdentity.arn`/`principalId` of **every event** |
| Session tags | ≤50; key ≤128, value ≤256; counts against PackedPolicySize | **AssumeRole event only** (`requestParameters.tags`); transitive tags persist through chaining |
| Inline session policy | ≤2,048 chars plaintext; counts against PackedPolicySize | AssumeRole event |
| Trust-policy conditions | `sts:SourceIdentity`, `sts:RoleSessionName`, `sts:TagSession`, `sts:SetSourceIdentity`; `aws:SourceIdentity` usable in resource policies for the session | — |
| CloudTrail integrity | SHA-256 hash chain + signed hourly digest files | MCC binds the upstream's own tamper-evidence chain (§9.6) |

**Corrected join-key rule (both prior docs' extractors must obey this):** per-event joins key on `sessionContext.sourceIdentity` (permit_id) + session ARN (ledger_seq); **tags are per-session enrichment only**, read from the AssumeRole event.

Caveats designed-around [V]: (i) SourceIdentity **values are strings anyone with assume rights could set** — verification is cryptographic (ledger lookup + signature), never string trust; forged `vlt.*` with no ledger entry ⇒ `LINEAGE_INVALID`, an alarm, not noise. (ii) SourceIdentity is **not captured for service/service-linked actors** ⇒ mandatory `SERVICE_ACTOR` class (§9.2). (iii) **AssumeRole floor = 900 s** ⇒ single-use is enforced by atomic claim + policy narrowness, never by expiry; no short-lived-credential marketing on AWS. (iv) Effective permissions = role policy ∩ session policy ∩ SCP/boundaries. (v) STS default quota ~600 req/s/account/region [verify].

### 2.2 Backend matrix
| Backend | Lineage on credential | Lands in provider audit log | Verdict |
|---|---|---|---|
| AWS STS | SourceIdentity + RoleSessionName + tags + inline policy | Yes, per-event + per-session | **v1 reference — level 7 capable** |
| HashiCorp Vault dynamic secrets | lease/username template `vlt_<pid8>_*` + audited request metadata; TTL to seconds | Yes (audit devices) | v1.1 — tightest temporal binding |
| GitHub App installation tokens | repo/permission-scoped; no free metadata field | Partial (time/installation correlation) | v1.1 at level 4, weak landing — reported as such |
| GCP WIF / SA impersonation | OIDC custom claims verified at token issuance; delegation info in audit logs; no per-resource-event free field | Partial | v2 spike (WO-B11) |
| Azure Entra WIF | constrained FIC objects; per-permit subject awkward | Partial | research only |
| Postgres (via Vault or broker) | short-lived role / `SET ROLE` + `application_name='velvet pid=… seq=…'` | Yes with pgaudit | v1.1 demo backend |

**Rule: coverage is scored and reported per backend at its binding level (§7); never blended.**

## 3. Vendor landscape (one-line form; full tables in the two source docs)
Strata ≈ level 3 (decision happens; not a signed replayable artifact; prevention posture, no residual measurement) [V]. PANW/Idira, Okta XAA, Aembit, Cequence AAK, Arcade ($60M A [V]), gateways, NHI platforms ≈ levels 1–3, logs-you-trust. Pipelock ≈ level 4 on the evidence axis (receipts in **its** chain; nothing rides into the upstream plane; no coverage metric) [B/V]. Attested Intelligence: evidence bundles + unpublished patent app 19/433,835 [V-status]. **Differentiation sentence:** *everyone above can show you their logs; none can hand a third party a credential-derived proof anchored in the provider's own audit record and a transparency log — and none will sign a coverage number.*

## 4. FTO and defensive publication
19/433,835 claims unpublished (expect ~mid-2027) [V-status/I-timing]. Public risk surface (signed Ed25519+Merkle governance artifacts) overlaps Velvet's *existing* evidence layer more than the WBC/MCC delta. Mitigations: defensive publication (tech report with derivation, taxonomy, MCC math, threat model — immutable timestamp) **before** OSS license lock; 2-hour patent-attorney consult; quarterly Patent Center monitoring; phrase-searches logged at each gate. Not legal advice.

## 5. Object model

### 5.1 PermitLineage (extends the existing Execution Permit; CBOR, deterministic encoding, covered by the permit's Ed25519 signature)
```
PermitLineage {
  v: 1
  permit_id: ULID                       # 26-char Crockford
  request_hash: sha256                  # existing canonicalization
  policy_hash: sha256                   # policy bundle
  schema_hash: sha256
  decision: enum{execute}               # only 'execute' reaches derivation
  ledger_seq: u64
  ledger_leaf_hash: sha256
  sth_hint: bytes8                      # covering-STH prefix at mint (advisory)
  audience: string                      # "aws:sts:<acct>:role/vlt-<class>"
  backend_profile: string               # "aws-sts-v1" | "vault-dynamic-v1" | ...
  scope: { actions[], resource_templates[], conditions_hash }   # canonical, pre-projection
  identity_ctx_hash: sha256
  minted_at / expires_at: unix_ms
  claim_nonce: bytes16                  # single-use; existing atomic claim store
  issuer_kid: string
}
```
Full hashes live in the permit/ledger; **provider metadata carries only compact handles**: `pid` (b32), `ph16`/`ph8`, `seq`, `sth8`, `aud8`, `req16`/`req8`. Never tool names, args, identities, prompts, or resource contents in provider tags.

### 5.2 CredentialMintReceipt (adopted from GPT run — new signed, ledger-appended artifact)
```
CredentialMintReceipt {
  v: 1, mint_id: ULID, permit_id, backend_profile,
  issued_at, expires_at,
  provider_handle: { type, account_id, role_arn_hash, role_session_name, source_identity }  # or backend equivalent
  embedded_handles: { pid, ph8, seq, sth8, aud8, req8 },
  session_policy_hash: sha256,
  claim_id, claim_store_receipt_hash,
  signer_kid, sig: Ed25519
}
```
Enables **mint-vs-use reconciliation**: a mint with no subsequent service events is `MINTED_UNUSED` (reported); a lineage-bearing event with no mint receipt is an alarm. Every mint appends the receipt to the Vault before the credential is released.

## 6. Derivation

### 6.1 Preconditions (Terraform module, WO-3)
Per-tool-class roles `vlt-<class>`: trust policy allows `sts:AssumeRole`, `sts:TagSession`, `sts:SetSourceIdentity` **only** to the Velvet Minting Service (VMS) principal, with `Condition: StringLike {"sts:SourceIdentity": "vlt.1.*"}` and `ForAllValues:StringEquals aws:TagKeys` allowlist (`vlt:ph16, vlt:rh16, vlt:seq, vlt:tier`). **No exact-hash tag pins in trust policies** (breaks on every policy release — corrected from GPT run). Optional SCP: deny AssumeRole on `role/vlt-*` except VMS ARN. Setup validator: EventBridge alert on assumption without `vlt.` SourceIdentity prefix + IAM Access Analyzer check (adopted from GPT run). Agent holds **nothing**.

### 6.2 AWS mint (VMS, after atomic permit claim)
```
AssumeRole(
  RoleArn         = permit.audience,
  RoleSessionName = "vlt-" + b32(ledger_seq),          # per-event channel
  SourceIdentity  = "vlt.1." + permit_id,               # 32 chars; per-event channel; immutable
  Tags            = [vlt:ph16, vlt:rh16, vlt:seq, vlt:tier],   # AssumeRole-event channel
  Policy          = compile(admitted_action),            # ≤2,048 chars; deny-by-default
  DurationSeconds = 900
)
→ append CredentialMintReceipt to Vault → release credential
```
`compile()` is a **total function per tool class**, shipped as versioned hash-pinned projection tables (tool schema → exact IAM Action list + Resource ARN templates from canonical args). Non-projectable request ⇒ typed fail-closed refusal, no partial mint. Compilation caps at 1,800 minified chars for provider overhead headroom; PackedPolicySize headroom ≥30% asserted per class (kill-tripwire). No `Action:*`/`Resource:*` except explicitly approved read-only profiles. APIs without resource-level IAM ⇒ tier escalation + `BROAD_SCOPE` marking in MCC. Pilot classes: `s3-object-write`, `dynamodb-item-write`.

### 6.3 Vault (v1.1): role-per-class; VMS-only mint; lease TTL = min(permit TTL, 120 s); lineage in audited request metadata + username template; single-use via revoke-on-first-verify or wrapped one-time response.

### 6.4 GitHub (v1.1): App key held only by VMS; repo+permission-scoped installation tokens; correlation-only landing; honest level-4 reporting.

### 6.5 OAuth/Txn-Token profile: RFC 8693 exchange at VMS-as-TTS; token type `txn_token`; standard claims per draft-08 (+ agents-extension `act`/`sub`); Velvet claims in `rctx`: `vlt_permit`, `vlt_ph16`, `vlt_seq`, `vlt_sth8`; DPoP-bound where supported. *WBC = strict superset of a Transaction Token; also expressible with `draft-liu-oauth-authorization-evidence` vocabulary as it stabilizes.*

### 6.6 Key custody (three-key separation, adopted from GPT run)
Admission signing key ≠ mint-receipt key ≠ STH/Vault key, distinct kids/rotation. **VMS verifies admission signatures but holds no admission signing rights.** KMS/HSM-backed in production; dev keys carry loud non-production kids. Compromise runbook: revoke VMS trust, rotate kid, re-anchor, publish signed key-status statement; cutover sequence disclosed in MCC metadata; events under a compromised-window kid classified `INDETERMINATE`, never MATCHED.

## 7. Binding scale (merged, 0–7 — replaces L0–L5 and B0–B7)
| Level | Binds | Verify model | Occupants |
|---|---|---|---|
| 0 | static secret | trust the vault | legacy |
| 1 | workload/agent identity + expiry | trust the IdP | SPIFFE, NHI vendors, AgentCore |
| 2 | + scope/audience/holder (DPoP/mTLS) | online, trust-domain keys | Okta XAA, PANW broker, gateways, Txn-Tokens |
| 3 | + a per-invocation authorization decision occurred | trust the decider's logs | Strata, PDPs |
| 4 | + signed admission proof (request hash, policy hash, typed decision, atomic claim) verifiable offline | offline, issuer key | Pipelock receipts (evidence axis); Velvet permit minimum |
| 5 | + ledger inclusion & consistency proofs | offline, without trusting issuer DB | Velvet Vault |
| 6 | + lineage landed in the **upstream provider's audit plane** | upstream log = second witness | **WBC/AWS** |
| 7 | + windowed reconciliation + signed aggregate MCC | third-party re-derivable | **target; unoccupied** |
Scored per backend (AWS→7; Vault→7-tight; GitHub→4-weak-landing; GCP v1→4/[verify]).

## 8. Offline verification — `velvet verify-lineage`
**Inputs:** upstream event (CloudTrail JSON; adapter interface) · permit (CBOR) · **mint receipt** · inclusion proofs for both · covering STH (+ optional consistency proof) · pinned key set · hash-pinned projection-table bundle · backend profile descriptor.
**Algorithm:** (1) parse event; extract `sessionContext.sourceIdentity`, session ARN, eventSource/Name/resources, `readOnly`, `invokedBy`; validate source-integrity wrapper if provided. (2) structural gate on `vlt.1.` prefix. (3) permit signature (pinned kid). (4) mint-receipt signature + permit_id linkage. (5) semantic check: event (service, action, resources) ⊆ projection of admitted action under the pinned table — decidable lookup, not policy simulation. (6) inclusion proofs (permit + receipt) under STH; STH signature; window consistency. (7) freshness: eventTime ∈ [minted_at, expires_at] ± skew; cross-batch duplicate-session detection. (8) structured verdict.
**Verdicts (exit codes):** `0 LINEAGE_VERIFIED` · `10 LINEAGE_INVALID` · `11 DARK_ACTION` · `12 UNMATCHED_SESSION` · `13 REPLAY_SUSPECT` · `14 MINT_RECEIPT_MISSING` · `15 LOG_INTEGRITY_INSUFFICIENT` · `20 OUT_OF_SCOPE` · `30 INDETERMINATE` (never coerced).
**Conformance fixtures (fixtures precede features):** golden — valid single-use; chained-role event retaining sourceIdentity; Vault-path golden. Malicious — forged sourceIdentity w/o ledger entry; valid permit + wrong policy_hash; replayed permit on second session; non-included ledger_seq; split-view STH pair; tampered event vs digest; **valid permit, no mint receipt**; **receipt signed by retired kid after cutover**; event resource outside projection; cross-audience replay. Edge — 64-char boundaries; PackedPolicySize truncation; ±300 s skew; `invokedBy` service actor; readOnly misclassification; **delivery delay across window boundary**; **API without resource-level IAM**; permit TTL < 900 s.

## 9. MCC math

**9.1 Universe.** `U(W)` = consequential events in window `W` under classifier `C_v` — versioned, hash-pinned ruleset (eventSource/eventName/readOnly=false/resource class) + mandatory-include catalogs (IAM/STS mutations, KMS grants, in-scope data-plane writes, charge-bearing actions, code-execution/CI mutations). `C_v` hash embedded in every MCC; classifier change ⇒ new certificate lineage.
**9.2 Partition (total, disjoint).** {MATCHED, DARK, INVALID, UNMATCHED, REPLAY, **SERVICE_ACTOR** (invokedBy/service-linked — excluded from denominator, count disclosed), **MINTED_UNUSED** (informational, from receipts), INDETERMINATE (denominator only)}.
**9.3 Completeness gate (adopted).** Exact coverage `p = |MATCHED|/|U|` may be asserted **only if** completeness holds: provider logging enabled for selectors; sink integrity (org trail + Object Lock + digest validation or equivalent); no detected gaps; STH consistency covers all permits/receipts in `W`. Otherwise `log_integrity = insufficient` and only a sampled interval may be presented. `zero_event_window=true` when `N=0`.
**9.4 Sampled regime.** Clopper–Pearson exact interval; **one-sided 95% lower bound is the headline**; committed sampling seed; CP chosen for guaranteed conservative coverage (never overstates) — correct posture for a signed attestation. Stratify by risk tier × backend; per-stratum intervals; **blended headlines impossible by schema**.
**9.5 Watermark semantics (adopted).** CloudTrail delivery lag ⇒ window status `pending` until the log watermark passes `t1`; MCCs are issued only on watermarked windows.
**9.6 Binding.** Each MCC binds (STH_a, STH_b, consistency proof) + CloudTrail digest-chain refs covering `W` + `C_v` hash + projection-table hash + verifier version + key set + selector config. `velvet verify-mcc` re-derives counts from the customer-held corpus; no trust in Velvet's DB.
**9.7 Privacy.** Aggregate-only, identical discipline to existing Assurance attestations: no tool names, args, identities, event IDs, prompts, resource names; **k=10 minimum bucket suppression/merging** (adopted); sealed per-event annex is customer-only, outside the attestation.
**9.8 Calculus fit.** MCC is an **observational boundary certificate** (GPT's term), not Max-DE: it certifies historical coverage over observed logs, never future safety. Composition: disjoint-window concatenation (pooled counts; CP recomputed on pooled Bernoulli trials); fleet aggregation over disjoint scopes only (scope-hash disjointness enforced at compose time). Max-DE bridge = paper question [S].

## 10. Threat model
| Adversary | Outcome | Mechanism |
|---|---|---|
| (a) Prompt-injected agent | Prevented on mediated paths; residual bounded | No credentials to exfiltrate; single-use audience-bound permit; session policy = projection of the admitted request |
| (b) Lazy/misconfigured deployment | Detected, quantified | Dark count in MCC; setup validator; shadow→warn→enforce |
| (c) Malicious developer (repo access) | Detected | Cannot mint (IAM); side-channel actions land DARK in the upstream plane — the MCC headline story |
| (d) Infra admin minting outside Velvet | Partially prevented; detected | SCP (prevention); other-role actions ⇒ DARK/UNMATCHED; forged `vlt.*` strings ⇒ INVALID (louder than silence) |
| (e) Velvet admission-key compromise | Not prevented; detected, bounded | Three-key separation; kid rotation; split-view detection via anchors; compromised-window events ⇒ INDETERMINATE; published cutover |
| (f) Mint-key / VMS-role compromise | Not prevented; detected | Receipts missing/abnormal; AWS logs show the minting principal; SCP limits blast radius; severe if ledger keys also lost (stated) |
| (g) Upstream log tampering/deletion | Out of prevention scope; partially detected | Digest-chain validation bound into MCC; Velvet-mints-without-upstream-sessions cross-count ⇒ named deletion-signal anomaly |
| (h) TOCTOU claim→use | Bounded, disclosed | Atomic claim; residual = 900 s window; exact-resource policy; replay detection; break-glass role-policy edit; stated in every MCC assumption register |
| (i) Confused deputy / cross-audience replay | Prevented | audience in signed lineage; per-backend roles; SourceIdentity immutability; `aud` in Txn profile; verifier rejects mismatch |
| (j) API without resource-level IAM | Not prevented | Tier escalation + BROAD_SCOPE classification; least-privilege impossibility disclosed |

## 11. Friction, failure, delivery
**Latency:** mint target p95 ≤150 ms in-region — **measured (WO-2 bench), never marketed before measurement**; verify-lineage ≤25 ms/event offline; reconciliation ≥100k events/10 min on a laptop (bench targets, adopted). **Failure tiers:** Tier A (destructive/financial) fail closed → typed `defer`; Tier B fail closed + page; Tier C degrade-to-warn on a pre-provisioned narrow fallback role **without lineage**, emitting a signed degradation record — degraded events count **UNMATCHED**, coverage takes the hit honestly. **Verifier availability has zero runtime impact** (doc line). **Rollout:** Phase 0 shadow (mint-and-log in parallel; MCC shows would-be coverage + real darks — this is the pilot) → Phase 1 warn → Phase 2 enforce per class, Tier A first → Phase 3 scheduled MCC issuance. **Delivery paths (adopted):** MCP-proxy credential injection (primary); AWS `credential_process` helper; local metadata-endpoint sidecar; CI via `AWS_PROFILE=velvet-wbc`. DX contract: the agent-side change is **deleting the secrets**.

## 12. Anti-scope (verbatim in docs; claim-language CI enforced)
No solved-bypass framing — mediation made provable and measurable; dark actions on ungated paths are found, not prevented. No legal-compliance conclusions (evidence aligned to Article-12-style record-keeping and CIS controls; not conformity assessment). No runtime LLM in the decision loop. No TEE claims. No sub-15-minute AWS credential claims. No cross-backend aggregate coverage claims across different binding levels. Not a SIEM; not anomaly detection. Verifiers trust published Velvet keys + arithmetic, not Velvet's UI or database. No complete prevention of malicious cloud admins.

## 13. Benchmark capability #6 — Lineage Verifiability & Bypass Accountability
Per adapter, evidence-pointer discipline as capabilities 1–5: **(6a)** binding level 0–7 per backend; **(6b)** does an unmediated action produce a distinguishable record in an audit plane outside the vendor's control (Y/N + pointer); **(6c)** third-party offline verification of a single action without vendor-DB trust (protocol pointer or N); **(6d)** signed coverage metric with defined window semantics (spec pointer or N). Test battery: credential-without-permit ⇒ dark/detected; permit-without-lineage ⇒ ≤5; lineage event ⇒ 6; mixed window ⇒ 7 iff counts+signature verify; cross-audience replay ⇒ fail; tampered policy hash ⇒ fail. Rubric published **before** any competitor is scored; competitor rows ship unscored-pending-evidence with a self-report PR template.

## 14. Pilot definition of done ($15k / 3 weeks / shadow / AWS)
Terraform applied idempotently <10 min on a fresh account; two tool classes in shadow; ≥95% of consequential events classified (no UNCLASSIFIED); watermarked 7-day MCC signed with per-tier lower bounds + anomaly classes; every dark event triaged with the customer; verifier + fixtures run clean on a customer laptop offline; sealed annex delivered; teardown residue-free; board one-pager. Pilot cannot fail: high coverage ⇒ auditor/underwriter artifact; darks found ⇒ enforcement Phase-2 justification.

## 15. Decisions log & tripwires
WBC name final; category "Provable Mediation"; scale 0–7; AWS ref / Vault+GitHub v1.1 / GCP-Azure v2; mint receipt mandatory; SourceIdentity `vlt.1.<ulid>`, session name `vlt-<seq_b32>`, tags ph16/rh16/seq/tier; CP one-sided lower bound headline; SERVICE_ACTOR excluded-and-disclosed; INDETERMINATE denominator-only; degraded=UNMATCHED; completeness gate before exact claims; k=10 suppression; fixtures precede features; defensive publication before license lock; Liu-draft engagement this month. **Tripwires re-scanned at every gate (15 min, logged):** Strata signed decision artifacts; Okta VDC scope creep toward action proofs; Pipelock upstream-plane lineage; Attested Intelligence claims publication; Liu-draft adoption of derivation/coverage semantics; any cloud provider shipping a native signed-decision field.
