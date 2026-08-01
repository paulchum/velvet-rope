# Velvet Assurance Underwriting Profile

This profile explains the signed control-state attestation emitted by Velvet for
insurance and audit review. It is written for underwriters, brokers, and audit
teams who need production control-state evidence without receiving customer
content.

The attestation is aggregate-only. It contains no prompts, action arguments,
tool names, customer identities, or per-action records. Verification is based on
the deployment public key, period continuity, signed tree heads, Merkle
consistency proofs when supplied, and count checks against vault growth.

Attestations are intended to be issued on a fixed cadence, typically hourly or
daily, by an outbound scheduler such as cron, a systemd timer, or a Kubernetes
CronJob. There is no inbound network service on the insured deployment for this
surface. If signing or anchoring is degraded, the reportable state is a signed
attestation with the relevant degraded flag, not a silent gap.

## Field Guide

| Field | What it evidences | What it cannot evidence | Relevant loss scenario |
| --- | --- | --- | --- |
| `period` | The exact reporting window covered by the signed snapshot. | Whether all business activity was routed through Velvet outside this window. | Silent telemetry gaps, post-loss selective disclosure. |
| `deployment_id` | A salted stable hash for one deployment, unlinkable across deployments without the salt. | The legal entity, customer, region, or system name. | Portfolio tracking without sharing customer identifiers. |
| `gateway_liveness` | Count of decisions observed and maximum no-decision gap inside the period. | Whether the underlying business was idle or bypassing Velvet during a quiet gap. | Missing control-plane operation, possible disabled gateway. |
| `policy_state` | Active policy hash, signature status, and last observed change time. | Whether the policy was well designed or appropriate for the insured's risk. | Stale policy, unauthorized policy update, disputed control state at loss time. |
| `decision_counts` | Aggregate admit/block/escalate/defer/skip outcomes by normalized risk class. | Why a specific action was admitted or blocked. | Control posture shift, unusual block/escalation rates, ignored high-risk action mix. |
| `escalation_integrity` | Fraction of escalated actions with valid approval receipts. | Whether the human approver made a good business decision. | Failure-to-escalate or unapproved execution disputes. |
| `drift_rejections` | Count of dispatch refusals caused by canonical-action mismatch. | The content of the changed action. | TOCTOU manipulation between approval and dispatch. |
| `certificate_coverage` | Fraction of spend-class actions with deterministic budget certificates and irreversible-class actions with Max-DE lockout/inspection evidence. | Whether every action type is covered by a formal certificate. | Bounded financial-loss arguments under stated hypotheses H1/H2; irreversible action review coverage. |
| `budget_safety` | H1/H2 conformance flags, maximum configured cap, and zero observed overshoot from available certificate metadata. | Provider billing truth outside the observed ledger or cross-provider hard caps not represented in the certificate. | Spend overrun, double-spend from non-single-writer accounting, budget authority dispute. |
| `evidence_plane` | Latest signed tree size/root hash, external anchor freshness, and retention preset. | That retained records are useful for model-quality or root-cause analysis without separate content access. | Missing vault growth, missing external anchoring, retention mismatch. |
| `degraded_flags` | Whether signing, anchoring, or fail-open conditions were reported as degraded. | The operational root cause of degradation. | Fail-closed posture review, evidence-weight adjustment during outage windows. |

## Verification Model

An underwriter or auditor verifies a series offline with the deployment public
key. The verifier fails closed on unknown schema versions, invalid signatures,
period gaps or overlaps, tree-size decreases, same-size root changes, missing or
invalid Merkle consistency proofs, and decision counts that exceed tree growth.
If the reviewer has independently retained signed tree heads, those anchors can
be supplied as an additional root-history check.

Passing verification means the attestation series is internally consistent with
the supplied public key and Merkle evidence. It does not mean Velvet was the only
dispatch path, that the insured's policies were appropriate, or that any insurer
has approved or endorsed the control state.

The retention preset field accepts the Vault preset `eu_ai_act_minimum` for the
183-day sealed-segment horizon, plus deployment-specific labels such as
`minimal`, `standard`, `extended`, and `legal_hold`.

## Budget-Safety Notes

Spend-class certificate coverage is relevant only under the deterministic budget
safety hypotheses:

- H1: true hard caps are present in the action certificate.
- H2: accounting is single-writer for the scoped budget ledger.

The theorem reference is `docs/math/budget_safety_deterministic_theorem.txt`. The
attestation reports whether those flags were present in observed certificate
metadata; it does not prove that an external provider's invoice stream is
complete unless that provider's spend feed is part of the deployment design.

## What This Does Not Tell An Underwriter

- No content inspection: the attestation does not reveal prompts, customer
  data, action arguments, tool names, or per-action records.
- No model-quality signal: it does not measure truthfulness, task success,
  hallucination rate, or output quality.
- No guarantee against policy misconfiguration: a signed policy hash proves
  which policy was active, not that it was the right policy.
- No guarantee that Velvet was the only dispatch path unless the insured
  separately provides deployment topology evidence.
- No legal or regulatory determination: this is control-state evidence for
  review, not an audit outcome or legal conclusion.
- No underwriting decision: it does not establish insurability, coverage terms,
  pricing impact, or endorsement by any carrier, broker, MGA, or auditor.
