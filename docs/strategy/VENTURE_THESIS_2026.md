# Velvet Venture Thesis

Research date: **2026-08-23**

## Decision

Build Velvet as the **outcome-assurance layer for autonomous agents**.

The funded market is already crowded around agent discovery, identity, posture, gateways, and
per-action authorization. Velvet should not claim to invent or replace those categories. Its wedge is
the layer they leave unresolved: prove whether a prohibited business effect was prevented across every
equivalent route, then preserve reviewable evidence of that result.

The open-source ShadowPath engine is the entry point. The commercial product should manage outcome
portfolios, continuous runs, protected observers, control regressions, evidence retention, and
enterprise integrations.

## What the market now validates

| Signal | Current evidence | Implication for Velvet |
| --- | --- | --- |
| Agent security is blocking adoption | NIST's May 2026 analysis says respondents widely agreed that agent security presents novel threats, creates an adoption barrier, and requires existing cyber practices to be adapted. [NIST 800-5](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai) | Sell enablement and evidence for consequential automation, not abstract “AI safety.” |
| Standards are forming now | NIST launched its AI Agent Standards Initiative in February 2026 around secure, interoperable agents, open protocols, security, and identity research. [NIST announcement](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure) | Keep schemas open, machine-verifiable, and standards-friendly. Contribute measurement artifacts rather than marketing claims. |
| Authorization is moving to deployment governance | The World Economic Forum and Capgemini introduced ACAP in May 2026 as a deployment-level instrument intended to make delegated agent actions auditable, enforceable, and accountable. [WEF playbook](https://www.weforum.org/publications/ai-agents-in-action-a-playbook-for-trusted-adoption-authorization-and-scaling/) | Map Velvet evidence to the authorization profile, while owning the post-control outcome test. |
| Agentic threats are a formal security workstream | OWASP now publishes a 2026 Top 10, an agentic security initiative, MCP guidance, and a Q2 2026 solutions landscape. [OWASP initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/) | Use OWASP route and threat classes as input to effect inventories; do not present a private taxonomy as universal. |
| Buyers and investors fund the control layer | Noma announced a $100M Series B in July 2025; Arcade.dev announced a $60M Series A in June 2026; Zenity announced a $125M Series C in August 2026. [Noma](https://noma.security/blog/noma-security-raises-100m-to-drive-adoption-of-ai-agent-security/), [Arcade.dev](https://www.arcade.dev/blog/arcade-series-a/), [Zenity](https://zenity.io/company-overview/newsroom/company-news/zenity-raises-125-million-to-secure-the-era-of-1-billion-ai-agents) | The category has budget and strategic urgency. A seed company still needs a visibly different control primitive and an initial buyer workflow. |

## Competitive position

Public positioning from Noma emphasizes unified discovery, access control, red teaming, and runtime
detection. Zenity emphasizes observability, posture, exposure, boundaries, identity, MCP security, and
detection/response. Arcade.dev emphasizes a secure action layer that enforces, executes, and governs
each agent action.

**Inference from those public product surfaces:** the most defensible open space is not another policy
decision point. It is continuous, effect-equivalent control assurance with independent reconciliation.
This is a positioning inference, not a claim that the named products lack unadvertised capabilities or
failed a live test.

| Layer | Crowded buyer question | Velvet question |
| --- | --- | --- |
| Discovery / posture | Which agents and connections exist? | Which business outcomes can that authority change? |
| Identity / authorization | Who is acting, for whom, and may this call execute? | What other routes reach the same effect? |
| Runtime detection | Did behavior or traffic look risky? | Did the prohibited substrate state change anyway? |
| Audit log | What did the control observe? | Can an independent reviewer verify control and outcome evidence? |

## Product architecture

### Open source

- **ShadowPath:** single-effect projects, route inventory, isolated execution, independent state
  reconciliation, strict exits, result rendering, and outcome portfolios.
- **Velvet Gateway:** local pre-dispatch MCP enforcement, signed policy bundles, approvals, short-lived
  execution permits, receipts, and deterministic replay.
- **Velvet Vault:** local tamper-evident evidence, Merkle proofs, Signed Tree Heads, attestations, and
  offline verification.

### Commercial product hypothesis

- outcome registry with owners, criticality, review cadence, and system dependencies;
- scheduled and change-triggered ShadowPath portfolio runs;
- protected observer connectors for databases, queues, SaaS state, cloud resources, and ledgers;
- regression diff when an agent, policy, credential, integration, or business path changes;
- private evidence service with retention, external anchoring, access controls, and reviewer portals;
- integrations into CI, SIEM, ticketing, identity, gateways, agent platforms, and GRC workflows.

The hosted service, shared tenancy, enterprise policy studio, and hardened approval orchestration are
not implemented in the current repository. They remain product work, not present-tense claims.

## Initial customer and use case

**Ideal customer:** a regulated or high-consequence enterprise moving an internal agent from demo to
real actions across several authority surfaces.

**Champion:** Head of AI Platform, product-security leader, or security architect responsible for
agent controls.

**Economic buyer:** CISO or risk leader accountable for enabling autonomous workflows without losing
control evidence.

**Land motion:** protect one outcome that has a clear substrate state and multiple reachable routes,
such as payment release, account lockout, production deployment, regulated-record mutation, or
sensitive-data export.

**Expansion:** add adjacent outcomes, teams, agents, and observers until Velvet becomes the continuous
assurance system for the autonomous-work estate.

## Design-partner offer

A focused engagement should produce one executable effect project, an outcome/route inventory, a
machine-readable baseline, a remediation plan, and a CI-ready rerun. Pricing is a hypothesis to test,
not a published promise:

- design-partner pilot hypothesis: **$25k–$50k** for a tightly bounded outcome;
- annual platform hypothesis after repeatable deployment: **$120k–$350k**, scaled by protected
  outcomes and active assurance environments rather than raw model tokens.

The buyer should pay for risk-bearing business outcomes and evidence continuity, not for the number of
policy checks.

## Defensibility

1. **Effect graph:** the durable customer asset is a versioned map from business outcome to every
   reachable authority path and independent observer.
2. **Adapter network:** reusable route and observer adapters shorten each new outcome deployment.
3. **Assurance history:** repeated result series reveal control regressions that a one-time red team or
   route log cannot.
4. **Proof chain:** Velvet already combines pre-dispatch artifacts, receipts, replay, Merkle evidence,
   and offline verification.
5. **Open benchmark gravity:** a neutral, reproducible benchmark can attract control vendors,
   researchers, and enterprise contributors without forcing adoption of the commercial service.

The mathematical certificate work is valuable technical depth but should not lead the seed pitch. The
fastest buyer story is observable: the tool was blocked, the outcome still happened, and Velvet shows
the exact escaped paths.

## Financing hypothesis

A credible seed target is **$3.5M–$5M for 18–24 months** after the company shows that the wedge converts
into repeatable paid work. The round should fund protected observer integrations, a managed control
plane, enterprise deployment/security work, and a compact go-to-market team.

Evidence expected before or during that raise:

- 3–5 design partners with named outcomes and executive sponsors;
- at least 2 paid pilots and one expansion or annual conversion;
- 20+ reusable effect-route or observer adapters;
- a repeatable pilot completed in weeks rather than a custom research engagement;
- external contributors or reference integrations around the open benchmark;
- clear handling of customer evidence, tenancy, retention, keys, and security review;
- a founding team narrative covering deep systems/security execution and enterprise distribution.

## Milestone plan

### Next 30 days

- launch the new outcome-assurance positioning and product site;
- publish the outcome portfolio runner and pilot guide;
- recruit ten problem interviews from AI platform and product-security leaders;
- select one effect template for payments, identity, or deployment control;
- remove or subordinate fundraise-only surfaces that distract users from the product loop.

### Days 31–90

- complete three design-partner effect inventories;
- ship protected observers for the two most common substrates encountered;
- add change-triggered portfolio diffing and a simple local control-room view;
- convert the strongest engagement into a paid, time-bounded pilot;
- contribute a measurement proposal or artifact to a relevant NIST/OWASP community process.

### Months 4–9

- standardize deployment and evidence retention for the first commercial environment;
- reach five paid pilots and at least two annual conversions;
- demonstrate expansion from one outcome to a multi-outcome portfolio;
- document security architecture, data handling, disaster recovery, and a SOC 2 readiness plan;
- raise on repeatability and outcome coverage—not on unverified market-size slides.

## Honest diligence gaps

- No customer, revenue, usage, or paid-pilot evidence is present in the repository.
- No hosted shared-tenant service exists.
- The current public benchmark is a synthetic local fixture, not a live competitor evaluation.
- The local dashboard is not a hardened enterprise control plane.
- The repository is technically broad; the commercial story needs disciplined focus on the outcome
  assurance loop.
- “Millions in funding” cannot be guaranteed by code or positioning. Fundability depends on founder
  credibility, paid customer pull, speed, distribution, team, timing, and clean diligence.

## Seed narrative in one paragraph

AI agents are crossing from answers into business actions, but today's controls mostly authorize and
observe named routes. Enterprises cannot confidently scale autonomy when the same prohibited effect
is still reachable through another API, a browser, a queue, a credential, a database, or a human.
Velvet is the outcome-assurance layer: its open ShadowPath engine maps and tests every route to a
critical effect, its Gate controls supported execution paths, and its Vault preserves evidence that can
be verified offline. Start with one outcome, prove the blind spots, then expand into the continuous
assurance system for the agent estate.
