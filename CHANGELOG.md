# Changelog

## Unreleased

- Migrated the public product site to Astro 7 on Cloudflare Workers Static
  Assets at `shadowpath.coriolislabs.ca`, with a managed custom domain, canonical
  metadata, hardened response headers, a custom 404, and a privacy-bounded event
  endpoint that accepts only allowlisted aggregate events.
- Updated the transitive Rust `h2` dependency to `0.4.16` to resolve
  `RUSTSEC-2026-0258` in the release dependency graph.
- Raised the Python `cryptography` and `pip` security floors to patched releases,
  and added a dedicated Astro build, test, audit, and Cloudflare dry-run CI job.
- Positioned Velvet as the open outcome-assurance layer above agent identity and
  route authorization, with a buyer-facing static product site, design-partner
  pilot, current market thesis, and updated claim boundaries.
- Added `velvet shadowpath portfolio`, which runs multiple user-owned effect
  projects and writes one conservative estate-level JSON/Markdown result with
  owner, criticality, strict exits, and per-effect artifact pointers.
- Added portfolio validation, output-path-safe effect identifiers, focused tests,
  and a public outcome portfolio guide.

## 1.1.0 - 2026-08-01 - ShadowPath

- Added Agent Authorization Benchmark `0.4.0` and ShadowPath: a hermetic
  effect-level suite that denies the obvious customer-disable tool while
  exercising browser, alternate API, database, queue, webhook, admin console,
  delegated credential, and simulated human-operator paths to the same
  synthetic effect.
- Added strict effect inventory and independent substrate reconciliation,
  `CONTROL_FALSE_SUCCESS`/`UNATTRIBUTED_EFFECT` findings, nonzero breach exits,
  a provider-neutral 20-trial JSONL agent protocol, and an optional OpenAI
  Agents SDK reference adapter.
- Added a zero-setup committed-result replay, custom-effect project scaffolding,
  deterministic social/share rendering, a reusable GitHub Action, and concise
  Claude Code/Codex, Cursor, and OpenAI Agents SDK integration guides.

## 1.0.0 - 2026-07-10 - Certified Decisions

- Released Agent Authorization Benchmark `0.3.0` with four certified-decision
  capability cells (certificate expiry, fleet false-lockout accounting,
  refusal as output, priced inspection) measured by a dedicated probe;
  systems without a probe adapter report `not_measured`, never `fail`, and
  the submission protocol accepts self-measured cells with evidence.
- Added the Certified Decisions layer (`velvet.verdict`): a port of the Max-DE
  decision corpus with Theorem V host-aware finite-horizon verdicts
  (`safe_kill`/`required_inspection`/`refusal`) and priced inspection/tail
  alternatives, drift-expiry certificates with computable expiry horizons and
  forced recertification, anytime-valid GLR retirement audits (Family M), an
  online e-BH gate holding the fleet false-lockout rate at or below delta,
  truncation/anchor-tail lockout certificates, rescue adjudication, and the
  useful-retirement frontier bounds — with upstream provenance, relicensing,
  and the claim-currency doctrine recorded in `src/velvet/verdict/UPSTREAM.md`,
  ported falsification batteries, and SHA-pinned golden parity tests.
- Added signed, expiring Verdict Certificates
  (`velvet.verdict_certificate.v1`): schema-validated wire objects carrying one
  claim currency, hypotheses, machine reason codes, and a mandatory wall-clock
  expiry that downgrades to required inspection; issuance/verification APIs, an
  append-only certificate log with recertification lineage, ledger-record
  embedding with hash-binding validation, aggregate verdict coverage in
  control-state attestations, and a `velvet verdict issue|issue-drift|verify`
  CLI.
- Enforced verdict certificates in the Rust proxy and `velvet-closure`:
  irreversible (destructive or high-risk) actions require a valid, unexpired
  `safe_kill` certificate supplied at
  `params._meta.velvet_verdict_certificate`; expired certificates escalate for
  recertification instead of executing, and verdict status/hash are recorded in
  pre- and post-execution ledger records. Strict mode requires verdicts;
  `require_verdict_for_irreversible` enables them elsewhere.
- Hardened certificate verification: the generic verifier now requires an
  explicit trust root (pinned key file or trust-root descriptor with allowed
  purposes/schema versions/issuer) and labels embedded-key checks UNTRUSTED
  with a nonzero exit; signature-record verification enforces the exact
  signature-block key set and no longer defaults a missing `signed_at`, so
  renamed or injected uncovered keys fail verification.
- Refreshed `velvet.research.crossing_dp` to the Theorem V host-aware rescue
  stopping set (`rescue_indicator`, `host_aware=True` default); the gate-only
  DP remains available as an explicit diagnostic.
- Added Certified Decisions documentation: six theorem summary notes under
  `docs/math/`, the verdict lifecycle doc and the measured replay-evidence page
  under `docs/verdicts/`, new claim-language currency rules, Certified
  Decisions and Fleet Gating rows in the claims boundary, and corrected
  external prior-art citations.
- Added actual-kernel Max-DE research helpers for integer-shape
  Bernoulli/Beta states, finite-horizon crossing probabilities, and
  protected-anchor tail bounds under the one-arm-per-round Bayesian-predictive
  kernel.
- Added `velvet-closure`, a local subgoal lifecycle controller that binds
  closure-issued Execution Permits to signed subgoal hashes and logical-step
  epochs, rejects stale permits before dispatch, records lifecycle events in the
  existing binary ledger, and includes a lingering-authority demo.
- Added the WBC/MCC design index, retired live proof-carrying/PCC wording in
  favor of warrant-bound language, and expanded claim-language checks for the
  WBC/MCC denylist and verdict vocabulary.
- Added GHCR publishing for the multi-arch Rope Proxy container, Linux arm64
  release wheels/proxy binaries, and manylinux-gated Linux wheel builds.
- Added a CIS MCP Companion Guide crosswalk that maps public MCP control
  themes to concrete Velvet proxy, Vault, permit, ledger, and Claims Pack
  artifacts.
- Prepared the OSS launch boundary: Apache-2.0 root metadata, root citation and
  authors files, curated public-tree exporter, OAP MIT license/notice, theorem
  notes moved under `docs/math/`, and explicit open/free vs. paid boundary docs.
- Switched launch metadata to the pre-1.0 `0.9.0` line and added `velvet demo`
  as a zero-Docker quickstart that runs the proxy demo and verifies the ledger.
- Hardened launch automation with wheel/proxy release artifacts, checksum/SBOM
  generation, SLSA-style provenance, cosign bundle signing, curated-tree secret
  scans, and cargo-deny advisory/license checks.
- Released Agent Authorization Benchmark `0.2.0` with pass^k reliability
  scoring, Pipelock and Attested Intelligence signed-receipt fixture rows, and
  regenerated evidence without local-path leakage in current artifacts.
- Added a standalone Agent Authorization Benchmark exporter that vendors the
  pure-Python benchmark package, offline verifier SDK, pinned comparison
  fixtures, and regenerated comparison evidence; the core OSS exporter now ships
  regenerated comparison results/evidence instead of excluding them.
- Added `velvet policy compile`, which converts Markdown policies into signed
  Velvet policy bundles with rulecards, compile provenance, router-backed
  synthetic violation fixtures, and native `llm_atom` fallback checks for atoms
  without deterministic extractors.
- Upgraded `velvet policy compile` with pluggable compile-time model clients,
  component-level repair triage, Ed25519 provenance signing, and
  `velvet policy verify-compile`.
- Added launch-day contributor scaffolding with a contributing guide, GitHub
  issue templates, and a pre-seeded good-first-issue queue.
- Tightened the Rope Proxy enforcement module by removing broad imports and the
  stale unused-import allowance.
- Added property-style coverage for canonical JSON key-order stability and
  binary-ledger frame decode hardening.
- Hardened Rope Proxy `.vledger` decode coverage with Rust proptests, Python
  Hypothesis decode-verification tests, cargo-fuzz decode/verify targets, and a
  manually dispatched weekly fuzz workflow.
- Split the Rope Proxy ledger and internal test files into concern-oriented
  modules while preserving existing test coverage and public call sites.
- Split the Rope Proxy OAP test module out of the main OAP implementation file
  as part of launch-readiness decomposition.
- Gated legacy heuristic-scoring golden assertions so default `velvet-core`
  all-target checks compile without enabling retired scorer exports.
- Red-team scrubbed stale benchmark-version references in submission examples
  and regenerated paper assets against Agent Authorization Benchmark `0.2.0`.
- Breaking: replaced production scalar clearance-score routing with the typed
  admission optimizer and thread schema `9.0`. Candidate decisions now carry
  `admission_trace`, `admission_trace_hash`, `effect_vector`, hard-constraint
  evidence, and optimizer objective components. Python consumers that read
  `admission_score` must migrate to the v9 trace fields; the legacy scorer is
  isolated behind explicit development compatibility only and is not production
  admission authority.
- Breaking: removed the legacy AdmissionToken API and replaced it with
  proof-derived Execution Permits, atomic permit claims, and signed Execution
  Receipts. Admission decisions now produce evidence only; execution authority
  is minted after the pre-execution record is durable and must be verified and
  claimed before dispatch.
- Expanded launch-demo evidence generation with Vault artifacts, Claims Pack outputs, verification reports, and evidence-store manifests.
- Updated Assurance control-state attestation handling, offline verifier behavior, and related schema/test coverage.
- Refreshed launch, commercial, pilot, and marketing materials to align with the current evidence surfaces and claim boundaries.
- Added landing-page concept artifacts and screenshots for builder, MCP firewall, and evidence-room positioning.
