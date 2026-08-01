# Compliance Evidence Crosswalk

This bundle demonstrates technical record-keeping capability relevant to EU AI Act Article 12. It is not a determination of legal compliance, which depends on system classification, deployment context, and counsel review.

This crosswalk is a technical capability map for Velvet vault evidence. It maps the same fields declared in `src/velvet/attestation/mapping.py` to adjacent governance frameworks and record provisions. It is not legal advice.

## Source Anchors

- EU AI Act: Regulation (EU) 2024/1689, especially Article 12 record keeping and Article 19 retention of automatically generated logs: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng>
- NIST AI RMF 1.0 functions and categories: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI RMF Playbook, aligned to Govern, Map, Measure, and Manage outcomes: <https://airc.nist.gov/airmf-resources/playbook/>
- ISO/IEC 42001 overview for AI management systems: <https://www.iso.org/standard/42001>
- Colorado SB24-205 bill page and enacted text: <https://leg.colorado.gov/bills/sb24-205>

## Status Legend

- `evidenced`: Velvet vault or pack artifacts contain a concrete field or verifiable binding.
- `partial`: Evidence exists only for specific record shapes, deployments, or supplied metadata.
- `out-of-scope`: The field is not produced by Velvet vault evidence.

## Field Crosswalk

| Velvet field | EU AI Act Article 12 / 19 | NIST AI RMF | ISO/IEC 42001 | Colorado AI Act | Status |
| --- | --- | --- | --- | --- | --- |
| `event.timestamp` | Lifetime automatic event recording | MEASURE 2, MANAGE 2 | 7.5 documented information; 9 monitoring | Risk-management and impact-assessment records | evidenced |
| `system.identity` | Traceability to intended purpose and deployed system | GOVERN 1, MAP 1 | 4 context; 8 operation | Developer/deployer system documentation | partial |
| `agent.identity` | Deployer operational monitoring | GOVERN 2, MAP 4 | 5 roles; 7 support | Deployer records of use context | partial |
| `actor.identity` | Identifies users or subjects where supplied | GOVERN 2, MAP 4 | 5 roles; 7 support | Consumer-impact context | partial |
| `action.type` | Risk situations and substantial modifications | MAP 3, MEASURE 2 | 8 operation | High-risk system use records | evidenced |
| `action.canonical_hash` | Traceability of the exact action evaluated | MEASURE 2, MANAGE 2 | 8 operation; 9 monitoring | Records supporting risk controls | partial |
| `arguments.hash` | Traceability of action inputs | MAP 2, MEASURE 2 | 7.5; 8 operation | Documentation of inputs and decisions | evidenced |
| `arguments.recording_mode` | Recording mode may affect traceability | GOVERN 4, MEASURE 2 | 7.5 control of documented information | Record-retention practice | out-of-scope |
| `tool.identity` | Identifies tool or subsystem involved in event | MAP 1, MAP 2 | 8 operation | High-risk system component context | evidenced |
| `tool.schema_hash` | Interface version at decision time | MAP 2, MEASURE 2 | 8 operation; 9 monitoring | Technical documentation inputs | evidenced |
| `policy.bundle_hash` | Policy active when event occurred | GOVERN 6, MANAGE 1 | 6 planning; 8 operation | Risk-management policy records | evidenced |
| `policy.bundle_version` | Policy changes and substantial modifications | GOVERN 6, MANAGE 1 | 6 planning; 8 operation | Risk-management policy records | evidenced |
| `decision.outcome` | Events relevant to risk situations and monitoring | MEASURE 2, MANAGE 2 | 9 monitoring | Decision records | evidenced |
| `decision.reason` | Basis for post-market and operational monitoring | MEASURE 2, MANAGE 2 | 9 monitoring; 10 improvement | Risk-management and impact records | evidenced |
| `approval.human_identity` | Natural person involved in verification where applicable | GOVERN 2, MANAGE 4 | 5 roles; 7 competence | Human-review records where used | partial |
| `approval.receipt` | Escalated action verification record | GOVERN 2, MANAGE 4 | 7.5; 8 operation | Human-review and governance records | partial |
| `authority.before` | Authority state before decision | MEASURE 2, MANAGE 2 | 8 operation; 9 monitoring | Risk-control evidence | partial |
| `authority.after` | Authority state after decision | MEASURE 2, MANAGE 2 | 8 operation; 9 monitoring | Risk-control evidence | partial |
| `ledger.sequence` | Lifetime ordering and completeness | MEASURE 2, MANAGE 2 | 7.5; 9 monitoring | Record integrity support | evidenced |
| `ledger.predecessor` | Chain binding for event sequence | MEASURE 2, MANAGE 2 | 7.5; 9 monitoring | Record integrity support | evidenced |
| `sth.coverage` | Verifiable coverage of record set | MEASURE 2, MANAGE 2 | 7.5; 9 monitoring | Record integrity support | evidenced |
| `replay.verification_status` | Machine verification result for pack build | MEASURE 2, MANAGE 2 | 9 monitoring; 10 improvement | Auditability of retained records | evidenced |
| `verification.natural_person_identity` | Natural person verifier identity where applicable | GOVERN 2 | 5 roles; 7 competence | Human verification context | out-of-scope |
| `biometric.reference_database` | Specialized remote-biometric logging element | MAP 1, MEASURE 2 | 8 operation if applicable | Usually outside this product surface | out-of-scope |

## Notes

Velvet evidences cryptographic record integrity, replay inputs, policy bindings, and approval receipts where those receipts exist. It does not classify a customer system as high-risk, determine whether a deployment is within EU or Colorado scope, or supply organization-level AI management-system controls outside the vault evidence plane.
