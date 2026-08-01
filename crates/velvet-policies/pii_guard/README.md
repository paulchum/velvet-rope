# pii_guard

`pii_guard` scans candidate action parameters and metadata before execution. The default path is deterministic regex detection for email, SSN, phone, credit card with Luhn and major-network BIN checks, IBAN with mod97, and US/CA postal codes. Optional NER must be supplied as preloaded observations; the policy never performs live I/O.

Evidence fields: `match_count`, `kinds`, `field_paths`, and `matched_hashes`. Redaction decisions include a mutation ledger with deterministic placeholders plus original values so replay can reconstruct the exact modified action.

Tuning guidance: use `block` on egress actions such as `SEARCH_WEB`, `redact` for internal retrieval or summaries, and `flag` where PII is expected but should remain auditable. Add context list keys for first-party values such as the current user's email.

Failure modes and mitigations:
- False positives on postal codes or numeric identifiers: disable `postal_code` for broad search workloads or prefer `flag`.
- False negatives for natural-language PII: enable the optional `pii_guard_ner` feature and feed traced NER spans through `PolicyContext.external_observations`.
- Sensitive replay traces: restrict trace storage access because redaction ledgers intentionally retain original values for deterministic replay.

