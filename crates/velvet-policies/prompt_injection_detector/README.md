# prompt_injection_detector

`prompt_injection_detector` applies source-aware regex rules to user input, retrieved content, and tool output. The default path performs bounded deterministic normalization: NFKC, a small homoglyph map, ROT13, and base64 token decoding. Embedding similarity and classifier hooks are opt-in and must be supplied as traced observations.

Evidence fields: source, field path, rule id, severity, matched pattern, and matched span. Classifier and embedding jurisdiction_evidence records thresholds and scores.

Tuning guidance: keep high-confidence role-hijack and exfiltration rules in every source set, tune retrieved-content rules more aggressively than user-input rules, and use embedding/classifier observations only after measuring false positives.

Failure modes and mitigations:
- Static rules miss new jailbreaks: update YAML pattern libraries frequently and treat this as a defense-in-depth policy, not a complete security boundary.
- Obfuscation beyond bounded decoders: add explicit deterministic decoders only when they are cheap and replayable.
- Legitimate security research prompts: route these through `flag`-like downstream workflows or Concierge Review instead of weakening global rules.

