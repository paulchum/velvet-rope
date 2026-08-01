# Policy YAML Schema

Generated from the Rust `Document` schema.

## Document Kinds

- `Policy`
- `PolicyChain`
- `PolicyTest`

## Policy Types

| Type | Config fields |
| --- | --- |
| `cost_ceiling` | `cost_model, per_org_monthly_usd_limit, per_task_usd_limit, per_user_daily_usd_limit, soft_ceiling_fraction` |
| `pii_guard` | `default_mode, enabled_detectors, list_context_keys, per_action_mode` |
| `prompt_injection_detector` | `default_action, distance_metric, embedding_threshold, pid_classifier_path, source_rules` |
| `rate_limiter` | `aggregate, per_action` |
| `escalation_gate` | `confidence_threshold, cost_threshold_usd, default_fallback, novelty_threshold, repeated_failure_threshold, sensitive_actions, targets` |
| `llm_atom` | `certificate_class, default_action, extraction_question, finding_keys, rule_id, runtime_enabled, severity` |
