#[derive(Debug, Clone, Copy)]
pub struct Recipe {
    pub name: &'static str,
    pub description: &'static str,
    pub sql: &'static str,
    pub correlational: bool,
}

pub fn get(name: &str) -> Option<Recipe> {
    all().into_iter().find(|recipe| recipe.name == name)
}

pub fn names() -> Vec<&'static str> {
    all().into_iter().map(|recipe| recipe.name).collect()
}

pub fn all() -> Vec<Recipe> {
    vec![
        recipe(
            "run_summary",
            "Run-level thread and condition counts",
            "SELECT run_id, count(*) threads, count(DISTINCT condition_id) conditions, count(DISTINCT policy_chain_revision) policy_revisions FROM threads GROUP BY run_id ORDER BY run_id",
            false,
        ),
        recipe(
            "completion_rate",
            "Completion rate per condition",
            "SELECT run_id, condition_id, avg(CASE WHEN selected_completed THEN 1.0 ELSE 0.0 END) completion_rate, count(*) n FROM threads GROUP BY run_id, condition_id ORDER BY run_id, condition_id",
            false,
        ),
        recipe(
            "completion_overall",
            "Overall completion rate",
            "SELECT run_id, avg(CASE WHEN selected_completed THEN 1.0 ELSE 0.0 END) completion_rate, count(*) n FROM threads GROUP BY run_id ORDER BY run_id",
            false,
        ),
        recipe(
            "gate_calibration",
            "One-step override calibration",
            "SELECT run_id, condition_id, avg(CASE WHEN selected_realized_reward > host_expected_reward THEN 1.0 ELSE 0.0 END) gate_calibration_rate, count(*) n FROM threads WHERE host_action IS NOT NULL AND selected_action != host_action AND host_expected_reward IS NOT NULL GROUP BY run_id, condition_id ORDER BY run_id, condition_id",
            false,
        ),
        recipe(
            "override_efficiency",
            "Mean cost delta per override",
            "SELECT t.run_id, t.condition_id, avg(coalesce(try_cast(so.realized_cost AS DOUBLE), try_cast(so.expected_cost AS DOUBLE), 0) - coalesce(try_cast(ho.expected_cost AS DOUBLE), try_cast(ho.realized_cost AS DOUBLE), 0)) mean_cost_delta, count(*) n FROM threads t JOIN outcomes so ON so.thread_id=t.thread_id AND so.action_type=t.selected_action JOIN outcomes ho ON ho.thread_id=t.thread_id AND ho.action_type=t.host_action WHERE t.host_action IS NOT NULL AND t.selected_action != t.host_action GROUP BY t.run_id, t.condition_id ORDER BY t.run_id, t.condition_id",
            false,
        ),
        recipe(
            "policy_denial_rate",
            "Policy denial rate",
            "SELECT run_id, policy_name, avg(CASE WHEN status IN ('deny','defer','block','blocked') OR decision_kind IN ('deny','defer') THEN 1.0 ELSE 0.0 END) denial_rate, count(*) events FROM policy_events GROUP BY run_id, policy_name ORDER BY denial_rate DESC, policy_name",
            false,
        ),
        recipe(
            "policy_denial_by_action",
            "Policy denial rate by action type",
            "SELECT run_id, policy_name, action_type, avg(CASE WHEN status IN ('deny','defer','block','blocked') OR decision_kind IN ('deny','defer') THEN 1.0 ELSE 0.0 END) denial_rate, count(*) events FROM policy_events GROUP BY run_id, policy_name, action_type ORDER BY denial_rate DESC, policy_name, action_type",
            false,
        ),
        recipe(
            "pareto_frontier",
            "Completion versus cost per condition",
            "SELECT run_id, condition_id, avg(CASE WHEN selected_completed THEN 1.0 ELSE 0.0 END) completion_rate, sum(coalesce(try_cast(selected_realized_cost AS DOUBLE), 0)) total_cost FROM threads GROUP BY run_id, condition_id ORDER BY total_cost, completion_rate DESC",
            false,
        ),
        recipe(
            "brier_by_action",
            "Brier score by action type",
            "SELECT s.run_id, s.action_type, avg((s.confidence - CASE WHEN o.completed THEN 1.0 ELSE 0.0 END) * (s.confidence - CASE WHEN o.completed THEN 1.0 ELSE 0.0 END)) brier_score, count(*) n FROM scores s JOIN outcomes o ON o.thread_id=s.thread_id AND o.action_type=s.action_type WHERE o.completed IS NOT NULL GROUP BY s.run_id, s.action_type ORDER BY brier_score DESC",
            false,
        ),
        recipe(
            "ece_bins",
            "Calibration bins for ECE",
            "SELECT s.run_id, s.action_type, floor(s.confidence * 10) / 10.0 confidence_bin, avg(s.confidence) mean_confidence, avg(CASE WHEN o.completed THEN 1.0 ELSE 0.0 END) accuracy, count(*) n FROM scores s JOIN outcomes o ON o.thread_id=s.thread_id AND o.action_type=s.action_type WHERE o.completed IS NOT NULL GROUP BY s.run_id, s.action_type, confidence_bin ORDER BY s.run_id, s.action_type, confidence_bin",
            false,
        ),
        recipe(
            "ece_by_action",
            "Expected calibration error by action type",
            "WITH bins AS (SELECT s.run_id, s.action_type, floor(s.confidence * 10) / 10.0 confidence_bin, avg(s.confidence) mean_confidence, avg(CASE WHEN o.completed THEN 1.0 ELSE 0.0 END) accuracy, count(*) n FROM scores s JOIN outcomes o ON o.thread_id=s.thread_id AND o.action_type=s.action_type WHERE o.completed IS NOT NULL GROUP BY s.run_id, s.action_type, confidence_bin), totals AS (SELECT run_id, action_type, sum(n) total_n FROM bins GROUP BY run_id, action_type) SELECT b.run_id, b.action_type, sum((b.n / t.total_n) * abs(b.mean_confidence - b.accuracy)) ece, t.total_n n FROM bins b JOIN totals t USING (run_id, action_type) GROUP BY b.run_id, b.action_type, t.total_n ORDER BY ece DESC",
            false,
        ),
        recipe(
            "novelty_calibration",
            "Novelty score versus information gain",
            "SELECT s.run_id, s.action_type, corr(s.surprisal, try_cast(o.information_gain AS DOUBLE)) novelty_information_gain_corr, count(*) n FROM scores s JOIN outcomes o ON o.thread_id=s.thread_id AND o.action_type=s.action_type WHERE o.information_gain IS NOT NULL GROUP BY s.run_id, s.action_type ORDER BY novelty_information_gain_corr DESC",
            true,
        ),
        recipe(
            "novelty_scatter",
            "Novelty scatter backing data",
            "SELECT s.run_id, s.condition_id, s.thread_id, s.action_type, s.surprisal novelty_score, try_cast(o.information_gain AS DOUBLE) information_gain, o.content_hash, o.memory_unique FROM scores s JOIN outcomes o ON o.thread_id=s.thread_id AND o.action_type=s.action_type WHERE o.information_gain IS NOT NULL ORDER BY s.run_id, s.condition_id, s.thread_id",
            true,
        ),
        recipe(
            "cost_attribution_variance",
            "Provider reported-versus-billed cost deltas",
            "SELECT run_id, provider, avg(abs(reported_cost - billed_cost)) mean_abs_delta, max(abs(reported_cost - billed_cost)) max_abs_delta, count(*) n FROM provider_costs GROUP BY run_id, provider ORDER BY mean_abs_delta DESC",
            false,
        ),
        recipe(
            "coverage_gaps",
            "Replay jurisdiction_evidence coverage gaps",
            "SELECT run_id, gap_kind, count(*) gaps FROM coverage_gaps GROUP BY run_id, gap_kind ORDER BY gaps DESC, gap_kind",
            false,
        ),
        recipe(
            "coverage_gap_details",
            "Thread-level coverage gap details",
            "SELECT run_id, condition_id, decision_id, thread_id, gap_kind, detail FROM coverage_gaps ORDER BY run_id, condition_id, decision_id, gap_kind",
            false,
        ),
        recipe(
            "liability_summary",
            "Greedy-epsilon liability benchmark pass summary",
            "WITH per_mode AS (SELECT run_id, liability_mode, avg(CASE WHEN (liability_mode='false_lockout' AND outcome='inspect') OR (liability_mode='certifiable_waste' AND outcome='lockout') THEN 1.0 ELSE 0.0 END) pass_rate, count(*) n FROM certificates GROUP BY run_id, liability_mode) SELECT run_id, sum(n) certificate_cases, max(CASE WHEN liability_mode='false_lockout' THEN pass_rate ELSE NULL END) certified_recovery_rate, max(CASE WHEN liability_mode='certifiable_waste' THEN pass_rate ELSE NULL END) certified_shutoff_rate, min(pass_rate) both_modes_min_rate FROM per_mode GROUP BY run_id ORDER BY run_id",
            false,
        ),
        recipe(
            "false_lockout_rate",
            "Rate at which recoverable candidates remain inspectable",
            "SELECT run_id, avg(CASE WHEN outcome='inspect' THEN 1.0 ELSE 0.0 END) false_lockout_prevented_rate, count(*) n FROM certificates WHERE liability_mode='false_lockout' GROUP BY run_id ORDER BY run_id",
            false,
        ),
        recipe(
            "certifiable_waste_rate",
            "Rate at which certifiably sub-price candidates are shut off",
            "SELECT run_id, avg(CASE WHEN outcome='lockout' THEN 1.0 ELSE 0.0 END) certified_waste_prevented_rate, count(*) n FROM certificates WHERE liability_mode='certifiable_waste' GROUP BY run_id ORDER BY run_id",
            false,
        ),
        recipe(
            "certificate_coverage",
            "Certificate jurisdiction_evidence coverage by liability mode",
            "SELECT run_id, liability_mode, count(*) certificate_rows, count(DISTINCT condition_id) conditions, avg(CASE WHEN lower_certificate IS NOT NULL AND upper_certificate IS NOT NULL AND certificate_lambda IS NOT NULL THEN 1.0 ELSE 0.0 END) complete_certificate_rate FROM certificates GROUP BY run_id, liability_mode ORDER BY run_id, liability_mode",
            false,
        ),
        recipe(
            "certificate_outcomes",
            "Max-DE certificate outcomes and unresolved band width",
            "SELECT run_id, family, liability_mode, outcome, count(*) certificate_rows, avg(upper_certificate - lower_certificate) mean_unresolved_width, max(upper_certificate - lower_certificate) max_unresolved_width FROM certificates GROUP BY run_id, family, liability_mode, outcome ORDER BY run_id, family, liability_mode, outcome",
            false,
        ),
        recipe(
            "refinement_zone_rate",
            "Share of posterior candidates left in the Max-DE refinement zone",
            "SELECT run_id, family, avg(CASE WHEN outcome='refinement' THEN 1.0 ELSE 0.0 END) refinement_zone_rate, count(*) certificate_rows FROM certificates GROUP BY run_id, family ORDER BY run_id, family",
            false,
        ),
        recipe(
            "competitor_matrix",
            "Named competitor and baseline liability outcomes",
            "SELECT run_id, system, adapter_kind, status, count(DISTINCT case_id) cases, bool_or(skipped) any_skipped, avg(CASE WHEN certificate_supported THEN 1.0 ELSE 0.0 END) certificate_support_rate, sum(coalesce(liability_cost, 0)) total_liability_cost FROM competitor_results GROUP BY run_id, system, adapter_kind, status ORDER BY run_id, certificate_support_rate DESC, total_liability_cost, system",
            false,
        ),
        recipe(
            "compensator_ledger",
            "Certified refinement compensator ledger",
            "SELECT run_id, arm_id, liability_mode, sum(coalesce(compensator_increment, 0)) compensator_spend, max(coalesce(initial_optionality, 0)) initial_optionality, CASE WHEN max(coalesce(initial_optionality, 0)) > 0 THEN sum(coalesce(compensator_increment, 0)) / max(coalesce(initial_optionality, 0)) ELSE NULL END spend_ratio FROM certificates GROUP BY run_id, arm_id, liability_mode ORDER BY run_id, arm_id, liability_mode",
            false,
        ),
        recipe(
            "velvet_rope_summary",
            "Velvet Rope Liability Arena verdict summary",
            "SELECT run_id, system_name, verdict, auditability_status, action_path_integrity, critical_failure_count, high_failure_count, medium_failure_count, opportunity_failure_count, cost_failure_count, liability_multiplier, result_type, public_claim_status FROM competitor_action_results ORDER BY action_path_integrity DESC, CASE auditability_status WHEN 'full' THEN 0 WHEN 'partial' THEN 1 ELSE 2 END, critical_failure_count, high_failure_count, liability_multiplier, system_name",
            false,
        ),
        recipe(
            "velvet_rope_bound_failures",
            "Failure cards bound to metric numerators",
            "SELECT run_id, system_name, failure_card_id, failure_class, scenario_id, query_id, metric_name, severity, liability_multiplier_contribution, trace_hash, reproduction_command FROM result_failure_bindings ORDER BY run_id, system_name, severity, failure_class, scenario_id",
            false,
        ),
        recipe(
            "velvet_rope_nonzero_metric_drilldown",
            "Every nonzero Velvet Rope liability metric with bound failure count",
            "SELECT run_id, system_name, metric_name, sum(metric_numerator_contribution) numerator, count(DISTINCT failure_card_id) bound_failure_cards FROM result_failure_bindings GROUP BY run_id, system_name, metric_name ORDER BY run_id, system_name, numerator DESC, metric_name",
            false,
        ),
        recipe(
            "velvet_rope_action_path_integrity",
            "Action Path Integrity pass/fail by system",
            "SELECT run_id, system_name, bool_and(action_path_integrity) action_path_integrity_pass, sum(CASE WHEN action_executed THEN 1 ELSE 0 END) executed_actions, sum(CASE WHEN executed_without_warrant THEN 1 ELSE 0 END) executed_without_warrant, sum(CASE WHEN hidden_tool_call THEN 1 ELSE 0 END) hidden_tool_calls, sum(CASE WHEN missing_warrant THEN 1 ELSE 0 END) missing_warrant_rows, sum(CASE WHEN missing_seal THEN 1 ELSE 0 END) missing_seal_rows FROM velvet_rope_traces GROUP BY run_id, system_name ORDER BY action_path_integrity_pass DESC, executed_without_warrant, hidden_tool_calls, system_name",
            false,
        ),
        recipe(
            "velvet_rope_research_matrix",
            "Trace-audit-only competitor research matrix",
            "SELECT run_id, system_name, category, auditability_grade, result_type, adapter_feasibility, public_claim_status FROM competitor_research_records ORDER BY system_name",
            false,
        ),
        recipe(
            "market_claim_support",
            "Draft-only support table for broader market claim",
            "WITH cert_claim AS (WITH delight AS (SELECT run_id, min(CASE WHEN (liability_mode='false_lockout' AND outcome='inspect') OR (liability_mode='certifiable_waste' AND outcome='lockout') THEN 1 ELSE 0 END) velvet_passes FROM certificates GROUP BY run_id), competitors AS (SELECT run_id, count(DISTINCT system) surveyed_systems, sum(CASE WHEN skipped THEN 1 ELSE 0 END) skipped_rows, sum(CASE WHEN certificate_supported THEN 1 ELSE 0 END) certificate_supported_rows FROM competitor_results GROUP BY run_id) SELECT d.run_id, d.velvet_passes = 1 velvet_passes_both_modes, c.surveyed_systems, c.skipped_rows, c.certificate_supported_rows, 'draft_requires_legal_review' claim_status, 'As of ' || CAST(current_date AS VARCHAR) || ', among surveyed named guardrail/agent products and benchmarked baselines, Velvet is the only system we found that enforces both certified recovery and certified shutoff using traceable posterior certificates.' safe_wording FROM delight d LEFT JOIN competitors c USING (run_id)), rope_claim AS (SELECT run_id, bool_or(system_name='Velvet native gate' AND action_path_integrity AND auditability_status='full') velvet_passes_both_modes, count(DISTINCT system_name) surveyed_systems, sum(CASE WHEN result_type IN ('not_run','trace_audit_only') THEN 1 ELSE 0 END) skipped_rows, sum(CASE WHEN auditability_status='full' THEN 1 ELSE 0 END) certificate_supported_rows, 'draft_requires_legal_review' claim_status, 'Velvet Rope classifies systems by whether they can prove the pre-execution action path. Systems that cannot emit candidate actions, admission decisions, execution contexts, warrants, and replay seals are classified as partial or non-auditable under the Velvet Rope contract.' safe_wording FROM competitor_action_results GROUP BY run_id) SELECT * FROM cert_claim UNION ALL SELECT * FROM rope_claim ORDER BY run_id",
            false,
        ),
        recipe(
            "highest_cost_denied",
            "Top denied actions by expected cost",
            "SELECT c.run_id, c.condition_id, c.decision_id, c.thread_id, c.action_type, c.decision, s.cost_money, c.reason FROM candidates c LEFT JOIN scores s USING (run_id, condition_id, decision_id, thread_id, candidate_index, action_type) WHERE c.decision != 'execute' ORDER BY coalesce(s.cost_money, 0) DESC LIMIT 20",
            false,
        ),
        recipe(
            "highest_value_overrides",
            "Top admitted overrides by reward gain",
            "SELECT t.run_id, t.condition_id, t.decision_id, t.thread_id, t.host_action, t.selected_action, t.selected_realized_reward - t.host_expected_reward reward_delta FROM threads t WHERE t.host_action IS NOT NULL AND t.selected_action != t.host_action AND t.selected_realized_reward IS NOT NULL AND t.host_expected_reward IS NOT NULL ORDER BY reward_delta DESC LIMIT 20",
            false,
        ),
        recipe(
            "changed_decision_keys",
            "Decision identity keys for diff",
            "SELECT run_id, condition_id, scenario_id, decision_id, thread_id, selected_action, policy_chain_revision, seal_id FROM threads ORDER BY condition_id, scenario_id, decision_id, run_id",
            false,
        ),
        recipe(
            "decision_costs",
            "Selected decision costs",
            "SELECT run_id, condition_id, decision_id, selected_action, selected_realized_cost FROM threads ORDER BY run_id, condition_id, decision_id",
            false,
        ),
        recipe(
            "action_mix",
            "Selected action distribution",
            "SELECT run_id, selected_action, count(*) n, count(*) * 1.0 / sum(count(*)) OVER (PARTITION BY run_id) rate FROM threads GROUP BY run_id, selected_action ORDER BY run_id, n DESC",
            false,
        ),
        recipe(
            "policy_trace",
            "Ordered policy events",
            "SELECT run_id, condition_id, decision_id, thread_id, candidate_index, policy_index, action_type, policy_name, status, decision_kind, rule_id FROM policy_events ORDER BY run_id, condition_id, decision_id, candidate_index, policy_index",
            false,
        ),
    ]
}

fn recipe(
    name: &'static str,
    description: &'static str,
    sql: &'static str,
    correlational: bool,
) -> Recipe {
    Recipe {
        name,
        description,
        sql,
        correlational,
    }
}
