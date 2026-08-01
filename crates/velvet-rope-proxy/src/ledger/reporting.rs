use super::*;

#[derive(Debug, Clone)]
pub(crate) struct LedgerSequenceState {
    pub(crate) sequence_number: u64,
    pub(crate) previous_record_hash: String,
    pub(crate) previous_frame_hash: String,
}

pub(crate) static LEDGER_APPEND_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Mutex<()>>>>> =
    OnceLock::new();

pub(crate) fn ledger_append_lock(path: &Path) -> Result<Arc<Mutex<()>>> {
    let locks = LEDGER_APPEND_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| anyhow!("ledger lock registry poisoned"))?;
    Ok(locks
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

pub(crate) fn load_policy_graph_or_error(path: &Path) -> Result<PolicyGraph> {
    load_policy_graph(path).map_err(|errors| anyhow!(format_policy_errors(errors)))
}

pub(crate) fn format_policy_errors(errors: Vec<PolicyLoadError>) -> String {
    errors
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn decision_string(decision: DecisionType) -> &'static str {
    match decision {
        DecisionType::Execute => "execute",
        DecisionType::Skip => "skip",
        DecisionType::Block => "block",
        DecisionType::Delay => "delay",
        DecisionType::AskApproval => "ask_approval",
        DecisionType::Escalate => "escalate",
    }
}

pub(crate) fn canonical_decision(decision: &str) -> &str {
    match decision {
        "execute" => "execute",
        "escalate" | "ask_approval" | "delay" => "escalate",
        _ => "block",
    }
}

#[allow(dead_code)]
pub(crate) fn non_forwarded_status(admission: &AdmissionOutcome) -> &'static str {
    match canonical_decision(&admission.decision) {
        "escalate" => "pending_approval",
        _ => "not_forwarded",
    }
}

pub(crate) fn max_de_requirement_for_call(
    config: &ProxyConfig,
    inventory_entry: &InventoryEntry,
    approval: Option<&ToolApproval>,
    decision: &str,
) -> (bool, String) {
    if inventory_entry.status != InventoryStatus::Approved {
        return (
            true,
            format!("inventory_status:{}", inventory_entry.status.as_str()),
        );
    }
    if approval.is_some_and(|approval| approval.destructive) {
        return (true, "destructive_tool".to_string());
    }
    if approval.is_some_and(|approval| matches!(approval.risk_class, RiskClass::High)) {
        return (true, "high_risk_tool".to_string());
    }
    if approval.is_some_and(|approval| !matches!(approval.approval_tier, ApprovalTier::AutoApprove))
    {
        return (true, "approval_required_tool".to_string());
    }
    if !matches!(decision, "execute") {
        return (true, format!("decision:{decision}"));
    }
    if config.oap.require_max_de_certificate || config.oap.require_max_de_for_all_tool_calls {
        return (true, "oap_config_requires_certificate".to_string());
    }
    if config.mode.is_strict() {
        return (true, "strict_mode_requires_certificate".to_string());
    }
    if matches!(config.mode, EnforcementMode::Development)
        && config.oap.allow_missing_max_de_in_development
    {
        return (false, "explicit_development_opt_out".to_string());
    }
    (false, "not_required_by_policy".to_string())
}

/// Whether a tools/call requires a signed Verdict Certificate.
///
/// Verdict certificates gate irreversible actions only: the tool must be
/// destructive or high-risk, and enforcement must be switched on either by
/// `oap.require_verdict_for_irreversible` or by strict mode (which forces the
/// requirement the same way it forces Max-DE certificates).
pub(crate) fn verdict_requirement_for_call(
    config: &ProxyConfig,
    approval: Option<&ToolApproval>,
) -> (bool, String) {
    let Some(approval) = approval else {
        return (false, "no_tool_approval".to_string());
    };
    if !approval.destructive && !matches!(approval.risk_class, RiskClass::High) {
        return (false, "not_irreversible".to_string());
    }
    if config.oap.require_verdict_for_irreversible {
        let reason = if approval.destructive {
            "destructive_tool"
        } else {
            "high_risk_tool"
        };
        return (true, reason.to_string());
    }
    if config.mode.is_strict() {
        return (true, "strict_mode_requires_verdict_certificate".to_string());
    }
    (false, "verdict_not_required_by_policy".to_string())
}

pub(crate) fn fallback_maxde_config_for_decision(decision: &str) -> MaxDeCertificateConfig {
    match canonical_decision(decision) {
        "execute" => MaxDeCertificateConfig {
            v: "0.900000".to_string(),
            lambda_value: "0.200000".to_string(),
            delight_scale: "1.000000".to_string(),
            alpha: "9.000000".to_string(),
            beta: "1.000000".to_string(),
            lower_certificate: "0.900000".to_string(),
            upper_certificate: "0.950000".to_string(),
            decision: MaxDeDecision::Inspect,
            theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
            maxde_version: "maxde/1.0".to_string(),
        },
        "escalate" => MaxDeCertificateConfig {
            v: "0.150000".to_string(),
            lambda_value: "0.200000".to_string(),
            delight_scale: "1.000000".to_string(),
            alpha: "3.000000".to_string(),
            beta: "7.000000".to_string(),
            lower_certificate: "0.100000".to_string(),
            upper_certificate: "0.300000".to_string(),
            decision: MaxDeDecision::Refinement,
            theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
            maxde_version: "maxde/1.0".to_string(),
        },
        _ => MaxDeCertificateConfig {
            v: "0.050000".to_string(),
            lambda_value: "0.200000".to_string(),
            delight_scale: "1.000000".to_string(),
            alpha: "1.000000".to_string(),
            beta: "9.000000".to_string(),
            lower_certificate: "0.050000".to_string(),
            upper_certificate: "0.100000".to_string(),
            decision: MaxDeDecision::Lockout,
            theorem_ref: "docs/math/certified_max_de_theorem.txt".to_string(),
            maxde_version: "maxde/1.0".to_string(),
        },
    }
}

pub(crate) fn obligations_for_decision(decision: &str) -> Vec<String> {
    match canonical_decision(decision) {
        "execute" => vec!["forward_upstream".to_string()],
        "escalate" => vec!["await_approval_before_execution".to_string()],
        _ => vec!["do_not_forward_upstream".to_string()],
    }
}

pub(crate) fn now_rfc3339_z() -> String {
    Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        .replace("+00:00", "Z")
}

pub(crate) fn mcp_tool_key(server: &str, tool: &str) -> String {
    format!("{server}/{tool}")
}

pub(crate) fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(value).context("serialize JSONL record")?
    )?;
    Ok(())
}
