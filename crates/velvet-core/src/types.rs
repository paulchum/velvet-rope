use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::utils::{clamp01, number_value, optional_string, stable_hash_json, truthy};

pub type JsonObject = BTreeMap<String, Value>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    AnswerDirectly,
    SearchWeb,
    RetrieveContext,
    ReadFile,
    InspectCode,
    ExecuteCode,
    CallTool,
    AskUser,
    StoreMemory,
    EscalateModel,
    ConciergeReview,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    #[default]
    Host,
    Scenario,
    Registry,
    Workflow,
    PolicyFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    Execute,
    Skip,
    Block,
    Delay,
    AskApproval,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Allowed,
    Skipped,
    Blocked,
    RequiresApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectLevel {
    None,
    LocalReversible,
    LocalPersistent,
    ExternalReversible,
    ExternalIrreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    NotRun,
    Succeeded,
    Failed,
    Blocked,
    TimedOut,
    PendingConcierge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CandidateAction {
    pub action_type: ActionType,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub certificate: Option<CertificateEvidence>,
    #[serde(default)]
    pub budget_certificate: Option<BudgetCertificate>,
    #[serde(default)]
    pub expected_improvement: Option<f64>,
    #[serde(default)]
    pub novelty: Option<f64>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub cost_overrides: BTreeMap<String, f64>,
    #[serde(default)]
    pub risk_overrides: BTreeMap<String, f64>,
    #[serde(default)]
    pub metadata: JsonObject,
    #[serde(default)]
    pub source: CandidateSource,
    #[serde(default)]
    pub parameters: JsonObject,
}

impl CandidateAction {
    pub fn metadata_truthy(&self, key: &str) -> bool {
        self.metadata.get(key).is_some_and(truthy)
    }

    pub fn parameter_truthy(&self, key: &str) -> bool {
        self.parameters.get(key).is_some_and(truthy)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.parameters
            .get(key)
            .or_else(|| self.metadata.get(key))
            .and_then(Value::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateOutcome {
    Inspect,
    Lockout,
    Refinement,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompensatorStep {
    pub arm: usize,
    pub baseline: f64,
    pub horizon: usize,
    pub z_current: f64,
    pub expected_z_next: f64,
    pub increment: f64,
    pub initial_optionality: f64,
    pub cumulative_increment: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CertificateEvidence {
    pub schema_version: String,
    pub family: String,
    pub arm_id: String,
    pub baseline: f64,
    pub lookback_horizon: usize,
    pub delight_scale: f64,
    pub liability_price: f64,
    pub threshold: f64,
    pub inspection_lower_bound: f64,
    pub safe_upper_bound: f64,
    pub outcome: CertificateOutcome,
    pub liability_mode: String,
    pub typed_effect: CertificateEffect,
    #[serde(default)]
    pub compensator_step: Option<CompensatorStep>,
    #[serde(default)]
    pub theorem_refs: Vec<String>,
    #[serde(default)]
    pub reserve_price: Option<f64>,
    #[serde(default)]
    pub value_numeraire: Option<String>,
    #[serde(default)]
    pub upside_value_scale: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CertificateEffect {
    pub max_payoff: f64,
    pub mean_bound: f64,
    #[serde(default)]
    pub variance_bound: Option<f64>,
    #[serde(default)]
    pub second_moment_bound: Option<f64>,
    pub resource_scope: String,
    pub write_footprint: Vec<String>,
    #[serde(default)]
    pub declared_write_set_hash: Option<String>,
    #[serde(default)]
    pub dependence_group: Option<String>,
    #[serde(default)]
    pub correlation_bound: Option<f64>,
    #[serde(default)]
    pub covariance_reserve_gamma: Option<f64>,
    #[serde(default = "default_dependence_kind")]
    pub dependence_kind: String,
    pub filtration_hash: String,
    pub filtration_index: u64,
    pub adapted: bool,
    #[serde(default)]
    pub adaptation_marker: Option<String>,
    #[serde(default = "default_write_conflict_policy")]
    pub write_conflict_policy: String,
    #[serde(default)]
    pub commutativity_certificate_hash: Option<String>,
    #[serde(default)]
    pub continuation_condition_hash: Option<String>,
}

fn default_dependence_kind() -> String {
    "unspecified".to_string()
}

fn default_write_conflict_policy() -> String {
    "exclusive".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    Task,
    UserDaily,
    OrgMonthly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyModel {
    SingleWriterAtomic,
    Unserialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapProvenance {
    ProviderEnforced,
    PrepaidReservation,
    EnforcedTokenCap,
    EstimateNotACap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetOutcome {
    Admit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetCertificateKind {
    DeterministicHardCap,
    CgfVille,
    MomentCantelli,
}

fn deterministic_budget_certificate_kind() -> BudgetCertificateKind {
    BudgetCertificateKind::DeterministicHardCap
}

pub const DETERMINISTIC_BUDGET_SCHEMA_VERSION: &str = "budget_safety_deterministic_v1";
pub const PROBABILISTIC_BUDGET_SCHEMA_VERSION: &str = "budget_safety_probabilistic_v1";
pub const DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON: f64 = 1e-9;
pub const MICROUSD_PER_USD: u64 = 1_000_000;
pub const MANDATORY_DETERMINISTIC_BUDGET_OBLIGATIONS: [&str; 4] = [
    "record_realized_cost_after_execution",
    "action_hash_match_required",
    "atomic_commit_required",
    "ledger_sequence_match_required",
];
pub const MANDATORY_PROBABILISTIC_BUDGET_OBLIGATIONS: [&str; 5] = [
    "record_realized_cost_after_execution",
    "action_hash_match_required",
    "filtration_hash_match_required",
    "ledger_sequence_match_required",
    "ledger_hash_match_required",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetSafetyLedger {
    pub scope: BudgetScope,
    pub budget_limit_usd: f64,
    pub budget_limit_microusd: u64,
    pub observed_spend_usd: f64,
    pub observed_spend_microusd: u64,
    pub ledger_hash: String,
    pub ledger_sequence: u64,
}

impl BudgetSafetyLedger {
    pub fn recomputed_hash(&self) -> String {
        budget_ledger_hash(
            self.scope,
            self.budget_limit_microusd,
            self.observed_spend_microusd,
            self.ledger_sequence,
        )
    }

    pub fn with_recomputed_hash(mut self) -> Self {
        self.ledger_hash = self.recomputed_hash();
        self
    }

    /// Authority-bearing ledger commit for realized spend.
    ///
    /// This method requires the full deterministic budget certification
    /// predicate, then rechecks ledger freshness before mutating state.
    pub fn commit_authorized_realized_cost(
        &mut self,
        certificate: &DeterministicBudgetCertificate,
        realized_microusd: u64,
    ) -> Result<(), String> {
        if !certificate.is_certifying() {
            return Err("budget certificate is not certifying".to_string());
        }
        if certificate.scope != self.scope {
            return Err("budget certificate scope does not match ledger scope".to_string());
        }
        if certificate.budget_limit_microusd != Some(self.budget_limit_microusd) {
            return Err("budget certificate limit does not match ledger limit".to_string());
        }
        if certificate.observed_spend_microusd != Some(self.observed_spend_microusd) {
            return Err("budget certificate observed spend is stale".to_string());
        }
        if certificate.ledger_sequence_before != self.ledger_sequence {
            return Err("budget certificate ledger sequence is stale".to_string());
        }
        let hard_cap_microusd = certificate
            .hard_cap_microusd
            .ok_or_else(|| "budget certificate is missing a hard cap".to_string())?;
        if realized_microusd > hard_cap_microusd {
            return Err("realized cost exceeds the certified hard cap".to_string());
        }
        let next_spend = self
            .observed_spend_microusd
            .checked_add(realized_microusd)
            .ok_or_else(|| "realized cost would overflow ledger spend".to_string())?;
        if next_spend > self.budget_limit_microusd {
            return Err("realized cost would exceed the budget limit".to_string());
        }
        self.observed_spend_microusd = next_spend;
        self.observed_spend_usd = microusd_to_usd_display(next_spend);
        self.ledger_sequence += 1;
        self.ledger_hash = self.recomputed_hash();
        Ok(())
    }

    /// Backward-compatible USD wrapper around `commit_authorized_realized_cost`.
    ///
    /// The float value is only accepted if it converts exactly to microusd.
    pub fn try_commit_realized_cost(
        &mut self,
        certificate: &DeterministicBudgetCertificate,
        realized_usd: f64,
    ) -> Result<(), String> {
        let realized_microusd = usd_to_microusd_exact_or_reject("realized_usd", realized_usd)?;
        self.commit_authorized_realized_cost(certificate, realized_microusd)
    }

    /// Authority-bearing ledger commit for realized spend authorized by a
    /// high-probability probabilistic certificate.
    ///
    /// This records realized cost for reconciliation. It does not create a
    /// deterministic hard-cap claim.
    pub fn commit_probabilistic_authorized_realized_cost(
        &mut self,
        certificate: &ProbabilisticBudgetCertificate,
        realized_microusd: u64,
    ) -> Result<(), String> {
        if !certificate.is_certifying() {
            return Err("probabilistic budget certificate is not certifying".to_string());
        }
        if certificate.scope != self.scope {
            return Err(
                "probabilistic budget certificate scope does not match ledger scope".to_string(),
            );
        }
        if certificate.budget_limit_microusd != Some(self.budget_limit_microusd) {
            return Err(
                "probabilistic budget certificate limit does not match ledger limit".to_string(),
            );
        }
        if certificate.observed_spend_microusd != Some(self.observed_spend_microusd) {
            return Err("probabilistic budget certificate observed spend is stale".to_string());
        }
        if certificate.ledger_sequence_before != self.ledger_sequence {
            return Err("probabilistic budget certificate ledger sequence is stale".to_string());
        }
        if certificate.pre_ledger_hash != self.ledger_hash {
            return Err("probabilistic budget certificate ledger hash is stale".to_string());
        }
        let next_spend = self
            .observed_spend_microusd
            .checked_add(realized_microusd)
            .ok_or_else(|| "realized cost would overflow ledger spend".to_string())?;
        self.observed_spend_microusd = next_spend;
        self.observed_spend_usd = microusd_to_usd_display(next_spend);
        self.ledger_sequence += 1;
        self.ledger_hash = self.recomputed_hash();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeterministicBudgetCertificate {
    pub schema_version: String,
    #[serde(default = "deterministic_budget_certificate_kind")]
    pub certificate_kind: BudgetCertificateKind,
    pub scope: BudgetScope,
    pub budget_limit_usd: f64,
    pub observed_spend_usd: f64,
    pub hard_cap_usd: f64,
    pub cap_provenance: CapProvenance,
    pub concurrency_model: ConcurrencyModel,
    pub action_hash: String,
    pub filtration_hash: String,
    pub ledger_sequence_before: u64,
    pub projected_spend_usd: f64,
    pub slack_usd: f64,
    pub outcome: BudgetOutcome,
    #[serde(default)]
    pub obligations: Vec<String>,
    #[serde(default)]
    pub theorem_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_spend_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_cap_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected_spend_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_microusd: Option<i64>,
}

impl DeterministicBudgetCertificate {
    pub fn is_certifying(&self) -> bool {
        // Keep this predicate in sync with `is_certifying` in
        // `src/velvet/budget_safety.py`.
        self.structural_validation_error().is_none()
            && matches!(
                self.cap_provenance,
                CapProvenance::ProviderEnforced
                    | CapProvenance::PrepaidReservation
                    | CapProvenance::EnforcedTokenCap
            )
            && self.concurrency_model == ConcurrencyModel::SingleWriterAtomic
            && self.outcome == BudgetOutcome::Admit
    }

    pub fn structural_validation_error(&self) -> Option<String> {
        if self.schema_version != DETERMINISTIC_BUDGET_SCHEMA_VERSION {
            return Some(format!(
                "Deterministic budget certificate schema_version {:?} is unsupported.",
                self.schema_version
            ));
        }
        if self.certificate_kind != BudgetCertificateKind::DeterministicHardCap {
            return Some(
                "Deterministic budget certificate_kind must be deterministic_hard_cap.".to_string(),
            );
        }
        for (label, value) in [
            ("budget_limit_usd", self.budget_limit_usd),
            ("observed_spend_usd", self.observed_spend_usd),
            ("hard_cap_usd", self.hard_cap_usd),
            ("projected_spend_usd", self.projected_spend_usd),
            ("slack_usd", self.slack_usd),
        ] {
            if !value.is_finite() {
                return Some(format!(
                    "Deterministic budget certificate has a non-finite {label} value."
                ));
            }
        }
        for (label, value) in [
            ("budget_limit_usd", self.budget_limit_usd),
            ("observed_spend_usd", self.observed_spend_usd),
            ("hard_cap_usd", self.hard_cap_usd),
        ] {
            if value < 0.0 {
                return Some(format!(
                    "Deterministic budget certificate has a negative {label} value."
                ));
            }
        }
        let Some(budget_limit_microusd) = self.budget_limit_microusd else {
            return Some(
                "Deterministic budget certificate is missing budget_limit_microusd.".to_string(),
            );
        };
        let Some(observed_spend_microusd) = self.observed_spend_microusd else {
            return Some(
                "Deterministic budget certificate is missing observed_spend_microusd.".to_string(),
            );
        };
        let Some(hard_cap_microusd) = self.hard_cap_microusd else {
            return Some(
                "Deterministic budget certificate is missing hard_cap_microusd.".to_string(),
            );
        };
        let Some(projected_spend_microusd) = self.projected_spend_microusd else {
            return Some(
                "Deterministic budget certificate is missing projected_spend_microusd.".to_string(),
            );
        };
        let Some(slack_microusd) = self.slack_microusd else {
            return Some("Deterministic budget certificate is missing slack_microusd.".to_string());
        };

        if !usd_display_matches_microusd(self.budget_limit_usd, budget_limit_microusd)
            || !usd_display_matches_microusd(self.observed_spend_usd, observed_spend_microusd)
            || !usd_display_matches_microusd(self.hard_cap_usd, hard_cap_microusd)
            || !usd_display_matches_microusd(self.projected_spend_usd, projected_spend_microusd)
        {
            return Some(
                "Deterministic budget certificate USD display fields do not match microusd authority fields.".to_string(),
            );
        }
        let Some(projected) = observed_spend_microusd.checked_add(hard_cap_microusd) else {
            return Some(
                "Deterministic budget certificate projected_spend_microusd overflows.".to_string(),
            );
        };
        if projected_spend_microusd != projected {
            return Some(
                "Deterministic budget certificate projected_spend_microusd does not match observed_spend_microusd + hard_cap_microusd.".to_string(),
            );
        }
        let slack = i128::from(budget_limit_microusd) - i128::from(projected);
        if slack < i128::from(i64::MIN) || slack > i128::from(i64::MAX) {
            return Some(
                "Deterministic budget certificate slack_microusd is out of range.".to_string(),
            );
        }
        let slack = slack as i64;
        if slack_microusd != slack {
            return Some(
                "Deterministic budget certificate slack_microusd does not match budget_limit_microusd - projected_spend_microusd.".to_string(),
            );
        }
        if !usd_display_matches_slack(self.slack_usd, slack_microusd) {
            return Some(
                "Deterministic budget certificate slack_usd display field does not match slack_microusd.".to_string(),
            );
        }
        let implied_outcome = if projected <= budget_limit_microusd {
            BudgetOutcome::Admit
        } else {
            BudgetOutcome::Block
        };
        if self.outcome != implied_outcome {
            return Some(format!(
                "Deterministic budget certificate outcome {:?} does not match the hard-cap rule; expected {:?}.",
                self.outcome, implied_outcome
            ));
        }
        for obligation in MANDATORY_DETERMINISTIC_BUDGET_OBLIGATIONS {
            if !self.obligations.iter().any(|item| item == obligation) {
                return Some(format!(
                    "Deterministic budget certificate is missing mandatory obligation {obligation:?}."
                ));
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProbabilisticBudgetCertificate {
    pub schema_version: String,
    pub certificate_kind: BudgetCertificateKind,
    pub scope: BudgetScope,
    pub budget_limit: f64,
    pub delta_total: f64,
    pub observed_spend: f64,
    #[serde(default)]
    pub certified_mean_sum: f64,
    #[serde(default)]
    pub cgf_sum_by_lambda: BTreeMap<String, f64>,
    #[serde(default)]
    pub lambda_grid: Vec<f64>,
    #[serde(default)]
    pub mixture_weights: Vec<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_upper: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variance_upper: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_moment_upper: Option<f64>,
    pub action_hash: String,
    pub filtration_hash: String,
    pub ledger_sequence_before: u64,
    pub pre_ledger_hash: String,
    pub cost_model_id: String,
    pub high_probability_bound: f64,
    pub slack: f64,
    pub outcome: BudgetOutcome,
    #[serde(default)]
    pub obligations: Vec<String>,
    #[serde(default)]
    pub theorem_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_spend_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_probability_bound_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_microusd: Option<i64>,
}

impl ProbabilisticBudgetCertificate {
    pub fn is_certifying(&self) -> bool {
        self.structural_validation_error().is_none() && self.outcome == BudgetOutcome::Admit
    }

    pub fn structural_validation_error(&self) -> Option<String> {
        if self.schema_version != PROBABILISTIC_BUDGET_SCHEMA_VERSION {
            return Some(format!(
                "Probabilistic budget certificate schema_version {:?} is unsupported.",
                self.schema_version
            ));
        }
        if !matches!(
            self.certificate_kind,
            BudgetCertificateKind::CgfVille | BudgetCertificateKind::MomentCantelli
        ) {
            return Some(
                "Probabilistic budget certificate_kind must be cgf_ville or moment_cantelli."
                    .to_string(),
            );
        }
        for (label, value) in [
            ("budget_limit", self.budget_limit),
            ("observed_spend", self.observed_spend),
            ("certified_mean_sum", self.certified_mean_sum),
            ("high_probability_bound", self.high_probability_bound),
            ("slack", self.slack),
        ] {
            if !value.is_finite() {
                return Some(format!(
                    "Probabilistic budget certificate has a non-finite {label} value."
                ));
            }
        }
        for (label, value) in [
            ("budget_limit", self.budget_limit),
            ("observed_spend", self.observed_spend),
            ("certified_mean_sum", self.certified_mean_sum),
            ("high_probability_bound", self.high_probability_bound),
        ] {
            if value < 0.0 {
                return Some(format!(
                    "Probabilistic budget certificate has a negative {label} value."
                ));
            }
        }
        if !(0.0..1.0).contains(&self.delta_total) {
            return Some(
                "Probabilistic budget certificate delta_total must be in (0, 1).".to_string(),
            );
        }
        if self.cost_model_id.trim().is_empty() {
            return Some(
                "Probabilistic budget certificate requires a non-empty cost_model_id.".to_string(),
            );
        }
        let Some(budget_limit_microusd) = self.budget_limit_microusd else {
            return Some(
                "Probabilistic budget certificate is missing budget_limit_microusd.".to_string(),
            );
        };
        let Some(observed_spend_microusd) = self.observed_spend_microusd else {
            return Some(
                "Probabilistic budget certificate is missing observed_spend_microusd.".to_string(),
            );
        };
        let Some(high_probability_bound_microusd) = self.high_probability_bound_microusd else {
            return Some(
                "Probabilistic budget certificate is missing high_probability_bound_microusd."
                    .to_string(),
            );
        };
        let Some(slack_microusd) = self.slack_microusd else {
            return Some("Probabilistic budget certificate is missing slack_microusd.".to_string());
        };
        if !usd_display_matches_microusd(self.budget_limit, budget_limit_microusd)
            || !usd_display_matches_microusd(self.observed_spend, observed_spend_microusd)
        {
            return Some(
                "Probabilistic budget certificate USD display fields do not match microusd authority fields.".to_string(),
            );
        }
        let computed_bound = match self.certificate_kind {
            BudgetCertificateKind::CgfVille => self.cgf_ville_bound(),
            BudgetCertificateKind::MomentCantelli => self.moment_cantelli_bound(),
            BudgetCertificateKind::DeterministicHardCap => unreachable!(),
        };
        let computed_bound = match computed_bound {
            Ok(value) => value,
            Err(reason) => return Some(reason),
        };
        if (self.high_probability_bound - computed_bound).abs()
            > DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
        {
            return Some(
                "Probabilistic budget certificate high_probability_bound does not recompute."
                    .to_string(),
            );
        }
        let computed_bound_microusd =
            match usd_to_microusd_ceil_or_reject("high_probability_bound", computed_bound) {
                Ok(value) => value,
                Err(reason) => return Some(reason),
            };
        if high_probability_bound_microusd != computed_bound_microusd {
            return Some(
                "Probabilistic budget certificate high_probability_bound_microusd does not conservatively round the recomputed bound.".to_string(),
            );
        }
        let slack = i128::from(budget_limit_microusd) - i128::from(high_probability_bound_microusd);
        if slack < i128::from(i64::MIN) || slack > i128::from(i64::MAX) {
            return Some(
                "Probabilistic budget certificate slack_microusd is out of range.".to_string(),
            );
        }
        let slack = slack as i64;
        if slack_microusd != slack {
            return Some(
                "Probabilistic budget certificate slack_microusd does not match budget_limit_microusd - high_probability_bound_microusd.".to_string(),
            );
        }
        if !usd_display_matches_slack(self.slack, slack_microusd) {
            return Some(
                "Probabilistic budget certificate slack display field does not match slack_microusd."
                    .to_string(),
            );
        }
        let implied_outcome = if high_probability_bound_microusd <= budget_limit_microusd {
            BudgetOutcome::Admit
        } else {
            BudgetOutcome::Block
        };
        if self.outcome != implied_outcome {
            return Some(format!(
                "Probabilistic budget certificate outcome {:?} does not match the high-probability envelope; expected {:?}.",
                self.outcome, implied_outcome
            ));
        }
        let expected_pre_ledger_hash = budget_ledger_hash(
            self.scope,
            budget_limit_microusd,
            observed_spend_microusd,
            self.ledger_sequence_before,
        );
        if self.pre_ledger_hash != expected_pre_ledger_hash {
            return Some(
                "Probabilistic budget certificate pre_ledger_hash does not match the budget ledger snapshot.".to_string(),
            );
        }
        for obligation in MANDATORY_PROBABILISTIC_BUDGET_OBLIGATIONS {
            if !self.obligations.iter().any(|item| item == obligation) {
                return Some(format!(
                    "Probabilistic budget certificate is missing mandatory obligation {obligation:?}."
                ));
            }
        }
        if !self
            .theorem_refs
            .iter()
            .any(|item| item == "docs/math/adaptive_spend_safety_theorem.txt")
        {
            return Some(
                "Probabilistic budget certificate is missing adaptive spend theorem reference."
                    .to_string(),
            );
        }
        None
    }

    fn cgf_ville_bound(&self) -> Result<f64, String> {
        if self.lambda_grid.is_empty() {
            return Err(
                "CGF/Ville budget certificate requires a non-empty lambda_grid.".to_string(),
            );
        }
        if self.lambda_grid.len() != self.mixture_weights.len() {
            return Err(
                "CGF/Ville budget certificate lambda_grid and mixture_weights lengths differ."
                    .to_string(),
            );
        }
        let mut weight_sum = 0.0;
        let mut best_margin = f64::INFINITY;
        for (lambda, weight) in self.lambda_grid.iter().zip(self.mixture_weights.iter()) {
            if !lambda.is_finite() || *lambda <= 0.0 {
                return Err(
                    "CGF/Ville budget certificate lambda values must be positive finite values."
                        .to_string(),
                );
            }
            if !weight.is_finite() || *weight <= 0.0 {
                return Err(
                    "CGF/Ville budget certificate mixture weights must be positive finite values."
                        .to_string(),
                );
            }
            weight_sum += *weight;
            let psi = self.cgf_sum_for_lambda(*lambda).ok_or_else(|| {
                "CGF/Ville budget certificate is missing a cgf_sum_by_lambda term.".to_string()
            })?;
            if !psi.is_finite() {
                return Err(
                    "CGF/Ville budget certificate has a non-finite cgf_sum_by_lambda term."
                        .to_string(),
                );
            }
            let margin = (psi + (1.0 / (self.delta_total * *weight)).ln()) / *lambda;
            if !margin.is_finite() {
                return Err("CGF/Ville budget certificate envelope is non-finite.".to_string());
            }
            best_margin = best_margin.min(margin);
        }
        if weight_sum > 1.0 + DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON {
            return Err(
                "CGF/Ville budget certificate mixture weights must sum to at most 1.".to_string(),
            );
        }
        Ok(self.observed_spend + self.certified_mean_sum + best_margin)
    }

    fn cgf_sum_for_lambda(&self, lambda: f64) -> Option<f64> {
        self.cgf_sum_by_lambda
            .get(&lambda.to_string())
            .copied()
            .or_else(|| {
                self.cgf_sum_by_lambda.iter().find_map(|(key, value)| {
                    key.parse::<f64>().ok().and_then(|parsed| {
                        if (parsed - lambda).abs() <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON {
                            Some(*value)
                        } else {
                            None
                        }
                    })
                })
            })
    }

    fn moment_cantelli_bound(&self) -> Result<f64, String> {
        let Some(mean_upper) = self.mean_upper else {
            return Err("Moment-only Cantelli budget certificate requires mean_upper.".to_string());
        };
        if !mean_upper.is_finite() || mean_upper < 0.0 {
            return Err(
                "Moment-only Cantelli budget certificate mean_upper must be non-negative finite."
                    .to_string(),
            );
        }
        let scale_square = self
            .variance_upper
            .or(self.second_moment_upper)
            .ok_or_else(|| {
                "Moment-only Cantelli budget certificate requires variance_upper or second_moment_upper.".to_string()
            })?;
        if !scale_square.is_finite() || scale_square < 0.0 {
            return Err(
                "Moment-only Cantelli budget certificate variance/second moment upper bound must be non-negative finite.".to_string(),
            );
        }
        Ok(self.observed_spend
            + mean_upper
            + ((1.0 - self.delta_total) / self.delta_total).sqrt() * scale_square.sqrt())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum BudgetCertificate {
    Deterministic(DeterministicBudgetCertificate),
    Probabilistic(ProbabilisticBudgetCertificate),
}

impl BudgetCertificate {
    pub fn certificate_kind(&self) -> BudgetCertificateKind {
        match self {
            Self::Deterministic(_) => BudgetCertificateKind::DeterministicHardCap,
            Self::Probabilistic(certificate) => certificate.certificate_kind,
        }
    }

    pub fn outcome(&self) -> BudgetOutcome {
        match self {
            Self::Deterministic(certificate) => certificate.outcome,
            Self::Probabilistic(certificate) => certificate.outcome,
        }
    }

    pub fn scope(&self) -> BudgetScope {
        match self {
            Self::Deterministic(certificate) => certificate.scope,
            Self::Probabilistic(certificate) => certificate.scope,
        }
    }

    pub fn ledger_sequence_before(&self) -> u64 {
        match self {
            Self::Deterministic(certificate) => certificate.ledger_sequence_before,
            Self::Probabilistic(certificate) => certificate.ledger_sequence_before,
        }
    }

    pub fn is_certifying(&self) -> bool {
        match self {
            Self::Deterministic(certificate) => certificate.is_certifying(),
            Self::Probabilistic(certificate) => certificate.is_certifying(),
        }
    }

    pub fn structural_validation_error(&self) -> Option<String> {
        match self {
            Self::Deterministic(certificate) => certificate.structural_validation_error(),
            Self::Probabilistic(certificate) => certificate.structural_validation_error(),
        }
    }
}

pub fn microusd_to_usd_display(value: u64) -> f64 {
    value as f64 / MICROUSD_PER_USD as f64
}

pub fn slack_microusd_to_usd_display(value: i64) -> f64 {
    value as f64 / MICROUSD_PER_USD as f64
}

pub fn usd_to_microusd_exact_or_reject(label: &str, value: f64) -> Result<u64, String> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!("{label} must be a non-negative finite value"));
    }
    let scaled = value * MICROUSD_PER_USD as f64;
    let rounded = scaled.round();
    if (scaled - rounded).abs() > DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON {
        return Err(format!("{label} is not exactly representable in microusd"));
    }
    if rounded > u64::MAX as f64 {
        return Err(format!("{label} exceeds the microusd range"));
    }
    Ok(rounded as u64)
}

pub fn usd_to_microusd_ceil_or_reject(label: &str, value: f64) -> Result<u64, String> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!("{label} must be a non-negative finite value"));
    }
    let scaled = value * MICROUSD_PER_USD as f64;
    let ceiled = (scaled - DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON).ceil();
    if ceiled > u64::MAX as f64 {
        return Err(format!("{label} exceeds the microusd range"));
    }
    Ok(ceiled as u64)
}

pub fn budget_ledger_hash(
    scope: BudgetScope,
    budget_limit_microusd: u64,
    observed_spend_microusd: u64,
    ledger_sequence: u64,
) -> String {
    #[derive(Serialize)]
    struct HashMaterial {
        scope: BudgetScope,
        budget_limit_microusd: u64,
        observed_spend_microusd: u64,
        ledger_sequence: u64,
    }

    stable_hash_json(&HashMaterial {
        scope,
        budget_limit_microusd,
        observed_spend_microusd,
        ledger_sequence,
    })
}

fn usd_display_matches_microusd(display_usd: f64, authority_microusd: u64) -> bool {
    display_usd.is_finite()
        && display_usd >= 0.0
        && (display_usd - microusd_to_usd_display(authority_microusd)).abs()
            <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
}

fn usd_display_matches_slack(display_usd: f64, authority_microusd: i64) -> bool {
    display_usd.is_finite()
        && (display_usd - slack_microusd_to_usd_display(authority_microusd)).abs()
            <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompetitorResult {
    pub system: String,
    pub system_version: String,
    pub adapter_kind: String,
    pub case_id: String,
    pub status: String,
    pub decision: String,
    pub certificate_supported: bool,
    #[serde(default)]
    pub certificate_outcome: Option<CertificateOutcome>,
    pub blocked: bool,
    pub skipped: bool,
    #[serde(default)]
    pub liability_cost: Option<f64>,
    #[serde(default)]
    pub evidence_url: Option<String>,
    #[serde(default)]
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub rule_id: String,
    pub evidence_type: String,
    pub message: String,
    #[serde(default)]
    pub details: JsonObject,
}

impl Evidence {
    pub fn new(rule_id: impl Into<String>, evidence_type: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            evidence_type: evidence_type.into(),
            message: String::new(),
            details: JsonObject::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyReason {
    pub code: String,
    pub message: String,
    #[serde(default = "default_policy_severity")]
    pub severity: String,
}

fn default_policy_severity() -> String {
    "info".to_string()
}

impl PolicyReason {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        severity: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: severity.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Redaction {
    pub field_path: String,
    pub original_value: String,
    pub replacement: String,
    pub original_hash: String,
    pub detector: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ActionMutation {
    #[serde(default)]
    pub parameter_updates: JsonObject,
    #[serde(default)]
    pub metadata_updates: JsonObject,
    #[serde(default)]
    pub redactions: Vec<Redaction>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub jurisdiction_evidence: Option<Evidence>,
}

impl ActionMutation {
    pub fn is_empty(&self) -> bool {
        self.parameter_updates.is_empty()
            && self.metadata_updates.is_empty()
            && self.redactions.is_empty()
            && self.notes.is_empty()
            && self.jurisdiction_evidence.is_none()
    }

    pub fn apply_to(&self, action: &mut CandidateAction) {
        for (key, value) in &self.parameter_updates {
            action.parameters.insert(key.clone(), value.clone());
        }
        for (key, value) in &self.metadata_updates {
            action.metadata.insert(key.clone(), value.clone());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscalationTarget {
    pub target_type: String,
    pub target: String,
    #[serde(default = "default_escalation_mode")]
    pub mode: String,
    #[serde(default = "default_escalation_fallback")]
    pub fallback: String,
    #[serde(default)]
    pub payload: Value,
}

fn default_escalation_mode() -> String {
    "sync".to_string()
}

fn default_escalation_fallback() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny {
        reason: PolicyReason,
        jurisdiction_evidence: Evidence,
    },
    Modify {
        mutation: ActionMutation,
        reason: PolicyReason,
    },
    Defer {
        to: EscalationTarget,
        reason: PolicyReason,
        jurisdiction_evidence: Evidence,
    },
}

impl PolicyDecision {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny { .. } => "deny",
            Self::Modify { .. } => "modify",
            Self::Defer { .. } => "defer",
        }
    }

    pub fn reason(&self) -> Option<&PolicyReason> {
        match self {
            Self::Allow => None,
            Self::Deny { reason, .. }
            | Self::Modify { reason, .. }
            | Self::Defer { reason, .. } => Some(reason),
        }
    }

    pub fn jurisdiction_evidence(&self) -> Option<&Evidence> {
        match self {
            Self::Deny {
                jurisdiction_evidence,
                ..
            }
            | Self::Defer {
                jurisdiction_evidence,
                ..
            } => Some(jurisdiction_evidence),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyTraceEntry {
    pub policy_name: String,
    pub policy_kind: String,
    pub policy_version: String,
    pub config_version: String,
    pub config_hash: String,
    pub status: String,
    pub decision: PolicyDecision,
    #[serde(default)]
    pub jurisdiction_evidence: Option<Evidence>,
    #[serde(default)]
    pub mutation: Option<ActionMutation>,
    pub input_action_hash: String,
    pub output_action_hash: String,
    pub elapsed_us: u64,
    #[serde(default)]
    pub short_circuit: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetLedger {
    #[serde(default)]
    pub limit_usd: Option<f64>,
    #[serde(default)]
    pub spent_usd: f64,
    #[serde(default)]
    pub limit_units: Option<f64>,
    #[serde(default)]
    pub spent_units: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimeWindow {
    pub start_unix_ms: i64,
    pub end_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyContext {
    #[serde(default)]
    pub permissions: BTreeSet<String>,
    #[serde(default)]
    pub approved_actions: BTreeSet<ActionType>,
    #[serde(default = "default_privacy_mode")]
    pub privacy_mode: String,
    #[serde(default)]
    pub organization_policy: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub decision_unix_ms: i64,
    #[serde(default)]
    pub time_window: Option<TimeWindow>,
    #[serde(default)]
    pub task_budget: BudgetLedger,
    #[serde(default)]
    pub user_budget: BudgetLedger,
    #[serde(default)]
    pub organization_budget: BudgetLedger,
    #[serde(default)]
    pub prior_thread: Vec<Value>,
    #[serde(default)]
    pub novelty_score: Option<f64>,
    #[serde(default)]
    pub realized_costs: BTreeMap<String, BudgetLedger>,
    #[serde(default)]
    pub external_observations: JsonObject,
}

fn default_privacy_mode() -> String {
    "standard".to_string()
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            permissions: BTreeSet::new(),
            approved_actions: BTreeSet::new(),
            privacy_mode: default_privacy_mode(),
            organization_policy: None,
            user_id: None,
            organization_id: None,
            task_id: None,
            decision_unix_ms: 0,
            time_window: None,
            task_budget: BudgetLedger::default(),
            user_budget: BudgetLedger::default(),
            organization_budget: BudgetLedger::default(),
            prior_thread: Vec::new(),
            novelty_score: None,
            realized_costs: BTreeMap::new(),
            external_observations: JsonObject::new(),
        }
    }
}

impl PolicyContext {
    pub fn from_state(state: &Value) -> Self {
        let Some(raw) = state.get("policy_context").and_then(Value::as_object) else {
            return Self::default();
        };
        let permissions = raw
            .get("permissions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect();
        let approved_actions = raw
            .get("approved_actions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| serde_json::from_value(value.clone()).ok())
            .collect();
        Self {
            permissions,
            approved_actions,
            privacy_mode: raw
                .get("privacy_mode")
                .and_then(Value::as_str)
                .unwrap_or("standard")
                .to_string(),
            organization_policy: optional_string(raw.get("organization_policy")),
            user_id: optional_string(raw.get("user_id")),
            organization_id: optional_string(raw.get("organization_id")),
            task_id: optional_string(raw.get("task_id")),
            decision_unix_ms: raw
                .get("decision_unix_ms")
                .and_then(Value::as_i64)
                .unwrap_or_else(|| {
                    state
                        .get("decision_unix_ms")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                }),
            time_window: raw
                .get("time_window")
                .and_then(|value| serde_json::from_value(value.clone()).ok()),
            task_budget: parse_budget_ledger(raw.get("task_budget")),
            user_budget: parse_budget_ledger(raw.get("user_budget")),
            organization_budget: parse_budget_ledger(raw.get("organization_budget")),
            prior_thread: raw
                .get("prior_thread")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            novelty_score: raw
                .get("novelty_score")
                .or_else(|| state.get("novelty_score"))
                .and_then(Value::as_f64),
            realized_costs: raw
                .get("realized_costs")
                .and_then(Value::as_object)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|(key, value)| {
                            serde_json::from_value(value.clone())
                                .ok()
                                .map(|ledger| (key.clone(), ledger))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            external_observations: raw
                .get("external_observations")
                .and_then(Value::as_object)
                .cloned()
                .map(|values| values.into_iter().collect())
                .unwrap_or_default(),
        }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }
}

fn parse_budget_ledger(value: Option<&Value>) -> BudgetLedger {
    value
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn default_override_rate() -> f64 {
    1.0
}

fn default_surprisal_cap() -> f64 {
    1.0
}

fn default_lambda_cap() -> f64 {
    1.0
}

fn default_horizon_floor() -> f64 {
    0.34
}

fn default_scarcity_strength() -> f64 {
    0.75
}

fn default_cost_strength() -> f64 {
    0.18
}

fn default_risk_strength() -> f64 {
    1.0
}

fn default_uncertainty_strength() -> f64 {
    1.0
}

fn default_override_rate_floor() -> f64 {
    0.05
}

fn default_override_rate_cap() -> f64 {
    3.0
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PricingPolicy {
    FixedPriceBaseline,
    LinearExhaustion,
    InverseHorizon,
    OverrideRateAware,
    RiskWeighted,
    UncertaintyCompensated,
    #[default]
    HybridProduction,
}

impl PricingPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedPriceBaseline => "fixed_price_baseline",
            Self::LinearExhaustion => "linear_exhaustion",
            Self::InverseHorizon => "inverse_horizon",
            Self::OverrideRateAware => "override_rate_aware",
            Self::RiskWeighted => "risk_weighted",
            Self::UncertaintyCompensated => "uncertainty_compensated",
            Self::HybridProduction => "hybrid_production",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BudgetState {
    pub tokens_remaining: f64,
    pub tool_calls_remaining: f64,
    pub latency_ms_remaining: f64,
    pub dollars_remaining: f64,
    pub model_escalations_remaining: f64,
    pub memory_writes_remaining: f64,
    pub concierge_reviews_remaining: f64,
    pub retrievals_remaining: f64,
    pub task_horizon_remaining: f64,
    pub confidence_deficit: f64,
    pub task_importance: f64,
    pub money_remaining: f64,
    pub api_calls_remaining: f64,
    pub compute_remaining: f64,
    pub user_attention_remaining: f64,
    pub memory_slots_remaining: f64,
    pub fallback_triggers: Vec<String>,
}

impl Default for BudgetState {
    fn default() -> Self {
        Self {
            tokens_remaining: 1.0,
            tool_calls_remaining: 1.0,
            latency_ms_remaining: 1.0,
            dollars_remaining: 1.0,
            model_escalations_remaining: 1.0,
            memory_writes_remaining: 1.0,
            concierge_reviews_remaining: 1.0,
            retrievals_remaining: 1.0,
            task_horizon_remaining: 1.0,
            confidence_deficit: 0.0,
            task_importance: 0.5,
            money_remaining: 1.0,
            api_calls_remaining: 1.0,
            compute_remaining: 1.0,
            user_attention_remaining: 1.0,
            memory_slots_remaining: 1.0,
            fallback_triggers: Vec::new(),
        }
    }
}

impl BudgetState {
    pub fn from_state(state: &Value) -> Self {
        let Some(raw) = state.get("budget_state").and_then(Value::as_object) else {
            let mut state = Self::default();
            state
                .fallback_triggers
                .push("budget_state_missing_default_full".to_string());
            return state;
        };
        let mut fallback_triggers = Vec::new();
        let tokens_remaining = budget_fraction(
            raw.get("tokens_remaining"),
            "tokens_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let tool_calls_remaining = budget_fraction(
            raw.get("tool_calls_remaining")
                .or_else(|| raw.get("api_calls_remaining")),
            "tool_calls_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let latency_ms_remaining = budget_fraction(
            raw.get("latency_ms_remaining")
                .or_else(|| raw.get("latency_remaining")),
            "latency_ms_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let dollars_remaining = budget_fraction(
            raw.get("dollars_remaining")
                .or_else(|| raw.get("money_remaining")),
            "dollars_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let model_escalations_remaining = budget_fraction(
            raw.get("model_escalations_remaining")
                .or_else(|| raw.get("compute_remaining")),
            "model_escalations_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let memory_writes_remaining = budget_fraction(
            raw.get("memory_writes_remaining")
                .or_else(|| raw.get("memory_slots_remaining")),
            "memory_writes_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let concierge_reviews_remaining = budget_fraction(
            raw.get("concierge_reviews_remaining")
                .or_else(|| raw.get("user_attention_remaining")),
            "concierge_reviews_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let retrievals_remaining = budget_fraction(
            raw.get("retrievals_remaining"),
            "retrievals_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let task_horizon_remaining = budget_fraction(
            raw.get("task_horizon_remaining")
                .or_else(|| raw.get("remaining_task_horizon")),
            "task_horizon_remaining",
            1.0,
            &mut fallback_triggers,
        );
        let confidence_deficit = budget_fraction(
            raw.get("confidence_deficit"),
            "confidence_deficit",
            0.0,
            &mut fallback_triggers,
        );
        let task_importance = budget_fraction(
            raw.get("task_importance").or_else(|| raw.get("risk_tier")),
            "task_importance",
            0.5,
            &mut fallback_triggers,
        );
        Self {
            tokens_remaining,
            tool_calls_remaining,
            latency_ms_remaining,
            dollars_remaining,
            model_escalations_remaining,
            memory_writes_remaining,
            concierge_reviews_remaining,
            retrievals_remaining,
            task_horizon_remaining,
            confidence_deficit,
            task_importance,
            money_remaining: dollars_remaining,
            api_calls_remaining: tool_calls_remaining,
            compute_remaining: model_escalations_remaining,
            user_attention_remaining: concierge_reviews_remaining,
            memory_slots_remaining: memory_writes_remaining,
            fallback_triggers,
        }
    }

    pub fn pressure(&self) -> f64 {
        let remaining = [
            self.tokens_remaining,
            self.tool_calls_remaining,
            self.latency_ms_remaining,
            self.dollars_remaining,
            self.model_escalations_remaining,
            self.memory_writes_remaining,
            self.concierge_reviews_remaining,
            self.retrievals_remaining,
            self.task_horizon_remaining,
        ];
        let average_remaining = remaining.iter().sum::<f64>() / remaining.len() as f64;
        clamp01(1.0 - average_remaining)
    }

    pub fn minimum_remaining(&self) -> f64 {
        [
            self.tokens_remaining,
            self.tool_calls_remaining,
            self.latency_ms_remaining,
            self.dollars_remaining,
            self.model_escalations_remaining,
            self.memory_writes_remaining,
            self.concierge_reviews_remaining,
            self.retrievals_remaining,
            self.task_horizon_remaining,
        ]
        .into_iter()
        .fold(1.0, f64::min)
    }

    pub fn remaining_for_cost_key(&self, key: &str) -> f64 {
        match key {
            "tokens" => self.tokens_remaining,
            "latency" => self.latency_ms_remaining,
            "money" => self.dollars_remaining,
            "compute" => self.model_escalations_remaining,
            "api_calls" => self.tool_calls_remaining,
            "context_pollution" => self.task_horizon_remaining,
            "memory_bloat" => self.memory_writes_remaining,
            "user_attention" => self.concierge_reviews_remaining,
            "privacy_exposure" => 1.0,
            "coordination_overhead" | "opportunity_cost" => self.task_horizon_remaining,
            _ => 1.0,
        }
    }
}

fn budget_fraction(
    value: Option<&Value>,
    field: &str,
    default: f64,
    fallback_triggers: &mut Vec<String>,
) -> f64 {
    let parsed = number_value(value, default);
    if value.is_none() {
        return default;
    }
    if !parsed.is_finite() {
        fallback_triggers.push(format!("budget_{field}_malformed_defaulted"));
        return default;
    }
    clamp01(parsed)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PricingContext {
    pub pricing_policy: PricingPolicy,
    pub pricing_policy_version: String,
    pub budget_state: BudgetState,
    pub override_rate: f64,
    pub surprisal_cap: f64,
    pub lambda_floor: f64,
    pub lambda_cap: f64,
    pub horizon_floor: f64,
    pub scarcity_strength: f64,
    pub cost_strength: f64,
    pub risk_strength: f64,
    pub uncertainty_strength: f64,
    pub override_rate_floor: f64,
    pub override_rate_cap: f64,
    pub scarcity_multiplier: f64,
    pub risk_multiplier: f64,
}

impl Default for PricingContext {
    fn default() -> Self {
        Self {
            pricing_policy: PricingPolicy::default(),
            pricing_policy_version: crate::PRICING_POLICY_VERSION.to_string(),
            budget_state: BudgetState::default(),
            override_rate: default_override_rate(),
            surprisal_cap: default_surprisal_cap(),
            lambda_floor: 0.0,
            lambda_cap: default_lambda_cap(),
            horizon_floor: default_horizon_floor(),
            scarcity_strength: default_scarcity_strength(),
            cost_strength: default_cost_strength(),
            risk_strength: default_risk_strength(),
            uncertainty_strength: default_uncertainty_strength(),
            override_rate_floor: default_override_rate_floor(),
            override_rate_cap: default_override_rate_cap(),
            scarcity_multiplier: 1.0,
            risk_multiplier: 1.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PricingBreakdown {
    pub pricing_policy: PricingPolicy,
    pub pricing_policy_name: String,
    pub pricing_policy_version: String,
    pub base_entry_price: f64,
    pub fixed_baseline_price: f64,
    pub entry_price: f64,
    pub final_lambda: f64,
    pub budget_state: BudgetState,
    pub action_cost: CostVector,
    pub horizon_multiplier: f64,
    pub scarcity_multiplier: f64,
    pub override_rate_multiplier: f64,
    pub action_cost_adjustment: f64,
    pub uncertainty_adjustment: f64,
    pub risk_adjustment: f64,
    pub scarcity_pressure: f64,
    pub weighted_scarcity: f64,
    pub effective_horizon: f64,
    pub override_rate: f64,
    pub cap_applied: bool,
    pub floor_applied: bool,
    pub fail_safe_applied: bool,
    pub hard_budget_exhausted: bool,
    pub clears_rope: bool,
    pub fixed_clears_rope: bool,
    pub differs_from_fixed: bool,
    pub fallback_triggers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PricingSignals {
    pub expected_upside: f64,
    pub surprisal: f64,
    pub confidence: f64,
    pub clearance_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouterConfig {
    pub config_version: String,
    pub seal_seed: u64,
    pub max_candidates: usize,
    pub pricing_context: PricingContext,
    #[serde(default)]
    pub admission_config: crate::AdmissionConfig,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            config_version: "router_config_v1".to_string(),
            seal_seed: 0,
            max_candidates: 64,
            pricing_context: PricingContext::default(),
            admission_config: crate::AdmissionConfig::default(),
        }
    }
}

impl RouterConfig {
    pub fn from_state(state: &Value) -> Self {
        let mut config = Self::default();
        config.pricing_context.budget_state = BudgetState::from_state(state);
        if let Some(raw) = state.get("admission_config")
            && let Ok(admission_config) =
                serde_json::from_value::<crate::AdmissionConfig>(raw.clone())
        {
            config.admission_config = admission_config;
        }
        if let Some(policy) = parse_pricing_policy(state.get("pricing_policy")) {
            config.pricing_context.pricing_policy = policy;
        }
        if let Some(seed) = state.get("seal_seed").and_then(Value::as_u64) {
            config.seal_seed = seed;
        }
        if let Some(raw) = state.get("router_config").and_then(Value::as_object) {
            if let Some(version) = raw.get("config_version").and_then(Value::as_str) {
                config.config_version = version.to_string();
            }
            if let Some(seed) = raw.get("seal_seed").and_then(Value::as_u64) {
                config.seal_seed = seed;
            }
            if let Some(max_candidates) = raw.get("max_candidates").and_then(Value::as_u64) {
                config.max_candidates = max_candidates as usize;
            }
            if let Some(raw_admission) = raw.get("admission_config")
                && let Ok(admission_config) =
                    serde_json::from_value::<crate::AdmissionConfig>(raw_admission.clone())
            {
                config.admission_config = admission_config;
            }
            if let Some(policy) = parse_pricing_policy(raw.get("pricing_policy")) {
                config.pricing_context.pricing_policy = policy;
            }
            if let Some(version) = raw.get("pricing_policy_version").and_then(Value::as_str) {
                config.pricing_context.pricing_policy_version = version.to_string();
            }
            config.pricing_context.override_rate = finite_nonnegative(
                number_value(
                    raw.get("override_rate"),
                    config.pricing_context.override_rate,
                ),
                config.pricing_context.override_rate,
            );
            config.pricing_context.surprisal_cap = finite_positive(
                number_value(
                    raw.get("surprisal_cap"),
                    config.pricing_context.surprisal_cap,
                ),
                config.pricing_context.surprisal_cap,
            );
            config.pricing_context.lambda_floor = finite_nonnegative(
                number_value(raw.get("lambda_floor"), config.pricing_context.lambda_floor),
                config.pricing_context.lambda_floor,
            );
            config.pricing_context.lambda_cap = finite_positive(
                number_value(raw.get("lambda_cap"), config.pricing_context.lambda_cap),
                config.pricing_context.lambda_cap,
            );
            config.pricing_context.horizon_floor = finite_positive(
                number_value(
                    raw.get("horizon_floor"),
                    config.pricing_context.horizon_floor,
                ),
                config.pricing_context.horizon_floor,
            );
            config.pricing_context.scarcity_strength = finite_nonnegative(
                number_value(
                    raw.get("scarcity_strength"),
                    config.pricing_context.scarcity_strength,
                ),
                config.pricing_context.scarcity_strength,
            );
            config.pricing_context.cost_strength = finite_nonnegative(
                number_value(
                    raw.get("cost_strength"),
                    config.pricing_context.cost_strength,
                ),
                config.pricing_context.cost_strength,
            );
            config.pricing_context.risk_strength = finite_nonnegative(
                number_value(
                    raw.get("risk_strength"),
                    config.pricing_context.risk_strength,
                ),
                config.pricing_context.risk_strength,
            );
            config.pricing_context.uncertainty_strength = finite_nonnegative(
                number_value(
                    raw.get("uncertainty_strength"),
                    config.pricing_context.uncertainty_strength,
                ),
                config.pricing_context.uncertainty_strength,
            );
            config.pricing_context.override_rate_floor = finite_positive(
                number_value(
                    raw.get("override_rate_floor"),
                    config.pricing_context.override_rate_floor,
                ),
                config.pricing_context.override_rate_floor,
            );
            config.pricing_context.override_rate_cap = finite_positive(
                number_value(
                    raw.get("override_rate_cap"),
                    config.pricing_context.override_rate_cap,
                ),
                config.pricing_context.override_rate_cap,
            );
            config.pricing_context.scarcity_multiplier =
                finite_nonnegative(number_value(raw.get("scarcity_multiplier"), 1.0), 1.0);
            config.pricing_context.risk_multiplier =
                finite_nonnegative(number_value(raw.get("risk_multiplier"), 1.0), 1.0);
        }
        config
    }
}

fn parse_pricing_policy(value: Option<&Value>) -> Option<PricingPolicy> {
    value.and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn finite_positive(value: f64, default: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        default
    }
}

fn finite_nonnegative(value: f64, default: f64) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        default
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteRequest {
    pub state: Value,
    #[serde(default)]
    pub candidates: Vec<CandidateAction>,
    #[serde(default)]
    pub host_action: Option<ActionType>,
    #[serde(default)]
    pub config: RouterConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CostVector {
    pub tokens: f64,
    pub latency: f64,
    pub money: f64,
    pub compute: f64,
    pub api_calls: f64,
    pub context_pollution: f64,
    pub memory_bloat: f64,
    pub user_attention: f64,
    pub privacy_exposure: f64,
    pub coordination_overhead: f64,
    pub opportunity_cost: f64,
}

impl Default for CostVector {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            latency: 0.0,
            money: 0.0,
            compute: 0.0,
            api_calls: 0.0,
            context_pollution: 0.0,
            memory_bloat: 0.0,
            user_attention: 0.0,
            privacy_exposure: 0.0,
            coordination_overhead: 0.0,
            opportunity_cost: 0.0,
        }
    }
}

impl CostVector {
    pub const WEIGHTS: [(&'static str, f64); 11] = [
        ("tokens", 0.08),
        ("latency", 0.11),
        ("money", 0.08),
        ("compute", 0.05),
        ("api_calls", 0.07),
        ("context_pollution", 0.12),
        ("memory_bloat", 0.13),
        ("user_attention", 0.18),
        ("privacy_exposure", 0.10),
        ("coordination_overhead", 0.04),
        ("opportunity_cost", 0.04),
    ];

    pub fn merge(self, overrides: &BTreeMap<String, f64>) -> Self {
        let mut merged = self;
        for (key, value) in overrides {
            merged.set(key, *value);
        }
        merged
    }

    pub fn penalty(self) -> f64 {
        let weighted = Self::WEIGHTS
            .iter()
            .map(|(key, weight)| self.get(key) * weight)
            .sum::<f64>();
        crate::utils::round4(weighted * 0.30)
    }

    pub fn set(&mut self, key: &str, value: f64) {
        let value = clamp01(value);
        match key {
            "tokens" => self.tokens = value,
            "latency" => self.latency = value,
            "money" => self.money = value,
            "compute" => self.compute = value,
            "api_calls" => self.api_calls = value,
            "context_pollution" => self.context_pollution = value,
            "memory_bloat" => self.memory_bloat = value,
            "user_attention" => self.user_attention = value,
            "privacy_exposure" => self.privacy_exposure = value,
            "coordination_overhead" => self.coordination_overhead = value,
            "opportunity_cost" => self.opportunity_cost = value,
            _ => {}
        }
    }

    pub fn get(self, key: &str) -> f64 {
        match key {
            "tokens" => self.tokens,
            "latency" => self.latency,
            "money" => self.money,
            "compute" => self.compute,
            "api_calls" => self.api_calls,
            "context_pollution" => self.context_pollution,
            "memory_bloat" => self.memory_bloat,
            "user_attention" => self.user_attention,
            "privacy_exposure" => self.privacy_exposure,
            "coordination_overhead" => self.coordination_overhead,
            "opportunity_cost" => self.opportunity_cost,
            _ => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RiskVector {
    pub privacy_risk: f64,
    pub tool_risk: f64,
    pub external_side_effect_risk: f64,
    pub hallucination_risk: f64,
    pub staleness_risk: f64,
    pub source_quality_risk: f64,
    pub irreversibility: f64,
    pub sensitivity: f64,
    pub compliance_risk: f64,
    pub user_trust_risk: f64,
    pub future_misuse_risk: f64,
}

impl Default for RiskVector {
    fn default() -> Self {
        Self {
            privacy_risk: 0.0,
            tool_risk: 0.0,
            external_side_effect_risk: 0.0,
            hallucination_risk: 0.0,
            staleness_risk: 0.0,
            source_quality_risk: 0.0,
            irreversibility: 0.0,
            sensitivity: 0.0,
            compliance_risk: 0.0,
            user_trust_risk: 0.0,
            future_misuse_risk: 0.0,
        }
    }
}

impl RiskVector {
    pub const WEIGHTS: [(&'static str, f64); 11] = [
        ("privacy_risk", 0.13),
        ("tool_risk", 0.10),
        ("external_side_effect_risk", 0.13),
        ("hallucination_risk", 0.12),
        ("staleness_risk", 0.08),
        ("source_quality_risk", 0.08),
        ("irreversibility", 0.10),
        ("sensitivity", 0.11),
        ("compliance_risk", 0.07),
        ("user_trust_risk", 0.05),
        ("future_misuse_risk", 0.03),
    ];

    pub fn merge(self, overrides: &BTreeMap<String, f64>) -> Self {
        let mut merged = self;
        for (key, value) in overrides {
            merged.set(key, *value);
        }
        merged
    }

    pub fn penalty(self) -> f64 {
        let weighted = Self::WEIGHTS
            .iter()
            .map(|(key, weight)| self.get(key) * weight)
            .sum::<f64>();
        crate::utils::round4(weighted * 0.35)
    }

    pub fn set(&mut self, key: &str, value: f64) {
        let value = clamp01(value);
        match key {
            "privacy_risk" => self.privacy_risk = value,
            "tool_risk" => self.tool_risk = value,
            "external_side_effect_risk" => self.external_side_effect_risk = value,
            "hallucination_risk" => self.hallucination_risk = value,
            "staleness_risk" => self.staleness_risk = value,
            "source_quality_risk" => self.source_quality_risk = value,
            "irreversibility" => self.irreversibility = value,
            "sensitivity" => self.sensitivity = value,
            "compliance_risk" => self.compliance_risk = value,
            "user_trust_risk" => self.user_trust_risk = value,
            "future_misuse_risk" => self.future_misuse_risk = value,
            _ => {}
        }
    }

    pub fn get(self, key: &str) -> f64 {
        match key {
            "privacy_risk" => self.privacy_risk,
            "tool_risk" => self.tool_risk,
            "external_side_effect_risk" => self.external_side_effect_risk,
            "hallucination_risk" => self.hallucination_risk,
            "staleness_risk" => self.staleness_risk,
            "source_quality_risk" => self.source_quality_risk,
            "irreversibility" => self.irreversibility,
            "sensitivity" => self.sensitivity,
            "compliance_risk" => self.compliance_risk,
            "user_trust_risk" => self.user_trust_risk,
            "future_misuse_risk" => self.future_misuse_risk,
            _ => 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionScore {
    pub action_type: ActionType,
    pub expected_upside: f64,
    pub surprisal: f64,
    pub confidence: f64,
    pub cost: CostVector,
    pub risk: RiskVector,
    pub cost_penalty: f64,
    pub risk_penalty: f64,
    pub clearance_score: f64,
    pub pricing_breakdown: PricingBreakdown,
    pub scorer_version: String,
}

impl AdmissionScore {
    pub fn clears_rope(&self) -> bool {
        self.pricing_breakdown.clears_rope
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetTrace {
    #[serde(default)]
    pub certificate_hash: Option<String>,
    #[serde(default)]
    pub certificate_kind: Option<BudgetCertificateKind>,
    #[serde(default)]
    pub claim_mode: Option<String>,
    #[serde(default)]
    pub pre_ledger_hash: Option<String>,
    #[serde(default)]
    pub ledger_sequence: Option<u64>,
    #[serde(default)]
    pub scope: Option<BudgetScope>,
    #[serde(default)]
    pub projected_spend_usd: Option<f64>,
    #[serde(default)]
    pub projected_spend_microusd: Option<u64>,
    #[serde(default)]
    pub high_probability_bound_usd: Option<f64>,
    #[serde(default)]
    pub high_probability_bound_microusd: Option<u64>,
    #[serde(default)]
    pub delta_total: Option<f64>,
    #[serde(default)]
    pub cost_model_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<BudgetOutcome>,
    #[serde(default)]
    pub certifying: bool,
    #[serde(default)]
    pub downgrade_reason: Option<String>,
    #[serde(default)]
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CandidateDecision {
    pub action_type: ActionType,
    pub decision: DecisionType,
    pub reason: String,
    pub final_candidate: CandidateAction,
    pub policy_trace: Vec<PolicyTraceEntry>,
    #[serde(default)]
    pub mutation_ledger: Vec<ActionMutation>,
    #[serde(default)]
    pub short_circuit: Option<String>,
    #[serde(default)]
    pub budget_trace: Option<BudgetTrace>,
    #[serde(default)]
    pub admission_trace: Option<crate::AdmissionTrace>,
    #[serde(default)]
    pub admission_trace_hash: Option<String>,
    #[serde(default)]
    pub effect_vector: Option<crate::EffectVector>,
    pub admission_score: Option<AdmissionScore>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutingDecision {
    pub action_type: Option<ActionType>,
    pub decision: DecisionType,
    pub reason: String,
    pub host_action: Option<ActionType>,
    pub candidate_decisions: Vec<CandidateDecision>,
    pub thread_id: Option<String>,
    pub seal_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryObject {
    pub content: String,
    pub memory_type: String,
    pub context: Value,
    pub confidence: f64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryDecision {
    pub store: bool,
    pub decision: DecisionType,
    pub reason: String,
    pub memory_score: f64,
    pub sensitivity: f64,
    pub memory_object: Option<MemoryObject>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ActionDefinition {
    pub action_type: ActionType,
    pub description: String,
    pub permissions: Vec<String>,
    pub side_effect_level: SideEffectLevel,
    pub reversibility: String,
    pub default_cost_class: String,
    pub default_risk_class: String,
    pub requires_user_approval: bool,
    pub action_family: String,
    pub availability_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionPlan {
    pub action_type: ActionType,
    pub provider: String,
    #[serde(default)]
    pub parameters: JsonObject,
    pub thread_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionResult {
    pub action_type: ActionType,
    pub status: ExecutionStatus,
    pub provider: String,
    pub summary: String,
    #[serde(default)]
    pub output: Value,
    #[serde(default)]
    pub cost: JsonObject,
    #[serde(default)]
    pub metadata: JsonObject,
    #[serde(default)]
    pub sandbox_provenance: Option<crate::SandboxProvenance>,
    #[serde(default)]
    pub sandbox_violations: Vec<crate::SandboxViolation>,
    #[serde(default)]
    pub normalized_output_hash: Option<String>,
    #[serde(default)]
    pub output_transforms: Vec<crate::OutputTransform>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationContext {
    #[serde(default)]
    pub condition_id: Option<String>,
    #[serde(default)]
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    #[serde(default)]
    pub benchmark_suite: Option<String>,
    #[serde(default)]
    pub arm_id: Option<String>,
    #[serde(default)]
    pub expected_action: Option<ActionType>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationOutcome {
    pub action_type: ActionType,
    #[serde(default)]
    pub completed: Option<bool>,
    #[serde(default)]
    pub realized_reward: Option<f64>,
    #[serde(default)]
    pub expected_reward: Option<f64>,
    #[serde(default)]
    pub realized_cost: Option<f64>,
    #[serde(default)]
    pub expected_cost: Option<f64>,
    #[serde(default)]
    pub information_gain: Option<f64>,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub memory_unique: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderCost {
    pub provider: String,
    pub reported_cost: f64,
    pub billed_cost: f64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub fixture_id: Option<String>,
}

fn default_currency() -> String {
    "USD".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayIdentity {
    pub seal_id: String,
    pub seal_seed: u64,
    pub seal_mode: String,
}

pub fn sensitivity_from_state(state: &Value, action: &CandidateAction) -> f64 {
    number_value(
        state
            .get("sensitivity")
            .or_else(|| action.metadata.get("sensitivity")),
        0.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_certificate(
        cap_provenance: CapProvenance,
        concurrency_model: ConcurrencyModel,
        outcome: BudgetOutcome,
    ) -> DeterministicBudgetCertificate {
        let hard_cap_microusd = match outcome {
            BudgetOutcome::Admit => 1_000_000,
            BudgetOutcome::Block => 11_000_000,
        };
        let budget_limit_microusd = 10_000_000;
        let observed_spend_microusd = 0;
        let projected_spend_microusd = observed_spend_microusd + hard_cap_microusd;
        let slack_microusd = budget_limit_microusd as i64 - projected_spend_microusd as i64;
        DeterministicBudgetCertificate {
            schema_version: DETERMINISTIC_BUDGET_SCHEMA_VERSION.to_string(),
            certificate_kind: BudgetCertificateKind::DeterministicHardCap,
            scope: BudgetScope::Task,
            budget_limit_usd: microusd_to_usd_display(budget_limit_microusd),
            observed_spend_usd: microusd_to_usd_display(observed_spend_microusd),
            hard_cap_usd: microusd_to_usd_display(hard_cap_microusd),
            cap_provenance,
            concurrency_model,
            action_hash: "action".to_string(),
            filtration_hash: "filtration".to_string(),
            ledger_sequence_before: 0,
            projected_spend_usd: microusd_to_usd_display(projected_spend_microusd),
            slack_usd: slack_microusd_to_usd_display(slack_microusd),
            outcome,
            obligations: MANDATORY_DETERMINISTIC_BUDGET_OBLIGATIONS
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            theorem_refs: vec!["docs/math/budget_safety_deterministic_theorem.txt".to_string()],
            budget_limit_microusd: Some(budget_limit_microusd),
            observed_spend_microusd: Some(observed_spend_microusd),
            hard_cap_microusd: Some(hard_cap_microusd),
            projected_spend_microusd: Some(projected_spend_microusd),
            slack_microusd: Some(slack_microusd),
        }
    }

    fn certifying_certificate() -> DeterministicBudgetCertificate {
        budget_certificate(
            CapProvenance::ProviderEnforced,
            ConcurrencyModel::SingleWriterAtomic,
            BudgetOutcome::Admit,
        )
    }

    fn budget_ledger(
        budget_limit_microusd: u64,
        observed_spend_microusd: u64,
    ) -> BudgetSafetyLedger {
        BudgetSafetyLedger {
            scope: BudgetScope::Task,
            budget_limit_usd: microusd_to_usd_display(budget_limit_microusd),
            budget_limit_microusd,
            observed_spend_usd: microusd_to_usd_display(observed_spend_microusd),
            observed_spend_microusd,
            ledger_hash: String::new(),
            ledger_sequence: 0,
        }
        .with_recomputed_hash()
    }

    fn assert_commit_rejects_unchanged(
        ledger: &mut BudgetSafetyLedger,
        certificate: &DeterministicBudgetCertificate,
        realized_microusd: u64,
    ) {
        let before = ledger.clone();
        assert!(
            ledger
                .commit_authorized_realized_cost(certificate, realized_microusd)
                .is_err()
        );
        assert_eq!(*ledger, before);
    }

    fn set_projected_authority(certificate: &mut DeterministicBudgetCertificate, value: u64) {
        certificate.projected_spend_microusd = Some(value);
        certificate.projected_spend_usd = microusd_to_usd_display(value);
    }

    fn set_slack_authority(certificate: &mut DeterministicBudgetCertificate, value: i64) {
        certificate.slack_microusd = Some(value);
        certificate.slack_usd = slack_microusd_to_usd_display(value);
    }

    #[test]
    fn deterministic_budget_is_certifying_full_matrix() {
        for provenance in [
            CapProvenance::ProviderEnforced,
            CapProvenance::EstimateNotACap,
        ] {
            for concurrency in [
                ConcurrencyModel::SingleWriterAtomic,
                ConcurrencyModel::Unserialized,
            ] {
                for outcome in [BudgetOutcome::Admit, BudgetOutcome::Block] {
                    let certificate = budget_certificate(provenance, concurrency, outcome);

                    assert_eq!(
                        certificate.is_certifying(),
                        provenance == CapProvenance::ProviderEnforced
                            && concurrency == ConcurrencyModel::SingleWriterAtomic
                            && outcome == BudgetOutcome::Admit
                    );
                }
            }
        }

        let mut missing_obligations = budget_certificate(
            CapProvenance::ProviderEnforced,
            ConcurrencyModel::SingleWriterAtomic,
            BudgetOutcome::Admit,
        );
        missing_obligations.obligations = vec!["record_realized_cost_after_execution".to_string()];
        assert!(!missing_obligations.is_certifying());

        let mut stale_projected = budget_certificate(
            CapProvenance::ProviderEnforced,
            ConcurrencyModel::SingleWriterAtomic,
            BudgetOutcome::Admit,
        );
        stale_projected.projected_spend_usd += 1.0;
        stale_projected.projected_spend_microusd = stale_projected
            .projected_spend_microusd
            .map(|value| value + 1);
        assert!(!stale_projected.is_certifying());
    }

    #[test]
    fn deterministic_budget_authority_commit_requires_full_certifying_predicate() {
        let cases = [
            {
                let mut certificate = certifying_certificate();
                certificate.obligations = vec!["record_realized_cost_after_execution".to_string()];
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                set_projected_authority(&mut certificate, 2_000_000);
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                set_slack_authority(&mut certificate, 9_000_001);
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                certificate.hard_cap_microusd = Some(11_000_000);
                certificate.hard_cap_usd = microusd_to_usd_display(11_000_000);
                set_projected_authority(&mut certificate, 11_000_000);
                set_slack_authority(&mut certificate, -1_000_000);
                certificate.outcome = BudgetOutcome::Admit;
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                certificate.cap_provenance = CapProvenance::EstimateNotACap;
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                certificate.concurrency_model = ConcurrencyModel::Unserialized;
                certificate
            },
            {
                let mut certificate = certifying_certificate();
                certificate.schema_version = "unsupported".to_string();
                certificate
            },
        ];

        for certificate in cases {
            assert!(!certificate.is_certifying());
            let mut ledger = budget_ledger(10_000_000, 0);
            assert_commit_rejects_unchanged(&mut ledger, &certificate, 500_000);
        }
    }

    #[test]
    fn deterministic_budget_authority_commit_succeeds_exactly_once() {
        let certificate = certifying_certificate();
        assert!(certificate.is_certifying());
        let mut ledger = budget_ledger(10_000_000, 0);

        assert!(
            ledger
                .commit_authorized_realized_cost(&certificate, 500_000)
                .is_ok()
        );
        assert_eq!(ledger.observed_spend_microusd, 500_000);
        assert_eq!(ledger.observed_spend_usd, 0.5);
        assert_eq!(ledger.ledger_sequence, 1);

        assert_commit_rejects_unchanged(&mut ledger, &certificate, 500_000);
    }

    #[test]
    fn deterministic_budget_integer_authority_boundaries_are_exact() {
        let projected_at_limit = {
            let mut certificate = certifying_certificate();
            certificate.hard_cap_microusd = Some(10_000_000);
            certificate.hard_cap_usd = microusd_to_usd_display(10_000_000);
            set_projected_authority(&mut certificate, 10_000_000);
            set_slack_authority(&mut certificate, 0);
            certificate
        };
        assert!(projected_at_limit.is_certifying());

        let projected_over_limit = {
            let mut certificate = projected_at_limit.clone();
            certificate.hard_cap_microusd = Some(10_000_001);
            certificate.hard_cap_usd = microusd_to_usd_display(10_000_001);
            set_projected_authority(&mut certificate, 10_000_001);
            set_slack_authority(&mut certificate, -1);
            certificate.outcome = BudgetOutcome::Admit;
            certificate
        };
        assert!(!projected_over_limit.is_certifying());

        let realized_at_hard_cap = certifying_certificate();
        let mut ledger = budget_ledger(10_000_000, 0);
        assert!(
            ledger
                .commit_authorized_realized_cost(&realized_at_hard_cap, 1_000_000)
                .is_ok()
        );

        let realized_over_hard_cap = certifying_certificate();
        let mut ledger = budget_ledger(10_000_000, 0);
        assert_commit_rejects_unchanged(&mut ledger, &realized_over_hard_cap, 1_000_001);

        let mut ledger = budget_ledger(10_000_000, 9_000_000);
        let mut next_at_limit = certifying_certificate();
        next_at_limit.observed_spend_microusd = Some(9_000_000);
        next_at_limit.observed_spend_usd = microusd_to_usd_display(9_000_000);
        next_at_limit.hard_cap_microusd = Some(1_000_000);
        next_at_limit.hard_cap_usd = microusd_to_usd_display(1_000_000);
        set_projected_authority(&mut next_at_limit, 10_000_000);
        set_slack_authority(&mut next_at_limit, 0);
        assert!(next_at_limit.is_certifying());
        assert!(
            ledger
                .commit_authorized_realized_cost(&next_at_limit, 1_000_000)
                .is_ok()
        );
        assert_eq!(ledger.observed_spend_microusd, 10_000_000);

        let mut next_over_limit = next_at_limit.clone();
        next_over_limit.hard_cap_microusd = Some(1_000_001);
        next_over_limit.hard_cap_usd = microusd_to_usd_display(1_000_001);
        set_projected_authority(&mut next_over_limit, 10_000_001);
        set_slack_authority(&mut next_over_limit, -1);
        next_over_limit.outcome = BudgetOutcome::Admit;
        let mut ledger = budget_ledger(10_000_000, 9_000_000);
        assert_commit_rejects_unchanged(&mut ledger, &next_over_limit, 1_000_001);
    }
}
