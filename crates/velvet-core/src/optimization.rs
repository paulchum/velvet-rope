use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{CapabilityClass, EffectVector, SideEffectClass};

pub const OPTIMIZER_MODEL_VERSION: &str = "velvet.admission_optimizer.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectiveWeights {
    pub cost_lambda_bps_per_usd: i64,
    pub privacy_rho_bps: i64,
    pub integrity_rho_bps: i64,
    pub availability_rho_bps: i64,
    pub financial_rho_bps: i64,
    pub compliance_rho_bps: i64,
    pub irreversible_penalty_bps: i64,
    pub unknown_penalty_bps: i64,
}

impl Default for ObjectiveWeights {
    fn default() -> Self {
        Self {
            cost_lambda_bps_per_usd: 2_500,
            privacy_rho_bps: 8_000,
            integrity_rho_bps: 8_000,
            availability_rho_bps: 5_000,
            financial_rho_bps: 10_000,
            compliance_rho_bps: 10_000,
            irreversible_penalty_bps: 6_000,
            unknown_penalty_bps: 12_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectiveComponents {
    pub schema_version: String,
    pub utility_lcb_bps: i32,
    pub cost_ucb_microusd: u64,
    pub risk_ucb_bps: u32,
    pub cost_penalty_bps: i64,
    pub risk_penalty_bps: i64,
    pub structural_penalty_bps: i64,
    pub objective_bps: i64,
    pub optimizer_model_version: String,
}

pub fn objective_components(
    effect: &EffectVector,
    weights: ObjectiveWeights,
) -> ObjectiveComponents {
    let utility_lcb_bps = effect.utility_bound.lower_bps;
    let cost_ucb_microusd = effect.cost_bound.upper_microusd;
    let cost_penalty_bps = ((cost_ucb_microusd as i128 * weights.cost_lambda_bps_per_usd as i128)
        / 1_000_000_i128)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    let risk_ucb_bps = u32::from(effect.risk_bound.privacy_risk_bps)
        + u32::from(effect.risk_bound.integrity_risk_bps)
        + u32::from(effect.risk_bound.availability_risk_bps)
        + u32::from(effect.risk_bound.financial_risk_bps)
        + u32::from(effect.risk_bound.compliance_risk_bps);
    let risk_penalty_bps = weighted_risk_penalty(effect, weights);
    let structural_penalty_bps = structural_penalty(effect, weights);
    let objective_bps =
        i64::from(utility_lcb_bps) - cost_penalty_bps - risk_penalty_bps - structural_penalty_bps;
    ObjectiveComponents {
        schema_version: "velvet.objective_components.v1".to_string(),
        utility_lcb_bps,
        cost_ucb_microusd,
        risk_ucb_bps,
        cost_penalty_bps,
        risk_penalty_bps,
        structural_penalty_bps,
        objective_bps,
        optimizer_model_version: OPTIMIZER_MODEL_VERSION.to_string(),
    }
}

fn weighted_risk_penalty(effect: &EffectVector, weights: ObjectiveWeights) -> i64 {
    let risk = effect.risk_bound;
    ((i64::from(risk.privacy_risk_bps) * weights.privacy_rho_bps
        + i64::from(risk.integrity_risk_bps) * weights.integrity_rho_bps
        + i64::from(risk.availability_risk_bps) * weights.availability_rho_bps
        + i64::from(risk.financial_risk_bps) * weights.financial_rho_bps
        + i64::from(risk.compliance_risk_bps) * weights.compliance_rho_bps)
        / 10_000)
        .max(0)
}

fn structural_penalty(effect: &EffectVector, weights: ObjectiveWeights) -> i64 {
    let mut penalty = 0;
    if effect.capability_class == CapabilityClass::Unknown {
        penalty += weights.unknown_penalty_bps;
    }
    if matches!(
        effect.side_effect_class,
        SideEffectClass::Irreversible | SideEffectClass::Regulated
    ) {
        penalty += weights.irreversible_penalty_bps;
    }
    if matches!(
        effect.capability_class,
        CapabilityClass::FinancialTransaction
            | CapabilityClass::CredentialAccess
            | CapabilityClass::CodeExecution
            | CapabilityClass::ExternalWrite
            | CapabilityClass::InfrastructureMutation
    ) {
        penalty += weights.unknown_penalty_bps / 2;
    }
    penalty
}
