//! Subgoal closure lifecycle control for Velvet Execution Permits.
//!
//! `velvet-closure` does not mint a parallel authority token. A grant is a
//! Velvet Execution Permit with a signed subgoal hash and logical-step validity.
//! Closure advances the trusted subgoal epoch, so outstanding permits for that
//! subgoal fail before dispatch while wall-clock validity remains enforced.

pub mod contract;
pub mod epoch;
pub mod monitor;
pub mod risk;

pub use contract::{
    Capability, ClosureKind, ClosurePredicate, DenyRule, GrantRule, TaskContract,
    contract_schema_json, load_contract, load_contract_path, load_contract_yaml, validate_contract,
};
pub use epoch::{EpochTable, SynchronizedEpochTable};
pub use monitor::{ClosureMonitor, Decision, VisibleCapability, VisibleTools};
pub use risk::{AllowRiskGate, MaxDeRiskGate, RiskDecision, RiskGate, VerdictRiskGate};
