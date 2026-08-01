"""Python-facing typed models for the Rust Velvet v1 kernel."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from enum import StrEnum
from math import isfinite, log, sqrt
from typing import Any, cast

from velvet.serialization import canonical_hash_sha256

JsonObject = dict[str, Any]


class ActionType(StrEnum):
    ANSWER_DIRECTLY = "ANSWER_DIRECTLY"
    SEARCH_WEB = "SEARCH_WEB"
    RETRIEVE_CONTEXT = "RETRIEVE_CONTEXT"
    READ_FILE = "READ_FILE"
    INSPECT_CODE = "INSPECT_CODE"
    EXECUTE_CODE = "EXECUTE_CODE"
    CALL_TOOL = "CALL_TOOL"
    ASK_USER = "ASK_USER"
    STORE_MEMORY = "STORE_MEMORY"
    ESCALATE_MODEL = "ESCALATE_MODEL"
    CONCIERGE_REVIEW = "CONCIERGE_REVIEW"


class CandidateSource(StrEnum):
    HOST = "host"
    SCENARIO = "scenario"
    REGISTRY = "registry"
    WORKFLOW = "workflow"
    POLICY_FALLBACK = "policy_fallback"


class DecisionType(StrEnum):
    EXECUTE = "execute"
    SKIP = "skip"
    BLOCK = "block"
    DELAY = "delay"
    ASK_APPROVAL = "ask_approval"
    ESCALATE = "escalate"


class PolicyStatus(StrEnum):
    ALLOWED = "allowed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    REQUIRES_APPROVAL = "requires_approval"


class PricingPolicy(StrEnum):
    FIXED_PRICE_BASELINE = "fixed_price_baseline"
    LINEAR_EXHAUSTION = "linear_exhaustion"
    INVERSE_HORIZON = "inverse_horizon"
    OVERRIDE_RATE_AWARE = "override_rate_aware"
    RISK_WEIGHTED = "risk_weighted"
    UNCERTAINTY_COMPENSATED = "uncertainty_compensated"
    HYBRID_PRODUCTION = "hybrid_production"


class SideEffectLevel(StrEnum):
    NONE = "none"
    LOCAL_REVERSIBLE = "local_reversible"
    LOCAL_PERSISTENT = "local_persistent"
    EXTERNAL_REVERSIBLE = "external_reversible"
    EXTERNAL_IRREVERSIBLE = "external_irreversible"


class CapabilityClass(StrEnum):
    READ_ONLY = "read_only"
    EXTERNAL_READ = "external_read"
    INTERNAL_WRITE = "internal_write"
    EXTERNAL_WRITE = "external_write"
    FINANCIAL_TRANSACTION = "financial_transaction"
    CREDENTIAL_ACCESS = "credential_access"
    CODE_EXECUTION = "code_execution"
    NETWORK_EGRESS = "network_egress"
    HUMAN_COMMUNICATION = "human_communication"
    DATA_EXPORT = "data_export"
    INFRASTRUCTURE_MUTATION = "infrastructure_mutation"
    UNKNOWN = "unknown"


class TypedSideEffectClass(StrEnum):
    NONE = "none"
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"
    EXTERNALLY_VISIBLE = "externally_visible"
    REGULATED = "regulated"


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PERSONAL_DATA = "personal_data"
    SECRET = "secret"  # noqa: S105  # nosec B105
    REGULATED = "regulated"
    UNKNOWN = "unknown"


class TypedReversibility(StrEnum):
    NONE = "none"
    REVERSIBLE = "reversible"
    PARTIAL = "partial"
    IRREVERSIBLE = "irreversible"


class ConstraintSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    DEFER = "defer"
    BLOCK = "block"


class AdmissionDecision(StrEnum):
    EXECUTE = "execute"
    BLOCK = "block"
    DEFER = "defer"
    ASK_APPROVAL = "ask_approval"
    ESCALATE = "escalate"
    ANSWER_DIRECTLY = "answer_directly"
    REQUIRE_WARRANT = "require_warrant"


class ExecutionStatus(StrEnum):
    NOT_RUN = "not_run"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    PENDING_CONCIERGE = "pending_concierge"


class CertificateOutcome(StrEnum):
    INSPECT = "inspect"
    LOCKOUT = "lockout"
    REFINEMENT = "refinement"


class BudgetScope(StrEnum):
    TASK = "task"
    USER_DAILY = "user_daily"
    ORG_MONTHLY = "org_monthly"


class ConcurrencyModel(StrEnum):
    SINGLE_WRITER_ATOMIC = "single_writer_atomic"
    UNSERIALIZED = "unserialized"


class CapProvenance(StrEnum):
    PROVIDER_ENFORCED = "provider_enforced"
    PREPAID_RESERVATION = "prepaid_reservation"
    ENFORCED_TOKEN_CAP = "enforced_token_cap"  # noqa: S105  # nosec B105
    ESTIMATE_NOT_A_CAP = "estimate_not_a_cap"


class BudgetOutcome(StrEnum):
    ADMIT = "admit"
    BLOCK = "block"


class BudgetCertificateKind(StrEnum):
    DETERMINISTIC_HARD_CAP = "deterministic_hard_cap"
    CGF_VILLE = "cgf_ville"
    MOMENT_CANTELLI = "moment_cantelli"


class RuntimeMode(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class SandboxBackendKind(StrEnum):
    NONE = "none"
    LIGHTWEIGHT = "lightweight"
    CONTAINER = "container"


class ContainerRuntime(StrEnum):
    PODMAN = "podman"
    DOCKER = "docker"


class MountMode(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


def parse_action_type(value: ActionType | str) -> ActionType:
    return value if isinstance(value, ActionType) else ActionType(str(value))


def parse_candidate_source(value: CandidateSource | str | None) -> CandidateSource:
    if value is None:
        return CandidateSource.HOST
    return value if isinstance(value, CandidateSource) else CandidateSource(str(value))


def parse_decision_type(value: DecisionType | str) -> DecisionType:
    return value if isinstance(value, DecisionType) else DecisionType(str(value))


def parse_policy_status(value: PolicyStatus | str) -> PolicyStatus:
    return value if isinstance(value, PolicyStatus) else PolicyStatus(str(value))


def parse_pricing_policy(value: PricingPolicy | str) -> PricingPolicy:
    return value if isinstance(value, PricingPolicy) else PricingPolicy(str(value))


def parse_execution_status(value: ExecutionStatus | str) -> ExecutionStatus:
    return value if isinstance(value, ExecutionStatus) else ExecutionStatus(str(value))


def parse_certificate_outcome(value: CertificateOutcome | str) -> CertificateOutcome:
    return value if isinstance(value, CertificateOutcome) else CertificateOutcome(str(value))


def parse_budget_scope(value: BudgetScope | str) -> BudgetScope:
    return value if isinstance(value, BudgetScope) else BudgetScope(str(value))


def parse_concurrency_model(value: ConcurrencyModel | str) -> ConcurrencyModel:
    return value if isinstance(value, ConcurrencyModel) else ConcurrencyModel(str(value))


def parse_cap_provenance(value: CapProvenance | str) -> CapProvenance:
    return value if isinstance(value, CapProvenance) else CapProvenance(str(value))


def parse_budget_outcome(value: BudgetOutcome | str) -> BudgetOutcome:
    return value if isinstance(value, BudgetOutcome) else BudgetOutcome(str(value))


def parse_budget_certificate_kind(
    value: BudgetCertificateKind | str,
) -> BudgetCertificateKind:
    return (
        value
        if isinstance(value, BudgetCertificateKind)
        else BudgetCertificateKind(str(value))
    )


def parse_runtime_mode(value: RuntimeMode | str) -> RuntimeMode:
    return value if isinstance(value, RuntimeMode) else RuntimeMode(str(value))


def parse_sandbox_backend(value: SandboxBackendKind | str) -> SandboxBackendKind:
    return value if isinstance(value, SandboxBackendKind) else SandboxBackendKind(str(value))


def parse_container_runtime(value: ContainerRuntime | str) -> ContainerRuntime:
    return value if isinstance(value, ContainerRuntime) else ContainerRuntime(str(value))


def parse_mount_mode(value: MountMode | str) -> MountMode:
    return value if isinstance(value, MountMode) else MountMode(str(value))


def parse_capability_class(value: CapabilityClass | str) -> CapabilityClass:
    return value if isinstance(value, CapabilityClass) else CapabilityClass(str(value))


def parse_typed_side_effect_class(
    value: TypedSideEffectClass | str,
) -> TypedSideEffectClass:
    return (
        value
        if isinstance(value, TypedSideEffectClass)
        else TypedSideEffectClass(str(value))
    )


def parse_data_class(value: DataClass | str) -> DataClass:
    return value if isinstance(value, DataClass) else DataClass(str(value))


def parse_typed_reversibility(
    value: TypedReversibility | str,
) -> TypedReversibility:
    return (
        value
        if isinstance(value, TypedReversibility)
        else TypedReversibility(str(value))
    )


def parse_constraint_severity(
    value: ConstraintSeverity | str,
) -> ConstraintSeverity:
    return (
        value
        if isinstance(value, ConstraintSeverity)
        else ConstraintSeverity(str(value))
    )


def parse_admission_decision(
    value: AdmissionDecision | str,
) -> AdmissionDecision:
    return value if isinstance(value, AdmissionDecision) else AdmissionDecision(str(value))


def _enum_safe(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if value.__class__.__name__ == "PolicyDecision":
        return value.to_dict()
    if value.__class__.__name__ == "NetworkPolicy":
        return value.to_dict()
    if value.__class__.__name__ in {
        "CertificateEvidence",
        "CompensatorStep",
        "CompetitorResult",
    }:
        return value.to_dict()
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _enum_safe(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, dict):
        return {str(key): _enum_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_enum_safe(item) for item in value]
    return value


def _as_json_object(value: Any) -> JsonObject:
    return cast(JsonObject, _enum_safe(value))


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


@dataclass(frozen=True)
class StateTransitionCertificate:
    schema_version: str
    pre_state_hash: str
    post_state_hash: str
    canonical_patch_hash: str
    declared_write_set_hash: str
    actual_write_set_hash: str
    policy_predicate_id: str
    policy_predicate_hash: str
    invariant_id: str
    invariant_hash: str
    warrant_hash: str
    transition_proof_hash: str
    transaction_id: str
    cas_sequence: int
    outcome: str
    obligations: tuple[str, ...]
    theorem_refs: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StateTransitionCertificate:
        missing = [field_name for field_name in cls._field_order() if field_name not in data]
        if missing:
            raise ValueError(
                "state transition certificate missing required field(s): "
                + ", ".join(missing)
            )
        return cls(
            schema_version=str(data["schema_version"]),
            pre_state_hash=str(data["pre_state_hash"]),
            post_state_hash=str(data["post_state_hash"]),
            canonical_patch_hash=str(data["canonical_patch_hash"]),
            declared_write_set_hash=str(data["declared_write_set_hash"]),
            actual_write_set_hash=str(data["actual_write_set_hash"]),
            policy_predicate_id=str(data["policy_predicate_id"]),
            policy_predicate_hash=str(data["policy_predicate_hash"]),
            invariant_id=str(data["invariant_id"]),
            invariant_hash=str(data["invariant_hash"]),
            warrant_hash=str(data["warrant_hash"]),
            transition_proof_hash=str(data["transition_proof_hash"]),
            transaction_id=str(data["transaction_id"]),
            cas_sequence=int(data["cas_sequence"]),
            outcome=str(data["outcome"]),
            obligations=_string_tuple(data["obligations"], "obligations"),
            theorem_refs=_string_tuple(data["theorem_refs"], "theorem_refs"),
        )

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "pre_state_hash": self.pre_state_hash,
            "post_state_hash": self.post_state_hash,
            "canonical_patch_hash": self.canonical_patch_hash,
            "declared_write_set_hash": self.declared_write_set_hash,
            "actual_write_set_hash": self.actual_write_set_hash,
            "policy_predicate_id": self.policy_predicate_id,
            "policy_predicate_hash": self.policy_predicate_hash,
            "invariant_id": self.invariant_id,
            "invariant_hash": self.invariant_hash,
            "warrant_hash": self.warrant_hash,
            "transition_proof_hash": self.transition_proof_hash,
            "transaction_id": self.transaction_id,
            "cas_sequence": self.cas_sequence,
            "outcome": self.outcome,
            "obligations": list(self.obligations),
            "theorem_refs": list(self.theorem_refs),
        }

    def unsigned_payload(self) -> JsonObject:
        payload = self.to_dict()
        payload.pop("transition_proof_hash", None)
        return payload

    def expected_transition_proof_hash(self) -> str:
        return self.build_transition_proof_hash(self.to_dict())

    @classmethod
    def build_transition_proof_hash(cls, payload: Mapping[str, Any]) -> str:
        unsigned = {str(key): value for key, value in payload.items()}
        unsigned.pop("transition_proof_hash", None)
        return canonical_hash_sha256(unsigned)

    @staticmethod
    def _field_order() -> tuple[str, ...]:
        return (
            "schema_version",
            "pre_state_hash",
            "post_state_hash",
            "canonical_patch_hash",
            "declared_write_set_hash",
            "actual_write_set_hash",
            "policy_predicate_id",
            "policy_predicate_hash",
            "invariant_id",
            "invariant_hash",
            "warrant_hash",
            "transition_proof_hash",
            "transaction_id",
            "cas_sequence",
            "outcome",
            "obligations",
            "theorem_refs",
        )


def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ValueError(f"{field_name} must be an array of strings")
    return tuple(str(item) for item in value)


@dataclass(frozen=True)
class CompensatorStep:
    arm: int
    baseline: float
    horizon: int
    z_current: float
    expected_z_next: float
    increment: float
    initial_optionality: float
    cumulative_increment: float

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CompensatorStep:
        return cls(
            arm=int(data["arm"]),
            baseline=float(data["baseline"]),
            horizon=int(data["horizon"]),
            z_current=float(data["z_current"]),
            expected_z_next=float(data["expected_z_next"]),
            increment=float(data["increment"]),
            initial_optionality=float(data["initial_optionality"]),
            cumulative_increment=float(data["cumulative_increment"]),
        )

    def to_dict(self) -> JsonObject:
        return {
            "arm": self.arm,
            "baseline": self.baseline,
            "horizon": self.horizon,
            "z_current": self.z_current,
            "expected_z_next": self.expected_z_next,
            "increment": self.increment,
            "initial_optionality": self.initial_optionality,
            "cumulative_increment": self.cumulative_increment,
        }


@dataclass(frozen=True)
class CertificateEffect:
    max_payoff: float
    mean_bound: float
    resource_scope: str
    write_footprint: tuple[str, ...]
    filtration_hash: str
    filtration_index: int
    adapted: bool
    variance_bound: float | None = None
    second_moment_bound: float | None = None
    declared_write_set_hash: str | None = None
    dependence_group: str | None = None
    correlation_bound: float | None = None
    covariance_reserve_gamma: float | None = None
    dependence_kind: str = "unspecified"
    adaptation_marker: str | None = None
    write_conflict_policy: str = "exclusive"
    commutativity_certificate_hash: str | None = None
    continuation_condition_hash: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CertificateEffect:
        missing = [
            field_name
            for field_name in (
                "max_payoff",
                "mean_bound",
                "resource_scope",
                "write_footprint",
                "filtration_hash",
                "filtration_index",
                "adapted",
            )
            if field_name not in data
        ]
        if missing:
            raise ValueError(
                "certificate typed effect missing required field(s): "
                + ", ".join(missing)
            )
        return cls(
            max_payoff=float(data["max_payoff"]),
            mean_bound=float(data["mean_bound"]),
            variance_bound=_optional_float(data.get("variance_bound")),
            second_moment_bound=_optional_float(data.get("second_moment_bound")),
            resource_scope=str(data["resource_scope"]),
            write_footprint=_string_tuple(data["write_footprint"], "write_footprint"),
            declared_write_set_hash=cast(str | None, data.get("declared_write_set_hash")),
            dependence_group=cast(str | None, data.get("dependence_group")),
            correlation_bound=_optional_float(data.get("correlation_bound")),
            covariance_reserve_gamma=_optional_float(data.get("covariance_reserve_gamma")),
            dependence_kind=str(data.get("dependence_kind", "unspecified")),
            filtration_hash=str(data["filtration_hash"]),
            filtration_index=int(data["filtration_index"]),
            adapted=bool(data["adapted"]),
            adaptation_marker=cast(str | None, data.get("adaptation_marker")),
            write_conflict_policy=str(data.get("write_conflict_policy", "exclusive")),
            commutativity_certificate_hash=cast(
                str | None,
                data.get("commutativity_certificate_hash"),
            ),
            continuation_condition_hash=cast(
                str | None,
                data.get("continuation_condition_hash"),
            ),
        )

    def variance(self) -> float | None:
        if self.variance_bound is not None:
            return self.variance_bound
        if self.second_moment_bound is None:
            return None
        return max(self.second_moment_bound - self.mean_bound**2, 0.0)

    def safe_upper_bound(self) -> float | None:
        variance = self.variance()
        if variance is None:
            return None
        return certificate_effect_safe_upper_bound(
            mean_bound=self.mean_bound,
            max_payoff=self.max_payoff,
            variance_bound=variance,
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "max_payoff": self.max_payoff,
            "mean_bound": self.mean_bound,
            "resource_scope": self.resource_scope,
            "write_footprint": list(self.write_footprint),
            "filtration_hash": self.filtration_hash,
            "filtration_index": self.filtration_index,
            "adapted": self.adapted,
            "dependence_kind": self.dependence_kind,
            "write_conflict_policy": self.write_conflict_policy,
        }
        for key, value in (
            ("variance_bound", self.variance_bound),
            ("second_moment_bound", self.second_moment_bound),
            ("declared_write_set_hash", self.declared_write_set_hash),
            ("dependence_group", self.dependence_group),
            ("correlation_bound", self.correlation_bound),
            ("covariance_reserve_gamma", self.covariance_reserve_gamma),
            ("adaptation_marker", self.adaptation_marker),
            ("commutativity_certificate_hash", self.commutativity_certificate_hash),
            ("continuation_condition_hash", self.continuation_condition_hash),
        ):
            if value is not None:
                payload[key] = value
        return payload


def certificate_effect_safe_upper_bound(
    *,
    mean_bound: float,
    max_payoff: float,
    variance_bound: float,
) -> float:
    if not all(isfinite(value) for value in (mean_bound, max_payoff, variance_bound)):
        raise ValueError("certificate effect bounds must be finite")
    if mean_bound < 0.0 or max_payoff < 0.0 or variance_bound < 0.0:
        raise ValueError("certificate effect bounds must be non-negative")
    if mean_bound == 0.0:
        return 0.0
    if max_payoff <= 0.0:
        raise ValueError("positive certificate mean requires a positive max payoff")
    if mean_bound > max_payoff:
        raise ValueError("certificate mean bound cannot exceed max payoff")
    log_envelope = mean_bound * (1.0 + log(max_payoff / mean_bound))
    l2_envelope = mean_bound + 2.0 * sqrt(variance_bound)
    return max(min(max_payoff, log_envelope, l2_envelope), 0.0)


@dataclass(frozen=True)
class CertificateEvidence:
    schema_version: str
    family: str
    arm_id: str
    baseline: float
    lookback_horizon: int
    delight_scale: float
    liability_price: float
    threshold: float
    inspection_lower_bound: float
    safe_upper_bound: float
    outcome: CertificateOutcome
    liability_mode: str
    typed_effect: CertificateEffect
    compensator_step: CompensatorStep | None = None
    theorem_refs: tuple[str, ...] = ()
    reserve_price: float | None = None
    value_numeraire: str | None = None
    upside_value_scale: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CertificateEvidence:
        compensator = data.get("compensator_step")
        upside_value_scale = data.get("upside_value_scale")
        typed_effect = data.get("typed_effect")
        if not isinstance(typed_effect, Mapping):
            raise ValueError("certificate evidence requires typed_effect")
        return cls(
            schema_version=str(data["schema_version"]),
            family=str(data["family"]),
            arm_id=str(data["arm_id"]),
            baseline=float(data["baseline"]),
            lookback_horizon=int(data["lookback_horizon"]),
            delight_scale=float(data["delight_scale"]),
            liability_price=float(data["liability_price"]),
            threshold=float(data["threshold"]),
            inspection_lower_bound=float(data["inspection_lower_bound"]),
            safe_upper_bound=float(data["safe_upper_bound"]),
            outcome=parse_certificate_outcome(str(data["outcome"])),
            liability_mode=str(data["liability_mode"]),
            typed_effect=CertificateEffect.from_dict(cast(Mapping[str, Any], typed_effect)),
            compensator_step=CompensatorStep.from_dict(cast(Mapping[str, Any], compensator))
            if isinstance(compensator, Mapping)
            else None,
            theorem_refs=tuple(str(item) for item in data.get("theorem_refs", ())),
            reserve_price=_optional_float(data.get("reserve_price")),
            value_numeraire=cast(str | None, data.get("value_numeraire")),
            upside_value_scale=int(upside_value_scale)
            if upside_value_scale is not None
            else None,
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "schema_version": self.schema_version,
            "family": self.family,
            "arm_id": self.arm_id,
            "baseline": self.baseline,
            "lookback_horizon": self.lookback_horizon,
            "delight_scale": self.delight_scale,
            "liability_price": self.liability_price,
            "threshold": self.threshold,
            "inspection_lower_bound": self.inspection_lower_bound,
            "safe_upper_bound": self.safe_upper_bound,
            "outcome": self.outcome.value,
            "liability_mode": self.liability_mode,
            "typed_effect": self.typed_effect.to_dict(),
            "compensator_step": self.compensator_step.to_dict()
            if self.compensator_step is not None
            else None,
            "theorem_refs": list(self.theorem_refs),
        }
        if self.reserve_price is not None:
            payload["reserve_price"] = self.reserve_price
        if self.value_numeraire is not None:
            payload["value_numeraire"] = self.value_numeraire
        if self.upside_value_scale is not None:
            payload["upside_value_scale"] = self.upside_value_scale
        return payload


@dataclass(frozen=True)
class BudgetSafetyLedger:
    scope: BudgetScope
    budget_limit_usd: float
    budget_limit_microusd: int
    observed_spend_usd: float
    observed_spend_microusd: int
    ledger_hash: str
    ledger_sequence: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BudgetSafetyLedger:
        return cls(
            scope=parse_budget_scope(str(data["scope"])),
            budget_limit_usd=float(data["budget_limit_usd"]),
            budget_limit_microusd=int(data["budget_limit_microusd"]),
            observed_spend_usd=float(data["observed_spend_usd"]),
            observed_spend_microusd=int(data["observed_spend_microusd"]),
            ledger_hash=str(data["ledger_hash"]),
            ledger_sequence=int(data["ledger_sequence"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class DeterministicBudgetCertificate:
    schema_version: str
    scope: BudgetScope
    budget_limit_usd: float
    observed_spend_usd: float
    hard_cap_usd: float
    cap_provenance: CapProvenance
    concurrency_model: ConcurrencyModel
    action_hash: str
    filtration_hash: str
    ledger_sequence_before: int
    projected_spend_usd: float
    slack_usd: float
    outcome: BudgetOutcome
    certificate_kind: BudgetCertificateKind = BudgetCertificateKind.DETERMINISTIC_HARD_CAP
    obligations: tuple[str, ...] = ()
    theorem_refs: tuple[str, ...] = ()
    budget_limit_microusd: int | None = None
    observed_spend_microusd: int | None = None
    hard_cap_microusd: int | None = None
    projected_spend_microusd: int | None = None
    slack_microusd: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeterministicBudgetCertificate:
        return cls(
            schema_version=str(data["schema_version"]),
            scope=parse_budget_scope(str(data["scope"])),
            budget_limit_usd=float(data["budget_limit_usd"]),
            observed_spend_usd=float(data["observed_spend_usd"]),
            hard_cap_usd=float(data["hard_cap_usd"]),
            cap_provenance=parse_cap_provenance(str(data["cap_provenance"])),
            concurrency_model=parse_concurrency_model(str(data["concurrency_model"])),
            action_hash=str(data["action_hash"]),
            filtration_hash=str(data["filtration_hash"]),
            ledger_sequence_before=int(data["ledger_sequence_before"]),
            projected_spend_usd=float(data["projected_spend_usd"]),
            slack_usd=float(data["slack_usd"]),
            outcome=parse_budget_outcome(str(data["outcome"])),
            certificate_kind=parse_budget_certificate_kind(
                str(
                    data.get(
                        "certificate_kind",
                        BudgetCertificateKind.DETERMINISTIC_HARD_CAP.value,
                    )
                )
            ),
            obligations=tuple(str(item) for item in data.get("obligations", ())),
            theorem_refs=tuple(str(item) for item in data.get("theorem_refs", ())),
            budget_limit_microusd=_optional_int(data.get("budget_limit_microusd")),
            observed_spend_microusd=_optional_int(data.get("observed_spend_microusd")),
            hard_cap_microusd=_optional_int(data.get("hard_cap_microusd")),
            projected_spend_microusd=_optional_int(data.get("projected_spend_microusd")),
            slack_microusd=_optional_int(data.get("slack_microusd")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ProbabilisticBudgetCertificate:
    schema_version: str
    certificate_kind: BudgetCertificateKind
    scope: BudgetScope
    budget_limit: float
    delta_total: float
    observed_spend: float
    action_hash: str
    filtration_hash: str
    ledger_sequence_before: int
    pre_ledger_hash: str
    cost_model_id: str
    high_probability_bound: float
    slack: float
    outcome: BudgetOutcome
    certified_mean_sum: float = 0.0
    cgf_sum_by_lambda: Mapping[str, float] = field(default_factory=dict)
    lambda_grid: tuple[float, ...] = ()
    mixture_weights: tuple[float, ...] = ()
    hard_cap: float | None = None
    mean_upper: float | None = None
    variance_upper: float | None = None
    second_moment_upper: float | None = None
    obligations: tuple[str, ...] = ()
    theorem_refs: tuple[str, ...] = ()
    budget_limit_microusd: int | None = None
    observed_spend_microusd: int | None = None
    high_probability_bound_microusd: int | None = None
    slack_microusd: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProbabilisticBudgetCertificate:
        return cls(
            schema_version=str(data["schema_version"]),
            certificate_kind=parse_budget_certificate_kind(str(data["certificate_kind"])),
            scope=parse_budget_scope(str(data["scope"])),
            budget_limit=float(data["budget_limit"]),
            delta_total=float(data["delta_total"]),
            observed_spend=float(data["observed_spend"]),
            certified_mean_sum=float(data.get("certified_mean_sum", 0.0)),
            cgf_sum_by_lambda={
                str(key): float(value)
                for key, value in data.get("cgf_sum_by_lambda", {}).items()
            },
            lambda_grid=tuple(float(item) for item in data.get("lambda_grid", ())),
            mixture_weights=tuple(float(item) for item in data.get("mixture_weights", ())),
            hard_cap=_optional_float(data.get("hard_cap")),
            mean_upper=_optional_float(data.get("mean_upper")),
            variance_upper=_optional_float(data.get("variance_upper")),
            second_moment_upper=_optional_float(data.get("second_moment_upper")),
            action_hash=str(data["action_hash"]),
            filtration_hash=str(data["filtration_hash"]),
            ledger_sequence_before=int(data["ledger_sequence_before"]),
            pre_ledger_hash=str(data["pre_ledger_hash"]),
            cost_model_id=str(data["cost_model_id"]),
            high_probability_bound=float(data["high_probability_bound"]),
            slack=float(data["slack"]),
            outcome=parse_budget_outcome(str(data["outcome"])),
            obligations=tuple(str(item) for item in data.get("obligations", ())),
            theorem_refs=tuple(str(item) for item in data.get("theorem_refs", ())),
            budget_limit_microusd=_optional_int(data.get("budget_limit_microusd")),
            observed_spend_microusd=_optional_int(data.get("observed_spend_microusd")),
            high_probability_bound_microusd=_optional_int(
                data.get("high_probability_bound_microusd")
            ),
            slack_microusd=_optional_int(data.get("slack_microusd")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


BudgetCertificate = DeterministicBudgetCertificate | ProbabilisticBudgetCertificate


def budget_certificate_from_dict(data: Mapping[str, Any]) -> BudgetCertificate:
    kind = str(
        data.get("certificate_kind", BudgetCertificateKind.DETERMINISTIC_HARD_CAP.value)
    )
    if kind == BudgetCertificateKind.DETERMINISTIC_HARD_CAP.value:
        return DeterministicBudgetCertificate.from_dict(data)
    return ProbabilisticBudgetCertificate.from_dict(data)


@dataclass(frozen=True)
class BudgetTrace:
    certificate_hash: str | None = None
    certificate_kind: BudgetCertificateKind | None = None
    claim_mode: str | None = None
    pre_ledger_hash: str | None = None
    ledger_sequence: int | None = None
    scope: BudgetScope | None = None
    projected_spend_usd: float | None = None
    projected_spend_microusd: int | None = None
    high_probability_bound_usd: float | None = None
    high_probability_bound_microusd: int | None = None
    delta_total: float | None = None
    cost_model_id: str | None = None
    outcome: BudgetOutcome | None = None
    certifying: bool = False
    downgrade_reason: str | None = None
    validation_error: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BudgetTrace:
        scope = data.get("scope")
        outcome = data.get("outcome")
        certificate_kind = data.get("certificate_kind")
        return cls(
            certificate_hash=cast(str | None, data.get("certificate_hash")),
            certificate_kind=parse_budget_certificate_kind(str(certificate_kind))
            if certificate_kind is not None
            else None,
            claim_mode=cast(str | None, data.get("claim_mode")),
            pre_ledger_hash=cast(str | None, data.get("pre_ledger_hash")),
            ledger_sequence=int(data["ledger_sequence"])
            if data.get("ledger_sequence") is not None
            else None,
            scope=parse_budget_scope(str(scope)) if scope is not None else None,
            projected_spend_usd=_optional_float(data.get("projected_spend_usd")),
            projected_spend_microusd=_optional_int(data.get("projected_spend_microusd")),
            high_probability_bound_usd=_optional_float(
                data.get("high_probability_bound_usd")
            ),
            high_probability_bound_microusd=_optional_int(
                data.get("high_probability_bound_microusd")
            ),
            delta_total=_optional_float(data.get("delta_total")),
            cost_model_id=cast(str | None, data.get("cost_model_id")),
            outcome=parse_budget_outcome(str(outcome)) if outcome is not None else None,
            certifying=bool(data.get("certifying", False)),
            downgrade_reason=cast(str | None, data.get("downgrade_reason")),
            validation_error=cast(str | None, data.get("validation_error")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class CompetitorResult:
    system: str
    system_version: str
    adapter_kind: str
    case_id: str
    status: str
    decision: str
    certificate_supported: bool
    blocked: bool
    skipped: bool
    certificate_outcome: CertificateOutcome | None = None
    liability_cost: float | None = None
    evidence_url: str | None = None
    skip_reason: str | None = None
    not_run_reason: str | None = None
    emitted_decision_certificate: bool = False
    deterministic_across_repeated_runs: bool = False
    replayable_seal_reproduces_decision: bool = False
    capability_facts: Mapping[str, Any] = field(default_factory=dict)
    adapter_versions: Mapping[str, Any] = field(default_factory=dict)
    measurement: Mapping[str, Any] = field(default_factory=dict)
    unsafe_issue: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CompetitorResult:
        certificate_outcome = data.get("certificate_outcome")
        return cls(
            system=str(data["system"]),
            system_version=str(data["system_version"]),
            adapter_kind=str(data["adapter_kind"]),
            case_id=str(data["case_id"]),
            status=str(data["status"]),
            decision=str(data["decision"]),
            certificate_supported=bool(data["certificate_supported"]),
            certificate_outcome=parse_certificate_outcome(str(certificate_outcome))
            if certificate_outcome is not None
            else None,
            blocked=bool(data["blocked"]),
            skipped=bool(data["skipped"]),
            liability_cost=_optional_float(data.get("liability_cost")),
            evidence_url=cast(str | None, data.get("evidence_url")),
            skip_reason=cast(str | None, data.get("skip_reason")),
            not_run_reason=cast(str | None, data.get("not_run_reason")),
            emitted_decision_certificate=bool(
                data.get("emitted_decision_certificate", data["certificate_supported"])
            ),
            deterministic_across_repeated_runs=bool(
                data.get("deterministic_across_repeated_runs", False)
            ),
            replayable_seal_reproduces_decision=bool(
                data.get("replayable_seal_reproduces_decision", False)
            ),
            capability_facts=dict(data.get("capability_facts", {})),
            adapter_versions=dict(data.get("adapter_versions", {})),
            measurement=dict(data.get("measurement", {})),
            unsafe_issue=cast(str | None, data.get("unsafe_issue")),
        )

    def to_dict(self) -> JsonObject:
        return {
            "system": self.system,
            "system_version": self.system_version,
            "adapter_kind": self.adapter_kind,
            "case_id": self.case_id,
            "status": self.status,
            "decision": self.decision,
            "certificate_supported": self.certificate_supported,
            "certificate_outcome": self.certificate_outcome.value
            if self.certificate_outcome is not None
            else None,
            "blocked": self.blocked,
            "skipped": self.skipped,
            "liability_cost": self.liability_cost,
            "evidence_url": self.evidence_url,
            "skip_reason": self.skip_reason,
            "not_run_reason": self.not_run_reason,
            "emitted_decision_certificate": self.emitted_decision_certificate,
            "deterministic_across_repeated_runs": self.deterministic_across_repeated_runs,
            "replayable_seal_reproduces_decision": self.replayable_seal_reproduces_decision,
            "capability_facts": dict(self.capability_facts),
            "adapter_versions": dict(self.adapter_versions),
            "measurement": dict(self.measurement),
            "unsafe_issue": self.unsafe_issue,
        }


@dataclass(frozen=True)
class CandidateAction:
    action_type: ActionType
    description: str = ""
    expected_improvement: float | None = None
    novelty: float | None = None
    confidence: float | None = None
    cost_overrides: Mapping[str, float] = field(default_factory=dict)
    risk_overrides: Mapping[str, float] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    source: CandidateSource = CandidateSource.HOST
    parameters: Mapping[str, Any] = field(default_factory=dict)
    certificate: CertificateEvidence | None = None
    budget_certificate: BudgetCertificate | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateAction:
        certificate = data.get("certificate")
        metadata = dict(data.get("metadata", {}))
        raw_budget_certificate = data.get("budget_certificate")
        if raw_budget_certificate is None and isinstance(
            metadata.get("budget_certificate"), Mapping
        ):
            raw_budget_certificate = metadata["budget_certificate"]
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            description=str(data.get("description", "")),
            certificate=CertificateEvidence.from_dict(cast(Mapping[str, Any], certificate))
            if isinstance(certificate, Mapping)
            else None,
            budget_certificate=budget_certificate_from_dict(
                cast(Mapping[str, Any], raw_budget_certificate)
            )
            if isinstance(raw_budget_certificate, Mapping)
            else None,
            expected_improvement=_optional_float(data.get("expected_improvement")),
            novelty=_optional_float(data.get("novelty")),
            confidence=_optional_float(data.get("confidence")),
            cost_overrides={
                str(key): float(value) for key, value in data.get("cost_overrides", {}).items()
            },
            risk_overrides={
                str(key): float(value) for key, value in data.get("risk_overrides", {}).items()
            },
            metadata=metadata,
            source=parse_candidate_source(cast(str | None, data.get("source"))),
            parameters=dict(data.get("parameters", {})),
        )

    @classmethod
    def coerce(
        cls, value: CandidateAction | ActionType | str | Mapping[str, Any]
    ) -> CandidateAction:
        if isinstance(value, CandidateAction):
            return value
        if isinstance(value, Mapping):
            return cls.from_dict(value)
        return cls(action_type=parse_action_type(value))

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    evidence_type: str
    message: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Evidence:
        return cls(
            rule_id=str(data["rule_id"]),
            evidence_type=str(data["evidence_type"]),
            message=str(data.get("message", "")),
            details=dict(data.get("details", {})),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class PolicyReason:
    code: str
    message: str
    severity: str = "info"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyReason:
        return cls(
            code=str(data["code"]),
            message=str(data["message"]),
            severity=str(data.get("severity", "info")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class Redaction:
    field_path: str
    original_value: str
    replacement: str
    original_hash: str
    detector: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Redaction:
        return cls(
            field_path=str(data["field_path"]),
            original_value=str(data["original_value"]),
            replacement=str(data["replacement"]),
            original_hash=str(data["original_hash"]),
            detector=str(data["detector"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ActionMutation:
    parameter_updates: Mapping[str, Any] = field(default_factory=dict)
    metadata_updates: Mapping[str, Any] = field(default_factory=dict)
    redactions: tuple[Redaction, ...] = ()
    notes: tuple[str, ...] = ()
    jurisdiction_evidence: Evidence | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActionMutation:
        jurisdiction_evidence = data.get("jurisdiction_evidence")
        return cls(
            parameter_updates=dict(data.get("parameter_updates", {})),
            metadata_updates=dict(data.get("metadata_updates", {})),
            redactions=tuple(
                Redaction.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("redactions", ())
            ),
            notes=tuple(str(item) for item in data.get("notes", ())),
            jurisdiction_evidence=Evidence.from_dict(cast(Mapping[str, Any], jurisdiction_evidence))
            if isinstance(jurisdiction_evidence, Mapping)
            else None,
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class EscalationTarget:
    target_type: str
    target: str
    mode: str = "sync"
    fallback: str = "deny"
    payload: Any = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EscalationTarget:
        return cls(
            target_type=str(data["target_type"]),
            target=str(data["target"]),
            mode=str(data.get("mode", "sync")),
            fallback=str(data.get("fallback", "deny")),
            payload=data.get("payload"),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class PolicyDecision:
    kind: str
    reason: PolicyReason | None = None
    jurisdiction_evidence: Evidence | None = None
    mutation: ActionMutation | None = None
    to: EscalationTarget | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyDecision:
        reason = data.get("reason")
        jurisdiction_evidence = data.get("jurisdiction_evidence")
        mutation = data.get("mutation")
        target = data.get("to")
        return cls(
            kind=str(data["kind"]),
            reason=PolicyReason.from_dict(cast(Mapping[str, Any], reason))
            if isinstance(reason, Mapping)
            else None,
            jurisdiction_evidence=Evidence.from_dict(cast(Mapping[str, Any], jurisdiction_evidence))
            if isinstance(jurisdiction_evidence, Mapping)
            else None,
            mutation=ActionMutation.from_dict(cast(Mapping[str, Any], mutation))
            if isinstance(mutation, Mapping)
            else None,
            to=EscalationTarget.from_dict(cast(Mapping[str, Any], target))
            if isinstance(target, Mapping)
            else None,
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {"kind": self.kind}
        if self.reason is not None:
            payload["reason"] = self.reason.to_dict()
        if self.jurisdiction_evidence is not None:
            payload["jurisdiction_evidence"] = self.jurisdiction_evidence.to_dict()
        if self.mutation is not None:
            payload["mutation"] = self.mutation.to_dict()
        if self.to is not None:
            payload["to"] = self.to.to_dict()
        return payload


@dataclass(frozen=True)
class PolicyTraceEntry:
    policy_name: str
    policy_kind: str
    policy_version: str
    config_version: str
    config_hash: str
    status: str
    decision: PolicyDecision
    jurisdiction_evidence: Evidence | None
    mutation: ActionMutation | None
    input_action_hash: str
    output_action_hash: str
    elapsed_us: int
    short_circuit: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyTraceEntry:
        jurisdiction_evidence = data.get("jurisdiction_evidence")
        mutation = data.get("mutation")
        return cls(
            policy_name=str(data["policy_name"]),
            policy_kind=str(data["policy_kind"]),
            policy_version=str(data["policy_version"]),
            config_version=str(data["config_version"]),
            config_hash=str(data["config_hash"]),
            status=str(data["status"]),
            decision=PolicyDecision.from_dict(cast(Mapping[str, Any], data["decision"])),
            jurisdiction_evidence=Evidence.from_dict(cast(Mapping[str, Any], jurisdiction_evidence))
            if isinstance(jurisdiction_evidence, Mapping)
            else None,
            mutation=ActionMutation.from_dict(cast(Mapping[str, Any], mutation))
            if isinstance(mutation, Mapping)
            else None,
            input_action_hash=str(data["input_action_hash"]),
            output_action_hash=str(data["output_action_hash"]),
            elapsed_us=int(data.get("elapsed_us", 0)),
            short_circuit=cast(str | None, data.get("short_circuit")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class BudgetLedger:
    limit_usd: float | None = None
    spent_usd: float = 0.0
    limit_units: float | None = None
    spent_units: float = 0.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BudgetLedger:
        return cls(
            limit_usd=_optional_float(data.get("limit_usd")),
            spent_usd=float(data.get("spent_usd", 0.0)),
            limit_units=_optional_float(data.get("limit_units")),
            spent_units=float(data.get("spent_units", 0.0)),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class PolicyContext:
    permissions: frozenset[str] = field(default_factory=frozenset)
    approved_actions: frozenset[ActionType] = field(default_factory=frozenset)
    privacy_mode: str = "standard"
    organization_policy: str | None = None
    user_id: str | None = None
    organization_id: str | None = None
    task_id: str | None = None
    decision_unix_ms: int = 0
    time_window: Mapping[str, Any] | None = None
    task_budget: BudgetLedger = field(default_factory=BudgetLedger)
    user_budget: BudgetLedger = field(default_factory=BudgetLedger)
    organization_budget: BudgetLedger = field(default_factory=BudgetLedger)
    prior_thread: tuple[Mapping[str, Any], ...] = ()
    novelty_score: float | None = None
    realized_costs: Mapping[str, BudgetLedger] = field(default_factory=dict)
    external_observations: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class CostVector:
    tokens: float = 0.0
    latency: float = 0.0
    money: float = 0.0
    compute: float = 0.0
    api_calls: float = 0.0
    context_pollution: float = 0.0
    memory_bloat: float = 0.0
    user_attention: float = 0.0
    privacy_exposure: float = 0.0
    coordination_overhead: float = 0.0
    opportunity_cost: float = 0.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CostVector:
        return cls(**{key: float(data.get(key, 0.0)) for key in cls.__dataclass_fields__})

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class RiskVector:
    privacy_risk: float = 0.0
    tool_risk: float = 0.0
    external_side_effect_risk: float = 0.0
    hallucination_risk: float = 0.0
    staleness_risk: float = 0.0
    source_quality_risk: float = 0.0
    irreversibility: float = 0.0
    sensitivity: float = 0.0
    compliance_risk: float = 0.0
    user_trust_risk: float = 0.0
    future_misuse_risk: float = 0.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RiskVector:
        return cls(**{key: float(data.get(key, 0.0)) for key in cls.__dataclass_fields__})

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class BudgetState:
    tokens_remaining: float = 1.0
    tool_calls_remaining: float = 1.0
    latency_ms_remaining: float = 1.0
    dollars_remaining: float = 1.0
    model_escalations_remaining: float = 1.0
    memory_writes_remaining: float = 1.0
    concierge_reviews_remaining: float = 1.0
    retrievals_remaining: float = 1.0
    task_horizon_remaining: float = 1.0
    confidence_deficit: float = 0.0
    task_importance: float = 0.5
    money_remaining: float = 1.0
    api_calls_remaining: float = 1.0
    compute_remaining: float = 1.0
    user_attention_remaining: float = 1.0
    memory_slots_remaining: float = 1.0
    fallback_triggers: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BudgetState:
        numeric_defaults = {
            "confidence_deficit": 0.0,
            "task_importance": 0.5,
        }
        values: dict[str, Any] = {}
        for key in cls.__dataclass_fields__:
            if key == "fallback_triggers":
                values[key] = tuple(str(item) for item in data.get(key, ()))
            else:
                values[key] = float(data.get(key, numeric_defaults.get(key, 1.0)))
        return cls(**values)

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class PricingBreakdown:
    pricing_policy: PricingPolicy
    pricing_policy_name: str
    pricing_policy_version: str
    base_entry_price: float
    fixed_baseline_price: float
    entry_price: float
    final_lambda: float
    budget_state: BudgetState
    action_cost: CostVector
    horizon_multiplier: float
    scarcity_multiplier: float
    override_rate_multiplier: float
    action_cost_adjustment: float
    uncertainty_adjustment: float
    risk_adjustment: float
    scarcity_pressure: float
    weighted_scarcity: float
    effective_horizon: float
    override_rate: float
    cap_applied: bool
    floor_applied: bool
    fail_safe_applied: bool
    hard_budget_exhausted: bool
    clears_rope: bool
    fixed_clears_rope: bool
    differs_from_fixed: bool
    fallback_triggers: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PricingBreakdown:
        return cls(
            pricing_policy=parse_pricing_policy(str(data["pricing_policy"])),
            pricing_policy_name=str(data["pricing_policy_name"]),
            pricing_policy_version=str(data["pricing_policy_version"]),
            base_entry_price=float(data["base_entry_price"]),
            fixed_baseline_price=float(data["fixed_baseline_price"]),
            entry_price=float(data["entry_price"]),
            final_lambda=float(data["final_lambda"]),
            budget_state=BudgetState.from_dict(cast(Mapping[str, Any], data["budget_state"])),
            action_cost=CostVector.from_dict(cast(Mapping[str, Any], data["action_cost"])),
            horizon_multiplier=float(data["horizon_multiplier"]),
            scarcity_multiplier=float(data["scarcity_multiplier"]),
            override_rate_multiplier=float(data["override_rate_multiplier"]),
            action_cost_adjustment=float(data["action_cost_adjustment"]),
            uncertainty_adjustment=float(data["uncertainty_adjustment"]),
            risk_adjustment=float(data["risk_adjustment"]),
            scarcity_pressure=float(data["scarcity_pressure"]),
            weighted_scarcity=float(data["weighted_scarcity"]),
            effective_horizon=float(data["effective_horizon"]),
            override_rate=float(data["override_rate"]),
            cap_applied=bool(data["cap_applied"]),
            floor_applied=bool(data["floor_applied"]),
            fail_safe_applied=bool(data["fail_safe_applied"]),
            hard_budget_exhausted=bool(data["hard_budget_exhausted"]),
            clears_rope=bool(data["clears_rope"]),
            fixed_clears_rope=bool(data["fixed_clears_rope"]),
            differs_from_fixed=bool(data["differs_from_fixed"]),
            fallback_triggers=tuple(str(item) for item in data.get("fallback_triggers", ())),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class PolicyResult:
    action_type: ActionType
    status: PolicyStatus
    policy_id: str
    reason: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyResult:
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            status=parse_policy_status(str(data["status"])),
            policy_id=str(data["policy_id"]),
            reason=str(data["reason"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class AdmissionScore:
    action_type: ActionType
    expected_upside: float
    surprisal: float
    confidence: float
    cost: CostVector
    risk: RiskVector
    cost_penalty: float
    risk_penalty: float
    clearance_score: float
    pricing_breakdown: PricingBreakdown
    scorer_version: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdmissionScore:
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            expected_upside=float(data["expected_upside"]),
            surprisal=float(data["surprisal"]),
            confidence=float(data["confidence"]),
            cost=CostVector.from_dict(cast(Mapping[str, Any], data["cost"])),
            risk=RiskVector.from_dict(cast(Mapping[str, Any], data["risk"])),
            cost_penalty=float(data["cost_penalty"]),
            risk_penalty=float(data["risk_penalty"]),
            clearance_score=float(data["clearance_score"]),
            pricing_breakdown=PricingBreakdown.from_dict(
                cast(Mapping[str, Any], data["pricing_breakdown"])
            ),
            scorer_version=str(data["scorer_version"]),
        )

    @property
    def clears_rope(self) -> bool:
        return self.pricing_breakdown.clears_rope

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class WriteFootprint:
    resource_type: str
    operation: str
    blast_radius: str
    rollback_profile: str
    resource_id: str | None = None
    resource_pattern: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> WriteFootprint:
        return cls(
            resource_type=str(data["resource_type"]),
            resource_id=cast(str | None, data.get("resource_id")),
            resource_pattern=cast(str | None, data.get("resource_pattern")),
            operation=str(data["operation"]),
            blast_radius=str(data["blast_radius"]),
            rollback_profile=str(data["rollback_profile"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class CostBound:
    lower_microusd: int
    expected_microusd: int
    upper_microusd: int
    confidence_bps: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CostBound:
        return cls(
            lower_microusd=int(data["lower_microusd"]),
            expected_microusd=int(data["expected_microusd"]),
            upper_microusd=int(data["upper_microusd"]),
            confidence_bps=int(data["confidence_bps"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class LatencyBound:
    lower_ms: int
    expected_ms: int
    upper_ms: int
    confidence_bps: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LatencyBound:
        return cls(
            lower_ms=int(data["lower_ms"]),
            expected_ms=int(data["expected_ms"]),
            upper_ms=int(data["upper_ms"]),
            confidence_bps=int(data["confidence_bps"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class RiskBound:
    privacy_risk_bps: int
    integrity_risk_bps: int
    availability_risk_bps: int
    financial_risk_bps: int
    compliance_risk_bps: int
    confidence_bps: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RiskBound:
        return cls(
            privacy_risk_bps=int(data["privacy_risk_bps"]),
            integrity_risk_bps=int(data["integrity_risk_bps"]),
            availability_risk_bps=int(data["availability_risk_bps"]),
            financial_risk_bps=int(data["financial_risk_bps"]),
            compliance_risk_bps=int(data["compliance_risk_bps"]),
            confidence_bps=int(data["confidence_bps"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class UtilityBound:
    lower_bps: int
    expected_bps: int
    upper_bps: int
    confidence_bps: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UtilityBound:
        return cls(
            lower_bps=int(data["lower_bps"]),
            expected_bps=int(data["expected_bps"]),
            upper_bps=int(data["upper_bps"]),
            confidence_bps=int(data["confidence_bps"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class SourceToSinkFlow:
    source_data_class: DataClass
    sink: str
    sink_capability_class: CapabilityClass

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SourceToSinkFlow:
        return cls(
            source_data_class=parse_data_class(str(data["source_data_class"])),
            sink=str(data["sink"]),
            sink_capability_class=parse_capability_class(
                str(data["sink_capability_class"])
            ),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class EffectVector:
    schema_version: str
    capability_class: CapabilityClass
    side_effect_class: TypedSideEffectClass
    data_classes_read: tuple[DataClass, ...]
    data_classes_written: tuple[DataClass, ...]
    write_footprint: tuple[WriteFootprint, ...]
    cost_bound: CostBound
    latency_bound: LatencyBound
    risk_bound: RiskBound
    utility_bound: UtilityBound
    reversibility: TypedReversibility
    approval_required: bool
    warrant_required: bool
    budget_required: bool
    source_to_sink_flows: tuple[SourceToSinkFlow, ...]
    model_version: str
    inference_evidence: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EffectVector:
        return cls(
            schema_version=str(data["schema_version"]),
            capability_class=parse_capability_class(str(data["capability_class"])),
            side_effect_class=parse_typed_side_effect_class(str(data["side_effect_class"])),
            data_classes_read=tuple(
                parse_data_class(str(item)) for item in data.get("data_classes_read", ())
            ),
            data_classes_written=tuple(
                parse_data_class(str(item))
                for item in data.get("data_classes_written", ())
            ),
            write_footprint=tuple(
                WriteFootprint.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("write_footprint", ())
            ),
            cost_bound=CostBound.from_dict(cast(Mapping[str, Any], data["cost_bound"])),
            latency_bound=LatencyBound.from_dict(
                cast(Mapping[str, Any], data["latency_bound"])
            ),
            risk_bound=RiskBound.from_dict(cast(Mapping[str, Any], data["risk_bound"])),
            utility_bound=UtilityBound.from_dict(
                cast(Mapping[str, Any], data["utility_bound"])
            ),
            reversibility=parse_typed_reversibility(str(data["reversibility"])),
            approval_required=bool(data["approval_required"]),
            warrant_required=bool(data["warrant_required"]),
            budget_required=bool(data["budget_required"]),
            source_to_sink_flows=tuple(
                SourceToSinkFlow.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("source_to_sink_flows", ())
            ),
            model_version=str(data["model_version"]),
            inference_evidence=dict(data.get("inference_evidence", {})),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class AdmissionConstraintResult:
    constraint_id: str
    passed: bool
    severity: ConstraintSeverity
    reason_code: str
    evidence_hash: str
    safe_public_message: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdmissionConstraintResult:
        return cls(
            constraint_id=str(data["constraint_id"]),
            passed=bool(data["passed"]),
            severity=parse_constraint_severity(str(data["severity"])),
            reason_code=str(data["reason_code"]),
            evidence_hash=str(data["evidence_hash"]),
            safe_public_message=str(data["safe_public_message"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ObjectiveComponents:
    schema_version: str
    utility_lcb_bps: int
    cost_ucb_microusd: int
    risk_ucb_bps: int
    cost_penalty_bps: int
    risk_penalty_bps: int
    structural_penalty_bps: int
    objective_bps: int
    optimizer_model_version: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ObjectiveComponents:
        return cls(
            schema_version=str(data["schema_version"]),
            utility_lcb_bps=int(data["utility_lcb_bps"]),
            cost_ucb_microusd=int(data["cost_ucb_microusd"]),
            risk_ucb_bps=int(data["risk_ucb_bps"]),
            cost_penalty_bps=int(data["cost_penalty_bps"]),
            risk_penalty_bps=int(data["risk_penalty_bps"]),
            structural_penalty_bps=int(data["structural_penalty_bps"]),
            objective_bps=int(data["objective_bps"]),
            optimizer_model_version=str(data["optimizer_model_version"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class AdmissionTrace:
    schema_version: str
    candidate_hash: str
    request_hash: str
    policy_bundle_hash: str
    tool_schema_hash: str
    capability_registry_hash: str
    effect_vector_hash: str
    utility_model_version: str
    risk_model_version: str
    calibration_set_hash: str
    hard_constraints: tuple[AdmissionConstraintResult, ...]
    objective_components: ObjectiveComponents
    selected_decision: AdmissionDecision
    selected_reason: str
    deterministic_replay_inputs_hash: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdmissionTrace:
        return cls(
            schema_version=str(data["schema_version"]),
            candidate_hash=str(data["candidate_hash"]),
            request_hash=str(data["request_hash"]),
            policy_bundle_hash=str(data["policy_bundle_hash"]),
            tool_schema_hash=str(data["tool_schema_hash"]),
            capability_registry_hash=str(data["capability_registry_hash"]),
            effect_vector_hash=str(data["effect_vector_hash"]),
            utility_model_version=str(data["utility_model_version"]),
            risk_model_version=str(data["risk_model_version"]),
            calibration_set_hash=str(data["calibration_set_hash"]),
            hard_constraints=tuple(
                AdmissionConstraintResult.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("hard_constraints", ())
            ),
            objective_components=ObjectiveComponents.from_dict(
                cast(Mapping[str, Any], data["objective_components"])
            ),
            selected_decision=parse_admission_decision(str(data["selected_decision"])),
            selected_reason=str(data["selected_reason"]),
            deterministic_replay_inputs_hash=str(
                data["deterministic_replay_inputs_hash"]
            ),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class CandidateDecision:
    action_type: ActionType
    decision: DecisionType
    reason: str
    final_candidate: CandidateAction
    policy_trace: tuple[PolicyTraceEntry, ...]
    mutation_ledger: tuple[ActionMutation, ...] = ()
    short_circuit: str | None = None
    budget_trace: BudgetTrace | None = None
    admission_trace: AdmissionTrace | None = None
    admission_trace_hash: str | None = None
    effect_vector: EffectVector | None = None
    admission_score: AdmissionScore | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateDecision:
        admission_score = data.get("admission_score")
        admission_trace = data.get("admission_trace")
        effect_vector = data.get("effect_vector")
        budget_trace = data.get("budget_trace")
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            decision=parse_decision_type(str(data["decision"])),
            reason=str(data["reason"]),
            final_candidate=CandidateAction.from_dict(
                cast(Mapping[str, Any], data["final_candidate"])
            ),
            policy_trace=tuple(
                PolicyTraceEntry.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("policy_trace", ())
            ),
            mutation_ledger=tuple(
                ActionMutation.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("mutation_ledger", ())
            ),
            short_circuit=cast(str | None, data.get("short_circuit")),
            budget_trace=BudgetTrace.from_dict(cast(Mapping[str, Any], budget_trace))
            if isinstance(budget_trace, Mapping)
            else None,
            admission_trace=AdmissionTrace.from_dict(
                cast(Mapping[str, Any], admission_trace)
            )
            if isinstance(admission_trace, Mapping)
            else None,
            admission_trace_hash=cast(str | None, data.get("admission_trace_hash")),
            effect_vector=EffectVector.from_dict(cast(Mapping[str, Any], effect_vector))
            if isinstance(effect_vector, Mapping)
            else None,
            admission_score=AdmissionScore.from_dict(cast(Mapping[str, Any], admission_score))
            if isinstance(admission_score, Mapping)
            else None,
        )

    def to_dict(self) -> JsonObject:
        payload = _as_json_object(self)
        if self.admission_trace is None:
            payload.pop("admission_trace", None)
        if self.admission_trace_hash is None:
            payload.pop("admission_trace_hash", None)
        if self.effect_vector is None:
            payload.pop("effect_vector", None)
        return payload


@dataclass(frozen=True)
class RoutingDecision:
    action_type: ActionType | None
    decision: DecisionType
    reason: str
    host_action: ActionType | None
    candidate_decisions: tuple[CandidateDecision, ...]
    thread_id: str | None = None
    seal_id: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RoutingDecision:
        raw_action_type = data.get("action_type")
        raw_host_action = data.get("host_action")
        return cls(
            action_type=parse_action_type(str(raw_action_type))
            if raw_action_type is not None
            else None,
            decision=parse_decision_type(str(data["decision"])),
            reason=str(data["reason"]),
            host_action=parse_action_type(str(raw_host_action))
            if raw_host_action is not None
            else None,
            candidate_decisions=tuple(
                CandidateDecision.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("candidate_decisions", ())
            ),
            thread_id=cast(str | None, data.get("thread_id")),
            seal_id=cast(str | None, data.get("seal_id")),
        )

    @property
    def selected_candidate(self) -> CandidateDecision | None:
        if self.action_type is None:
            return None
        return next(
            (
                candidate
                for candidate in self.candidate_decisions
                if candidate.action_type == self.action_type and candidate.decision == self.decision
            ),
            None,
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class MemoryObject:
    content: str
    memory_type: str
    context: Mapping[str, Any]
    confidence: float
    created_at: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MemoryObject:
        return cls(
            content=str(data["content"]),
            memory_type=str(data["memory_type"]),
            context=dict(cast(Mapping[str, Any], data["context"])),
            confidence=float(data["confidence"]),
            created_at=str(data["created_at"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class MemoryDecision:
    store: bool
    decision: DecisionType
    reason: str
    memory_score: float
    sensitivity: float
    memory_object: MemoryObject | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MemoryDecision:
        memory_object = data.get("memory_object")
        return cls(
            store=bool(data["store"]),
            decision=parse_decision_type(str(data["decision"])),
            reason=str(data["reason"]),
            memory_score=float(data["memory_score"]),
            sensitivity=float(data["sensitivity"]),
            memory_object=MemoryObject.from_dict(cast(Mapping[str, Any], memory_object))
            if isinstance(memory_object, Mapping)
            else None,
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ActionDefinition:
    action_type: ActionType
    description: str
    permissions: tuple[str, ...]
    side_effect_level: SideEffectLevel
    reversibility: str
    default_cost_class: str
    default_risk_class: str
    requires_user_approval: bool
    action_family: str
    availability_key: str | None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActionDefinition:
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            description=str(data["description"]),
            permissions=tuple(str(item) for item in data.get("permissions", ())),
            side_effect_level=SideEffectLevel(str(data["side_effect_level"])),
            reversibility=str(data["reversibility"]),
            default_cost_class=str(data["default_cost_class"]),
            default_risk_class=str(data["default_risk_class"]),
            requires_user_approval=bool(data["requires_user_approval"]),
            action_family=str(data["action_family"]),
            availability_key=cast(str | None, data.get("availability_key")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class MountSpec:
    host_path: str
    sandbox_path: str
    mode: MountMode

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MountSpec:
        return cls(
            host_path=str(data["host_path"]),
            sandbox_path=str(data["sandbox_path"]),
            mode=parse_mount_mode(str(data["mode"])),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class EgressRule:
    host: str
    port: int | None = None
    protocol: str = "tcp"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EgressRule:
        port = data.get("port")
        return cls(
            host=str(data["host"]),
            port=int(port) if port is not None else None,
            protocol=str(data.get("protocol", "tcp")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 10
    memory_bytes: int = 512 * 1024 * 1024
    wall_clock_ms: int = 10_000
    max_fs_writes_bytes: int = 8 * 1024 * 1024
    max_stdout_bytes: int = 12_000
    max_processes: int = 64

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ResourceLimits:
        return cls(
            cpu_seconds=int(data["cpu_seconds"]),
            memory_bytes=int(data["memory_bytes"]),
            wall_clock_ms=int(data["wall_clock_ms"]),
            max_fs_writes_bytes=int(data["max_fs_writes_bytes"]),
            max_stdout_bytes=int(data["max_stdout_bytes"]),
            max_processes=int(data["max_processes"]),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class OutputTransform:
    kind: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OutputTransform:
        return cls(kind=str(data["kind"]))

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class NetworkPolicy:
    mode: str
    rules: tuple[EgressRule, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NetworkPolicy:
        return cls(
            mode=str(data["mode"]),
            rules=tuple(
                EgressRule.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("rules", ())
            ),
        )

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {"mode": self.mode}
        if self.rules:
            payload["rules"] = [rule.to_dict() for rule in self.rules]
        return payload


@dataclass(frozen=True)
class SandboxedCommand:
    argv: tuple[str, ...]
    cwd: str
    env_list: tuple[str, ...] = ()
    stdin: tuple[int, ...] | None = None
    mounts: tuple[MountSpec, ...] = ()
    egress_list: tuple[EgressRule, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SandboxedCommand:
        raw_stdin = data.get("stdin")
        return cls(
            argv=tuple(str(item) for item in data["argv"]),
            cwd=str(data["cwd"]),
            env_list=tuple(str(item) for item in data.get("env_list", ())),
            stdin=tuple(int(item) for item in raw_stdin) if raw_stdin is not None else None,
            mounts=tuple(
                MountSpec.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("mounts", ())
            ),
            egress_list=tuple(
                EgressRule.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("egress_list", ())
            ),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class SandboxProvenance:
    backend: SandboxBackendKind
    profile_hash: str
    image_digest: str | None
    container_runtime: ContainerRuntime | None
    mount_spec: tuple[MountSpec, ...]
    network_policy: NetworkPolicy
    applied_limits: ResourceLimits
    backend_guarantees: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SandboxProvenance:
        raw_runtime = data.get("container_runtime")
        return cls(
            backend=parse_sandbox_backend(str(data["backend"])),
            profile_hash=str(data["profile_hash"]),
            image_digest=cast(str | None, data.get("image_digest")),
            container_runtime=parse_container_runtime(str(raw_runtime))
            if raw_runtime is not None
            else None,
            mount_spec=tuple(
                MountSpec.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("mount_spec", ())
            ),
            network_policy=NetworkPolicy.from_dict(
                cast(Mapping[str, Any], data["network_policy"])
            ),
            applied_limits=ResourceLimits.from_dict(
                cast(Mapping[str, Any], data["applied_limits"])
            ),
            backend_guarantees=tuple(str(item) for item in data.get("backend_guarantees", ())),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class SandboxViolation:
    kind: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SandboxViolation:
        return cls(
            kind=str(data["kind"]),
            message=str(data["message"]),
            details=dict(data.get("details", {})),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class SandboxExecutionPlan:
    backend: SandboxBackendKind
    command: SandboxedCommand
    limits: ResourceLimits
    output_transforms: tuple[OutputTransform, ...]
    provenance: SandboxProvenance

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SandboxExecutionPlan:
        return cls(
            backend=parse_sandbox_backend(str(data["backend"])),
            command=SandboxedCommand.from_dict(cast(Mapping[str, Any], data["command"])),
            limits=ResourceLimits.from_dict(cast(Mapping[str, Any], data["limits"])),
            output_transforms=tuple(
                OutputTransform.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("output_transforms", ())
            ),
            provenance=SandboxProvenance.from_dict(
                cast(Mapping[str, Any], data["provenance"])
            ),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ExecutionResult:
    action_type: ActionType
    status: ExecutionStatus
    provider: str
    summary: str
    output: Any = None
    cost: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    sandbox_provenance: SandboxProvenance | None = None
    sandbox_violations: tuple[SandboxViolation, ...] = ()
    normalized_output_hash: str | None = None
    output_transforms: tuple[OutputTransform, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionResult:
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            status=parse_execution_status(str(data["status"])),
            provider=str(data["provider"]),
            summary=str(data["summary"]),
            output=data.get("output"),
            cost=dict(data.get("cost", {})),
            metadata=dict(data.get("metadata", {})),
            sandbox_provenance=SandboxProvenance.from_dict(
                cast(Mapping[str, Any], data["sandbox_provenance"])
            )
            if isinstance(data.get("sandbox_provenance"), Mapping)
            else None,
            sandbox_violations=tuple(
                SandboxViolation.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("sandbox_violations", ())
            ),
            normalized_output_hash=cast(str | None, data.get("normalized_output_hash")),
            output_transforms=tuple(
                OutputTransform.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("output_transforms", ())
            ),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ThreadCandidateAction:
    raw_action: CandidateAction
    final_action: CandidateAction
    certificate: CertificateEvidence | None
    budget_certificate: BudgetCertificate | None
    policy_trace: tuple[PolicyTraceEntry, ...]
    mutation_ledger: tuple[ActionMutation, ...]
    budget_trace: BudgetTrace | None
    short_circuit: str | None
    decision: DecisionType
    reason: str
    admission_score: AdmissionScore | None = None
    admission_trace: AdmissionTrace | None = None
    admission_trace_hash: str | None = None
    effect_vector: EffectVector | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ThreadCandidateAction:
        admission_score = data.get("admission_score")
        admission_trace = data.get("admission_trace")
        effect_vector = data.get("effect_vector")
        certificate = data.get("certificate")
        budget_certificate = data.get("budget_certificate")
        budget_trace = data.get("budget_trace")
        return cls(
            raw_action=CandidateAction.from_dict(cast(Mapping[str, Any], data["raw_action"])),
            final_action=CandidateAction.from_dict(cast(Mapping[str, Any], data["final_action"])),
            certificate=CertificateEvidence.from_dict(cast(Mapping[str, Any], certificate))
            if isinstance(certificate, Mapping)
            else None,
            budget_certificate=budget_certificate_from_dict(
                cast(Mapping[str, Any], budget_certificate)
            )
            if isinstance(budget_certificate, Mapping)
            else None,
            policy_trace=tuple(
                PolicyTraceEntry.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("policy_trace", ())
            ),
            mutation_ledger=tuple(
                ActionMutation.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("mutation_ledger", ())
            ),
            budget_trace=BudgetTrace.from_dict(cast(Mapping[str, Any], budget_trace))
            if isinstance(budget_trace, Mapping)
            else None,
            short_circuit=cast(str | None, data.get("short_circuit")),
            admission_score=AdmissionScore.from_dict(cast(Mapping[str, Any], admission_score))
            if isinstance(admission_score, Mapping)
            else None,
            decision=parse_decision_type(str(data["decision"])),
            reason=str(data["reason"]),
            admission_trace=AdmissionTrace.from_dict(
                cast(Mapping[str, Any], admission_trace)
            )
            if isinstance(admission_trace, Mapping)
            else None,
            admission_trace_hash=cast(str | None, data.get("admission_trace_hash")),
            effect_vector=EffectVector.from_dict(cast(Mapping[str, Any], effect_vector))
            if isinstance(effect_vector, Mapping)
            else None,
        )

    def to_dict(self) -> JsonObject:
        payload = _as_json_object(self)
        if self.admission_trace is None:
            payload.pop("admission_trace", None)
        if self.admission_trace_hash is None:
            payload.pop("admission_trace_hash", None)
        if self.effect_vector is None:
            payload.pop("effect_vector", None)
        return payload


@dataclass(frozen=True)
class EvaluationContext:
    condition_id: str | None = None
    scenario_id: str | None = None
    decision_id: str | None = None
    benchmark_suite: str | None = None
    arm_id: str | None = None
    expected_action: ActionType | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvaluationContext:
        expected_action = data.get("expected_action")
        return cls(
            condition_id=cast(str | None, data.get("condition_id")),
            scenario_id=cast(str | None, data.get("scenario_id")),
            decision_id=cast(str | None, data.get("decision_id")),
            benchmark_suite=cast(str | None, data.get("benchmark_suite")),
            arm_id=cast(str | None, data.get("arm_id")),
            expected_action=parse_action_type(str(expected_action))
            if expected_action is not None
            else None,
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class EvaluationOutcome:
    action_type: ActionType
    completed: bool | None = None
    realized_reward: float | None = None
    expected_reward: float | None = None
    realized_cost: float | None = None
    expected_cost: float | None = None
    information_gain: float | None = None
    content_hash: str | None = None
    memory_unique: bool | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvaluationOutcome:
        return cls(
            action_type=parse_action_type(str(data["action_type"])),
            completed=cast(bool | None, data.get("completed")),
            realized_reward=_optional_float(data.get("realized_reward")),
            expected_reward=_optional_float(data.get("expected_reward")),
            realized_cost=_optional_float(data.get("realized_cost")),
            expected_cost=_optional_float(data.get("expected_cost")),
            information_gain=_optional_float(data.get("information_gain")),
            content_hash=cast(str | None, data.get("content_hash")),
            memory_unique=cast(bool | None, data.get("memory_unique")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ProviderCost:
    provider: str
    reported_cost: float
    billed_cost: float
    currency: str = "USD"
    fixture_id: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProviderCost:
        return cls(
            provider=str(data["provider"]),
            reported_cost=float(data["reported_cost"]),
            billed_cost=float(data["billed_cost"]),
            currency=str(data.get("currency", "USD")),
            fixture_id=cast(str | None, data.get("fixture_id")),
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class ThreadRecord:
    schema_version: str
    thread_id: str
    timestamp: str
    router_version: str
    scorer_version: str
    pricing_policy_name: str
    pricing_policy_version: str
    policy_chain_name: str
    policy_chain_revision: str
    action_registry_version: str
    config_version: str
    seal_seed: int
    seal_id: str
    seal_status: str
    state: Mapping[str, Any]
    host_action: ActionType | None
    raw_candidates: tuple[CandidateAction, ...]
    policy_filtered_candidates: tuple[ThreadCandidateAction, ...]
    scored_candidates: tuple[ThreadCandidateAction, ...]
    selected_action: ActionType | None
    selected_candidate_index: int | None
    rejected_actions: tuple[ThreadCandidateAction, ...]
    budget_state: BudgetState
    sandbox_plan: SandboxExecutionPlan | None = None
    execution_result: ExecutionResult | None = None
    fallback_triggers: tuple[str, ...] = ()
    evaluation_context: EvaluationContext = field(default_factory=EvaluationContext)
    evaluation_outcomes: tuple[EvaluationOutcome, ...] = ()
    provider_costs: tuple[ProviderCost, ...] = ()
    competitor_results: tuple[CompetitorResult, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ThreadRecord:
        raw_selected_action = data.get("selected_action")
        raw_host_action = data.get("host_action")
        execution_result = data.get("execution_result")
        sandbox_plan = data.get("sandbox_plan")
        return cls(
            schema_version=str(data["schema_version"]),
            thread_id=str(data["thread_id"]),
            timestamp=str(data["timestamp"]),
            router_version=str(data["router_version"]),
            scorer_version=str(data["scorer_version"]),
            pricing_policy_name=str(data["pricing_policy_name"]),
            pricing_policy_version=str(data["pricing_policy_version"]),
            policy_chain_name=str(data["policy_chain_name"]),
            policy_chain_revision=str(data["policy_chain_revision"]),
            action_registry_version=str(data["action_registry_version"]),
            config_version=str(data["config_version"]),
            seal_seed=int(data["seal_seed"]),
            seal_id=str(data["seal_id"]),
            seal_status=str(data["seal_status"]),
            state=dict(cast(Mapping[str, Any], data["state"])),
            host_action=parse_action_type(str(raw_host_action))
            if raw_host_action is not None
            else None,
            raw_candidates=tuple(
                CandidateAction.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("raw_candidates", ())
            ),
            policy_filtered_candidates=tuple(
                ThreadCandidateAction.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("policy_filtered_candidates", ())
            ),
            scored_candidates=tuple(
                ThreadCandidateAction.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("scored_candidates", ())
            ),
            selected_action=parse_action_type(str(raw_selected_action))
            if raw_selected_action is not None
            else None,
            selected_candidate_index=cast(int | None, data.get("selected_candidate_index")),
            rejected_actions=tuple(
                ThreadCandidateAction.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("rejected_actions", ())
            ),
            budget_state=BudgetState.from_dict(cast(Mapping[str, Any], data["budget_state"])),
            sandbox_plan=SandboxExecutionPlan.from_dict(
                cast(Mapping[str, Any], sandbox_plan)
            )
            if isinstance(sandbox_plan, Mapping)
            else None,
            execution_result=ExecutionResult.from_dict(cast(Mapping[str, Any], execution_result))
            if isinstance(execution_result, Mapping)
            else None,
            fallback_triggers=tuple(str(item) for item in data.get("fallback_triggers", ())),
            evaluation_context=EvaluationContext.from_dict(
                cast(Mapping[str, Any], data.get("evaluation_context", {}))
            ),
            evaluation_outcomes=tuple(
                EvaluationOutcome.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("evaluation_outcomes", ())
            ),
            provider_costs=tuple(
                ProviderCost.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("provider_costs", ())
            ),
            competitor_results=tuple(
                CompetitorResult.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("competitor_results", ())
            ),
            metadata=dict(data.get("metadata", {})),
        )

    def with_execution_result(self, result: ExecutionResult) -> ThreadRecord:
        return replace(self, execution_result=result, seal_status="execution_recorded")

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class RouteRunResult:
    decision: RoutingDecision
    thread: ThreadRecord
    execution_result: ExecutionResult

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)


@dataclass(frozen=True)
class EvalMetric:
    policy_name: str
    total_tasks: int
    task_success: float
    total_token_spend: float
    total_tool_call_spend: float
    total_dollar_spend: float
    latency: float
    unnecessary_exploration_rate: float
    useful_exploration_rate: float
    unnecessary_clarification_rate: float
    unnecessary_model_escalation_rate: float
    false_memory_write_rate: float
    premature_shutoff_rate: float
    late_stage_over_exploration_rate: float
    thread_interpretability: float
    seal_determinism: float

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvalMetric:
        return cls(
            policy_name=str(data["policy_name"]),
            total_tasks=int(data["total_tasks"]),
            task_success=float(data["task_success"]),
            total_token_spend=float(data["total_token_spend"]),
            total_tool_call_spend=float(data["total_tool_call_spend"]),
            total_dollar_spend=float(data["total_dollar_spend"]),
            latency=float(data["latency"]),
            unnecessary_exploration_rate=float(data["unnecessary_exploration_rate"]),
            useful_exploration_rate=float(data["useful_exploration_rate"]),
            unnecessary_clarification_rate=float(data["unnecessary_clarification_rate"]),
            unnecessary_model_escalation_rate=float(data["unnecessary_model_escalation_rate"]),
            false_memory_write_rate=float(data["false_memory_write_rate"]),
            premature_shutoff_rate=float(data["premature_shutoff_rate"]),
            late_stage_over_exploration_rate=float(data["late_stage_over_exploration_rate"]),
            thread_interpretability=float(data["thread_interpretability"]),
            seal_determinism=float(data["seal_determinism"]),
        )


@dataclass(frozen=True)
class EvalReport:
    metrics: tuple[EvalMetric, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvalReport:
        return cls(
            metrics=tuple(
                EvalMetric.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("metrics", ())
            )
        )

    def to_dict(self) -> JsonObject:
        return _as_json_object(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
