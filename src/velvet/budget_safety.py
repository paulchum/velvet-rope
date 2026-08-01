"""Budget safety helpers for deterministic and probabilistic certificates."""

from __future__ import annotations

import json
import math
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from threading import RLock
from typing import Any

from velvet.types import (
    ActionType,
    BudgetCertificateKind,
    BudgetOutcome,
    BudgetSafetyLedger,
    BudgetScope,
    CandidateAction,
    CandidateSource,
    CapProvenance,
    ConcurrencyModel,
    DeterministicBudgetCertificate,
    ProbabilisticBudgetCertificate,
)

DETERMINISTIC_BUDGET_SCHEMA_VERSION = "budget_safety_deterministic_v1"
PROBABILISTIC_BUDGET_SCHEMA_VERSION = "budget_safety_probabilistic_v1"
DEFAULT_DETERMINISTIC_BUDGET_THEOREM_REFS: tuple[str, ...] = (
    "docs/math/budget_safety_deterministic_theorem.txt",
)
DEFAULT_PROBABILISTIC_BUDGET_THEOREM_REFS: tuple[str, ...] = (
    "docs/math/adaptive_spend_safety_theorem.txt",
)
DEFAULT_DETERMINISTIC_OBLIGATIONS: tuple[str, ...] = (
    "record_realized_cost_after_execution",
    "action_hash_match_required",
    "atomic_commit_required",
    "ledger_sequence_match_required",
)
DEFAULT_PROBABILISTIC_OBLIGATIONS: tuple[str, ...] = (
    "record_realized_cost_after_execution",
    "action_hash_match_required",
    "filtration_hash_match_required",
    "ledger_sequence_match_required",
    "ledger_hash_match_required",
)
DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON = 1e-9
MICROUSD_PER_USD = 1_000_000

_FNV64_OFFSET = 0xCBF29CE484222325
_FNV64_PRIME = 0x100000001B3


@dataclass(frozen=True)
class DeterministicBudgetSpec:
    """Runtime-facing spec for a deterministic hard-cap budget certificate."""

    budget_limit: float
    observed_spend: float
    hard_cap: float
    cap_provenance: CapProvenance | str
    scope: BudgetScope | str
    action_hash: str = ""
    filtration_hash: str = ""
    ledger_sequence_before: int = 0
    concurrency_model: ConcurrencyModel | str = ConcurrencyModel.SINGLE_WRITER_ATOMIC
    obligations: Sequence[str] = DEFAULT_DETERMINISTIC_OBLIGATIONS
    theorem_refs: Sequence[str] = DEFAULT_DETERMINISTIC_BUDGET_THEOREM_REFS
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def certificate(self) -> DeterministicBudgetCertificate:
        return build_deterministic_budget_certificate(
            budget_limit=self.budget_limit,
            observed_spend=self.observed_spend,
            hard_cap=self.hard_cap,
            cap_provenance=self.cap_provenance,
            scope=self.scope,
            concurrency_model=self.concurrency_model,
            action_hash=self.action_hash,
            filtration_hash=self.filtration_hash,
            ledger_sequence_before=self.ledger_sequence_before,
            obligations=self.obligations,
            theorem_refs=self.theorem_refs,
        )

    def candidate(
        self,
        action_type: ActionType | str,
        *,
        description: str = "",
        cost_overrides: Mapping[str, float] | None = None,
        risk_overrides: Mapping[str, float] | None = None,
        parameters: Mapping[str, Any] | None = None,
        source: CandidateSource = CandidateSource.SCENARIO,
        metadata: Mapping[str, Any] | None = None,
    ) -> CandidateAction:
        merged_metadata = {
            "budget_safety_engine": DETERMINISTIC_BUDGET_SCHEMA_VERSION,
            "budget_affecting": True,
            **dict(self.metadata),
            **dict(metadata or {}),
        }
        unsigned = CandidateAction(
            ActionType(str(action_type)),
            description=description,
            cost_overrides=dict(cost_overrides or {}),
            risk_overrides=dict(risk_overrides or {}),
            metadata=merged_metadata,
            source=source,
            parameters=dict(parameters or {}),
        )
        certificate = replace(self, action_hash=budget_action_hash(unsigned)).certificate()
        return replace(unsigned, budget_certificate=certificate)


@dataclass(frozen=True)
class ProbabilisticBudgetSpec:
    """Runtime-facing spec for high-probability adaptive spend certificates."""

    budget_limit: float
    delta_total: float
    observed_spend: float
    scope: BudgetScope | str
    certificate_kind: BudgetCertificateKind | str
    cost_model_id: str
    action_hash: str = ""
    filtration_hash: str = ""
    ledger_sequence_before: int = 0
    certified_mean_sum: float = 0.0
    cgf_sum_by_lambda: Mapping[str, float] = field(default_factory=dict)
    lambda_grid: Sequence[float] = ()
    mixture_weights: Sequence[float] = ()
    hard_cap: float | None = None
    mean_upper: float | None = None
    variance_upper: float | None = None
    second_moment_upper: float | None = None
    obligations: Sequence[str] = DEFAULT_PROBABILISTIC_OBLIGATIONS
    theorem_refs: Sequence[str] = DEFAULT_PROBABILISTIC_BUDGET_THEOREM_REFS
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def certificate(self) -> ProbabilisticBudgetCertificate:
        kind = parse_budget_certificate_kind(self.certificate_kind)
        if kind == BudgetCertificateKind.CGF_VILLE:
            return build_cgf_ville_budget_certificate(
                budget_limit=self.budget_limit,
                delta_total=self.delta_total,
                observed_spend=self.observed_spend,
                certified_mean_sum=self.certified_mean_sum,
                cgf_sum_by_lambda=self.cgf_sum_by_lambda,
                lambda_grid=self.lambda_grid,
                mixture_weights=self.mixture_weights,
                scope=self.scope,
                action_hash=self.action_hash,
                filtration_hash=self.filtration_hash,
                ledger_sequence_before=self.ledger_sequence_before,
                cost_model_id=self.cost_model_id,
                hard_cap=self.hard_cap,
                obligations=self.obligations,
                theorem_refs=self.theorem_refs,
            )
        if kind == BudgetCertificateKind.MOMENT_CANTELLI:
            return build_moment_cantelli_budget_certificate(
                budget_limit=self.budget_limit,
                delta_total=self.delta_total,
                observed_spend=self.observed_spend,
                mean_upper=0.0 if self.mean_upper is None else self.mean_upper,
                scope=self.scope,
                action_hash=self.action_hash,
                filtration_hash=self.filtration_hash,
                ledger_sequence_before=self.ledger_sequence_before,
                cost_model_id=self.cost_model_id,
                variance_upper=self.variance_upper,
                second_moment_upper=self.second_moment_upper,
                hard_cap=self.hard_cap,
                obligations=self.obligations,
                theorem_refs=self.theorem_refs,
            )
        raise ValueError("probabilistic budget spec requires cgf_ville or moment_cantelli")

    def candidate(
        self,
        action_type: ActionType | str,
        *,
        description: str = "",
        cost_overrides: Mapping[str, float] | None = None,
        risk_overrides: Mapping[str, float] | None = None,
        parameters: Mapping[str, Any] | None = None,
        source: CandidateSource = CandidateSource.SCENARIO,
        metadata: Mapping[str, Any] | None = None,
    ) -> CandidateAction:
        merged_metadata = {
            "budget_safety_engine": PROBABILISTIC_BUDGET_SCHEMA_VERSION,
            "budget_affecting": True,
            **dict(self.metadata),
            **dict(metadata or {}),
        }
        unsigned = CandidateAction(
            ActionType(str(action_type)),
            description=description,
            cost_overrides=dict(cost_overrides or {}),
            risk_overrides=dict(risk_overrides or {}),
            metadata=merged_metadata,
            source=source,
            parameters=dict(parameters or {}),
        )
        certificate = replace(self, action_hash=budget_action_hash(unsigned)).certificate()
        return replace(unsigned, budget_certificate=certificate)


class BudgetSafetyLedgerStore:
    """Single-process CAS helper for deterministic budget certificate tests and demos."""

    def __init__(self, ledger: BudgetSafetyLedger) -> None:
        self._ledger = with_recomputed_ledger_hash(ledger)
        self._lock = RLock()
        self._fail_closed_reason: str | None = None

    @property
    def fail_closed_reason(self) -> str | None:
        return self._fail_closed_reason

    def snapshot(self) -> BudgetSafetyLedger:
        with self._lock:
            if self._fail_closed_reason is not None:
                raise RuntimeError(self._fail_closed_reason)
            return self._ledger

    def record_missing_realized_cost(self) -> None:
        with self._lock:
            self._fail_closed_reason = (
                "missing realized cost observation; budget ledger is fail-closed"
            )

    def commit_authorized_realized_cost(
        self,
        certificate: DeterministicBudgetCertificate,
        *,
        realized_microusd: int | None,
    ) -> bool:
        """Commit realized spend through the authority-bearing microusd path."""

        with self._lock:
            if realized_microusd is None:
                self.record_missing_realized_cost()
                return False
            if self._fail_closed_reason is not None:
                return False
            if isinstance(realized_microusd, bool) or int(realized_microusd) < 0:
                self.record_missing_realized_cost()
                return False
            realized_microusd = int(realized_microusd)
            if not is_certifying(certificate):
                return False
            if certificate.scope != self._ledger.scope:
                return False
            if certificate.budget_limit_microusd != self._ledger.budget_limit_microusd:
                return False
            if certificate.observed_spend_microusd != self._ledger.observed_spend_microusd:
                return False
            if certificate.ledger_sequence_before != self._ledger.ledger_sequence:
                return False
            if certificate.hard_cap_microusd is None:
                return False
            if realized_microusd > certificate.hard_cap_microusd:
                return False
            next_spend = self._ledger.observed_spend_microusd + realized_microusd
            if next_spend > self._ledger.budget_limit_microusd:
                return False
            self._ledger = with_recomputed_ledger_hash(
                replace(
                    self._ledger,
                    observed_spend_usd=microusd_to_usd_display(next_spend),
                    observed_spend_microusd=next_spend,
                    ledger_sequence=self._ledger.ledger_sequence + 1,
                )
            )
            return True

    def commit_probabilistic_authorized_realized_cost(
        self,
        certificate: ProbabilisticBudgetCertificate,
        *,
        realized_microusd: int | None,
    ) -> bool:
        """Record realized spend authorized by a probabilistic certificate."""

        with self._lock:
            if realized_microusd is None:
                self.record_missing_realized_cost()
                return False
            if self._fail_closed_reason is not None:
                return False
            if isinstance(realized_microusd, bool) or int(realized_microusd) < 0:
                self.record_missing_realized_cost()
                return False
            if not is_probabilistic_certifying(certificate):
                return False
            if certificate.scope != self._ledger.scope:
                return False
            if certificate.budget_limit_microusd != self._ledger.budget_limit_microusd:
                return False
            if certificate.observed_spend_microusd != self._ledger.observed_spend_microusd:
                return False
            if certificate.ledger_sequence_before != self._ledger.ledger_sequence:
                return False
            if certificate.pre_ledger_hash != self._ledger.ledger_hash:
                return False
            next_spend = self._ledger.observed_spend_microusd + int(realized_microusd)
            self._ledger = with_recomputed_ledger_hash(
                replace(
                    self._ledger,
                    observed_spend_usd=microusd_to_usd_display(next_spend),
                    observed_spend_microusd=next_spend,
                    ledger_sequence=self._ledger.ledger_sequence + 1,
                )
            )
            return True

    def try_commit(
        self,
        certificate: DeterministicBudgetCertificate,
        *,
        realized_usd: float | None,
    ) -> bool:
        """Backward-compatible USD wrapper requiring exact microusd conversion."""

        if realized_usd is None:
            return self.commit_authorized_realized_cost(
                certificate,
                realized_microusd=None,
            )
        try:
            realized_microusd = usd_to_microusd_exact_or_reject(
                "realized_usd",
                realized_usd,
            )
        except ValueError:
            self.record_missing_realized_cost()
            return False
        return self.commit_authorized_realized_cost(
            certificate,
            realized_microusd=realized_microusd,
        )


def build_deterministic_budget_certificate(
    *,
    budget_limit: float,
    observed_spend: float,
    hard_cap: float,
    cap_provenance: CapProvenance | str,
    scope: BudgetScope | str,
    concurrency_model: ConcurrencyModel | str = ConcurrencyModel.SINGLE_WRITER_ATOMIC,
    action_hash: str,
    filtration_hash: str,
    ledger_sequence_before: int,
    obligations: Sequence[str] = DEFAULT_DETERMINISTIC_OBLIGATIONS,
    theorem_refs: Sequence[str] = DEFAULT_DETERMINISTIC_BUDGET_THEOREM_REFS,
) -> DeterministicBudgetCertificate:
    _require_non_negative_finite("budget_limit", budget_limit)
    _require_non_negative_finite("observed_spend", observed_spend)
    _require_non_negative_finite("hard_cap", hard_cap)
    if ledger_sequence_before < 0:
        raise ValueError("ledger_sequence_before must be non-negative")

    scope_value = parse_budget_scope(scope)
    provenance_value = parse_cap_provenance(cap_provenance)
    concurrency_value = parse_concurrency_model(concurrency_model)
    budget_limit_microusd = usd_to_microusd_exact_or_reject(
        "budget_limit",
        float(budget_limit),
    )
    observed_spend_microusd = usd_to_microusd_exact_or_reject(
        "observed_spend",
        float(observed_spend),
    )
    hard_cap_microusd = usd_to_microusd_exact_or_reject("hard_cap", float(hard_cap))
    projected_microusd = observed_spend_microusd + hard_cap_microusd
    slack_microusd = budget_limit_microusd - projected_microusd
    outcome = (
        BudgetOutcome.ADMIT
        if projected_microusd <= budget_limit_microusd
        else BudgetOutcome.BLOCK
    )
    return DeterministicBudgetCertificate(
        schema_version=DETERMINISTIC_BUDGET_SCHEMA_VERSION,
        certificate_kind=BudgetCertificateKind.DETERMINISTIC_HARD_CAP,
        scope=scope_value,
        budget_limit_usd=microusd_to_usd_display(budget_limit_microusd),
        observed_spend_usd=microusd_to_usd_display(observed_spend_microusd),
        hard_cap_usd=microusd_to_usd_display(hard_cap_microusd),
        cap_provenance=provenance_value,
        concurrency_model=concurrency_value,
        action_hash=str(action_hash),
        filtration_hash=str(filtration_hash),
        ledger_sequence_before=int(ledger_sequence_before),
        projected_spend_usd=microusd_to_usd_display(projected_microusd),
        slack_usd=slack_microusd_to_usd_display(slack_microusd),
        outcome=outcome,
        obligations=tuple(str(item) for item in obligations),
        theorem_refs=tuple(str(item) for item in theorem_refs),
        budget_limit_microusd=budget_limit_microusd,
        observed_spend_microusd=observed_spend_microusd,
        hard_cap_microusd=hard_cap_microusd,
        projected_spend_microusd=projected_microusd,
        slack_microusd=slack_microusd,
    )


def build_cgf_ville_budget_certificate(
    *,
    budget_limit: float,
    delta_total: float,
    observed_spend: float,
    certified_mean_sum: float,
    cgf_sum_by_lambda: Mapping[str, float],
    lambda_grid: Sequence[float],
    mixture_weights: Sequence[float],
    scope: BudgetScope | str,
    action_hash: str,
    filtration_hash: str,
    ledger_sequence_before: int,
    cost_model_id: str,
    hard_cap: float | None = None,
    obligations: Sequence[str] = DEFAULT_PROBABILISTIC_OBLIGATIONS,
    theorem_refs: Sequence[str] = DEFAULT_PROBABILISTIC_BUDGET_THEOREM_REFS,
) -> ProbabilisticBudgetCertificate:
    bound = cgf_ville_high_probability_bound(
        observed_spend=observed_spend,
        certified_mean_sum=certified_mean_sum,
        cgf_sum_by_lambda=cgf_sum_by_lambda,
        lambda_grid=lambda_grid,
        mixture_weights=mixture_weights,
        delta_total=delta_total,
    )
    return _build_probabilistic_budget_certificate(
        certificate_kind=BudgetCertificateKind.CGF_VILLE,
        budget_limit=budget_limit,
        delta_total=delta_total,
        observed_spend=observed_spend,
        certified_mean_sum=certified_mean_sum,
        cgf_sum_by_lambda=cgf_sum_by_lambda,
        lambda_grid=lambda_grid,
        mixture_weights=mixture_weights,
        hard_cap=hard_cap,
        mean_upper=None,
        variance_upper=None,
        second_moment_upper=None,
        high_probability_bound=bound,
        scope=scope,
        action_hash=action_hash,
        filtration_hash=filtration_hash,
        ledger_sequence_before=ledger_sequence_before,
        cost_model_id=cost_model_id,
        obligations=obligations,
        theorem_refs=theorem_refs,
    )


def build_moment_cantelli_budget_certificate(
    *,
    budget_limit: float,
    delta_total: float,
    observed_spend: float,
    mean_upper: float,
    scope: BudgetScope | str,
    action_hash: str,
    filtration_hash: str,
    ledger_sequence_before: int,
    cost_model_id: str,
    variance_upper: float | None = None,
    second_moment_upper: float | None = None,
    hard_cap: float | None = None,
    obligations: Sequence[str] = DEFAULT_PROBABILISTIC_OBLIGATIONS,
    theorem_refs: Sequence[str] = DEFAULT_PROBABILISTIC_BUDGET_THEOREM_REFS,
) -> ProbabilisticBudgetCertificate:
    bound = moment_cantelli_high_probability_bound(
        observed_spend=observed_spend,
        mean_upper=mean_upper,
        variance_upper=variance_upper,
        second_moment_upper=second_moment_upper,
        delta_total=delta_total,
    )
    return _build_probabilistic_budget_certificate(
        certificate_kind=BudgetCertificateKind.MOMENT_CANTELLI,
        budget_limit=budget_limit,
        delta_total=delta_total,
        observed_spend=observed_spend,
        certified_mean_sum=0.0,
        cgf_sum_by_lambda={},
        lambda_grid=(),
        mixture_weights=(),
        hard_cap=hard_cap,
        mean_upper=mean_upper,
        variance_upper=variance_upper,
        second_moment_upper=second_moment_upper,
        high_probability_bound=bound,
        scope=scope,
        action_hash=action_hash,
        filtration_hash=filtration_hash,
        ledger_sequence_before=ledger_sequence_before,
        cost_model_id=cost_model_id,
        obligations=obligations,
        theorem_refs=theorem_refs,
    )


def cgf_ville_high_probability_bound(
    *,
    observed_spend: float,
    certified_mean_sum: float,
    cgf_sum_by_lambda: Mapping[str, float],
    lambda_grid: Sequence[float],
    mixture_weights: Sequence[float],
    delta_total: float,
) -> float:
    _require_probability_delta(delta_total)
    _require_non_negative_finite("observed_spend", observed_spend)
    _require_non_negative_finite("certified_mean_sum", certified_mean_sum)
    if not lambda_grid:
        raise ValueError("lambda_grid must be non-empty")
    if len(lambda_grid) != len(mixture_weights):
        raise ValueError("lambda_grid and mixture_weights must have the same length")
    best_margin = math.inf
    total_weight = 0.0
    for lambda_value, weight in zip(lambda_grid, mixture_weights, strict=True):
        if not math.isfinite(float(lambda_value)) or float(lambda_value) <= 0.0:
            raise ValueError("lambda_grid values must be positive finite values")
        if not math.isfinite(float(weight)) or float(weight) <= 0.0:
            raise ValueError("mixture_weights values must be positive finite values")
        total_weight += float(weight)
        psi = _cgf_sum_for_lambda(cgf_sum_by_lambda, float(lambda_value))
        margin = (psi + math.log(1.0 / (float(delta_total) * float(weight)))) / float(
            lambda_value
        )
        if not math.isfinite(margin):
            raise ValueError("CGF/Ville high-probability envelope is non-finite")
        best_margin = min(best_margin, margin)
    if total_weight > 1.0 + DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON:
        raise ValueError("mixture_weights must sum to at most 1")
    return float(observed_spend) + float(certified_mean_sum) + best_margin


def moment_cantelli_high_probability_bound(
    *,
    observed_spend: float,
    mean_upper: float,
    delta_total: float,
    variance_upper: float | None = None,
    second_moment_upper: float | None = None,
) -> float:
    _require_probability_delta(delta_total)
    _require_non_negative_finite("observed_spend", observed_spend)
    _require_non_negative_finite("mean_upper", mean_upper)
    scale_square = variance_upper if variance_upper is not None else second_moment_upper
    if scale_square is None:
        raise ValueError("variance_upper or second_moment_upper is required")
    _require_non_negative_finite("variance_upper/second_moment_upper", scale_square)
    return (
        float(observed_spend)
        + float(mean_upper)
        + math.sqrt((1.0 - float(delta_total)) / float(delta_total))
        * math.sqrt(float(scale_square))
    )


def _build_probabilistic_budget_certificate(
    *,
    certificate_kind: BudgetCertificateKind,
    budget_limit: float,
    delta_total: float,
    observed_spend: float,
    certified_mean_sum: float,
    cgf_sum_by_lambda: Mapping[str, float],
    lambda_grid: Sequence[float],
    mixture_weights: Sequence[float],
    hard_cap: float | None,
    mean_upper: float | None,
    variance_upper: float | None,
    second_moment_upper: float | None,
    high_probability_bound: float,
    scope: BudgetScope | str,
    action_hash: str,
    filtration_hash: str,
    ledger_sequence_before: int,
    cost_model_id: str,
    obligations: Sequence[str],
    theorem_refs: Sequence[str],
) -> ProbabilisticBudgetCertificate:
    if ledger_sequence_before < 0:
        raise ValueError("ledger_sequence_before must be non-negative")
    if not str(cost_model_id).strip():
        raise ValueError("cost_model_id must be non-empty")
    _require_probability_delta(delta_total)
    scope_value = parse_budget_scope(scope)
    budget_limit_microusd = usd_to_microusd_exact_or_reject("budget_limit", budget_limit)
    observed_spend_microusd = usd_to_microusd_exact_or_reject(
        "observed_spend",
        observed_spend,
    )
    high_probability_bound_microusd = usd_to_microusd_ceil_or_reject(
        "high_probability_bound",
        high_probability_bound,
    )
    slack_microusd = budget_limit_microusd - high_probability_bound_microusd
    outcome = (
        BudgetOutcome.ADMIT
        if high_probability_bound_microusd <= budget_limit_microusd
        else BudgetOutcome.BLOCK
    )
    pre_ledger_hash = budget_ledger_hash(
        BudgetSafetyLedger(
            scope=scope_value,
            budget_limit_usd=microusd_to_usd_display(budget_limit_microusd),
            budget_limit_microusd=budget_limit_microusd,
            observed_spend_usd=microusd_to_usd_display(observed_spend_microusd),
            observed_spend_microusd=observed_spend_microusd,
            ledger_hash="",
            ledger_sequence=int(ledger_sequence_before),
        )
    )
    return ProbabilisticBudgetCertificate(
        schema_version=PROBABILISTIC_BUDGET_SCHEMA_VERSION,
        certificate_kind=certificate_kind,
        scope=scope_value,
        budget_limit=microusd_to_usd_display(budget_limit_microusd),
        delta_total=float(delta_total),
        observed_spend=microusd_to_usd_display(observed_spend_microusd),
        certified_mean_sum=float(certified_mean_sum),
        cgf_sum_by_lambda={
            str(key): float(value) for key, value in cgf_sum_by_lambda.items()
        },
        lambda_grid=tuple(float(item) for item in lambda_grid),
        mixture_weights=tuple(float(item) for item in mixture_weights),
        hard_cap=hard_cap,
        mean_upper=mean_upper,
        variance_upper=variance_upper,
        second_moment_upper=second_moment_upper,
        action_hash=str(action_hash),
        filtration_hash=str(filtration_hash),
        ledger_sequence_before=int(ledger_sequence_before),
        pre_ledger_hash=pre_ledger_hash,
        cost_model_id=str(cost_model_id),
        high_probability_bound=float(high_probability_bound),
        slack=slack_microusd_to_usd_display(slack_microusd),
        outcome=outcome,
        obligations=tuple(str(item) for item in obligations),
        theorem_refs=tuple(str(item) for item in theorem_refs),
        budget_limit_microusd=budget_limit_microusd,
        observed_spend_microusd=observed_spend_microusd,
        high_probability_bound_microusd=high_probability_bound_microusd,
        slack_microusd=slack_microusd,
    )


def is_certifying(
    certificate: DeterministicBudgetCertificate | ProbabilisticBudgetCertificate,
) -> bool:
    """Return whether a budget certificate can authorize spend.

    The deterministic branch stays in sync with
    `DeterministicBudgetCertificate::is_certifying` in
    `crates/velvet-core/src/types.rs`.
    """

    if isinstance(certificate, ProbabilisticBudgetCertificate):
        return is_probabilistic_certifying(certificate)
    provenance = _coerce_cap_provenance(certificate.cap_provenance)
    concurrency = _coerce_concurrency_model(certificate.concurrency_model)
    outcome = _coerce_budget_outcome(certificate.outcome)
    return (
        _budget_certificate_structural_validation_error(certificate) is None
        and provenance
        in {
            CapProvenance.PROVIDER_ENFORCED,
            CapProvenance.PREPAID_RESERVATION,
            CapProvenance.ENFORCED_TOKEN_CAP,
        }
        and concurrency == ConcurrencyModel.SINGLE_WRITER_ATOMIC
        and outcome == BudgetOutcome.ADMIT
    )


def is_probabilistic_certifying(certificate: ProbabilisticBudgetCertificate) -> bool:
    return (
        _probabilistic_certificate_structural_validation_error(certificate) is None
        and _coerce_budget_outcome(certificate.outcome) == BudgetOutcome.ADMIT
    )


def budget_action_hash(candidate: CandidateAction) -> str:
    metadata = {
        key: value
        for key, value in dict(candidate.metadata).items()
        if key not in {"budget_certificate", "certificate"}
    }
    material = OrderedDict(
        (
            ("action_type", candidate.action_type.value),
            ("description", candidate.description),
            ("cost_overrides", _json_safe_sorted(dict(candidate.cost_overrides))),
            ("metadata", _json_safe_sorted(metadata)),
            ("parameters", _json_safe_sorted(dict(candidate.parameters))),
            ("risk_overrides", _json_safe_sorted(dict(candidate.risk_overrides))),
        )
    )
    return _stable_hash_json(material)


def filtration_hash_for_state(state: Mapping[str, Any]) -> str:
    for key in ("budget_filtration_hash", "filtration_hash"):
        value = state.get(key)
        if isinstance(value, str):
            return value
    policy_context = state.get("policy_context")
    if isinstance(policy_context, Mapping):
        external = policy_context.get("external_observations")
        if isinstance(external, Mapping):
            for key in ("budget_filtration_hash", "filtration_hash"):
                value = external.get(key)
                if isinstance(value, str):
                    return value
        prior_thread = policy_context.get("prior_thread", ())
    else:
        prior_thread = ()
    return _stable_hash_json(_json_safe_sorted(prior_thread))


def make_budget_ledger(
    *,
    scope: BudgetScope | str,
    budget_limit: float,
    observed_spend: float = 0.0,
    ledger_sequence: int = 0,
) -> BudgetSafetyLedger:
    budget_limit_microusd = usd_to_microusd_exact_or_reject("budget_limit", budget_limit)
    observed_spend_microusd = usd_to_microusd_exact_or_reject(
        "observed_spend",
        observed_spend,
    )
    ledger = BudgetSafetyLedger(
        scope=parse_budget_scope(scope),
        budget_limit_usd=microusd_to_usd_display(budget_limit_microusd),
        budget_limit_microusd=budget_limit_microusd,
        observed_spend_usd=microusd_to_usd_display(observed_spend_microusd),
        observed_spend_microusd=observed_spend_microusd,
        ledger_hash="",
        ledger_sequence=int(ledger_sequence),
    )
    return with_recomputed_ledger_hash(ledger)


def with_recomputed_ledger_hash(ledger: BudgetSafetyLedger) -> BudgetSafetyLedger:
    return replace(ledger, ledger_hash=budget_ledger_hash(ledger))


def budget_ledger_hash(ledger: BudgetSafetyLedger) -> str:
    material = OrderedDict(
        (
            ("scope", ledger.scope.value),
            ("budget_limit_microusd", ledger.budget_limit_microusd),
            ("observed_spend_microusd", ledger.observed_spend_microusd),
            ("ledger_sequence", ledger.ledger_sequence),
        )
    )
    return _stable_hash_json(material)


def microusd_to_usd_display(value: int) -> float:
    return int(value) / MICROUSD_PER_USD


def slack_microusd_to_usd_display(value: int) -> float:
    return int(value) / MICROUSD_PER_USD


def usd_to_microusd_exact_or_reject(name: str, value: float) -> int:
    parsed = float(value)
    _require_non_negative_finite(name, parsed)
    scaled = parsed * MICROUSD_PER_USD
    rounded = round(scaled)
    if abs(scaled - rounded) > DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON:
        raise ValueError(f"{name} is not exactly representable in microusd")
    if rounded < 0:
        raise ValueError(f"{name} must be non-negative")
    return int(rounded)


def usd_to_microusd_ceil_or_reject(name: str, value: float) -> int:
    parsed = float(value)
    _require_non_negative_finite(name, parsed)
    scaled = parsed * MICROUSD_PER_USD
    ceiled = math.ceil(scaled - DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON)
    if ceiled < 0:
        raise ValueError(f"{name} must be non-negative")
    return int(ceiled)


def conservative_utf8_token_upper_bound(text: str) -> int:
    return len(text.encode("utf-8"))


def openai_responses_hard_cap_usd(
    *,
    input_text: str,
    max_output_tokens: int,
    input_usd_per_million_tokens: float,
    output_usd_per_million_tokens: float,
) -> float:
    if max_output_tokens < 0:
        raise ValueError("max_output_tokens must be non-negative")
    _require_non_negative_finite("input_usd_per_million_tokens", input_usd_per_million_tokens)
    _require_non_negative_finite("output_usd_per_million_tokens", output_usd_per_million_tokens)
    input_tokens = conservative_utf8_token_upper_bound(input_text)
    return (
        input_tokens * float(input_usd_per_million_tokens)
        + int(max_output_tokens) * float(output_usd_per_million_tokens)
    ) / 1_000_000.0


def openai_responses_realized_cost_usd(
    response: Mapping[str, Any],
    *,
    input_usd_per_million_tokens: float,
    output_usd_per_million_tokens: float,
) -> float | None:
    usage = response.get("usage")
    if not isinstance(usage, Mapping):
        return None
    input_tokens = _usage_int(usage, "input_tokens")
    output_tokens = _usage_int(usage, "output_tokens")
    if input_tokens is None or output_tokens is None:
        return None
    return (
        input_tokens * float(input_usd_per_million_tokens)
        + output_tokens * float(output_usd_per_million_tokens)
    ) / 1_000_000.0


def parse_budget_scope(value: BudgetScope | str) -> BudgetScope:
    return value if isinstance(value, BudgetScope) else BudgetScope(str(value))


def parse_cap_provenance(value: CapProvenance | str) -> CapProvenance:
    return value if isinstance(value, CapProvenance) else CapProvenance(str(value))


def parse_concurrency_model(value: ConcurrencyModel | str) -> ConcurrencyModel:
    return value if isinstance(value, ConcurrencyModel) else ConcurrencyModel(str(value))


def parse_budget_certificate_kind(
    value: BudgetCertificateKind | str,
) -> BudgetCertificateKind:
    return (
        value
        if isinstance(value, BudgetCertificateKind)
        else BudgetCertificateKind(str(value))
    )


def _usage_int(usage: Mapping[str, Any], key: str) -> int | None:
    value = usage.get(key)
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _require_non_negative_finite(name: str, value: float) -> None:
    if not math.isfinite(float(value)) or float(value) < 0.0:
        raise ValueError(f"{name} must be a non-negative finite value")


def _require_probability_delta(value: float) -> None:
    if not math.isfinite(float(value)) or not (0.0 < float(value) < 1.0):
        raise ValueError("delta_total must be in (0, 1)")


def _cgf_sum_for_lambda(
    cgf_sum_by_lambda: Mapping[str, float],
    lambda_value: float,
) -> float:
    for key, value in cgf_sum_by_lambda.items():
        try:
            parsed_key = float(key)
        except ValueError:
            continue
        if abs(parsed_key - lambda_value) <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON:
            parsed_value = float(value)
            if not math.isfinite(parsed_value):
                raise ValueError("cgf_sum_by_lambda values must be finite")
            return parsed_value
    raise ValueError("cgf_sum_by_lambda is missing a lambda_grid entry")


def _required_authority_int(
    value: int | None,
    label: str,
    *,
    non_negative: bool,
) -> int | str:
    if value is None:
        return f"deterministic budget certificate is missing {label}"
    if isinstance(value, bool):
        return f"deterministic budget certificate has invalid {label}"
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return f"deterministic budget certificate has invalid {label}"
    if non_negative and parsed < 0:
        return f"deterministic budget certificate has negative {label}"
    return parsed


def _usd_display_matches_microusd(display_usd: float, authority_microusd: int) -> bool:
    return (
        math.isfinite(display_usd)
        and display_usd >= 0.0
        and abs(display_usd - microusd_to_usd_display(authority_microusd))
        <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
    )


def _usd_display_matches_slack(display_usd: float, authority_microusd: int) -> bool:
    return (
        math.isfinite(display_usd)
        and abs(display_usd - slack_microusd_to_usd_display(authority_microusd))
        <= DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
    )


def _budget_certificate_structural_validation_error(
    certificate: DeterministicBudgetCertificate,
) -> str | None:
    if certificate.schema_version != DETERMINISTIC_BUDGET_SCHEMA_VERSION:
        return "unsupported deterministic budget certificate schema_version"
    if (
        certificate.certificate_kind
        != BudgetCertificateKind.DETERMINISTIC_HARD_CAP
    ):
        return "deterministic budget certificate_kind must be deterministic_hard_cap"
    numeric_fields = (
        ("budget_limit_usd", certificate.budget_limit_usd),
        ("observed_spend_usd", certificate.observed_spend_usd),
        ("hard_cap_usd", certificate.hard_cap_usd),
        ("projected_spend_usd", certificate.projected_spend_usd),
        ("slack_usd", certificate.slack_usd),
    )
    try:
        parsed_fields = tuple((label, float(value)) for label, value in numeric_fields)
    except (TypeError, ValueError):
        return "deterministic budget certificate has a non-numeric value"
    for label, value in parsed_fields:
        if not math.isfinite(value):
            return f"deterministic budget certificate has a non-finite {label} value"
    for label, value in parsed_fields[:3]:
        if value < 0.0:
            return f"deterministic budget certificate has a negative {label} value"
    try:
        ledger_sequence_before = int(certificate.ledger_sequence_before)
    except (TypeError, ValueError):
        return "deterministic budget certificate has a non-integer ledger_sequence_before"
    if ledger_sequence_before < 0:
        return "deterministic budget certificate has a negative ledger_sequence_before"

    budget_limit_microusd = _required_authority_int(
        certificate.budget_limit_microusd,
        "budget_limit_microusd",
        non_negative=True,
    )
    if isinstance(budget_limit_microusd, str):
        return budget_limit_microusd
    observed_spend_microusd = _required_authority_int(
        certificate.observed_spend_microusd,
        "observed_spend_microusd",
        non_negative=True,
    )
    if isinstance(observed_spend_microusd, str):
        return observed_spend_microusd
    hard_cap_microusd = _required_authority_int(
        certificate.hard_cap_microusd,
        "hard_cap_microusd",
        non_negative=True,
    )
    if isinstance(hard_cap_microusd, str):
        return hard_cap_microusd
    projected_spend_microusd = _required_authority_int(
        certificate.projected_spend_microusd,
        "projected_spend_microusd",
        non_negative=True,
    )
    if isinstance(projected_spend_microusd, str):
        return projected_spend_microusd
    slack_microusd = _required_authority_int(
        certificate.slack_microusd,
        "slack_microusd",
        non_negative=False,
    )
    if isinstance(slack_microusd, str):
        return slack_microusd

    if (
        not _usd_display_matches_microusd(parsed_fields[0][1], budget_limit_microusd)
        or not _usd_display_matches_microusd(parsed_fields[1][1], observed_spend_microusd)
        or not _usd_display_matches_microusd(parsed_fields[2][1], hard_cap_microusd)
        or not _usd_display_matches_microusd(parsed_fields[3][1], projected_spend_microusd)
        or not _usd_display_matches_slack(parsed_fields[4][1], slack_microusd)
    ):
        return (
            "deterministic budget certificate USD display fields do not match "
            "microusd authority fields"
        )

    projected = observed_spend_microusd + hard_cap_microusd
    if projected_spend_microusd != projected:
        return "deterministic budget certificate projected_spend_microusd does not recompute"
    expected_slack = budget_limit_microusd - projected
    if slack_microusd != expected_slack:
        return "deterministic budget certificate slack_microusd does not recompute"
    expected_outcome = (
        BudgetOutcome.ADMIT
        if projected <= budget_limit_microusd
        else BudgetOutcome.BLOCK
    )
    if _coerce_budget_outcome(certificate.outcome) != expected_outcome:
        return "deterministic budget certificate outcome does not match hard-cap rule"
    try:
        obligations = {str(item) for item in certificate.obligations}
    except TypeError:
        return "deterministic budget certificate has invalid obligations"
    if not set(DEFAULT_DETERMINISTIC_OBLIGATIONS).issubset(obligations):
        return "deterministic budget certificate is missing mandatory obligations"
    return None


def _probabilistic_certificate_structural_validation_error(
    certificate: ProbabilisticBudgetCertificate,
) -> str | None:
    if certificate.schema_version != PROBABILISTIC_BUDGET_SCHEMA_VERSION:
        return "unsupported probabilistic budget certificate schema_version"
    kind = parse_budget_certificate_kind(certificate.certificate_kind)
    if kind not in {
        BudgetCertificateKind.CGF_VILLE,
        BudgetCertificateKind.MOMENT_CANTELLI,
    }:
        return "probabilistic budget certificate_kind must be cgf_ville or moment_cantelli"
    try:
        _require_probability_delta(certificate.delta_total)
        _require_non_negative_finite("budget_limit", certificate.budget_limit)
        _require_non_negative_finite("observed_spend", certificate.observed_spend)
        _require_non_negative_finite(
            "high_probability_bound",
            certificate.high_probability_bound,
        )
    except ValueError as error:
        return str(error)
    if not str(certificate.cost_model_id).strip():
        return "probabilistic budget certificate requires cost_model_id"
    if kind == BudgetCertificateKind.CGF_VILLE:
        try:
            recomputed = cgf_ville_high_probability_bound(
                observed_spend=certificate.observed_spend,
                certified_mean_sum=certificate.certified_mean_sum,
                cgf_sum_by_lambda=certificate.cgf_sum_by_lambda,
                lambda_grid=certificate.lambda_grid,
                mixture_weights=certificate.mixture_weights,
                delta_total=certificate.delta_total,
            )
        except ValueError as error:
            return str(error)
    else:
        try:
            recomputed = moment_cantelli_high_probability_bound(
                observed_spend=certificate.observed_spend,
                mean_upper=certificate.mean_upper
                if certificate.mean_upper is not None
                else math.nan,
                variance_upper=certificate.variance_upper,
                second_moment_upper=certificate.second_moment_upper,
                delta_total=certificate.delta_total,
            )
        except ValueError as error:
            return str(error)
    if (
        abs(recomputed - certificate.high_probability_bound)
        > DETERMINISTIC_BUDGET_CERTIFICATE_EPSILON
    ):
        return "probabilistic budget certificate high_probability_bound does not recompute"

    budget_limit_microusd = _required_authority_int(
        certificate.budget_limit_microusd,
        "budget_limit_microusd",
        non_negative=True,
    )
    if isinstance(budget_limit_microusd, str):
        return budget_limit_microusd
    observed_spend_microusd = _required_authority_int(
        certificate.observed_spend_microusd,
        "observed_spend_microusd",
        non_negative=True,
    )
    if isinstance(observed_spend_microusd, str):
        return observed_spend_microusd
    bound_microusd = _required_authority_int(
        certificate.high_probability_bound_microusd,
        "high_probability_bound_microusd",
        non_negative=True,
    )
    if isinstance(bound_microusd, str):
        return bound_microusd
    slack_microusd = _required_authority_int(
        certificate.slack_microusd,
        "slack_microusd",
        non_negative=False,
    )
    if isinstance(slack_microusd, str):
        return slack_microusd
    if not _usd_display_matches_microusd(
        certificate.budget_limit,
        budget_limit_microusd,
    ) or not _usd_display_matches_microusd(
        certificate.observed_spend,
        observed_spend_microusd,
    ):
        return (
            "probabilistic budget certificate USD display fields do not match "
            "microusd authority fields"
        )
    try:
        recomputed_bound_microusd = usd_to_microusd_ceil_or_reject(
            "high_probability_bound",
            recomputed,
        )
    except ValueError as error:
        return str(error)
    if bound_microusd != recomputed_bound_microusd:
        return "probabilistic budget certificate bound microusd authority does not recompute"
    expected_slack = budget_limit_microusd - bound_microusd
    if slack_microusd != expected_slack:
        return "probabilistic budget certificate slack_microusd does not recompute"
    if not _usd_display_matches_slack(certificate.slack, slack_microusd):
        return "probabilistic budget certificate slack display does not match slack_microusd"
    expected_outcome = (
        BudgetOutcome.ADMIT
        if bound_microusd <= budget_limit_microusd
        else BudgetOutcome.BLOCK
    )
    if _coerce_budget_outcome(certificate.outcome) != expected_outcome:
        return "probabilistic budget certificate outcome does not match certified envelope rule"
    expected_ledger_hash = budget_ledger_hash(
        BudgetSafetyLedger(
            scope=certificate.scope,
            budget_limit_usd=certificate.budget_limit,
            budget_limit_microusd=budget_limit_microusd,
            observed_spend_usd=certificate.observed_spend,
            observed_spend_microusd=observed_spend_microusd,
            ledger_hash="",
            ledger_sequence=certificate.ledger_sequence_before,
        )
    )
    if certificate.pre_ledger_hash != expected_ledger_hash:
        return "probabilistic budget certificate pre_ledger_hash does not match ledger snapshot"
    try:
        obligations = {str(item) for item in certificate.obligations}
    except TypeError:
        return "probabilistic budget certificate has invalid obligations"
    if not set(DEFAULT_PROBABILISTIC_OBLIGATIONS).issubset(obligations):
        return "probabilistic budget certificate is missing mandatory obligations"
    if "docs/math/adaptive_spend_safety_theorem.txt" not in {
        str(item) for item in certificate.theorem_refs
    }:
        return "probabilistic budget certificate is missing adaptive spend theorem reference"
    return None


def _coerce_cap_provenance(value: CapProvenance | str) -> CapProvenance | None:
    if isinstance(value, CapProvenance):
        return value
    try:
        return CapProvenance(str(value))
    except ValueError:
        return None


def _coerce_concurrency_model(value: ConcurrencyModel | str) -> ConcurrencyModel | None:
    if isinstance(value, ConcurrencyModel):
        return value
    try:
        return ConcurrencyModel(str(value))
    except ValueError:
        return None


def _coerce_budget_outcome(value: BudgetOutcome | str) -> BudgetOutcome | None:
    if isinstance(value, BudgetOutcome):
        return value
    try:
        return BudgetOutcome(str(value))
    except ValueError:
        return None


def _stable_hash_json(value: Any) -> str:
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    current = _FNV64_OFFSET
    for byte in serialized.encode("utf-8"):
        current ^= byte
        current = (current * _FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{current:016x}"


def _json_safe_sorted(value: Any) -> Any:
    if isinstance(
        value,
        (
            ActionType,
            BudgetScope,
            ConcurrencyModel,
            CapProvenance,
            BudgetOutcome,
            BudgetCertificateKind,
        ),
    ):
        return value.value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _json_safe_sorted(to_dict())
    if isinstance(value, Mapping):
        return OrderedDict(
            (str(key), _json_safe_sorted(item))
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe_sorted(item) for item in value]
    return value
