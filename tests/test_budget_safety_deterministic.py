from __future__ import annotations

import importlib.util
import random
import sys
import types
from dataclasses import replace
from itertools import product
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

if TYPE_CHECKING:
    from velvet.budget_safety import BudgetSafetyLedgerStore as BudgetSafetyLedgerStoreType
    from velvet.router import Router as RouterClass
    from velvet.types import CandidateAction as CandidateActionType
    from velvet.types import CapProvenance as CapProvenanceType
    from velvet.types import ConcurrencyModel as ConcurrencyModelType

ROOT = Path(__file__).resolve().parents[1]
VELVET_SRC = ROOT / "src" / "velvet"


def _load_velvet_submodule(name: str) -> types.ModuleType:
    full_name = f"velvet.{name}"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, VELVET_SRC / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {full_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


# Python-only verification intentionally avoids importing velvet/__init__.py.
# The package root imports velvet.rope, which requires compiled velvet._native.
if "velvet" not in sys.modules:
    velvet_package = types.ModuleType("velvet")
    velvet_package.__path__ = [str(VELVET_SRC)]
    sys.modules["velvet"] = velvet_package

velvet_types = _load_velvet_submodule("types")
budget_safety = _load_velvet_submodule("budget_safety")

ActionType = velvet_types.ActionType
BudgetOutcome = velvet_types.BudgetOutcome
BudgetCertificateKind = velvet_types.BudgetCertificateKind
CandidateAction = velvet_types.CandidateAction
CapProvenance = velvet_types.CapProvenance
ConcurrencyModel = velvet_types.ConcurrencyModel
DecisionType = velvet_types.DecisionType

BudgetSafetyLedgerStore = budget_safety.BudgetSafetyLedgerStore
DeterministicBudgetSpec = budget_safety.DeterministicBudgetSpec
build_deterministic_budget_certificate = budget_safety.build_deterministic_budget_certificate
build_cgf_ville_budget_certificate = budget_safety.build_cgf_ville_budget_certificate
build_moment_cantelli_budget_certificate = (
    budget_safety.build_moment_cantelli_budget_certificate
)
cgf_ville_high_probability_bound = budget_safety.cgf_ville_high_probability_bound
is_certifying = budget_safety.is_certifying
is_probabilistic_certifying = budget_safety.is_probabilistic_certifying
make_budget_ledger = budget_safety.make_budget_ledger
microusd_to_usd_display = budget_safety.microusd_to_usd_display
moment_cantelli_high_probability_bound = (
    budget_safety.moment_cantelli_high_probability_bound
)
openai_responses_hard_cap_usd = budget_safety.openai_responses_hard_cap_usd
openai_responses_realized_cost_usd = budget_safety.openai_responses_realized_cost_usd
slack_microusd_to_usd_display = budget_safety.slack_microusd_to_usd_display

Router: type[RouterClass] | None
try:
    from velvet.router import Router as _Router
except ImportError:
    Router = None
else:
    Router = _Router

velvet_package = cast(Any, sys.modules["velvet"])
velvet_package.ActionType = ActionType
velvet_package.CandidateAction = CandidateAction
velvet_package.Router = Router

requires_native_router = pytest.mark.skipif(
    Router is None,
    reason="velvet._native is unavailable; router safety is verified from packaged Rust evidence",
)


def _router() -> RouterClass:
    assert Router is not None
    return Router()


ZERO_COST = {
    "tokens": 0.0,
    "latency": 0.0,
    "money": 0.0,
    "compute": 0.0,
    "api_calls": 0.0,
    "context_pollution": 0.0,
    "memory_bloat": 0.0,
    "user_attention": 0.0,
    "privacy_exposure": 0.0,
    "coordination_overhead": 0.0,
    "opportunity_cost": 0.0,
}

ZERO_RISK = {
    "privacy_risk": 0.0,
    "tool_risk": 0.0,
    "external_side_effect_risk": 0.0,
    "hallucination_risk": 0.0,
    "staleness_risk": 0.0,
    "source_quality_risk": 0.0,
    "irreversibility": 0.0,
    "sensitivity": 0.0,
    "compliance_risk": 0.0,
    "user_trust_risk": 0.0,
    "future_misuse_risk": 0.0,
}


def _failed_constraint(candidate_decision: Any, constraint_id: str) -> Any:
    assert candidate_decision.admission_trace is not None
    matches = [
        constraint
        for constraint in candidate_decision.admission_trace.hard_constraints
        if constraint.constraint_id == constraint_id
    ]
    assert matches
    assert matches[0].passed is False
    return matches[0]


def test_pathwise_hard_cap_simulation_has_zero_overshoot() -> None:
    for seed in range(250):
        rng = random.Random(seed)  # noqa: S311 - deterministic property-test generator.
        budget = 10.0
        spend = 0.0
        for _ in range(100):
            hard_cap = rng.uniform(0.0, 1.0)
            if spend + hard_cap <= budget:
                spend += rng.uniform(0.0, hard_cap)
                assert spend <= budget
        assert spend <= budget


def test_admit_block_boundary() -> None:
    blocked = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=9.6,
        hard_cap=0.5,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    admitted = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=9.4,
        hard_cap=0.5,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )

    assert blocked.outcome == BudgetOutcome.BLOCK
    assert admitted.outcome == BudgetOutcome.ADMIT
    assert admitted.slack_usd == pytest.approx(0.1)


def test_is_certifying_full_matrix() -> None:
    provenances = (
        CapProvenance.PROVIDER_ENFORCED,
        CapProvenance.ESTIMATE_NOT_A_CAP,
    )
    concurrency_models = (
        ConcurrencyModel.SINGLE_WRITER_ATOMIC,
        ConcurrencyModel.UNSERIALIZED,
    )
    outcome_caps = (
        (BudgetOutcome.ADMIT, 1.0),
        (BudgetOutcome.BLOCK, 11.0),
    )
    for provenance, concurrency_model, (outcome, hard_cap) in product(
        provenances,
        concurrency_models,
        outcome_caps,
    ):
        certificate = build_deterministic_budget_certificate(
            budget_limit=10.0,
            observed_spend=0.0,
            hard_cap=hard_cap,
            cap_provenance=provenance,
            scope="task",
            concurrency_model=concurrency_model,
            action_hash="action",
            filtration_hash="filtration",
            ledger_sequence_before=0,
        )

        assert certificate.outcome == outcome
        assert is_certifying(certificate) is (
            provenance == CapProvenance.PROVIDER_ENFORCED
            and concurrency_model == ConcurrencyModel.SINGLE_WRITER_ATOMIC
            and outcome == BudgetOutcome.ADMIT
        )

    valid = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    missing_obligations = replace(
        valid,
        obligations=("record_realized_cost_after_execution",),
    )
    assert is_certifying(missing_obligations) is False
    assert is_certifying(replace(valid, projected_spend_usd=2.0)) is False


def test_integer_authority_boundaries_are_exact() -> None:
    projected_at_limit = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=9.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    assert projected_at_limit.outcome == BudgetOutcome.ADMIT
    assert projected_at_limit.projected_spend_microusd == 10_000_000
    assert is_certifying(projected_at_limit) is True

    projected_over_limit = replace(
        projected_at_limit,
        hard_cap_usd=microusd_to_usd_display(1_000_001),
        hard_cap_microusd=1_000_001,
        projected_spend_usd=microusd_to_usd_display(10_000_001),
        projected_spend_microusd=10_000_001,
        slack_usd=slack_microusd_to_usd_display(-1),
        slack_microusd=-1,
        outcome=BudgetOutcome.ADMIT,
    )
    assert is_certifying(projected_over_limit) is False

    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    hard_cap = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    assert ledger.commit_authorized_realized_cost(
        hard_cap,
        realized_microusd=1_000_000,
    )

    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    _assert_commit_rejects_unchanged(ledger, hard_cap, realized_microusd=1_000_001)

    ledger = BudgetSafetyLedgerStore(
        make_budget_ledger(scope="task", budget_limit=10.0, observed_spend=9.0)
    )
    next_at_limit = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=9.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    assert ledger.commit_authorized_realized_cost(
        next_at_limit,
        realized_microusd=1_000_000,
    )
    assert ledger.snapshot().observed_spend_microusd == 10_000_000

    ledger = BudgetSafetyLedgerStore(
        make_budget_ledger(scope="task", budget_limit=10.0, observed_spend=9.0)
    )
    next_over_limit = replace(
        next_at_limit,
        hard_cap_usd=microusd_to_usd_display(1_000_001),
        hard_cap_microusd=1_000_001,
        projected_spend_usd=microusd_to_usd_display(10_000_001),
        projected_spend_microusd=10_000_001,
        slack_usd=slack_microusd_to_usd_display(-1),
        slack_microusd=-1,
        outcome=BudgetOutcome.ADMIT,
    )
    _assert_commit_rejects_unchanged(ledger, next_over_limit, realized_microusd=1_000_001)


@requires_native_router
def test_valid_budget_block_short_circuits_before_scoring() -> None:
    candidate = _budget_candidate(observed_spend=9.6, hard_cap=0.5)

    decision = _router().decide({"filtration_hash": "fh"}, [candidate])

    candidate_decision = decision.candidate_decisions[0]
    assert decision.decision == DecisionType.BLOCK
    assert candidate_decision.short_circuit == "deterministic_budget_block"
    assert candidate_decision.admission_score is None
    assert candidate_decision.budget_trace is not None
    assert candidate_decision.budget_trace.certifying is False


@requires_native_router
def test_valid_budget_admit_falls_through_to_normal_scoring() -> None:
    candidate = replace(
        _budget_candidate(observed_spend=9.4, hard_cap=0.5),
        expected_improvement=1.0,
        novelty=0.1,
        confidence=1.0,
    )

    decision = _router().decide(
        {
            "filtration_hash": "fh",
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.01,
                "lambda_cap": 0.01,
            },
        },
        [candidate],
    )

    candidate_decision = decision.candidate_decisions[0]
    assert decision.decision == DecisionType.EXECUTE
    assert candidate_decision.short_circuit is None
    assert candidate_decision.admission_score is None
    assert candidate_decision.admission_trace is not None
    assert candidate_decision.admission_trace.selected_decision.value == "execute"
    assert candidate_decision.effect_vector is not None
    assert candidate_decision.admission_trace.objective_components.objective_bps > 0
    assert candidate_decision.budget_trace is not None
    assert candidate_decision.budget_trace.certifying is True


@requires_native_router
def test_estimate_not_a_cap_downgrades_without_budget_short_circuit() -> None:
    candidate = _budget_candidate(
        observed_spend=0.0,
        hard_cap=1.0,
        provenance=CapProvenance.ESTIMATE_NOT_A_CAP,
        metadata={"non_budget_affecting": True},
    )

    decision = _router().decide({"filtration_hash": "fh"}, [candidate])

    candidate_decision = decision.candidate_decisions[0]
    assert decision.decision == DecisionType.BLOCK
    assert candidate_decision.short_circuit == "budget_authorization_required"
    assert candidate_decision.budget_trace is not None
    assert candidate_decision.budget_trace.certifying is False
    assert "estimate-only" in str(candidate_decision.budget_trace.downgrade_reason)


@requires_native_router
def test_unserialized_downgrades_without_budget_short_circuit() -> None:
    candidate = _budget_candidate(
        observed_spend=0.0,
        hard_cap=1.0,
        concurrency_model=ConcurrencyModel.UNSERIALIZED,
        metadata={"non_budget_affecting": True},
    )

    decision = _router().decide({"filtration_hash": "fh"}, [candidate])

    candidate_decision = decision.candidate_decisions[0]
    assert decision.decision == DecisionType.BLOCK
    assert candidate_decision.short_circuit == "budget_authorization_required"
    assert candidate_decision.budget_trace is not None
    assert candidate_decision.budget_trace.certifying is False
    assert "unserialized" in str(candidate_decision.budget_trace.downgrade_reason)


@requires_native_router
def test_stale_filtration_hash_rejects_budget_certificate() -> None:
    candidate = _budget_candidate(observed_spend=0.0, hard_cap=1.0)
    assert candidate.budget_certificate is not None
    stale = replace(
        candidate,
        budget_certificate=replace(candidate.budget_certificate, filtration_hash="stale"),
    )

    decision = _router().decide({"filtration_hash": "fh"}, [stale])

    assert decision.decision == DecisionType.BLOCK
    assert decision.candidate_decisions[0].short_circuit == "invalid_budget_certificate"


@requires_native_router
def test_action_hash_mismatch_rejects_budget_certificate() -> None:
    candidate = _budget_candidate(observed_spend=0.0, hard_cap=1.0)
    mutated = replace(candidate, metadata={**dict(candidate.metadata), "new_argument": "after"})

    decision = _router().decide({"filtration_hash": "fh"}, [mutated])

    assert decision.decision == DecisionType.BLOCK
    assert "action_hash" in decision.candidate_decisions[0].reason


@requires_native_router
def test_missing_mandatory_obligation_rejects_budget_certificate() -> None:
    candidate = _budget_candidate(observed_spend=0.0, hard_cap=1.0)
    assert candidate.budget_certificate is not None
    invalid = replace(
        candidate,
        budget_certificate=replace(
            candidate.budget_certificate,
            obligations=("record_realized_cost_after_execution",),
        ),
    )

    decision = _router().decide({"filtration_hash": "fh"}, [invalid])

    assert decision.decision == DecisionType.BLOCK
    assert "mandatory obligation" in decision.candidate_decisions[0].reason


@requires_native_router
def test_router_invariant_blocks_spend_bearing_execute_without_budget_certificate() -> None:
    candidate = CandidateAction(
        ActionType.RETRIEVE_CONTEXT,
        expected_improvement=1.0,
        novelty=0.1,
        confidence=1.0,
        cost_overrides=ZERO_COST,
        risk_overrides=ZERO_RISK,
        metadata={"usd_estimate": 1.0},
    )

    decision = _router().decide(
        {
            "router_config": {
                "pricing_policy": "fixed_price_baseline",
                "lambda_floor": 0.01,
                "lambda_cap": 0.01,
            }
        },
        [candidate],
    )

    assert decision.decision in {DecisionType.BLOCK, DecisionType.ESCALATE}
    assert decision.decision != DecisionType.EXECUTE
    failed = _failed_constraint(decision.candidate_decisions[0], "budget_reserved")
    assert failed.reason_code == "budget_required"


def test_same_snapshot_budget_certificates_commit_at_most_once() -> None:
    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    first = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=6.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="first",
        filtration_hash="fh",
        ledger_sequence_before=0,
    )
    second = replace(first, action_hash="second")

    results = [
        ledger.commit_authorized_realized_cost(item, realized_microusd=6_000_000)
        for item in (first, second)
    ]

    assert sorted(results) == [False, True]
    assert ledger.snapshot().observed_spend_usd == 6.0
    assert ledger.snapshot().observed_spend_microusd == 6_000_000
    assert ledger.snapshot().ledger_sequence == 1


def test_authority_commit_requires_full_certifying_predicate() -> None:
    valid = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )
    cases = (
        replace(valid, obligations=("record_realized_cost_after_execution",)),
        replace(
            valid,
            projected_spend_usd=microusd_to_usd_display(2_000_000),
            projected_spend_microusd=2_000_000,
        ),
        replace(
            valid,
            slack_usd=slack_microusd_to_usd_display(9_000_001),
            slack_microusd=9_000_001,
        ),
        replace(
            valid,
            hard_cap_usd=microusd_to_usd_display(11_000_000),
            hard_cap_microusd=11_000_000,
            projected_spend_usd=microusd_to_usd_display(11_000_000),
            projected_spend_microusd=11_000_000,
            slack_usd=slack_microusd_to_usd_display(-1_000_000),
            slack_microusd=-1_000_000,
            outcome=BudgetOutcome.ADMIT,
        ),
        replace(valid, cap_provenance=CapProvenance.ESTIMATE_NOT_A_CAP),
        replace(valid, concurrency_model=ConcurrencyModel.UNSERIALIZED),
        replace(valid, schema_version="unsupported"),
    )

    for certificate in cases:
        assert is_certifying(certificate) is False
        ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
        _assert_commit_rejects_unchanged(ledger, certificate, realized_microusd=500_000)


def test_authority_commit_succeeds_once_for_certifying_certificate() -> None:
    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    certificate = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="filtration",
        ledger_sequence_before=0,
    )

    assert is_certifying(certificate) is True
    assert ledger.commit_authorized_realized_cost(certificate, realized_microusd=500_000)
    assert ledger.snapshot().observed_spend_usd == 0.5
    assert ledger.snapshot().observed_spend_microusd == 500_000
    assert ledger.snapshot().ledger_sequence == 1
    _assert_commit_rejects_unchanged(ledger, certificate, realized_microusd=500_000)


def test_missing_realized_cost_fails_closed_before_next_admission() -> None:
    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    certificate = build_deterministic_budget_certificate(
        budget_limit=10.0,
        observed_spend=0.0,
        hard_cap=1.0,
        cap_provenance=CapProvenance.PROVIDER_ENFORCED,
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
    )

    assert ledger.try_commit(certificate, realized_usd=None) is False
    with pytest.raises(RuntimeError, match="fail-closed"):
        ledger.snapshot()


def test_cgf_ville_certificate_admits_when_envelope_clears() -> None:
    bound = cgf_ville_high_probability_bound(
        observed_spend=1.0,
        certified_mean_sum=1.0,
        cgf_sum_by_lambda={"1": 0.0},
        lambda_grid=(1.0,),
        mixture_weights=(1.0,),
        delta_total=0.05,
    )
    certificate = build_cgf_ville_budget_certificate(
        budget_limit=10.0,
        delta_total=0.05,
        observed_spend=1.0,
        certified_mean_sum=1.0,
        cgf_sum_by_lambda={"1": 0.0},
        lambda_grid=(1.0,),
        mixture_weights=(1.0,),
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
        cost_model_id="unit-test-cgf",
    )

    assert certificate.certificate_kind == BudgetCertificateKind.CGF_VILLE
    assert certificate.high_probability_bound == pytest.approx(bound)
    assert certificate.outcome == BudgetOutcome.ADMIT
    assert is_probabilistic_certifying(certificate) is True


def test_cgf_ville_certificate_blocks_when_envelope_exceeds_budget() -> None:
    certificate = build_cgf_ville_budget_certificate(
        budget_limit=3.0,
        delta_total=0.05,
        observed_spend=1.0,
        certified_mean_sum=1.0,
        cgf_sum_by_lambda={"1": 0.0},
        lambda_grid=(1.0,),
        mixture_weights=(1.0,),
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
        cost_model_id="unit-test-cgf",
    )

    assert certificate.outcome == BudgetOutcome.BLOCK
    assert is_probabilistic_certifying(certificate) is False


def test_moment_cantelli_certificate_is_probabilistic_and_blocks_when_bound_fails() -> None:
    bound = moment_cantelli_high_probability_bound(
        observed_spend=0.0,
        mean_upper=2.0,
        variance_upper=1.0,
        delta_total=0.05,
    )
    certificate = build_moment_cantelli_budget_certificate(
        budget_limit=5.0,
        delta_total=0.05,
        observed_spend=0.0,
        mean_upper=2.0,
        variance_upper=1.0,
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
        cost_model_id="unit-test-moment",
    )

    assert certificate.certificate_kind == BudgetCertificateKind.MOMENT_CANTELLI
    assert certificate.high_probability_bound == pytest.approx(bound)
    assert certificate.outcome == BudgetOutcome.BLOCK
    assert is_probabilistic_certifying(certificate) is False


def test_probabilistic_missing_realized_cost_fails_closed() -> None:
    ledger = BudgetSafetyLedgerStore(make_budget_ledger(scope="task", budget_limit=10.0))
    certificate = build_cgf_ville_budget_certificate(
        budget_limit=10.0,
        delta_total=0.05,
        observed_spend=0.0,
        certified_mean_sum=1.0,
        cgf_sum_by_lambda={"1": 0.0},
        lambda_grid=(1.0,),
        mixture_weights=(1.0,),
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
        cost_model_id="unit-test-cgf",
    )

    assert ledger.commit_probabilistic_authorized_realized_cost(
        certificate,
        realized_microusd=None,
    ) is False
    with pytest.raises(RuntimeError, match="fail-closed"):
        ledger.snapshot()


def test_probabilistic_stale_ledger_snapshot_rejects_commit() -> None:
    ledger = BudgetSafetyLedgerStore(
        make_budget_ledger(scope="task", budget_limit=10.0, observed_spend=1.0)
    )
    certificate = build_cgf_ville_budget_certificate(
        budget_limit=10.0,
        delta_total=0.05,
        observed_spend=0.0,
        certified_mean_sum=1.0,
        cgf_sum_by_lambda={"1": 0.0},
        lambda_grid=(1.0,),
        mixture_weights=(1.0,),
        scope="task",
        action_hash="action",
        filtration_hash="fh",
        ledger_sequence_before=0,
        cost_model_id="unit-test-cgf",
    )
    before = ledger.snapshot()

    assert ledger.commit_probabilistic_authorized_realized_cost(
        certificate,
        realized_microusd=100_000,
    ) is False
    assert ledger.snapshot() == before


def test_estimate_only_cost_model_cannot_masquerade_as_cgf_certificate() -> None:
    with pytest.raises(ValueError, match="lambda_grid"):
        build_cgf_ville_budget_certificate(
            budget_limit=10.0,
            delta_total=0.05,
            observed_spend=0.0,
            certified_mean_sum=1.0,
            cgf_sum_by_lambda={},
            lambda_grid=(),
            mixture_weights=(),
            scope="task",
            action_hash="action",
            filtration_hash="fh",
            ledger_sequence_before=0,
            cost_model_id="estimate-only-model",
        )


def test_openai_responses_cost_helpers_require_supplied_price_table() -> None:
    cap = openai_responses_hard_cap_usd(
        input_text="abc",
        max_output_tokens=10,
        input_usd_per_million_tokens=1.0,
        output_usd_per_million_tokens=2.0,
    )
    realized = openai_responses_realized_cost_usd(
        {"usage": {"input_tokens": 3, "output_tokens": 4}},
        input_usd_per_million_tokens=1.0,
        output_usd_per_million_tokens=2.0,
    )

    assert cap == pytest.approx(23.0 / 1_000_000.0)
    assert realized == pytest.approx(11.0 / 1_000_000.0)
    assert (
        openai_responses_realized_cost_usd(
            {},
            input_usd_per_million_tokens=1.0,
            output_usd_per_million_tokens=2.0,
        )
        is None
    )


def _budget_candidate(
    *,
    observed_spend: float,
    hard_cap: float,
    provenance: CapProvenanceType = CapProvenance.PROVIDER_ENFORCED,
    concurrency_model: ConcurrencyModelType = ConcurrencyModel.SINGLE_WRITER_ATOMIC,
    metadata: dict[str, object] | None = None,
) -> CandidateActionType:
    return cast(
        "CandidateActionType",
        DeterministicBudgetSpec(
            budget_limit=10.0,
            observed_spend=observed_spend,
            hard_cap=hard_cap,
            cap_provenance=provenance,
            scope="task",
            concurrency_model=concurrency_model,
            filtration_hash="fh",
        ).candidate(
            ActionType.RETRIEVE_CONTEXT,
            description="budgeted tool call",
            cost_overrides=ZERO_COST,
            risk_overrides=ZERO_RISK,
            metadata=metadata,
        ),
    )


def _assert_commit_rejects_unchanged(
    ledger: BudgetSafetyLedgerStoreType,
    certificate: object,
    *,
    realized_microusd: int,
) -> None:
    before = ledger.snapshot()
    assert ledger.commit_authorized_realized_cost(
        certificate,  # type: ignore[arg-type]
        realized_microusd=realized_microusd,
    ) is False
    after = ledger.snapshot()
    assert after == before
