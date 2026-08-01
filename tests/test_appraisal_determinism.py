from __future__ import annotations

from velvet.appraisal import AppraisalEngine
from velvet.contracts import AdmissionContract
from velvet.fallback import VelvetFallbackCompiler
from velvet.ledger import AuthorityLedger
from velvet.normalizer import VelvetActionNormalizer


def test_appraisal_is_deterministic_for_fixed_inputs() -> None:
    contract = AdmissionContract(default_authority_budget=10_000)
    ledger = AuthorityLedger(default_authority_budget=10_000)
    action = VelvetActionNormalizer().normalize(
        {
            "surface": "function",
            "name": "refund",
            "refund_amount": 250,
            "boundary_key": "case:1",
        },
        contract,
    )
    fallback = VelvetFallbackCompiler().compile(action)
    appraiser = AppraisalEngine()

    first = appraiser.appraise(
        action,
        fallback,
        contract,
        current_world_state_hash="world",
        authority_ledger=ledger,
        policy_version=contract.policy_version,
    )
    second = appraiser.appraise(
        action,
        fallback,
        contract,
        current_world_state_hash="world",
        authority_ledger=ledger,
        policy_version=contract.policy_version,
    )

    assert first.to_dict() == second.to_dict()
    assert first.admission_price > 0
