from __future__ import annotations

from velvet.actions import ProofDecision
from velvet.contracts import AdmissionContract
from velvet.executor import VelvetAdmissionLayer


def test_masked_action_failure_prices_plausible_actions_and_refuses() -> None:
    layer = VelvetAdmissionLayer(AdmissionContract(default_authority_budget=10_000))

    outcome = layer.evaluate(
        {"surface": "sql", "sql": "DELETE FROM", "boundary_key": "case:masked"},
        logical_step=1,
    )

    assert outcome.decision is ProofDecision.MASKED_ACTION_FAILURE
    assert outcome.appraisal.admission_price > 0
    assert outcome.envelope.decision is ProofDecision.MASKED_ACTION_FAILURE
