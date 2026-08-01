from __future__ import annotations

from velvet.actions import AuthorityClass
from velvet.contracts import AdmissionContract
from velvet.normalizer import VelvetActionNormalizer


def test_taxonomy_uses_priority_order_for_external_money_action() -> None:
    action = VelvetActionNormalizer().normalize(
        {
            "surface": "function",
            "operation": "refund",
            "name": "issue_refund",
            "refund_amount": 5000,
            "email_to": "vendor@example.com",
            "boundary_key": "case:1",
        },
        AdmissionContract(spend_cap=500),
    )

    assert action.authority_class is AuthorityClass.BIND_EXTERNAL


def test_taxonomy_classifies_typed_mutations() -> None:
    normalizer = VelvetActionNormalizer()
    contract = AdmissionContract(spend_cap=500)

    assert (
        normalizer.normalize({"surface": "function", "name": "read_rows"}, contract).authority_class
        is AuthorityClass.OBSERVE
    )
    assert (
        normalizer.normalize(
            {"surface": "function", "name": "append_audit_note"}, contract
        ).authority_class
        is AuthorityClass.APPEND
    )
    assert (
        normalizer.normalize(
            {"surface": "function", "name": "update_customer"}, contract
        ).authority_class
        is AuthorityClass.ALTER
    )
    assert (
        normalizer.normalize(
            {"surface": "function", "name": "delete_row"}, contract
        ).authority_class
        is AuthorityClass.DESTROY
    )
    assert (
        normalizer.normalize(
            {"surface": "function", "name": "refund", "refund_amount": 50}, contract
        ).authority_class
        is AuthorityClass.SPEND_LOW
    )
    assert (
        normalizer.normalize(
            {"surface": "function", "name": "refund", "refund_amount": 501}, contract
        ).authority_class
        is AuthorityClass.SPEND_HIGH
    )
