"""Typed Velvet authority taxonomy."""

from __future__ import annotations

from velvet.actions import AuthorityClass, CanonicalAction, MutationKind, Reversibility
from velvet.contracts import AdmissionContract

AUTHORITY_CLASS_PRIORITY: tuple[AuthorityClass, ...] = (
    AuthorityClass.BIND_EXTERNAL,
    AuthorityClass.DESTROY,
    AuthorityClass.SPEND_HIGH,
    AuthorityClass.SPEND_LOW,
    AuthorityClass.ALTER,
    AuthorityClass.APPEND,
    AuthorityClass.OBSERVE,
)


def classify_authority(action: CanonicalAction, contract: AdmissionContract) -> AuthorityClass:
    """Classify by typed predicates over canonical action fields."""

    if action.external_party is not None or action.normalized_payload.get("binds_external") is True:
        return AuthorityClass.BIND_EXTERNAL
    if (
        action.mutation_kind is MutationKind.DESTROY
        or action.reversibility is Reversibility.IRREVERSIBLE
    ):
        return AuthorityClass.DESTROY
    if action.economic_exposure > contract.spend_cap:
        return AuthorityClass.SPEND_HIGH
    if action.economic_exposure > 0:
        return AuthorityClass.SPEND_LOW
    if action.mutation_kind is MutationKind.ALTER:
        return AuthorityClass.ALTER
    if action.mutation_kind is MutationKind.APPEND:
        return AuthorityClass.APPEND
    return AuthorityClass.OBSERVE
