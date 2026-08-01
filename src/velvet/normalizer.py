"""Native Rust canonicalization of proposed Velvet actions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from velvet import _native
from velvet.actions import CanonicalAction, MaskedActionFailure
from velvet.contracts import AdmissionContract
from velvet.serialization import JsonObject, stable_json_object


class VelvetActionNormalizer:
    """Canonicalize raw action proposals through the Rust core normalizer."""

    def normalize(
        self,
        proposal: Mapping[str, Any],
        contract: AdmissionContract,
        *,
        ledger: object | None = None,
    ) -> CanonicalAction:
        del ledger
        raw = stable_json_object(proposal)
        try:
            payload = _native.normalize_action(raw, contract.to_dict())
        except ValueError as error:
            raise MaskedActionFailure(
                str(error),
                proposed_action=raw,
                ambiguity_set=self.ambiguity_set(raw, contract),
            ) from error
        return CanonicalAction.from_dict(payload)

    def ambiguity_set(
        self,
        proposal: Mapping[str, Any],
        contract: AdmissionContract,
        *,
        limit: int = 5,
    ) -> tuple[CanonicalAction, ...]:
        raw = stable_json_object(proposal)
        candidates: list[CanonicalAction] = []
        if raw.get("sql") is not None or raw.get("query") is not None:
            for sql in (
                "DROP TABLE ambiguous_resource",
                "UPDATE ambiguous_resource SET value = value",
                "SELECT * FROM ambiguous_resource",
            ):
                try:
                    payload = _native.normalize_action(
                        {
                            "surface": "sql",
                            "sql": sql,
                            "boundary_key": raw.get("boundary_key", "agent:agent:default"),
                            "agent_id": raw.get("agent_id", "agent"),
                        },
                        contract.to_dict(),
                    )
                except ValueError:
                    continue
                candidates.append(CanonicalAction.from_dict(payload))
        return tuple(candidates[:limit])


def normalize_action(
    proposal: Mapping[str, Any],
    contract: AdmissionContract | None = None,
) -> JsonObject:
    """Return the Rust-native canonical action payload as a JSON object."""

    active_contract = contract or AdmissionContract()
    return stable_json_object(_native.normalize_action(dict(proposal), active_contract.to_dict()))
