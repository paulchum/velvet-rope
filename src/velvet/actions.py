"""Canonical consequential action types for the Velvet Admission Layer."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from velvet.serialization import JsonObject, canonical_hash, stable_json_object


class AuthorityClass(StrEnum):
    OBSERVE = "OBSERVE"
    APPEND = "APPEND"
    ALTER = "ALTER"
    DESTROY = "DESTROY"
    SPEND_LOW = "SPEND_LOW"
    SPEND_HIGH = "SPEND_HIGH"
    BIND_EXTERNAL = "BIND_EXTERNAL"


class MutationKind(StrEnum):
    NONE = "none"
    APPEND = "append"
    ALTER = "alter"
    DESTROY = "destroy"
    SPEND = "spend"


class Reversibility(StrEnum):
    NONE = "none"
    REVERSIBLE = "reversible"
    PARTIAL = "partial"
    IRREVERSIBLE = "irreversible"


class ProofDecision(StrEnum):
    ADMITTED = "ADMITTED"
    HELD = "HELD"
    FALLBACK_EXECUTED = "FALLBACK_EXECUTED"
    ESCALATED = "ESCALATED"
    REFUSED = "REFUSED"
    MASKED_ACTION_FAILURE = "MASKED_ACTION_FAILURE"


@dataclass(frozen=True)
class CanonicalAction:
    action_id: str
    actor_id: str
    agent_id: str
    boundary_key: str
    tool_name: str
    canonical_type: str
    authority_class: AuthorityClass
    target_resource: str
    economic_exposure: int
    external_party: str | None
    mutation_kind: MutationKind
    reversibility: Reversibility
    read_set_hash: str
    proposed_payload_hash: str
    normalized_payload: JsonObject
    timestamp_input: str
    contract_version: str
    policy_version: str
    schema_version: str = "velvet.canonical_action.v1"
    tenant_id: str = "tenant:default"
    environment: str = "local"
    surface: str = "unknown"
    operation: str = "unknown"
    arguments_hash: str = ""
    tool_schema_hash: str | None = None
    redaction_summary: JsonObject | None = None
    provenance: JsonObject | None = None

    def with_authority_class(self, authority_class: AuthorityClass) -> CanonicalAction:
        return replace(self, authority_class=authority_class)

    def with_normalized_payload(self, payload: JsonObject) -> CanonicalAction:
        return replace(self, normalized_payload=stable_json_object(payload))

    def unsigned_payload(self) -> JsonObject:
        payload: JsonObject = {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "actor_id": self.actor_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "boundary_key": self.boundary_key,
            "surface": self.surface,
            "tool_name": self.tool_name,
            "canonical_type": self.canonical_type,
            "operation": self.operation,
            "authority_class": self.authority_class.value,
            "target_resource": self.target_resource,
            "economic_exposure": self.economic_exposure,
            "external_party": self.external_party,
            "mutation_kind": self.mutation_kind.value,
            "reversibility": self.reversibility.value,
            "read_set_hash": self.read_set_hash,
            "proposed_payload_hash": self.proposed_payload_hash,
            "arguments_hash": self.arguments_hash,
            "tool_schema_hash": self.tool_schema_hash,
            "normalized_payload": stable_json_object(self.normalized_payload),
            "redaction_summary": stable_json_object(self.redaction_summary or {}),
            "timestamp_input": self.timestamp_input,
            "contract_version": self.contract_version,
            "policy_version": self.policy_version,
            "provenance": stable_json_object(self.provenance or {}),
        }
        return payload

    def to_dict(self) -> JsonObject:
        payload = self.unsigned_payload()
        payload["canonical_action_hash"] = self.canonical_action_hash
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalAction:
        return cls(
            action_id=str(data["action_id"]),
            actor_id=str(data["actor_id"]),
            agent_id=str(data["agent_id"]),
            boundary_key=str(data["boundary_key"]),
            tool_name=str(data["tool_name"]),
            canonical_type=str(data["canonical_type"]),
            authority_class=AuthorityClass(str(data["authority_class"])),
            target_resource=str(data["target_resource"]),
            economic_exposure=int(data["economic_exposure"]),
            external_party=str(data["external_party"]) if data.get("external_party") else None,
            mutation_kind=MutationKind(str(data["mutation_kind"])),
            reversibility=Reversibility(str(data["reversibility"])),
            read_set_hash=str(data["read_set_hash"]),
            proposed_payload_hash=str(data["proposed_payload_hash"]),
            normalized_payload=stable_json_object(
                data.get("normalized_payload")
                if isinstance(data.get("normalized_payload"), dict)
                else {}
            ),
            timestamp_input=str(data["timestamp_input"]),
            contract_version=str(data["contract_version"]),
            policy_version=str(data["policy_version"]),
            schema_version=str(data.get("schema_version", "velvet.canonical_action.v1")),
            tenant_id=str(data.get("tenant_id", "tenant:default")),
            environment=str(data.get("environment", "local")),
            surface=str(data.get("surface", "unknown")),
            operation=str(data.get("operation", data.get("canonical_type", "unknown"))),
            arguments_hash=str(data.get("arguments_hash", "")),
            tool_schema_hash=str(data["tool_schema_hash"])
            if data.get("tool_schema_hash") is not None
            else None,
            redaction_summary=stable_json_object(
                data.get("redaction_summary")
                if isinstance(data.get("redaction_summary"), dict)
                else {}
            ),
            provenance=stable_json_object(
                data.get("provenance") if isinstance(data.get("provenance"), dict) else {}
            ),
        )

    @property
    def canonical_action_hash(self) -> str:
        return canonical_hash(self.unsigned_payload())

    @property
    def split_group_key(self) -> str | None:
        value = self.normalized_payload.get("split_group_key")
        return str(value) if value else None

    @property
    def aggregated_economic_exposure(self) -> int:
        value = self.normalized_payload.get("aggregated_economic_exposure")
        return int(value) if isinstance(value, int) else self.economic_exposure


class MaskedActionFailure(Exception):
    """Raised when a proposal cannot map to one unambiguous canonical action."""

    def __init__(
        self,
        reason: str,
        *,
        proposed_action: JsonObject,
        ambiguity_set: tuple[CanonicalAction, ...] = (),
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.proposed_action = proposed_action
        self.ambiguity_set = ambiguity_set
