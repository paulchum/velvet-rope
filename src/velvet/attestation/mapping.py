"""Declarative Article 12 evidence mapping for Velvet vault records.

The table in this module maps technical record-keeping fields to concrete
Velvet vault artifacts and JSON Pointers. It is not legal advice and it does
not assert legal status.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from velvet.serialization import JsonObject

ARTICLE_12_BOUNDARY_NOTICE = (
    "This bundle demonstrates technical record-keeping capability relevant to EU AI Act "
    "Article 12. It is not a determination of legal compliance, which depends on system "
    "classification, deployment context, and counsel review."
)

COVERAGE_SCHEMA_VERSION = "velvet.attestation.coverage_report.v1"
MAPPING_SCHEMA_VERSION = "velvet.attestation.mapping.v1"

Coverage = Literal["evidenced", "partial", "not_evidenced"]


@dataclass(frozen=True)
class EvidencePointer:
    artifact: str
    pointer: str
    required: bool = True
    note: str | None = None

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "artifact": self.artifact,
            "json_pointer": self.pointer,
            "required": self.required,
        }
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass(frozen=True)
class MappingEntry:
    field_id: str
    label: str
    article_12_relevance: str
    pointers: tuple[EvidencePointer, ...] = ()
    default_coverage: Coverage = "evidenced"
    note: str = ""
    not_evidenced_by_velvet: bool = False

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "field_id": self.field_id,
            "label": self.label,
            "article_12_relevance": self.article_12_relevance,
            "default_coverage": self.default_coverage,
            "artifact_pointers": [pointer.to_dict() for pointer in self.pointers],
            "not_evidenced_by_velvet": self.not_evidenced_by_velvet,
        }
        if self.note:
            payload["note"] = self.note
        if self.not_evidenced_by_velvet:
            payload["not_evidenced_reason"] = self.note or "No Velvet vault source is declared."
        return payload


def ptr(
    artifact: str,
    pointer: str,
    *,
    required: bool = True,
    note: str | None = None,
) -> EvidencePointer:
    return EvidencePointer(artifact=artifact, pointer=pointer, required=required, note=note)


FIELD_MAPPINGS: tuple[MappingEntry, ...] = (
    MappingEntry(
        "event.timestamp",
        "Event timestamp",
        "Automatic recording over system lifetime; supports Article 12(2)(a)-(c) sequencing.",
        (
            ptr("ledger_record", "/recorded_at"),
            ptr("admission_evidence", "/issued_at", required=False),
        ),
    ),
    MappingEntry(
        "system.identity",
        "System and tenant identity",
        "Traceability appropriate to intended purpose and deployer monitoring.",
        (
            ptr("deployment_metadata", "/system_name"),
            ptr("ledger_record", "/tenant_id"),
            ptr("ledger_record", "/environment", required=False),
        ),
    ),
    MappingEntry(
        "agent.identity",
        "Agent identity",
        "Identifies the actor context for operational monitoring.",
        (
            ptr("admission_evidence", "/identity/agent_id"),
            ptr("selected_warrant", "/agent_id", required=False),
        ),
        default_coverage="partial",
        note="Some MCP vault records do not include an agent identifier.",
    ),
    MappingEntry(
        "actor.identity",
        "Actor or subject identity",
        "Supports traceability for deployer monitoring where supplied by the caller.",
        (
            ptr("admission_evidence", "/identity/actor_user_id"),
            ptr("admission_evidence", "/identity/subject_id", required=False),
        ),
        default_coverage="partial",
        note="Identity fields are evidenced only when the upstream request provided them.",
    ),
    MappingEntry(
        "action.type",
        "Action type",
        "Identifies risk-relevant events and substantial modifications.",
        (
            ptr("ledger_record", "/action_type"),
            ptr("admission_evidence", "/decision/action_type", required=False),
        ),
    ),
    MappingEntry(
        "action.canonical_hash",
        "Canonical action hash",
        "Binds the admitted action to replay and drift checks.",
        (
            ptr("ledger_record", "/canonical_action_hash"),
            ptr("selected_warrant", "/canonical_action_hash", required=False),
        ),
        default_coverage="partial",
        note=(
            "Inline gateway records carry this directly; MCP vault records may bind request "
            "and arguments hashes instead."
        ),
    ),
    MappingEntry(
        "arguments.hash",
        "Arguments hash",
        "Binds action arguments for replay and mutation detection.",
        (
            ptr("ledger_record", "/arguments_hash"),
            ptr("admission_evidence", "/tool/arguments_hash", required=False),
            ptr("selected_warrant", "/arguments_hash", required=False),
        ),
    ),
    MappingEntry(
        "arguments.recording_mode",
        "Arguments recording mode",
        "Identifies whether arguments are hash-only, plaintext, or encrypted in the "
        "evidence plane.",
        (),
        default_coverage="not_evidenced",
        not_evidenced_by_velvet=True,
        note=(
            "Current vault admission evidence records hashes and raw-action refs, but no "
            "explicit argument recording-mode field."
        ),
    ),
    MappingEntry(
        "tool.identity",
        "Tool identity",
        "Identifies the tool involved in the event.",
        (
            ptr("ledger_record", "/tool_key"),
            ptr("admission_evidence", "/tool/tool_key", required=False),
            ptr("admission_evidence", "/tool/mcp_server", required=False),
            ptr("admission_evidence", "/tool/mcp_tool", required=False),
        ),
    ),
    MappingEntry(
        "tool.schema_hash",
        "Tool schema hash",
        "Binds the evaluated tool interface to the decision.",
        (
            ptr("ledger_record", "/tool_schema_hash"),
            ptr("admission_evidence", "/tool/tool_schema_hash", required=False),
            ptr("selected_warrant", "/tool_schema_hash", required=False),
        ),
    ),
    MappingEntry(
        "policy.bundle_hash",
        "Policy bundle hash active at decision time",
        "Supports traceability of the decision rules active for the event.",
        (
            ptr("ledger_record", "/policy_hash"),
            ptr("admission_evidence", "/policy/policy_hash", required=False),
            ptr("sth", "/policy_hash", required=False),
        ),
    ),
    MappingEntry(
        "policy.bundle_version",
        "Policy bundle version active at decision time",
        "Supports traceability of policy changes and substantial modifications.",
        (
            ptr("ledger_record", "/policy_version"),
            ptr("admission_evidence", "/policy/policy_version", required=False),
        ),
    ),
    MappingEntry(
        "decision.outcome",
        "Decision outcome",
        "Identifies admit, block, escalate, defer, or skip outcomes for monitoring.",
        (
            ptr("ledger_record", "/decision"),
            ptr("admission_evidence", "/decision/decision", required=False),
        ),
    ),
    MappingEntry(
        "decision.reason",
        "Decision reason",
        "Supports post-market and deployer monitoring of risk situations.",
        (
            ptr("ledger_record", "/reason"),
            ptr("admission_evidence", "/decision/reason", required=False),
            ptr("selected_warrant", "/policy_reasons", required=False),
        ),
    ),
    MappingEntry(
        "approval.human_identity",
        "Human approver identity",
        "Identifies natural persons involved in verification where escalated actions use "
        "approvals.",
        (ptr("approval_receipt", "/approver_id"),),
        default_coverage="partial",
        note="Only escalated actions with approval receipts have this field.",
    ),
    MappingEntry(
        "approval.receipt",
        "Approval receipt",
        "Binds escalated action verification to an approval artifact.",
        (
            ptr("approval_receipt", "/approval_receipt_id"),
            ptr("approval_receipt", "/receipt_hash"),
            ptr("approval_receipt", "/signature"),
        ),
        default_coverage="partial",
        note="Only escalated actions with approval receipts have this field.",
    ),
    MappingEntry(
        "authority.before",
        "Budget or authority state before decision",
        "Supports operational monitoring of authority consumption.",
        (
            ptr("admission_evidence", "/authority/authority_budget_before"),
            ptr("selected_warrant", "/authority_budget_before", required=False),
        ),
        default_coverage="partial",
        note="Router-pricing vault records may not include ledger budget counters.",
    ),
    MappingEntry(
        "authority.after",
        "Budget or authority state after decision",
        "Supports operational monitoring of authority consumption.",
        (
            ptr("admission_evidence", "/authority/authority_budget_after"),
            ptr("selected_warrant", "/authority_budget_after", required=False),
        ),
        default_coverage="partial",
        note="Router-pricing vault records may not include ledger budget counters.",
    ),
    MappingEntry(
        "ledger.sequence",
        "Ledger sequence",
        "Supports lifetime ordering and completeness checks.",
        (
            ptr("ledger_record", "/sequence_number"),
            ptr("admission_evidence", "/ledger_state/sequence_number", required=False),
        ),
    ),
    MappingEntry(
        "ledger.predecessor",
        "Ledger predecessor",
        "Binds each record to its predecessor in the ledger chain.",
        (
            ptr("ledger_record", "/previous_record_hash"),
            ptr("admission_evidence", "/ledger_state/previous_record_hash", required=False),
            ptr("admission_evidence", "/ledger_state/previous_frame_hash", required=False),
        ),
    ),
    MappingEntry(
        "sth.coverage",
        "Signed tree head covering the record set",
        "Supports completeness and mutation detection for the selected record set.",
        (
            ptr("sth", "/root_hash"),
            ptr("sth", "/ledger_segment/first_sequence"),
            ptr("sth", "/ledger_segment/last_sequence"),
            ptr("sth", "/signature"),
        ),
    ),
    MappingEntry(
        "replay.verification_status",
        "Replay verification status",
        "Records whether offline verification passed during pack generation.",
        (
            ptr("verification_report", "/status"),
            ptr("verification_report", "/checks"),
        ),
    ),
    MappingEntry(
        "verification.natural_person_identity",
        "Natural person verifier identity",
        "Article 19-adjacent identification of natural persons involved in verification "
        "where applicable.",
        (),
        default_coverage="not_evidenced",
        not_evidenced_by_velvet=True,
        note=(
            "Vault verification reports identify cryptographic checks, not the person "
            "running them."
        ),
    ),
    MappingEntry(
        "biometric.reference_database",
        "Remote biometric reference database",
        "Specialized Article 12 logging element for remote biometric identification systems.",
        (),
        default_coverage="not_evidenced",
        not_evidenced_by_velvet=True,
        note=(
            "Velvet vault admission records do not evidence biometric reference database "
            "searches."
        ),
    ),
)


def mapping_table_json() -> list[JsonObject]:
    return [entry.to_dict() for entry in FIELD_MAPPINGS]


def build_coverage_report(
    *,
    records: Sequence[Mapping[str, Any]],
    sth: Mapping[str, Any],
    verification_report: Mapping[str, Any],
    deployment_metadata: Mapping[str, Any],
    approval_receipts: Sequence[Mapping[str, Any]] = (),
) -> JsonObject:
    """Evaluate mapping coverage against a concrete pack input set."""

    artifacts = {
        "sth": [sth],
        "verification_report": [verification_report],
        "deployment_metadata": [deployment_metadata],
        "approval_receipt": list(approval_receipts),
    }
    entries: list[JsonObject] = []
    totals = {"evidenced": 0, "partially_evidenced": 0, "not_evidenced": 0}
    not_evidenced: list[JsonObject] = []
    for mapping in FIELD_MAPPINGS:
        evaluated = _evaluate_mapping(mapping, records=records, artifacts=artifacts)
        entries.append(evaluated)
        status = str(evaluated["coverage"])
        if status == "evidenced":
            totals["evidenced"] += 1
        elif status == "partial":
            totals["partially_evidenced"] += 1
        else:
            totals["not_evidenced"] += 1
            not_evidenced.append(evaluated)
    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "mapping_schema_version": MAPPING_SCHEMA_VERSION,
        "notice": ARTICLE_12_BOUNDARY_NOTICE,
        "summary": totals,
        "not_evidenced_by_velvet": not_evidenced,
        "fields": entries,
    }


def _evaluate_mapping(
    mapping: MappingEntry,
    *,
    records: Sequence[Mapping[str, Any]],
    artifacts: Mapping[str, Sequence[Mapping[str, Any]]],
) -> JsonObject:
    if mapping.not_evidenced_by_velvet:
        return {
            **mapping.to_dict(),
            "coverage": "not_evidenced",
            "matches": [],
            "missing": [pointer.to_dict() for pointer in mapping.pointers],
        }
    matches: list[JsonObject] = []
    missing: list[JsonObject] = []
    for pointer in mapping.pointers:
        targets = _targets_for_pointer(pointer, records=records, artifacts=artifacts)
        if not targets:
            if pointer.required:
                missing.append(pointer.to_dict())
            continue
        resolved = [
            {
                "artifact_index": index,
                "value_present": _resolve_json_pointer(target, pointer.pointer)[0],
            }
            for index, target in enumerate(targets)
        ]
        present_count = sum(1 for item in resolved if item["value_present"])
        if present_count:
            matches.append(
                {
                    **pointer.to_dict(),
                    "present": present_count,
                    "checked": len(targets),
                }
            )
        if pointer.required and present_count < len(targets):
            missing.append(
                {
                    **pointer.to_dict(),
                    "present": present_count,
                    "checked": len(targets),
                }
            )
    if not mapping.pointers or (missing and not matches):
        coverage: Coverage = "not_evidenced"
    elif missing or mapping.default_coverage == "partial":
        coverage = "partial"
    else:
        coverage = "evidenced"
    return {
        **mapping.to_dict(),
        "coverage": coverage,
        "matches": matches,
        "missing": missing,
    }


def _targets_for_pointer(
    pointer: EvidencePointer,
    *,
    records: Sequence[Mapping[str, Any]],
    artifacts: Mapping[str, Sequence[Mapping[str, Any]]],
) -> Sequence[Mapping[str, Any]]:
    if pointer.artifact == "ledger_record":
        return records
    if pointer.artifact == "admission_evidence":
        return [
            evidence
            for record in records
            for evidence in (_mapping(record.get("admission_evidence")),)
            if evidence
        ]
    if pointer.artifact == "selected_warrant":
        return [
            warrant
            for record in records
            for warrant in (_mapping(record.get("selected_warrant")),)
            if warrant
        ]
    return artifacts.get(pointer.artifact, ())


def _resolve_json_pointer(payload: Mapping[str, Any], pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, payload
    if not pointer.startswith("/"):
        return False, None
    current: Any = payload
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return current is not None, current


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
