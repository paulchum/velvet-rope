"""Replay historical threads against a policy bundle without mutating ledgers."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from velvet.ledger import read_ledger_records
from velvet.policy_bundle import VerifiedPolicyBundle, load_policy_bundle
from velvet.router import Router
from velvet.thread_log import ThreadLogger
from velvet.types import ThreadCandidateAction, ThreadRecord

JsonObject = dict[str, Any]

POLICY_SIMULATION_SCHEMA_VERSION = "velvet.policy_simulation.v1"


@dataclass(frozen=True)
class PolicySimulationDelta:
    thread_id: str
    seal_id: str
    previous_action: str | None
    simulated_action: str | None
    previous_decision: str
    simulated_decision: str
    previous_reason: str
    simulated_reason: str
    previous_policy_hash: str | None = None
    simulated_policy_hash: str | None = None

    @property
    def changed(self) -> bool:
        return (
            self.previous_action != self.simulated_action
            or self.previous_decision != self.simulated_decision
        )

    @property
    def policy_hash_changed(self) -> bool:
        previous = _normalize_policy_hash(self.previous_policy_hash)
        simulated = _normalize_policy_hash(self.simulated_policy_hash)
        return (
            previous is not None
            and simulated is not None
            and previous != simulated
        )

    def to_dict(self) -> JsonObject:
        return {
            "thread_id": self.thread_id,
            "seal_id": self.seal_id,
            "previous_action": self.previous_action,
            "simulated_action": self.simulated_action,
            "previous_decision": self.previous_decision,
            "simulated_decision": self.simulated_decision,
            "previous_reason": self.previous_reason,
            "simulated_reason": self.simulated_reason,
            "changed": self.changed,
            "previous_policy_hash": self.previous_policy_hash,
            "simulated_policy_hash": self.simulated_policy_hash,
            "policy_hash_changed": self.policy_hash_changed,
        }


@dataclass(frozen=True)
class PolicySimulationReport:
    thread_path: str
    policy_dir: str
    chain: str
    generated_at: str
    deltas: tuple[PolicySimulationDelta, ...]
    ledger_path: str | None = None
    policy_hash: str | None = None
    policy_version: str | None = None
    schema_version: str = POLICY_SIMULATION_SCHEMA_VERSION

    def to_dict(self) -> JsonObject:
        decision_counts = Counter(delta.simulated_decision for delta in self.deltas)
        changed = sum(1 for delta in self.deltas if delta.changed)
        policy_hash_changed = sum(1 for delta in self.deltas if delta.policy_hash_changed)
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "thread_path": self.thread_path,
            "ledger_path": self.ledger_path,
            "policy_dir": self.policy_dir,
            "chain": self.chain,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "summary": {
                "threads": len(self.deltas),
                "changed": changed,
                "unchanged": len(self.deltas) - changed,
                "policy_hash_changed": policy_hash_changed,
                "simulated_decision_counts": dict(sorted(decision_counts.items())),
            },
            "deltas": [delta.to_dict() for delta in self.deltas],
        }


def simulate_policy(
    thread_path: str | Path,
    *,
    policy_dir: str = "policies",
    chain: str = "default",
    policy_bundle: str | Path | VerifiedPolicyBundle | None = None,
    policy_bundle_signing_key: str | None = None,
    ledger_path: str | Path | None = None,
) -> PolicySimulationReport:
    verified_bundle = _resolve_policy_bundle(
        policy_bundle,
        signing_key=policy_bundle_signing_key,
    )
    if verified_bundle is not None:
        policy_dir = str(verified_bundle.materialize_policy_dir())
        chain = verified_bundle.policy_chain
    ledger_index = _ledger_policy_hash_index(ledger_path)
    router = Router(policy_dir=policy_dir, chain=chain)
    deltas: list[PolicySimulationDelta] = []
    for raw in ThreadLogger.read(thread_path):
        record = ThreadRecord.from_dict(raw)
        previous_policy_hash = ledger_index.get(record.seal_id)
        simulated = router.decide(record.state, record.raw_candidates)
        simulated_payload = simulated.to_dict()
        deltas.append(
            PolicySimulationDelta(
                thread_id=record.thread_id,
                seal_id=record.seal_id,
                previous_action=record.selected_action.value
                if record.selected_action is not None
                else None,
                simulated_action=simulated_payload.get("action_type"),
                previous_decision=_record_decision(record),
                simulated_decision=str(simulated_payload["decision"]),
                previous_reason=_record_reason(record),
                simulated_reason=str(simulated_payload["reason"]),
                previous_policy_hash=previous_policy_hash,
                simulated_policy_hash=verified_bundle.policy_hash
                if verified_bundle is not None
                else None,
            )
        )
    return PolicySimulationReport(
        thread_path=str(thread_path),
        policy_dir=policy_dir,
        chain=chain,
        generated_at=datetime.now(tz=UTC).isoformat(),
        deltas=tuple(deltas),
        ledger_path=str(ledger_path) if ledger_path is not None else None,
        policy_hash=verified_bundle.policy_hash if verified_bundle is not None else None,
        policy_version=verified_bundle.policy_version if verified_bundle is not None else None,
    )


def render_policy_simulation_markdown(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Velvet Policy Simulation",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Thread file: `{report['thread_path']}`",
        f"Policy: `{report['policy_dir']}` / `{report['chain']}`",
        f"Policy hash: `{report.get('policy_hash')}`",
        "",
        "## Summary",
        "",
        f"- Threads: `{summary['threads']}`",
        f"- Changed decisions: `{summary['changed']}`",
        f"- Policy hash changes: `{summary.get('policy_hash_changed', 0)}`",
        f"- Unchanged decisions: `{summary['unchanged']}`",
        "- Simulated decisions: "
        f"`{json.dumps(summary['simulated_decision_counts'], sort_keys=True)}`",
        "",
        "## Deltas",
        "",
    ]
    for delta in report["deltas"]:
        lines.extend(
            [
                f"### `{delta['seal_id']}`",
                "",
                f"- Changed: `{delta['changed']}`",
                f"- Previous: `{delta['previous_decision']}` / `{delta['previous_action']}`",
                f"- Simulated: `{delta['simulated_decision']}` / `{delta['simulated_action']}`",
                f"- Policy hash changed: `{delta.get('policy_hash_changed')}`",
                f"- Reason: {delta['simulated_reason']}",
                "",
            ]
        )
    return "\n".join(lines)


def write_policy_simulation_report(
    thread_path: str | Path,
    *,
    policy_dir: str = "policies",
    chain: str = "default",
    policy_bundle: str | Path | VerifiedPolicyBundle | None = None,
    policy_bundle_signing_key: str | None = None,
    ledger_path: str | Path | None = None,
    output_dir: str | Path,
) -> tuple[Path, Path, PolicySimulationReport]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = simulate_policy(
        thread_path,
        policy_dir=policy_dir,
        chain=chain,
        policy_bundle=policy_bundle,
        policy_bundle_signing_key=policy_bundle_signing_key,
        ledger_path=ledger_path,
    )
    json_path = destination / "policy_simulation.json"
    markdown_path = destination / "policy_simulation.md"
    payload = report.to_dict()
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_policy_simulation_markdown(payload), encoding="utf-8")
    return json_path, markdown_path, report


def _resolve_policy_bundle(
    policy_bundle: str | Path | VerifiedPolicyBundle | None,
    *,
    signing_key: str | None,
) -> VerifiedPolicyBundle | None:
    if policy_bundle is None:
        return None
    if isinstance(policy_bundle, VerifiedPolicyBundle):
        return policy_bundle
    return load_policy_bundle(policy_bundle, signing_key=signing_key)


def _normalize_policy_hash(value: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.removeprefix("sha256:")
    if len(normalized) == 64 and all(character in "0123456789abcdef" for character in normalized):
        return f"sha256:{normalized}"
    return value


def _ledger_policy_hash_index(ledger_path: str | Path | None) -> dict[str, str]:
    if ledger_path is None or not Path(ledger_path).exists():
        return {}
    index: dict[str, str] = {}
    for record in read_ledger_records(ledger_path):
        seal_id = record.get("seal_id")
        policy_hash = record.get("policy_hash")
        if not isinstance(policy_hash, str):
            selected = record.get("selected_warrant")
            if isinstance(selected, Mapping):
                selected_hash = selected.get("policy_hash")
                policy_hash = selected_hash if isinstance(selected_hash, str) else None
        if isinstance(seal_id, str) and isinstance(policy_hash, str):
            index[seal_id] = policy_hash
    return index


def _record_decision(record: ThreadRecord) -> str:
    selected = _selected_thread_candidate(record)
    return selected.decision.value if selected is not None else "unknown"


def _record_reason(record: ThreadRecord) -> str:
    selected = _selected_thread_candidate(record)
    return selected.reason if selected is not None else "No selected candidate recorded."


def _selected_thread_candidate(record: ThreadRecord) -> ThreadCandidateAction | None:
    candidates = (
        record.scored_candidates
        or record.policy_filtered_candidates
        or record.rejected_actions
    )
    if record.selected_candidate_index is not None:
        if 0 <= record.selected_candidate_index < len(candidates):
            return candidates[record.selected_candidate_index]
    if record.selected_action is None:
        return None
    for candidate in (
        *record.scored_candidates,
        *record.policy_filtered_candidates,
        *record.rejected_actions,
    ):
        if candidate.final_action.action_type == record.selected_action:
            return candidate
    return None
