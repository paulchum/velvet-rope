"""Control-plane summary payloads for dashboard and CLI surfaces."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from velvet.agent_registry import load_agent_registry
from velvet.approvals import load_approval_snapshot
from velvet.ledger import build_velvet_ledger_report
from velvet.thread_log import ThreadLogger

JsonObject = dict[str, Any]


def build_control_plane_snapshot(
    *,
    thread_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
) -> JsonObject:
    threads = _thread_records(thread_path)
    registry = load_agent_registry(registry_path)
    approvals = load_approval_snapshot(approvals_path)
    ledger = (
        build_velvet_ledger_report(ledger_path, thread_path=thread_path)
        if ledger_path is not None and Path(ledger_path).exists()
        else None
    )
    selected_actions = Counter(str(record.get("selected_action")) for record in threads)
    return {
        "surface": "velvet_agent_ops",
        "summary": {
            "thread_records": len(threads),
            "selected_actions": dict(sorted(selected_actions.items())),
            "ledger_records": ledger["summary"]["records"] if ledger is not None else 0,
            "approval_pending": sum(
                1 for request in approvals.requests if request.status.value == "pending"
            ),
            "registry_agents": len(registry.agents) if registry is not None else 0,
            "registry_tools": len(registry.tools) if registry is not None else 0,
        },
        "registry": registry.to_dict() if registry is not None else None,
        "approvals": approvals.to_dict(),
        "ledger": ledger,
        "latest_thread": threads[-1] if threads else None,
    }


def _thread_records(path: str | Path | None) -> list[JsonObject]:
    if path is None or not Path(path).exists():
        return []
    return list(ThreadLogger.read(path))
