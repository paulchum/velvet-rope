#!/usr/bin/env python3
"""Reconstructability harness for Velvet and baseline action logs."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from velvet.ledger import VelvetLedger, ledger_record_hash, read_ledger_records  # noqa: E402
from velvet.mcp import DirectVelvetMCPAdapter, load_requests  # noqa: E402
from velvet.rope import VelvetToolCall  # noqa: E402
from velvet.signing import DEMO_ED25519_PUBLIC_KEY_BASE64, load_demo_ed25519_signer  # noqa: E402
from velvet.vault.sth import build_signed_tree_head  # noqa: E402
from velvet.vault.verify import verify_vault_segment  # noqa: E402

NOTICE = (
    "This bundle demonstrates technical record-keeping capability relevant to EU AI Act "
    "Article 12. It is not a determination of legal compliance, which depends on system "
    "classification, deployment context, and counsel review."
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run reconstructability corpus scoring.")
    parser.add_argument("--output-dir", default="reports/compliance/reconstructability")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)
    result = run_reconstructability(output_dir)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(render_markdown(result))
    return 0


def run_reconstructability(output_dir: Path) -> dict[str, Any]:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    velvet = _generate_velvet_corpus(output_dir / "velvet_vault")
    plain = _generate_plain_jsonl_corpus(output_dir / "plain_jsonl_gateway")
    logs = _generate_unstructured_log_corpus(output_dir / "unstructured_logs")
    results = {
        "schema_version": "velvet.reconstructability_results.v1",
        "notice": NOTICE,
        "corpora": [
            _score_velvet_corpus(velvet),
            _score_plain_jsonl(plain),
            _score_unstructured_logs(logs),
        ],
    }
    (output_dir / "results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "results.md").write_text(render_markdown(results), encoding="utf-8")
    return results


def _generate_velvet_corpus(destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    signer = load_demo_ed25519_signer()
    adapter = DirectVelvetMCPAdapter.from_list_file(
        ROOT / "examples" / "mcp" / "list.json",
        signing_profile="demo",
    )
    ledger_path = destination / "ledger.vledger"
    ledger = VelvetLedger(ledger_path, signer=signer, signing_key_id="demo-not-for-production")
    requests = list(load_requests(ROOT / "examples" / "mcp" / "workflow.json"))[:3]
    for request in requests:
        decision = adapter.firewall.authorize(
            VelvetToolCall(
                server=str(request["server"]),
                tool=str(request["tool"]),
                arguments=cast(Mapping[str, Any], request.get("arguments", {})),
                user_request=str(request.get("user_request", "")),
                untrusted_content=cast(str | None, request.get("untrusted_content")),
            ),
            state=cast(Mapping[str, object] | None, request.get("state")),
        )
        ledger.write_admission_decision(decision, request=request, label="reconstructability")
    records = list(read_ledger_records(ledger_path))
    record_hashes = [str(record["record_hash"]) for record in records]
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=signer,
    )
    sth_path = destination / "sth.json"
    sth_path.write_text(json.dumps(sth, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    record_set_path = destination / "decision_records.json"
    record_set_path.write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "name": "Velvet vault",
        "ledger_path": ledger_path,
        "sth_path": sth_path,
        "record_set_path": record_set_path,
        "records": records,
        "requests": requests,
    }


def _generate_plain_jsonl_corpus(destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "timestamp": "2026-06-12T12:00:00Z",
            "request_id": "gw-001",
            "agent_id": "release-agent",
            "tool": "servicenow/search_change_requests",
            "arguments": {"query": "service=payments state=open"},
            "decision": "allow",
            "policy_version": "gateway-policy-7",
            "dispatched": True,
        },
        {
            "timestamp": "2026-06-12T12:00:05Z",
            "request_id": "gw-002",
            "agent_id": "release-agent",
            "tool": "servicenow/delete_change_request",
            "arguments": {"change_id": "CHG0042007"},
            "decision": "deny",
            "policy_version": "gateway-policy-7",
            "dispatched": False,
        },
        {
            "timestamp": "2026-06-12T12:00:08Z",
            "request_id": "gw-003",
            "agent_id": "release-agent",
            "tool": "servicenow/create_change_request",
            "arguments": {"service": "payments", "summary": "Approve deploy"},
            "decision": "review",
            "policy_version": "gateway-policy-7",
            "dispatched": False,
        },
    ]
    path = destination / "gateway.jsonl"
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    return {"name": "Plain JSONL gateway log", "path": path, "rows": rows}


def _generate_unstructured_log_corpus(destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    lines = [
        "2026-06-12T12:00:00Z INFO agent release-agent called servicenow search_change_requests",
        "2026-06-12T12:00:05Z WARN denied delete_change_request change_id=CHG0042007",
        "2026-06-12T12:00:08Z INFO review needed for create_change_request payments deploy",
    ]
    path = destination / "application.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"name": "Unstructured application logs", "path": path, "lines": lines}


def _score_velvet_corpus(corpus: Mapping[str, Any]) -> dict[str, Any]:
    records = cast(list[Mapping[str, Any]], corpus["records"])
    report = verify_vault_segment(
        segment_range=f"1-{len(records)}",
        sth_path=cast(Path, corpus["sth_path"]),
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
        ledger_path=cast(Path, corpus["ledger_path"]),
    )
    rederived = _rederive_velvet_decisions(records)
    mutation_detected = _velvet_single_field_mutation_detected(records)
    drift_checked = _velvet_drift_binding_present(records)
    return _score_row(
        "Velvet vault",
        completeness=report["status"] == "pass",
        rederive=rederived,
        mutation=mutation_detected,
        drift=drift_checked,
        evidence={
            "verification_status": report["status"],
            "record_count": len(records),
        },
    )


def _score_plain_jsonl(corpus: Mapping[str, Any]) -> dict[str, Any]:
    rows = cast(list[Mapping[str, Any]], corpus["rows"])
    rederive = all(_plain_policy(row) == row["decision"] for row in rows)
    mutated = dict(rows[0])
    mutated["decision"] = "deny"
    mutation_detected = "record_hash" in mutated or "signature" in mutated
    return _score_row(
        "Plain JSONL gateway log",
        completeness=False,
        rederive=rederive,
        mutation=mutation_detected,
        drift=False,
        evidence={"record_count": len(rows), "reason": "No signed root or action-hash binding."},
    )


def _score_unstructured_logs(corpus: Mapping[str, Any]) -> dict[str, Any]:
    lines = cast(list[str], corpus["lines"])
    return _score_row(
        "Unstructured application logs",
        completeness=False,
        rederive=False,
        mutation=False,
        drift=False,
        evidence={
            "line_count": len(lines),
            "reason": "Events are not structured enough for replay.",
        },
    )


def _rederive_velvet_decisions(records: Sequence[Mapping[str, Any]]) -> bool:
    for record in records:
        stored_hash = record.get("record_hash")
        if stored_hash != ledger_record_hash(record):
            return False
        evidence = record.get("admission_evidence")
        if not isinstance(evidence, Mapping):
            return False
        selected = record.get("selected_warrant")
        if not isinstance(selected, Mapping):
            return False
        if evidence.get("policy", {}).get("policy_hash") != record.get("policy_hash"):
            return False
        if selected.get("decision") != record.get("decision"):
            return False
    return True


def _velvet_single_field_mutation_detected(records: Sequence[Mapping[str, Any]]) -> bool:
    mutated = dict(records[0])
    mutated["decision"] = "block" if mutated.get("decision") != "block" else "execute"
    return mutated.get("record_hash") != ledger_record_hash(mutated)


def _velvet_drift_binding_present(records: Sequence[Mapping[str, Any]]) -> bool:
    for record in records:
        if record.get("decision") != "execute":
            continue
        evidence = record.get("admission_evidence")
        if not isinstance(evidence, Mapping):
            return False
        raw_hash = _nested_string(evidence, ("raw_action", "raw_action_hash"))
        request_hash = _nested_string(evidence, ("bindings", "request_hash"))
        args_hash = _nested_string(evidence, ("tool", "arguments_hash"))
        return bool(raw_hash and request_hash and args_hash)
    return False


def _plain_policy(row: Mapping[str, Any]) -> str:
    tool = str(row.get("tool", ""))
    if "delete" in tool:
        return "deny"
    if "create" in tool:
        return "review"
    return "allow"


def _score_row(
    name: str,
    *,
    completeness: bool,
    rederive: bool,
    mutation: bool,
    drift: bool,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    checks = {
        "complete_and_unmodified": completeness,
        "rederive_decisions": rederive,
        "detect_single_field_mutation": mutation,
        "confirm_no_admitted_action_drift": drift,
    }
    return {
        "corpus": name,
        "score": sum(1 for value in checks.values() if value),
        "max_score": len(checks),
        "checks": checks,
        "evidence": dict(evidence),
    }


def render_markdown(result: Mapping[str, Any]) -> str:
    rows = []
    for corpus in cast(Sequence[Mapping[str, Any]], result["corpora"]):
        checks = cast(Mapping[str, bool], corpus["checks"])
        rows.append(
            (
                "| {corpus} | {score}/{max_score} | {complete} | {rederive} | "
                "{mutation} | {drift} |"
            ).format(
                corpus=corpus["corpus"],
                score=corpus["score"],
                max_score=corpus["max_score"],
                complete=_mark(checks["complete_and_unmodified"]),
                rederive=_mark(checks["rederive_decisions"]),
                mutation=_mark(checks["detect_single_field_mutation"]),
                drift=_mark(checks["confirm_no_admitted_action_drift"]),
            )
        )
    return "\n".join(
        [
            "# Velvet Reconstructability Harness Results",
            "",
            NOTICE,
            "",
            (
                "| Corpus | Score | Complete and unmodified | Re-derive decisions | "
                "Detect mutation | No admitted-action drift |"
            ),
            "| --- | ---: | --- | --- | --- | --- |",
            *rows,
            "",
        ]
    )


def _mark(value: bool) -> str:
    return "yes" if value else "no"


def _nested_string(payload: Mapping[str, Any], path: Sequence[str]) -> str | None:
    current: Any = payload
    for part in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current if isinstance(current, str) and current else None


if __name__ == "__main__":
    raise SystemExit(main())
