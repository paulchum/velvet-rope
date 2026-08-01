from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from velvet.ledger import build_ledger_segment_manifest, read_ledger_records
from velvet.liability_benchmark import run_liability_benchmark
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.velvet_rope_liability import (
    ARENA_SUITE,
    PUBLIC_CLAIM_SAFE_WORDING,
    CompetitorResearchRecord,
    ResultType,
    ScenarioSpec,
    VelvetRopeSystemAdapter,
    build_optional_live_adapter_stubs,
    run_velvet_rope_liability_arena,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "velvet_rope"
ROOT = SCHEMA_DIR.parents[1]


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _ledger_schema_examples(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    ledger_path = tmp_path / "ledger.vledger"
    adapter = DirectVelvetMCPAdapter.from_list_file(ROOT / "examples" / "mcp" / "list.json")
    request = load_requests(ROOT / "examples" / "mcp" / "workflow.json")[0]
    adapter.authorize(request, ledger_path=ledger_path)
    return next(iter(read_ledger_records(ledger_path))), build_ledger_segment_manifest(ledger_path)


class _FakeTopFiveLiveAdapter:
    system_name = "OpenAI Agents SDK"
    adapter_name = "openai_agents_sdk_live"
    adapter_version = "test"
    result_type: ResultType = "live"

    def __init__(self, *, can_run: bool) -> None:
        self._can_run = can_run

    def can_run_live(self) -> bool:
        return self._can_run

    def classify_missing_artifacts(self) -> tuple[str, ...]:
        return ("warrant", "seal", "replay")

    def run_scenario(self, scenario: ScenarioSpec, output_path: Path) -> dict[str, Any]:
        _ = (scenario, output_path)
        return {
            "final_response": "Task completed by fake live adapter.",
            "action_attempted": True,
            "action_admitted": True,
            "action_executed": True,
            "latency_ms": 1,
            "candidate_actions": [],
            "admission_decisions": [],
            "execution_contexts": [],
            "warrants": [],
            "seals": [],
        }

    def research_record(self) -> CompetitorResearchRecord:
        result_type: ResultType = "live" if self._can_run else "not_run"
        return CompetitorResearchRecord(
            self.system_name,
            "agent_framework",
            "https://openai.github.io/openai-agents-python/",
            (
                "https://openai.github.io/openai-agents-python/",
                "https://openai.github.io/openai-agents-python/human_in_the_loop/",
            ),
            "live" if self._can_run else "not_run",
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            "partial",
            result_type,
            self.classify_missing_artifacts(),
            ("Missing Warrant", "Missing Seal", "Missing Replay"),
            "internal_only",
            "Fake top-five adapter used to test live-run normalization.",
        )


def test_velvet_rope_arena_emits_required_artifacts(tmp_path: Path) -> None:
    payload = run_velvet_rope_liability_arena(tmp_path)

    expected = {
        "run_manifest.json",
        "query_traces.jsonl",
        "summary.json",
        "failure_cards.jsonl",
        "result_failure_bindings.jsonl",
        "competitor_results.json",
        "auditability_report.md",
        "liability_benchmark.md",
        "eval/index.html",
    }
    assert expected.issubset({str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")})
    assert payload["suite"] == ARENA_SUITE

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["result_integrity_status"] == "valid"
    assert "Task success does not offset" in summary["task_success_does_not_offset"]
    assert len(summary["real_world_incidents"]) >= 4


def test_velvet_native_path_has_warrant_seal_and_no_action_integrity_failures(
    tmp_path: Path,
) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    traces = _jsonl(tmp_path / "query_traces.jsonl")
    native = [trace for trace in traces if trace["system_name"] == "Velvet native gate"]

    assert native
    assert all(trace["auditability_status"] == "full" for trace in native)
    assert all(not trace["invariant_violations"] for trace in native)
    assert all(trace["candidate_actions"] for trace in native)
    assert all(trace["admission_decisions"] for trace in native)
    assert all(
        decision["gate_name"] == "Velvet Rope"
        for trace in native
        for decision in trace["admission_decisions"]
    )
    assert any(trace["warrants"] for trace in native)
    assert any(trace["seals"] for trace in native)
    assert any(trace["final_response"] == "denied_at_rope" for trace in native)


def test_hidden_tool_refusal_and_posthoc_paths_are_bound_to_failures(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    bindings = _jsonl(tmp_path / "result_failure_bindings.jsonl")
    by_class = {binding["failure_class"] for binding in bindings}

    assert "Hidden Tool Call Before Refusal" in by_class
    assert "Final Refusal Did Not Undo Execution" in by_class
    assert "Post-Hoc Warrant Laundering" in by_class
    assert "Action Executed Without Warrant" in by_class


def test_result_integrity_binds_every_nonzero_metric(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    competitor_results = json.loads(
        (tmp_path / "competitor_results.json").read_text(encoding="utf-8")
    )["results"]
    bindings = _jsonl(tmp_path / "result_failure_bindings.jsonl")
    counts = Counter((binding["system_name"], binding["metric_name"]) for binding in bindings)

    for result in competitor_results:
        for metric in result["nonzero_liability_metrics"]:
            key = (result["system_name"], metric["metric_name"])
            assert counts[key] == metric["count"]
        if result["nonzero_liability_metrics"]:
            assert result["bound_failure_ids"]
        assert result["result_integrity_status"] == "valid"


def test_issue_based_safety_verdicts_label_non_native_results(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    results = json.loads((tmp_path / "competitor_results.json").read_text(encoding="utf-8"))[
        "results"
    ]
    native = next(result for result in results if result["system_name"] == "Velvet native gate")

    assert native["safety_status"] == "safe_for_consequential_action"
    assert native["unsafe_issue"] == "none"
    for result in results:
        assert result["evidence_boundary"] == result["result_type"]
        assert result["unsafe_explanation"]
        if result["system_name"] == "Velvet native gate":
            continue
        assert result["safety_status"] == "unsafe_for_consequential_action"
        assert result["unsafe_issue"] != "none"


def test_real_world_incident_pack_is_source_grounded(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    incidents = summary["real_world_incidents"]

    assert {incident["unsafe_issue"] for incident in incidents} >= {
        "unauthorized_destructive_action",
        "stale_policy_snapshot",
        "jurisdiction_mismatch",
        "prompt_policy_bypass",
    }
    assert all(incident["source_url"].startswith("https://") for incident in incidents)
    assert all(incident["real_world_implication"] for incident in incidents)


def test_failure_cards_are_deterministic(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path / "one")
    run_velvet_rope_liability_arena(tmp_path / "two")

    one = {
        card["failure_card_id"]: card["failure_fingerprint"]
        for card in _jsonl(tmp_path / "one" / "failure_cards.jsonl")
    }
    two = {
        card["failure_card_id"]: card["failure_fingerprint"]
        for card in _jsonl(tmp_path / "two" / "failure_cards.jsonl")
    }
    assert one == two


def test_tier_one_research_rows_are_not_live_claims(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    records = _jsonl(tmp_path / "competitor_research_records.jsonl")
    assert len(records) >= 10
    assert all(record["result_type"] == "trace_audit_only" for record in records)
    assert all(record["public_claim_status"] == "internal_only" for record in records)
    assert all(record["auditability_grade"] in {"partial", "non_auditable"} for record in records)


def test_suite_dispatch_keeps_velvet_rope_separate(tmp_path: Path) -> None:
    payload = run_liability_benchmark(tmp_path, suite=ARENA_SUITE)
    assert payload["suite"] == ARENA_SUITE
    assert Path(payload["summary_path"]).exists()


def test_every_velvet_rope_schema_validates_generated_artifacts(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    traces = _jsonl(tmp_path / "query_traces.jsonl")
    native_trace = next(trace for trace in traces if trace["candidate_actions"])
    ledger_record, segment_manifest = _ledger_schema_examples(tmp_path)

    examples = {
        "admission_decision.schema.json": native_trace["admission_decisions"][0],
        "candidate_action.schema.json": native_trace["candidate_actions"][0],
        "competitor_action_result.schema.json": json.loads(
            (tmp_path / "competitor_results.json").read_text(encoding="utf-8")
        )["results"][0],
        "competitor_research_record.schema.json": _jsonl(
            tmp_path / "competitor_research_records.jsonl"
        )[0],
        "competitor_results.schema.json": json.loads(
            (tmp_path / "competitor_results.json").read_text(encoding="utf-8")
        ),
        "execution_context.schema.json": native_trace["execution_contexts"][0],
        "ledger_record.schema.json": ledger_record,
        "ledger_segment_manifest.v1.schema.json": segment_manifest,
        "result_failure_binding.schema.json": _jsonl(
            tmp_path / "result_failure_bindings.jsonl"
        )[0],
        "run_manifest.schema.json": json.loads(
            (tmp_path / "run_manifest.json").read_text(encoding="utf-8")
        ),
        "velvet_failure_card.schema.json": _jsonl(tmp_path / "failure_cards.jsonl")[0],
        "velvet_rope_run_summary.schema.json": json.loads(
            (tmp_path / "summary.json").read_text(encoding="utf-8")
        ),
        "velvet_rope_trace.schema.json": native_trace,
        "velvet_seal.schema.json": native_trace["seals"][0],
        "liability_warrant.schema.json": native_trace["warrants"][0],
    }

    schema_names = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}
    assert set(examples).issubset(schema_names)
    for schema_name, example in examples.items():
        schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        validator.check_schema(schema)
        validator.validate(example)
        corrupted = dict(example)
        corrupted.pop(schema["required"][0])
        try:
            validator.validate(corrupted)
        except ValidationError:
            pass
        else:  # pragma: no cover - assertion clarity
            raise AssertionError(f"{schema_name} accepted a missing required field")


def test_public_reports_include_required_auditability_fields(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    audit_report = (tmp_path / "auditability_report.md").read_text(encoding="utf-8")
    html_report = (tmp_path / "eval" / "index.html").read_text(encoding="utf-8")

    required_markdown = [
        "Verdict:",
        "Result type:",
        "Auditability:",
        "Safety status:",
        "Unsafe issue:",
        "Action Path Integrity:",
        "Failures:",
        "Trace hashes:",
        "### Bound Failure Table",
        "### Nonzero Metric Drilldown",
        "Task success does not offset unauthorized execution.",
    ]
    for marker in required_markdown:
        assert marker in audit_report
    assert "Nonzero Metric Drilldown" in html_report
    assert "Result type" in html_report
    assert "Auditability" in html_report


def test_public_wording_and_live_claim_boundary_are_preserved(tmp_path: Path) -> None:
    run_velvet_rope_liability_arena(tmp_path)
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    records = _jsonl(tmp_path / "competitor_research_records.jsonl")
    combined_public_text = "\n".join(
        [
            (tmp_path / "liability_benchmark.md").read_text(encoding="utf-8"),
            (tmp_path / "auditability_report.md").read_text(encoding="utf-8"),
        ]
    )

    assert summary["public_claim_safe_wording"] == PUBLIC_CLAIM_SAFE_WORDING
    assert all(record["result_type"] == "trace_audit_only" for record in records)
    assert "Competitor X failed" not in combined_public_text
    assert "Velvet beats" not in combined_public_text
    assert "All competitors are liabilities" not in combined_public_text
    assert "unsafe action paths by issue" in combined_public_text


def test_optional_live_adapter_stubs_are_not_run_by_default() -> None:
    records = [stub.research_record() for stub in build_optional_live_adapter_stubs()]
    names = {stub.system_name for stub in build_optional_live_adapter_stubs()}

    assert names == {
        "OpenAI Agents SDK",
        "LangGraph / LangChain agents",
        "CrewAI",
        "LlamaIndex agents/workflows",
        "n8n AI agents/workflows",
    }
    assert records
    assert all(record.result_type == "not_run" for record in records)
    assert all(record.public_claim_status == "internal_only" for record in records)
    assert all("warrant" in record.missing_artifacts for record in records)


def test_live_mode_binds_missing_exact_contract_to_live_failures(tmp_path: Path) -> None:
    adapter: VelvetRopeSystemAdapter = _FakeTopFiveLiveAdapter(can_run=True)
    run_velvet_rope_liability_arena(
        tmp_path,
        live_competitors=True,
        live_adapters=[adapter],
    )

    results = json.loads((tmp_path / "competitor_results.json").read_text(encoding="utf-8"))[
        "results"
    ]
    result = next(item for item in results if item["system_name"] == "OpenAI Agents SDK")
    records = _jsonl(tmp_path / "competitor_research_records.jsonl")
    record = next(item for item in records if item["system_name"] == "OpenAI Agents SDK")

    assert result["result_type"] == "live"
    assert result["safety_status"] == "unsafe_for_consequential_action"
    assert result["unsafe_issue"] == "missing_pre_execution_warrant"
    assert result["bound_failure_ids"]
    assert result["public_claim_status"] == "draft_requires_legal_review"
    assert "In this live run" in result["unsafe_explanation"]
    assert record["result_type"] == "live"


def test_live_mode_not_run_does_not_manufacture_failures(tmp_path: Path) -> None:
    adapter: VelvetRopeSystemAdapter = _FakeTopFiveLiveAdapter(can_run=False)
    run_velvet_rope_liability_arena(
        tmp_path,
        live_competitors=True,
        live_adapters=[adapter],
    )

    results = json.loads((tmp_path / "competitor_results.json").read_text(encoding="utf-8"))[
        "results"
    ]
    result = next(item for item in results if item["system_name"] == "OpenAI Agents SDK")
    records = _jsonl(tmp_path / "competitor_research_records.jsonl")
    record = next(item for item in records if item["system_name"] == "OpenAI Agents SDK")

    assert result["result_type"] == "not_run"
    assert result["safety_status"] == "insufficient_evidence"
    assert result["unsafe_issue"] == "not_run"
    assert result["bound_failure_ids"] == []
    assert result["nonzero_liability_metrics"] == []
    assert record["result_type"] == "not_run"
