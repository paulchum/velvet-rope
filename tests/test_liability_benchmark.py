from __future__ import annotations

from pathlib import Path

from velvet.liability_benchmark import build_liability_cases, run_liability_benchmark
from velvet.thread_log import ThreadLogger
from velvet.types import CertificateOutcome, ThreadRecord


def test_liability_cases_cover_recovery_and_waste() -> None:
    cases = build_liability_cases()
    modes = {
        case["candidates"][1].certificate.liability_mode: case["candidates"][1].certificate
        for case in cases
        if case["candidates"][1].certificate is not None
    }

    recovery = modes["false_lockout"]
    assert recovery.outcome == CertificateOutcome.INSPECT
    assert recovery.typed_effect.mean_bound < recovery.liability_price
    assert recovery.inspection_lower_bound > recovery.liability_price

    waste = modes["certifiable_waste"]
    assert waste.outcome == CertificateOutcome.LOCKOUT
    assert waste.safe_upper_bound < waste.liability_price
    assert waste.compensator_step is not None
    assert waste.compensator_step.increment >= 0.0


def test_liability_benchmark_writes_schema_traces_and_report(tmp_path: Path) -> None:
    payload = run_liability_benchmark(tmp_path)
    thread_path = Path(payload["thread_path"])
    raw_records = list(ThreadLogger.read(thread_path))
    records = [ThreadRecord.from_dict(record) for record in raw_records]

    assert len(records) >= 10
    assert {record.schema_version for record in records} == {"9.0"}
    assert {record.evaluation_context.benchmark_suite for record in records} == {"liability"}
    assert all(record.competitor_results for record in records)
    assert payload["generated_at"] == "1970-01-01T00:00:00Z"
    assert payload["commit_hash"]

    by_mode = {
        candidate.certificate.liability_mode: (record, candidate.certificate)
        for record in records
        for candidate in (*record.scored_candidates, *record.rejected_actions)
        if candidate.certificate is not None
    }
    assert by_mode["false_lockout"][0].selected_action is not None
    assert by_mode["false_lockout"][1].outcome == CertificateOutcome.INSPECT
    assert by_mode["certifiable_waste"][1].outcome == CertificateOutcome.LOCKOUT
    markdown = Path(payload["markdown_path"]).read_text(encoding="utf-8")
    # Neutral self-measurement only — no comparative superiority claim, no legal-review flag.
    assert "self_measurement_no_comparative_claim" in markdown
    assert "only system we found" not in markdown
    assert "draft_requires_legal_review" not in markdown
    assert "## Methodology" in markdown
    assert "## Capability Matrix" in markdown
    # Not-run systems render as "not run", never as boolean failures beside Velvet.
    assert "| not run | not run | n/a | n/a | not run | not_measured |" in markdown
    assert "| False | False | n/a | n/a | False | not_measured |" not in markdown

    unsafe_issues = {
        record["state"].get("unsafe_issue")
        for record in raw_records
        if record["state"].get("unsafe_issue")
    }
    assert unsafe_issues >= {
        "unauthorized_destructive_action",
        "stale_policy_snapshot",
        "jurisdiction_mismatch",
        "prompt_policy_bypass",
        "missing_pre_execution_warrant",
    }


def test_capability_matrix_and_not_run_reasons_are_populated(tmp_path: Path) -> None:
    payload = run_liability_benchmark(tmp_path)
    raw_results = payload["competitor_results"]

    assert raw_results
    for result in raw_results:
        assert isinstance(result["emitted_decision_certificate"], bool)
        assert isinstance(result["deterministic_across_repeated_runs"], bool)
        assert isinstance(result["replayable_seal_reproduces_decision"], bool)
        facts = result["capability_facts"]
        assert facts["repeat_count"] == 3
        assert isinstance(facts["run_decisions"], list)
        assert isinstance(facts["run_successes"], list)
        assert isinstance(facts["pass_k"], dict)
        if result["status"] == "not_run":
            assert result["not_run_reason"]
            assert result["not_run_reason"].startswith("not run: missing ")

    matrix_by_system = {row["system"]: row for row in payload["capability_matrix"]}
    expected_systems = {
        "Velvet Certified Max-DE",
        "OpenAI Agents SDK guardrails",
        "NVIDIA NeMo Guardrails",
        "Guardrails AI",
        "Amazon Bedrock Guardrails",
        "Azure AI Content Safety",
        "Lakera Guard",
    }
    assert expected_systems.issubset(matrix_by_system)
    assert matrix_by_system["Velvet Certified Max-DE"]["emitted_decision_certificate"] is True
    assert (
        matrix_by_system["Velvet Certified Max-DE"]["replayable_seal_reproduces_decision"]
        is True
    )
    assert matrix_by_system["Velvet Certified Max-DE"]["pass_k_reliability"]["1"] == 1.0
    for system in expected_systems - {"Velvet Certified Max-DE"}:
        if matrix_by_system[system]["measurement_status"] == "not_measured":
            assert matrix_by_system[system]["not_run_reasons"]
