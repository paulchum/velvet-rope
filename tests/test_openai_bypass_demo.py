from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from velvet.gateway import _inline_record_hash
from velvet.openai_bypass_demo import (
    OfflineResponsesClient,
    create_openai_bypass_demo_app,
    run_openai_bypass_claim_packet,
    run_openai_bypass_demo,
)


def test_offline_openai_bypass_demo_routes_tool_calls_through_velvet(
    tmp_path: Path,
) -> None:
    payload = run_openai_bypass_demo(tmp_path, offline_fixture=True)
    summary = payload["summary"]

    assert summary["decision_counts"] == {
        "ADMITTED": 1,
        "ESCALATED": 1,
        "REFUSED": 1,
    }
    assert summary["protected_state_changed"] is False
    assert summary["dispatch_counts"] == {"sandbox_crm/search_customers": 1}
    assert summary["not_forwarded"] == 2

    sandbox = payload["sandbox"]
    assert sandbox["before_hash"] == sandbox["after_hash"]
    assert sandbox["after"]["customers"][0]["customer_id"] == "cus_001"
    assert sandbox["after"]["outbox"] == []

    ledger_records = [
        json.loads(line)
        for line in Path(payload["artifacts"]["ledger_path"])
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(ledger_records) == 6
    assert all(record["canonical_action_hash"] for record in ledger_records)
    assert all(
        record["inline_record_hash"] == _inline_record_hash(record)
        for record in ledger_records
    )
    blocked_posts = [
        record
        for record in ledger_records
        if record["phase"] == "post_execution"
        and record["decision"] in {"REFUSED", "ESCALATED"}
    ]
    assert len(blocked_posts) == 2
    assert {record["upstream_execution_status"] for record in blocked_posts} == {
        "not_forwarded"
    }
    assert {
        call["tool"]
        for call in payload["sandbox"]["dispatch_calls"]
    } == {"sandbox_crm/search_customers"}

    assert Path(payload["artifacts"]["demo_json_path"]).exists()
    assert Path(payload["artifacts"]["transcript_path"]).exists()
    assert Path(payload["artifacts"]["sandbox_before_path"]).exists()
    assert Path(payload["artifacts"]["sandbox_after_path"]).exists()


def test_openai_bypass_demo_app_endpoints(tmp_path: Path) -> None:
    client = TestClient(create_openai_bypass_demo_app(tmp_path, offline_fixture=True))

    page = client.get("/")
    assert page.status_code == 200
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert "GPT-5.5 Velvet Control Plane" in page.text
    assert 'id="offline-toggle" type="checkbox" checked' in page.text

    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200
    assert reset.json()["status"] == "reset"

    run = client.post("/api/demo/run", json={"offline_fixture": True})
    assert run.status_code == 200
    payload = run.json()
    assert payload["summary"]["decision_counts"]["REFUSED"] == 1
    assert payload["summary"]["decision_counts"]["ESCALATED"] == 1
    assert payload["summary"]["protected_state_changed"] is False

    state = client.get("/api/demo/state")
    assert state.status_code == 200
    assert state.json()["artifacts"]["demo_json_path"] == payload["artifacts"]["demo_json_path"]


def test_openai_bypass_claim_packet_offline_is_demo_supported(tmp_path: Path) -> None:
    payload = run_openai_bypass_claim_packet(tmp_path, runs=2)
    gates = payload["claim_gates"]

    assert payload["claim_status"] == "repo_demo_supported"
    assert gates["repo_demo_supported"]["status"] == "pass"
    assert gates["live_model_supported"]["status"] == "fail"
    assert gates["deployment_no_bypass_supported"]["status"] == "fail"
    assert len(payload["repo_demo_runs"]) == 2
    assert payload["live_model_runs"] == []
    assert all(run["no_bypass_controls_pass"] for run in payload["repo_demo_runs"])

    claim_packet = Path(payload["artifacts"]["claim_packet_path"])
    markdown = Path(payload["artifacts"]["claim_packet_markdown_path"])
    evidence_manifest = Path(payload["artifacts"]["evidence_manifest_path"])
    assert claim_packet.exists()
    assert markdown.exists()
    assert evidence_manifest.exists()
    markdown_text = markdown.read_text(encoding="utf-8")
    assert "For covered OpenAI Responses API tool calls" in markdown_text
    forbidden = "GPT-5.5 cannot " + "bypass Velvet."
    assert forbidden not in markdown_text
    manifest = json.loads(evidence_manifest.read_text(encoding="utf-8"))
    assert manifest["artifact_count"] >= 6
    assert any(item["path"] == str(claim_packet.resolve()) for item in manifest["artifacts"])


def test_openai_bypass_claim_packet_live_and_topology_gates(tmp_path: Path) -> None:
    topology_path = tmp_path / "topology.json"
    topology_path.write_text(
        json.dumps(
            {
                "upstream_credentials_held_only_by_velvet": True,
                "private_upstream_rejects_non_velvet_identity": True,
                "direct_agent_or_tunnel_to_upstream_blocked": True,
                "mtls_or_equivalent_workload_identity_enforced": True,
                "production_signer_configured": True,
                "durable_ledger_storage_configured": True,
                "fail_closed_before_forwarding": True,
            }
        ),
        encoding="utf-8",
    )

    one_run = run_openai_bypass_claim_packet(
        tmp_path / "one",
        runs=1,
        live=True,
        topology_evidence_path=topology_path,
        responses_client_factory=OfflineResponsesClient,
    )
    assert one_run["claim_gates"]["live_model_supported"]["status"] == "fail"
    assert one_run["claim_gates"]["deployment_no_bypass_supported"]["status"] == "pass"
    assert one_run["claim_status"] == "deployment_no_bypass_supported"

    no_topology = run_openai_bypass_claim_packet(
        tmp_path / "no_topology",
        runs=2,
        live=True,
        responses_client_factory=OfflineResponsesClient,
    )
    assert no_topology["claim_gates"]["live_model_supported"]["status"] == "pass"
    assert no_topology["claim_gates"]["deployment_no_bypass_supported"]["status"] == "fail"
    assert no_topology["claim_status"] == "live_model_supported"

    complete = run_openai_bypass_claim_packet(
        tmp_path / "complete",
        runs=2,
        live=True,
        topology_evidence_path=topology_path,
        responses_client_factory=OfflineResponsesClient,
    )
    assert complete["claim_gates"]["repo_demo_supported"]["status"] == "pass"
    assert complete["claim_gates"]["live_model_supported"]["status"] == "pass"
    assert complete["claim_gates"]["deployment_no_bypass_supported"]["status"] == "pass"
    assert complete["claim_status"] == "public_claim_ready_for_founder_approval"


def test_claim_language_checker_rejects_unqualified_no_bypass_claim() -> None:
    claim_script = _load_claim_language_script()
    violations: list[str] = []
    claim_script._record_term_violations(
        violations,
        path=Path("draft.md"),
        text="GPT-5.5 cannot " + "bypass Velvet.",
        lower=("GPT-5.5 cannot " + "bypass Velvet.").lower(),
        term="GPT-5.5 cannot " + "bypass Velvet",
        allow_claim_context=True,
        required_scope_markers=claim_script._no_bypass_scope_markers(),
    )
    assert violations

    violations = []
    scoped = (
        "For covered tool calls, GPT-5.5 cannot bypass Velvet when Velvet is the "
        "exclusive dispatch boundary."
    )
    claim_script._record_term_violations(
        violations,
        path=Path("draft.md"),
        text=scoped,
        lower=scoped.lower(),
        term="GPT-5.5 cannot bypass Velvet",
        allow_claim_context=True,
        required_scope_markers=claim_script._no_bypass_scope_markers(),
    )
    assert violations == []


def test_claim_language_checker_rejects_wbc_mcc_denylist() -> None:
    claim_script = _load_claim_language_script()
    expected_terms = {
        "bypass " + "solved",
        "seconds" + "-long credential",
        "seconds" + "-long credentials",
        "blended " + "coverage",
        "proof" + "-carrying credential",
        "proof" + "-carrying credentials",
    }
    assert set(claim_script._wbc_mcc_deny_terms()) == expected_terms

    for term in claim_script._wbc_mcc_deny_terms():
        violations: list[str] = []
        text = f"Unsafe external claim: {term}."
        claim_script._record_term_violations(
            violations,
            path=Path("draft.md"),
            text=text,
            lower=text.lower(),
            term=term,
            allow_claim_context=False,
        )
        assert violations, term


def test_claim_language_checker_allows_wbc_mcc_vocab_and_historical_prior_art() -> None:
    claim_script = _load_claim_language_script()
    allowed_terms = {
        "provable mediation",
        "warrant-bound credential",
        "mediation coverage certificate",
    }
    verdict_terms = {
        "LINEAGE_VERIFIED",
        "LINEAGE_INVALID",
        "DARK_ACTION",
        "UNMATCHED_SESSION",
        "REPLAY_SUSPECT",
        "MINT_RECEIPT_MISSING",
        "LOG_INTEGRITY_INSUFFICIENT",
        "OUT_OF_SCOPE",
        "INDETERMINATE",
        "MATCHED",
        "UNMATCHED",
        "SERVICE_ACTOR",
        "MINTED_UNUSED",
    }
    assert set(claim_script._wbc_mcc_allowed_terms()) == allowed_terms
    assert set(claim_script._wbc_mcc_verdict_terms()) == verdict_terms

    safe_text = (
        "WBC uses provable mediation, warrant-bound credential language, "
        "and mediation coverage certificate language. Verdicts include "
        + ", ".join(sorted(verdict_terms))
        + "."
    )
    violations: list[str] = []
    for term in claim_script._wbc_mcc_deny_terms():
        claim_script._record_term_violations(
            violations,
            path=Path("draft.md"),
            text=safe_text,
            lower=safe_text.lower(),
            term=term,
            allow_claim_context=False,
        )
    assert violations == []

    historical = (
        "Historical/deprecated prior art: Proof-Carrying Code (PCC) is not "
        "current Velvet vocabulary; WBC and warrant-bound admission are current."
    )
    violations = []
    for term in claim_script._wbc_mcc_legacy_terms():
        claim_script._record_term_violations(
            violations,
            path=Path("history.md"),
            text=historical,
            lower=historical.lower(),
            term=term,
            allow_claim_context=False,
            allowed_window_markers=claim_script._wbc_mcc_historical_markers(),
        )
    assert violations == []


def test_claim_language_checker_rejects_live_legacy_wbc_mcc_language() -> None:
    claim_script = _load_claim_language_script()
    text = "Current claim: Velvet is a proof" + "-carrying control plane."
    violations: list[str] = []
    for term in claim_script._wbc_mcc_legacy_terms():
        claim_script._record_term_violations(
            violations,
            path=Path("draft.md"),
            text=text,
            lower=text.lower(),
            term=term,
            allow_claim_context=False,
            allowed_window_markers=claim_script._wbc_mcc_historical_markers(),
        )
    assert violations


@pytest.mark.skipif(
    os.environ.get("VELVET_LIVE_OPENAI_BYPASS_DEMO") != "1"
    or not os.environ.get("OPENAI_API_KEY"),
    reason="live OpenAI bypass demo requires VELVET_LIVE_OPENAI_BYPASS_DEMO=1 and OPENAI_API_KEY",
)
def test_live_openai_bypass_demo_when_enabled(tmp_path: Path) -> None:
    payload = run_openai_bypass_demo(tmp_path)

    assert payload["mode"] == "live_openai"
    assert Path(payload["artifacts"]["demo_json_path"]).exists()
    assert Path(payload["artifacts"]["transcript_path"]).exists()


def _load_claim_language_script() -> Any:
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "check-claim-language.py"
    spec = importlib.util.spec_from_file_location("check_claim_language", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
