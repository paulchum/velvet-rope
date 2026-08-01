from __future__ import annotations

import json
from pathlib import Path

from starlette.testclient import TestClient

from velvet.cli import main
from velvet.dashboard import create_app
from velvet.router import Router
from velvet.thread_log import ThreadLogger

ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_serves_thread_and_security_headers(tmp_path: Path) -> None:
    thread_path = tmp_path / "demo.jsonl"
    Router().decide(
        state={"freshness_required": True, "expected_action": "SEARCH_WEB"},
        candidates=[
            {"action_type": "ANSWER_DIRECTLY", "metadata": {"non_budget_affecting": True}},
            {"action_type": "SEARCH_WEB", "metadata": {"non_budget_affecting": True}},
            {"action_type": "ASK_USER", "metadata": {"non_budget_affecting": True}},
        ],
        thread_logger=ThreadLogger(thread_path),
    )
    client = TestClient(create_app(thread_path))
    page = client.get("/")
    assert page.status_code == 200
    assert "default-src 'self'" in page.headers["content-security-policy"]
    data = client.get("/api/thread")
    assert data.status_code == 200
    payload = data.json()
    assert payload["records"][0]["selected_action"] == "SEARCH_WEB"
    assert payload["records"][0]["scored_candidates"][1]["decision"] == "execute"
    assert payload["records"][0]["schema_version"] == "9.0"
    selected = payload["records"][0]["scored_candidates"][1]
    assert selected["admission_trace"]["selected_decision"] == "execute"
    assert selected["admission_trace_hash"].startswith("sha256:")
    assert selected["effect_vector"]["schema_version"] == "velvet.effect_vector.v1"
    assert payload["records"][0]["evaluation_context"]["expected_action"] == "SEARCH_WEB"
    vc_page = client.get("/vc-demo")
    assert vc_page.status_code == 200
    assert "Warrant-bound threshold" in vc_page.text
    assert "Evidence Review Lane" in vc_page.text
    vc_payload = client.get("/api/vc-demo")
    assert vc_payload.status_code == 200
    demo_payload = vc_payload.json()
    assert demo_payload["demos"]["mcp_block"]["decision"] == "block"
    assert (
        demo_payload["insurer_auditor_lane"]["artifacts"][0]["path"]
        == "reports/live-demo/incident/claims_pack/manifest.json"
    )


def test_cli_route(tmp_path: Path, capsys: object) -> None:
    thread_path = tmp_path / "cli.jsonl"
    assert (
        main(
            [
                "route",
                "--scenario",
                str(ROOT / "scenarios" / "freshness_required.json"),
                "--thread",
                str(thread_path),
                "--json",
            ]
        )
        == 0
    )
    route_output = capsys.readouterr().out  # type: ignore[attr-defined]
    decision = json.loads(route_output)
    assert decision["action_type"] == "SEARCH_WEB"


def test_cli_rope_returns_warrant(tmp_path: Path, capsys: object) -> None:
    thread_path = tmp_path / "rope.jsonl"
    assert (
        main(
            [
                "rope",
                "--scenario",
                str(ROOT / "scenarios" / "freshness_required.json"),
                "--thread",
                str(thread_path),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["product_surface"] == "velvet_rope"
    assert output["seal_id"].startswith("seal_")
    assert output["decision"]["action_type"] == "SEARCH_WEB"
    assert output["selected_warrant"]["final_lambda"] > 0.0


def test_cli_vc_demo_returns_demo_payload(capsys: object) -> None:
    assert main(["vc-demo", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["demos"]["rope"]["selected_warrant"]["final_lambda"] > 0.0
    assert output["demos"]["mcp_block"]["seal_id"].startswith("seal_")
    assert output["demos"]["certified_max_de"]["arms"][1]["certified_inspect"]
    assert "Article 12" in output["insurer_auditor_lane"]["safe_claims"][0]


def test_cli_run_executes_selected_action(tmp_path: Path, capsys: object) -> None:
    thread_path = tmp_path / "run.jsonl"
    assert (
        main(
            [
                "run",
                "--scenario",
                str(ROOT / "scenarios" / "simple_factual.json"),
                "--thread",
                str(thread_path),
                "--workspace",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["decision"]["action_type"] == "ANSWER_DIRECTLY"
    assert output["execution_result"]["status"] == "succeeded"
    assert output["thread"]["execution_result"]["status"] == "succeeded"
