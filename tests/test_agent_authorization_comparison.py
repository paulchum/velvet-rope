from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from velvet.agent_authorization_benchmark import DEFAULT_REPEAT_COUNT
from velvet.agent_authorization_comparison import (
    COMPARISON_CAPABILITY_KEYS,
    COMPARISON_SCHEMA_VERSION,
    run_agent_authorization_comparison,
)
from velvet.cli import main


def test_agent_authorization_comparison_writes_evidence_backed_rows(
    tmp_path: Path,
) -> None:
    payload = run_agent_authorization_comparison(tmp_path, allow_dirty=True)

    assert payload["schema_version"] == COMPARISON_SCHEMA_VERSION
    assert payload["repeat_count"] == DEFAULT_REPEAT_COUNT
    assert Path(payload["results_path"]).exists()
    assert Path(payload["markdown_path"]).exists()

    rows = {row["system"]: row for row in payload["capability_matrix"]}
    assert set(rows) == {
        "Velvet Inline Gateway",
        "OAP/APort pinned schema fixture",
        "Pipelock action receipt fixture",
        "Attested Intelligence AGA fixture",
        "Cerbos PDP fixture",
        "Gateway allowlist baseline",
    }

    for row in rows.values():
        assert row["public_claim_status"]
        assert Path(row["evidence_path"]).exists()
        assert set(row["capabilities"]) == set(COMPARISON_CAPABILITY_KEYS)
        for capability in row["capabilities"].values():
            assert capability["status"] in {"pass", "fail", "not_measured"}
            assert capability["evidence_pointer"]

    velvet = rows["Velvet Inline Gateway"]["capabilities"]
    for key in COMPARISON_CAPABILITY_KEYS:
        assert velvet[key]["status"] == "pass"

    oap = rows["OAP/APort pinned schema fixture"]
    assert oap["capabilities"]["signed_artifact"]["status"] == "pass"
    assert oap["capabilities"]["public_verification"]["status"] == "pass"
    assert oap["capabilities"]["tamper_evidence"]["status"] == "pass"
    assert oap["capabilities"]["replayable_artifact"]["status"] == "fail"
    assert oap["capabilities"]["binding_depth"]["status"] == "fail"
    assert oap["capabilities"]["drift_rejection"]["status"] == "fail"
    assert oap["public_claim_status"] == "not_claimable_against_live_product"
    assert oap["strict_oap_schema_validation_passed"] is False
    assert any("passport_id" in error for error in oap["strict_oap_schema_validation_errors"])

    for system in ("Pipelock action receipt fixture", "Attested Intelligence AGA fixture"):
        signed_receipt = rows[system]
        assert signed_receipt["public_claim_status"] == "not_claimable_against_live_product"
        assert signed_receipt["capabilities"]["signed_artifact"]["status"] == "pass"
        assert signed_receipt["capabilities"]["public_verification"]["status"] == "pass"
        assert signed_receipt["capabilities"]["tamper_evidence"]["status"] == "pass"
        assert signed_receipt["capabilities"]["replayable_artifact"]["status"] == "pass"
        assert signed_receipt["capabilities"]["binding_depth"]["status"] == "fail"
        assert signed_receipt["capabilities"]["drift_rejection"]["status"] == "fail"
        assert signed_receipt["pass_k_reliability"]["1"] == 1.0

    cerbos = rows["Cerbos PDP fixture"]
    gateway = rows["Gateway allowlist baseline"]
    for row in (cerbos, gateway):
        assert row["capabilities"]["pre_execution_decision"]["status"] == "pass"
        assert row["capabilities"]["deterministic_decision"]["status"] == "pass"
        assert row["capabilities"]["signed_artifact"]["status"] == "fail"
        assert row["capabilities"]["drift_rejection"]["status"] == "fail"

    markdown = Path(payload["markdown_path"]).read_text(encoding="utf-8")
    assert "fixture evidence only" in markdown
    assert "not live product evaluations" in markdown
    assert "benchmark dominance" not in markdown.lower()

    result_hash = hashlib.sha256(Path(payload["results_path"]).read_bytes()).hexdigest()
    velvet_evidence_hash = hashlib.sha256(
        Path(rows["Velvet Inline Gateway"]["evidence_path"]).read_bytes()
    ).hexdigest()
    payload_again = run_agent_authorization_comparison(tmp_path, allow_dirty=True)
    assert (
        hashlib.sha256(Path(payload_again["results_path"]).read_bytes()).hexdigest()
        == result_hash
    )
    rows_again = {row["system"]: row for row in payload_again["capability_matrix"]}
    rerun_velvet_path = Path(rows_again["Velvet Inline Gateway"]["evidence_path"])
    assert hashlib.sha256(rerun_velvet_path.read_bytes()).hexdigest() == velvet_evidence_hash


def test_agent_authorization_comparison_cli_flag(
    tmp_path: Path,
    capsys: object,
) -> None:
    assert (
        main(
            [
                "agent-auth-benchmark",
                "--comparison",
                "--output-dir",
                str(tmp_path),
                "--json",
                "--allow-dirty",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["schema_version"] == COMPARISON_SCHEMA_VERSION
    assert Path(payload["markdown_path"]).exists()


def test_agent_authorization_comparison_dirty_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "velvet.agent_authorization_comparison._git_dirty",
        lambda: True,
    )

    with pytest.raises(SystemExit):
        run_agent_authorization_comparison(tmp_path)
