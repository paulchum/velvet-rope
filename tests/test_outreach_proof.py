from __future__ import annotations

import json
from pathlib import Path

from velvet.outreach_proof import PROOF_VERSION, write_outreach_warrant_proof


def test_outreach_warrant_proof_emits_public_key_verifiable_pack(tmp_path: Path) -> None:
    payload = write_outreach_warrant_proof(tmp_path / "proof")

    assert payload["proof_version"] == PROOF_VERSION
    assert payload["signing"]["algorithm"] == "Ed25519"
    assert payload["ledger_verification"]["status"] == "pass"
    assert payload["ledger_verification"]["canonical_records"] == 3
    assert {item["decision"] for item in payload["decisions"]} == {
        "block",
        "escalate",
        "execute",
    }
    assert all(report["status"] == "pass" for report in payload["warrants"])
    assert all(
        report["status"] == "pass" for report in payload["ledger_signature_reports"]
    )

    proof_json = Path(payload["artifacts"]["proof_json"])
    written = json.loads(proof_json.read_text(encoding="utf-8"))
    assert written["artifact_hash"] == payload["artifact_hash"]
