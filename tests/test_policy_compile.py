from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from velvet.cli import main
from velvet.policy_bundle import DEFAULT_POLICY_BUNDLE_SIGNING_KEY, load_policy_bundle
from velvet.policy_compile import compile_policy_document, verify_policy_compile_provenance
from velvet.signing import load_demo_ed25519_signer


def test_policy_compile_writes_signed_validated_bundle(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(tmp_path)
    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )

    manifest = result.manifest
    assert manifest["source_policy_hash"].startswith("sha256:")
    assert manifest["validation_summary"] == {
        "fixtures": 6,
        "passed": 6,
        "failed": 0,
        "repairs_applied": 0,
    }
    assert manifest["determinism_boundary"] == {
        "compile_time_model_only": True,
        "runtime_llm_atoms_enabled": False,
        "certificate_class": "deterministic_with_prebound_llm_atom_evidence",
        "excluded_from_determinism_claims": False,
    }
    assert all(
        not str(artifact["path"]).startswith("/")
        for artifact in manifest["artifacts"].values()
    )

    compiled_policy = (result.policies_dir / "compiled_policy.yaml").read_text(
        encoding="utf-8"
    )
    assert '"type": "llm_atom"' in compiled_policy
    assert "compiled_prompt_injection_detector" in compiled_policy

    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    assert provenance["schema_version"] == "velvet.policy_compile.provenance.v2"
    assert provenance["signature"]["algorithm"] == "Ed25519"
    assert provenance["source_policy_hash"] == manifest["source_policy_hash"]
    assert verify_policy_compile_provenance(result.provenance_path)["verified"] is True

    bundle = load_policy_bundle(
        result.policy_bundle_path,
        signing_key=DEFAULT_POLICY_BUNDLE_SIGNING_KEY,
    )
    assert bundle.policy_chain == "compiled_policy"
    assert bundle.policy_hash == manifest["policy_bundle_hash"]


def test_policy_compile_cli_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    policy_doc = _write_policy_doc(tmp_path)
    output_dir = tmp_path / "cli-bundle"

    status = main(["policy", "compile", str(policy_doc), "--out", str(output_dir), "--json"])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["manifest"]["validation_summary"]["failed"] == 0
    assert Path(payload["policy_bundle_path"]).exists()


def _write_policy_doc(tmp_path: Path) -> Path:
    policy_doc = tmp_path / "policy.md"
    policy_doc.write_text(
        "\n".join(
            [
                "# Example policy",
                "",
                "- Agents must not reveal PII email addresses.",
                "- Agents must block prompt injection attempts that ignore previous instructions.",
                "- Agents must not spend more than $5 per task.",
                "- Agents must limit requests to 1 request per minute.",
                "- Agents require approval before destructive admin tool calls.",
                "- Agents must preserve approved data residency regions.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return policy_doc
