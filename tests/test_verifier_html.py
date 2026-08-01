from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from velvet.ledger import (
    VelvetLedger,
    _write_binary_records,
    ledger_record_hash,
    read_ledger_records,
    verify_velvet_ledger,
)
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import VelvetToolCall, VelvetWarrant
from velvet.serialization import proof_artifact_unsigned_payload
from velvet.signing import (
    DEMO_ED25519_PUBLIC_KEY_BASE64,
    DEMO_ED25519_PUBLIC_KEY_PATH,
    PURPOSE_WARRANT,
    verify_signature_record,
)
from velvet.vault.merkle import build_inclusion_proof
from velvet.vault.sth import build_signed_tree_head

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "docs" / "public" / "velvet-verifier.html"

NODE_RUNNER = r"""
const fs = require("fs");
const vm = require("vm");

const htmlPath = process.argv[1];
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const html = fs.readFileSync(htmlPath, "utf8");
const coreRe = (
  /\/\* BEGIN VELVET_VERIFIER_CORE \*\/[\s\S]*?\/\* END VELVET_VERIFIER_CORE \*\//
);
const match = html.match(coreRe);
if (!match) throw new Error("VelvetVerifierCore sentinel block not found");

const context = {
  console,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  DataView,
  BigInt,
  Buffer,
  atob,
};
if (!input.disableCrypto) context.crypto = globalThis.crypto;
context.window = context;
context.globalThis = context;
vm.createContext(context);
vm.runInContext(match[0], context, { filename: "velvet-verifier-core.js" });
const V = context.VelvetVerifierCore;

(async () => {
  const output = {};
  if (input.mode === "bundled") {
    output.validWarrant = await V.verifyArtifactText(
      V.BUNDLED_EXAMPLES.validWarrantJson,
      V.DEMO_PUBLIC_KEY_BASE64
    );
    output.tamperedWarrant = await V.verifyArtifactText(
      V.BUNDLED_EXAMPLES.tamperedWarrantJson,
      V.DEMO_PUBLIC_KEY_BASE64
    );
    output.validLedger = await V.verifyLedgerRecordsText(
      V.BUNDLED_EXAMPLES.validLedgerRecordsJson,
      V.DEMO_PUBLIC_KEY_BASE64
    );
    output.tamperedLedger = await V.verifyLedgerRecordsText(
      V.BUNDLED_EXAMPLES.tamperedLedgerRecordsJson,
      V.DEMO_PUBLIC_KEY_BASE64
    );
  } else if (input.mode === "parity") {
    output.warrant = await V.verifyArtifactText(input.warrantJson, input.publicKey);
    output.ledger = await V.verifyLedgerRecordsText(input.ledgerRecordsJson, input.publicKey);
    output.mutatedWarrants = [];
    for (const item of input.mutatedWarrants) {
      let result;
      try {
        result = await V.verifyArtifactText(item.json, input.publicKey);
      } catch (error) {
        result = {
          status: "fail",
          issues: [{ code: "canonicalization_error", actual: String(error.message || error) }],
        };
      }
      output.mutatedWarrants.push({
        field: item.field,
        result,
      });
    }
    output.tamperedLedger = await V.verifyLedgerRecordsText(
      input.tamperedLedgerRecordsJson,
      input.publicKey
    );
  } else if (input.mode === "hash") {
    output.sha256Empty = V.sha256Hex(new Uint8Array());
    output.sha512Empty = Array.from(V.sha512(new Uint8Array()))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } else if (input.mode === "sth") {
    output.valid = await V.verifySTHInclusionProofText(
      input.recordJson,
      input.sthJson,
      input.proofJson,
      input.publicKey
    );
    output.tampered = await V.verifySTHInclusionProofText(
      input.recordJson,
      input.sthJson,
      input.tamperedProofJson,
      input.publicKey
    );
  } else {
    throw new Error("unsupported mode " + input.mode);
  }
  process.stdout.write(JSON.stringify(output));
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
"""


def _run_node(payload: Mapping[str, Any]) -> dict[str, Any]:
    node = shutil.which("node")
    assert node is not None
    completed = subprocess.run(  # noqa: S603 - node path is resolved locally; input is fixture JSON.
        [node, "-e", NODE_RUNNER, str(HTML_PATH)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        cwd=ROOT,
    )
    return cast(dict[str, Any], json.loads(completed.stdout))


def _demo_artifacts(tmp_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    adapter = DirectVelvetMCPAdapter.from_list_file(
        ROOT / "examples" / "mcp" / "list.json",
        signing_profile="demo",
    )
    requests = list(load_requests(ROOT / "examples" / "mcp" / "workflow.json"))[:3]
    ledger_path = tmp_path / "ledger.vledger"
    ledger = VelvetLedger(
        ledger_path,
        signer=adapter.firewall.signer,
        signing_key_id=adapter.firewall.signing_key_id,
    )
    warrant: dict[str, Any] | None = None
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
        selected = decision.selected_warrant
        if selected is not None:
            warrant = selected.to_dict()
        ledger.write_admission_decision(decision, request=request, label="verifier_test")
    assert warrant is not None
    records = list(read_ledger_records(ledger_path))
    ledger_records_json = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )
    return warrant, records, ledger_records_json


def _mutated_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value + "_tampered"
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 0.125
    if isinstance(value, list):
        return value + ["tampered"]
    if isinstance(value, dict):
        mutated = dict(value)
        mutated["tampered"] = True
        return mutated
    if value is None:
        return "tampered"
    return "tampered"


def _python_warrant_verifies(warrant: Mapping[str, Any]) -> bool:
    signature = warrant.get("signature")
    try:
        expected_hash = VelvetWarrant.compute_hash_for_payload(warrant)
        return (
            isinstance(signature, Mapping)
            and warrant.get("warrant_hash") == expected_hash
            and verify_signature_record(
                signature,
                expected_hash,
                purpose=PURPOSE_WARRANT,
                tenant_id=cast(str, warrant.get("tenant_id")),
                key_id=cast(str, warrant.get("signing_key_id")),
                public_key=DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8"),
            )
        )
    except ValueError:
        return False


def test_verifier_html_is_single_file_and_offline() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    assert "<script" in html
    assert "VelvetVerifierCore" in html
    assert "@noble/ed25519@3.1.0" in html
    assert "npm gitHead: f22a12486e252526b2658e4401d286b27c9c753b" in html
    assert not re.search(r"<script[^>]+src=", html, flags=re.IGNORECASE)
    assert not re.search(r"<link[^>]+href=", html, flags=re.IGNORECASE)
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html
    assert "WebSocket" not in html
    assert "EventSource" not in html
    assert "sendBeacon" not in html


def test_inline_hash_primitives_match_known_empty_hashes() -> None:
    output = _run_node({"mode": "hash", "disableCrypto": True})

    assert output["sha256Empty"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert output["sha512Empty"] == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc"
        "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    )


def test_bundled_examples_show_valid_and_tampered_states() -> None:
    output = _run_node({"mode": "bundled"})

    assert output["validWarrant"]["status"] == "pass"
    assert output["validWarrant"]["signature"]["verificationTier"] == "demo-not-for-production"
    assert output["validLedger"]["status"] == "pass"
    assert output["validLedger"]["recordCount"] == 3
    assert output["tamperedWarrant"]["status"] == "fail"
    assert output["tamperedLedger"]["status"] == "fail"
    assert {
        "record_hash_mismatch",
        "previous_hash_mismatch",
        "signature_mismatch",
    }.issubset({issue["code"] for issue in output["tamperedLedger"]["issues"]})


def test_js_verifier_matches_python_on_fresh_demo_artifacts(tmp_path: Path) -> None:
    warrant, records, ledger_records_json = _demo_artifacts(tmp_path)
    assert _python_warrant_verifies(warrant)
    assert all(record["record_hash"] == ledger_record_hash(record) for record in records)

    ledger_path = tmp_path / "ledger.vledger"
    _write_binary_records(ledger_path, records)
    assert verify_velvet_ledger(ledger_path)["status"] == "pass"

    mutated_warrants: list[dict[str, str]] = []
    covered = proof_artifact_unsigned_payload("warrant", warrant)
    for field in covered:
        mutated = copy.deepcopy(warrant)
        mutated[field] = _mutated_value(mutated[field])
        assert not _python_warrant_verifies(mutated), field
        mutated_warrants.append(
            {
                "field": field,
                "json": json.dumps(mutated, sort_keys=True, separators=(",", ":")),
            }
        )

    tampered_records = copy.deepcopy(records)
    tampered_records[1]["decision"] = (
        "execute" if tampered_records[1].get("decision") != "execute" else "block"
    )
    tampered_jsonl = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in tampered_records
    )
    tampered_path = tmp_path / "tampered.vledger"
    _write_binary_records(tampered_path, tampered_records)
    assert verify_velvet_ledger(tampered_path)["status"] == "fail"

    output = _run_node(
        {
            "mode": "parity",
            "publicKey": DEMO_ED25519_PUBLIC_KEY_BASE64,
            "warrantJson": json.dumps(warrant, sort_keys=True, separators=(",", ":")),
            "ledgerRecordsJson": ledger_records_json,
            "mutatedWarrants": mutated_warrants,
            "tamperedLedgerRecordsJson": tampered_jsonl,
        }
    )

    assert output["warrant"]["status"] == "pass"
    assert output["warrant"]["recomputedHash"] == VelvetWarrant.compute_hash_for_payload(warrant)
    assert output["ledger"]["status"] == "pass"
    assert [record["recomputedRecordHash"] for record in output["ledger"]["records"]] == [
        ledger_record_hash(record) for record in records
    ]
    assert all(item["result"]["status"] == "fail" for item in output["mutatedWarrants"])
    assert output["tamperedLedger"]["status"] == "fail"
    assert "record_hash_mismatch" in {
        issue["code"] for issue in output["tamperedLedger"]["issues"]
    }


def test_inline_noble_fallback_verifies_without_webcrypto(tmp_path: Path) -> None:
    warrant, _records, _ledger_records_json = _demo_artifacts(tmp_path)

    output = _run_node(
        {
            "mode": "parity",
            "disableCrypto": True,
            "publicKey": DEMO_ED25519_PUBLIC_KEY_BASE64,
            "warrantJson": json.dumps(warrant, sort_keys=True, separators=(",", ":")),
            "ledgerRecordsJson": "",
            "mutatedWarrants": [],
            "tamperedLedgerRecordsJson": "",
        }
    )

    assert output["warrant"]["status"] == "pass"
    assert output["warrant"]["signature"]["engine"] == "@noble/ed25519@3.1.0 inline fallback"


def test_js_verifier_checks_sth_inclusion_proof(tmp_path: Path) -> None:
    _warrant, records, _ledger_records_json = _demo_artifacts(tmp_path)
    record_hashes = [str(record["record_hash"]) for record in records]
    signer = DirectVelvetMCPAdapter.from_list_file(
        ROOT / "examples" / "mcp" / "list.json",
        signing_profile="demo",
    ).firewall.signer
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=signer,
    )
    proof = build_inclusion_proof(record_hashes, 1)
    tampered_proof = copy.deepcopy(proof)
    tampered_proof["proof"][0] = "sha256:" + ("f" * 64)

    output = _run_node(
        {
            "mode": "sth",
            "publicKey": DEMO_ED25519_PUBLIC_KEY_BASE64,
            "recordJson": json.dumps(records[1], sort_keys=True, separators=(",", ":")),
            "sthJson": json.dumps(sth, sort_keys=True, separators=(",", ":")),
            "proofJson": json.dumps(proof, sort_keys=True, separators=(",", ":")),
            "tamperedProofJson": json.dumps(
                tampered_proof,
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
    )

    assert output["valid"]["status"] == "pass"
    assert output["tampered"]["status"] == "fail"
    assert "inclusion_proof_mismatch" in {
        issue["code"] for issue in output["tampered"]["issues"]
    }
