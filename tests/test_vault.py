from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from velvet.cli import main
from velvet.ledger import VelvetLedger, read_ledger_records, verify_velvet_ledger
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import VelvetToolCall
from velvet.signing import (
    DEMO_ED25519_PUBLIC_KEY_BASE64,
    VELVET_SIGNING_PRIVATE_KEY_ENV,
    VELVET_SIGNING_PRIVATE_KEY_FILE_ENV,
    load_demo_ed25519_signer,
)
from velvet.vault.anchor import FileAnchor, WebhookAnchor, write_anchor_receipt
from velvet.vault.merkle import (
    build_consistency_proof,
    build_inclusion_proof,
    record_hashes_root,
    verify_consistency_proof_artifact,
    verify_inclusion_proof_artifact,
)
from velvet.vault.modes import (
    FieldRecordingPolicy,
    RecordingMode,
    record_arguments,
    record_results,
)
from velvet.vault.retention import (
    delete_expired_segments,
    sealed_segment_from_ledger,
)
from velvet.vault.sth import build_signed_tree_head, try_build_signed_tree_head

ROOT = Path(__file__).resolve().parents[1]


def _record_hash_strategy() -> st.SearchStrategy[str]:
    return st.binary(min_size=32, max_size=32).map(lambda item: f"sha256:{item.hex()}")


@given(st.lists(_record_hash_strategy(), min_size=1, max_size=32))
@settings(max_examples=80)
def test_merkle_inclusion_verifies_for_all_leaves(record_hashes: list[str]) -> None:
    root = record_hashes_root(record_hashes)

    for index in range(len(record_hashes)):
        proof = build_inclusion_proof(record_hashes, index)
        assert verify_inclusion_proof_artifact(proof, root_hash=root)


@given(
    st.lists(_record_hash_strategy(), min_size=1, max_size=24),
    st.lists(_record_hash_strategy(), min_size=1, max_size=12),
)
@settings(max_examples=80)
def test_merkle_consistency_verifies_across_growth(
    prefix: list[str],
    suffix: list[str],
) -> None:
    proof = build_consistency_proof(prefix, [*prefix, *suffix])

    assert verify_consistency_proof_artifact(proof)


@given(st.lists(_record_hash_strategy(), min_size=2, max_size=24))
@settings(max_examples=60)
def test_merkle_single_bit_mutation_fails(record_hashes: list[str]) -> None:
    root = record_hashes_root(record_hashes)
    proof = build_inclusion_proof(record_hashes, 1)
    mutated_leaf = _mutate_sha256(record_hashes[1])
    mutated_leaf_proof = {**proof, "leaf_hash": mutated_leaf}

    assert not verify_inclusion_proof_artifact(mutated_leaf_proof, root_hash=root)
    if proof["proof"]:
        mutated_path_proof = copy.deepcopy(proof)
        mutated_path_proof["proof"][0] = _mutate_sha256(mutated_path_proof["proof"][0])
        assert not verify_inclusion_proof_artifact(mutated_path_proof, root_hash=root)


def test_signed_tree_head_uses_canonical_hash_and_verifies() -> None:
    signer = load_demo_ed25519_signer()
    record_hashes = [f"sha256:{i:064x}" for i in range(1, 4)]
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=f"sha256:{'a' * 64}",
        signer=signer,
        timestamp="2026-06-12T00:00:00.000000Z",
    )

    from velvet.vault.sth import signed_tree_head_hash, verify_signed_tree_head

    reordered = dict(reversed(list(sth.items())))
    assert signed_tree_head_hash(sth) == signed_tree_head_hash(reordered)
    assert verify_signed_tree_head(sth, public_key=DEMO_ED25519_PUBLIC_KEY_BASE64)
    tampered = dict(sth)
    tampered["policy_hash"] = f"sha256:{'b' * 64}"
    assert not verify_signed_tree_head(tampered, public_key=DEMO_ED25519_PUBLIC_KEY_BASE64)


def test_signed_tree_head_production_key_missing_degrades(monkeypatch: object) -> None:
    monkeypatch.delenv(VELVET_SIGNING_PRIVATE_KEY_ENV, raising=False)  # type: ignore[attr-defined]
    monkeypatch.delenv(VELVET_SIGNING_PRIVATE_KEY_FILE_ENV, raising=False)  # type: ignore[attr-defined]

    result = try_build_signed_tree_head(
        record_hashes=[f"sha256:{'1' * 64}"],
        first_sequence=1,
        policy_hash=f"sha256:{'a' * 64}",
        signing_profile="production",
    )

    assert result.status == "degraded"
    assert result.sth is None


def test_file_anchor_is_write_once(tmp_path: Path) -> None:
    signer = load_demo_ed25519_signer()
    sth = build_signed_tree_head(
        record_hashes=[f"sha256:{'1' * 64}"],
        first_sequence=1,
        policy_hash=f"sha256:{'a' * 64}",
        signer=signer,
    )
    anchor = FileAnchor(tmp_path / "anchors")

    first = anchor.publish(sth)
    duplicate = anchor.publish(sth)
    conflict_sth = dict(sth)
    conflict_sth["timestamp"] = "2026-06-12T00:00:00.000000Z"
    conflict = FileAnchor(cast(str, first.location)).publish(conflict_sth)

    assert first.status == "ok"
    assert duplicate.status == "ok"
    assert conflict.status == "degraded"


def test_webhook_anchor_spools_on_failure(tmp_path: Path) -> None:
    class FailingTransport:
        def post(
            self,
            url: str,
            body: bytes,
            headers: Mapping[str, str],
            timeout: float,
        ) -> int:
            del url, body, headers, timeout
            return 503

    signer = load_demo_ed25519_signer()
    sth = build_signed_tree_head(
        record_hashes=[f"sha256:{'1' * 64}"],
        first_sequence=1,
        policy_hash=f"sha256:{'a' * 64}",
        signer=signer,
    )
    anchor = WebhookAnchor(
        url="https://anchor.example.invalid/sth",
        spool_dir=tmp_path / "spool",
        transport=FailingTransport(),
        retries=1,
    )

    result = anchor.publish(sth)

    assert result.status == "degraded"
    assert result.spool_path is not None
    assert Path(result.spool_path).exists()


def test_webhook_anchor_rejects_non_http_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="webhook URL must use http or https"):
        WebhookAnchor(url="file:///tmp/sth", spool_dir=tmp_path / "spool")


def test_recording_modes_bind_hashes_and_require_plaintext_opt_in() -> None:
    default_record = record_arguments({"secret": "value"})
    assert default_record["mode"] == "hash_only"
    assert "plaintext_hash" in default_record
    policy = FieldRecordingPolicy(
        results_mode=RecordingMode.PLAINTEXT,
        allow_plaintext_fields=frozenset({"results"}),
    )
    plaintext_record = record_results({"ok": True}, policy=policy)

    assert plaintext_record["mode"] == "plaintext"
    assert plaintext_record["plaintext"] == {"ok": True}


def test_encrypted_body_requires_provider_and_uses_provider() -> None:
    class FakeEncryptor:
        provider_name = "fake_kms"
        key_id = "alias/fake"

        def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
            assert context["plaintext_hash"].startswith("sha256:")
            return b"cipher:" + plaintext

    policy = FieldRecordingPolicy(arguments_mode=RecordingMode.ENCRYPTED_BODY)

    encrypted = record_arguments(
        {"secret": "value"},
        policy=policy,
        encryption_provider=FakeEncryptor(),
    )

    assert encrypted["mode"] == "encrypted_body"
    assert encrypted["encryption_provider"] == "fake_kms"
    assert "ciphertext_base64" in encrypted


def test_retention_refuses_without_anchor_and_deletes_with_tombstone(tmp_path: Path) -> None:
    signer = load_demo_ed25519_signer()
    ledger_path = _write_demo_ledger(tmp_path, signer=signer)
    records = list(read_ledger_records(ledger_path))
    record_hashes = [str(record["record_hash"]) for record in records]
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=signer,
    )
    old_segment = sealed_segment_from_ledger(
        ledger_path,
        sealed_at=datetime.now(tz=UTC) - timedelta(days=184),
    )
    refused = delete_expired_segments(
        [old_segment],
        sth=sth,
        anchor_receipts=[],
        live_ledger_path=tmp_path / "live.vledger",
        signer=signer,
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
    )
    assert refused["status"] == "refused"
    assert ledger_path.exists()

    anchor_result = FileAnchor(tmp_path / "anchors").publish(sth)
    receipt_path = tmp_path / "anchor_receipt.json"
    receipt = write_anchor_receipt(receipt_path, anchor_result)
    deleted = delete_expired_segments(
        [old_segment],
        sth=sth,
        anchor_receipts=[receipt],
        live_ledger_path=tmp_path / "live.vledger",
        signer=signer,
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
    )

    assert deleted["status"] == "pass"
    assert not ledger_path.exists()
    assert verify_velvet_ledger(
        tmp_path / "live.vledger",
        public_key=DEMO_ED25519_PUBLIC_KEY_BASE64,
    )["status"] == "pass"


def test_vault_cli_verifies_demo_segment_offline_in_fresh_process(tmp_path: Path) -> None:
    signer = load_demo_ed25519_signer()
    ledger_path = _write_demo_ledger(tmp_path, signer=signer)
    records = list(read_ledger_records(ledger_path))
    record_hashes = [str(record["record_hash"]) for record in records]
    sth = build_signed_tree_head(
        record_hashes=record_hashes,
        first_sequence=1,
        policy_hash=str(records[-1]["policy_hash"]),
        signer=signer,
    )
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth, sort_keys=True) + "\n", encoding="utf-8")
    anchor_result = FileAnchor(tmp_path / "anchors").publish(sth)
    assert anchor_result.status == "ok"
    key_path = tmp_path / "demo.pub"
    material = signer.public_verification_material("demo-not-for-production")
    assert material is not None
    key_path.write_text(str(material["public_key_pem"]), encoding="utf-8")

    completed = subprocess.run(  # noqa: S603 - fresh-process CLI parity uses local Python.
        [
            sys.executable,
            "-c",
            (
                "from velvet.cli import main; "
                "raise SystemExit(main(['vault','verify','--segment','1-3','--sth',"
                f"{str(sth_path)!r},'--ledger',{str(ledger_path)!r},"
                f"'--public-key-file',{str(key_path)!r},'--json']))"
            ),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "pass"

    tampered = json.loads(sth_path.read_text(encoding="utf-8"))
    tampered["root_hash"] = f"sha256:{'f' * 64}"
    sth_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")
    assert (
        main(
            [
                "vault",
                "verify",
                "--segment",
                "1-3",
                "--sth",
                str(sth_path),
                "--ledger",
                str(ledger_path),
                "--public-key-file",
                str(key_path),
                "--json",
            ]
        )
        == 1
    )


def _write_demo_ledger(tmp_path: Path, *, signer: Any) -> Path:
    adapter = DirectVelvetMCPAdapter.from_list_file(
        ROOT / "examples" / "mcp" / "list.json",
        signing_profile="demo",
    )
    ledger_path = tmp_path / "ledger.vledger"
    ledger = VelvetLedger(
        ledger_path,
        signer=signer,
        signing_key_id="demo-not-for-production",
    )
    for request in list(load_requests(ROOT / "examples" / "mcp" / "workflow.json"))[:3]:
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
        ledger.write_admission_decision(decision, request=request, label="vault_test")
    return ledger_path


def _mutate_sha256(value: str) -> str:
    digest = bytearray(bytes.fromhex(value.removeprefix("sha256:")))
    digest[0] ^= 1
    return f"sha256:{digest.hex()}"
