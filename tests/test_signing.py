from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Mapping
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.approvals import ApprovalStatus, ApprovalStore
from velvet.cli import main
from velvet.contracts import AdmissionContract
from velvet.evidence import build_evidence_pack, verify_evidence_manifest
from velvet.execution import (
    ExecutionPermit,
    PermitValidationContext,
    build_pre_execution_record,
    prepare_execution,
    verify_execution_permit,
)
from velvet.executor import VelvetAdmissionLayer
from velvet.ledger import (
    VelvetLedger,
    _write_binary_records,
    read_ledger_records,
    verify_velvet_ledger,
)
from velvet.mcp_firewall import run_mcp_firewall_pilot, verify_mcp_firewall_pilot
from velvet.rope import (
    ToolRiskClass,
    VelvetMCP,
    VelvetToolCall,
    VelvetToolPolicy,
    VelvetWarrant,
)
from velvet.signing import (
    DEFAULT_AWS_KMS_SIGNING_ALGORITHM,
    DEMO_ED25519_KEY_ID,
    DEMO_ED25519_PRIVATE_KEY_PATH,
    DEMO_ED25519_PUBLIC_KEY_PATH,
    PRODUCTION_KEY_MISSING_MESSAGE,
    PURPOSE_WARRANT,
    SIGNATURE_SCHEMA_VERSION_V1,
    ArtifactSigner,
    AwsKmsSigner,
    LocalDevHmacSigner,
    LocalEd25519Signer,
    SigningProviderNotConfigured,
    VaultTransitSigner,
    load_demo_ed25519_signer,
    resolve_ed25519_signing_provider,
    signing_message,
    verify_signature_record,
)


def prepared_context_for_test(
    permit: ExecutionPermit,
    *,
    signer: Any,
) -> PermitValidationContext:
    return PermitValidationContext(
        tenant_id=permit.tenant_id,
        environment=permit.environment,
        audience=permit.audience,
        policy_hash=permit.policy.policy_hash,
        policy_version=permit.policy.policy_version,
        tool_schema_hash=permit.scope.tool_schema_hash,
        scope=permit.scope,
        now=permit.validity.not_before,
        trusted_signer=signer,
        trusted_key_id=permit.signature.get("key_id")
        if isinstance(permit.signature, Mapping)
        else None,
    )


class FakeAwsKmsClient:
    def __init__(self, *, key_id: str = "arn:aws:kms:us-west-2:111122223333:key/fake") -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.key_id = key_id
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sign_calls: list[dict[str, Any]] = []
        self.verify_calls: list[dict[str, Any]] = []

    def sign(self, **kwargs: Any) -> Mapping[str, Any]:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        self.sign_calls.append(dict(kwargs))
        signature = self.private_key.sign(
            cast(bytes, kwargs["Message"]),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        return {"KeyId": self.key_id, "Signature": signature}

    def verify(self, **kwargs: Any) -> Mapping[str, Any]:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        self.verify_calls.append(dict(kwargs))
        try:
            self.private_key.public_key().verify(
                cast(bytes, kwargs["Signature"]),
                cast(bytes, kwargs["Message"]),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                hashes.SHA256(),
            )
        except Exception:  # noqa: BLE001 - fake mirrors KMS SignatureValid false.
            return {"KeyId": self.key_id, "SignatureValid": False}
        return {"KeyId": self.key_id, "SignatureValid": True}

    def get_public_key(self, **kwargs: Any) -> Mapping[str, Any]:
        from cryptography.hazmat.primitives import serialization

        return {
            "KeyId": self.key_id,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [DEFAULT_AWS_KMS_SIGNING_ALGORITHM],
            "PublicKey": self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }


class FakeVaultTransit:
    def __init__(self) -> None:
        self.secret = b"fake-vault-transit-secret"
        self.sign_calls: list[dict[str, Any]] = []
        self.verify_calls: list[dict[str, Any]] = []

    def sign_data(self, **kwargs: Any) -> Mapping[str, Any]:
        self.sign_calls.append(dict(kwargs))
        message = base64.b64decode(str(kwargs["hash_input"]).encode("ascii"), validate=True)
        signature = hmac.new(self.secret, message, sha256).digest()
        return {
            "data": {
                "signature": f"vault:v42:{base64.b64encode(signature).decode('ascii')}"
            }
        }

    def verify_signed_data(self, **kwargs: Any) -> Mapping[str, Any]:
        self.verify_calls.append(dict(kwargs))
        try:
            message = base64.b64decode(str(kwargs["hash_input"]).encode("ascii"), validate=True)
            encoded = str(kwargs["signature"]).split(":", 2)[2]
            signature = base64.b64decode(encoded.encode("ascii"), validate=True)
        except Exception:  # noqa: BLE001 - fake mirrors Vault valid false.
            return {"data": {"valid": False}}
        expected = hmac.new(self.secret, message, sha256).digest()
        return {"data": {"valid": hmac.compare_digest(signature, expected)}}


class FakeVaultClient:
    def __init__(self) -> None:
        self.transit = FakeVaultTransit()
        self.secrets = type("Secrets", (), {"transit": self.transit})()


def test_local_hmac_signature_binds_payload_purpose_tenant_and_key() -> None:
    signer = ArtifactSigner(
        LocalDevHmacSigner("secret"),
        tenant_id="tenant-a",
        key_id="key-a",
    )
    payload = {"decision": "execute", "seal_id": "seal_1"}
    signed = signer.attach_signature(payload, PURPOSE_WARRANT)

    assert signed["signature"]["provider_name"] == "local_dev_hmac_demo"
    assert signer.verify_payload(signed, PURPOSE_WARRANT)

    tampered_payload = dict(signed)
    tampered_payload["decision"] = "block"
    assert not signer.verify_payload(tampered_payload, PURPOSE_WARRANT)

    tampered_purpose = dict(signed)
    tampered_purpose["signature"] = dict(signed["signature"])
    tampered_purpose["signature"]["purpose"] = "velvet.other.v1"
    assert not signer.verify_payload(tampered_purpose, PURPOSE_WARRANT)

    tampered_tenant = dict(signed)
    tampered_tenant["signature"] = dict(signed["signature"])
    tampered_tenant["signature"]["tenant_id"] = "tenant-b"
    assert not signer.verify_payload(tampered_tenant, PURPOSE_WARRANT)

    tampered_key = dict(signed)
    tampered_key["signature"] = dict(signed["signature"])
    tampered_key["signature"]["key_id"] = "key-b"
    assert not signer.verify_payload(tampered_key, PURPOSE_WARRANT)


def test_optional_ed25519_signer_when_cryptography_is_installed() -> None:
    signer = ArtifactSigner(
        LocalEd25519Signer(),
        tenant_id="tenant-a",
        key_id="ed25519-local",
    )
    signed = signer.attach_signature({"artifact": "warrant"}, PURPOSE_WARRANT)

    assert signed["signature"]["algorithm"] == "Ed25519"
    assert signer.verify_payload(signed, PURPOSE_WARRANT)


def test_third_party_public_key_verifies_genuine_warrant() -> None:
    decision = VelvetMCP(
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="create_change_request",
                risk_class=ToolRiskClass.HIGH,
            ),
        )
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="create_change_request",
            arguments={"service": "payments"},
        )
    )
    selected = decision.selected_warrant
    assert selected is not None
    warrant = selected.to_dict()
    signature = warrant["signature"]
    assert isinstance(signature, dict)

    assert warrant["signing_key_id"] == DEMO_ED25519_KEY_ID
    assert verify_signature_record(
        signature,
        str(warrant["warrant_hash"]),
        purpose=PURPOSE_WARRANT,
        tenant_id=str(warrant["tenant_id"]),
        key_id=DEMO_ED25519_KEY_ID,
        public_key=DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8"),
    )

    mutated = dict(warrant)
    mutated["decision"] = "block"
    assert not verify_signature_record(
        signature,
        VelvetWarrant.compute_hash_for_payload(mutated),
        purpose=PURPOSE_WARRANT,
        tenant_id=str(warrant["tenant_id"]),
        key_id=DEMO_ED25519_KEY_ID,
        public_key=DEMO_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8"),
    )


def test_hmac_v1_records_still_verify() -> None:
    signer = ArtifactSigner(
        LocalDevHmacSigner(schema_version=SIGNATURE_SCHEMA_VERSION_V1),
        tenant_id="tenant-a",
        key_id="key-a",
    )
    signed = signer.attach_signature({"artifact": "legacy"}, PURPOSE_WARRANT)
    assert signed["signature"]["schema_version"] == SIGNATURE_SCHEMA_VERSION_V1
    assert signer.verify_payload(signed, PURPOSE_WARRANT)
    assert verify_signature_record(
        signed["signature"],
        signed["signature"]["payload_hash"],
        purpose=PURPOSE_WARRANT,
    )


def test_tampered_ed25519_signature_is_rejected() -> None:
    signer = ArtifactSigner(
        LocalEd25519Signer(),
        tenant_id="tenant-a",
        key_id="ed25519-local",
    )
    signed = signer.attach_signature({"artifact": "warrant"}, PURPOSE_WARRANT)
    tampered = dict(signed)
    tampered["signature"] = dict(signed["signature"])
    signature_bytes = bytearray(
        base64.b64decode(str(signed["signature"]["signature"]), validate=True)
    )
    signature_bytes[0] ^= 0x01
    tampered["signature"]["signature"] = base64.b64encode(signature_bytes).decode("ascii")
    assert not signer.verify_payload(tampered, PURPOSE_WARRANT)


def test_production_signing_fails_closed_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "VELVET_SIGNING_PROFILE",
        "VELVET_SIGNING_PRIVATE_KEY",
        "VELVET_SIGNING_PRIVATE_KEY_FILE",
        "VELVET_ALLOW_EPHEMERAL_SIGNING",
    ):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(SigningProviderNotConfigured, match="VELVET_SIGNING_PRIVATE_KEY"):
        VelvetMCP()
    with pytest.raises(SigningProviderNotConfigured, match="--dev-ephemeral-key"):
        resolve_ed25519_signing_provider()
    assert "VELVET_SIGNING_PRIVATE_KEY_FILE" in PRODUCTION_KEY_MISSING_MESSAGE


def test_demo_key_is_rejected_as_production_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VELVET_SIGNING_PROFILE", raising=False)
    monkeypatch.setenv("VELVET_SIGNING_PRIVATE_KEY_FILE", str(DEMO_ED25519_PRIVATE_KEY_PATH))
    with pytest.raises(SigningProviderNotConfigured, match="Refusing"):
        resolve_ed25519_signing_provider(signing_profile="production")


def test_ephemeral_signing_marks_non_durable_and_exports_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VELVET_SIGNING_PROFILE", raising=False)
    signer = resolve_ed25519_signing_provider(dev_ephemeral_key=True)
    signed = ArtifactSigner(signer, tenant_id="tenant-a", key_id="ephemeral-dev").attach_signature(
        {"artifact": "warrant"},
        PURPOSE_WARRANT,
    )
    assert signed["signature"]["metadata"]["verification_tier"] == "non-durable"
    material = signed["signature"]["public_verification_material"]
    assert material["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert material["public_key_base64"]


def test_enterprise_providers_fail_closed_without_configuration() -> None:
    with pytest.raises(SigningProviderNotConfigured, match="explicit KMS client"):
        AwsKmsSigner(key_id="alias/velvet").sign(
            "sha256:" + "0" * 64,
            PURPOSE_WARRANT,
            "tenant-a",
            "alias/velvet",
        )
    assert not AwsKmsSigner(key_id="alias/velvet").verify(
        "sha256:" + "0" * 64,
        "not-base64",
        PURPOSE_WARRANT,
        "tenant-a",
        "alias/velvet",
    )

    with pytest.raises(SigningProviderNotConfigured, match="explicit hvac client"):
        VaultTransitSigner(key_name="velvet-key").sign(
            "sha256:" + "0" * 64,
            PURPOSE_WARRANT,
            "tenant-a",
            "velvet-key",
        )
    assert not VaultTransitSigner(key_name="velvet-key").verify(
        "sha256:" + "0" * 64,
        "vault:v1:AAAA",
        PURPOSE_WARRANT,
        "tenant-a",
        "velvet-key",
    )


def test_aws_kms_signer_signs_canonical_bytes_and_verifies_with_kms_and_public_material() -> None:
    client = FakeAwsKmsClient()
    signer = AwsKmsSigner(key_id="alias/velvet", client=client)
    artifact_signer = ArtifactSigner(signer, tenant_id="tenant-a", key_id="alias/velvet")
    payload_hash = "sha256:" + "1" * 64

    block = artifact_signer.sign_hash(payload_hash, PURPOSE_WARRANT)
    record = block.to_dict()

    assert client.sign_calls[0]["Message"] == signing_message(
        payload_hash,
        PURPOSE_WARRANT,
        "tenant-a",
        "alias/velvet",
        provider_name="aws_kms",
        algorithm=DEFAULT_AWS_KMS_SIGNING_ALGORITHM,
        key_version="alias/velvet",
    )
    assert record["provider_name"] == "aws_kms"
    assert record["metadata"]["verification_tier"] == "durable"
    assert record["metadata"]["kms_key_id"] == client.key_id
    assert record["metadata"]["signing_algorithm"] == DEFAULT_AWS_KMS_SIGNING_ALGORITHM
    assert record["metadata"]["message_type"] == "RAW"
    material = cast(Mapping[str, Any], record["public_verification_material"])
    assert material["public_key_der_base64"]
    assert material["key_spec"] == "RSA_2048"

    assert verify_signature_record(
        record,
        payload_hash,
        purpose=PURPOSE_WARRANT,
        tenant_id="tenant-a",
        key_id="alias/velvet",
        signer=signer,
    )
    assert verify_signature_record(
        record,
        payload_hash,
        purpose=PURPOSE_WARRANT,
        tenant_id="tenant-a",
        key_id="alias/velvet",
    )

    tampered_payload = dict(record)
    tampered_payload["payload_hash"] = "sha256:" + "2" * 64
    assert not verify_signature_record(tampered_payload, str(tampered_payload["payload_hash"]))

    tampered_purpose = dict(record)
    tampered_purpose["purpose"] = "velvet.other"
    assert not verify_signature_record(tampered_purpose, payload_hash)

    tampered_tenant = dict(record)
    tampered_tenant["tenant_id"] = "tenant-b"
    assert not verify_signature_record(tampered_tenant, payload_hash)

    tampered_key = dict(record)
    tampered_key["key_id"] = "alias/other"
    assert not verify_signature_record(tampered_key, payload_hash)


def test_vault_transit_signer_uses_base64_canonical_input_and_preserves_key_version() -> None:
    client = FakeVaultClient()
    signer = VaultTransitSigner(key_name="velvet-key", client=client, key_version="42")
    artifact_signer = ArtifactSigner(signer, tenant_id="tenant-a", key_id="velvet-key")
    payload_hash = "sha256:" + "3" * 64

    block = artifact_signer.sign_hash(payload_hash, PURPOSE_WARRANT)
    record = block.to_dict()
    transit = client.transit

    expected_message = signing_message(
        payload_hash,
        PURPOSE_WARRANT,
        "tenant-a",
        "velvet-key",
        provider_name="vault_transit",
        algorithm="VaultTransit-sha2-256-pss",
        key_version="42",
    )
    assert transit.sign_calls[0]["hash_input"] == base64.b64encode(expected_message).decode(
        "ascii"
    )
    assert transit.sign_calls[0]["key_version"] == 42
    assert record["provider_name"] == "vault_transit"
    assert record["signature"].startswith("vault:v42:")
    assert record["metadata"]["verification_tier"] == "durable"
    assert record["metadata"]["key_name"] == "velvet-key"
    assert record["metadata"]["key_version"] == "42"
    assert record["metadata"]["vault_signature_version"] == "v42"
    assert record["metadata"]["mount_point"] == "transit"

    assert verify_signature_record(
        record,
        payload_hash,
        purpose=PURPOSE_WARRANT,
        tenant_id="tenant-a",
        key_id="velvet-key",
        signer=signer,
    )

    tampered_purpose = dict(record)
    tampered_purpose["purpose"] = "velvet.other"
    assert not verify_signature_record(tampered_purpose, payload_hash, signer=signer)

    tampered_tenant = dict(record)
    tampered_tenant["tenant_id"] = "tenant-b"
    assert not verify_signature_record(tampered_tenant, payload_hash, signer=signer)

    tampered_key = dict(record)
    tampered_key["key_id"] = "other-key"
    assert not verify_signature_record(tampered_key, payload_hash, signer=signer)

    assert not verify_signature_record(
        record,
        "sha256:" + "4" * 64,
        purpose=PURPOSE_WARRANT,
        tenant_id="tenant-a",
        key_id="velvet-key",
        signer=signer,
    )


def test_signing_cli_round_trips_with_fake_enterprise_provider(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = AwsKmsSigner(key_id="alias/velvet", client=FakeAwsKmsClient())

    def fake_resolve_signing_provider(**kwargs: Any) -> AwsKmsSigner:
        assert kwargs["signing_provider"] == "aws-kms"
        return signer

    monkeypatch.setattr("velvet.cli.resolve_signing_provider", fake_resolve_signing_provider)
    payload_hash = "sha256:" + "5" * 64

    assert (
        main(
            [
                "signing",
                "sign",
                "--provider",
                "aws-kms",
                "--payload-hash",
                payload_hash,
                "--purpose",
                PURPOSE_WARRANT,
                "--tenant-id",
                "tenant-a",
                "--key-id",
                "alias/velvet",
                "--json",
            ]
        )
        == 0
    )
    signature = json.loads(capsys.readouterr().out)
    signature_path = tmp_path / "signature.json"
    signature_path.write_text(json.dumps(signature, sort_keys=True), encoding="utf-8")

    assert (
        main(
            [
                "signing",
                "verify",
                "--provider",
                "aws-kms",
                "--payload-hash",
                payload_hash,
                "--signature-file",
                str(signature_path),
                "--purpose",
                PURPOSE_WARRANT,
                "--tenant-id",
                "tenant-a",
                "--key-id",
                "alias/velvet",
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "pass"
    assert report["provider_name"] == "aws_kms"


def test_mcp_firewall_artifacts_can_use_fake_enterprise_signer(tmp_path: Path) -> None:
    signer = AwsKmsSigner(key_id="alias/velvet", client=FakeAwsKmsClient())
    payload = run_mcp_firewall_pilot(
        tmp_path,
        signer=signer,
        signing_key_id="alias/velvet",
    )

    first_decision = cast(Mapping[str, Any], payload["decisions"][0])
    warrant = cast(Mapping[str, Any], first_decision["warrant"])
    assert warrant["canonical_action_hash"] == first_decision["canonical_action_hash"]
    admission_evidence = cast(Mapping[str, Any], first_decision["admission_evidence"])
    assert cast(Mapping[str, Any], admission_evidence["signature"])[
        "provider_name"
    ] == "aws_kms"

    ledger_path = Path(str(payload["artifacts"]["ledger_path"]))
    first_record = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[0])
    assert first_record["canonical_action_hash"] == first_decision["canonical_action_hash"]
    record_evidence = cast(Mapping[str, Any], first_record["admission_evidence"])
    assert cast(Mapping[str, Any], record_evidence["signature"])["provider_name"] == "aws_kms"

    evidence_pack = cast(Mapping[str, Any], payload["evidence_pack"])
    assert evidence_pack["summary"]["controls_attention"] == 0

    approvals_path = Path(str(payload["artifacts"]["approvals_path"]))
    snapshot = ApprovalStore(
        approvals_path,
        signer=signer,
        signing_key_id="alias/velvet",
    ).load()
    request = next(iter(snapshot.requests))
    receipt = ApprovalStore(
        approvals_path,
        signer=signer,
        signing_key_id="alias/velvet",
    ).decide(
        request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )
    assert receipt.signature["provider_name"] == "aws_kms"
    assert receipt.verify_signature(signer=signer)

    verification = verify_mcp_firewall_pilot(tmp_path, signer=signer)
    assert verification["status"] == "pass"


def test_signed_artifacts_fail_after_tamper(tmp_path: Path) -> None:
    decision = VelvetMCP(
        policies=(
            VelvetToolPolicy(
                server="servicenow",
                tool="create_change_request",
                risk_class=ToolRiskClass.HIGH,
            ),
        )
    ).authorize(
        VelvetToolCall(
            server="servicenow",
            tool="create_change_request",
            arguments={"service": "payments"},
        )
    )
    selected = decision.selected_warrant
    assert selected is not None
    warrant_payload = selected.to_dict()
    assert VelvetWarrant.verify_payload_signature(warrant_payload)
    tampered_warrant = dict(warrant_payload)
    tampered_warrant["reason"] = "tampered"
    assert not VelvetWarrant.verify_payload_signature(tampered_warrant)

    ledger_path = tmp_path / "ledger.vledger"
    record = VelvetLedger(ledger_path).write_admission_decision(
        decision,
        request={"server": "servicenow", "tool": "create_change_request"},
    )
    assert verify_velvet_ledger(ledger_path)["status"] == "pass"
    tampered_record = dict(record)
    tampered_record["decision"] = "execute"
    _write_binary_records(ledger_path, [tampered_record])
    assert verify_velvet_ledger(ledger_path)["status"] == "fail"

    approvals_path = tmp_path / "approvals.json"
    store = ApprovalStore(approvals_path)
    request = store.create_request(decision, original_request={"tool": "create_change_request"})
    assert request is not None
    receipt = store.decide(
        request.approval_request_id,
        status=ApprovalStatus.APPROVED,
        approver="change-manager@example.com",
        reason="approved",
    )
    assert receipt.verify_signature()
    assert not replace(receipt, reason="tampered").verify_signature()

    fresh_ledger = tmp_path / "fresh_ledger.vledger"
    VelvetLedger(fresh_ledger).write_admission_decision(
        decision,
        request={"server": "servicenow", "tool": "create_change_request"},
    )
    pack = build_evidence_pack(fresh_ledger, approvals_path=approvals_path)
    assert verify_evidence_manifest(pack)
    tampered_pack = dict(pack)
    tampered_pack["summary"] = dict(pack["summary"])
    tampered_pack["summary"]["records"] = 99
    assert not verify_evidence_manifest(tampered_pack)


def test_verify_warrant_cli_round_trips_warrant_and_launch_ledger(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    decision = VelvetMCP(
        policies=(
            VelvetToolPolicy(
                server="linear",
                tool="create_issue",
                risk_class=ToolRiskClass.HIGH,
            ),
        )
    ).authorize(
        VelvetToolCall(
            server="linear",
            tool="create_issue",
            arguments={"title": "Investigate signing"},
        )
    )
    selected = decision.selected_warrant
    assert selected is not None
    warrant_path = tmp_path / "warrant.json"
    warrant_path.write_text(json.dumps(selected.to_dict(), sort_keys=True), encoding="utf-8")
    assert (
        main(
            [
                "verify-warrant",
                "--file",
                str(warrant_path),
                "--public-key-file",
                str(DEMO_ED25519_PUBLIC_KEY_PATH),
                "--json",
            ]
        )
        == 0
    )
    warrant_report = json.loads(capsys.readouterr().out)
    assert warrant_report["status"] == "pass"

    launch_dir = tmp_path / "launch"
    assert main(["launch-demo", "--output-dir", str(launch_dir), "--json"]) == 0
    capsys.readouterr()
    ledger_record_path = launch_dir / "first_ledger_record.json"
    first_record = next(iter(read_ledger_records(launch_dir / "velvet_ledger.vledger")))
    ledger_record_path.write_text(json.dumps(first_record, sort_keys=True), encoding="utf-8")
    assert (
        main(
            [
                "verify-warrant",
                "--file",
                str(ledger_record_path),
                "--public-key-file",
                str(DEMO_ED25519_PUBLIC_KEY_PATH),
                "--json",
            ]
        )
        == 0
    )
    ledger_report = json.loads(capsys.readouterr().out)
    assert ledger_report["status"] == "pass"
    assert ledger_report["artifact_type"] == "ledger_record"


def test_execution_permit_and_proof_envelope_signatures_fail_after_tamper() -> None:
    contract = AdmissionContract(default_authority_budget=10_000)
    outcome = VelvetAdmissionLayer(contract).evaluate(
        {
            "surface": "function",
            "name": "refund",
            "operation": "refund",
            "refund_amount": 100,
            "boundary_key": "case:signing",
        },
        logical_step=1,
    )

    signer = load_demo_ed25519_signer()
    record = build_pre_execution_record(outcome, request={"tool": "refund"})
    prepared = prepare_execution(
        outcome,
        actual_request={"tool": "refund"},
        pre_execution_record=record,
        contract=contract,
        signer=signer,
        signing_key_id=DEMO_ED25519_KEY_ID,
    )
    permit = prepared.permit
    checks = verify_execution_permit(
        permit,
        prepared_context_for_test(permit, signer=signer),
    )
    assert all(check["status"] == "pass" for check in checks)
    tampered = replace(permit, audience="other-executor")
    tampered_checks = verify_execution_permit(
        tampered,
        prepared_context_for_test(permit, signer=signer),
    )
    assert any(check["status"] == "fail" for check in tampered_checks)

    assert outcome.envelope.verify_signature(contract)
    assert not replace(outcome.envelope, admission_price=999).verify_signature(contract)
