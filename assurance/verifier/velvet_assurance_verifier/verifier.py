"""Dependency-light offline verifier for Velvet assurance attestations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTROL_STATE_ATTESTATION_SCHEMA_VERSION = "velvet.assurance.control_state_attestation.v1"
CONTROL_STATE_ATTESTATION_ENVELOPE_SCHEMA_VERSION = (
    "velvet.assurance.control_state_attestation.envelope.v1"
)
PURPOSE_CONTROL_STATE_ATTESTATION = "velvet.assurance.control_state_attestation.v1"
SIGNATURE_SCHEMA_VERSIONS = {"velvet.signature.v1", "velvet.signature.v2"}
VERIFICATION_REPORT_SCHEMA_VERSION = "velvet.assurance.verification_report.v1"
MERKLE_CONSISTENCY_PROOF_SCHEMA_VERSION = "velvet.vault.merkle_consistency_proof.v1"
EMPTY_TREE_HASH = hashlib.sha256(b"").digest()
DECISION_CLASSES = ("admit", "block", "escalate", "defer", "skip")
RISK_CLASSES = (
    "unknown",
    "low",
    "medium",
    "high",
    "unlisted",
    "destructive",
    "bind_external",
    "spend",
    "irreversible",
    "other",
)
RETENTION_PRESETS = {
    "unavailable",
    "eu_ai_act_minimum",
    "minimal",
    "standard",
    "extended",
    "legal_hold",
}
POLICY_SIGNATURE_STATUSES = {"valid", "invalid", "unavailable", "degraded"}
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ISO_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def load_attestations_jsonl(path: str | Path) -> list[dict[str, Any]]:
    attestations: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            if not isinstance(payload, dict):
                raise ValueError(f"line {line_number}: expected JSON object")
            attestations.append(payload)
    return attestations


def load_consistency_proofs(path: str | Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        proofs = payload.get("proofs", [])
        if isinstance(proofs, list):
            return [dict(item) for item in proofs if isinstance(item, dict)]
    raise ValueError("consistency proof file must be a list or an object with proofs")


def load_anchor_sths(path: str | Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if "sths" in payload and isinstance(payload["sths"], list):
            return [dict(item) for item in payload["sths"] if isinstance(item, dict)]
        if "tree_size" in payload and "root_hash" in payload:
            return [dict(payload)]
    raise ValueError("anchor STH file must be a list, a single STH, or an object with sths")


def verify_attestation_series(
    attestations: Sequence[Mapping[str, Any]],
    *,
    public_key: str | bytes,
    consistency_proofs: Sequence[Mapping[str, Any]] = (),
    anchored_sths: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    parsed_public_key = _load_public_key(public_key)
    ordered = sorted(attestations, key=_period_start_sort_key)

    payloads: list[Mapping[str, Any]] = []
    for index, envelope in enumerate(ordered):
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        ok_shape = (
            envelope.get("schema_version") == CONTROL_STATE_ATTESTATION_ENVELOPE_SCHEMA_VERSION
            and isinstance(payload, Mapping)
            and isinstance(signature, Mapping)
            and payload.get("schema_version") == CONTROL_STATE_ATTESTATION_SCHEMA_VERSION
        )
        _check(checks, "attestation_schema", ok_shape, index=index)
        if not ok_shape:
            issues.append(_issue("attestation_schema_unsupported", index=index))
            continue
        shape_errors = _payload_shape_errors(cast(Mapping[str, Any], payload))
        _check(checks, "attestation_payload_shape", not shape_errors, index=index)
        for code in shape_errors:
            issues.append(_issue(code, index=index))
        if shape_errors:
            continue
        payload_hash = _canonical_hash_sha256(payload)
        if envelope.get("payload_hash") != payload_hash:
            issues.append(_issue("payload_hash_mismatch", index=index))
            _check(checks, "payload_hash", False, index=index)
        else:
            _check(checks, "payload_hash", True, index=index)
        signature_ok = _verify_signature_record(
            cast(Mapping[str, Any], signature),
            expected_payload_hash=payload_hash,
            public_key=parsed_public_key,
        )
        _check(checks, "attestation_signature", signature_ok, index=index)
        if not signature_ok:
            issues.append(_issue("attestation_signature_invalid", index=index))
        payloads.append(cast(Mapping[str, Any], payload))

    _verify_periods(payloads, checks=checks, issues=issues)
    _verify_tree_growth_and_counts(
        payloads,
        consistency_proofs=consistency_proofs,
        anchored_sths=anchored_sths,
        checks=checks,
        issues=issues,
    )
    status = "fail" if any(issue["severity"] == "error" for issue in issues) else "pass"
    return {
        "schema_version": VERIFICATION_REPORT_SCHEMA_VERSION,
        "status": status,
        "attestation_count": len(attestations),
        "checks": checks,
        "issues": issues,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Velvet assurance attestations offline.")
    parser.add_argument("--attestations", required=True, help="Signed attestation JSONL file.")
    parser.add_argument("--public-key-file", required=True)
    parser.add_argument("--consistency-proofs")
    parser.add_argument("--anchor-sths")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = verify_attestation_series(
        load_attestations_jsonl(args.attestations),
        public_key=Path(args.public_key_file).read_text(encoding="utf-8"),
        consistency_proofs=load_consistency_proofs(args.consistency_proofs),
        anchored_sths=load_anchor_sths(args.anchor_sths),
    )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"Velvet assurance verification: {report['status'].upper()}")
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


def _verify_periods(
    payloads: Sequence[Mapping[str, Any]],
    *,
    checks: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    ok = True
    previous_end: datetime | None = None
    for index, payload in enumerate(payloads):
        period = cast(Mapping[str, Any], payload.get("period", {}))
        try:
            start = _parse_time(str(period.get("start")))
            end = _parse_time(str(period.get("end")))
        except ValueError:
            issues.append(_issue("period_timestamp_invalid", index=index))
            ok = False
            continue
        if end <= start:
            issues.append(_issue("period_not_positive", index=index))
            ok = False
        if previous_end is not None and start != previous_end:
            code = "period_overlap" if start < previous_end else "period_gap"
            issues.append(_issue(code, index=index))
            ok = False
        previous_end = end
    _check(checks, "period_continuity", ok)


def _verify_tree_growth_and_counts(
    payloads: Sequence[Mapping[str, Any]],
    *,
    consistency_proofs: Sequence[Mapping[str, Any]],
    anchored_sths: Sequence[Mapping[str, Any]],
    checks: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    proof_by_bounds: dict[tuple[int, int, str, str], Mapping[str, Any]] = {}
    proof_keys_ok = True
    for proof_index, proof in enumerate(consistency_proofs):
        try:
            proof_by_bounds[_proof_key(proof)] = proof
        except (TypeError, ValueError):
            issues.append(_issue("sth_consistency_proof_malformed", index=proof_index))
            proof_keys_ok = False
    anchors: list[tuple[int, str]] = []
    anchor_ok = True
    for anchor_index, anchor in enumerate(anchored_sths):
        size = anchor.get("tree_size")
        root = anchor.get("root_hash")
        if not _is_int_nonnegative(size) or not _is_hash(root):
            issues.append(_issue("anchor_sth_invalid", index=anchor_index))
            anchor_ok = False
            continue
        anchors.append((cast(int, size), cast(str, root)))
    root_by_anchor_size: dict[int, str] = {}
    for size, root in anchors:
        previous_root = root_by_anchor_size.get(size)
        if previous_root is not None and previous_root != root:
            issues.append(_issue("anchor_sth_conflict"))
            anchor_ok = False
        root_by_anchor_size[size] = root
    previous_size = 0
    previous_root = _encode_sha256(EMPTY_TREE_HASH)
    if payloads and anchors:
        first_evidence_plane = cast(Mapping[str, Any], payloads[0]["evidence_plane"])
        first_sth = cast(Mapping[str, Any], first_evidence_plane["latest_sth"])
        first_size = int(first_sth.get("tree_size", -1))
        eligible_anchors = [(size, root) for size, root in anchors if size <= first_size]
        if eligible_anchors:
            previous_size, previous_root = max(eligible_anchors, key=lambda item: item[0])

    growth_ok = True
    proof_ok = proof_keys_ok
    count_ok = True
    for index, payload in enumerate(payloads):
        evidence_plane = cast(Mapping[str, Any], payload["evidence_plane"])
        sth = cast(Mapping[str, Any], evidence_plane["latest_sth"])
        current_size = int(sth.get("tree_size", -1))
        current_root = str(sth.get("root_hash"))
        anchored_root = root_by_anchor_size.get(current_size)
        if anchored_root is not None and anchored_root != current_root:
            issues.append(_issue("anchor_sth_root_mismatch", index=index))
            anchor_ok = False
        claimed = _claimed_decisions(payload)
        if current_size < previous_size:
            issues.append(_issue("sth_tree_size_decreased", index=index))
            growth_ok = False
            added = -1
        else:
            added = current_size - previous_size
        if added >= 0 and added < claimed:
            issues.append(
                _issue(
                    "decision_counts_exceed_tree_growth",
                    index=index,
                    expected_minimum=claimed,
                    actual=added,
                )
            )
            count_ok = False
        if current_size == previous_size:
            if current_root != previous_root:
                issues.append(_issue("sth_root_changed_without_growth", index=index))
                proof_ok = False
        elif previous_size != 0:
            key = (previous_size, current_size, previous_root, current_root)
            matching_proof = proof_by_bounds.get(key)
            if matching_proof is None:
                issues.append(_issue("sth_consistency_proof_missing", index=index))
                proof_ok = False
            elif not _verify_consistency_proof_artifact(matching_proof):
                issues.append(_issue("sth_consistency_proof_invalid", index=index))
                proof_ok = False
        previous_size = current_size
        previous_root = current_root
    _check(checks, "sth_tree_growth", growth_ok)
    _check(checks, "sth_consistency_proofs", proof_ok)
    _check(checks, "decision_counts_vs_tree_growth", count_ok)
    _check(checks, "anchor_sths", anchor_ok)


def _verify_signature_record(
    record: Mapping[str, Any],
    *,
    expected_payload_hash: str,
    public_key: Ed25519PublicKey,
) -> bool:
    if record.get("schema_version") not in SIGNATURE_SCHEMA_VERSIONS:
        return False
    if record.get("algorithm") != "Ed25519":
        return False
    if record.get("purpose") != PURPOSE_CONTROL_STATE_ATTESTATION:
        return False
    if record.get("payload_hash") != expected_payload_hash:
        return False
    try:
        public_key.verify(
            base64.b64decode(str(record["signature"]).encode("ascii")),
            _signing_message(
                expected_payload_hash,
                str(record["purpose"]),
                str(record["tenant_id"]),
                str(record["key_id"]),
                provider_name=str(record["provider_name"]),
                algorithm=str(record["algorithm"]),
                key_version=str(record["key_version"]),
                schema_version=str(record["schema_version"]),
            ),
        )
    except Exception:
        return False
    return True


def _payload_shape_errors(payload: Mapping[str, Any]) -> list[str]:
    try:
        if not _exact_keys(
            payload,
            {
                "schema_version",
                "period",
                "deployment_id",
                "gateway_liveness",
                "policy_state",
                "decision_counts",
                "escalation_integrity",
                "drift_rejections",
                "certificate_coverage",
                "budget_safety",
                "evidence_plane",
                "degraded_flags",
            },
        ):
            return ["payload_shape_invalid"]
        if payload.get("schema_version") != CONTROL_STATE_ATTESTATION_SCHEMA_VERSION:
            return ["attestation_schema_unsupported"]
        period = _mapping(payload.get("period"))
        if not _exact_keys(period, {"start", "end"}) or not all(
            _is_iso(value) for value in (period.get("start"), period.get("end"))
        ):
            return ["payload_shape_invalid"]
        if not _is_hash(payload.get("deployment_id")):
            return ["payload_shape_invalid"]
        liveness = _mapping(payload.get("gateway_liveness"))
        if not _exact_keys(liveness, {"decisions_observed", "max_gap_seconds"}) or not all(
            _is_int_nonnegative(liveness.get(key))
            for key in ("decisions_observed", "max_gap_seconds")
        ):
            return ["payload_shape_invalid"]
        policy = _mapping(payload.get("policy_state"))
        if (
            not _exact_keys(
                policy,
                {
                    "active_policy_bundle_hash",
                    "bundle_signature_status",
                    "last_change_timestamp",
                },
            )
            or not _is_optional_hash(policy.get("active_policy_bundle_hash"))
            or policy.get("bundle_signature_status") not in POLICY_SIGNATURE_STATUSES
            or not _is_optional_iso(policy.get("last_change_timestamp"))
        ):
            return ["payload_shape_invalid"]
        counts = _mapping(payload.get("decision_counts"))
        if not _exact_keys(counts, set(DECISION_CLASSES)):
            return ["payload_shape_invalid"]
        for decision in DECISION_CLASSES:
            by_risk = _mapping(counts.get(decision))
            if not _exact_keys(by_risk, set(RISK_CLASSES)):
                return ["payload_shape_invalid"]
            if not all(_is_int_nonnegative(by_risk.get(risk_class)) for risk_class in RISK_CLASSES):
                return ["payload_shape_invalid"]
        escalation = _mapping(payload.get("escalation_integrity"))
        if (
            not _exact_keys(
                escalation,
                {
                    "escalations_in_period",
                    "valid_approval_receipts",
                    "valid_approval_receipt_fraction",
                },
            )
            or not _is_int_nonnegative(escalation.get("escalations_in_period"))
            or not _is_int_nonnegative(escalation.get("valid_approval_receipts"))
            or not _is_fraction(escalation.get("valid_approval_receipt_fraction"))
        ):
            return ["payload_shape_invalid"]
        drift = _mapping(payload.get("drift_rejections"))
        if not _exact_keys(
            drift,
            {"canonical_action_mismatch_refusals"},
        ) or not _is_int_nonnegative(drift.get("canonical_action_mismatch_refusals")):
            return ["payload_shape_invalid"]
        coverage = _mapping(payload.get("certificate_coverage"))
        if (
            not _exact_keys(
                coverage,
                {
                    "spend_class_actions",
                    "spend_class_deterministic_budget_certificate_fraction",
                    "irreversible_class_actions",
                    "irreversible_class_max_de_lockout_inspection_certificate_fraction",
                    "irreversible_class_verdict_certificate_fraction",
                },
            )
            or not _is_int_nonnegative(coverage.get("spend_class_actions"))
            or not _is_int_nonnegative(coverage.get("irreversible_class_actions"))
            or not _is_fraction(
                coverage.get("spend_class_deterministic_budget_certificate_fraction")
            )
            or not _is_fraction(
                coverage.get("irreversible_class_max_de_lockout_inspection_certificate_fraction")
            )
            or not _is_fraction(
                coverage.get("irreversible_class_verdict_certificate_fraction")
            )
        ):
            return ["payload_shape_invalid"]
        budget = _mapping(payload.get("budget_safety"))
        if (
            not _exact_keys(
                budget,
                {
                    "h1_true_hard_caps_present",
                    "h2_single_writer_accounting",
                    "max_configured_cap_usd",
                    "zero_overshoot_observed",
                },
            )
            or not isinstance(budget.get("h1_true_hard_caps_present"), bool)
            or not isinstance(budget.get("h2_single_writer_accounting"), bool)
            or not _is_decimal6(budget.get("max_configured_cap_usd"))
            or not isinstance(budget.get("zero_overshoot_observed"), bool)
        ):
            return ["payload_shape_invalid"]
        evidence = _mapping(payload.get("evidence_plane"))
        sth = _mapping(evidence.get("latest_sth"))
        if (
            not _exact_keys(
                evidence,
                {
                    "latest_sth",
                    "last_successful_external_anchor_timestamp",
                    "retention_preset",
                },
            )
            or not _exact_keys(sth, {"tree_size", "root_hash"})
            or not _is_int_nonnegative(sth.get("tree_size"))
            or not _is_hash(sth.get("root_hash"))
            or not _is_optional_iso(evidence.get("last_successful_external_anchor_timestamp"))
            or evidence.get("retention_preset") not in RETENTION_PRESETS
        ):
            return ["payload_shape_invalid"]
        degraded = _mapping(payload.get("degraded_flags"))
        if not _exact_keys(
            degraded,
            {"signing_degraded", "anchoring_degraded", "fail_open_condition_observed"},
        ) or not all(isinstance(degraded.get(key), bool) for key in degraded):
            return ["payload_shape_invalid"]
    except (TypeError, ValueError):
        return ["payload_shape_invalid"]
    return []


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected object")
    return cast(Mapping[str, Any], value)


def _exact_keys(value: Mapping[str, Any], expected: set[str]) -> bool:
    return set(value.keys()) == expected


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _is_optional_hash(value: Any) -> bool:
    return value is None or _is_hash(value)


def _is_iso(value: Any) -> bool:
    return isinstance(value, str) and ISO_Z_RE.fullmatch(value) is not None


def _is_optional_iso(value: Any) -> bool:
    return value is None or _is_iso(value)


def _is_int_nonnegative(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_fraction(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"^(?:0|1)\.[0-9]{6}$", value) is not None


def _is_decimal6(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"^[0-9]+\.[0-9]{6}$", value) is not None


def _load_public_key(material: str | bytes) -> Ed25519PublicKey:
    raw = material if isinstance(material, bytes) else material.encode("utf-8")
    text = raw.decode("utf-8", errors="ignore").strip()
    if "BEGIN" in text:
        public_key = serialization.load_pem_public_key(raw)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return public_key
    decoded = base64.b64decode(text.encode("ascii"), validate=True)
    if len(decoded) != 32:
        raise ValueError("raw Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(decoded)


def _signing_message(
    payload_hash: str,
    purpose: str,
    tenant_id: str,
    key_id: str,
    *,
    provider_name: str,
    algorithm: str,
    key_version: str,
    schema_version: str,
) -> bytes:
    return _canonical_dumps(
        {
            "schema_version": schema_version,
            "provider_name": provider_name,
            "algorithm": algorithm,
            "key_version": key_version,
            "key_id": key_id,
            "tenant_id": tenant_id,
            "purpose": purpose,
            "payload_hash": payload_hash,
        }
    ).encode("utf-8")


def _claimed_decisions(payload: Mapping[str, Any]) -> int:
    decision_counts = cast(Mapping[str, Any], payload.get("decision_counts", {}))
    total = 0
    for risk_counts in decision_counts.values():
        if isinstance(risk_counts, Mapping):
            total += sum(int(value) for value in risk_counts.values())
    return total


def _proof_key(proof: Mapping[str, Any]) -> tuple[int, int, str, str]:
    return (
        int(proof.get("old_tree_size", -1)),
        int(proof.get("new_tree_size", -1)),
        str(proof.get("old_root_hash")),
        str(proof.get("new_root_hash")),
    )


def _verify_consistency_proof_artifact(proof: Mapping[str, Any]) -> bool:
    try:
        if proof.get("schema_version") != MERKLE_CONSISTENCY_PROOF_SCHEMA_VERSION:
            return False
        return _verify_consistency_proof(
            old_tree_size=int(proof.get("old_tree_size", -1)),
            new_tree_size=int(proof.get("new_tree_size", -1)),
            old_root_hash=str(proof.get("old_root_hash")),
            new_root_hash=str(proof.get("new_root_hash")),
            proof=[str(item) for item in proof.get("proof", ())],
        )
    except (TypeError, ValueError):
        return False


def _verify_consistency_proof(
    *,
    old_tree_size: int,
    new_tree_size: int,
    old_root_hash: str,
    new_root_hash: str,
    proof: Sequence[str],
) -> bool:
    try:
        if old_tree_size < 0 or new_tree_size < 0 or old_tree_size > new_tree_size:
            return False
        old_root = _decode_sha256(old_root_hash)
        new_root = _decode_sha256(new_root_hash)
        proof_hashes = tuple(_decode_sha256(item) for item in proof)
        if old_tree_size == 0:
            return not proof_hashes and old_root == EMPTY_TREE_HASH
        if old_tree_size == new_tree_size:
            return not proof_hashes and old_root == new_root
        proof_iter = iter(proof_hashes)
        computed_old, computed_new = _consistency_roots_from_path(
            old_tree_size,
            new_tree_size,
            old_root,
            proof_iter,
            complete=True,
        )
        try:
            next(proof_iter)
            return False
        except StopIteration:
            return computed_old == old_root and computed_new == new_root
    except (ValueError, TypeError, StopIteration):
        return False


def _consistency_roots_from_path(
    old_size: int,
    new_size: int,
    old_root: bytes,
    proof_iter: Iterable[bytes],
    *,
    complete: bool,
) -> tuple[bytes, bytes]:
    if old_size == new_size:
        node = old_root if complete else next(iter(proof_iter))
        return node, node
    split = _largest_power_of_two_less_than(new_size)
    if old_size <= split:
        old_hash, new_left = _consistency_roots_from_path(
            old_size,
            split,
            old_root,
            proof_iter,
            complete=complete,
        )
        right = next(iter(proof_iter))
        return old_hash, _node_hash(new_left, right)
    old_right, new_right = _consistency_roots_from_path(
        old_size - split,
        new_size - split,
        old_root,
        proof_iter,
        complete=False,
    )
    left = next(iter(proof_iter))
    return _node_hash(left, old_right), _node_hash(left, new_right)


def _node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle nodes must be 32-byte digests")
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(value: int) -> int:
    if value <= 1:
        raise ValueError("value must be greater than 1")
    return 1 << ((value - 1).bit_length() - 1)


def _decode_sha256(value: str) -> bytes:
    if not value.startswith("sha256:"):
        raise ValueError("hash must be sha256-prefixed")
    raw = bytes.fromhex(value.removeprefix("sha256:"))
    if len(raw) != 32:
        raise ValueError("hash must be 32 bytes")
    return raw


def _encode_sha256(value: bytes) -> str:
    if len(value) != 32:
        raise ValueError("hash must be 32 bytes")
    return f"sha256:{value.hex()}"


def _period_start_sort_key(envelope: Mapping[str, Any]) -> str:
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        return ""
    period = payload.get("period")
    if not isinstance(period, Mapping):
        return ""
    return str(period.get("start", ""))


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _canonical_hash_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_dumps(value).encode('utf-8')).hexdigest()}"


def _canonical_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _check(checks: list[dict[str, Any]], name: str, ok: bool, **extra: Any) -> None:
    checks.append({"name": name, "status": "pass" if ok else "fail", **extra})


def _issue(code: str, *, index: int | None = None, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "severity": "error", **extra}
    if index is not None:
        payload["attestation_index"] = index
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
