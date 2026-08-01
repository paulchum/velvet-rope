from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

from velvet.ledger import (
    LEDGER_GENESIS_HASH,
    LedgerSequenceState,
    ledger_record_for_decision,
    ledger_record_hash,
    validate_ledger_record,
)
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.rope import AdmissionDecision, VelvetToolCall
from velvet.serialization import canonical_hash_sha256
from velvet.state_transition import (
    StateTransitionCommitError,
    StateTransitionLedgerStore,
    StateTransitionValidationError,
    build_state_transition_certificate,
    state_transition_certificate_hash,
    validate_state_transition_certificate,
    write_set_hash,
)
from velvet.types import StateTransitionCertificate

ROOT = Path(__file__).resolve().parents[1]


def _hash(label: str) -> str:
    return canonical_hash_sha256({"fixture": label})


def _state_hash(state: dict[str, Any]) -> str:
    return canonical_hash_sha256({"state": state})


def _patch(post_state_hash: str) -> dict[str, Any]:
    return {
        "op": "replace",
        "path": "/quota/used",
        "value": 1,
        "write_set": ["quota.used"],
        "post_state_hash": post_state_hash,
    }


def _certificate(
    *,
    pre_state_hash: str | None = None,
    post_state_hash: str | None = None,
    write_set: list[str] | None = None,
    actual_write_set: list[str] | None = None,
    cas_sequence: int = 1,
) -> StateTransitionCertificate:
    pre = pre_state_hash or _state_hash({"quota": {"used": 0}})
    post = post_state_hash or _state_hash({"quota": {"used": 1}})
    declared = write_set or ["quota.used"]
    return build_state_transition_certificate(
        pre_state_hash=pre,
        post_state_hash=post,
        patch=_patch(post),
        write_set=declared,
        actual_write_set=actual_write_set,
        policy_predicate_id="policy.shared_state.quota_update",
        policy_predicate_hash=_hash("policy-predicate"),
        invariant_id="invariant.quota.nonnegative",
        invariant_hash=_hash("invariant"),
        warrant_hash=_hash("warrant"),
        transaction_id=f"txn-{cas_sequence}",
        cas_sequence=cas_sequence,
    )


def _request() -> dict[str, Any]:
    return dict(next(iter(load_requests(ROOT / "examples" / "mcp" / "workflow.json"))))


def _decision_for_request(request: dict[str, Any]) -> AdmissionDecision:
    adapter = DirectVelvetMCPAdapter.from_list_file(ROOT / "examples" / "mcp" / "list.json")
    return adapter.firewall.authorize(
        VelvetToolCall(
            server=str(request["server"]),
            tool=str(request["tool"]),
            arguments=cast(dict[str, Any], request.get("arguments", {})),
            user_request=str(request.get("user_request", "")),
            untrusted_content=cast(str | None, request.get("untrusted_content")),
        ),
        state=cast(dict[str, object] | None, request.get("state")),
    )


def _ledger_record(certificate: StateTransitionCertificate) -> dict[str, Any]:
    request = _request()
    return ledger_record_for_decision(
        _decision_for_request(request),
        sequence_state=LedgerSequenceState(1, LEDGER_GENESIS_HASH),
        request=request,
        label="state_transition_safety",
        state_transition_certificate=certificate,
    )


def test_valid_authorized_transition_commits_and_advances_cas_sequence() -> None:
    pre = _state_hash({"quota": {"used": 0}})
    post = _state_hash({"quota": {"used": 1}})
    store = StateTransitionLedgerStore(pre)
    certificate = _certificate(pre_state_hash=pre, post_state_hash=post, cas_sequence=1)

    committed = store.commit(certificate)

    assert committed.transition_proof_hash == certificate.expected_transition_proof_hash()
    assert store.current_state_hash == post
    assert store.sequence == 1
    assert store.snapshot() == {"current_state_hash": post, "sequence": 1}


def test_stale_pre_state_hash_fails_closed() -> None:
    current = _state_hash({"quota": {"used": 1}})
    stale = _state_hash({"quota": {"used": 0}})
    store = StateTransitionLedgerStore(current)
    certificate = _certificate(pre_state_hash=stale, cas_sequence=1)

    with pytest.raises(StateTransitionCommitError, match="stale pre_state_hash"):
        store.commit(certificate)

    assert store.current_state_hash == current
    assert store.sequence == 0


def test_actual_write_set_mismatch_fails_validation() -> None:
    certificate = _certificate()
    payload = certificate.to_dict()
    payload["actual_write_set_hash"] = write_set_hash(["quota.limit"])
    payload["transition_proof_hash"] = StateTransitionCertificate.build_transition_proof_hash(
        payload
    )
    mismatched = StateTransitionCertificate.from_dict(payload)

    with pytest.raises(StateTransitionValidationError, match="actual write-set hash"):
        validate_state_transition_certificate(mismatched)


def test_out_of_band_write_simulation_fails_next_commit() -> None:
    pre = _state_hash({"quota": {"used": 0}})
    out_of_band = _state_hash({"quota": {"used": 99}})
    post = _state_hash({"quota": {"used": 1}})
    store = StateTransitionLedgerStore(pre)
    store.simulate_out_of_band_write(out_of_band)
    certificate = _certificate(pre_state_hash=pre, post_state_hash=post, cas_sequence=1)

    with pytest.raises(StateTransitionCommitError, match="stale pre_state_hash"):
        store.commit(certificate)

    assert store.current_state_hash == out_of_band
    assert store.sequence == 0


def test_tampered_patch_hash_fails_validation() -> None:
    certificate = _certificate()
    payload = certificate.to_dict()
    payload["canonical_patch_hash"] = _hash("tampered-patch")
    payload["transition_proof_hash"] = StateTransitionCertificate.build_transition_proof_hash(
        payload
    )
    tampered = StateTransitionCertificate.from_dict(payload)

    errors = validate_state_transition_certificate(
        tampered,
        expected_patch=_patch(certificate.post_state_hash),
        raise_error=False,
    )

    assert {error["code"] for error in errors} == {"state_transition_patch_hash_mismatch"}


def test_ledger_record_hash_changes_when_transition_certificate_changes() -> None:
    first = _certificate()
    second = _certificate(
        post_state_hash=_state_hash({"quota": {"used": 2}}),
        cas_sequence=2,
    )
    record = _ledger_record(first)
    changed_record = deepcopy(record)
    changed_record["state_transition_certificate"] = second.to_dict()
    changed_record["state_transition_certificate_hash"] = state_transition_certificate_hash(
        second
    )

    assert ledger_record_hash(record) == record["record_hash"]
    assert ledger_record_hash(record) != ledger_record_hash(changed_record)


def test_schema_accepts_valid_transition_record_and_rejects_missing_required_field() -> None:
    record = _ledger_record(_certificate())
    schema = json.loads(
        (ROOT / "schemas" / "velvet_rope" / "ledger_record.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)

    assert list(validator.iter_errors(record)) == []
    assert validate_ledger_record(record, raise_error=False) == []

    invalid = deepcopy(record)
    certificate = cast(dict[str, Any], invalid["state_transition_certificate"])
    del certificate["pre_state_hash"]

    assert list(validator.iter_errors(invalid))
    assert validate_ledger_record(invalid, raise_error=False)
