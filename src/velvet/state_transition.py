"""Shared-state transition certificates and atomic CAS helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from threading import RLock
from typing import Any

from velvet.serialization import canonical_hash_sha256
from velvet.types import StateTransitionCertificate

JsonObject = dict[str, Any]

STATE_TRANSITION_CERTIFICATE_SCHEMA_VERSION = "velvet.state_transition_certificate.v1"
STATE_TRANSITION_PATCH_SCHEMA_VERSION = "velvet.state_transition_patch.v1"
STATE_TRANSITION_WRITE_SET_SCHEMA_VERSION = "velvet.state_transition_write_set.v1"
DEFAULT_STATE_TRANSITION_OBLIGATIONS = (
    "atomic_cas_commit_required",
    "policy_checked_on_current_pre_state",
    "canonical_patch_hash_bound_to_write_set_and_post_state",
    "exclusive_mediated_writes_required",
    "ledger_append_after_successful_transition",
)
DEFAULT_STATE_TRANSITION_THEOREM_REFS = (
    "docs/math/shared_state_transition_safety_theorem.txt#Theorem 1",
)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class StateTransitionValidationError(ValueError):
    """Raised when a transition certificate is not valid."""


class StateTransitionCommitError(ValueError):
    """Raised when a CAS transition cannot be committed."""


def canonical_patch_hash(patch: Any) -> str:
    """Return a domain-separated canonical hash for a state transition patch."""

    return canonical_hash_sha256(
        {
            "schema_version": STATE_TRANSITION_PATCH_SCHEMA_VERSION,
            "patch": patch,
        }
    )


def write_set_hash(write_set: Any) -> str:
    """Return a domain-separated canonical hash for a declared or actual write set."""

    return canonical_hash_sha256(
        {
            "schema_version": STATE_TRANSITION_WRITE_SET_SCHEMA_VERSION,
            "write_set": write_set,
        }
    )


def state_transition_certificate_hash(
    certificate: StateTransitionCertificate | Mapping[str, Any],
) -> str:
    return _as_certificate(certificate).transition_proof_hash


def build_state_transition_certificate(
    *,
    pre_state_hash: str,
    post_state_hash: str,
    patch: Any,
    write_set: Any,
    policy_predicate_id: str,
    policy_predicate_hash: str,
    invariant_id: str,
    invariant_hash: str,
    warrant_hash: str,
    transaction_id: str,
    cas_sequence: int,
    outcome: str = "committed",
    actual_write_set: Any | None = None,
    canonical_patch_hash_value: str | None = None,
    declared_write_set_hash: str | None = None,
    actual_write_set_hash: str | None = None,
    obligations: Sequence[str] | None = None,
    theorem_refs: Sequence[str] | None = None,
    schema_version: str = STATE_TRANSITION_CERTIFICATE_SCHEMA_VERSION,
) -> StateTransitionCertificate:
    """Build a deterministic hash-bound transition certificate."""

    patch_hash = canonical_patch_hash_value or canonical_patch_hash(patch)
    declared_hash = declared_write_set_hash or write_set_hash(write_set)
    actual_hash = actual_write_set_hash or write_set_hash(
        write_set if actual_write_set is None else actual_write_set
    )
    payload: JsonObject = {
        "schema_version": schema_version,
        "pre_state_hash": pre_state_hash,
        "post_state_hash": post_state_hash,
        "canonical_patch_hash": patch_hash,
        "declared_write_set_hash": declared_hash,
        "actual_write_set_hash": actual_hash,
        "policy_predicate_id": policy_predicate_id,
        "policy_predicate_hash": policy_predicate_hash,
        "invariant_id": invariant_id,
        "invariant_hash": invariant_hash,
        "warrant_hash": warrant_hash,
        "transaction_id": transaction_id,
        "cas_sequence": int(cas_sequence),
        "outcome": outcome,
        "obligations": list(obligations or DEFAULT_STATE_TRANSITION_OBLIGATIONS),
        "theorem_refs": list(theorem_refs or DEFAULT_STATE_TRANSITION_THEOREM_REFS),
    }
    payload["transition_proof_hash"] = StateTransitionCertificate.build_transition_proof_hash(
        payload
    )
    certificate = StateTransitionCertificate.from_dict(payload)
    validate_state_transition_certificate(
        certificate,
        expected_patch=patch,
        declared_write_set=write_set,
        actual_write_set=write_set if actual_write_set is None else actual_write_set,
    )
    return certificate


def validate_state_transition_certificate(
    certificate: StateTransitionCertificate | Mapping[str, Any],
    *,
    expected_pre_state_hash: str | None = None,
    expected_post_state_hash: str | None = None,
    expected_patch: Any | None = None,
    declared_write_set: Any | None = None,
    actual_write_set: Any | None = None,
    raise_error: bool = True,
) -> list[JsonObject]:
    """Validate the internal hash bindings of a state transition certificate."""

    errors: list[JsonObject] = []
    try:
        parsed = _as_certificate(certificate)
    except (TypeError, ValueError) as error:
        errors.append(_validation_error("state_transition_certificate_invalid", str(error)))
        _raise_if_requested(errors, raise_error)
        return errors

    if parsed.schema_version != STATE_TRANSITION_CERTIFICATE_SCHEMA_VERSION:
        errors.append(
            _validation_error(
                "state_transition_schema_version_invalid",
                "unsupported state transition certificate schema_version",
                expected=STATE_TRANSITION_CERTIFICATE_SCHEMA_VERSION,
                actual=parsed.schema_version,
                field="schema_version",
            )
        )

    for field_name in _certificate_hash_fields():
        value = str(getattr(parsed, field_name))
        if not HASH_RE.fullmatch(value):
            errors.append(
                _validation_error(
                    "state_transition_hash_invalid",
                    f"{field_name} must be a sha256 hash",
                    actual=value,
                    field=field_name,
                )
            )

    for field_name in (
        "policy_predicate_id",
        "invariant_id",
        "transaction_id",
        "outcome",
    ):
        if not str(getattr(parsed, field_name)).strip():
            errors.append(
                _validation_error(
                    "state_transition_field_empty",
                    f"{field_name} must not be empty",
                    field=field_name,
                )
            )

    if parsed.cas_sequence < 1:
        errors.append(
            _validation_error(
                "state_transition_cas_sequence_invalid",
                "cas_sequence must be positive",
                actual=parsed.cas_sequence,
                field="cas_sequence",
            )
        )
    if not parsed.obligations:
        errors.append(
            _validation_error(
                "state_transition_obligations_empty",
                "obligations must not be empty",
                field="obligations",
            )
        )
    if not parsed.theorem_refs:
        errors.append(
            _validation_error(
                "state_transition_theorem_refs_empty",
                "theorem_refs must not be empty",
                field="theorem_refs",
            )
        )
    if parsed.declared_write_set_hash != parsed.actual_write_set_hash:
        errors.append(
            _validation_error(
                "state_transition_write_set_mismatch",
                "actual write-set hash does not match declared write-set hash",
                expected=parsed.declared_write_set_hash,
                actual=parsed.actual_write_set_hash,
                field="actual_write_set_hash",
            )
        )

    expected_transition_hash = parsed.expected_transition_proof_hash()
    if parsed.transition_proof_hash != expected_transition_hash:
        errors.append(
            _validation_error(
                "state_transition_proof_hash_mismatch",
                "transition_proof_hash does not match the canonical certificate payload",
                expected=expected_transition_hash,
                actual=parsed.transition_proof_hash,
                field="transition_proof_hash",
            )
        )

    comparisons = (
        ("pre_state_hash", expected_pre_state_hash, parsed.pre_state_hash),
        ("post_state_hash", expected_post_state_hash, parsed.post_state_hash),
    )
    for field_name, expected, actual in comparisons:
        if expected is not None and expected != actual:
            errors.append(
                _validation_error(
                    "state_transition_expected_hash_mismatch",
                    f"{field_name} does not match expected value",
                    expected=expected,
                    actual=actual,
                    field=field_name,
                )
            )

    if expected_patch is not None:
        expected_hash = canonical_patch_hash(expected_patch)
        if parsed.canonical_patch_hash != expected_hash:
            errors.append(
                _validation_error(
                    "state_transition_patch_hash_mismatch",
                    "canonical_patch_hash does not match the supplied patch",
                    expected=expected_hash,
                    actual=parsed.canonical_patch_hash,
                    field="canonical_patch_hash",
                )
            )
    if declared_write_set is not None:
        expected_hash = write_set_hash(declared_write_set)
        if parsed.declared_write_set_hash != expected_hash:
            errors.append(
                _validation_error(
                    "state_transition_declared_write_set_hash_mismatch",
                    "declared_write_set_hash does not match the supplied write set",
                    expected=expected_hash,
                    actual=parsed.declared_write_set_hash,
                    field="declared_write_set_hash",
                )
            )
    if actual_write_set is not None:
        expected_hash = write_set_hash(actual_write_set)
        if parsed.actual_write_set_hash != expected_hash:
            errors.append(
                _validation_error(
                    "state_transition_actual_write_set_hash_mismatch",
                    "actual_write_set_hash does not match the supplied write set",
                    expected=expected_hash,
                    actual=parsed.actual_write_set_hash,
                    field="actual_write_set_hash",
                )
            )

    _raise_if_requested(errors, raise_error)
    return errors


class StateTransitionLedgerStore:
    """In-memory atomic CAS store for state transition tests and demos."""

    def __init__(self, initial_state_hash: str, *, initial_sequence: int = 0) -> None:
        if not HASH_RE.fullmatch(initial_state_hash):
            raise ValueError("initial_state_hash must be a sha256 hash")
        if initial_sequence < 0:
            raise ValueError("initial_sequence must be nonnegative")
        self._current_state_hash = initial_state_hash
        self._sequence = initial_sequence
        self._lock = RLock()

    @property
    def current_state_hash(self) -> str:
        with self._lock:
            return self._current_state_hash

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence

    def snapshot(self) -> JsonObject:
        with self._lock:
            return {
                "current_state_hash": self._current_state_hash,
                "sequence": self._sequence,
            }

    def commit(
        self,
        certificate: StateTransitionCertificate | Mapping[str, Any],
    ) -> StateTransitionCertificate:
        with self._lock:
            parsed = _as_certificate(certificate)
            validate_state_transition_certificate(parsed)
            if parsed.pre_state_hash != self._current_state_hash:
                raise StateTransitionCommitError(
                    "stale pre_state_hash does not match current state hash"
                )
            expected_sequence = self._sequence + 1
            if parsed.cas_sequence != expected_sequence:
                raise StateTransitionCommitError(
                    f"cas_sequence must equal next sequence {expected_sequence}"
                )
            self._current_state_hash = parsed.post_state_hash
            self._sequence = parsed.cas_sequence
            return parsed

    def simulate_out_of_band_write(self, new_state_hash: str) -> None:
        if not HASH_RE.fullmatch(new_state_hash):
            raise ValueError("new_state_hash must be a sha256 hash")
        with self._lock:
            self._current_state_hash = new_state_hash


def _as_certificate(
    certificate: StateTransitionCertificate | Mapping[str, Any],
) -> StateTransitionCertificate:
    if isinstance(certificate, StateTransitionCertificate):
        return certificate
    if isinstance(certificate, Mapping):
        return StateTransitionCertificate.from_dict(certificate)
    raise TypeError("certificate must be a StateTransitionCertificate or mapping")


def _certificate_hash_fields() -> tuple[str, ...]:
    return (
        "pre_state_hash",
        "post_state_hash",
        "canonical_patch_hash",
        "declared_write_set_hash",
        "actual_write_set_hash",
        "policy_predicate_hash",
        "invariant_hash",
        "warrant_hash",
        "transition_proof_hash",
    )


def _validation_error(
    code: str,
    message: str,
    *,
    expected: Any | None = None,
    actual: Any | None = None,
    field: str | None = None,
) -> JsonObject:
    payload: JsonObject = {
        "code": code,
        "severity": "error",
        "message": message,
    }
    if expected is not None:
        payload["expected"] = expected
    if actual is not None:
        payload["actual"] = actual
    if field is not None:
        payload["field"] = field
    return payload


def _raise_if_requested(errors: Sequence[Mapping[str, Any]], raise_error: bool) -> None:
    if raise_error and errors:
        first = errors[0]
        raise StateTransitionValidationError(str(first["message"]))
