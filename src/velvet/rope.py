"""Product-facing rope and Velvet MCP wrappers.

These classes do not replace the Rust router. They turn the existing
deterministic routing decision into a product envelope that an application,
MCP client, or developer-agent control plane can consume directly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from velvet.integrations import IntegrationExecutor
from velvet.policy_bundle import (
    PolicyBundleError,
    PolicyBundleExpired,
    PolicyBundleMissing,
    VerifiedPolicyBundle,
    load_policy_bundle,
    policy_bundle_status_for_error,
)
from velvet.router import Router
from velvet.serialization import (
    canonical_hash_sha256,
    canonical_json_v1_bytes,
    canonical_json_v1_hash,
    proof_artifact_hash,
    quantize_decimal,
)
from velvet.signing import (
    LOCAL_DEMO_KEY_ID,
    LOCAL_DEMO_SIGNATURE_KEY,
    LOCAL_DEMO_TENANT_ID,
    PURPOSE_WARRANT,
    SigningProvider,
    default_demo_signer,
    resolve_ed25519_signing_provider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.thread_log import ThreadLogger
from velvet.types import (
    ActionType,
    AdmissionScore,
    BudgetState,
    CandidateAction,
    CandidateDecision,
    CandidateSource,
    DecisionType,
    PolicyTraceEntry,
    RouteRunResult,
    RoutingDecision,
    ThreadCandidateAction,
    ThreadRecord,
)

JsonObject = dict[str, Any]

WARRANT_CANONICALIZATION = "velvet.canonical_json.sha256.unsigned_payload"
LOCAL_DEMO_ISSUED_AT = "1970-01-01T00:00:00Z"
LOCAL_DEMO_SIGNING_ALGORITHM = "HMAC-SHA256"
DEFAULT_WARRANT_EXPIRES_AT = "9999-12-31T23:59:59Z"
DEFAULT_WARRANT_ISSUER = "velvet"


@dataclass(frozen=True)
class VelvetWarrant:
    """A compact, replayable explanation for one candidate action."""

    action_type: ActionType
    decision: DecisionType
    reason: str
    selected: bool
    clears_rope: bool | None
    expected_upside: float | None
    surprisal: float | None
    confidence: float | None
    clearance_score: float | None
    final_lambda: float | None
    scarcity_pressure: float | None
    cost_penalty: float | None
    risk_penalty: float | None
    tool_key: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    risk_class: str | None = None
    pricing_status: str = "not_priced"
    policy_statuses: tuple[str, ...] = ()
    policy_reasons: tuple[str, ...] = ()
    jurisdiction_evidence: tuple[JsonObject, ...] = ()
    certificate: Mapping[str, Any] | None = None
    warrant_id: str = ""
    issued_at: str = LOCAL_DEMO_ISSUED_AT
    tenant_id: str | None = None
    environment: str = "local_demo"
    product_surface: str = "velvet_rope"
    actor_user_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    seal_id: str | None = None
    bound_seal_id: str | None = None
    thread_id: str | None = None
    data_class: str | None = None
    policy_hash: str | None = None
    policy_version: str | None = None
    request_hash: str | None = None
    tool_schema_hash: str | None = None
    arguments_hash: str | None = None
    approval_required: bool = False
    approval_request_id: str | None = None
    ledger_record_hash: str | None = None
    canonicalization: str = WARRANT_CANONICALIZATION
    warrant_hash: str = ""
    signature: Mapping[str, Any] | str | None = None
    signing_key_id: str | None = None
    signing_provider: str | None = None
    signing_algorithm: str | None = None
    signing_key_version: str | None = None

    def __post_init__(self) -> None:
        if self.bound_seal_id is None and self.seal_id is not None:
            object.__setattr__(self, "bound_seal_id", self.seal_id)
        if self.warrant_id == "":
            object.__setattr__(self, "warrant_id", self._computed_warrant_id())
        if self.warrant_hash == "":
            object.__setattr__(self, "warrant_hash", self.compute_warrant_hash())

    @classmethod
    def from_candidate(
        cls,
        candidate: CandidateDecision,
        *,
        selected: bool,
        supplemental_score: AdmissionScore | None = None,
        seal_id: str | None = None,
        thread_id: str | None = None,
        product_surface: str = "velvet_rope",
        state: Mapping[str, object] | None = None,
        policy_hash: str | None = None,
        policy_version: str | None = None,
    ) -> VelvetWarrant:
        score = candidate.admission_score or supplemental_score
        metadata = candidate.final_candidate.metadata
        parameters = candidate.final_candidate.parameters
        policy_reasons = tuple(
            entry.decision.reason.code
            for entry in candidate.policy_trace
            if entry.decision.reason is not None
        )
        jurisdiction_evidence = tuple(
            entry.jurisdiction_evidence.to_dict()
            for entry in candidate.policy_trace
            if entry.jurisdiction_evidence is not None
        )
        effect = candidate.effect_vector
        objective = (
            candidate.admission_trace.objective_components
            if candidate.admission_trace is not None
            else None
        )
        derived_expected_upside = (
            effect.utility_bound.expected_bps / 10_000.0 if effect is not None else None
        )
        derived_confidence = (
            effect.utility_bound.confidence_bps / 10_000.0 if effect is not None else None
        )
        derived_clearance = (
            objective.objective_bps / 10_000.0 if objective is not None else None
        )
        derived_cost_penalty = (
            objective.cost_penalty_bps / 10_000.0 if objective is not None else None
        )
        derived_risk_penalty = (
            objective.risk_penalty_bps / 10_000.0 if objective is not None else None
        )
        derived_scarcity = (
            effect.cost_bound.upper_microusd / 1_000_000.0 if effect is not None else None
        )
        derived_entry_price = max(
            value
            for value in (
                derived_cost_penalty,
                derived_risk_penalty,
                derived_scarcity,
                0.0,
            )
            if value is not None
        )
        return cls(
            action_type=candidate.action_type,
            decision=candidate.decision,
            reason=candidate.reason,
            selected=selected,
            clears_rope=(
                score.clears_rope
                if score is not None
                else candidate.decision == DecisionType.EXECUTE
            ),
            expected_upside=score.expected_upside if score is not None else derived_expected_upside,
            surprisal=score.surprisal if score is not None else None,
            confidence=score.confidence if score is not None else derived_confidence,
            clearance_score=score.clearance_score if score is not None else derived_clearance,
            final_lambda=(
                score.pricing_breakdown.final_lambda
                if score is not None
                else derived_entry_price
            ),
            scarcity_pressure=(
                score.pricing_breakdown.scarcity_pressure if score is not None else derived_scarcity
            ),
            cost_penalty=score.cost_penalty if score is not None else derived_cost_penalty,
            risk_penalty=score.risk_penalty if score is not None else derived_risk_penalty,
            tool_key=_metadata_string(metadata, "mcp_tool_key")
            or _metadata_string(candidate.final_candidate.parameters, "tool_name"),
            mcp_server=_metadata_string(metadata, "mcp_server"),
            mcp_tool=_metadata_string(metadata, "mcp_tool"),
            risk_class=_metadata_string(metadata, "risk_class"),
            pricing_status=_pricing_status(candidate, supplemental_score),
            policy_statuses=tuple(
                f"{entry.policy_name}:{entry.status}" for entry in candidate.policy_trace
            ),
            policy_reasons=policy_reasons,
            jurisdiction_evidence=jurisdiction_evidence,
            certificate=_candidate_certificate(candidate.final_candidate),
            issued_at=_context_string(state, "issued_at")
            or _context_string(state, "decision_timestamp")
            or _context_string(state, "timestamp")
            or LOCAL_DEMO_ISSUED_AT,
            tenant_id=_tenant_id(state),
            environment=_environment(state, metadata, parameters),
            product_surface=product_surface,
            actor_user_id=_actor_user_id(state),
            agent_id=_agent_id(state, metadata),
            session_id=_context_string(state, "session_id"),
            request_id=_request_id(state, metadata),
            seal_id=seal_id,
            bound_seal_id=seal_id,
            thread_id=thread_id,
            data_class=_data_class(state, metadata, parameters),
            policy_hash=policy_hash or _policy_hash(candidate.policy_trace),
            policy_version=policy_version or _policy_version(candidate.policy_trace),
            tool_schema_hash=_metadata_hash(metadata, "tool_schema_hash"),
            arguments_hash=_arguments_hash(parameters),
            approval_required=candidate.decision
            in {DecisionType.ESCALATE, DecisionType.ASK_APPROVAL},
        )

    @classmethod
    def manual_block(
        cls,
        candidate: CandidateAction,
        *,
        reason: str,
        rule_id: str,
        details: Mapping[str, Any],
        risk_class: str | None = None,
        seal_id: str | None = None,
        thread_id: str | None = None,
        product_surface: str = "velvet_mcp",
        state: Mapping[str, object] | None = None,
        policy_hash: str | None = None,
        policy_version: str | None = None,
        policy_statuses: tuple[str, ...] = ("velvet_mcp:block",),
    ) -> VelvetWarrant:
        metadata = candidate.metadata
        parameters = candidate.parameters
        return cls(
            action_type=candidate.action_type,
            decision=DecisionType.BLOCK,
            reason=reason,
            selected=True,
            clears_rope=False,
            expected_upside=None,
            surprisal=None,
            confidence=None,
            clearance_score=None,
            final_lambda=None,
            scarcity_pressure=None,
            cost_penalty=None,
            risk_penalty=None,
            tool_key=_metadata_string(metadata, "mcp_tool_key")
            or _metadata_string(candidate.parameters, "tool_name")
            or _metadata_string(details, "tool"),
            mcp_server=_metadata_string(metadata, "mcp_server"),
            mcp_tool=_metadata_string(metadata, "mcp_tool"),
            risk_class=risk_class or _metadata_string(metadata, "risk_class"),
            pricing_status="denied_at_rope",
            policy_statuses=policy_statuses,
            policy_reasons=(rule_id,),
            jurisdiction_evidence=(
                {
                    "rule_id": rule_id,
                    "evidence_type": "velvet_mcp",
                    "message": reason,
                    "details": dict(details),
                },
            ),
            certificate=_candidate_certificate(candidate),
            issued_at=_context_string(state, "issued_at")
            or _context_string(state, "decision_timestamp")
            or _context_string(state, "timestamp")
            or LOCAL_DEMO_ISSUED_AT,
            tenant_id=_tenant_id(state),
            environment=_environment(state, metadata, parameters),
            product_surface=product_surface,
            actor_user_id=_actor_user_id(state),
            agent_id=_agent_id(state, metadata),
            session_id=_context_string(state, "session_id"),
            request_id=_request_id(state, metadata),
            seal_id=seal_id,
            bound_seal_id=seal_id,
            thread_id=thread_id,
            data_class=_data_class(state, metadata, parameters),
            policy_hash=policy_hash,
            policy_version=policy_version,
            tool_schema_hash=_metadata_hash(metadata, "tool_schema_hash"),
            arguments_hash=_arguments_hash(parameters),
            approval_required=False,
        )

    @property
    def entry_price(self) -> float | None:
        return self.final_lambda

    def v1_unsigned_payload(self) -> JsonObject:
        return self.to_v1_dict(include_hash=False, include_signature=False)

    def v1_signature_payload(self) -> JsonObject:
        return self.to_v1_dict(include_hash=True, include_signature=False)

    def compute_warrant_hash(self) -> str:
        return proof_artifact_hash("warrant", self.to_v1_dict())

    def sign(
        self,
        signing_key: str | None = None,
        *,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
        signing_provider: str | None = None,
        signing_algorithm: str | None = None,
        tenant_id: str | None = None,
        signing_profile: str | None = None,
        dev_ephemeral_key: bool = False,
    ) -> VelvetWarrant:
        active_signer = signer or (
            default_demo_signer(signing_key) if signing_key is not None else None
        )
        if active_signer is None:
            active_signer = resolve_ed25519_signing_provider(
                signing_profile=signing_profile,
                dev_ephemeral_key=dev_ephemeral_key,
                key_id=signing_key_id,
            )
        resolved_signing_key_id = signing_key_id or signer_default_key_id(active_signer)
        unsigned = replace(
            self,
            signing_key_id=resolved_signing_key_id,
            signing_provider=signing_provider or active_signer.provider_name,
            signing_algorithm=signing_algorithm or active_signer.algorithm,
            signing_key_version=active_signer.key_version,
            warrant_hash="",
            signature=None,
        )
        signature = sign_payload_hash(
            unsigned.warrant_hash,
            purpose=PURPOSE_WARRANT,
            tenant_id=tenant_id or unsigned.tenant_id or LOCAL_DEMO_TENANT_ID,
            key_id=resolved_signing_key_id,
            signer=active_signer,
        )
        return replace(unsigned, signature=signature)

    def verify_hash(self) -> bool:
        return hmac.compare_digest(self.warrant_hash, self.compute_warrant_hash())

    def verify_signature(
        self,
        signing_key: str | None = None,
        *,
        signer: SigningProvider | None = None,
    ) -> bool:
        if self.signature is None:
            return False
        if not self.verify_hash():
            return False
        if isinstance(self.signature, Mapping):
            active_signer = signer or (
                default_demo_signer(signing_key) if signing_key is not None else None
            )
            return verify_signature_record(
                self.signature,
                self.warrant_hash,
                purpose=PURPOSE_WARRANT,
                tenant_id=self.tenant_id or LOCAL_DEMO_TENANT_ID,
                key_id=self.signing_key_id or LOCAL_DEMO_KEY_ID,
                signer=active_signer,
            )
        if signing_key is None:
            signing_key = LOCAL_DEMO_SIGNATURE_KEY
        return hmac.compare_digest(
            self.signature,
            _sign_payload(self.v1_signature_payload(), signing_key),
        )

    @classmethod
    def compute_hash_for_payload(cls, payload: Mapping[str, Any]) -> str:
        return proof_artifact_hash("warrant", payload)

    @classmethod
    def verify_payload_hash(cls, payload: Mapping[str, Any]) -> bool:
        warrant_hash = payload.get("warrant_hash")
        if not isinstance(warrant_hash, str):
            return False
        return hmac.compare_digest(warrant_hash, cls.compute_hash_for_payload(payload))

    @classmethod
    def verify_payload_signature(
        cls,
        payload: Mapping[str, Any],
        signing_key: str | None = None,
        *,
        signer: SigningProvider | None = None,
    ) -> bool:
        signature = payload.get("signature")
        if isinstance(signature, Mapping):
            if not cls.verify_payload_hash(payload):
                return False
            active_signer = signer or (
                default_demo_signer(signing_key) if signing_key is not None else None
            )
            return verify_signature_record(
                signature,
                cls.compute_hash_for_payload(payload),
                purpose=PURPOSE_WARRANT,
                tenant_id=_payload_string(payload, "tenant_id") or LOCAL_DEMO_TENANT_ID,
                key_id=_payload_string(payload, "signing_key_id") or LOCAL_DEMO_KEY_ID,
                signer=active_signer,
            )
        if not isinstance(signature, str):
            return False
        if signing_key is None:
            signing_key = LOCAL_DEMO_SIGNATURE_KEY
        return hmac.compare_digest(
            signature,
            _sign_payload(_signature_payload_from_dict(payload), signing_key),
        )

    def to_v1_dict(
        self,
        *,
        include_hash: bool = True,
        include_signature: bool = True,
    ) -> JsonObject:
        tool_name = self.tool_key or (
            f"{self.mcp_server}/{self.mcp_tool}"
            if self.mcp_server is not None and self.mcp_tool is not None
            else self.action_type.value
        )
        reason_codes = list(self.policy_reasons) or [_reason_code(self.reason)]
        obligations = _warrant_obligations(self.decision, self.approval_required)
        payload: JsonObject = {
            "warrant_id": self.warrant_id,
            "issued_at": _canonical_timestamp(self.issued_at),
            "tenant_id": self.tenant_id or LOCAL_DEMO_TENANT_ID,
            "environment": self.environment,
            "request_hash": _proof_hash_or_fallback(
                self.request_hash or self.arguments_hash,
                {
                    "tool_name": tool_name,
                    "action_type": self.action_type.value,
                    "request_id": self.request_id,
                },
            ),
            "policy_hash": _proof_hash_or_fallback(
                self.policy_hash,
                {"policy_reasons": reason_codes, "policy_statuses": list(self.policy_statuses)},
            ),
            "tool_schema_hash": _proof_hash_or_fallback(
                self.tool_schema_hash,
                {"tool_name": tool_name, "risk_class": self.risk_class or "unknown"},
            ),
            "tool_name": tool_name,
            "decision": _canonical_decision(self.decision.value),
            "reason_codes": reason_codes,
            "obligations": obligations,
            "approval_required": self.approval_required,
            "expires_at": DEFAULT_WARRANT_EXPIRES_AT,
            "issuer": DEFAULT_WARRANT_ISSUER,
            "product_surface": self.product_surface,
            "actor_user_id": self.actor_user_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "action_type": self.action_type.value,
            "reason": self.reason,
            "seal_id": self.seal_id,
            "bound_seal_id": self.bound_seal_id,
            "thread_id": self.thread_id,
            "tool_key": self.tool_key,
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "risk_class": self.risk_class or "unknown",
            "data_class": self.data_class,
            "policy_version": self.policy_version,
            "arguments_hash": self.arguments_hash,
            "jurisdiction_evidence": _canonical_json_v1_safe(
                list(self.jurisdiction_evidence)
            ),
            "policy_statuses": list(self.policy_statuses),
            "policy_reasons": list(self.policy_reasons),
            "approval_request_id": self.approval_request_id,
            "ledger_record_hash": self.ledger_record_hash,
            "signing_key_id": self.signing_key_id,
            "signing_provider": self.signing_provider,
            "signing_algorithm": self.signing_algorithm,
            "signing_key_version": self.signing_key_version,
        }
        if include_hash:
            payload["warrant_hash"] = self.warrant_hash
        if include_signature:
            payload["signature"] = self.signature
        return payload

    def to_dict(self) -> JsonObject:
        payload = self.to_v1_dict()
        payload.update(
            {
                "action_type": self.action_type.value,
                "decision": self.decision.value,
                "reason": self.reason,
                "selected": self.selected,
                "clears_rope": self.clears_rope,
                "expected_upside": self.expected_upside,
                "surprisal": self.surprisal,
                "confidence": self.confidence,
                "clearance_score": self.clearance_score,
                "final_lambda": self.final_lambda,
                "entry_price": self.entry_price,
                "scarcity_pressure": self.scarcity_pressure,
                "cost_penalty": self.cost_penalty,
                "risk_penalty": self.risk_penalty,
                "tool_key": self.tool_key,
                "mcp_server": self.mcp_server,
                "mcp_tool": self.mcp_tool,
                "risk_class": self.risk_class or "unknown",
                "pricing_status": self.pricing_status,
                "policy_statuses": list(self.policy_statuses),
                "policy_reasons": list(self.policy_reasons),
                "jurisdiction_evidence": list(self.jurisdiction_evidence),
            }
        )
        if self.certificate is not None:
            payload["certificate"] = dict(self.certificate)
        return payload

    def _computed_warrant_id(self) -> str:
        material = {
            "issued_at": self.issued_at,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "product_surface": self.product_surface,
            "actor_user_id": self.actor_user_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "action_type": self.action_type.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "seal_id": self.seal_id,
            "bound_seal_id": self.bound_seal_id,
            "thread_id": self.thread_id,
            "tool_key": self.tool_key,
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "risk_class": self.risk_class or "unknown",
            "data_class": self.data_class,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "tool_schema_hash": self.tool_schema_hash,
            "arguments_hash": self.arguments_hash,
            "policy_statuses": list(self.policy_statuses),
            "policy_reasons": list(self.policy_reasons),
            "jurisdiction_evidence": _canonical_json_v1_safe(
                list(self.jurisdiction_evidence)
            ),
            "approval_required": self.approval_required,
            "approval_request_id": self.approval_request_id,
            "canonicalization": self.canonicalization,
            "signing_key_version": self.signing_key_version,
        }
        return f"wrnt_{canonical_json_v1_hash(material)[:32]}"


@dataclass(frozen=True)
class AdmissionDecision:
    """A routing decision plus warrant."""

    decision: RoutingDecision
    warrants: tuple[VelvetWarrant, ...]
    product_surface: str = "velvet_rope"

    @property
    def selected_warrant(self) -> VelvetWarrant | None:
        return next((warrant for warrant in self.warrants if warrant.selected), None)

    def to_dict(self) -> JsonObject:
        return {
            "product_surface": self.product_surface,
            "seal_id": self.decision.seal_id,
            "thread_id": self.decision.thread_id,
            "decision": self.decision.to_dict(),
            "selected_warrant": self.selected_warrant.to_dict()
            if self.selected_warrant is not None
            else None,
            "warrants": [warrant.to_dict() for warrant in self.warrants],
        }


@dataclass(frozen=True)
class RopeRun:
    """Route-plus-execute result with a warrant."""

    run: RouteRunResult
    admission_decision: AdmissionDecision

    def to_dict(self) -> JsonObject:
        return {
            "run": self.run.to_dict(),
            "admission_decision": self.admission_decision.to_dict(),
        }


class VelvetRope:
    """Self-hosted decision rope over the canonical Velvet router."""

    def __init__(
        self,
        router: Router | None = None,
        *,
        policy_dir: str = "policies",
        chain: str = "default",
        policy_bundle: str | Path | VerifiedPolicyBundle | None = None,
        policy_bundle_signing_key: str | None = None,
        require_policy_bundle: bool = False,
        allow_expired_policy_degraded: bool = False,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
        signing_profile: str | None = None,
        dev_ephemeral_key: bool = False,
    ) -> None:
        self.require_policy_bundle = require_policy_bundle or policy_bundle is not None
        self.allow_expired_policy_degraded = allow_expired_policy_degraded
        self.policy_bundle: VerifiedPolicyBundle | None = None
        self.policy_bundle_error: PolicyBundleError | None = None
        self.signer = signer or resolve_ed25519_signing_provider(
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
            key_id=signing_key_id,
        )
        self.signing_key_id = signing_key_id or signer_default_key_id(self.signer)

        if policy_bundle is None and require_policy_bundle:
            self.policy_bundle_error = PolicyBundleMissing("policy bundle is required")
        elif policy_bundle is not None:
            try:
                self.policy_bundle = (
                    policy_bundle
                    if isinstance(policy_bundle, VerifiedPolicyBundle)
                    else load_policy_bundle(
                        policy_bundle,
                        signing_key=policy_bundle_signing_key,
                        allow_expired=allow_expired_policy_degraded,
                    )
                )
                if self.policy_bundle.expired and not allow_expired_policy_degraded:
                    self.policy_bundle_error = PolicyBundleExpired("policy bundle is expired")
                policy_dir = str(self.policy_bundle.materialize_policy_dir())
                chain = self.policy_bundle.policy_chain
            except PolicyBundleError as error:
                self.policy_bundle_error = error

        self.router = None if self._must_fail_closed_without_router() else router or Router(
            policy_dir=policy_dir,
            chain=chain,
        )

    @property
    def policy_hash(self) -> str | None:
        policy_bundle = self.policy_bundle
        return policy_bundle.policy_hash if policy_bundle is not None else None

    @property
    def policy_version(self) -> str | None:
        policy_bundle = self.policy_bundle
        policy_bundle_error = self.policy_bundle_error
        if policy_bundle is not None:
            return policy_bundle.policy_version
        if policy_bundle_error is not None:
            return "unavailable"
        return None

    @property
    def policy_bundle_status(self) -> str:
        policy_bundle = self.policy_bundle
        policy_bundle_error = self.policy_bundle_error
        if policy_bundle is not None and policy_bundle.expired:
            return "expired"
        return policy_bundle_status_for_error(policy_bundle_error)

    def decide(
        self,
        state: Mapping[str, object],
        candidates: Iterable[CandidateAction | ActionType | str | Mapping[str, object]],
        *,
        thread_logger: ThreadLogger | None = None,
        product_surface: str = "velvet_rope",
    ) -> AdmissionDecision:
        normalized = tuple(CandidateAction.coerce(candidate) for candidate in candidates)
        blocked = self._policy_bundle_block_decision(
            normalized,
            state=state,
            product_surface=product_surface,
        )
        if blocked is not None:
            return blocked
        if self.router is None:
            raise PolicyBundleError("Velvet Rope has no router after policy bundle failure")
        decision = self.router.decide(state, normalized, thread_logger=thread_logger)
        return AdmissionDecision(
            decision=decision,
            warrants=_warrants_for_decision(
                decision,
                product_surface=product_surface,
                state=state,
                policy_hash=self.policy_hash,
                policy_version=self.policy_version,
                signer=self.signer,
                signing_key_id=self.signing_key_id,
            ),
            product_surface=product_surface,
        )

    def run(
        self,
        state: Mapping[str, object],
        candidates: Iterable[CandidateAction | ActionType | str | Mapping[str, object]],
        *,
        executor: IntegrationExecutor | None = None,
        thread_logger: ThreadLogger | None = None,
        product_surface: str = "velvet_rope",
    ) -> RopeRun:
        normalized = tuple(CandidateAction.coerce(candidate) for candidate in candidates)
        blocked = self._policy_bundle_block_decision(
            normalized,
            state=state,
            product_surface=product_surface,
        )
        if blocked is not None:
            raise PolicyBundleError(f"policy bundle blocked run: {blocked.decision.reason}")
        if self.router is None:
            raise PolicyBundleError("Velvet Rope has no router after policy bundle failure")
        run = self.router.run(state, normalized, executor=executor, thread_logger=thread_logger)
        admission_decision = AdmissionDecision(
            decision=run.decision,
            warrants=_warrants_for_decision(
                run.decision,
                product_surface=product_surface,
                state=state,
                policy_hash=self.policy_hash,
                policy_version=self.policy_version,
                signer=self.signer,
                signing_key_id=self.signing_key_id,
            ),
            product_surface=product_surface,
        )
        return RopeRun(run=run, admission_decision=admission_decision)

    def _must_fail_closed_without_router(self) -> bool:
        return self.require_policy_bundle and self.policy_bundle_error is not None

    def _policy_bundle_block_decision(
        self,
        candidates: tuple[CandidateAction, ...],
        *,
        state: Mapping[str, object],
        product_surface: str,
    ) -> AdmissionDecision | None:
        if self.policy_bundle_error is not None and self.require_policy_bundle:
            return _manual_policy_bundle_block(
                candidates,
                reason=f"Policy bundle unavailable: {self.policy_bundle_error}",
                status=self.policy_bundle_error.status,
                state=state,
                product_surface=product_surface,
                signer=self.signer,
                signing_key_id=self.signing_key_id,
            )
        if (
            self.policy_bundle is not None
            and self.policy_bundle.expired
            and self.allow_expired_policy_degraded
            and any(_is_consequential_candidate(candidate) for candidate in candidates)
        ):
            return _manual_policy_bundle_block(
                candidates,
                reason="Policy bundle is expired; consequential actions are blocked.",
                status="expired",
                state=state,
                product_surface=product_surface,
                policy_hash=self.policy_hash,
                policy_version=self.policy_version,
                signer=self.signer,
                signing_key_id=self.signing_key_id,
            )
        return None


class ToolRiskClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class VelvetToolPolicy:
    """Policy metadata for one MCP server/tool pair."""

    server: str
    tool: str
    risk_class: ToolRiskClass = ToolRiskClass.MEDIUM
    expected_improvement: float = 0.78
    novelty: float = 0.60
    confidence: float = 0.72
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return mcp_tool_key(self.server, self.tool)


@dataclass(frozen=True)
class VelvetToolCall:
    """A normalized MCP tool-call authorization request."""

    server: str
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    user_request: str = ""
    untrusted_content: str | None = None

    @property
    def key(self) -> str:
        return mcp_tool_key(self.server, self.tool)


class VelvetMCP:
    """List, price, and audit MCP tool calls before execution."""

    def __init__(
        self,
        rope: VelvetRope | None = None,
        *,
        policies: Iterable[VelvetToolPolicy] = (),
        allow_unlisted: bool = False,
        signer: SigningProvider | None = None,
        signing_key_id: str | None = None,
        signing_profile: str | None = None,
        dev_ephemeral_key: bool = False,
    ) -> None:
        self.rope = rope or VelvetRope(
            signer=signer,
            signing_key_id=signing_key_id,
            signing_profile=signing_profile,
            dev_ephemeral_key=dev_ephemeral_key,
        )
        self.signer = signer or getattr(self.rope, "signer", None)
        if self.signer is None:
            self.signer = resolve_ed25519_signing_provider(
                signing_profile=signing_profile,
                dev_ephemeral_key=dev_ephemeral_key,
                key_id=signing_key_id,
            )
        self.signing_key_id = signing_key_id or getattr(
            self.rope,
            "signing_key_id",
            signer_default_key_id(self.signer),
        )
        self.allow_unlisted = allow_unlisted
        self._policies = {policy.key: policy for policy in policies}

    def authorize(
        self,
        call: VelvetToolCall,
        *,
        state: Mapping[str, object] | None = None,
        thread_logger: ThreadLogger | None = None,
    ) -> AdmissionDecision:
        policy = self._policies.get(call.key)
        candidate = self._candidate_for_call(call, policy)
        if policy is None and not self.allow_unlisted:
            block_state = self._state_for_call(call, state)
            return _manual_mcp_block(
                call,
                candidate,
                reason="MCP tool is not listed.",
                rule_id="velvet_mcp.list",
                details={
                    "tool": call.key,
                    "server": call.server,
                    "mcp_tool": call.tool,
                    "risk_class": "unlisted",
                },
                risk_class="unlisted",
                state=block_state,
                policy_hash=_safe_rope_policy_hash(self.rope),
                policy_version=_safe_rope_policy_version(self.rope),
                signer=self.signer,
                signing_key_id=self.signing_key_id,
                thread_logger=thread_logger,
            )

        routed_state = self._state_for_call(call, state)
        schema_block = _schema_status_block(
            call,
            policy,
            candidate,
            state=routed_state,
            policy_hash=_safe_rope_policy_hash(self.rope),
            policy_version=_safe_rope_policy_version(self.rope),
            signer=self.signer,
            signing_key_id=self.signing_key_id,
            thread_logger=thread_logger,
        )
        if schema_block is not None:
            return schema_block
        routed = self.rope.decide(
            routed_state,
            [candidate],
            thread_logger=thread_logger,
            product_surface="velvet_mcp",
        )
        return AdmissionDecision(
            decision=routed.decision,
            warrants=_warrants_for_decision(
                routed.decision,
                product_surface="velvet_mcp",
                state=routed_state,
                policy_hash=self.rope.policy_hash,
                policy_version=self.rope.policy_version,
                signer=self.signer,
                signing_key_id=self.signing_key_id,
            ),
            product_surface="velvet_mcp",
        )

    def _candidate_for_call(
        self,
        call: VelvetToolCall,
        policy: VelvetToolPolicy | None,
    ) -> CandidateAction:
        active_policy = policy or VelvetToolPolicy(server=call.server, tool=call.tool)
        risk_overrides = {
            "tool_risk": _risk_weight(active_policy.risk_class),
            "external_side_effect_risk": _risk_weight(active_policy.risk_class),
        }
        metadata: JsonObject = {
            "mcp_server": call.server,
            "mcp_tool": call.tool,
            "mcp_tool_key": call.key,
            "risk_class": active_policy.risk_class.value,
        }
        metadata.update(dict(active_policy.metadata))
        approval_tier = str(
            metadata.get(
                "approval_tier",
                "auto_approve"
                if active_policy.risk_class == ToolRiskClass.LOW
                else "concierge_review",
            )
        )
        metadata.setdefault("approval_tier", approval_tier)
        if "capability_class" not in metadata:
            if (
                active_policy.risk_class == ToolRiskClass.LOW
                and approval_tier == "auto_approve"
            ):
                metadata["capability_class"] = "read_only"
                metadata.setdefault("data_class", "internal")
            elif metadata.get("usd_estimate") is not None:
                metadata["capability_class"] = "external_write"
            elif approval_tier == "blocked":
                metadata["capability_class"] = "infrastructure_mutation"
            else:
                metadata["capability_class"] = "unknown"
        if "side_effect_class" not in metadata:
            metadata["side_effect_class"] = (
                "externally_visible"
                if metadata["capability_class"] in {"external_write", "infrastructure_mutation"}
                else "none"
            )
        if "usd_estimate" not in metadata:
            if (
                metadata.get("capability_class") == "read_only"
                and approval_tier == "auto_approve"
            ):
                metadata.setdefault("budget_affecting", False)
                metadata["non_budget_affecting"] = True
            else:
                metadata["budget_affecting"] = True
                metadata["cost_unknown"] = True
        elif float(metadata["usd_estimate"]) > 0.0:
            metadata["budget_affecting"] = True
        return CandidateAction(
            ActionType.CALL_TOOL,
            description=f"MCP tool call {call.key}",
            expected_improvement=active_policy.expected_improvement,
            novelty=active_policy.novelty,
            confidence=active_policy.confidence,
            risk_overrides=risk_overrides,
            metadata=metadata,
            source=CandidateSource.HOST,
            parameters={
                "tool_name": call.key,
                "arguments": dict(call.arguments),
                "mcp_server": call.server,
                "mcp_tool": call.tool,
            },
        )

    def _state_for_call(
        self,
        call: VelvetToolCall,
        state: Mapping[str, object] | None,
    ) -> JsonObject:
        merged: JsonObject = dict(state or {})
        merged["tool_call_requested"] = True
        if call.user_request:
            merged.setdefault("user_request", call.user_request)
        if call.untrusted_content is not None:
            merged.setdefault("tool_output", call.untrusted_content)
        merged["mcp"] = {
            "server": call.server,
            "tool": call.tool,
            "tool_key": call.key,
        }
        return merged


def mcp_tool_key(server: str, tool: str) -> str:
    return f"{server}/{tool}"


def manual_mcp_block_seal_id(tool_key: str, *, reason: str, rule_id: str) -> str:
    """Return the deterministic seal ID used for fail-closed MCP manual blocks."""

    return _manual_seal_id(
        "velvet_mcp.block",
        {"tool": tool_key, "reason": reason, "rule_id": rule_id},
    )


def _manual_policy_bundle_block(
    candidates: tuple[CandidateAction, ...],
    *,
    reason: str,
    status: str,
    state: Mapping[str, object],
    product_surface: str,
    policy_hash: str | None = None,
    policy_version: str | None = "unavailable",
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> AdmissionDecision:
    candidate = candidates[0] if candidates else CandidateAction(ActionType.CALL_TOOL)
    blocked = CandidateDecision(
        action_type=candidate.action_type,
        decision=DecisionType.BLOCK,
        reason=reason,
        final_candidate=candidate,
        policy_trace=(),
    )
    routing = RoutingDecision(
        action_type=candidate.action_type,
        decision=DecisionType.BLOCK,
        reason=reason,
        host_action=None,
        candidate_decisions=(blocked,),
        seal_id=_manual_seal_id(
            "velvet_policy_bundle.block",
            {
                "action_type": candidate.action_type.value,
                "reason": reason,
                "status": status,
            },
        ),
    )
    return AdmissionDecision(
        decision=routing,
        warrants=(
            _sign_warrant(
                VelvetWarrant.manual_block(
                    candidate,
                    reason=reason,
                    rule_id=f"velvet_policy_bundle.{status}",
                    details={
                        "policy_bundle_status": status,
                        "policy_hash": policy_hash,
                        "policy_version": policy_version,
                    },
                    risk_class=_metadata_string(candidate.metadata, "risk_class")
                    or "policy_bundle",
                    seal_id=routing.seal_id,
                    thread_id=routing.thread_id,
                    product_surface=product_surface,
                    state=state,
                    policy_hash=policy_hash,
                    policy_version=policy_version,
                    policy_statuses=("velvet_policy_bundle:block",),
                ),
                signer=signer,
                signing_key_id=signing_key_id,
            ),
        ),
        product_surface=product_surface,
    )


def _is_consequential_candidate(candidate: CandidateAction) -> bool:
    return candidate.action_type not in {
        ActionType.ANSWER_DIRECTLY,
        ActionType.SEARCH_WEB,
        ActionType.RETRIEVE_CONTEXT,
        ActionType.READ_FILE,
        ActionType.INSPECT_CODE,
        ActionType.ASK_USER,
    }


def _schema_status_block(
    call: VelvetToolCall,
    policy: VelvetToolPolicy | None,
    candidate: CandidateAction,
    *,
    state: Mapping[str, object],
    policy_hash: str | None,
    policy_version: str | None,
    signer: SigningProvider | None,
    signing_key_id: str | None,
    thread_logger: ThreadLogger | None,
) -> AdmissionDecision | None:
    if policy is None:
        return None
    schema_status = _metadata_string(policy.metadata, "schema_status") or "approved"
    approval_tier = _metadata_string(policy.metadata, "approval_tier") or ""
    if schema_status == "approved" and approval_tier != "blocked":
        return None
    if approval_tier == "blocked" or schema_status == "blocked":
        reason = "MCP tool is blocked by registry policy."
        rule_id = "velvet_mcp.tool_blocked"
    elif schema_status == "drifted":
        reason = "MCP tool schema drifted from the approved hash."
        rule_id = "velvet_mcp.schema_drift"
    elif schema_status == "unreviewed":
        reason = "MCP tool schema has not been approved."
        rule_id = "velvet_mcp.schema_unreviewed"
    else:
        return None
    return _manual_mcp_block(
        call,
        candidate,
        reason=reason,
        rule_id=rule_id,
        details=_schema_block_details(call, policy, schema_status=schema_status),
        risk_class=_metadata_string(policy.metadata, "risk_class") or policy.risk_class.value,
        state=state,
        policy_hash=policy_hash,
        policy_version=policy_version,
        signer=signer,
        signing_key_id=signing_key_id,
        thread_logger=thread_logger,
    )


def _schema_block_details(
    call: VelvetToolCall,
    policy: VelvetToolPolicy,
    *,
    schema_status: str,
) -> JsonObject:
    return {
        "tool": call.key,
        "server": call.server,
        "mcp_tool": call.tool,
        "tool_id": _metadata_string(policy.metadata, "tool_id"),
        "risk_class": policy.risk_class.value,
        "approval_tier": _metadata_string(policy.metadata, "approval_tier"),
        "schema_status": schema_status,
        "schema_hash": _metadata_string(policy.metadata, "schema_hash"),
        "approved_schema_hash": _metadata_string(policy.metadata, "approved_schema_hash"),
        "owner": _metadata_string(policy.metadata, "owner"),
        "environment": _metadata_string(policy.metadata, "environment"),
        "tenant_id": _metadata_string(policy.metadata, "tenant_id"),
        "data_class": _metadata_string(policy.metadata, "data_class"),
    }


def _manual_mcp_block(
    call: VelvetToolCall,
    candidate: CandidateAction,
    *,
    reason: str,
    rule_id: str,
    details: Mapping[str, Any],
    risk_class: str,
    state: Mapping[str, object],
    policy_hash: str | None,
    policy_version: str | None,
    signer: SigningProvider | None,
    signing_key_id: str | None,
    thread_logger: ThreadLogger | None,
) -> AdmissionDecision:
    seal_id = manual_mcp_block_seal_id(call.key, reason=reason, rule_id=rule_id)
    thread_id = _manual_mcp_block_thread_id(call.key, reason=reason, rule_id=rule_id)
    blocked = CandidateDecision(
        action_type=ActionType.CALL_TOOL,
        decision=DecisionType.BLOCK,
        reason=reason,
        final_candidate=candidate,
        policy_trace=(),
    )
    routing = RoutingDecision(
        action_type=ActionType.CALL_TOOL,
        decision=DecisionType.BLOCK,
        reason=reason,
        host_action=None,
        candidate_decisions=(blocked,),
        thread_id=thread_id,
        seal_id=seal_id,
    )
    if thread_logger is not None:
        thread_logger.write(
            _manual_mcp_block_thread_record(
                call,
                candidate,
                reason=reason,
                rule_id=rule_id,
                state=state,
                thread_id=thread_id,
                seal_id=seal_id,
                policy_hash=policy_hash,
                policy_version=policy_version,
            )
        )
    return AdmissionDecision(
        decision=routing,
        warrants=(
            _sign_warrant(
                VelvetWarrant.manual_block(
                    candidate,
                    reason=reason,
                    rule_id=rule_id,
                    details=details,
                    risk_class=risk_class,
                    seal_id=routing.seal_id,
                    thread_id=routing.thread_id,
                    product_surface="velvet_mcp",
                    state=state,
                    policy_hash=policy_hash,
                    policy_version=policy_version,
                ),
                signer=signer,
                signing_key_id=signing_key_id,
            ),
        ),
        product_surface="velvet_mcp",
    )


def _manual_mcp_block_thread_record(
    call: VelvetToolCall,
    candidate: CandidateAction,
    *,
    reason: str,
    rule_id: str,
    state: Mapping[str, object],
    thread_id: str,
    seal_id: str,
    policy_hash: str | None,
    policy_version: str | None,
) -> ThreadRecord:
    timestamp = _canonical_timestamp(
        _context_string(state, "decision_timestamp")
        or _context_string(state, "timestamp")
        or LOCAL_DEMO_ISSUED_AT
    )
    thread_candidate = ThreadCandidateAction(
        raw_action=candidate,
        final_action=candidate,
        certificate=None,
        budget_certificate=None,
        policy_trace=(),
        mutation_ledger=(),
        budget_trace=None,
        short_circuit=rule_id,
        admission_score=None,
        decision=DecisionType.BLOCK,
        reason=reason,
    )
    return ThreadRecord(
        schema_version="9.0",
        thread_id=thread_id,
        timestamp=timestamp,
        router_version="velvet_mcp_manual_block_v1",
        scorer_version="not_routed",
        pricing_policy_name="manual_fail_closed",
        pricing_policy_version="manual_mcp_block_v1",
        policy_chain_name="manual_mcp_block",
        policy_chain_revision=policy_version or "unavailable",
        action_registry_version="velvet_mcp_registry",
        config_version=policy_hash or "unavailable",
        seal_seed=_manual_mcp_block_seed(call.key, reason=reason, rule_id=rule_id),
        seal_id=seal_id,
        seal_status="decision_sealed",
        state=dict(state),
        host_action=None,
        raw_candidates=(candidate,),
        policy_filtered_candidates=(thread_candidate,),
        scored_candidates=(thread_candidate,),
        selected_action=ActionType.CALL_TOOL,
        selected_candidate_index=0,
        rejected_actions=(thread_candidate,),
        budget_state=BudgetState(fallback_triggers=("manual_mcp_block",)),
        fallback_triggers=("manual_mcp_block",),
        metadata={
            "record_kind": "velvet_mcp.manual_block.v1",
            "tool_key": call.key,
            "server": call.server,
            "mcp_tool": call.tool,
            "reason": reason,
            "rule_id": rule_id,
        },
    )


def _manual_mcp_block_thread_id(tool_key: str, *, reason: str, rule_id: str) -> str:
    return f"thread_{_manual_mcp_block_digest(tool_key, reason=reason, rule_id=rule_id)}"


def _manual_mcp_block_seed(tool_key: str, *, reason: str, rule_id: str) -> int:
    return int(_manual_mcp_block_digest(tool_key, reason=reason, rule_id=rule_id), 16)


def _manual_mcp_block_digest(tool_key: str, *, reason: str, rule_id: str) -> str:
    serialized = json.dumps(
        {"tool": tool_key, "reason": reason, "rule_id": rule_id},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.blake2b(serialized.encode("utf-8"), digest_size=8).hexdigest()


def _warrants_for_decision(
    decision: RoutingDecision,
    *,
    product_surface: str = "velvet_rope",
    state: Mapping[str, object] | None = None,
    policy_hash: str | None = None,
    policy_version: str | None = None,
    supplemental_scores: Mapping[int, AdmissionScore] | None = None,
    signer: SigningProvider | None = None,
    signing_key_id: str | None = None,
) -> tuple[VelvetWarrant, ...]:
    selected_candidate = decision.selected_candidate
    return tuple(
        _sign_warrant(
            VelvetWarrant.from_candidate(
                candidate,
                selected=selected_candidate is candidate,
                supplemental_score=(supplemental_scores or {}).get(index),
                seal_id=decision.seal_id,
                thread_id=decision.thread_id,
                product_surface=product_surface,
                state=state,
                policy_hash=policy_hash,
                policy_version=policy_version,
            ),
            signer=signer,
            signing_key_id=signing_key_id,
        )
        for index, candidate in enumerate(decision.candidate_decisions)
    )


def _sign_warrant(
    warrant: VelvetWarrant,
    *,
    signer: SigningProvider | None,
    signing_key_id: str | None,
) -> VelvetWarrant:
    try:
        return warrant.sign(signer=signer, signing_key_id=signing_key_id)
    except TypeError as error:
        if "unexpected keyword argument" in str(error):
            return warrant.sign()
        raise


def _optional_mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _context_string(state: Mapping[str, object] | None, key: str) -> str | None:
    if state is None:
        return None
    value = state.get(key)
    return value if isinstance(value, str) and value else None


def _mapping_string(mapping: Mapping[str, Any] | None, key: str) -> str | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _policy_context(state: Mapping[str, object] | None) -> Mapping[str, Any] | None:
    if state is None:
        return None
    return _optional_mapping(state.get("policy_context"))


def _gateway_context(state: Mapping[str, object] | None) -> Mapping[str, Any] | None:
    if state is None:
        return None
    return _optional_mapping(state.get("gateway"))


def _arguments_mapping(parameters: Mapping[str, Any]) -> Mapping[str, Any] | None:
    return _optional_mapping(parameters.get("arguments"))


def _tenant_id(state: Mapping[str, object] | None) -> str | None:
    return (
        _context_string(state, "tenant_id")
        or _context_string(state, "organization_id")
        or _mapping_string(_policy_context(state), "organization_id")
    )


def _actor_user_id(state: Mapping[str, object] | None) -> str | None:
    return (
        _context_string(state, "actor_user_id")
        or _context_string(state, "user_id")
        or _mapping_string(_policy_context(state), "user_id")
    )


def _agent_id(
    state: Mapping[str, object] | None,
    metadata: Mapping[str, Any],
) -> str | None:
    return (
        _metadata_string(metadata, "agent_id")
        or _context_string(state, "agent_id")
        or _mapping_string(_gateway_context(state), "agent_id")
    )


def _request_id(
    state: Mapping[str, object] | None,
    metadata: Mapping[str, Any],
) -> str | None:
    return (
        _metadata_string(metadata, "gateway_request_id")
        or _metadata_string(metadata, "request_id")
        or _context_string(state, "request_id")
        or _mapping_string(_gateway_context(state), "request_id")
    )


def _environment(
    state: Mapping[str, object] | None,
    metadata: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> str:
    return (
        _metadata_string(metadata, "environment")
        or _context_string(state, "environment")
        or _context_string(state, "runtime_environment")
        or _mapping_string(_policy_context(state), "environment")
        or _mapping_string(_arguments_mapping(parameters), "environment")
        or "local_demo"
    )


def _data_class(
    state: Mapping[str, object] | None,
    metadata: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> str | None:
    return (
        _metadata_string(metadata, "data_class")
        or _context_string(state, "data_class")
        or _mapping_string(_policy_context(state), "data_class")
        or _mapping_string(_arguments_mapping(parameters), "data_class")
    )


def _safe_rope_policy_hash(rope: VelvetRope) -> str | None:
    try:
        return rope.policy_hash
    except AttributeError:
        return None


def _safe_rope_policy_version(rope: VelvetRope) -> str | None:
    try:
        return rope.policy_version
    except AttributeError:
        return None


def _policy_hash(policy_trace: Iterable[PolicyTraceEntry]) -> str | None:
    material = [
        {
            "policy_name": entry.policy_name,
            "policy_kind": entry.policy_kind,
            "policy_version": entry.policy_version,
            "config_version": entry.config_version,
            "config_hash": entry.config_hash,
            "status": entry.status,
        }
        for entry in policy_trace
    ]
    return canonical_hash_sha256(material) if material else None


def _policy_version(policy_trace: Iterable[PolicyTraceEntry]) -> str | None:
    versions = sorted(
        {
            f"{entry.policy_name}@{entry.policy_version}/{entry.config_version}"
            for entry in policy_trace
        }
    )
    return ",".join(versions) if versions else None


def _arguments_hash(parameters: Mapping[str, Any]) -> str | None:
    if "arguments" in parameters:
        return canonical_hash_sha256({"arguments": parameters["arguments"]})
    if parameters:
        return canonical_hash_sha256({"parameters": dict(parameters)})
    return None


def _candidate_certificate(candidate: CandidateAction) -> Mapping[str, Any] | None:
    metadata_certificate = _optional_mapping(candidate.metadata.get("certificate"))
    if metadata_certificate is not None:
        return metadata_certificate
    if candidate.certificate is None:
        return None
    return candidate.certificate.to_dict()


def _metadata_string(metadata: Mapping[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) else None


def _payload_string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) and value else None


def _metadata_hash(metadata: Mapping[str, Any], key: str) -> str | None:
    value = _metadata_string(metadata, key)
    if value is None:
        return None
    normalized = value.removeprefix("sha256:")
    if len(normalized) == 64 and all(character in "0123456789abcdef" for character in normalized):
        return f"sha256:{normalized}"
    return canonical_hash_sha256({key: value})


def _canonical_decision(decision: str) -> str:
    if decision == "execute":
        return "execute"
    if decision in {"escalate", "ask_approval", "delay"}:
        return "escalate"
    return "block"


def _warrant_obligations(decision: DecisionType, approval_required: bool) -> list[str]:
    canonical = _canonical_decision(decision.value)
    if canonical == "execute":
        return ["forward_upstream"]
    if canonical == "escalate" or approval_required:
        return ["await_approval_before_execution"]
    return ["do_not_forward_upstream"]


def _reason_code(reason: str) -> str:
    normalized = reason.strip().lower().replace(" ", "_")
    return normalized[:96] or "velvet.decision"


def _proof_hash_or_fallback(value: str | None, fallback: Mapping[str, Any]) -> str:
    if isinstance(value, str) and value:
        normalized = value.removeprefix("sha256:")
        if len(normalized) == 64 and all(
            character in "0123456789abcdef" for character in normalized
        ):
            return f"sha256:{normalized}"
        if value.startswith("sha256:"):
            return value
    return canonical_hash_sha256(fallback)


def _canonical_timestamp(value: str) -> str:
    if value.endswith("+00:00"):
        return f"{value[:-6]}Z"
    return value


def _unsigned_payload_from_dict(payload: Mapping[str, Any]) -> JsonObject:
    return {str(key): value for key, value in payload.items() if key != "signature"}


def _signature_payload_from_dict(payload: Mapping[str, Any]) -> JsonObject:
    if all(field in payload for field in _WARRANT_SIGNATURE_FIELDS):
        return {field: payload[field] for field in _WARRANT_SIGNATURE_FIELDS}
    return {str(key): value for key, value in payload.items() if key != "signature"}


def _sign_payload(payload: Mapping[str, Any], signing_key: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"),
        canonical_json_v1_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


_WARRANT_SIGNATURE_FIELDS = (
    "warrant_id",
    "issued_at",
    "tenant_id",
    "environment",
    "request_hash",
    "policy_hash",
    "tool_schema_hash",
    "tool_name",
    "decision",
    "reason_codes",
    "obligations",
    "approval_required",
    "expires_at",
    "issuer",
    "product_surface",
    "actor_user_id",
    "agent_id",
    "session_id",
    "request_id",
    "action_type",
    "reason",
    "seal_id",
    "bound_seal_id",
    "thread_id",
    "tool_key",
    "mcp_server",
    "mcp_tool",
    "risk_class",
    "data_class",
    "policy_version",
    "arguments_hash",
    "jurisdiction_evidence",
    "policy_statuses",
    "policy_reasons",
    "approval_request_id",
    "ledger_record_hash",
    "signing_key_id",
    "signing_provider",
    "signing_algorithm",
    "signing_key_version",
    "warrant_hash",
)


def _canonical_json_v1_safe(value: Any) -> Any:
    if isinstance(value, float):
        return quantize_decimal(str(value))
    if isinstance(value, Mapping):
        return {str(key): _canonical_json_v1_safe(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical_json_v1_safe(item) for item in value]
    return value


def _pricing_status(candidate: CandidateDecision, supplemental_score: AdmissionScore | None) -> str:
    if candidate.admission_score is not None:
        return "priced"
    if candidate.admission_trace is not None:
        return "admission_optimizer"
    if supplemental_score is not None:
        return "policy_short_circuit_priced"
    return "not_priced"


def _risk_weight(risk_class: ToolRiskClass) -> float:
    if risk_class == ToolRiskClass.LOW:
        return 0.15
    if risk_class == ToolRiskClass.HIGH:
        return 0.85
    return 0.45


def _manual_seal_id(prefix: str, payload: Mapping[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.blake2b(serialized.encode("utf-8"), digest_size=8).hexdigest()
    return f"seal_{prefix}_{digest}"
