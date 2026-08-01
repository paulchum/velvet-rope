"""Deterministic Velvet fallback compiler."""

from __future__ import annotations

from dataclasses import dataclass

from velvet.actions import AuthorityClass, CanonicalAction
from velvet.serialization import JsonObject, canonical_hash, stable_json_object


@dataclass(frozen=True)
class VelvetFallback:
    fallback_type: str
    authority_class: AuthorityClass
    canonical_action_hash: str
    payload: JsonObject
    fallback_hash: str

    def to_dict(self) -> JsonObject:
        return {
            "fallback_type": self.fallback_type,
            "authority_class": self.authority_class.value,
            "canonical_action_hash": self.canonical_action_hash,
            "payload": stable_json_object(self.payload),
            "fallback_hash": self.fallback_hash,
        }


class VelvetFallbackCompiler:
    def compile(self, action: CanonicalAction | VelvetFallback) -> VelvetFallback:
        if isinstance(action, VelvetFallback):
            return action

        fallback_type = _fallback_type_for_class(action.authority_class)
        payload = {
            "fallback_type": fallback_type,
            "original_action_id": action.action_id,
            "boundary_key": action.boundary_key,
            "target_resource": action.target_resource,
            "canonical_type": action.canonical_type,
            "normalized_payload": action.normalized_payload,
        }
        hash_payload = {
            "fallback_type": fallback_type,
            "authority_class": action.authority_class.value,
            "canonical_action_hash": action.canonical_action_hash,
            "payload": payload,
        }
        return VelvetFallback(
            fallback_type=fallback_type,
            authority_class=action.authority_class,
            canonical_action_hash=action.canonical_action_hash,
            payload=stable_json_object(payload),
            fallback_hash=canonical_hash(hash_payload),
        )


def compile_velvet_fallback(action: CanonicalAction | VelvetFallback) -> VelvetFallback:
    return VelvetFallbackCompiler().compile(action)


def _fallback_type_for_class(authority_class: AuthorityClass) -> str:
    if authority_class in {
        AuthorityClass.OBSERVE,
        AuthorityClass.APPEND,
        AuthorityClass.SPEND_LOW,
    }:
        return "original_action"
    if authority_class is AuthorityClass.ALTER:
        return "dry_run_diff"
    if authority_class is AuthorityClass.DESTROY:
        return "log_proposed_destroy"
    if authority_class is AuthorityClass.SPEND_HIGH:
        return "draft_for_human_signature"
    if authority_class is AuthorityClass.BIND_EXTERNAL:
        return "escalate_for_signature"
    raise ValueError(f"unknown authority class: {authority_class}")
