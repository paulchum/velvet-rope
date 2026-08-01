"""Model client boundary for compile-time policy compilation."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from velvet.serialization import canonical_dumps

JsonObject = dict[str, Any]

DEFAULT_POLICY_COMPILE_MODEL_ID = "velvet-offline-heuristic-compiler-v1"
DEFAULT_POLICY_COMPILE_MODEL_SPEC = "offline-heuristic"

STAGE1_SYSTEM = (
    "You decompose Markdown policy text into Velvet policy rulecards. "
    "Respond ONLY with one JSON object matching the requested schema. "
    "Do not include prose or markdown fences."
)
STAGE1_PROMPT_TMPL = """Input policy source text:
{policy_source_json}

Return this JSON schema:
{{"rulecards":[{{"issue":"string","position":"prohibit|require|recommend","severity":"error|warning|defer","target":"string","controlled_nl_antecedent":"string","source_unit":"string"}}]}}

Every source_unit must be copied exactly from one policy unit in the source text."""

STAGE2_SYSTEM = (
    "You tighten one Velvet policy rulecard around underlying effect rather than "
    "surface wording. Respond ONLY with one JSON object matching the requested "
    "schema. Do not include prose or markdown fences."
)
STAGE2_PROMPT_TMPL = """Input rulecard JSON:
{rulecard_json}

Return this JSON schema:
{{"tightened_antecedent":"string","underlying_effect":"string","waiver_disjunct":{{"pattern":"explicit_waiver","required_fields":["metadata.policy_waiver.rule_id","metadata.policy_waiver.authority","metadata.policy_waiver.expires_at"],"rule_id":"string"}}}}"""

STAGE4_SYSTEM = (
    "You triage one failed synthetic policy-compiler validation fixture. Decide "
    "which single component is faulty and return a patch for only that component. "
    "Respond ONLY with one JSON object matching the requested schema. Do not "
    "include prose or markdown fences."
)
STAGE4_PROMPT_TMPL = """Input repair context JSON:
{repair_context_json}

Return this JSON schema:
{{"fault_component":"rule_formula|extraction_question|fixture","patch":{{}},"reasoning":"string"}}

Patch shapes:
- rule_formula: fields to merge into the rulecard before re-lowering, optionally
  including source_unit, tightened_antecedent, severity, or lowering.
- extraction_question: {{"extraction_question":"string"}}
- fixture: {{"fixture": <full replacement fixture JSON>}}"""

JSON_REASK_INSTRUCTION = (
    "Your previous response was not valid JSON for the schema. Respond with only "
    "the JSON object."
)


class PolicyCompileModel(Protocol):
    """Compile-time-only model client used by the policy compiler."""

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> ModelResponse:
        """Return one model completion for a policy-compile prompt."""


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model_id: str
    request_hash: str
    response_hash: str


class OfflineHeuristicModel:
    """Deterministic model facade over the existing heuristic compiler stages."""

    model_id = DEFAULT_POLICY_COMPILE_MODEL_ID

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> ModelResponse:
        request = _request_payload(system=system, prompt=prompt, max_tokens=max_tokens)
        if system == STAGE1_SYSTEM:
            payload = self._stage1(prompt)
        elif system == STAGE2_SYSTEM:
            payload = self._stage2(prompt)
        elif system == STAGE4_SYSTEM:
            payload = self._stage4(prompt)
        else:
            payload = {}
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return _model_response(text=text, model_id=self.model_id, request=request)

    @staticmethod
    def _stage1(prompt: str) -> JsonObject:
        from velvet import policy_compile as compiler

        source_text = _json_after_label(prompt, "Input policy source text:")
        rulecards = compiler._heuristic_decompose_rulecards(cast(str, source_text))
        return {
            "rulecards": [
                {
                    "issue": rulecard["issue"],
                    "position": rulecard["position"],
                    "severity": rulecard["severity"],
                    "target": rulecard["target"],
                    "controlled_nl_antecedent": rulecard["controlled_nl_antecedent"],
                    "source_unit": rulecard["source_unit"],
                }
                for rulecard in rulecards
            ]
        }

    @staticmethod
    def _stage2(prompt: str) -> JsonObject:
        from velvet import policy_compile as compiler

        rulecard = _json_after_label(prompt, "Input rulecard JSON:")
        tightened = compiler._heuristic_tighten_rulecard(cast(Mapping[str, Any], rulecard))
        return {
            "tightened_antecedent": tightened["tightened_antecedent"],
            "underlying_effect": tightened.get(
                "underlying_effect",
                compiler._underlying_effect(str(tightened["source_unit"])),
            ),
            "waiver_disjunct": tightened["waiver_disjunct"],
        }

    @staticmethod
    def _stage4(prompt: str) -> JsonObject:
        from velvet import policy_compile as compiler

        context = cast(Mapping[str, Any], _json_after_label(prompt, "Input repair context JSON:"))
        fixture = cast(Mapping[str, Any], context["fixture"])
        rulecard = cast(Mapping[str, Any], context["rulecard"])
        repaired = compiler._heuristic_repair_fixture(fixture, rulecard)
        return {
            "fault_component": "fixture",
            "patch": {"fixture": repaired},
            "reasoning": "deterministic cost_ceiling fixture patch",
        }


class AnthropicModel:
    """Anthropic Messages API policy compile model client."""

    def __init__(
        self,
        model_id: str,
        *,
        transport: object | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise _policy_compile_error("ANTHROPIC_API_KEY is required for anthropic models")
        self.model_id = model_id
        self._api_key = api_key
        self._transport = transport
        self._sleep = sleep

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> ModelResponse:
        body = {
            "model": self.model_id,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "x-api-key": self._api_key,
        }
        payload = self._post_json(
            "https://api.anthropic.com/v1/messages",
            body=body,
            headers=headers,
        )
        text = _anthropic_text(payload)
        return _model_response(
            text=text,
            model_id=str(payload.get("model") or self.model_id),
            request=_request_payload(system=system, prompt=prompt, max_tokens=max_tokens),
        )

    def _post_json(
        self,
        url: str,
        *,
        body: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> JsonObject:
        import httpx

        kwargs: JsonObject = {"timeout": 120.0}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        with httpx.Client(**kwargs) as client:
            response = client.post(url, json=body, headers=dict(headers))
            if response.status_code == 429 or 500 <= response.status_code < 600:
                self._sleep(2.0)
                response = client.post(url, json=body, headers=dict(headers))
            if response.status_code >= 400:
                raise _policy_compile_error(
                    f"Anthropic policy compile request failed with HTTP {response.status_code}"
                )
            payload = response.json()
        if not isinstance(payload, dict):
            raise _policy_compile_error("Anthropic policy compile response was not a JSON object")
        return cast(JsonObject, payload)


class OpenAICompatibleModel:
    """OpenAI-compatible chat-completions client for local/open-weight endpoints."""

    def __init__(
        self,
        model_id: str,
        base_url: str,
        *,
        transport: object | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise _policy_compile_error("OPENAI_API_KEY is required for openai-compatible models")
        self.model_id = model_id
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._transport = transport
        self._sleep = sleep

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> ModelResponse:
        body = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        headers = {
            "authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
        }
        payload = self._post_json(
            f"{self.base_url}/chat/completions",
            body=body,
            headers=headers,
        )
        text = _openai_text(payload)
        return _model_response(
            text=text,
            model_id=str(payload.get("model") or self.model_id),
            request=_request_payload(system=system, prompt=prompt, max_tokens=max_tokens),
        )

    def _post_json(
        self,
        url: str,
        *,
        body: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> JsonObject:
        import httpx

        kwargs: JsonObject = {"timeout": 120.0}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        with httpx.Client(**kwargs) as client:
            response = client.post(url, json=body, headers=dict(headers))
            if response.status_code == 429 or 500 <= response.status_code < 600:
                self._sleep(2.0)
                response = client.post(url, json=body, headers=dict(headers))
            if response.status_code >= 400:
                raise _policy_compile_error(
                    "OpenAI-compatible policy compile request failed with "
                    f"HTTP {response.status_code}"
                )
            payload = response.json()
        if not isinstance(payload, dict):
            raise _policy_compile_error(
                "OpenAI-compatible policy compile response was not a JSON object"
            )
        return cast(JsonObject, payload)


def create_policy_compile_model(model_spec: str) -> PolicyCompileModel:
    if model_spec in {DEFAULT_POLICY_COMPILE_MODEL_SPEC, DEFAULT_POLICY_COMPILE_MODEL_ID}:
        return OfflineHeuristicModel()
    if model_spec.startswith("anthropic:"):
        model_id = model_spec.removeprefix("anthropic:").strip()
        if not model_id:
            raise _policy_compile_error("anthropic model spec must include a model id")
        return AnthropicModel(model_id)
    if model_spec.startswith("openai:"):
        remainder = model_spec.removeprefix("openai:")
        model_id, separator, base_url = remainder.partition("@")
        if not model_id.strip() or separator != "@" or not base_url.strip():
            raise _policy_compile_error(
                "openai model spec must be formatted as openai:<id>@<base_url>"
            )
        return OpenAICompatibleModel(model_id.strip(), base_url.strip())
    raise _policy_compile_error(
        "model must be offline-heuristic, anthropic:<id>, or openai:<id>@<base_url>"
    )


def prompt_hashes() -> JsonObject:
    prompts = {
        "decompose": STAGE1_SYSTEM + "\n" + STAGE1_PROMPT_TMPL,
        "tighten": STAGE2_SYSTEM + "\n" + STAGE2_PROMPT_TMPL,
        "repair": STAGE4_SYSTEM + "\n" + STAGE4_PROMPT_TMPL,
    }
    return {name: _sha256_text(prompt) for name, prompt in sorted(prompts.items())}


def parse_json_object(text: str) -> JsonObject:
    stripped = _strip_markdown_fence(text)
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise ValueError(f"response was not valid JSON: {error.msg}") from error
    if not isinstance(payload, dict):
        raise ValueError("response JSON must be an object")
    return cast(JsonObject, payload)


def validate_stage1_rulecard(payload: Mapping[str, Any]) -> JsonObject:
    return {
        "issue": _required_string(payload, "issue"),
        "position": _enum_string(payload, "position", {"prohibit", "require", "recommend"}),
        "severity": _enum_string(payload, "severity", {"error", "warning", "defer"}),
        "target": _required_string(payload, "target"),
        "controlled_nl_antecedent": _required_string(payload, "controlled_nl_antecedent"),
        "source_unit": _required_string(payload, "source_unit"),
    }


def validate_stage1_payload(payload: Mapping[str, Any]) -> list[JsonObject]:
    raw_rulecards = payload.get("rulecards")
    if not isinstance(raw_rulecards, list):
        raise ValueError("rulecards must be a list")
    validated: list[JsonObject] = []
    for item in raw_rulecards:
        if not isinstance(item, Mapping):
            raise ValueError("each rulecard must be an object")
        validated.append(validate_stage1_rulecard(item))
    return validated


def validate_stage2_payload(payload: Mapping[str, Any]) -> JsonObject:
    waiver = payload.get("waiver_disjunct")
    if not isinstance(waiver, Mapping):
        raise ValueError("waiver_disjunct must be an object")
    required_fields = waiver.get("required_fields")
    if not isinstance(required_fields, list) or not all(
        isinstance(item, str) and item for item in required_fields
    ):
        raise ValueError("waiver_disjunct.required_fields must be a non-empty string list")
    return {
        "tightened_antecedent": _required_string(payload, "tightened_antecedent"),
        "underlying_effect": _required_string(payload, "underlying_effect"),
        "waiver_disjunct": {
            "pattern": _required_string(waiver, "pattern"),
            "required_fields": list(required_fields),
            "rule_id": _required_string(waiver, "rule_id"),
        },
    }


def validate_stage4_payload(payload: Mapping[str, Any]) -> JsonObject:
    patch = payload.get("patch")
    if not isinstance(patch, Mapping):
        raise ValueError("patch must be an object")
    return {
        "fault_component": _enum_string(
            payload,
            "fault_component",
            {"rule_formula", "extraction_question", "fixture"},
        ),
        "patch": dict(cast(Mapping[str, Any], patch)),
        "reasoning": _required_string(payload, "reasoning"),
    }


def _request_payload(*, system: str, prompt: str, max_tokens: int) -> JsonObject:
    return {"system": system, "prompt": prompt, "max_tokens": max_tokens}


def _model_response(
    *,
    text: str,
    model_id: str,
    request: Mapping[str, Any],
) -> ModelResponse:
    return ModelResponse(
        text=text,
        model_id=model_id,
        request_hash=_canonical_json_hash(request),
        response_hash=_canonical_json_hash({"model_id": model_id, "text": text}),
    )


def _canonical_json_hash(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_dumps(payload).encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strip_markdown_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _json_after_label(prompt: str, label: str) -> Any:
    _, separator, remainder = prompt.partition(label)
    if not separator:
        raise _policy_compile_error(f"offline heuristic prompt missing label: {label}")
    stripped = remainder.strip()
    decoder = json.JSONDecoder()
    try:
        value, _ = decoder.raw_decode(stripped)
    except json.JSONDecodeError as error:
        raise _policy_compile_error(
            f"offline heuristic prompt input was invalid JSON: {label}"
        ) from error
    return value


def _required_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _enum_string(payload: Mapping[str, Any], key: str, allowed: set[str]) -> str:
    value = _required_string(payload, key)
    if value not in allowed:
        raise ValueError(f"{key} must be one of {sorted(allowed)}")
    return value


def _anthropic_text(payload: Mapping[str, Any]) -> str:
    content = payload.get("content")
    if not isinstance(content, list):
        raise _policy_compile_error("Anthropic response content must be a list")
    parts = [
        item.get("text")
        for item in content
        if isinstance(item, Mapping) and item.get("type") == "text"
    ]
    text = "".join(part for part in parts if isinstance(part, str)).strip()
    if not text:
        raise _policy_compile_error("Anthropic response did not contain text content")
    return text


def _openai_text(payload: Mapping[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise _policy_compile_error("OpenAI-compatible response choices must be a non-empty list")
    first = choices[0]
    if not isinstance(first, Mapping):
        raise _policy_compile_error("OpenAI-compatible response choice must be an object")
    message = first.get("message")
    if not isinstance(message, Mapping):
        raise _policy_compile_error("OpenAI-compatible response message must be an object")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise _policy_compile_error("OpenAI-compatible response did not contain text content")
    return content


def _policy_compile_error(message: str) -> Exception:
    from velvet.policy_compile import PolicyCompileError

    return PolicyCompileError(message)
