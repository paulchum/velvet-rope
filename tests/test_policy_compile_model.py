from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from velvet.policy_compile import (
    PolicyCompileError,
    compile_policy_document,
    verify_policy_compile_provenance,
)
from velvet.policy_compile_model import (
    STAGE1_SYSTEM,
    STAGE2_SYSTEM,
    STAGE4_SYSTEM,
    AnthropicModel,
    ModelResponse,
    OpenAICompatibleModel,
)
from velvet.serialization import canonical_dumps
from velvet.signing import load_demo_ed25519_signer

JsonObject = dict[str, Any]


class FakeModel:
    model_id = "fake-policy-compiler-v1"

    def __init__(
        self,
        handler: Callable[[str, str, int, int], str],
    ) -> None:
        self.handler = handler
        self.calls: list[JsonObject] = []

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> ModelResponse:
        self.calls.append({"system": system, "prompt": prompt, "max_tokens": max_tokens})
        text = self.handler(system, prompt, max_tokens, len(self.calls))
        return _model_response(
            text=text,
            model_id=self.model_id,
            system=system,
            prompt=prompt,
            max_tokens=max_tokens,
        )


def test_fake_model_pipeline_records_hashes_and_model_rulecards(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must not spend more than $5 per task.",
    )

    def handler(system: str, _prompt: str, _max_tokens: int, _call: int) -> str:
        if system == STAGE1_SYSTEM:
            return _json(
                {
                    "rulecards": [
                        {
                            "issue": "Model cost rule",
                            "position": "prohibit",
                            "severity": "error",
                            "target": "request",
                            "controlled_nl_antecedent": "model antecedent",
                            "source_unit": "Agents must not spend more than $5 per task.",
                        }
                    ]
                }
            )
        if system == STAGE2_SYSTEM:
            return _json(
                {
                    "tightened_antecedent": "candidate action spends more than $5",
                    "underlying_effect": "spend more than $5",
                    "waiver_disjunct": _waiver(
                        "rule_001_agents_must_not_spend_more_than_5_per_task"
                    ),
                }
            )
        return _json({"fault_component": "fixture", "patch": {}, "reasoning": "unused"})

    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        model=FakeModel(handler),
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )

    rulecards = json.loads(result.rulecards_path.read_text(encoding="utf-8"))["rulecards"]
    assert rulecards[0]["issue"] == "Model cost rule"
    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    assert provenance["stage_model_ids"]["decompose"] == "fake-policy-compiler-v1"
    assert {call["stage"] for call in provenance["model_call_hashes"]} == {
        "decompose",
        "tighten",
    }
    assert all(
        call["request_hash"].startswith("sha256:")
        for call in provenance["model_call_hashes"]
    )
    assert provenance["fallback_events"] == []


def test_model_garbage_then_valid_json_uses_reask(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must not spend more than $5 per task.",
    )
    stage1_calls = 0

    def handler(system: str, prompt: str, _max_tokens: int, _call: int) -> str:
        nonlocal stage1_calls
        if system == STAGE1_SYSTEM:
            stage1_calls += 1
            if stage1_calls == 1:
                return "not json"
            assert "previous response was not valid JSON" in prompt
            return _json(
                {
                    "rulecards": [
                        {
                            "issue": "Reasked cost rule",
                            "position": "prohibit",
                            "severity": "error",
                            "target": "request",
                            "controlled_nl_antecedent": "model antecedent",
                            "source_unit": "Agents must not spend more than $5 per task.",
                        }
                    ]
                }
            )
        if system == STAGE2_SYSTEM:
            return _json(
                {
                    "tightened_antecedent": "candidate action spends more than $5",
                    "underlying_effect": "spend more than $5",
                    "waiver_disjunct": _waiver(
                        "rule_001_agents_must_not_spend_more_than_5_per_task"
                    ),
                }
            )
        return _json({"fault_component": "fixture", "patch": {}, "reasoning": "unused"})

    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        model=FakeModel(handler),
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )
    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    assert provenance["fallback_events"] == []
    assert [call["stage"] for call in provenance["model_call_hashes"]].count("decompose") == 2


def test_persistent_garbage_falls_back_per_item(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must not spend more than $5 per task.",
    )
    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        model=FakeModel(lambda _system, _prompt, _tokens, _call: "not json"),
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )
    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    assert provenance["fallback_events"]
    assert provenance["fallback_events"][0]["stage"] == "decompose"
    rulecards = json.loads(result.rulecards_path.read_text(encoding="utf-8"))["rulecards"]
    assert rulecards[0]["issue"] == "Agents must not spend more than $5 per task."


def test_rule_formula_repair_changes_policy_not_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from velvet import policy_compile

    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must not spend more than $5 per task.",
    )
    original_fixture_for_rulecard = policy_compile._fixture_for_rulecard

    def underpowered_fixture(rulecard: Mapping[str, Any]) -> JsonObject:
        fixture = json.loads(json.dumps(original_fixture_for_rulecard(rulecard)))
        if fixture["check_type"] == "cost_ceiling":
            fixture["candidates"][0]["cost_overrides"] = {"money": 1.0}
        return cast(JsonObject, fixture)

    monkeypatch.setattr(policy_compile, "_fixture_for_rulecard", underpowered_fixture)

    def handler(system: str, _prompt: str, _max_tokens: int, _call: int) -> str:
        if system == STAGE1_SYSTEM:
            return _json(
                {
                    "rulecards": [
                        {
                            "issue": "Cost rule",
                            "position": "prohibit",
                            "severity": "error",
                            "target": "request",
                            "controlled_nl_antecedent": "model antecedent",
                            "source_unit": "Agents must not spend more than $5 per task.",
                        }
                    ]
                }
            )
        if system == STAGE2_SYSTEM:
            return _json(
                {
                    "tightened_antecedent": "candidate action spends more than $5",
                    "underlying_effect": "spend more than $5",
                    "waiver_disjunct": _waiver(
                        "rule_001_agents_must_not_spend_more_than_5_per_task"
                    ),
                }
            )
        if system == STAGE4_SYSTEM:
            return _json(
                {
                    "fault_component": "rule_formula",
                    "patch": {
                        "source_unit": "Agents must not spend more than $0.50 per task."
                    },
                    "reasoning": "policy threshold was too high for the synthetic miss",
                }
            )
        raise AssertionError(system)

    output_dir = tmp_path / "bundle"
    result = compile_policy_document(
        policy_doc,
        output_dir=output_dir,
        model=FakeModel(handler),
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )

    validation = json.loads(result.validation_report_path.read_text(encoding="utf-8"))
    assert validation["summary"]["repairs_applied"] == 1
    assert validation["summary"]["failed"] == 0
    fixtures = json.loads((output_dir / "validation_fixtures.json").read_text(encoding="utf-8"))
    assert fixtures["fixtures"][0]["candidates"][0]["cost_overrides"] == {"money": 1.0}
    compiled_policy = (result.policies_dir / "compiled_policy.yaml").read_text(encoding="utf-8")
    assert '"per_task_usd_limit": 0.5' in compiled_policy
    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    assert provenance["repair_events"][0]["fault_component"] == "rule_formula"


def test_ed25519_provenance_round_trip_and_tamper(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must not spend more than $5 per task.",
    )
    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )
    assert verify_policy_compile_provenance(result.provenance_path)["verified"] is True

    tampered = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    tampered["source_policy_name"] = "tampered.md"
    tampered_path = tmp_path / "tampered_provenance.json"
    tampered_path.write_text(json.dumps(tampered, sort_keys=True), encoding="utf-8")
    assert verify_policy_compile_provenance(tampered_path)["verified"] is False


def test_compile_time_model_does_not_emit_runtime_network_config(tmp_path: Path) -> None:
    policy_doc = _write_policy_doc(
        tmp_path,
        "- Agents must preserve approved data residency regions.",
    )

    def handler(system: str, _prompt: str, _max_tokens: int, _call: int) -> str:
        if system == STAGE1_SYSTEM:
            return _json(
                {
                    "rulecards": [
                        {
                            "issue": "Data residency",
                            "position": "require",
                            "severity": "defer",
                            "target": "data",
                            "controlled_nl_antecedent": "model antecedent",
                            "source_unit": "Agents must preserve approved data residency regions.",
                        }
                    ]
                }
            )
        if system == STAGE2_SYSTEM:
            return _json(
                {
                    "tightened_antecedent": "candidate action changes residency region",
                    "underlying_effect": "change residency region",
                    "waiver_disjunct": _waiver(
                        "rule_001_agents_must_preserve_approved_data_residency_regions"
                    ),
                }
            )
        return _json({"fault_component": "fixture", "patch": {}, "reasoning": "unused"})

    result = compile_policy_document(
        policy_doc,
        output_dir=tmp_path / "bundle",
        model=FakeModel(handler),
        model_id="anthropic:claude-test",
        signer=load_demo_ed25519_signer(),
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )
    compiled_policy = (result.policies_dir / "compiled_policy.yaml").read_text(encoding="utf-8")
    assert "https://api.anthropic.com" not in compiled_policy
    assert '"runtime_enabled": false' in compiled_policy
    assert result.manifest["determinism_boundary"]["compile_time_model_only"] is True


def test_anthropic_constructor_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(PolicyCompileError):
        AnthropicModel("claude-test")


def test_openai_constructor_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(PolicyCompileError):
        OpenAICompatibleModel("local-model", "http://127.0.0.1:8000/v1")


def test_anthropic_request_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    captured: JsonObject = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "model": "claude-test",
                "content": [{"type": "text", "text": "{\"ok\":true}"}],
            },
        )

    model = AnthropicModel(
        "claude-test",
        transport=httpx.MockTransport(handler),
        sleep=lambda _seconds: None,
    )
    response = model.complete(system="sys", prompt="prompt", max_tokens=42)
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "test-key"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["body"]["temperature"] == 0
    assert captured["body"]["messages"] == [{"role": "user", "content": "prompt"}]
    assert response.text == "{\"ok\":true}"


def test_openai_compatible_request_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    captured: JsonObject = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "model": "local-model",
                "choices": [{"message": {"content": "{\"ok\":true}"}}],
            },
        )

    model = OpenAICompatibleModel(
        "local-model",
        "http://127.0.0.1:8000/v1/",
        transport=httpx.MockTransport(handler),
        sleep=lambda _seconds: None,
    )
    response = model.complete(system="sys", prompt="prompt", max_tokens=42)
    assert captured["url"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert captured["headers"]["authorization"] == "Bearer test-key"
    assert captured["body"]["temperature"] == 0
    assert captured["body"]["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "prompt"},
    ]
    assert response.text == "{\"ok\":true}"


def _write_policy_doc(tmp_path: Path, body: str) -> Path:
    policy_doc = tmp_path / "policy.md"
    policy_doc.write_text(f"# Example policy\n\n{body}\n", encoding="utf-8")
    return policy_doc


def _waiver(rule_id: str) -> JsonObject:
    return {
        "pattern": "explicit_waiver",
        "required_fields": [
            "metadata.policy_waiver.rule_id",
            "metadata.policy_waiver.authority",
            "metadata.policy_waiver.expires_at",
        ],
        "rule_id": rule_id,
    }


def _json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def _model_response(
    *,
    text: str,
    model_id: str,
    system: str,
    prompt: str,
    max_tokens: int,
) -> ModelResponse:
    request_hash = _hash({"system": system, "prompt": prompt, "max_tokens": max_tokens})
    response_hash = _hash({"model_id": model_id, "text": text})
    return ModelResponse(
        text=text,
        model_id=model_id,
        request_hash=request_hash,
        response_hash=response_hash,
    )


def _hash(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_dumps(payload).encode("utf-8")).hexdigest()
