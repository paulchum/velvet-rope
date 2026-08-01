from __future__ import annotations

import difflib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.ledger import seal_thread_decision
from velvet.mcp import DirectVelvetMCPAdapter
from velvet.rope import VelvetWarrant

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "golden_seals" / "v1"
CONTRACT_FIELDS = ("decision", "selected_action", "seal_id")

JsonObject = dict[str, Any]


def _load_json(path: Path) -> JsonObject:
    return cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))


def _load_manifest() -> JsonObject:
    manifest = _load_json(FIXTURE_DIR / "manifest.json")
    assert manifest["schema_version"] == "velvet.golden_seals.v1"
    assert manifest["stable_contract_fields"] == list(CONTRACT_FIELDS)
    return manifest


def _fixtures() -> list[JsonObject]:
    fixtures = cast(list[JsonObject], _load_manifest()["fixtures"])
    assert fixtures
    return fixtures


def _contract_payload(payload: Mapping[str, object]) -> JsonObject:
    return {field: payload.get(field) for field in CONTRACT_FIELDS}


def _thread_replay(fixture: Mapping[str, Any]) -> JsonObject:
    expected = cast(Mapping[str, object], fixture["expected"])
    replay_seal_id = str(fixture.get("replay_seal_id", expected["seal_id"]))
    report = seal_thread_decision(
        FIXTURE_DIR / str(fixture["thread"]),
        replay_seal_id,
        policy_dir=str(ROOT / str(fixture["policy_dir"])),
        chain=str(fixture["chain"]),
    )
    return {
        "decision": report["decision"],
        "selected_action": report["sealed_selected_action"],
        "seal_id": report["sealed_seal_id"],
    }


def _mcp_authorize_replay(fixture: Mapping[str, Any]) -> JsonObject:
    request = _load_json(FIXTURE_DIR / str(fixture["request"]))
    adapter = DirectVelvetMCPAdapter.from_list_file(
        FIXTURE_DIR / str(fixture["mcp_list"]),
        policy_dir=str(ROOT / str(fixture["policy_dir"])),
        chain=str(fixture["chain"]),
    )

    # This corpus asserts replay identity, not signature-provider behavior.
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(VelvetWarrant, "sign", _unsigned_warrant)
        payload = adapter.authorize(request)
    decision = cast(Mapping[str, object], payload["admission_decision"]["decision"])
    return {
        "decision": decision["decision"],
        "selected_action": decision["action_type"],
        "seal_id": payload["admission_decision"]["seal_id"],
    }


def _unsigned_warrant(warrant: VelvetWarrant) -> VelvetWarrant:
    return warrant


def _replay_fixture(fixture: Mapping[str, Any]) -> JsonObject:
    replay_kind = fixture["replay"]
    if replay_kind == "thread":
        return _thread_replay(fixture)
    if replay_kind == "mcp_authorize":
        return _mcp_authorize_replay(fixture)
    raise AssertionError(f"unsupported replay kind: {replay_kind}")


def _diff(expected: Mapping[str, object], observed: Mapping[str, object]) -> str:
    expected_json = json.dumps(expected, indent=2, sort_keys=True).splitlines()
    observed_json = json.dumps(observed, indent=2, sort_keys=True).splitlines()
    return "\n".join(
        difflib.unified_diff(
            expected_json,
            observed_json,
            fromfile="expected golden seal",
            tofile="current replay",
            lineterm="",
        )
    )


@pytest.mark.parametrize("fixture", _fixtures(), ids=lambda fixture: str(fixture["id"]))
def test_golden_sealed_decision_replays_to_same_contract(fixture: JsonObject) -> None:
    expected = _contract_payload(cast(Mapping[str, object], fixture["expected"]))
    observed = _contract_payload(_replay_fixture(fixture))

    if observed != expected:
        pytest.fail(
            f"golden seal drift for {fixture['id']} from {fixture['source']}\n"
            f"{_diff(expected, observed)}"
        )


def test_golden_seal_corpus_covers_required_launch_and_max_de_cases() -> None:
    fixtures = _fixtures()
    fixture_ids = {str(fixture["id"]) for fixture in fixtures}
    assert {
        "launch-demo-execute",
        "launch-demo-block",
        "launch-demo-escalate",
        "max-de-certified-lockout",
    } <= fixture_ids

    max_de_fixture = next(
        fixture for fixture in fixtures if fixture["id"] == "max-de-certified-lockout"
    )
    record = json.loads((FIXTURE_DIR / str(max_de_fixture["thread"])).read_text(encoding="utf-8"))
    raw_candidates = cast(list[Mapping[str, object]], record["raw_candidates"])
    certificate = cast(Mapping[str, object], raw_candidates[0]["certificate"])
    assert max_de_fixture["certificate_outcome"] == "lockout"
    assert certificate["outcome"] == "lockout"
