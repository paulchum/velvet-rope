from __future__ import annotations

import pytest

from velvet.shadowpath_effects import (
    EFFECT_FOOTPRINT_SCHEMA_VERSION,
    EffectFootprintError,
    EffectRecord,
    ResourceRef,
    effect_footprint,
)


def test_resource_identity_is_stable_and_keeps_platform_kind() -> None:
    first = ResourceRef("docker.test", "docker.container", "web", facet="lifecycle")
    second = ResourceRef("docker.test", "docker.container", "web", facet="lifecycle")

    assert first.resource_id == second.resource_id
    assert first.to_json() == {
        "namespace": "docker.test",
        "kind": "docker.container",
        "key": "web",
        "facet": "lifecycle",
        "resource_id": first.resource_id,
    }


def test_resource_keys_preserve_significant_whitespace_without_colliding() -> None:
    plain = ResourceRef("filesystem.test", "filesystem.entry", "file")
    spaced = ResourceRef("filesystem.test", "filesystem.entry", " file ")

    assert spaced.key == " file "
    assert spaced.resource_id != plain.resource_id


def test_effect_footprint_spans_services_runtimes_network_and_delegated_tools() -> None:
    candidate_records = (
        EffectRecord(
            "service.object.update",
            ResourceRef("crm.test", "service.object", "account/42"),
            "source_supported",
            "service_source_index",
        ),
    )
    observed_records = (
        EffectRecord(
            "container.start",
            ResourceRef("docker.test", "docker.container", "web"),
            "observed",
            "docker_state_observer",
        ),
        EffectRecord(
            "process.spawn",
            ResourceRef("sandbox.test", "runtime.process", "worker-1"),
            "observed",
            "runtime_observer",
        ),
        EffectRecord(
            "network.connect",
            ResourceRef("sandbox.test", "network.endpoint", "api.example.test:443"),
            "observed",
            "network_observer",
        ),
        EffectRecord(
            "delegated_tool.call",
            ResourceRef("agent.test", "delegated_tool.operation", "browser.open"),
            "observed",
            "explorer_dispatch",
        ),
    )

    footprint = effect_footprint(candidates=candidate_records, observed=observed_records)

    assert footprint["schema_version"] == EFFECT_FOOTPRINT_SCHEMA_VERSION
    kinds = {
        item["resource"]["kind"]
        for item in [*footprint["candidate_effects"], *footprint["observed_effects"]]
    }
    assert kinds == {
        "docker.container",
        "runtime.process",
        "service.object",
        "network.endpoint",
        "delegated_tool.operation",
    }


def test_candidate_and_observed_evidence_remain_separate() -> None:
    resource = ResourceRef("service.test", "service.object", "record/7")
    candidate = EffectRecord(
        "effect.unknown",
        resource,
        "candidate",
        "schema_bound_argument",
    )
    observed = EffectRecord(
        "service.object.delete",
        resource,
        "observed",
        "service_state_observer",
    )

    footprint = effect_footprint(candidates=[candidate], observed=[observed])

    assert footprint["candidate_effects"][0]["effect"] == "effect.unknown"
    assert footprint["observed_effects"][0]["effect"] == "service.object.delete"
    assert footprint["observed_resources_not_in_candidates"] == []
    assert footprint["candidate_resources_not_observed"] == []
    assert footprint["observed_effects_not_in_candidates"] == [observed.to_json()]
    assert footprint["candidate_effects_not_observed"] == [candidate.to_json()]


def test_effect_comparison_keeps_operation_identity() -> None:
    resource = ResourceRef("service.test", "service.object", "record/7")
    candidate = EffectRecord(
        "service.object.delete",
        resource,
        "adapter_declared",
        "adapter",
        operation="records.delete",
    )
    observed = EffectRecord(
        "service.object.delete",
        resource,
        "observed",
        "service_observer",
        operation="admin.purge",
    )

    footprint = effect_footprint(candidates=[candidate], observed=[observed])

    assert footprint["observed_effects_not_in_candidates"] == [observed.to_json()]
    assert footprint["candidate_effects_not_observed"] == [candidate.to_json()]


def test_evidence_tiers_cannot_be_mislabeled_by_the_caller() -> None:
    resource = ResourceRef("service.test", "service.object", "record/7")
    observed = EffectRecord("service.object.delete", resource, "observed", "service_state_observer")
    declared = EffectRecord(
        "service.object.delete", resource, "adapter_declared", "service_adapter"
    )

    with pytest.raises(EffectFootprintError, match="candidate effect"):
        effect_footprint(candidates=[observed])
    with pytest.raises(EffectFootprintError, match="observed effect"):
        effect_footprint(observed=[declared])


def test_effect_details_are_detached_and_immutable() -> None:
    supplied = {"nested": {"values": ["before"]}}
    record = EffectRecord(
        "service.object.update",
        ResourceRef("service.test", "service.object", "record/7"),
        "candidate",
        "test",
        details=supplied,
    )
    supplied["nested"]["values"].append("after")

    assert record.to_json()["details"] == {"nested": {"values": ["before"]}}
    with pytest.raises(TypeError):
        record.details["new"] = "value"  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "value"),
    [("namespace", ""), ("kind", "spaces are invalid"), ("key", "bad\x00key")],
)
def test_invalid_resource_identity_is_rejected(field: str, value: str) -> None:
    values = {"namespace": "test", "kind": "service.object", "key": "one"}
    values[field] = value
    with pytest.raises(EffectFootprintError):
        ResourceRef(**values)
