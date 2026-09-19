"""Provider-neutral scope derivation and relation semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.shadowpath_effects import ResourceRef
from velvet.shadowpath_explorer import ExplorationScope
from velvet.shadowpath_observer import ProtectedAsset
from velvet.shadowpath_scope import (
    ResourceGraph,
    ResourceRelation,
    ResourceScopeError,
    canonical_filesystem_key,
    compile_policy_scope,
    filesystem_relations,
    materialize_filesystem_scope,
    regex_witnesses,
    static_policy_coverage,
)

POLICY = r"""
    - name: "Persistence Path Write"
      tool_pattern: '(?i)^(write_file|edit_file)$'
      arg_pattern: '(?i)(/sandbox/automation\.(jobs|daily)/|/sandbox/services/)'
      action: block
    - name: "Shell Profile Resource"
      tool_pattern: '(?i)^(write_file|edit_file)$'
      arg_pattern: '(?i)((?:^|/)\.(interactivecfg|sessioncfg)\b|/sandbox/session/profile\b)'
      action: block
    - name: "Audit Log Resource"
      tool_pattern: '(?i)^(write_file|edit_file)$'
      arg_pattern: '(?i)(>{1,2}\s*[^;|&]*(/sandbox/evidence/|\.(trace|jsonl)\b))'
      action: block
"""


def _ref(key: str, *, namespace: str = "test.filesystem") -> ResourceRef:
    return ResourceRef(namespace, "filesystem.entry", key)


def test_filesystem_containment_is_provider_derived_and_canonical() -> None:
    home = _ref("home")
    profile = _ref("home/.interactivecfg")
    graph = ResourceGraph(filesystem_relations((home, profile)))
    assert graph.affects(home, profile, relations=("contains",))

    escaped = _ref(canonical_filesystem_key("home/../etc/passwd", flavor="posix"))
    assert escaped.key == "etc/passwd"
    assert not graph.affects(home, escaped, relations=("contains",))
    with pytest.raises(ResourceScopeError):
        canonical_filesystem_key("../etc/passwd", flavor="posix")


def test_non_filesystem_relations_are_explicit_instead_of_prefix_based() -> None:
    deployment = ResourceRef("kubernetes.cluster", "kubernetes.deployment", "prod/api")
    pod = ResourceRef("kubernetes.cluster", "kubernetes.pod", "prod/api-7f9")
    graph = ResourceGraph(
        (ResourceRelation(deployment, pod, "owns", transitive=True, provenance="ownerRef"),)
    )
    assert graph.affects(deployment, pod, relations=("owns",))

    upper = ResourceRef("http.service", "http.endpoint", "api.example.test/V1")
    lower = ResourceRef("http.service", "http.endpoint", "api.example.test/v1/orders")
    assert not ResourceGraph().affects(upper, lower)


def test_windows_canonicalization_does_not_depend_on_posix_separators() -> None:
    assert canonical_filesystem_key(
        r"C:\Users\u\AppData\..\profile", flavor="windows"
    ) == r"C:\Users\u\profile"


def test_policy_compiler_derives_three_families_without_path_fixtures() -> None:
    scope = compile_policy_scope(POLICY)
    by_family: dict[str, set[str]] = {
        family: set() for family in ("shell_profile", "persistence", "audit_log")
    }
    for witness in scope.witnesses:
        if witness.family in by_family:
            by_family[witness.family].add(witness.resource_key)

    assert ".interactivecfg" in by_family["shell_profile"]
    assert "/sandbox/services/" in by_family["persistence"]
    assert "/sandbox/evidence/" in by_family["audit_log"]
    assert all(witness.provenance.startswith("policy.rule:") for witness in scope.witnesses)


def test_static_pass_predicts_move_gaps_for_every_derived_family() -> None:
    scope = compile_policy_scope(POLICY)
    tools = [
        {"name": "write_file", "annotations": {"readOnlyHint": False}},
        {"name": "edit_file", "annotations": {"readOnlyHint": False}},
        {"name": "move_file", "annotations": {"readOnlyHint": False}},
    ]
    coverage = static_policy_coverage(tools=tools, scope=scope)
    move_families = {
        row["family"]
        for row in coverage["rows"]
        if row["operation"] == "move_file" and row["predicted_open"]
    }
    assert {"shell_profile", "persistence", "audit_log"} <= move_families
    summaries = {item["family"]: item for item in coverage["families"]}
    assert "move_file" in summaries["shell_profile"]["predicted_open_operations"]
    assert "move_file" in summaries["persistence"]["predicted_open_operations"]
    assert "move_file" in summaries["audit_log"]["predicted_open_operations"]
    assert summaries["audit_log"]["operation_status"]["write_file"] == "uncovered"
    assert summaries["shell_profile"]["operation_status"]["write_file"] == "covered"
    assert any(
        row["operation"] == "write_file"
        and row["family"] == "shell_profile"
        and not row["predicted_open"]
        for row in coverage["rows"]
    )
    assert any(
        row["operation"] == "write_file"
        and row["family"] == "audit_log"
        and row["predicted_open"]
        and row["presented_resource_argument"] == row["resource_key"]
        for row in coverage["rows"]
    )


def test_policy_scope_materializes_a_disposable_baseline(tmp_path: Path) -> None:
    compiled = compile_policy_scope(POLICY)
    materialized = materialize_filesystem_scope(root=tmp_path, scope=compiled)
    assert materialized.protected_paths
    assert materialized.payload_path not in materialized.protected_paths
    assert (tmp_path / materialized.payload_path).is_file()
    assert all((tmp_path / path).is_file() for path in materialized.protected_paths)


def test_policy_yaml_parser_supports_effective_inline_mapping_and_field_order() -> None:
    scope = compile_policy_scope(
        r"""
version: 1
name: unrelated
mcp_tool_policy: {rules: [{action: block, arg_pattern: '(?i)(\.interactivecfg\b)',
  tool_pattern: '^(write_file)$', name: 'Shell Profile Resource'}]}
"""
    )
    assert [rule.name for rule in scope.rules] == ["Shell Profile Resource"]
    assert {item.resource_key for item in scope.witnesses} == {".interactivecfg"}


def test_policy_yaml_parser_fails_closed_on_partial_rule() -> None:
    with pytest.raises(ResourceScopeError, match="missing required fields"):
        compile_policy_scope(
            "mcp_tool_policy:\n  rules:\n    - name: incomplete\n      action: block\n"
        )


def test_huge_regex_repeat_is_capped_and_reported() -> None:
    witnesses, issues, truncated = regex_witnesses(r"a{1000000000}")
    assert witnesses == ()
    assert truncated is True
    assert any("generation cap" in issue for issue in issues)


def test_anchored_absolute_rule_is_not_credited_as_sandbox_materializable() -> None:
    scope = compile_policy_scope(
        r"""
- name: Exact absolute
  tool_pattern: '^write_file$'
  arg_pattern: '^/sandbox/exact$'
  action: block
"""
    )
    assert scope.witnesses == ()
    assert scope.truncated is True
    assert any("anchored absolute" in issue for issue in scope.issues)


def test_materialization_rejects_preexisting_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "baseline"
    root.mkdir()
    outside = tmp_path / "outside"
    (root / ".shadowpath-generated-payload").symlink_to(outside)
    with pytest.raises(ResourceScopeError, match="owned empty directory"):
        materialize_filesystem_scope(root=root, scope=compile_policy_scope(POLICY))
    assert not outside.exists()


def test_binding_pool_round_robins_provider_derived_resource_groups() -> None:
    scope = ExplorationScope(
        protected=tuple(
            ProtectedAsset(path=path)
            for path in ("credential-a", "credential-b", "profile-a", "audit-a")
        ),
        payload_paths=("payload",),
        resource_groups={
            "credential-a": "credential",
            "credential-b": "credential",
            "profile-a": "profile",
            "audit-a": "audit",
        },
        include_ancestors=False,
    )

    assert scope.binding_pool()[:5] == [
        "credential-a",
        "payload",
        "profile-a",
        "audit-a",
        "credential-b",
    ]
