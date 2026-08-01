"""Agent, tool, and binding registry for the Velvet control plane."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from velvet.rope import ToolRiskClass, VelvetToolPolicy

JsonObject = dict[str, Any]

REGISTRY_SCHEMA_VERSION = "velvet.agent_registry.v1"


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


class AgentStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class ToolSurfaceKind(StrEnum):
    MCP = "mcp"
    LLM = "llm"
    A2A = "a2a"
    MEMORY = "memory"
    CODE = "code"
    EXTERNAL_SEND = "external_send"


class ApprovalTier(StrEnum):
    AUTO_APPROVE = "auto_approve"
    CONCIERGE_REVIEW = "concierge_review"
    BLOCKED = "blocked"


class SchemaStatus(StrEnum):
    APPROVED = "approved"
    UNREVIEWED = "unreviewed"
    DRIFTED = "drifted"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    name: str
    owner: str
    runtime: str = "unknown"
    purpose: str = ""
    status: AgentStatus = AgentStatus.ACTIVE
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentRecord:
        return cls(
            agent_id=str(data["agent_id"]),
            name=str(data.get("name", data["agent_id"])),
            owner=str(data.get("owner", "unassigned")),
            runtime=str(data.get("runtime", "unknown")),
            purpose=str(data.get("purpose", "")),
            status=AgentStatus(str(data.get("status", AgentStatus.ACTIVE.value))),
            tags=tuple(str(item) for item in data.get("tags", ())),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    def to_dict(self) -> JsonObject:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "owner": self.owner,
            "runtime": self.runtime,
            "purpose": self.purpose,
            "status": self.status.value,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ToolSurface:
    tool_id: str
    kind: ToolSurfaceKind
    server: str
    tool: str
    risk_class: ToolRiskClass = ToolRiskClass.MEDIUM
    approval_tier: ApprovalTier = ApprovalTier.CONCIERGE_REVIEW
    description: str = ""
    expected_improvement: float = 0.78
    novelty: float = 0.60
    confidence: float = 0.72
    discovered_from: str = "manual"
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    schema_hash: str = ""
    approved_schema_hash: str | None = None
    schema_status: SchemaStatus = SchemaStatus.APPROVED
    first_seen_at: str = field(default_factory=_now_iso)
    last_seen_at: str = field(default_factory=_now_iso)
    owner: str = "unassigned"
    environment: str = "unknown"
    tenant_id: str | None = None
    data_class: str | None = None
    risk_rationale: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        schema = dict(self.input_schema)
        object.__setattr__(self, "input_schema", schema)
        schema_hash = self.schema_hash or schema_hash_for_input_schema(schema)
        object.__setattr__(self, "schema_hash", schema_hash)
        if self.schema_status == SchemaStatus.APPROVED and self.approved_schema_hash is None:
            object.__setattr__(self, "approved_schema_hash", schema_hash)
        if self.description and not self.risk_rationale:
            object.__setattr__(self, "risk_rationale", self.description)
        if self.risk_rationale and not self.description:
            object.__setattr__(self, "description", self.risk_rationale)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolSurface:
        input_schema = cast(Mapping[str, Any], data.get("input_schema", {}))
        risk_rationale = str(
            data.get("risk_rationale", data.get("description", data.get("rationale", "")))
        )
        return cls(
            tool_id=str(data["tool_id"]),
            kind=ToolSurfaceKind(str(data.get("kind", ToolSurfaceKind.MCP.value))),
            server=str(data.get("server", "")),
            tool=str(data.get("tool", "")),
            risk_class=ToolRiskClass(str(data.get("risk_class", ToolRiskClass.MEDIUM.value))),
            approval_tier=ApprovalTier(
                str(data.get("approval_tier", ApprovalTier.CONCIERGE_REVIEW.value))
            ),
            description=str(data.get("description", "")),
            expected_improvement=float(data.get("expected_improvement", 0.78)),
            novelty=float(data.get("novelty", 0.60)),
            confidence=float(data.get("confidence", 0.72)),
            discovered_from=str(data.get("discovered_from", "manual")),
            input_schema=dict(input_schema),
            schema_hash=str(data.get("schema_hash") or schema_hash_for_input_schema(input_schema)),
            approved_schema_hash=cast(str | None, data.get("approved_schema_hash")),
            schema_status=SchemaStatus(str(data.get("schema_status", SchemaStatus.APPROVED.value))),
            first_seen_at=str(data.get("first_seen_at", _now_iso())),
            last_seen_at=str(data.get("last_seen_at", _now_iso())),
            owner=str(data.get("owner", "unassigned")),
            environment=str(data.get("environment", "unknown")),
            tenant_id=cast(str | None, data.get("tenant_id")),
            data_class=cast(str | None, data.get("data_class")),
            risk_rationale=risk_rationale,
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    @property
    def key(self) -> str:
        if self.kind == ToolSurfaceKind.MCP:
            return f"{self.server}/{self.tool}"
        return self.tool_id

    def to_mcp_policy(self) -> VelvetToolPolicy:
        metadata = {
            "approval_tier": self.approval_tier.value,
            "tool_id": self.tool_id,
            "tool_surface_kind": self.kind.value,
            "input_schema": dict(self.input_schema),
            "schema_hash": self.schema_hash,
            "tool_schema_hash": self.schema_hash,
            "approved_schema_hash": self.approved_schema_hash,
            "schema_status": self.schema_status.value,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "owner": self.owner,
            "environment": self.environment,
            "tenant_id": self.tenant_id,
            "data_class": self.data_class,
            "risk_rationale": self.risk_rationale,
        }
        metadata.update(dict(self.metadata))
        if self.risk_rationale:
            metadata["rationale"] = self.risk_rationale
        return VelvetToolPolicy(
            server=self.server,
            tool=self.tool,
            risk_class=self.risk_class,
            expected_improvement=self.expected_improvement,
            novelty=self.novelty,
            confidence=self.confidence,
            metadata=metadata,
        )

    def to_dict(self) -> JsonObject:
        return {
            "tool_id": self.tool_id,
            "kind": self.kind.value,
            "server": self.server,
            "tool": self.tool,
            "risk_class": self.risk_class.value,
            "approval_tier": self.approval_tier.value,
            "description": self.description,
            "expected_improvement": self.expected_improvement,
            "novelty": self.novelty,
            "confidence": self.confidence,
            "discovered_from": self.discovered_from,
            "input_schema": dict(self.input_schema),
            "schema_hash": self.schema_hash,
            "approved_schema_hash": self.approved_schema_hash,
            "schema_status": self.schema_status.value,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "owner": self.owner,
            "environment": self.environment,
            "tenant_id": self.tenant_id,
            "data_class": self.data_class,
            "risk_rationale": self.risk_rationale,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AgentToolBinding:
    binding_id: str
    agent_id: str
    tool_id: str
    approved: bool = True
    policy_chain: str = "default"
    budget_account: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentToolBinding:
        return cls(
            binding_id=str(data["binding_id"]),
            agent_id=str(data["agent_id"]),
            tool_id=str(data["tool_id"]),
            approved=bool(data.get("approved", True)),
            policy_chain=str(data.get("policy_chain", "default")),
            budget_account=cast(str | None, data.get("budget_account")),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    def to_dict(self) -> JsonObject:
        return {
            "binding_id": self.binding_id,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "approved": self.approved,
            "policy_chain": self.policy_chain,
            "budget_account": self.budget_account,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RegistryFinding:
    finding_id: str
    severity: str
    message: str
    subject: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "message": self.message,
            "subject": self.subject,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AgentRegistry:
    agents: tuple[AgentRecord, ...] = ()
    tools: tuple[ToolSurface, ...] = ()
    bindings: tuple[AgentToolBinding, ...] = ()
    schema_version: str = REGISTRY_SCHEMA_VERSION
    generated_at: str = field(default_factory=_now_iso)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentRegistry:
        return cls(
            agents=tuple(
                AgentRecord.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("agents", ())
            ),
            tools=tuple(
                ToolSurface.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("tools", ())
            ),
            bindings=tuple(
                AgentToolBinding.from_dict(cast(Mapping[str, Any], item))
                for item in data.get("bindings", ())
            ),
            schema_version=str(data.get("schema_version", REGISTRY_SCHEMA_VERSION)),
            generated_at=str(data.get("generated_at", _now_iso())),
            metadata=dict(cast(Mapping[str, Any], data.get("metadata", {}))),
        )

    @classmethod
    def from_mcp_list(
        cls,
        path: str | Path,
        *,
        agent_id: str = "default-agent",
        agent_name: str = "Default Agent",
        owner: str = "unassigned",
        runtime: str = "mcp",
        environment: str = "production",
    ) -> AgentRegistry:
        payload = _read_json(path)
        tools = tuple(
            _tool_from_mcp_config(
                item,
                discovered_from=str(path),
                owner=owner,
                environment=environment,
            )
            for item in cast(list[Mapping[str, Any]], payload.get("tools", ()))
        )
        agent = AgentRecord(
            agent_id=agent_id,
            name=agent_name,
            owner=owner,
            runtime=runtime,
            purpose="Imported from MCP list.",
        )
        bindings = tuple(
            AgentToolBinding(
                binding_id=f"{agent_id}:{tool.tool_id}",
                agent_id=agent_id,
                tool_id=tool.tool_id,
                policy_chain="mcp_demo",
            )
            for tool in tools
        )
        return cls(
            agents=(agent,),
            tools=tools,
            bindings=bindings,
            metadata={"source_mcp_list": str(path), "source_version": payload.get("version")},
        )

    def import_mcp_tools_with_schema(
        self,
        source: str | Path | Mapping[str, Any],
        *,
        agent_id: str = "default-agent",
        agent_name: str = "Default Agent",
        owner: str = "unassigned",
        runtime: str = "mcp",
        environment: str = "unknown",
        tenant_id: str | None = None,
    ) -> AgentRegistry:
        payload, source_label = _registry_payload_and_label(source)
        observed_at = _now_iso()
        registry = self.with_agent(
            AgentRecord(
                agent_id=agent_id,
                name=agent_name,
                owner=owner,
                runtime=runtime,
                purpose="Imported from schema-aware MCP tool inventory.",
            )
        )
        existing_by_tool_id = {tool.tool_id: tool for tool in registry.tools}
        for item in cast(list[Mapping[str, Any]], payload.get("tools", ())):
            tool = _tool_from_mcp_schema_config(
                item,
                discovered_from=source_label,
                existing=existing_by_tool_id.get(_mcp_tool_id(item)),
                default_owner=owner,
                default_environment=environment,
                default_tenant_id=tenant_id,
                observed_at=observed_at,
            )
            registry = registry.with_tool(tool)
            registry = registry.with_binding(
                AgentToolBinding(
                    binding_id=f"{agent_id}:{tool.tool_id}",
                    agent_id=agent_id,
                    tool_id=tool.tool_id,
                    policy_chain="mcp_demo",
                )
            )
        metadata = dict(registry.metadata)
        metadata["source_mcp_schema_inventory"] = source_label
        metadata["source_version"] = payload.get("version")
        return replace(registry, metadata=metadata, generated_at=_now_iso())

    @classmethod
    def load(cls, path: str | Path) -> AgentRegistry:
        return cls.from_dict(_read_json(path))

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
        return target

    def with_agent(self, agent: AgentRecord) -> AgentRegistry:
        agents = tuple(item for item in self.agents if item.agent_id != agent.agent_id) + (agent,)
        return replace(self, agents=agents, generated_at=_now_iso())

    def with_tool(self, tool: ToolSurface) -> AgentRegistry:
        tools = tuple(item for item in self.tools if item.tool_id != tool.tool_id) + (tool,)
        return replace(self, tools=tools, generated_at=_now_iso())

    def with_binding(self, binding: AgentToolBinding) -> AgentRegistry:
        bindings = tuple(
            item for item in self.bindings if item.binding_id != binding.binding_id
        ) + (binding,)
        return replace(self, bindings=bindings, generated_at=_now_iso())

    def mcp_policies(self, *, agent_id: str | None = None) -> tuple[VelvetToolPolicy, ...]:
        allowed_tool_ids = self._approved_tool_ids(agent_id)
        return tuple(
            tool.to_mcp_policy()
            for tool in self.tools
            if tool.kind == ToolSurfaceKind.MCP and tool.tool_id in allowed_tool_ids
        )

    def mcp_list_payload(self, *, agent_id: str | None = None) -> JsonObject:
        allowed_tool_ids = self._approved_tool_ids(agent_id)
        tools: list[JsonObject] = []
        for tool in self.tools:
            if tool.kind != ToolSurfaceKind.MCP or tool.tool_id not in allowed_tool_ids:
                continue
            payload = {
                "server": tool.server,
                "tool": tool.tool,
                "risk_class": tool.risk_class.value,
                "approval_tier": tool.approval_tier.value,
                "rationale": tool.risk_rationale,
                "expected_improvement": tool.expected_improvement,
                "novelty": tool.novelty,
                "confidence": tool.confidence,
                "input_schema": dict(tool.input_schema),
                "schema_hash": tool.schema_hash,
                "approved_schema_hash": tool.approved_schema_hash,
                "schema_status": tool.schema_status.value,
                "owner": tool.owner,
                "environment": tool.environment,
                "tenant_id": tool.tenant_id,
                "data_class": tool.data_class,
            }
            payload.update(dict(tool.metadata))
            tools.append(payload)
        return {"version": "velvet.mcp_list.from_registry.v1", "tools": tools}

    def tool_by_mcp_key(self, server: str, tool_name: str) -> ToolSurface | None:
        key = f"{server}/{tool_name}"
        return next(
            (tool for tool in self.tools if tool.kind == ToolSurfaceKind.MCP and tool.key == key),
            None,
        )

    def scan_findings(self) -> tuple[RegistryFinding, ...]:
        findings: list[RegistryFinding] = []
        bound_tool_ids = {binding.tool_id for binding in self.bindings if binding.approved}
        agent_ids = {agent.agent_id for agent in self.agents}
        for agent in self.agents:
            if agent.owner in {"", "unassigned"}:
                findings.append(
                    RegistryFinding(
                        "agent.unowned",
                        "warning",
                        "Agent has no accountable owner.",
                        agent.agent_id,
                    )
                )
            if agent.status == AgentStatus.QUARANTINED:
                findings.append(
                    RegistryFinding(
                        "agent.quarantined",
                        "error",
                        "Quarantined agent remains in the registry.",
                        agent.agent_id,
                    )
                )
        for binding in self.bindings:
            if binding.agent_id not in agent_ids:
                findings.append(
                    RegistryFinding(
                        "binding.missing_agent",
                        "error",
                        "Tool binding references an unknown agent.",
                        binding.binding_id,
                    )
                )
        for tool in self.tools:
            subject = tool.key
            if tool.tool_id not in bound_tool_ids:
                findings.append(
                    RegistryFinding(
                        "tool.unbound",
                        "warning",
                        "Tool is registered but not approved for any agent.",
                        subject,
                    )
                )
            if tool.schema_status == SchemaStatus.UNREVIEWED:
                findings.append(
                    RegistryFinding(
                        "tool.schema_unreviewed",
                        "warning",
                        "Tool schema has not been approved.",
                        subject,
                        details=_schema_finding_details(tool),
                    )
                )
            if tool.schema_status == SchemaStatus.DRIFTED:
                findings.append(
                    RegistryFinding(
                        "tool.schema_drifted",
                        "error",
                        "Tool schema hash differs from the approved schema hash.",
                        subject,
                        details=_schema_finding_details(tool),
                    )
                )
            if tool.schema_status == SchemaStatus.BLOCKED:
                findings.append(
                    RegistryFinding(
                        "tool.schema_blocked",
                        "error",
                        "Tool schema is explicitly blocked.",
                        subject,
                        details=_schema_finding_details(tool),
                    )
                )
            high_risk_auto_approve = (
                tool.risk_class == ToolRiskClass.HIGH
                and tool.approval_tier == ApprovalTier.AUTO_APPROVE
            )
            if high_risk_auto_approve:
                findings.append(
                    RegistryFinding(
                        "tool.high_risk_auto_approve",
                        "error",
                        "High-risk tool is auto-approved instead of routed to review.",
                        subject,
                    )
                )
            if _looks_destructive(tool.tool) and tool.approval_tier != ApprovalTier.BLOCKED:
                findings.append(
                    RegistryFinding(
                        "tool.destructive_not_blocked",
                        "error",
                        "Destructive tool should be blocked or explicitly exceptioned.",
                        subject,
                    )
                )
            if tool.owner in {"", "unassigned"}:
                findings.append(
                    RegistryFinding(
                        "tool.unowned",
                        "warning",
                        "Tool has no accountable owner.",
                        subject,
                    )
                )
            if tool.environment in {"", "unknown"}:
                findings.append(
                    RegistryFinding(
                        "tool.missing_environment",
                        "warning",
                        "Tool has no deployment environment label.",
                        subject,
                    )
                )
            if not tool.risk_rationale:
                findings.append(
                    RegistryFinding(
                        "tool.missing_rationale",
                        "warning",
                        "Tool has no business rationale.",
                        subject,
                    )
                )
        return tuple(findings)

    def summary(self) -> JsonObject:
        risk_counts = Counter(tool.risk_class.value for tool in self.tools)
        tier_counts = Counter(tool.approval_tier.value for tool in self.tools)
        kind_counts = Counter(tool.kind.value for tool in self.tools)
        schema_status_counts = Counter(tool.schema_status.value for tool in self.tools)
        findings = self.scan_findings()
        severity_counts = Counter(finding.severity for finding in findings)
        return {
            "agents": len(self.agents),
            "tools": len(self.tools),
            "bindings": len(self.bindings),
            "risk_counts": dict(sorted(risk_counts.items())),
            "approval_tier_counts": dict(sorted(tier_counts.items())),
            "surface_counts": dict(sorted(kind_counts.items())),
            "schema_status_counts": dict(sorted(schema_status_counts.items())),
            "findings": len(findings),
            "finding_severity_counts": dict(sorted(severity_counts.items())),
        }

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "summary": self.summary(),
            "agents": [agent.to_dict() for agent in self.agents],
            "tools": [tool.to_dict() for tool in self.tools],
            "bindings": [binding.to_dict() for binding in self.bindings],
            "findings": [finding.to_dict() for finding in self.scan_findings()],
            "metadata": dict(self.metadata),
        }

    def detect_new_tools(self, new: AgentRegistry) -> tuple[ToolSurface, ...]:
        old_tool_ids = {tool.tool_id for tool in self.tools}
        return tuple(tool for tool in new.tools if tool.tool_id not in old_tool_ids)

    def detect_removed_tools(self, new: AgentRegistry) -> tuple[ToolSurface, ...]:
        new_tool_ids = {tool.tool_id for tool in new.tools}
        return tuple(tool for tool in self.tools if tool.tool_id not in new_tool_ids)

    def detect_schema_drift(self, new: AgentRegistry) -> tuple[JsonObject, ...]:
        old_by_id = {tool.tool_id: tool for tool in self.tools}
        drift: list[JsonObject] = []
        for new_tool in new.tools:
            old_tool = old_by_id.get(new_tool.tool_id)
            if old_tool is None:
                continue
            approved_hash = old_tool.approved_schema_hash or old_tool.schema_hash
            if approved_hash != new_tool.schema_hash:
                drift.append(
                    {
                        "tool_id": new_tool.tool_id,
                        "tool_key": new_tool.key,
                        "old_schema_hash": old_tool.schema_hash,
                        "new_schema_hash": new_tool.schema_hash,
                        "approved_schema_hash": approved_hash,
                        "old_schema_status": old_tool.schema_status.value,
                        "new_schema_status": new_tool.schema_status.value,
                    }
                )
        return tuple(drift)

    def diff_tool_inventory(self, new: AgentRegistry) -> JsonObject:
        new_tools = self.detect_new_tools(new)
        removed_tools = self.detect_removed_tools(new)
        schema_drift = self.detect_schema_drift(new)
        return {
            "schema_version": "velvet.tool_inventory_diff.v1",
            "generated_at": _now_iso(),
            "old_generated_at": self.generated_at,
            "new_generated_at": new.generated_at,
            "summary": {
                "new_tools": len(new_tools),
                "removed_tools": len(removed_tools),
                "schema_drift": len(schema_drift),
            },
            "new_tools": [tool.to_dict() for tool in new_tools],
            "removed_tools": [tool.to_dict() for tool in removed_tools],
            "schema_drift": list(schema_drift),
        }

    def approve_schema_hash(
        self,
        tool_id: str,
        schema_hash: str,
        *,
        approved_by: str = "velvet-operator",
    ) -> AgentRegistry:
        tool = self._tool_by_identifier(tool_id)
        if tool is None:
            raise ValueError(f"unknown tool: {tool_id}")
        if tool.schema_hash != schema_hash:
            raise ValueError(
                f"schema hash mismatch for {tool.tool_id}: "
                f"current={tool.schema_hash} requested={schema_hash}"
            )
        approved_at = _now_iso()
        metadata = dict(tool.metadata)
        metadata["schema_approved_by"] = approved_by
        metadata["schema_approved_at"] = approved_at
        return self.with_tool(
            replace(
                tool,
                approved_schema_hash=schema_hash,
                schema_status=SchemaStatus.APPROVED,
                last_seen_at=approved_at,
                metadata=metadata,
            )
        )

    def block_tool(
        self,
        tool_id: str,
        *,
        reason: str = "Blocked in Velvet registry.",
        blocked_by: str = "velvet-operator",
    ) -> AgentRegistry:
        tool = self._tool_by_identifier(tool_id)
        if tool is None:
            raise ValueError(f"unknown tool: {tool_id}")
        blocked_at = _now_iso()
        metadata = dict(tool.metadata)
        metadata.update(
            {
                "schema_blocked_by": blocked_by,
                "schema_blocked_at": blocked_at,
                "schema_block_reason": reason,
            }
        )
        return self.with_tool(
            replace(
                tool,
                approval_tier=ApprovalTier.BLOCKED,
                schema_status=SchemaStatus.BLOCKED,
                last_seen_at=blocked_at,
                metadata=metadata,
            )
        )

    def export_policy_bundle(self) -> JsonObject:
        approved_tools: list[JsonObject] = []
        denied_tools: list[JsonObject] = []
        for tool in self.tools:
            payload = _policy_bundle_tool_payload(tool)
            if (
                tool.schema_status == SchemaStatus.APPROVED
                and tool.approval_tier != ApprovalTier.BLOCKED
            ):
                approved_tools.append(payload)
            else:
                denied_tools.append(payload)
        return {
            "schema_version": "velvet.registry_policy_bundle.v1",
            "generated_at": _now_iso(),
            "summary": {
                "approved_tools": len(approved_tools),
                "denied_tools": len(denied_tools),
                "findings": len(self.scan_findings()),
            },
            "mcp_allowlist": {
                "version": "velvet.mcp_list.from_registry_policy_bundle.v1",
                "tools": approved_tools,
            },
            "schema_controls": denied_tools,
            "findings": [finding.to_dict() for finding in self.scan_findings()],
        }

    def _approved_tool_ids(self, agent_id: str | None) -> set[str]:
        bindings = self.bindings
        if agent_id is not None:
            bindings = tuple(binding for binding in bindings if binding.agent_id == agent_id)
        return {binding.tool_id for binding in bindings if binding.approved}

    def _tool_by_identifier(self, identifier: str) -> ToolSurface | None:
        normalized = identifier
        if "/" in identifier and not identifier.startswith("mcp:"):
            normalized = f"mcp:{identifier}"
        return next(
            (
                tool
                for tool in self.tools
                if tool.tool_id == normalized
                or tool.tool_id == identifier
                or tool.key == identifier
            ),
            None,
        )


def load_agent_registry(path: str | Path | None) -> AgentRegistry | None:
    if path is None:
        return None
    resolved = Path(path)
    if not resolved.exists():
        return None
    return AgentRegistry.load(resolved)


def registry_from_mcp_lists(paths: Iterable[str | Path]) -> AgentRegistry:
    registry = AgentRegistry()
    for index, path in enumerate(paths, start=1):
        imported = AgentRegistry.from_mcp_list(
            path,
            agent_id=f"agent-{index}",
            agent_name=f"Imported MCP Agent {index}",
        )
        for agent in imported.agents:
            registry = registry.with_agent(agent)
        for tool in imported.tools:
            registry = registry.with_tool(tool)
        for binding in imported.bindings:
            registry = registry.with_binding(binding)
    return registry


def write_registry_report(
    registry: AgentRegistry,
    output_dir: str | Path,
) -> tuple[Path, Path, Path, JsonObject]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = registry.to_dict()
    policy_bundle = registry.export_policy_bundle()
    json_path = destination / "registry_report.json"
    markdown_path = destination / "registry_report.md"
    policy_path = destination / "policy_bundle.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_registry_report_markdown(report), encoding="utf-8")
    policy_path.write_text(
        json.dumps(policy_bundle, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return json_path, markdown_path, policy_path, report


def render_registry_report_markdown(report: Mapping[str, Any]) -> str:
    summary = cast(Mapping[str, Any], report["summary"])
    lines = [
        "# Velvet Tool Registry Report",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Summary",
        "",
        f"- Agents: `{summary['agents']}`",
        f"- Tools: `{summary['tools']}`",
        f"- Bindings: `{summary['bindings']}`",
        f"- Schema statuses: `{json.dumps(summary['schema_status_counts'], sort_keys=True)}`",
        f"- Findings: `{summary['findings']}`",
        "",
        "## Tool Inventory",
        "",
        "| Tool | Status | Approved Hash | Current Hash | Owner | Environment |",
        "|---|---|---|---|---|---|",
    ]
    for tool in cast(Iterable[Mapping[str, Any]], report["tools"]):
        lines.append(
            "| "
            f"`{tool['tool_id']}` | "
            f"`{tool['schema_status']}` | "
            f"`{tool.get('approved_schema_hash')}` | "
            f"`{tool.get('schema_hash')}` | "
            f"`{tool.get('owner')}` | "
            f"`{tool.get('environment')}` |"
        )
    findings = list(cast(Iterable[Mapping[str, Any]], report.get("findings", [])))
    if findings:
        lines.extend(["", "## Findings", ""])
        for finding in findings:
            lines.append(
                f"- `{finding['finding_id']}` `{finding['severity']}` "
                f"`{finding['subject']}`: {finding['message']}"
            )
    lines.append("")
    return "\n".join(lines)


def schema_hash_for_input_schema(schema: Mapping[str, Any] | None) -> str:
    return hashlib.sha256(_canonical_schema_json(schema or {}).encode("utf-8")).hexdigest()


def _canonical_schema_json(schema: Mapping[str, Any]) -> str:
    return json.dumps(
        schema,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _registry_payload_and_label(
    source: str | Path | Mapping[str, Any],
) -> tuple[JsonObject, str]:
    if isinstance(source, Mapping):
        return dict(source), "inline"
    return _read_json(source), str(source)


def _mcp_tool_id(item: Mapping[str, Any]) -> str:
    server = str(item["server"])
    tool = str(item["tool"])
    return f"mcp:{server}/{tool}"


def _input_schema_from_mcp_config(item: Mapping[str, Any]) -> JsonObject:
    for key in ("input_schema", "inputSchema", "schema", "parameters"):
        value = item.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _schema_status_for_import(
    *,
    schema_hash: str,
    existing: ToolSurface | None,
    explicit_status: object,
    explicit_approved_hash: object,
    approval_tier: ApprovalTier,
) -> tuple[SchemaStatus, str | None]:
    explicit_approved = _non_empty_string(explicit_approved_hash)
    if approval_tier == ApprovalTier.BLOCKED:
        approved_hash = explicit_approved or (
            existing.approved_schema_hash if existing is not None else None
        )
        return SchemaStatus.BLOCKED, approved_hash
    if isinstance(explicit_status, str) and explicit_status:
        status = SchemaStatus(explicit_status)
        approved_hash = explicit_approved or (
            existing.approved_schema_hash if existing is not None else None
        )
        if status == SchemaStatus.APPROVED and approved_hash != schema_hash:
            return (
                SchemaStatus.DRIFTED if approved_hash is not None else SchemaStatus.UNREVIEWED,
                approved_hash,
            )
        return status, approved_hash
    approved_hash = explicit_approved or (
        existing.approved_schema_hash if existing is not None else None
    )
    if existing is not None and existing.schema_status == SchemaStatus.BLOCKED:
        return SchemaStatus.BLOCKED, approved_hash
    if approved_hash is None:
        return SchemaStatus.UNREVIEWED, None
    if approved_hash != schema_hash:
        return SchemaStatus.DRIFTED, approved_hash
    return SchemaStatus.APPROVED, approved_hash


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _tool_from_mcp_schema_config(
    item: Mapping[str, Any],
    *,
    discovered_from: str,
    existing: ToolSurface | None,
    default_owner: str,
    default_environment: str,
    default_tenant_id: str | None,
    observed_at: str,
) -> ToolSurface:
    server = str(item["server"])
    tool = str(item["tool"])
    input_schema = _input_schema_from_mcp_config(item)
    schema_hash = schema_hash_for_input_schema(input_schema)
    approval_tier = ApprovalTier(
        str(item.get("approval_tier", ApprovalTier.CONCIERGE_REVIEW.value))
    )
    schema_status, approved_hash = _schema_status_for_import(
        schema_hash=schema_hash,
        existing=existing,
        explicit_status=item.get("schema_status"),
        explicit_approved_hash=item.get("approved_schema_hash"),
        approval_tier=approval_tier,
    )
    risk_rationale = str(item.get("risk_rationale", item.get("rationale", "")))
    metadata = _tool_metadata_from_config(item)
    if existing is not None:
        metadata = {**dict(existing.metadata), **metadata}
    return ToolSurface(
        tool_id=f"mcp:{server}/{tool}",
        kind=ToolSurfaceKind.MCP,
        server=server,
        tool=tool,
        risk_class=ToolRiskClass(str(item.get("risk_class", ToolRiskClass.MEDIUM.value))),
        approval_tier=approval_tier,
        description=risk_rationale,
        expected_improvement=float(item.get("expected_improvement", 0.78)),
        novelty=float(item.get("novelty", 0.60)),
        confidence=float(item.get("confidence", 0.72)),
        discovered_from=discovered_from,
        input_schema=input_schema,
        schema_hash=schema_hash,
        approved_schema_hash=approved_hash,
        schema_status=schema_status,
        first_seen_at=existing.first_seen_at if existing is not None else observed_at,
        last_seen_at=observed_at,
        owner=str(item.get("owner", default_owner)),
        environment=str(item.get("environment", default_environment)),
        tenant_id=cast(str | None, item.get("tenant_id", default_tenant_id)),
        data_class=cast(str | None, item.get("data_class")),
        risk_rationale=risk_rationale,
        metadata=metadata,
    )


def _tool_from_mcp_config(
    item: Mapping[str, Any],
    *,
    discovered_from: str,
    owner: str,
    environment: str,
) -> ToolSurface:
    server = str(item["server"])
    tool = str(item["tool"])
    metadata = _tool_metadata_from_config(item)
    input_schema = _input_schema_from_mcp_config(item)
    schema_hash = schema_hash_for_input_schema(input_schema)
    risk_rationale = str(item.get("risk_rationale", item.get("rationale", "")))
    return ToolSurface(
        tool_id=f"mcp:{server}/{tool}",
        kind=ToolSurfaceKind.MCP,
        server=server,
        tool=tool,
        risk_class=ToolRiskClass(str(item.get("risk_class", ToolRiskClass.MEDIUM.value))),
        approval_tier=ApprovalTier(
            str(item.get("approval_tier", ApprovalTier.CONCIERGE_REVIEW.value))
        ),
        description=risk_rationale,
        expected_improvement=float(item.get("expected_improvement", 0.78)),
        novelty=float(item.get("novelty", 0.60)),
        confidence=float(item.get("confidence", 0.72)),
        discovered_from=discovered_from,
        input_schema=input_schema,
        schema_hash=schema_hash,
        approved_schema_hash=schema_hash,
        schema_status=SchemaStatus.APPROVED,
        owner=str(item.get("owner", owner)),
        environment=str(item.get("environment", environment)),
        tenant_id=cast(str | None, item.get("tenant_id")),
        data_class=cast(str | None, item.get("data_class")),
        risk_rationale=risk_rationale,
        metadata=metadata,
    )


def _tool_metadata_from_config(item: Mapping[str, Any]) -> JsonObject:
    return {
        key: value
        for key, value in item.items()
        if key
        not in {
            "server",
            "tool",
            "risk_class",
            "approval_tier",
            "rationale",
            "risk_rationale",
            "expected_improvement",
            "novelty",
            "confidence",
            "input_schema",
            "inputSchema",
            "schema",
            "parameters",
            "schema_hash",
            "approved_schema_hash",
            "schema_status",
            "first_seen_at",
            "last_seen_at",
            "owner",
            "environment",
            "tenant_id",
            "data_class",
        }
    }


def _schema_finding_details(tool: ToolSurface) -> JsonObject:
    return {
        "tool_id": tool.tool_id,
        "schema_status": tool.schema_status.value,
        "schema_hash": tool.schema_hash,
        "approved_schema_hash": tool.approved_schema_hash,
        "owner": tool.owner,
        "environment": tool.environment,
        "tenant_id": tool.tenant_id,
        "data_class": tool.data_class,
    }


def _policy_bundle_tool_payload(tool: ToolSurface) -> JsonObject:
    return {
        "tool_id": tool.tool_id,
        "server": tool.server,
        "tool": tool.tool,
        "risk_class": tool.risk_class.value,
        "approval_tier": tool.approval_tier.value,
        "schema_status": tool.schema_status.value,
        "schema_hash": tool.schema_hash,
        "approved_schema_hash": tool.approved_schema_hash,
        "owner": tool.owner,
        "environment": tool.environment,
        "tenant_id": tool.tenant_id,
        "data_class": tool.data_class,
        "risk_rationale": tool.risk_rationale,
    }


def _looks_destructive(tool_name: str) -> bool:
    lowered = tool_name.lower()
    return any(
        token in lowered
        for token in (
            "delete",
            "drop",
            "destroy",
            "purge",
            "terminate",
            "remove",
            "revoke",
            "disable",
        )
    )


def _read_json(path: str | Path) -> JsonObject:
    with Path(path).open("r", encoding="utf-8") as handle:
        return cast(JsonObject, json.load(handle))
