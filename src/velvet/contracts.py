"""Admission contracts for the Velvet Admission Layer."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from velvet.actions import AuthorityClass
from velvet.serialization import JsonObject, stable_json_object


def _class_map(values: dict[AuthorityClass, int]) -> dict[str, int]:
    return {key.value: value for key, value in values.items()}


@dataclass(frozen=True)
class AdmissionContract:
    contract_id: str = "velvet_demo_contract"
    contract_version: str = "velvet.contract.v1"
    policy_version: str = "velvet.policy.v1"
    estimator_version: str = "velvet.estimator.rules.v1"
    admission_mode: str = "reserve_only"
    value_numeraire: str = "authority_budget_units"
    upside_value_scale: int = 1_000
    joint_marginal_authority_band: int = 0
    spend_cap: int = 500
    default_authority_budget: int = 750
    authority_budgets: dict[str, int] = field(default_factory=dict)
    execution_permit_ttl_seconds: int = 30
    max_execution_permit_ttl_seconds: int = 300
    tenant_id: str = "velvet-demo-tenant"
    signing_key_id: str = "velvet-local-dev-hmac-demo-key"
    signing_key_version: str = "demo-v1"
    signature_key: str = "velvet-local-deterministic-demo-key"
    sql_dialect: str = "postgres"
    masked_action_policy: str = "refuse"
    execute_fallback_on_insufficient_budget: bool = True
    split_preauthorization_enabled: bool = True
    split_retention_floor: int = 50
    split_retention_rate_basis_points: int = 15_000
    base_prices: dict[str, int] = field(
        default_factory=lambda: _class_map(
            {
                AuthorityClass.OBSERVE: 1,
                AuthorityClass.APPEND: 5,
                AuthorityClass.ALTER: 75,
                AuthorityClass.DESTROY: 500,
                AuthorityClass.SPEND_LOW: 25,
                AuthorityClass.SPEND_HIGH: 250,
                AuthorityClass.BIND_EXTERNAL: 300,
            }
        )
    )
    class_multipliers: dict[str, int] = field(
        default_factory=lambda: _class_map(
            {
                AuthorityClass.OBSERVE: 1,
                AuthorityClass.APPEND: 1,
                AuthorityClass.ALTER: 2,
                AuthorityClass.DESTROY: 4,
                AuthorityClass.SPEND_LOW: 1,
                AuthorityClass.SPEND_HIGH: 3,
                AuthorityClass.BIND_EXTERNAL: 3,
            }
        )
    )
    reversibility_penalties: dict[str, int] = field(
        default_factory=lambda: {
            "none": 0,
            "reversible": 0,
            "partial": 30,
            "irreversible": 125,
        }
    )
    externality_penalty: int = 200
    denial_pressure_weight: int = 25
    split_aggregation_penalty: int = 50
    metadata: JsonObject = field(default_factory=dict)

    def boundary_budget(self, boundary_key: str) -> int:
        return int(self.authority_budgets.get(boundary_key, self.default_authority_budget))

    def with_budget(self, budget: int, *, boundary_key: str | None = None) -> AdmissionContract:
        if boundary_key is None:
            return replace(self, default_authority_budget=budget)
        budgets = dict(self.authority_budgets)
        budgets[boundary_key] = budget
        return replace(self, authority_budgets=budgets)

    def to_dict(self) -> JsonObject:
        return {
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "policy_version": self.policy_version,
            "estimator_version": self.estimator_version,
            "admission_mode": self.admission_mode,
            "value_numeraire": self.value_numeraire,
            "upside_value_scale": self.upside_value_scale,
            "joint_marginal_authority_band": self.joint_marginal_authority_band,
            "spend_cap": self.spend_cap,
            "default_authority_budget": self.default_authority_budget,
            "authority_budgets": dict(sorted(self.authority_budgets.items())),
            "execution_permit_ttl_seconds": self.execution_permit_ttl_seconds,
            "max_execution_permit_ttl_seconds": self.max_execution_permit_ttl_seconds,
            "tenant_id": self.tenant_id,
            "signing_key_id": self.signing_key_id,
            "signing_key_version": self.signing_key_version,
            "sql_dialect": self.sql_dialect,
            "masked_action_policy": self.masked_action_policy,
            "execute_fallback_on_insufficient_budget": self.execute_fallback_on_insufficient_budget,
            "split_preauthorization_enabled": self.split_preauthorization_enabled,
            "split_retention_floor": self.split_retention_floor,
            "split_retention_rate_basis_points": self.split_retention_rate_basis_points,
            "base_prices": dict(sorted(self.base_prices.items())),
            "class_multipliers": dict(sorted(self.class_multipliers.items())),
            "reversibility_penalties": dict(sorted(self.reversibility_penalties.items())),
            "externality_penalty": self.externality_penalty,
            "denial_pressure_weight": self.denial_pressure_weight,
            "split_aggregation_penalty": self.split_aggregation_penalty,
            "metadata": stable_json_object(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdmissionContract:
        return cls(
            contract_id=str(data.get("contract_id", "velvet_demo_contract")),
            contract_version=str(data.get("contract_version", "velvet.contract.v1")),
            policy_version=str(data.get("policy_version", "velvet.policy.v1")),
            estimator_version=str(data.get("estimator_version", "velvet.estimator.rules.v1")),
            admission_mode=str(data.get("admission_mode", "reserve_only")),
            value_numeraire=str(data.get("value_numeraire", "authority_budget_units")),
            upside_value_scale=int(data.get("upside_value_scale", 1_000)),
            joint_marginal_authority_band=int(
                data.get("joint_marginal_authority_band", 0)
            ),
            spend_cap=int(data.get("spend_cap", 500)),
            default_authority_budget=int(data.get("default_authority_budget", 750)),
            authority_budgets={
                str(key): int(value)
                for key, value in dict(data.get("authority_budgets", {})).items()
            },
            execution_permit_ttl_seconds=int(data.get("execution_permit_ttl_seconds", 30)),
            max_execution_permit_ttl_seconds=int(
                data.get("max_execution_permit_ttl_seconds", 300)
            ),
            tenant_id=str(data.get("tenant_id", "velvet-demo-tenant")),
            signing_key_id=str(
                data.get("signing_key_id", "velvet-local-dev-hmac-demo-key")
            ),
            signing_key_version=str(data.get("signing_key_version", "demo-v1")),
            sql_dialect=str(data.get("sql_dialect", "postgres")),
            masked_action_policy=str(data.get("masked_action_policy", "refuse")),
            execute_fallback_on_insufficient_budget=bool(
                data.get("execute_fallback_on_insufficient_budget", True)
            ),
            split_preauthorization_enabled=bool(
                data.get("split_preauthorization_enabled", True)
            ),
            split_retention_floor=int(data.get("split_retention_floor", 50)),
            split_retention_rate_basis_points=int(
                data.get("split_retention_rate_basis_points", 15_000)
            ),
            base_prices={
                str(key): int(value) for key, value in dict(data.get("base_prices", {})).items()
            }
            or cls().base_prices,
            class_multipliers={
                str(key): int(value)
                for key, value in dict(data.get("class_multipliers", {})).items()
            }
            or cls().class_multipliers,
            reversibility_penalties={
                str(key): int(value)
                for key, value in dict(data.get("reversibility_penalties", {})).items()
            }
            or cls().reversibility_penalties,
            externality_penalty=int(data.get("externality_penalty", 200)),
            denial_pressure_weight=int(data.get("denial_pressure_weight", 25)),
            split_aggregation_penalty=int(data.get("split_aggregation_penalty", 50)),
            metadata=stable_json_object(
                data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            ),
        )
