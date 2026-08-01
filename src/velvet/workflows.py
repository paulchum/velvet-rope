"""Deterministic multi-step workflow runner over the Rust routing core."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from velvet.integrations import IntegrationExecutor
from velvet.router import Router
from velvet.types import (
    ActionType,
    CandidateAction,
    ExecutionStatus,
    RouteRunResult,
)

CandidateFactory = Callable[
    [Mapping[str, Any], tuple[RouteRunResult, ...]],
    Iterable[CandidateAction],
]


@dataclass(frozen=True)
class WorkflowRun:
    """Result of a bounded route-execute-update loop."""

    steps: tuple[RouteRunResult, ...]
    status: str
    final_state: Mapping[str, Any]

    @property
    def last_step(self) -> RouteRunResult | None:
        return self.steps[-1] if self.steps else None


class WorkflowRunner:
    """Run route -> execute -> update cycles until a deterministic stop condition."""

    def __init__(
        self,
        *,
        router: Router | None = None,
        executor: IntegrationExecutor | None = None,
        max_steps: int = 4,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self.router = router or Router()
        self.executor = executor or IntegrationExecutor()
        self.max_steps = max_steps

    def run(
        self,
        state: Mapping[str, Any],
        candidates: Iterable[CandidateAction] | CandidateFactory,
    ) -> WorkflowRun:
        current_state: dict[str, Any] = dict(state)
        steps: list[RouteRunResult] = []
        status = "max_steps"
        for _ in range(self.max_steps):
            if callable(candidates):
                candidate_set = tuple(candidates(current_state, tuple(steps)))
            else:
                candidate_set = tuple(candidates)
            result = self.router.run(current_state, candidate_set, executor=self.executor)
            steps.append(result)
            current_state = self._update_state(current_state, result)
            status = self._stop_status(result, current_state)
            if status != "continue":
                break
        return WorkflowRun(steps=tuple(steps), status=status, final_state=current_state)

    def _update_state(self, state: Mapping[str, Any], result: RouteRunResult) -> dict[str, Any]:
        next_state = dict(state)
        history = list(next_state.get("workflow_history", []))
        history.append(
            {
                "action_type": result.decision.action_type.value
                if result.decision.action_type is not None
                else None,
                "decision": result.decision.decision.value,
                "execution_status": result.execution_result.status.value,
                "summary": result.execution_result.summary,
                "seal_id": result.thread.seal_id,
            }
        )
        next_state["workflow_history"] = history
        next_state["budget_state"] = self._debit_budget(
            next_state.get("budget_state", {}),
            result.execution_result.cost,
        )
        return next_state

    def _debit_budget(
        self,
        budget_state: object,
        cost: Mapping[str, float],
    ) -> dict[str, float]:
        budgets = {
            "tokens_remaining": 1.0,
            "money_remaining": 1.0,
            "api_calls_remaining": 1.0,
            "latency_ms_remaining": 1.0,
            "compute_remaining": 1.0,
            "user_attention_remaining": 1.0,
            "memory_slots_remaining": 1.0,
        }
        if isinstance(budget_state, Mapping):
            for key in budgets:
                if key in budget_state:
                    budgets[key] = float(budget_state[key])
        debits = {
            "tokens_remaining": float(cost.get("tokens", 0.0)) * 0.01,
            "money_remaining": float(cost.get("money", 0.0)),
            "api_calls_remaining": float(cost.get("api_calls", 0.0)) * 0.1,
            "latency_ms_remaining": float(cost.get("latency", 0.0)) * 0.01,
            "compute_remaining": float(cost.get("compute", 0.0)) * 0.01,
            "user_attention_remaining": float(cost.get("user_attention", 0.0)) * 0.1,
            "memory_slots_remaining": float(cost.get("memory_bloat", 0.0)) * 0.1,
        }
        return {key: max(0.0, value - debits[key]) for key, value in budgets.items()}

    def _stop_status(self, result: RouteRunResult, state: Mapping[str, Any]) -> str:
        if result.execution_result.status == ExecutionStatus.PENDING_CONCIERGE:
            return "pending_concierge"
        if result.execution_result.status in {
            ExecutionStatus.BLOCKED,
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMED_OUT,
        }:
            return result.execution_result.status.value
        if result.decision.action_type == ActionType.ANSWER_DIRECTLY:
            return "answered"
        budget_state = state.get("budget_state", {})
        exhausted = isinstance(budget_state, Mapping) and any(
            float(value) <= 0.0 for value in budget_state.values()
        )
        if exhausted:
            return "budget_exhausted"
        return "continue"
