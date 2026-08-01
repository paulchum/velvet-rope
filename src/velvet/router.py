"""Rust-backed routing entry points."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, cast

import velvet._native as _native

from .integrations import IntegrationExecutor
from .sandbox import merge_sandbox_state
from .thread_log import ThreadLogger
from .types import ActionType, CandidateAction, RouteRunResult, RoutingDecision, ThreadRecord


class Router:
    """Canonical Python wrapper over the Rust routing kernel."""

    def __init__(
        self,
        policy_dir: str = "policies",
        chain: str = "default",
        *,
        watch: bool = False,
    ) -> None:
        self._native_router = _native.NativeRouter(policy_dir, chain, watch)

    def decide(
        self,
        state: Mapping[str, object],
        candidates: Iterable[CandidateAction | ActionType | str | Mapping[str, object]],
        thread_logger: ThreadLogger | None = None,
        thread_id: str | None = None,
        timestamp: str | None = None,
    ) -> RoutingDecision:
        normalized = tuple(CandidateAction.coerce(candidate) for candidate in candidates)
        payload = [candidate.to_dict() for candidate in normalized]
        if thread_logger is None:
            raw_decision = cast(
                Mapping[str, Any], self._native_router.route_decision(dict(state), payload)
            )
            return RoutingDecision.from_dict(raw_decision)
        raw_result = cast(
            Mapping[str, Any],
            self._native_router.route_thread(dict(state), payload, thread_id, timestamp),
        )
        thread_logger.write(
            ThreadRecord.from_dict(cast(Mapping[str, Any], raw_result["thread"]))
        )
        return RoutingDecision.from_dict(cast(Mapping[str, Any], raw_result["decision"]))

    def run(
        self,
        state: Mapping[str, object],
        candidates: Iterable[CandidateAction | ActionType | str | Mapping[str, object]],
        *,
        executor: IntegrationExecutor | None = None,
        thread_logger: ThreadLogger | None = None,
    ) -> RouteRunResult:
        active_executor = executor or IntegrationExecutor()
        resolved_state = merge_sandbox_state(state, active_executor.sandbox_config)
        normalized = tuple(CandidateAction.coerce(candidate) for candidate in candidates)
        payload = [candidate.to_dict() for candidate in normalized]
        raw_result = cast(
            Mapping[str, Any], self._native_router.route_thread(dict(resolved_state), payload)
        )
        decision = RoutingDecision.from_dict(cast(Mapping[str, Any], raw_result["decision"]))
        thread = ThreadRecord.from_dict(cast(Mapping[str, Any], raw_result["thread"]))
        execution_result = active_executor.execute(
            decision,
            normalized,
            resolved_state,
            sandbox_plan=thread.sandbox_plan,
        )
        thread = thread.with_execution_result(execution_result)
        if thread_logger is not None:
            thread_logger.write(thread)
        return RouteRunResult(
            decision=decision,
            thread=thread,
            execution_result=execution_result,
        )
