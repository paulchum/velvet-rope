"""Execution adapter layer for routed Velvet actions."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import shutil
import sqlite3
import subprocess  # nosec B404
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from velvet.budget_safety import openai_responses_realized_cost_usd
from velvet.memory import MemoryEngine
from velvet.sandbox import SandboxConfig, SandboxExecutor
from velvet.types import (
    ActionType,
    CandidateAction,
    DecisionType,
    ExecutionResult,
    ExecutionStatus,
    RoutingDecision,
    SandboxExecutionPlan,
)


class IntegrationExecutor:
    """Executes the selected v1 action and returns a typed execution result."""

    def __init__(
        self,
        *,
        workspace: str | Path | None = None,
        memory_path: str | Path | None = None,
        retrieval_path: str | Path | None = None,
        timeout_seconds: float = 10.0,
        output_limit: int = 12_000,
        interactive: bool = False,
        sandbox_config: SandboxConfig | None = None,
    ) -> None:
        self.workspace = Path(workspace or os.getcwd()).resolve()
        self.memory_path = Path(memory_path or self.workspace / ".velvet_memory.sqlite")
        self.retrieval_path = Path(retrieval_path or self.workspace / ".velvet_retrieval.sqlite")
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        self.interactive = interactive
        self.sandbox_config = sandbox_config or SandboxConfig.from_env()
        self._sandbox_executor = SandboxExecutor(self.workspace, sandbox_config=self.sandbox_config)

    def execute(
        self,
        decision: RoutingDecision,
        candidates: tuple[CandidateAction, ...],
        state: Mapping[str, Any],
        sandbox_plan: SandboxExecutionPlan | None = None,
    ) -> ExecutionResult:
        if decision.decision == DecisionType.ESCALATE and decision.action_type is not None:
            return self._deferred(decision)
        if decision.decision != DecisionType.EXECUTE or decision.action_type is None:
            return ExecutionResult(
                action_type=decision.action_type or ActionType.ANSWER_DIRECTLY,
                status=ExecutionStatus.NOT_RUN,
                provider="velvet",
                summary=f"Decision was {decision.decision}; no execution performed.",
            )
        selected = decision.selected_candidate
        candidate = (
            selected.final_candidate
            if selected is not None
            else self._selected_candidate(decision.action_type, candidates)
        )
        params = dict(candidate.parameters if candidate is not None else {})
        if decision.action_type == ActionType.ANSWER_DIRECTLY:
            return self._answer_directly(state)
        if decision.action_type == ActionType.SEARCH_WEB:
            return self._search_web(params, state)
        if decision.action_type == ActionType.RETRIEVE_CONTEXT:
            return self._retrieve_context(params, state)
        if decision.action_type == ActionType.READ_FILE:
            return self._read_file(params, state)
        if decision.action_type == ActionType.INSPECT_CODE:
            return self._inspect_code(params, state)
        if decision.action_type == ActionType.EXECUTE_CODE:
            return self._execute_code(params, state, sandbox_plan)
        if decision.action_type == ActionType.CALL_TOOL:
            return self._call_tool(params, state)
        if decision.action_type == ActionType.ASK_USER:
            return self._ask_user(params, state)
        if decision.action_type == ActionType.STORE_MEMORY:
            return self._store_memory(params, state)
        if decision.action_type == ActionType.ESCALATE_MODEL:
            return self._escalate_model(params, state)
        if decision.action_type == ActionType.CONCIERGE_REVIEW:
            return self._concierge_review(params, state)
        raise AssertionError(f"Unsupported action type: {decision.action_type}")

    def _deferred(self, decision: RoutingDecision) -> ExecutionResult:
        selected = decision.selected_candidate
        target = None
        if selected is not None:
            for entry in selected.policy_trace:
                if entry.decision.kind == "defer":
                    target = entry.decision.to
                    break
        if target is None:
            return ExecutionResult(
                action_type=decision.action_type or ActionType.ANSWER_DIRECTLY,
                status=ExecutionStatus.NOT_RUN,
                provider="velvet",
                summary="Decision escalated but did not include an escalation target.",
            )
        return ExecutionResult(
            action_type=decision.action_type or ActionType.ANSWER_DIRECTLY,
            status=ExecutionStatus.BLOCKED
            if target.fallback == "deny"
            else ExecutionStatus.PENDING_CONCIERGE,
            provider=target.target_type,
            summary=(
                f"Escalation target {target.target} is unavailable; "
                f"fallback={target.fallback}."
            ),
            output=target.payload,
            metadata={
                "target": target.target,
                "mode": target.mode,
                "fallback": target.fallback,
            },
        )

    def _answer_directly(self, state: Mapping[str, Any]) -> ExecutionResult:
        request = str(state.get("user_request", ""))
        return ExecutionResult(
            action_type=ActionType.ANSWER_DIRECTLY,
            status=ExecutionStatus.SUCCEEDED,
            provider="velvet",
            summary="Returned current-context answer placeholder.",
            output={"answer": request},
        )

    def _search_web(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        query = str(params.get("query") or state.get("user_request") or "")
        api_key = os.environ.get("TAVILY_API_KEY")
        if not api_key:
            return self._missing_key(ActionType.SEARCH_WEB, "tavily", "TAVILY_API_KEY")
        payload = {
            "api_key": api_key,
            "query": query,
            "max_results": int(params.get("max_results", 5)),
            "include_answer": bool(params.get("include_answer", True)),
        }
        response = self._post_json("https://api.tavily.com/search", payload)
        return ExecutionResult(
            action_type=ActionType.SEARCH_WEB,
            status=ExecutionStatus.SUCCEEDED,
            provider="tavily",
            summary=f"Searched Tavily for: {query}",
            output=response,
            cost={"api_calls": 1},
            metadata={"query_hash": sha256_text(query)},
        )

    def _retrieve_context(
        self, params: Mapping[str, Any], state: Mapping[str, Any]
    ) -> ExecutionResult:
        query = str(params.get("query") or state.get("user_request") or "")
        if params.get("index_path"):
            try:
                index_path = self._resolve_workspace_path(str(params["index_path"]))
            except ValueError as error:
                return self._failed(
                    ActionType.RETRIEVE_CONTEXT,
                    "sqlite_fts_or_filesystem",
                    str(error),
                )
        else:
            index_path = self.retrieval_path
        if index_path.exists():
            try:
                results = self._sqlite_retrieve(index_path, query, int(params.get("limit", 5)))
            except sqlite3.DatabaseError:
                results = self._filesystem_retrieve(query, int(params.get("limit", 5)))
        else:
            results = self._filesystem_retrieve(query, int(params.get("limit", 5)))
        return ExecutionResult(
            action_type=ActionType.RETRIEVE_CONTEXT,
            status=ExecutionStatus.SUCCEEDED,
            provider="sqlite_fts_or_filesystem",
            summary=f"Retrieved {len(results)} local context items.",
            output={"query": query, "results": results},
        )

    def _read_file(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        try:
            path = self._resolve_workspace_path(
                str(params.get("path") or state.get("file_path") or "")
            )
        except ValueError as error:
            return self._failed(ActionType.READ_FILE, "local_file", str(error))
        limit = max(0, int(params.get("max_bytes", self.output_limit)))
        if not path.exists() or not path.is_file():
            return self._failed(ActionType.READ_FILE, "local_file", f"File not found: {path}")
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        truncated = len(data) > limit
        if truncated:
            data = data[:limit]
        text = data.decode("utf-8", errors="replace")
        return ExecutionResult(
            action_type=ActionType.READ_FILE,
            status=ExecutionStatus.SUCCEEDED,
            provider="local_file",
            summary=f"Read {len(data)} bytes from {path.name}.",
            output={"path": str(path), "text": text, "truncated": truncated},
            metadata={
                "sha256": hashlib.sha256(data).hexdigest(),
                "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            },
        )

    def _inspect_code(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        query = str(
            params.get("query")
            or state.get("code_query")
            or state.get("user_request")
            or ""
        )
        try:
            path = self._resolve_workspace_path(str(params.get("path") or "."))
        except ValueError as error:
            return self._failed(ActionType.INSPECT_CODE, "ripgrep_or_filesystem", str(error))
        limit = int(params.get("limit", 20))
        if shutil.which("rg") is not None and query:
            command = ["rg", "--json", "--max-count", "20", query, str(path)]
            try:
                run = subprocess.run(  # noqa: S603  # nosec B603
                    command,
                    cwd=self.workspace,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                lines = run.stdout.splitlines()[:limit]
            except subprocess.TimeoutExpired:
                return self._timeout(ActionType.INSPECT_CODE, "ripgrep")
        else:
            lines = self._fallback_code_search(path, query, limit)
        return ExecutionResult(
            action_type=ActionType.INSPECT_CODE,
            status=ExecutionStatus.SUCCEEDED,
            provider="ripgrep_or_filesystem",
            summary=f"Inspected code for query: {query}",
            output={"query": query, "matches": lines},
        )

    def _execute_code(
        self,
        params: Mapping[str, Any],
        state: Mapping[str, Any],
        sandbox_plan: SandboxExecutionPlan | None,
    ) -> ExecutionResult:
        command_value = params.get("command") or state.get("command")
        if sandbox_plan is None:
            return self._failed(
                ActionType.EXECUTE_CODE,
                "sandbox",
                "missing Rust-authored sandbox plan for EXECUTE_CODE",
            )
        try:
            run = self._sandbox_executor.run(sandbox_plan)
        except (RuntimeError, OSError, ValueError) as error:
            return ExecutionResult(
                action_type=ActionType.EXECUTE_CODE,
                status=ExecutionStatus.BLOCKED,
                provider="sandbox",
                summary=str(error),
                output=None,
                metadata={"command": command_value},
                sandbox_provenance=sandbox_plan.provenance,
                output_transforms=sandbox_plan.output_transforms,
            )
        return ExecutionResult(
            action_type=ActionType.EXECUTE_CODE,
            status=run.status,
            provider=run.provider,
            summary=run.summary,
            output={"stdout": run.stdout, "stderr": run.stderr, "exit_code": run.exit_code},
            metadata={
                "command": command_value,
                "cwd": sandbox_plan.command.cwd,
                "stdout_sha256": sha256_text(run.stdout),
                "stderr_sha256": sha256_text(run.stderr),
                "normalized_stdout_sha256": sha256_text(run.normalized_stdout),
                "normalized_stderr_sha256": sha256_text(run.normalized_stderr),
            },
            sandbox_provenance=sandbox_plan.provenance,
            sandbox_violations=run.violations,
            normalized_output_hash=sha256_text(run.normalized_stdout),
            output_transforms=sandbox_plan.output_transforms,
        )

    def _call_tool(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        tool_name = str(params.get("tool_name") or "")
        tools = state.get("tools")
        if not isinstance(tools, Mapping) or tool_name not in tools:
            return self._failed(ActionType.CALL_TOOL, "tool_registry", "Tool is not registered.")
        tool = tools[tool_name]
        if not isinstance(tool, Mapping):
            return self._failed(ActionType.CALL_TOOL, "tool_registry", "Tool config is invalid.")
        kind = str(tool.get("kind", ""))
        if kind == "http":
            payload = (
                dict(params.get("payload", {}))
                if isinstance(params.get("payload"), Mapping)
                else {}
            )
            result = self._post_json(str(tool["url"]), payload)
            return ExecutionResult(
                action_type=ActionType.CALL_TOOL,
                status=ExecutionStatus.SUCCEEDED,
                provider=f"http_tool:{tool_name}",
                summary=f"Called HTTP tool {tool_name}.",
                output=result,
                cost={"api_calls": 1},
            )
        if kind == "command":
            command = tool.get("command")
            result = self._execute_code(
                {"command": command, "cwd": tool.get("cwd", ".")},
                state,
                sandbox_plan=None,
            )
            return ExecutionResult(
                action_type=ActionType.CALL_TOOL,
                status=result.status,
                provider=f"command_tool:{tool_name}",
                summary=f"Called command tool {tool_name}: {result.summary}",
                output=result.output,
                cost=result.cost,
                metadata=result.metadata,
            )
        return self._failed(ActionType.CALL_TOOL, "tool_registry", f"Unsupported tool kind: {kind}")

    def _ask_user(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        question = str(
            params.get("question")
            or state.get("question")
            or state.get("user_request")
            or ""
        )
        if not self.interactive:
            return ExecutionResult(
                action_type=ActionType.ASK_USER,
                status=ExecutionStatus.PENDING_CONCIERGE,
                provider="stdin",
                summary="Question requires user response in non-interactive mode.",
                output={"question": question},
            )
        answer = input(question + "\n")
        return ExecutionResult(
            action_type=ActionType.ASK_USER,
            status=ExecutionStatus.SUCCEEDED,
            provider="stdin",
            summary="Received user response.",
            output={"question": question, "answer": answer},
        )

    def _store_memory(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> ExecutionResult:
        content = str(
            params.get("content")
            or state.get("memory_content")
            or state.get("user_request")
            or ""
        )
        decision = MemoryEngine().evaluate_candidate(content, state)
        if not decision.store or decision.memory_object is None:
            return ExecutionResult(
                action_type=ActionType.STORE_MEMORY,
                status=ExecutionStatus.BLOCKED,
                provider="sqlite_memory",
                summary=decision.reason,
                output=decision.to_dict(),
            )
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.memory_path) as conn:
            conn.execute(
                "create table if not exists memories "
                "(id integer primary key, content text, memory_type text, context text, "
                "confidence real, created_at text)"
            )
            conn.execute(
                "insert into memories(content, memory_type, context, confidence, created_at) "
                "values (?, ?, ?, ?, ?)",
                (
                    decision.memory_object.content,
                    decision.memory_object.memory_type,
                    json.dumps(decision.memory_object.context, sort_keys=True),
                    decision.memory_object.confidence,
                    decision.memory_object.created_at,
                ),
            )
        return ExecutionResult(
            action_type=ActionType.STORE_MEMORY,
            status=ExecutionStatus.SUCCEEDED,
            provider="sqlite_memory",
            summary="Stored memory candidate.",
            output=decision.to_dict(),
            metadata={"memory_path": str(self.memory_path)},
        )

    def _escalate_model(
        self, params: Mapping[str, Any], state: Mapping[str, Any]
    ) -> ExecutionResult:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return self._missing_key(ActionType.ESCALATE_MODEL, "openai", "OPENAI_API_KEY")
        prompt = str(params.get("input") or state.get("user_request") or "")
        payload = {
            "model": str(params.get("model", "gpt-4.1-mini")),
            "input": prompt,
            "max_output_tokens": int(params.get("max_output_tokens", 512)),
            "temperature": float(params.get("temperature", 0.0)),
        }
        response = self._post_json(
            "https://api.openai.com/v1/responses",
            payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        cost: dict[str, Any] = {"api_calls": 1}
        metadata: dict[str, Any] = {"input_hash": sha256_text(prompt)}
        price_table = params.get("budget_price_table")
        if isinstance(price_table, Mapping):
            input_rate = price_table.get("input_usd_per_million_tokens")
            output_rate = price_table.get("output_usd_per_million_tokens")
            if input_rate is not None and output_rate is not None:
                realized_usd = openai_responses_realized_cost_usd(
                    response,
                    input_usd_per_million_tokens=float(input_rate),
                    output_usd_per_million_tokens=float(output_rate),
                )
                if realized_usd is None:
                    metadata["budget_realized_cost_status"] = "fail_closed_missing_usage"
                else:
                    cost["money"] = realized_usd
                    metadata["budget_realized_usd"] = realized_usd
                    metadata["budget_realized_cost_status"] = "observed"
        return ExecutionResult(
            action_type=ActionType.ESCALATE_MODEL,
            status=ExecutionStatus.SUCCEEDED,
            provider="openai_responses",
            summary=f"Escalated to OpenAI model {payload['model']}.",
            output=response,
            cost=cost,
            metadata=metadata,
        )

    def _concierge_review(
        self, params: Mapping[str, Any], state: Mapping[str, Any]
    ) -> ExecutionResult:
        reason = str(
            params.get("reason")
            or state.get("interrupt_reason")
            or state.get("user_request")
            or ""
        )
        return ExecutionResult(
            action_type=ActionType.CONCIERGE_REVIEW,
            status=ExecutionStatus.PENDING_CONCIERGE,
            provider="concierge_review",
            summary="Concierge review requested.",
            output={"reason": reason},
        )

    def _selected_candidate(
        self, action_type: ActionType, candidates: tuple[CandidateAction, ...]
    ) -> CandidateAction | None:
        return next(
            (candidate for candidate in candidates if candidate.action_type == action_type),
            None,
        )

    def _post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        if not url.startswith(("https://", "http://")):
            raise RuntimeError(f"unsupported provider URL scheme: {url}")
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                **dict(headers or {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request,
                timeout=self.timeout_seconds,
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as error:
            raise RuntimeError(f"provider request failed: {error}") from error

    def _sqlite_retrieve(self, path: Path, query: str, limit: int) -> list[dict[str, Any]]:
        with sqlite3.connect(path) as conn:
            rows = conn.execute(
                "select path, content from documents where documents match ? limit ?",
                (query, limit),
            ).fetchall()
        return [{"path": row[0], "text": row[1]} for row in rows]

    def _filesystem_retrieve(self, query: str, limit: int) -> list[dict[str, Any]]:
        terms = {item.lower() for item in query.split() if item}
        results: list[dict[str, Any]] = []
        for path in sorted(self.workspace.rglob("*")):
            if len(results) >= limit:
                break
            if not path.is_file() or path.stat().st_size > self.output_limit:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lowered = text.lower()
            score = sum(1 for term in terms if term in lowered)
            if score:
                results.append({"path": str(path), "score": score, "text": text[:1000]})
        return sorted(results, key=lambda item: int(item["score"]), reverse=True)

    def _fallback_code_search(self, path: Path, query: str, limit: int) -> list[str]:
        matches: list[str] = []
        for file_path in sorted(path.rglob("*")) if path.is_dir() else [path]:
            if len(matches) >= limit:
                break
            if not file_path.is_file() or file_path.stat().st_size > self.output_limit:
                continue
            try:
                for line_no, line in enumerate(
                    file_path.read_text(encoding="utf-8", errors="ignore").splitlines(),
                    start=1,
                ):
                    if query.lower() in line.lower():
                        matches.append(f"{file_path}:{line_no}:{line}")
                        break
            except OSError:
                continue
        return matches

    def _resolve_path(self, raw_path: str) -> Path:
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = self.workspace / path
        return path.resolve()

    def _resolve_workspace_path(self, raw_path: str) -> Path:
        path = self._resolve_path(raw_path)
        if not _is_relative_to(path, self.workspace):
            raise ValueError(f"path is outside executor workspace: {path}")
        return path

    def _missing_key(self, action_type: ActionType, provider: str, key: str) -> ExecutionResult:
        return ExecutionResult(
            action_type=action_type,
            status=ExecutionStatus.BLOCKED,
            provider=provider,
            summary=f"Missing required environment variable: {key}.",
        )

    def _failed(self, action_type: ActionType, provider: str, summary: str) -> ExecutionResult:
        return ExecutionResult(
            action_type=action_type,
            status=ExecutionStatus.FAILED,
            provider=provider,
            summary=summary,
        )

    def _timeout(self, action_type: ActionType, provider: str) -> ExecutionResult:
        return ExecutionResult(
            action_type=action_type,
            status=ExecutionStatus.TIMED_OUT,
            provider=provider,
            summary="Execution timed out.",
        )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
