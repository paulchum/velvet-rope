"""Reference OpenAI Agents SDK adapter for the ShadowPath JSONL protocol."""

from __future__ import annotations

import importlib
import json
import os
import sys
from typing import Any, TextIO

from velvet.shadowpath import SHADOWPATH_AGENT_PROTOCOL_VERSION

JsonObject = dict[str, Any]


class ProtocolClient:
    def __init__(self, start: JsonObject, stdin: TextIO, stdout: TextIO) -> None:
        self.start = start
        self.stdin = stdin
        self.stdout = stdout
        self.sequence = int(start["sequence"])
        self.call_count = 0

    def call_route(self, route_id: str) -> str:
        self.call_count += 1
        self.sequence += 1
        call_id = f"call-{self.call_count:04d}"
        event = {
            "schema_version": SHADOWPATH_AGENT_PROTOCOL_VERSION,
            "event": "tool_call",
            "run_id": self.start["run_id"],
            "trial_id": self.start["trial_id"],
            "sequence": self.sequence,
            "call_id": call_id,
            "route_id": route_id,
        }
        _write_event(self.stdout, event)
        result = _read_event(self.stdin)
        if result.get("event") != "tool_result":
            raise RuntimeError("expected tool_result from ShadowPath harness")
        if result.get("call_id") != call_id or result.get("route_id") != route_id:
            raise RuntimeError("tool_result correlation mismatch")
        self.sequence = int(result["sequence"])
        return json.dumps(result["result"], sort_keys=True)

    def finish(
        self,
        *,
        status: str,
        final_output: str = "",
        reason: str | None = None,
    ) -> None:
        self.sequence += 1
        event: JsonObject = {
            "schema_version": SHADOWPATH_AGENT_PROTOCOL_VERSION,
            "event": "finish",
            "run_id": self.start["run_id"],
            "trial_id": self.start["trial_id"],
            "sequence": self.sequence,
            "status": status,
            "final_output": final_output,
        }
        if reason is not None:
            event["reason"] = reason
        _write_event(self.stdout, event)


def main() -> int:
    start = _read_event(sys.stdin)
    if start.get("schema_version") != SHADOWPATH_AGENT_PROTOCOL_VERSION:
        print("ShadowPath protocol version mismatch", file=sys.stderr)
        return 2
    client = ProtocolClient(start, sys.stdin, sys.stdout)
    if not os.environ.get("OPENAI_API_KEY"):
        client.finish(status="not_run", reason="not run: missing OPENAI_API_KEY")
        return 0
    try:
        agents = importlib.import_module("agents")
    except ImportError:
        client.finish(
            status="not_run",
            reason="not run: missing optional package import 'agents'",
        )
        return 0

    allowed_routes = tuple(str(route) for route in start["available_routes"])

    def use_shadowpath_route(route_id: str) -> str:
        """Use one available synthetic ShadowPath route by its exact route_id."""

        if route_id not in allowed_routes:
            return f"route_id must be one of: {', '.join(allowed_routes)}"
        return client.call_route(route_id)

    model = os.environ.get("SHADOWPATH_OPENAI_MODEL", "gpt-5.5")
    route_tool = agents.function_tool(use_shadowpath_route)
    agent = agents.Agent(
        name="ShadowPath reference agent",
        model=model,
        instructions=(
            f"{start['policy']}\n\n"
            "Follow the policy. You may refuse the task. Available synthetic route IDs: "
            + ", ".join(allowed_routes)
        ),
        tools=[route_tool],
    )
    try:
        result = agents.Runner.run_sync(agent, str(start["task"]))
    except Exception as error:  # noqa: BLE001 - provider error is returned to harness.
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return 4
    client.finish(status="completed", final_output=str(result.final_output))
    return 0


def _read_event(stream: TextIO) -> JsonObject:
    line = stream.readline()
    if not line:
        raise RuntimeError("unexpected end of ShadowPath protocol stream")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise RuntimeError("ShadowPath protocol event must be an object")
    return value


def _write_event(stream: TextIO, event: JsonObject) -> None:
    stream.write(
        json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
