from collections.abc import Mapping, Sequence
from typing import Any

class NativeRouter:
    def __init__(
        self,
        policy_dir: str = "policies",
        chain: str = "default",
        watch: bool = False,
    ) -> None: ...
    def route_decision(
        self,
        state: Mapping[str, Any],
        candidates: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]: ...
    def route_thread(
        self,
        state: Mapping[str, Any],
        candidates: Sequence[Mapping[str, Any]],
        thread_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]: ...

def route_decision(
    state: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]: ...

def route_thread(
    state: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    thread_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]: ...

def memory_decision(
    content: str,
    context: Mapping[str, Any],
    timestamp: str | None = None,
) -> dict[str, Any]: ...

def redact(value: Any) -> Any: ...
def registry() -> list[dict[str, Any]]: ...
def normalize_action(
    proposal: Mapping[str, Any],
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]: ...
