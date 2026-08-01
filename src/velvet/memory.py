"""Rust-backed selective memory evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import velvet._native as _native

from .types import MemoryDecision, MemoryObject


class MemoryEngine:
    """Evaluate whether a memory candidate is worth persisting."""

    def evaluate_candidate(
        self,
        content: str,
        context: Mapping[str, object] | None = None,
    ) -> MemoryDecision:
        raw = cast(Mapping[str, Any], _native.memory_decision(content, dict(context or {})))
        return MemoryDecision.from_dict(raw)

    def write(self, memory_object: MemoryObject) -> MemoryObject:
        return memory_object
