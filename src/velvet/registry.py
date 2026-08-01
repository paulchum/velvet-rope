"""Rust-backed action registry accessors."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import velvet._native as _native

from .types import ActionDefinition, ActionType


def action_registry() -> tuple[ActionDefinition, ...]:
    raw = cast(list[Mapping[str, Any]], _native.registry())
    return tuple(ActionDefinition.from_dict(item) for item in raw)


def get_action_definition(action_type: ActionType) -> ActionDefinition:
    return next(item for item in action_registry() if item.action_type == action_type)
