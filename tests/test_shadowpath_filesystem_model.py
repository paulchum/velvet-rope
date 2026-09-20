"""The live Pipelock filesystem substrate feeds the generic resource core."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

from velvet.shadowpath_filesystem_model import (
    PipelockFilesystemModel,
    PipelockResourceTarget,
)
from velvet.shadowpath_observer import AssetState

TOOLS = [
    {
        "name": "edit_file",
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "edits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "oldText": {
                                "type": "string",
                                "description": "Text to search for - must match exactly",
                            },
                            "newText": {"type": "string"},
                        },
                        "required": ["oldText", "newText"],
                    },
                },
            },
            "required": ["path", "edits"],
        },
    }
]


class _Target:
    session_scope = "per_call"

    def __init__(self, root: Path) -> None:
        self.root = root

    def observe(self, _trial_id: str) -> dict[str, AssetState]:
        content = "approved contents\n"
        return {
            "config.txt": AssetState(
                "file",
                0o644,
                hashlib.sha256(content.encode()).hexdigest(),
                size=len(content),
                sample_text=content,
            )
        }

    def resolve(self, _trial_id: str, key: str) -> str:
        return (self.root / key).as_posix()


def test_model_generates_content_aware_actions_and_derived_write_effects(
    tmp_path: Path,
) -> None:
    target = PipelockResourceTarget(cast(Any, _Target(tmp_path)))
    model = PipelockFilesystemModel(TOOLS)
    snapshot = model.observe(target, "trial")

    actions = model.actions(baseline=snapshot, current=snapshot)
    exact_edit = next(
        action
        for action in actions
        if action.arguments["edits"]
        and action.arguments["edits"][0]["oldText"] == "approved contents\n"
        and action.arguments["path"] == "config.txt"
    )
    assert any(effect.effect == "resource.write" for effect in exact_edit.candidate_effects)
    assert any(
        effect.evidence_level == "adapter_declared"
        for effect in exact_edit.candidate_effects
    )

    wire = model.materialize(target, "trial", exact_edit)
    assert wire["arguments"]["path"] == (tmp_path / "config.txt").as_posix()
