"""JSONL thread logging backed by Rust redaction primitives."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import velvet._native as _native

from .types import ThreadRecord


class ThreadLogger:
    """Append-only JSONL thread logger."""

    def __init__(self, path: str | Path, redact: bool = True) -> None:
        self.path = Path(path)
        self.redact = redact
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: ThreadRecord) -> None:
        payload: Mapping[str, Any] = record.to_dict()
        if self.redact:
            payload = cast(Mapping[str, Any], _native.redact(payload))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")

    @staticmethod
    def read(path: str | Path) -> Iterator[dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield cast(dict[str, Any], json.loads(stripped))


def redact_secrets(value: Any) -> Any:
    return _native.redact(value)
