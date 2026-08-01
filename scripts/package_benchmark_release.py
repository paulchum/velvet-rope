#!/usr/bin/env python3
"""Compatibility shim for packaging the Agent Authorization Benchmark release."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from package_release_tree import main as package_release_tree_main

DEFAULT_TREE = "build/oss/agent-authorization-benchmark"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    return package_release_tree_main(["--tree", DEFAULT_TREE, *args])


if __name__ == "__main__":
    raise SystemExit(main())
