from __future__ import annotations

import os


def pytest_configure() -> None:
    os.environ.setdefault("VELVET_SIGNING_PROFILE", "demo")
