from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent


def _fixtures() -> list[dict[str, object]]:
    fixtures: list[dict[str, object]] = []
    for path in sorted((ROOT / "sandbox_adversarial").glob("*.json")):
        fixtures.extend(json.loads(path.read_text(encoding="utf-8")))
    return fixtures


def test_adversarial_fixture_catalog_has_required_cases() -> None:
    fixtures = {str(item["id"]): item for item in _fixtures()}
    assert {
        "write_etc",
        "write_proc_sys",
        "docker_socket",
        "fork_bomb",
        "memory_exhaustion",
        "cpu_exhaustion",
        "filesystem_exfiltration",
        "dns_exfiltration",
        "tcp_exfiltration",
        "wall_clock",
        "stdout_flood",
    } <= fixtures.keys()
    for fixture in fixtures.values():
        assert fixture["command"]
        assert fixture["expected_violation"]
        assert fixture["bounded_ms"]


@pytest.mark.skipif(
    os.environ.get("VELVET_SANDBOX_LIVE_TESTS") != "1",
    reason="live adversarial sandbox execution requires VELVET_SANDBOX_LIVE_TESTS=1",
)
def test_live_adversarial_suite_is_opt_in_until_ci_has_backend_runners() -> None:
    assert _fixtures()
