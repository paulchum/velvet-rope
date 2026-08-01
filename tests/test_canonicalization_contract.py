from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from velvet.cli import main
from velvet.serialization import (
    VELVET_CANONICAL_JSON_V1,
    CanonicalizationError,
    canonical_json_v1_hash,
    load_canonical_json_v1,
    proof_artifact_canonical_bytes,
    proof_artifact_hash,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "canonicalization" / "v1"


def _vectors() -> list[dict[str, str]]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["canonicalization"] == VELVET_CANONICAL_JSON_V1
    return cast(list[dict[str, str]], manifest["vectors"])


def test_shared_canonicalization_vectors_are_stable() -> None:
    for vector in _vectors():
        payload = load_canonical_json_v1((FIXTURE_DIR / vector["file"]).read_bytes())
        assert isinstance(payload, dict)

        canonical = proof_artifact_canonical_bytes(vector["type"], payload).decode("utf-8")
        assert canonical == vector["expected_canonical"]
        assert proof_artifact_hash(vector["type"], payload) == vector["sha256"]
        assert proof_artifact_hash(vector["type"], payload) == vector["sha256"]


def test_proof_hash_cli_matches_shared_vectors(capsys: Any) -> None:
    for vector in _vectors():
        assert (
            main(
                [
                    "proof",
                    "hash",
                    "--file",
                    str(FIXTURE_DIR / vector["file"]),
                    "--type",
                    vector["type"],
                ]
            )
            == 0
        )
        assert capsys.readouterr().out.strip() == vector["sha256"]

        assert (
            main(
                [
                    "proof",
                    "hash",
                    "--file",
                    str(FIXTURE_DIR / vector["file"]),
                    "--type",
                    vector["type"],
                    "--json",
                ]
            )
            == 0
        )
        output = json.loads(capsys.readouterr().out)
        assert output == {
            "canonicalization": VELVET_CANONICAL_JSON_V1,
            "hash": vector["sha256"],
            "hash_algorithm": "sha256",
            "type": vector["type"],
        }


def test_unsupported_json_values_fail_loudly() -> None:
    invalid_inputs = (
        b'{"a":1,"a":2}',
        b'{"entry_price":1.5}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b"\xef\xbb\xbf{}",
    )
    for raw in invalid_inputs:
        with pytest.raises(CanonicalizationError):
            load_canonical_json_v1(raw)

    with pytest.raises(CanonicalizationError):
        proof_artifact_hash(
            "policy",
            {
                "canonicalization": VELVET_CANONICAL_JSON_V1,
                "soft_ceiling_fraction": "01.20",
            },
        )
    with pytest.raises(CanonicalizationError):
        proof_artifact_hash(
            "approval",
            {
                "canonicalization": VELVET_CANONICAL_JSON_V1,
                "decided_at": "2026-05-27T19:04:00+00:00",
            },
        )
    with pytest.raises(CanonicalizationError):
        proof_artifact_hash(
            "policy",
            {
                "canonicalization": VELVET_CANONICAL_JSON_V1,
                "limit_usd": 1,
            },
        )
    with pytest.raises(CanonicalizationError):
        canonical_json_v1_hash({"bad_unicode": "\ud800"})
    with pytest.raises(CanonicalizationError):
        canonical_json_v1_hash({"bytes": b"binary"})
