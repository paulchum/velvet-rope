#!/usr/bin/env python3
"""Fail on TruffleHog findings outside exact documented public fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# Each fingerprint binds detector + repository-relative path + raw matched value.
# The GitHub matches are public commit identifiers; the PrivateKey match is the
# deterministic mTLS fixture documented in SECURITY.md. Never add broad detector
# or directory exclusions here.
ALLOWED_FINDINGS = frozenset(
    {
        (
            "Github",
            ".github/workflows/release.yml",
            "ea2ad4f6ef7e968f215b7e976a7e875643d6b6c7499a28758b86a11655b5c62c",
        ),
        (
            "Github",
            ".github/workflows/release.yml",
            "87717b83a220035974682b2f5ed56e8dcfdee18c8bc64040fd5620d8ee9d5890",
        ),
        (
            "Github",
            "benchmarks/agent_authorization/comparison/evidence/"
            "oap_aport_pinned_schema_fixture_evidence.json",
            "5caa5f45533a54af4556823233b58606b5effea00d96e508f80b7201c96fd01a",
        ),
        (
            "Github",
            "docs/oap/SPEC_CONSISTENCY.md",
            "7f3925c8ebeff34e5b7921feefbc5a9b9826add39236a63aa37e072ee6447784",
        ),
        (
            "Github",
            "third_party/oap/OAP_SPEC_LOCK.json",
            "ac78573c9ca7e42161081d6e4328f19563ec6e2d0f30a89ccbb3e7bda0c7c84b",
        ),
        (
            "PrivateKey",
            "crates/velvet-rope-proxy/src/tests/support.rs",
            "52e499b83d7bb4e1c6aa457981f40dc41591189632b8ed7e5747ea96baf25588",
        ),
    }
)


def _filesystem_metadata(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    source = finding.get("SourceMetadata")
    data = source.get("Data") if isinstance(source, Mapping) else None
    filesystem = data.get("Filesystem") if isinstance(data, Mapping) else None
    return filesystem if isinstance(filesystem, Mapping) else {}


def _relative_source_path(value: object, source_root: Path) -> str:
    if not isinstance(value, str) or not value:
        return "<unknown>"
    candidate = Path(value)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (Path.cwd() / candidate).resolve()
    )
    try:
        return resolved.relative_to(source_root.resolve()).as_posix()
    except ValueError:
        return candidate.as_posix()


def _raw_value(finding: Mapping[str, Any]) -> str:
    raw = finding.get("Raw")
    if isinstance(raw, str):
        return raw
    return json.dumps(raw, sort_keys=True, separators=(",", ":"))


def finding_key(finding: Mapping[str, Any], source_root: Path) -> tuple[str, str, str]:
    detector = str(finding.get("DetectorName") or "<unknown>")
    metadata = _filesystem_metadata(finding)
    path = _relative_source_path(metadata.get("file"), source_root)
    material = f"{detector}\0{path}\0{_raw_value(finding)}".encode()
    return detector, path, hashlib.sha256(material).hexdigest()


def check_report(report_path: Path, source_root: Path) -> list[tuple[str, str, int, bool]]:
    unexpected: list[tuple[str, str, int, bool]] = []
    for line_number, line in enumerate(report_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid TruffleHog JSON on report line {line_number}") from error
        if not isinstance(finding, Mapping):
            raise ValueError(f"invalid TruffleHog object on report line {line_number}")
        detector, path, fingerprint = finding_key(finding, source_root)
        if (detector, path, fingerprint) in ALLOWED_FINDINGS:
            continue
        metadata = _filesystem_metadata(finding)
        source_line = metadata.get("line")
        unexpected.append(
            (
                detector,
                path,
                source_line if isinstance(source_line, int) else 0,
                bool(finding.get("Verified")),
            )
        )
    return sorted(set(unexpected))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        unexpected = check_report(args.report, args.source_root)
    except (OSError, ValueError) as error:
        print(f"trufflehog-policy: ERROR: {error}")
        return 2
    if unexpected:
        print("trufflehog-policy: unexpected findings (secret values withheld):")
        for detector, path, line, verified in unexpected:
            print(f"- {detector} {path}:{line} verified={str(verified).lower()}")
        return 1
    print("trufflehog-policy: OK (only exact documented fixture fingerprints found)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
