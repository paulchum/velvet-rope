from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_ROOTS = (
    ROOT / "src" / "velvet",
    ROOT / "crates" / "velvet-rope-proxy" / "src",
    ROOT / "crates" / "velvet-core" / "src" / "canonicalization.rs",
    ROOT / "schemas" / "velvet_rope",
    ROOT / "docs",
    ROOT / "reports" / "launch",
    ROOT / "reports" / "investor_demos",
    ROOT / "tests" / "fixtures" / "canonicalization",
)
TEXT_SUFFIXES = {".html", ".json", ".jsonl", ".md", ".py", ".rs", ".txt", ".yaml", ".yml"}
DENIED_CURRENT_CONTRACT_PATTERNS = (
    re.compile(r"Ledger v2", re.IGNORECASE),
    re.compile(r"ledger v2", re.IGNORECASE),
    re.compile(r"schema v2", re.IGNORECASE),
    re.compile(r"proof v2", re.IGNORECASE),
    re.compile(r"warrant v2", re.IGNORECASE),
    re.compile(r"ledger_record\.v2"),
    re.compile(r"velvet\.ledger\.v2"),
    re.compile(r"ledger_schema_version"),
    re.compile(r"velvet_warrant\.schema\.json"),
    re.compile(r"velvet_warrant\.v1"),
    re.compile(r"Warrant v1"),
    re.compile(r"warrant_version"),
)
PUBLIC_PROXY_ROOTS = (
    ROOT / "README.md",
    ROOT / "docs" / "mcp_proxy",
    ROOT / "docs" / "oap",
    ROOT / "docs" / "deployment",
    ROOT / "docs" / "enterprise" / "velvet-rope-proxy.md",
    ROOT / "docs" / "liability" / "VELVET_ROPE_ARENA.md",
    ROOT / "docs" / "liability" / "VELVET_ROPE_DATASET_CONTRACT.md",
    ROOT / "docs" / "public",
    ROOT / "examples" / "deployment",
)
DENIED_PUBLIC_PROXY_PATTERNS = (
    re.compile(r"OAP-CONFORMANT DECISION \+ VELVET SIGNED BOUND ENVELOPE"),
    re.compile(r"OAP-conformant", re.IGNORECASE),
    re.compile(r"OAP compliant", re.IGNORECASE),
    re.compile(r"OAP certified", re.IGNORECASE),
    re.compile(r"vanilla OAP verifier validates Velvet certificate", re.IGNORECASE),
    re.compile(r"external Velvet Warrant v1", re.IGNORECASE),
    re.compile(r"Velvet Warrant v1", re.IGNORECASE),
    re.compile(r"Ledger v2", re.IGNORECASE),
)


def test_current_proof_contract_has_no_version_noise() -> None:
    offenders: list[str] = []
    for path in _active_text_files():
        text = path.read_text(encoding="utf-8")
        for pattern in DENIED_CURRENT_CONTRACT_PATTERNS:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")

    assert offenders == []


def test_current_schema_files_are_unversioned() -> None:
    schema_dir = ROOT / "schemas" / "velvet_rope"
    assert (schema_dir / "ledger_record.schema.json").is_file()
    assert (schema_dir / "warrant.schema.json").is_file()
    assert (schema_dir / "evidence_pack.schema.json").is_file()
    assert (schema_dir / "execution_permit.schema.json").is_file()
    assert (schema_dir / "execution_receipt.schema.json").is_file()
    assert not (schema_dir / "ledger_record.v2.schema.json").exists()
    assert not (schema_dir / "velvet_warrant.schema.json").exists()
    assert not (schema_dir / "velvet_warrant.v1.schema.json").exists()
    assert not (schema_dir / "execution_permit.v1.schema.json").exists()
    assert not (schema_dir / "execution_receipt.v1.schema.json").exists()


def test_public_proxy_docs_use_oap_decision_and_velvet_envelope_language() -> None:
    offenders: list[str] = []
    for path in _public_proxy_text_files():
        if path.name in {"HARDENING_PLAN.md", "HARDENING_RESULTS.md"}:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in DENIED_PUBLIC_PROXY_PATTERNS:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")

    assert offenders == []


def _active_text_files() -> list[Path]:
    files: list[Path] = []
    for root in ACTIVE_ROOTS:
        if root.is_file():
            files.append(root)
            continue
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in TEXT_SUFFIXES
        )
    return sorted(files)


def _public_proxy_text_files() -> list[Path]:
    files: list[Path] = []
    for root in PUBLIC_PROXY_ROOTS:
        if root.is_file():
            files.append(root)
            continue
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in TEXT_SUFFIXES
        )
    return sorted(files)
