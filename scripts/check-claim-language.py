"""Fail when scoped MCP gateway docs or code assert banned maturity claims."""

from __future__ import annotations

import argparse
import glob
import shutil
import subprocess
import sys
from pathlib import Path


def _terms() -> list[str]:
    return [
        "production" + "-ready",
        "production" + " grade",
        "enterprise" + "-ready",
        "enterprise" + " grade",
        "complete MCP" + " enforcement",
        "full MCP" + " coverage",
        "multi" + "-tenant",
        "hardened for" + " production",
    ]


def _public_doc_terms() -> list[str]:
    return [
        "OAP-conformant",
        "OAP compliant",
        "OAP certified",
        "vanilla OAP verifier validates Velvet certificate",
        "Velvet is OAP",
        "Velvet replaces OAP",
        "OAP failed",
        "OAP unsafe",
        "only Velvet can do pre-action authorization",
        "external Velvet Warrant v1",
        "Ledger v2",
        "OAP-CONFORMANT DECISION + VELVET SIGNED BOUND ENVELOPE",
    ]


def _claim_guard_terms() -> list[str]:
    return [
        "tamper" + "-proof",
        "ledger proves" + " safety",
        "ledger proves" + " correctness",
        "immutable proof" + " of compliance",
    ]


def _wbc_mcc_allowed_terms() -> list[str]:
    return [
        "provable mediation",
        "warrant-bound credential",
        "mediation coverage certificate",
    ]


def _wbc_mcc_verdict_terms() -> list[str]:
    return [
        "LINEAGE_VERIFIED",
        "LINEAGE_INVALID",
        "DARK_ACTION",
        "UNMATCHED_SESSION",
        "REPLAY_SUSPECT",
        "MINT_RECEIPT_MISSING",
        "LOG_INTEGRITY_INSUFFICIENT",
        "OUT_OF_SCOPE",
        "INDETERMINATE",
        "MATCHED",
        "UNMATCHED",
        "SERVICE_ACTOR",
        "MINTED_UNUSED",
    ]


def _wbc_mcc_deny_terms() -> list[str]:
    return [
        "bypass " + "solved",
        "seconds" + "-long credential",
        "seconds" + "-long credentials",
        "blended " + "coverage",
        "proof" + "-carrying credential",
        "proof" + "-carrying credentials",
    ]


def _wbc_mcc_legacy_terms() -> list[str]:
    return [
        "proof" + "-carrying",
        "P" + "CC",
    ]


def _wbc_mcc_historical_markers() -> list[str]:
    return [
        "historical",
        "deprecated",
        "prior art",
        "retired",
        "intellectual ancestry",
    ]


def _verdict_deny_terms() -> list[str]:
    # Claim-currency discipline for Certified Decisions (see
    # src/velvet/verdict/UPSTREAM.md): a [BP] safe_kill is a statement about
    # the modeled kernel at level delta, never a truth claim about the retired
    # arm, and BP/FM quantities are never blended. Terms are concatenated so
    # this file never trips itself.
    return [
        "truly " + "better",
        "actually " + "better",
        "proven " + "better",
        "proven " + "superior",
        "certificate " + "proves",
        "guaranteed " + "winner",
        "guaranteed " + "rescue",
        "guaranteed " + "lift",
        "guaranteed " + "profit",
        "money left on" + " the table",
        "killed variants that" + " were better",
        "zero false" + " lockouts",
        "blended refusal" + " fraction",
        "average of BP" + " and FM",
    ]


def _verdict_negation_markers() -> list[str]:
    # Windows that discuss the boundary (negations, forbidden-claim lists)
    # are allowed; bare assertions are not.
    return [
        "not ",
        "never",
        "does not mean",
        "must not",
        "forbidden",
        "rather than",
        "instead of",
    ]


def _scoped_no_bypass_terms() -> list[str]:
    return [
        "GPT-5.5 cannot bypass" + " Velvet",
        "models cannot bypass" + " Velvet",
        "Velvet stops" + " jailbreaks",
        "Velvet prevents prompt" + " injection",
    ]


def _attestation_surface_terms() -> list[str]:
    return [
        "com" + "pliant",
        "cert" + "ified",
        "tamper" + "-proof",
    ]


def _attestation_surface_path(path: Path) -> bool:
    parts = path.parts
    return (
        parts[:3] == ("src", "velvet", "attestation")
        or parts[:3] == ("src", "velvet", "assurance")
        or parts[:2] == ("docs", "assurance")
        or parts[:2] == ("docs", "compliance")
        or parts == ("scripts", "reconstructability_test.py")
    )


def _no_bypass_scope_markers() -> list[str]:
    return [
        "covered tool calls",
        "exclusive dispatch boundary",
        "in this deployment architecture",
        "in this architecture",
        "only dispatch path",
    ]


def _allowed_claim_context(text: str, index: int) -> bool:
    title = _section_title_before(text, index)
    allowed_titles = {
        "non-goal",
        "non-goals",
        "non goal",
        "non goals",
        "counterexample",
        "counterexamples",
        "claim boundary",
        "honest claim boundary",
        "limits",
        "limitations",
        "out of scope",
        "forbidden claims",
        "red claims",
        "disallowed language",
        "rewrite patterns",
    }
    return title in allowed_titles


def _section_title_before(text: str, index: int) -> str:
    lines = text[:index].splitlines()
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip().lower()
        if len(stripped) <= 100 and stripped.endswith((".", ":")):
            normalized = stripped[:-1].strip().lower()
            if normalized in {
                "non-goal",
                "non-goals",
                "non goal",
                "non goals",
                "counterexample",
                "counterexamples",
                "claim boundary",
                "honest claim boundary",
                "limits",
                "limitations",
                "out of scope",
                "forbidden claims",
                "red claims",
                "disallowed language",
                "rewrite patterns",
            }:
                return normalized
    return ""


def _public_doc_path(path: Path) -> bool:
    public_roots = {
        ("README.md",),
        ("docs", "mcp_proxy"),
        ("docs", "oap"),
        ("docs", "deployment"),
        ("docs", "enterprise", "velvet-rope-proxy.md"),
        ("docs", "oss", "launch"),
        ("docs", "liability", "VELVET_ROPE_ARENA.md"),
        ("docs", "liability", "VELVET_ROPE_DATASET_CONTRACT.md"),
        ("docs", "paper", "main.tex"),
        ("docs", "policy-compiler.md"),
        ("docs", "public"),
        ("benchmarks", "agent_authorization"),
        ("docs", "investors"),
        ("examples", "deployment"),
    }
    parts = path.parts
    if path.name in {"HARDENING_PLAN.md", "HARDENING_RESULTS.md"}:
        return False
    return any(parts[: len(root)] == root for root in public_roots)


def _tracked_files() -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable not found")
    completed = subprocess.run(  # noqa: S603 - fixed git command vector.
        [git, "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[Path] = []
    for line in completed.stdout.splitlines():
        path = Path(line)
        if path.parts and path.parts[0] in {".git", ".venv", "archive", "target", "third_party"}:
            continue
        if path.suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".pdf",
            ".pptx",
            ".xlsx",
            ".lock",
        }:
            continue
        paths.append(path)
    return paths


def _extra_files(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        if not matches:
            matches = [pattern]
        for match in matches:
            path = Path(match)
            if path.is_dir():
                paths.extend(child for child in path.rglob("*") if child.is_file())
            elif path.exists():
                paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extra-paths",
        nargs="*",
        default=[],
        help="Additional files, directories, or globs to scan with the same banned terms.",
    )
    args = parser.parse_args()

    violations: list[str] = []
    terms = _terms()
    paths = list(dict.fromkeys([*_tracked_files(), *_extra_files(args.extra_paths)]))
    for path in paths:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lower = text.lower()
        scoped_terms = list(terms)
        if _public_doc_path(path):
            scoped_terms.extend(_public_doc_terms())
        for term in scoped_terms:
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=False,
            )
        for term in _claim_guard_terms():
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=True,
            )
        for term in _wbc_mcc_deny_terms():
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=False,
            )
        for term in _wbc_mcc_legacy_terms():
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=False,
                allowed_window_markers=_wbc_mcc_historical_markers(),
                whole_word=term.lower() == "pcc",
            )
        for term in _verdict_deny_terms():
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=True,
                allowed_window_markers=_verdict_negation_markers(),
            )
        for term in _scoped_no_bypass_terms():
            _record_term_violations(
                violations,
                path=path,
                text=text,
                lower=lower,
                term=term,
                allow_claim_context=True,
                required_scope_markers=_no_bypass_scope_markers(),
            )
        if _attestation_surface_path(path):
            for term in _attestation_surface_terms():
                _record_term_violations(
                    violations,
                    path=path,
                    text=text,
                    lower=lower,
                    term=term,
                    allow_claim_context=False,
                )
    if violations:
        print("Claim language check failed:", file=sys.stderr)
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1
    print("Claim language check passed.")
    return 0


def _record_term_violations(
    violations: list[str],
    *,
    path: Path,
    text: str,
    lower: str,
    term: str,
    allow_claim_context: bool,
    required_scope_markers: list[str] | None = None,
    allowed_window_markers: list[str] | None = None,
    whole_word: bool = False,
) -> None:
    start = 0
    needle = term.lower()
    while True:
        index = lower.find(needle, start)
        if index == -1:
            break
        if whole_word and not _is_whole_word_match(lower, index, len(needle)):
            start = index + len(needle)
            continue
        allowed_by_claim_context = allow_claim_context and _allowed_claim_context(text, index)
        allowed_by_scope = False
        if required_scope_markers is not None:
            window = lower[max(0, index - 220) : index + len(needle) + 220]
            allowed_by_scope = any(marker in window for marker in required_scope_markers)
        allowed_by_window = False
        if allowed_window_markers is not None:
            window = lower[max(0, index - 260) : index + len(needle) + 260]
            allowed_by_window = any(marker in window for marker in allowed_window_markers)
        if not (allowed_by_claim_context or allowed_by_scope or allowed_by_window):
            line_no = text.count("\n", 0, index) + 1
            violations.append(f"{path}:{line_no}: {term}")
        start = index + len(needle)


def _is_whole_word_match(text: str, index: int, length: int) -> bool:
    before = text[index - 1] if index > 0 else ""
    after_index = index + length
    after = text[after_index] if after_index < len(text) else ""
    return not _is_word_char(before) and not _is_word_char(after)


def _is_word_char(char: str) -> bool:
    return bool(char) and (char.isalnum() or char == "_")


if __name__ == "__main__":
    raise SystemExit(main())
