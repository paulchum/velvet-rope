"""Underwriter-facing bundle assembly from verified live-demo artifacts."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from velvet.serialization import JsonObject

UNDERWRITER_BUNDLE_SCHEMA_VERSION = "velvet.underwriter_review_bundle.v1"
DEFAULT_INCIDENT_DIR = Path("reports/live-demo/incident")
DEFAULT_COMMERCIAL_DOCS_DIR = Path("docs/commercial")
DEFAULT_OUTPUT_DIR = Path("reports/underwriter_review/argument_drift_june13")
DEFAULT_ZIP_PATH = Path("reports/underwriter_review/argument_drift_june13.zip")

CLAIM_SOURCE_FILES: tuple[Path, ...] = (
    Path("docs/public/CLAIMS.md"),
    Path("docs/assurance/underwriting_profile.md"),
    Path("demo/BOUNDARIES.md"),
    Path("docs/vault.md"),
    Path("docs/compliance/crosswalk.md"),
)

ROOT_COPY_FILES: tuple[str, ...] = (
    "incident.summary.json",
    "offline_verification_report.json",
    "argument_drift.cast",
    "argument_drift_forensic_bundle.tar.gz",
    "live_demo_oap_public_key.hex",
)

LIMITATIONS: tuple[str, ...] = (
    "Not insurance approval, pricing impact, coverage terms, or carrier endorsement.",
    "Not a legal compliance determination, audit signoff, or substitute for counsel review.",
    "Not a full forensic root-cause analysis outside the supplied incident artifacts.",
    "Not production-key proof; the included live-demo signing material is deterministic "
    "demo material.",
    "Not proof that Velvet was the only dispatch path outside the live-demo trust boundary.",
    "Not proof of resistance to a compromised Velvet host, kernel, hypervisor, or database engine.",
)


class UnderwriterBundleError(RuntimeError):
    """Raised when a verified underwriter bundle cannot be assembled."""


def write_underwriter_review_bundle(
    *,
    incident_dir: str | Path | None = None,
    commercial_docs_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    zip_path: str | Path | None = None,
    force: bool = False,
) -> JsonObject:
    """Assemble a partner-facing underwriter packet and zipped export."""

    repo_root = Path(__file__).resolve().parents[2]
    active_incident_dir = _resolve_user_path(incident_dir or DEFAULT_INCIDENT_DIR)
    active_commercial_docs_dir = _resolve_user_path(
        commercial_docs_dir or DEFAULT_COMMERCIAL_DOCS_DIR
    )
    active_output_dir = _resolve_user_path(output_dir or DEFAULT_OUTPUT_DIR)
    active_zip_path = (
        _resolve_user_path(zip_path)
        if zip_path is not None
        else (
            _resolve_user_path(DEFAULT_ZIP_PATH)
            if output_dir is None
            else active_output_dir.with_suffix(".zip")
        )
    )

    source = _load_and_validate_sources(active_incident_dir)
    commercial_docs = _commercial_docs(active_commercial_docs_dir)
    _prepare_output_dir(active_output_dir, force=force)

    artifacts_dir = active_output_dir / "artifacts"
    _copy_tree(source.claims_pack_dir, artifacts_dir / "claims_pack")
    _copy_tree(source.vault_dir, artifacts_dir / "vault")
    for name in ROOT_COPY_FILES:
        _copy_file(active_incident_dir / name, active_output_dir / name)

    for relative_path in CLAIM_SOURCE_FILES:
        _copy_file(repo_root / relative_path, active_output_dir / "claim_sources" / relative_path)
    for doc_path in commercial_docs:
        _copy_file(doc_path, active_output_dir / "commercial_docs" / doc_path.name)

    summary = _build_summary(
        incident_dir=active_incident_dir,
        commercial_docs_dir=active_commercial_docs_dir,
        output_dir=active_output_dir,
        zip_path=active_zip_path,
        source=source,
        commercial_docs=commercial_docs,
        repo_root=repo_root,
    )
    _write_json(active_output_dir / "verification_summary.json", summary)
    (active_output_dir / "README.md").write_text(
        _render_readme(summary),
        encoding="utf-8",
    )
    (active_output_dir / "CLAIM_BOUNDARIES.md").write_text(
        _render_claim_boundaries(summary),
        encoding="utf-8",
    )

    zip_entries = _write_zip(active_output_dir, active_zip_path)
    payload = dict(summary)
    payload["zip_export"] = {
        "path": str(active_zip_path),
        "sha256": _file_sha256(active_zip_path),
        "entry_count": zip_entries,
    }
    return payload


class _SourceArtifacts:
    def __init__(
        self,
        *,
        incident_summary: JsonObject,
        claims_pack_result: JsonObject,
        offline_verification: JsonObject,
        vault_verification: JsonObject,
        claims_assurance_verification: JsonObject,
        claims_replay_verification: JsonObject,
        claims_vault_verification: JsonObject,
        claims_pack_dir: Path,
        vault_dir: Path,
        source_files: Sequence[Path],
    ) -> None:
        self.incident_summary = incident_summary
        self.claims_pack_result = claims_pack_result
        self.offline_verification = offline_verification
        self.vault_verification = vault_verification
        self.claims_assurance_verification = claims_assurance_verification
        self.claims_replay_verification = claims_replay_verification
        self.claims_vault_verification = claims_vault_verification
        self.claims_pack_dir = claims_pack_dir
        self.vault_dir = vault_dir
        self.source_files = tuple(source_files)


def _load_and_validate_sources(incident_dir: Path) -> _SourceArtifacts:
    if not incident_dir.exists():
        raise UnderwriterBundleError(f"incident directory does not exist: {incident_dir}")

    claims_pack_dir = incident_dir / "claims_pack"
    vault_dir = incident_dir / "vault"
    if not claims_pack_dir.is_dir():
        raise UnderwriterBundleError(f"claims_pack directory does not exist: {claims_pack_dir}")
    if not vault_dir.is_dir():
        raise UnderwriterBundleError(f"vault directory does not exist: {vault_dir}")

    incident_summary_path = incident_dir / "incident.summary.json"
    claims_pack_result_path = incident_dir / "claims_pack.result.json"
    offline_verification_path = incident_dir / "offline_verification_report.json"
    vault_verification_path = vault_dir / "vault_verification_report.json"
    claims_assurance_path = (
        claims_pack_dir / "verification" / "assurance_verification_report.json"
    )
    claims_replay_path = (
        claims_pack_dir / "verification" / "claims_replay_verification_report.json"
    )
    claims_vault_path = claims_pack_dir / "verification" / "vault_verification_report.json"

    for path in (
        incident_summary_path,
        claims_pack_result_path,
        offline_verification_path,
        vault_verification_path,
        claims_assurance_path,
        claims_replay_path,
        claims_vault_path,
    ):
        _require_file(path)
    for name in ROOT_COPY_FILES:
        _require_file(incident_dir / name)

    incident_summary = _read_json_object(incident_summary_path)
    claims_pack_result = _read_json_object(claims_pack_result_path)
    offline_verification = _read_json_object(offline_verification_path)
    vault_verification = _read_json_object(vault_verification_path)
    claims_assurance_verification = _read_json_object(claims_assurance_path)
    claims_replay_verification = _read_json_object(claims_replay_path)
    claims_vault_verification = _read_json_object(claims_vault_path)

    _require_status("incident.summary.status", incident_summary.get("status"), "pass")
    _require_status(
        "incident.summary.vault.verification_status",
        _nested_string(incident_summary, ("vault", "verification_status")),
        "pass",
    )
    _require_status(
        "incident.summary.claims_pack.assurance_verification_status",
        _nested_string(incident_summary, ("claims_pack", "assurance_verification_status")),
        "pass",
    )
    _require_status("vault_verification_report.status", vault_verification.get("status"), "pass")
    _require_status(
        "claims_pack.vault_verification_report.status",
        claims_vault_verification.get("status"),
        "pass",
    )
    _require_status(
        "claims_pack.assurance_verification_report.status",
        claims_assurance_verification.get("status"),
        "pass",
    )
    _require_status(
        "claims_pack.result.assurance_verification.status",
        _nested_string(claims_pack_result, ("assurance_verification", "status")),
        "pass",
    )
    _require_status(
        "offline_verification_report.status",
        offline_verification.get("status"),
        "pass",
    )

    source_files = [
        incident_summary_path,
        claims_pack_result_path,
        offline_verification_path,
        vault_verification_path,
        claims_assurance_path,
        claims_replay_path,
        claims_vault_path,
        incident_dir / "argument_drift.cast",
        incident_dir / "argument_drift_forensic_bundle.tar.gz",
        incident_dir / "live_demo_oap_public_key.hex",
        vault_dir / "argument_drift.vledger",
        vault_dir / "bridge_manifest.json",
        vault_dir / "signed_tree_head.json",
        vault_dir / "vault_public_key.pem",
        claims_pack_dir / "manifest.json",
        claims_pack_dir / "coverage_report.json",
        claims_pack_dir / "assurance" / "attestations.jsonl",
        claims_pack_dir / "assurance" / "consistency_proofs.json",
    ]
    for path in source_files:
        _require_file(path)

    return _SourceArtifacts(
        incident_summary=incident_summary,
        claims_pack_result=claims_pack_result,
        offline_verification=offline_verification,
        vault_verification=vault_verification,
        claims_assurance_verification=claims_assurance_verification,
        claims_replay_verification=claims_replay_verification,
        claims_vault_verification=claims_vault_verification,
        claims_pack_dir=claims_pack_dir,
        vault_dir=vault_dir,
        source_files=source_files,
    )


def _build_summary(
    *,
    incident_dir: Path,
    commercial_docs_dir: Path,
    output_dir: Path,
    zip_path: Path,
    source: _SourceArtifacts,
    commercial_docs: Sequence[Path],
    repo_root: Path,
) -> JsonObject:
    replay_status = _string_status(source.claims_replay_verification.get("status"))
    incident_window = _mapping_or_empty(source.incident_summary.get("incident_window"))
    vault_summary = _mapping_or_empty(source.incident_summary.get("vault"))
    offline_attack = source.offline_verification.get("attack")
    source_hashes = [
        {
            "path": str(path),
            "sha256": _file_sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in source.source_files
    ]
    return {
        "schema_version": UNDERWRITER_BUNDLE_SCHEMA_VERSION,
        "status": "pass",
        "generated_at": _utc_now(),
        "source": {
            "incident_dir": str(incident_dir),
            "commercial_docs_dir": str(commercial_docs_dir),
            "artifact_basis": "reports/live-demo/incident June 13 verified pass",
        },
        "output": {
            "directory": str(output_dir),
            "zip_path": str(zip_path),
        },
        "incident": {
            "name": "June 13 live-demo argument drift incident",
            "attack": offline_attack if isinstance(offline_attack, str) else "argument_drift",
            "window": incident_window,
            "vault_segment": vault_summary.get("segment"),
        },
        "verification_statuses": {
            "incident_summary": _string_status(source.incident_summary.get("status")),
            "vault_summary": _nested_string(
                source.incident_summary,
                ("vault", "verification_status"),
            ),
            "vault_verification": _string_status(source.vault_verification.get("status")),
            "claims_pack_assurance_summary": _nested_string(
                source.incident_summary,
                ("claims_pack", "assurance_verification_status"),
            ),
            "claims_pack_assurance_verification": _string_status(
                source.claims_assurance_verification.get("status")
            ),
            "claims_pack_vault_verification": _string_status(
                source.claims_vault_verification.get("status")
            ),
            "claims_replay_verification": replay_status,
            "offline_incident_verification": _string_status(
                source.offline_verification.get("status")
            ),
            "oap_signature": _string_status(source.offline_verification.get("oap_signature")),
            "database_effect": _string_status(source.offline_verification.get("database_effect")),
        },
        "source_hashes": source_hashes,
        "claim_sources": [
            {
                "source_path": str(repo_root / relative_path),
                "packet_path": str(Path("claim_sources") / relative_path),
                "sha256": _file_sha256(repo_root / relative_path),
            }
            for relative_path in CLAIM_SOURCE_FILES
        ],
        "commercial_docs": [
            {
                "source_path": str(path),
                "packet_path": str(Path("commercial_docs") / path.name),
                "sha256": _file_sha256(path),
            }
            for path in commercial_docs
        ],
        "limitations": list(LIMITATIONS),
    }


def _render_readme(summary: Mapping[str, Any]) -> str:
    statuses = _mapping_or_empty(summary.get("verification_statuses"))
    incident = _mapping_or_empty(summary.get("incident"))
    source = _mapping_or_empty(summary.get("source"))
    output = _mapping_or_empty(summary.get("output"))
    window = _mapping_or_empty(incident.get("window"))
    start = str(window.get("start", "unknown"))
    end = str(window.get("end", "unknown"))
    replay_status = str(statuses.get("claims_replay_verification", "unknown"))
    return "\n".join(
        [
            "# Velvet Underwriter Review Bundle",
            "",
            "This packet is a partner-facing snapshot of the June 13, 2026 local "
            "live-demo argument-drift incident. It is assembled from verified "
            "repo artifacts only, primarily `reports/live-demo/incident`.",
            "",
            "## Read Order",
            "",
            "1. `CLAIM_BOUNDARIES.md`",
            "2. `verification_summary.json`",
            "3. `artifacts/claims_pack/manifest.json`",
            "4. `artifacts/claims_pack/verification/assurance_verification_report.json`",
            "5. `artifacts/vault/vault_verification_report.json`",
            "6. `offline_verification_report.json`",
            "7. `commercial_docs/` for current partner-facing positioning",
            "",
            "## Verification Summary",
            "",
            "| Check | Status |",
            "| --- | --- |",
            f"| Incident summary | `{statuses.get('incident_summary', 'unknown')}` |",
            f"| Vault verification | `{statuses.get('vault_verification', 'unknown')}` |",
            "| Claims Pack Assurance verification | "
            f"`{statuses.get('claims_pack_assurance_verification', 'unknown')}` |",
            "| Claims Pack Vault verification | "
            f"`{statuses.get('claims_pack_vault_verification', 'unknown')}` |",
            f"| Claims Pack replay verification | `{replay_status}` |",
            "| Offline incident verification | "
            f"`{statuses.get('offline_incident_verification', 'unknown')}` |",
            f"| OAP decision signature | `{statuses.get('oap_signature', 'unknown')}` |",
            f"| Database effect | `{statuses.get('database_effect', 'unknown')}` |",
            "",
            "The Claims Pack replay status is preserved exactly as reported by the "
            f"source artifact: `{replay_status}`. This packet does not upgrade that "
            "status or imply replay verification passed.",
            "",
            "## Incident Window",
            "",
            f"- Start: `{start}`",
            f"- End: `{end}`",
            f"- Vault segment: `{incident.get('vault_segment', 'unknown')}`",
            f"- Source artifact basis: `{source.get('artifact_basis', 'unknown')}`",
            "",
            "## Artifact Map",
            "",
            "- `artifacts/claims_pack/`: the verified live-demo Claims Pack.",
            "- `artifacts/vault/`: derived Vault ledger, Signed Tree Head, bridge "
            "manifest, public key, and Vault verification report.",
            "- `argument_drift_forensic_bundle.tar.gz`: original Rust proxy forensic "
            "bundle plus recording and public key copy.",
            "- `offline_verification_report.json`: separate incident verifier output.",
            "- `claim_sources/`: verbatim source documents for claim boundaries.",
            "- `commercial_docs/`: current commercial partner documents.",
            "",
            "## Zip Export",
            "",
            f"The zipped export is written to `{output.get('zip_path', 'unknown')}`.",
            "",
            "## Boundary",
            "",
            "This packet supports underwriter, broker, auditor, and risk-review "
            "discussion. It is not insurance approval, pricing impact, carrier "
            "endorsement, legal compliance, audit signoff, full forensic root-cause "
            "analysis, production-key proof, or proof that Velvet was the only "
            "dispatch path outside the live-demo trust boundary.",
            "",
        ]
    )


def _render_claim_boundaries(summary: Mapping[str, Any]) -> str:
    statuses = _mapping_or_empty(summary.get("verification_statuses"))
    replay_status = str(statuses.get("claims_replay_verification", "unknown"))
    limitations = summary.get("limitations")
    limitations_list = (
        [str(value) for value in limitations] if isinstance(limitations, Sequence) else []
    )
    limitation_lines = [f"- {item}" for item in limitations_list]
    return "\n".join(
        [
            "# Claim Boundaries",
            "",
            "## Claims This Packet Supports",
            "",
            "- The June 13, 2026 local live-demo argument-drift incident refused "
            "execution before the demo target committed a refund row.",
            "- The included Vault segment verification status is `pass`.",
            "- The included Claims Pack Assurance verification status is `pass`.",
            "- The included offline incident verification status is `pass`.",
            "- The included OAP decision signature verification status is `valid`.",
            "- The included Claims Pack replay verification status is "
            f"`{replay_status}` and must be described that way.",
            "",
            "## Explicit Non-Claims",
            "",
            *limitation_lines,
            "",
            "## Provenance Boundary",
            "",
            "The Vault ledger and Signed Tree Head in `artifacts/vault/` are derived "
            "demo evidence artifacts for Vault and Claims Pack verification. They "
            "preserve canonical proxy record payloads and record hashes while using "
            "the demo Ed25519 signer expected by the Vault verifier.",
            "",
            "The original Rust proxy ledger remains in the forensic bundle and is "
            "listed in the bridge manifest. Do not describe the derived Vault export "
            "as replacing the original proxy evidence.",
            "",
            "## Language To Avoid",
            "",
            "- Do not say Velvet determines insurability, coverage, pricing, or claim outcome.",
            "- Do not say the packet is legal compliance, audit signoff, or regulatory "
            "certification.",
            "- Do not say the demo keys are production-safe.",
            "- Do not say the packet proves complete root cause or deployment-wide "
            "control coverage.",
            "- Do not say the Vault evidence is impossible to alter.",
            "",
        ]
    )


def _write_zip(source_dir: Path, zip_path: Path) -> int:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    entries = 0
    root_name = source_dir.name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = Path(root_name) / path.relative_to(source_dir)
            info = zipfile.ZipInfo(str(relative).replace("\\", "/"))
            info.date_time = (2026, 6, 13, 21, 26, 31)
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
            entries += 1
    return entries


def _commercial_docs(path: Path) -> list[Path]:
    if not path.is_dir():
        raise UnderwriterBundleError(f"commercial docs directory does not exist: {path}")
    docs = sorted(path.glob("*.md"))
    if not docs:
        raise UnderwriterBundleError(f"commercial docs directory has no Markdown files: {path}")
    return docs


def _prepare_output_dir(output_dir: Path, *, force: bool) -> None:
    if output_dir.exists():
        marker = output_dir / "verification_summary.json"
        if force or _is_previous_underwriter_bundle(marker):
            shutil.rmtree(output_dir)
        else:
            raise UnderwriterBundleError(
                f"output directory exists and is not a known underwriter bundle: {output_dir}"
            )
    output_dir.mkdir(parents=True, exist_ok=True)


def _is_previous_underwriter_bundle(marker: Path) -> bool:
    if not marker.exists():
        return False
    try:
        payload = _read_json_object(marker)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return payload.get("schema_version") == UNDERWRITER_BUNDLE_SCHEMA_VERSION


def _copy_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def _copy_file(source: Path, destination: Path) -> None:
    _require_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _require_file(path: Path) -> None:
    if not path.is_file():
        raise UnderwriterBundleError(f"required file does not exist: {path}")


def _read_json_object(path: Path) -> JsonObject:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise UnderwriterBundleError(f"expected JSON object at {path}")
    return cast(JsonObject, payload)


def _require_status(field: str, actual: object, expected: str) -> None:
    if actual != expected:
        raise UnderwriterBundleError(f"{field} must be {expected!r}; got {actual!r}")


def _nested_string(payload: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    current: object = payload
    for key in keys:
        if not isinstance(current, Mapping):
            return "missing"
        current = current.get(key)
    return _string_status(current)


def _string_status(value: object) -> str:
    return value if isinstance(value, str) and value else "missing"


def _mapping_or_empty(value: object) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


def _resolve_user_path(value: str | Path) -> Path:
    return Path(value).expanduser()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
