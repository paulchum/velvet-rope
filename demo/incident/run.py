from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

from demo.attacks.common import REPORT_ROOT, ROOT, run_named_attack
from demo.incident.vault_bridge import (
    LiveDemoVaultArtifacts,
    export_argument_drift_vault_artifacts,
)

JsonObject = dict[str, Any]


def write_cast(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "version": 2,
                    "width": 100,
                    "height": 30,
                    "timestamp": int(time.time()),
                    "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
                },
                sort_keys=True,
            )
            + "\n"
        )
        offset = 0.0
        for line in lines:
            handle.write(json.dumps([round(offset, 3), "o", line + "\n"]) + "\n")
            offset += 0.35


def build_bundle(incident_dir: Path, attack_report: JsonObject) -> Path:
    run_dir = Path(str(attack_report["artifacts"]["run_dir"]))
    public_key = ROOT / "demo" / "keys" / "live_demo_oap_public_key.hex"
    copied_public_key = incident_dir / "live_demo_oap_public_key.hex"
    shutil.copy2(public_key, copied_public_key)
    cast_path = incident_dir / "argument_drift.cast"
    write_cast(
        cast_path,
        [
            "$ make live-demo",
            "docker compose -f demo/live_target/docker-compose.yml up -d",
            "cargo build -q -p velvet-rope-proxy",
            "uv run python -m demo.attacks.argument_drift",
            "executor dispatch refused: canonical action hash mismatch",
            "database assertion: no refund rows committed",
            "uv run velvet vault verify --segment 1-2 --sth ... --ledger ...",
            "vault verification: pass",
            "uv run velvet claims-pack --incident-window ... --ledger ... --sth ...",
            "claims pack: written",
            "uv run python -m demo.incident.offline_verify --bundle ...",
            "--public-key demo/keys/live_demo_oap_public_key.hex",
            "offline replay: pass; OAP signature: valid",
        ],
    )
    bundle = incident_dir / "argument_drift_forensic_bundle.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        archive.add(run_dir, arcname="argument_drift")
        archive.add(copied_public_key, arcname="public/live_demo_oap_public_key.hex")
        archive.add(cast_path, arcname="recording/argument_drift.cast")
    return bundle


def run_json_command(command: list[str], *, output: Path) -> JsonObject:
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    if completed.returncode != 0:
        failure = {
            "status": "fail",
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        output.write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    payload = json.loads(completed.stdout or "{}")
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object from {' '.join(command)}")
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def verify_vault_cli(uv_bin: str, artifacts: LiveDemoVaultArtifacts) -> JsonObject:
    return run_json_command(
        [
            uv_bin,
            "run",
            "velvet",
            "vault",
            "verify",
            "--segment",
            artifacts.segment_range,
            "--sth",
            str(artifacts.sth_path),
            "--ledger",
            str(artifacts.ledger_path),
            "--public-key-file",
            str(artifacts.public_key_path),
            "--json",
        ],
        output=artifacts.verification_report_path,
    )


def build_claims_pack(
    uv_bin: str,
    artifacts: LiveDemoVaultArtifacts,
    incident_dir: Path,
) -> JsonObject:
    claims_dir = incident_dir / "claims_pack"
    return run_json_command(
        [
            uv_bin,
            "run",
            "velvet",
            "claims-pack",
            "--incident-window",
            artifacts.incident_window_start,
            artifacts.incident_window_end,
            "--ledger",
            str(artifacts.ledger_path),
            "--sth",
            str(artifacts.sth_path),
            "--public-key-file",
            str(artifacts.public_key_path),
            "--output-dir",
            str(claims_dir),
            "--system-name",
            "Velvet live drift-rejection demo",
            "--intended-purpose",
            "Pre-execution action admission for the local live-demo target",
            "--deployer-legal-entity",
            "Velvet Demo Ltd.",
            "--eu-exposure",
            "false",
            "--deployment-id-source",
            "velvet-live-demo/local",
            "--deployment-salt",
            "velvet-live-demo-demo-salt",
            "--signing-profile",
            "demo",
            "--json",
        ],
        output=incident_dir / "claims_pack.result.json",
    )


def main() -> int:
    incident_dir = REPORT_ROOT / "incident"
    if incident_dir.exists():
        shutil.rmtree(incident_dir)
    incident_dir.mkdir(parents=True, exist_ok=True)

    attack_report = run_named_attack("argument_drift")
    policy_hash = attack_report.get("policy_hash")
    vault_artifacts = export_argument_drift_vault_artifacts(
        proxy_ledger_path=str(attack_report["artifacts"]["proxy_ledger"]),
        output_dir=incident_dir / "vault",
        policy_hash=policy_hash if isinstance(policy_hash, str) else None,
    )
    bundle = build_bundle(incident_dir, attack_report)
    verification_output = incident_dir / "offline_verification_report.json"
    uv_bin = shutil.which("uv") or "uv"
    vault_report = verify_vault_cli(uv_bin, vault_artifacts)
    claims_pack = build_claims_pack(uv_bin, vault_artifacts, incident_dir)
    subprocess.run(  # noqa: S603
        [
            uv_bin,
            "run",
            "python",
            "-m",
            "demo.incident.offline_verify",
            "--bundle",
            str(bundle),
            "--public-key",
            str(incident_dir / "live_demo_oap_public_key.hex"),
            "--output",
            str(verification_output),
        ],
        cwd=ROOT,
        check=True,
    )
    summary = {
        "status": "pass",
        "primary_artifact": str(incident_dir / "claims_pack"),
        "claims_pack": {
            "output_dir": str(incident_dir / "claims_pack"),
            "result": str(incident_dir / "claims_pack.result.json"),
            "assurance_verification_status": claims_pack["assurance_verification"]["status"],
        },
        "incident_window": {
            "start": vault_artifacts.incident_window_start,
            "end": vault_artifacts.incident_window_end,
        },
        "vault": {
            "ledger": str(vault_artifacts.ledger_path),
            "sth": str(vault_artifacts.sth_path),
            "public_key": str(vault_artifacts.public_key_path),
            "bridge_manifest": str(vault_artifacts.manifest_path),
            "verification": str(vault_artifacts.verification_report_path),
            "verification_status": vault_report["status"],
            "segment": vault_artifacts.segment_range,
        },
        "bundle": str(bundle),
        "recording": str(incident_dir / "argument_drift.cast"),
        "offline_verification": str(verification_output),
    }
    (incident_dir / "incident.summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
