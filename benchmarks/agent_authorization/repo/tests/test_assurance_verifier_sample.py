from __future__ import annotations

import subprocess
import sys


def test_assurance_verifier_sample() -> None:
    public_key = "tests/fixtures/keys/velvet_demo_ed25519.pub"
    pass_run = subprocess.run(  # noqa: S603 - fixed local verifier command
        [
            sys.executable,
            "verifier/verify_attestations.py",
            "verifier/sample_bundle",
            "--public-key-file",
            public_key,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert pass_run.returncode == 0, pass_run.stderr or pass_run.stdout
    assert '"status": "pass"' in pass_run.stdout

    fail_run = subprocess.run(  # noqa: S603 - fixed local verifier command
        [
            sys.executable,
            "verifier/verify_attestations.py",
            "verifier/sample_bundle/tampered",
            "--public-key-file",
            public_key,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert fail_run.returncode != 0
    assert '"status": "fail"' in fail_run.stdout
