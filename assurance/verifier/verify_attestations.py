#!/usr/bin/env python3
"""Reference cold-directory ingestion script for Velvet assurance bundles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from velvet_assurance_verifier import (
    load_anchor_sths,
    load_attestations_jsonl,
    load_consistency_proofs,
    verify_attestation_series,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Velvet assurance bundle directory.")
    parser.add_argument("bundle_dir")
    parser.add_argument("--public-key-file", required=True)
    parser.add_argument("--output")
    parser.add_argument("--anchor-sths")
    args = parser.parse_args()

    bundle = Path(args.bundle_dir)
    report = verify_attestation_series(
        load_attestations_jsonl(bundle / "attestations.jsonl"),
        public_key=Path(args.public_key_file).read_text(encoding="utf-8"),
        consistency_proofs=load_consistency_proofs(bundle / "consistency_proofs.json"),
        anchored_sths=load_anchor_sths(args.anchor_sths),
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
