"""Run: python -m velvet.refunds --help."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from velvet.refunds.demo import run_demo
from velvet.refunds.evidence import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Protected refund reference ledger")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Use an explicitly configured disposable PostgreSQL DB")
    demo.add_argument("--output-dir", type=Path, default=Path("reports/protected-refunds"))
    verify = commands.add_parser(
        "verify", help="Verify a closed snapshot with independently pinned trust"
    )
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--observer-key", type=Path, required=True)
    verify.add_argument("--observer-key-id", required=True)
    verify.add_argument("--contract-hash", required=True)
    args = parser.parse_args(argv)
    if args.command == "demo":
        dsn = os.environ.get("VELVET_REFUNDS_DEMO_DSN")
        if not dsn:
            parser.error("set VELVET_REFUNDS_DEMO_DSN to a disposable PostgreSQL database")
        result = run_demo(dsn, args.output_dir)
        code = 0
    else:
        try:
            result = verify_bundle(
                json.loads(args.bundle.read_text()),
                observer_public_key=args.observer_key.read_text(),
                observer_key_id=args.observer_key_id,
                contract_hash=args.contract_hash,
            )
        except (OSError, ValueError) as error:
            result = {"status": "INVALID", "error": str(error)}
        code = 0 if result["status"] == "COMPLETE" else 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
