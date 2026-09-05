"""Disposable local reference workload; no payment rails or model calls."""

from __future__ import annotations

import hashlib
import json
import platform
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from velvet.refunds.contract import VERSION, RefundCommand, RefundRejected, issue_permit
from velvet.refunds.evidence import seal_snapshot, verify_bundle
from velvet.refunds.postgres import RefundLedger
from velvet.serialization import JsonObject, canonical_hash_sha256
from velvet.signing import Ed25519SigningProvider


@dataclass
class ReferenceLedger:
    config: JsonObject
    executor: RefundLedger
    observer: RefundLedger
    authority: Ed25519SigningProvider
    observer_signer: Ed25519SigningProvider
    agent_dsn: str


@contextmanager
def reference_ledger(admin_dsn: str, *, budget: int = 10000) -> Iterator[ReferenceLedger]:
    """Create and remove only a unique schema and three new roles in a disposable DB."""
    schema = "vr_" + uuid4().hex
    roles = [schema + suffix for suffix in ("_executor", "_observer", "_agent")]
    credentials = [uuid4().hex for _ in roles]
    authority = Ed25519SigningProvider(key_id="reference-authority")
    observer_signer = Ed25519SigningProvider(key_id="reference-observer")
    material = authority.public_verification_material(authority.key_id) or {}
    config = {
        "version": VERSION,
        "ledger_id": schema,
        "tenant_id": "reference",
        "environment": "local-reference",
        "audience": "protected-refunds",
        "authority_key_id": authority.key_id,
        "authority_public_key": material["public_key_pem"],
        "currency": "USD",
        "budget_cents": budget,
        "orders": {f"order-{index}": 10000 for index in range(1, 6)},
    }
    created: list[str] = []
    installed = False
    try:
        with psycopg.connect(admin_dsn, autocommit=True) as owner:
            for role, password in zip(roles, credentials, strict=True):
                owner.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
                created.append(role)
        RefundLedger(admin_dsn, schema).install(
            config, executor_role=roles[0], observer_role=roles[1]
        )
        installed = True
        dsns = [
            make_conninfo(admin_dsn, user=role, password=password)
            for role, password in zip(roles, credentials, strict=True)
        ]
        yield ReferenceLedger(
            config,
            RefundLedger(dsns[0], schema),
            RefundLedger(dsns[1], schema),
            authority,
            observer_signer,
            dsns[2],
        )
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as owner:
            if installed:
                owner.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
            for role in reversed(created):
                owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def run_demo(admin_dsn: str, output_dir: Path) -> JsonObject:
    """Generate evidence from useful refunds, contention, a retry and terminal closure."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with reference_ledger(admin_dsn) as reference:
        config = reference.config
        ledger = reference.executor
        timings: list[float] = []
        attempts: list[JsonObject] = []

        def call(index: int, amount: int) -> JsonObject:
            command = RefundCommand(
                f"refund-{index}", config["ledger_id"], f"order-{index}", amount, 0, 0
            )
            permit = issue_permit(config, command, reference.authority)
            started = perf_counter()
            try:
                result = ledger.refund(command, permit)
            except RefundRejected as error:
                result = {"status": "rejected", "reason": str(error)}
            return {
                "operation_id": command.operation_id,
                "amount_cents": amount,
                "elapsed_ms": round((perf_counter() - started) * 1000, 3),
                **result,
            }

        command = RefundCommand("refund-1", config["ledger_id"], "order-1", 1000, 0, 0)
        permit = issue_permit(config, command, reference.authority)
        started = perf_counter()
        first = ledger.refund(command, permit)
        timings.append((perf_counter() - started) * 1000)
        attempts.append({"amount_cents": 1000, **first})
        attempts.append({"amount_cents": 1000, **ledger.refund(command, permit)})
        with ThreadPoolExecutor(max_workers=2) as pool:
            for indices, amount in (((2, 3), 4000), ((4, 5), 1000)):
                results = list(pool.map(lambda i, value=amount: call(i, value), indices))
                attempts.extend(results)
                timings.extend(result["elapsed_ms"] for result in results)
        late = RefundCommand("after-close", config["ledger_id"], "order-1", 1, 1, 0)
        late_permit = issue_permit(config, late, reference.authority)
        ledger.close()
        try:
            ledger.refund(late, late_permit)
        except RefundRejected as error:
            attempts.append(
                {"operation_id": late.operation_id, "status": "rejected", "reason": str(error)}
            )
        snapshot = reference.observer.observe()
        bundle = seal_snapshot(snapshot, reference.observer_signer, key_id="reference-observer")
        public_key = (
            reference.observer_signer.public_verification_material("reference-observer") or {}
        )["public_key_pem"]
        contract_hash = canonical_hash_sha256(config)
        result = verify_bundle(
            bundle,
            observer_public_key=public_key,
            observer_key_id="reference-observer",
            contract_hash=contract_hash,
        )
        if result["status"] != "COMPLETE" or result["committed_refunds"] != 4:
            raise RuntimeError("reference workload did not satisfy its declared result")
        sources = {
            path.name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(__file__).parent.glob("*.py"))
        }
        # Timing metadata and source provenance are workload metadata, not observer attestations.
        report = {
            "verification": result,
            "attempts": attempts,
            "provenance": {
                "python": platform.python_version(),
                "platform": platform.system() + " " + platform.machine(),
                "postgres": snapshot["observation"]["postgres"],
                "source_hashes": sources,
            },
            "timing": {
                "sample_count": len(timings),
                "min_ms": round(min(timings), 3),
                "max_ms": round(max(timings), 3),
                "mean_ms": round(sum(timings) / len(timings), 3),
                "scope": "5 local calls incl. one budget rejection; connection + "
                "lock + authorization + transaction; not a benchmark",
            },
            "observed_at": snapshot["observation"]["observed_at"],
            "claim_boundary": "Closed reference ledger only. Trusted database, executor, "
            "authority and observer. No payment provider or vendor comparison.",
        }
        for name, value in (("evidence.json", bundle), ("report.json", report)):
            (output_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        (output_dir / "observer-public-key.pem").write_text(public_key)
        (output_dir / "contract.sha256").write_text(contract_hash + "\n")
    return report
