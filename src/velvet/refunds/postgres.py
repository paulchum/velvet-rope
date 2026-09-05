"""One ledger per schema, with transactional authorization, mutation and evidence.

The executor is trusted and holds its own DB identity. Agents never receive it.
All refunds and closure serialize on the ledger row. This intentionally prioritizes
a reviewable contract over throughput; external payment systems are out of scope.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from velvet.execution import ExecutionPermit
from velvet.refunds.contract import (
    RefundCommand,
    RefundRejected,
    close_transition,
    initial_state,
    transition,
    validate_permit,
)
from velvet.serialization import JsonObject, canonical_hash_sha256

DDL = """
CREATE TABLE vr_ledger (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    config jsonb NOT NULL,
    state jsonb NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 0),
    head_hash text NOT NULL,
    CHECK ((state->>'spent_cents')::bigint >= 0),
    CHECK ((state->>'spent_cents')::bigint <= (config->>'budget_cents')::bigint)
);
CREATE TABLE vr_journal (
    sequence bigint PRIMARY KEY CHECK (sequence >= 0),
    event jsonb NOT NULL,
    event_hash text NOT NULL UNIQUE
);
CREATE TABLE vr_operations (
    operation_id text PRIMARY KEY,
    permit_id text NOT NULL UNIQUE,
    command_hash text NOT NULL,
    event_sequence bigint NOT NULL UNIQUE REFERENCES vr_journal(sequence),
    event_hash text NOT NULL REFERENCES vr_journal(event_hash)
);
"""


def _required(row: JsonObject | None) -> JsonObject:
    if row is None:
        raise RefundRejected("required ledger row is missing")
    return row


class RefundLedger:
    def __init__(self, dsn: str, schema: str) -> None:
        self.dsn = dsn
        self.schema = schema

    @contextmanager
    def _connect(self, *, observer: bool = False) -> Iterator[psycopg.Connection[Any]]:
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            if observer:
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            else:
                conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE")
                conn.execute("SET LOCAL synchronous_commit = on")
            conn.execute(
                sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(
                    sql.Identifier(self.schema)
                )
            )
            conn.execute("SET LOCAL lock_timeout = '5s'")
            conn.execute("SET LOCAL statement_timeout = '10s'")
            yield conn

    def install(self, config: JsonObject, *, executor_role: str, observer_role: str) -> None:
        """Owner-only installation into a NEW schema. Never alters an existing ledger.

        Roles must already exist; role creation and credentials belong to deployment.
        """
        state = initial_state(config)
        with self._connect() as conn:
            owner = _required(conn.execute("SELECT current_user AS name").fetchone())["name"]
            if len({owner, executor_role, observer_role}) != 3:
                raise RefundRejected("owner, executor and observer identities must differ")
            for role in (executor_role, observer_role):
                row = conn.execute(
                    "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = %s", (role,)
                ).fetchone()
                if row is None or row["rolsuper"] or row["rolcreaterole"]:
                    raise RefundRejected("executor and observer require unprivileged roles")
                if _required(
                    conn.execute(
                        "SELECT pg_has_role(%s, %s, 'MEMBER') AS member", (role, owner)
                    ).fetchone()
                )["member"]:
                    raise RefundRejected("service roles must not inherit the owner role")
            conn.execute(
                sql.SQL("CREATE SCHEMA {} AUTHORIZATION CURRENT_USER").format(
                    sql.Identifier(self.schema)
                )
            )
            conn.execute(
                sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema))
            )
            conn.execute(DDL)
            now = (
                _required(conn.execute("SELECT clock_timestamp() AS now").fetchone())["now"]
                .astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
            event = {
                "sequence": 0,
                "previous_hash": None,
                "kind": "open",
                "contract_hash": canonical_hash_sha256(config),
                "evaluated_at": now,
                "command": None,
                "permit": None,
                "state_hash": canonical_hash_sha256(state),
            }
            digest = canonical_hash_sha256(event)
            conn.execute(
                "INSERT INTO vr_ledger VALUES (true, %s, %s, 0, %s)",
                (Jsonb(config), Jsonb(state), digest),
            )
            conn.execute("INSERT INTO vr_journal VALUES (0, %s, %s)", (Jsonb(event), digest))
            conn.execute(
                "REVOKE ALL ON ALL TABLES IN SCHEMA "
                + sql.Identifier(self.schema).as_string(conn)
                + " FROM PUBLIC"
            )
            for role in (executor_role, observer_role):
                conn.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                        sql.Identifier(self.schema), sql.Identifier(role)
                    )
                )
                conn.execute(
                    sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                        sql.Identifier(self.schema), sql.Identifier(role)
                    )
                )
            conn.execute(
                sql.SQL("GRANT UPDATE (state, sequence, head_hash) ON vr_ledger TO {}").format(
                    sql.Identifier(executor_role)
                )
            )
            conn.execute(
                sql.SQL("GRANT INSERT ON vr_journal, vr_operations TO {}").format(
                    sql.Identifier(executor_role)
                )
            )

    def refund(self, command: RefundCommand, permit: ExecutionPermit) -> JsonObject:
        """Return after COMMIT. Connection errors leave the caller's outcome unresolved.

        Retry an identical operation to recover a committed result; a cached result is
        historical retrieval, including after closure or permit expiry, never a new effect.
        """
        with self._connect() as conn:
            ledger = _required(conn.execute("SELECT * FROM vr_ledger FOR UPDATE").fetchone())
            previous = conn.execute(
                "SELECT * FROM vr_operations WHERE operation_id = %s", (command.operation_id,)
            ).fetchone()
            if previous:
                if (
                    previous["command_hash"] != canonical_hash_sha256(command.to_dict())
                    or previous["permit_id"] != permit.permit_id
                ):
                    raise RefundRejected("operation identity already belongs to another request")
                event = _required(
                    conn.execute(
                        "SELECT event FROM vr_journal WHERE sequence = %s",
                        (previous["event_sequence"],),
                    ).fetchone()
                )["event"]
                if canonical_hash_sha256(event["permit"]) != canonical_hash_sha256(
                    permit.to_dict()
                ):
                    raise RefundRejected("retry permit differs from the committed permit")
                result = {"status": "committed", "replayed": True, **previous}
            else:
                # Read database wall time AFTER acquiring the lock; waiting must not extend TTL.
                now = (
                    _required(conn.execute("SELECT clock_timestamp() AS now").fetchone())["now"]
                    .astimezone(UTC)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                validate_permit(ledger["config"], command, permit, now)
                state = transition(ledger["config"], ledger["state"], command)
                if conn.execute(
                    "SELECT 1 FROM vr_operations WHERE permit_id = %s", (permit.permit_id,)
                ).fetchone():
                    raise RefundRejected("permit already consumed")
                event, digest = self._append(
                    conn, ledger, state, "refund", now, command.to_dict(), permit.to_dict()
                )
                operation = {
                    "operation_id": command.operation_id,
                    "permit_id": permit.permit_id,
                    "command_hash": canonical_hash_sha256(command.to_dict()),
                    "event_sequence": event["sequence"],
                    "event_hash": digest,
                }
                conn.execute(
                    "INSERT INTO vr_operations VALUES (%s, %s, %s, %s, %s)",
                    tuple(operation.values()),
                )
                result = {"status": "committed", "replayed": False, **operation}
        return result

    def close(self) -> JsonObject:
        """Trusted lifecycle control. The same lock orders closure relative to refunds."""
        with self._connect() as conn:
            ledger = _required(conn.execute("SELECT * FROM vr_ledger FOR UPDATE").fetchone())
            if not ledger["state"]["closed"]:
                state = close_transition(ledger["state"])
                now = (
                    _required(conn.execute("SELECT clock_timestamp() AS now").fetchone())["now"]
                    .astimezone(UTC)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                self._append(conn, ledger, state, "close", now, None, None)
            else:
                state = ledger["state"]
        return dict(state)

    @staticmethod
    def _append(
        conn: psycopg.Connection[Any],
        ledger: JsonObject,
        state: JsonObject,
        kind: str,
        now: str,
        command: JsonObject | None,
        permit: JsonObject | None,
    ) -> tuple[JsonObject, str]:
        event = {
            "sequence": ledger["sequence"] + 1,
            "previous_hash": ledger["head_hash"],
            "kind": kind,
            "contract_hash": canonical_hash_sha256(ledger["config"]),
            "evaluated_at": now,
            "command": command,
            "permit": permit,
            "state_hash": canonical_hash_sha256(state),
        }
        digest = canonical_hash_sha256(event)
        conn.execute(
            "INSERT INTO vr_journal VALUES (%s, %s, %s)", (event["sequence"], Jsonb(event), digest)
        )
        conn.execute(
            "UPDATE vr_ledger SET state = %s, sequence = %s, head_hash = %s",
            (Jsonb(state), event["sequence"], digest),
        )
        return event, digest

    def observe(self) -> JsonObject:
        """Consistent snapshot through a distinct identity without table write privileges."""
        with self._connect(observer=True) as conn:
            for table in ("vr_ledger", "vr_journal", "vr_operations"):
                name = sql.Identifier(self.schema, table).as_string(conn)
                rights = _required(
                    conn.execute(
                        "SELECT has_table_privilege(current_user, %s, "
                        "'INSERT,UPDATE,DELETE,TRUNCATE') OR "
                        "has_any_column_privilege(current_user, %s, 'UPDATE') AS writable",
                        (name, name),
                    ).fetchone()
                )
                if rights["writable"]:
                    raise RefundRejected("observer identity has write privileges")
            ledger = _required(conn.execute("SELECT * FROM vr_ledger").fetchone())
            records = conn.execute("SELECT * FROM vr_journal ORDER BY sequence").fetchall()
            operations = conn.execute(
                "SELECT * FROM vr_operations ORDER BY operation_id"
            ).fetchall()
            meta = _required(
                conn.execute(
                    "SELECT current_user AS observer, "
                    "transaction_timestamp() AS snapshot_started_at, "
                    "clock_timestamp() AS observed_at, "
                    "current_setting('server_version') AS postgres"
                ).fetchone()
            )
            for key in ("snapshot_started_at", "observed_at"):
                meta[key] = meta[key].astimezone(UTC).isoformat().replace("+00:00", "Z")
        return {
            "config": ledger["config"],
            "state": ledger["state"],
            "sequence": ledger["sequence"],
            "head_hash": ledger["head_hash"],
            "records": records,
            "operations": operations,
            "observation": meta,
        }
