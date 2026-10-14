"""Consistent retained-row receipts for backup, restore and adoption checks.

Receipts contain relation names, counts and SHA-256 digests, not source values.
They supplement schema/authority and attribution checks; they do not replace them.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import uuid
from dataclasses import asdict, dataclass

from psycopg2 import sql
from psycopg2.extensions import TRANSACTION_STATUS_INERROR, cursor


@dataclass(frozen=True)
class RelationReceipt:
    rows: int
    sha256: str


@contextmanager
def _canonical_output(cur: cursor) -> Iterator[None]:
    settings = {
        "TimeZone": "UTC",
        "DateStyle": "ISO, YMD",
        "IntervalStyle": "postgres",
        "extra_float_digits": "3",
        "bytea_output": "hex",
    }
    previous = {}
    for name in settings:
        cur.execute("SELECT current_setting(%s)", (name,))
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL did not return output settings")
        previous[name] = row[0]
    try:
        for name, value in settings.items():
            cur.execute("SELECT set_config(%s,%s,true)", (name, value))
        yield
    finally:
        if cur.connection.get_transaction_status() != TRANSACTION_STATUS_INERROR:
            for name, value in previous.items():
                cur.execute("SELECT set_config(%s,%s,true)", (name, value))


def evidence_receipt(
    cur: cursor, *, locked: bool = False
) -> dict[str, dict[str, int | str]]:
    """Stream deterministic row hashes from an owner-authorized stable snapshot.

    The caller starts a read-only REPEATABLE READ or SERIALIZABLE transaction,
    owns its lifetime and stores the resulting receipt in protected local storage.
    Adoption may use a read/write stable snapshot only with locked=True and actual
    SHARE-or-stronger relation locks, which are checked below.
    Installation metadata is deliberately separate because adoption changes it.
    """
    if cur.connection.autocommit:
        raise ValueError("Evidence verification requires a stable transaction")
    cur.execute("SHOW transaction_isolation")
    isolation = cur.fetchone()
    cur.execute("SHOW transaction_read_only")
    readonly = cur.fetchone()
    if isolation not in (("repeatable read",), ("serializable",)) or (
        readonly != ("on",) and not locked
    ):
        raise ValueError("Evidence verification requires a read-only stable snapshot")
    cur.execute(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user"
    )
    if cur.fetchone() != (True,):
        raise ValueError(
            "Evidence verification requires explicit owner audit authority"
        )
    if readonly != ("on",):
        cur.execute("""
            SELECT n.nspname,c.relname
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE c.relkind IN ('r','p','m')
              AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
              AND NOT EXISTS (
                SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid()
                  AND l.locktype='relation' AND l.relation=c.oid AND l.granted
                  AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')
              )
        """)
        if cur.fetchall():
            raise ValueError(
                "Adoption evidence verification requires locks on every stored relation"
            )
    cur.execute("""
        SELECT n.nspname,c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','m')
          AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
          AND NOT (n.nspname='evidence_pipeline' AND c.relname='installation')
        ORDER BY n.nspname,c.relname
    """)
    relations = cur.fetchall()
    result = {}
    with _canonical_output(cur):
        for schema, table in relations:
            digest = hashlib.sha256()
            count = 0
            # ONLY avoids double counting inherited rows. Partitioned parents store
            # no rows; their physical leaf relations are included independently.
            with cur.connection.cursor(
                name=f"tm_receipt_{uuid.uuid4().hex}"
            ) as rows_cur:
                rows_cur.execute(
                    sql.SQL(
                        'SELECT to_jsonb(t)::text FROM ONLY {} t ORDER BY to_jsonb(t)::text COLLATE "C"'
                    ).format(sql.Identifier(schema, table))
                )
                while rows := rows_cur.fetchmany(1000):
                    for (value,) in rows:
                        encoded = value.encode("utf-8")
                        digest.update(len(encoded).to_bytes(8, "big"))
                        digest.update(encoded)
                        count += 1
            result[f"{schema}.{table}"] = asdict(
                RelationReceipt(count, digest.hexdigest())
            )
    return result
