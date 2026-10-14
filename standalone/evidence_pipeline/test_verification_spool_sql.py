"""Named verification cursors retain transaction semantics and close on failure."""

import psycopg2
import pytest

from .test_store import db as database_fixture
from .verification_spool import VerificationSpool, streamed_rows

db = database_fixture


def test_exact_json_decoding_is_cursor_local_and_survives_spooling(db):
    from decimal import Decimal

    query = 'SELECT \'{"id":"synthetic","value":0.12345678901234567890123456789,"zero":0,"flag":false}\'::jsonb'
    with db.cursor() as cur, VerificationSpool() as spool:
        with streamed_rows(cur, query, exact_json=True) as rows:
            saved = spool.rows(row[0] for row in rows)
        assert saved[0] == {
            "id": "synthetic",
            "value": Decimal("0.12345678901234567890123456789"),
            "zero": 0,
            "flag": False,
        }
        indexed = spool.reference_mapping(saved, "id")
        assert indexed["synthetic"] == saved[0]
        assert saved[0]["value"] != Decimal(str(float(saved[0]["value"])))
        with streamed_rows(cur, query) as rows:
            assert isinstance(next(rows)[0]["value"], float)
        cur.execute(query)
        assert isinstance(cur.fetchone()[0]["value"], float)


def test_stream_sees_own_writes_and_closes_after_early_exit(db):
    with db.cursor() as cur:
        cur.execute("CREATE TEMP TABLE synthetic_spool_test(value integer)")
        cur.execute("INSERT INTO synthetic_spool_test VALUES(0),(1),(2)")
        with streamed_rows(
            cur, "SELECT value FROM synthetic_spool_test ORDER BY value"
        ) as rows:
            assert next(rows) == (0,)
            name = rows.name
            cur.execute("SELECT count(*) FROM synthetic_spool_test")
            assert cur.fetchone() == (3,)
        cur.execute("SELECT count(*) FROM pg_cursors WHERE name=%s", (name,))
        assert cur.fetchone() == (0,)


def test_query_timeout_cleans_spool_and_recovers_at_savepoint(db):
    import sqlite3

    with db.cursor() as cur:
        cur.execute("SAVEPOINT synthetic_spool_timeout")
        cur.execute("SET LOCAL statement_timeout=50")
        connection = None
        with pytest.raises(psycopg2.errors.QueryCanceled):
            with VerificationSpool() as spool:
                connection = spool.connection
                with streamed_rows(cur, "SELECT pg_sleep(1)") as rows:
                    spool.rows(rows)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
        cur.execute("ROLLBACK TO SAVEPOINT synthetic_spool_timeout")
        cur.execute("SELECT 1")
        assert cur.fetchone() == (1,)
        cur.execute("SELECT count(*) FROM pg_cursors WHERE name LIKE 'verify_rows_%'")
        assert cur.fetchone() == (0,)
