"""Narrow operational storage authority; all schema changes roll back."""

from backend.database import schema as database_schema

import psycopg2
import pytest

from .test_store import db as database_fixture


db = database_fixture


def test_writer_can_measure_only_current_database(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SELECT pg_catalog.pg_database_size(pg_catalog.current_database())")
        expected = cur.fetchone()[0]
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        cur.execute("SELECT evidence_pipeline.product_database_bytes()")
        assert cur.fetchone()[0] == expected > 0
        cur.execute("SAVEPOINT raw_size")
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(
                "SELECT pg_catalog.pg_database_size(pg_catalog.current_database())"
            )
        cur.execute("ROLLBACK TO SAVEPOINT raw_size")
        cur.execute("SAVEPOINT arbitrary_target")
        with pytest.raises(psycopg2.errors.UndefinedFunction):
            cur.execute("SELECT evidence_pipeline.product_database_bytes('postgres')")
        cur.execute("ROLLBACK TO SAVEPOINT arbitrary_target")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("SELECT evidence_pipeline.product_database_bytes()")
