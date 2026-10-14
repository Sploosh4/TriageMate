"""Current-schema fingerprints detect definition and authority drift."""

from contextlib import closing

import pytest

from backend.database.baseline.catalogue import fingerprint, require_contract
from standalone.evidence_pipeline.test_bootstrap import empty_database  # noqa: F401


def test_contract_requires_every_category():
    require_contract({"tables": "a"}, {"tables": "a"})
    for actual in ({}, {"tables": "b"}, {"tables": "a", "other": "x"}):
        with pytest.raises(ValueError, match="schema/authority differs"):
            require_contract(actual, {"tables": "a"})


def test_catalogue_detects_changes_and_preserves_transaction(empty_database):  # noqa: F811
    database = empty_database
    with closing(database.connect()) as conn, conn.cursor() as cur:
        cur.execute("CREATE SCHEMA evidence")
        cur.execute("CREATE TABLE evidence.records(id integer PRIMARY KEY, value text)")
        cur.execute("CREATE ROLE tm_test_reader NOLOGIN NOINHERIT")
        cur.execute(
            "CREATE FUNCTION evidence.answer() RETURNS integer LANGUAGE sql AS 'SELECT 42'"
        )
        cur.execute("SET LOCAL search_path TO evidence, public")
        expected = fingerprint(cur)
        cur.execute("SHOW search_path")
        assert cur.fetchone() == ("evidence, public",)
        # Collection metadata is independent of stored evidence and does not
        # commit the caller's changes. Data integrity has a separate verifier.
        cur.execute("INSERT INTO evidence.records VALUES(1,'synthetic')")
        require_contract(fingerprint(cur), expected)
        changes = (
            ("ALTER TABLE evidence.records ADD COLUMN extra text", "columns"),
            ("ALTER TABLE evidence.records DISABLE TRIGGER ALL", "triggers"),
            ("ALTER TABLE evidence.records ENABLE ROW LEVEL SECURITY", "relations"),
            ("CREATE POLICY injected ON evidence.records USING(true)", "policies"),
            ("GRANT SELECT ON evidence.records TO tm_test_reader", "object_acl"),
            ("GRANT SELECT(value) ON evidence.records TO tm_test_reader", "object_acl"),
            ("ALTER ROLE tm_test_reader LOGIN", "roles"),
            ("ALTER ROLE tm_test_reader SET statement_timeout='1s'", "roles"),
            ("CREATE SCHEMA unexpected", "schemas"),
            ("CREATE TABLE public.unexpected(id int)", "relations"),
            (
                "CREATE OR REPLACE FUNCTION evidence.answer() RETURNS integer LANGUAGE sql AS 'SELECT 7'",
                "functions",
            ),
            (
                "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO tm_test_reader",
                "object_acl",
            ),
            (
                "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO tm_test_reader",
                "default_acl",
            ),
            ("GRANT CONNECT ON DATABASE empty_test TO tm_test_reader", "database_acl"),
        )
        # An internal FK trigger must also be checked, regardless of its
        # installation-specific generated name.
        cur.execute(
            "CREATE TABLE evidence.children(parent_id integer REFERENCES evidence.records(id))"
        )
        expected = fingerprint(cur)
        for statement, category in changes:
            cur.execute("SAVEPOINT intact")
            cur.execute(statement)
            actual = fingerprint(cur)
            assert actual[category] != expected[category], statement
            with pytest.raises(ValueError, match=category):
                require_contract(actual, expected)
            cur.execute("ROLLBACK TO SAVEPOINT intact")
            require_contract(fingerprint(cur), expected)
        conn.rollback()
        cur.execute("SELECT to_regnamespace('evidence')")
        assert cur.fetchone() == (None,)


def test_catalogue_requires_transaction(empty_database):  # noqa: F811
    with closing(empty_database.connect()) as conn:
        conn.autocommit = True
        with conn.cursor() as cur, pytest.raises(ValueError, match="caller-owned"):
            fingerprint(cur)


def test_evidence_receipt_preserves_and_detects_rows(empty_database):  # noqa: F811
    from backend.database.baseline.evidence import evidence_receipt

    database = empty_database
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("CREATE SCHEMA evidence")
        cur.execute("CREATE TABLE evidence.records(id integer, value text)")
        cur.execute(
            "INSERT INTO evidence.records VALUES(1,'explicit synthetic record')"
        )
    with closing(database.connect()) as conn:
        conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
        with conn.cursor() as cur:
            before = evidence_receipt(cur)
            assert before["evidence.records"]["rows"] == 1
            assert "synthetic" not in str(before)
            with (
                closing(database.connect()) as writer,
                writer,
                writer.cursor() as write,
            ):
                write.execute(
                    "UPDATE evidence.records SET value='changed synthetic record'"
                )
            # The receipt remains stable across a concurrent committed writer.
            assert evidence_receipt(cur) == before
    with closing(database.connect()) as conn:
        conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
        with conn.cursor() as cur:
            after = evidence_receipt(cur)
            assert after["evidence.records"]["rows"] == 1
            assert after != before
    with closing(database.connect()) as conn, conn.cursor() as cur:
        with pytest.raises(ValueError, match="read-only stable snapshot"):
            evidence_receipt(cur)


def test_locked_receipt_requires_actual_relation_locks(empty_database):  # noqa: F811
    from backend.database.backup import lock_relations
    from backend.database.baseline.evidence import evidence_receipt

    with closing(empty_database.connect()) as conn:
        with conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.synthetic(id integer)")
        conn.set_session(isolation_level="REPEATABLE READ")
        with conn.cursor() as cur:
            with pytest.raises(ValueError, match="locks on every"):
                evidence_receipt(cur, locked=True)
            lock_relations(cur)
            assert evidence_receipt(cur, locked=True)["public.synthetic"]["rows"] == 0
