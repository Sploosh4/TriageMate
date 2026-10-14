from backend.database import schema as database_schema
import pytest


from standalone.evidence_pipeline.test_store import db as database_fixture

db = database_fixture


def test_additive_migration_repeats_without_rewriting_manifest_or_rows(db):
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        before = cursor.fetchone()
        cursor.execute("SELECT count(*) FROM evidence.device_observations")
        count = cursor.fetchone()
        cursor.execute("SELECT to_regclass('evidence_pipeline.current_device_status')")
        previous = []
        if cursor.fetchone()[0] is not None:
            cursor.execute(
                "SELECT * FROM evidence_pipeline.current_device_status ORDER BY 1"
            )
            previous = cursor.fetchall()
        database_schema.verify(cursor)
        cursor.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        assert cursor.fetchone() == before
        cursor.execute("SELECT count(*) FROM evidence.device_observations")
        assert cursor.fetchone() == count
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cursor.execute(
            "SELECT * FROM evidence_pipeline.current_device_status ORDER BY 1"
        )
        assert cursor.fetchall() == previous


def test_role_privilege_drift_is_rejected(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("ALTER ROLE tm_pipeline_writer CREATEDB")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_row_policy_drift_is_rejected(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "ALTER TABLE evidence.device_observations DISABLE ROW LEVEL SECURITY"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_view_drift_is_rejected(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        # Same output shape, different semantics must not be silently accepted.
        cursor.execute(
            "SELECT pg_get_viewdef('evidence_pipeline.current_device_status'::regclass)"
        )
        original = cursor.fetchone()[0].rstrip().removesuffix(";")
        statement = "SELECT * FROM (" + original + ") original WHERE false"
        cursor.execute(
            "CREATE OR REPLACE VIEW evidence_pipeline.current_device_status AS "
            + statement
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)
