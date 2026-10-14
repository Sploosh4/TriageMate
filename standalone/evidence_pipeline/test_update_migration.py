"""The pending v10 migration preserves earlier verification interfaces."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema


import pytest

from .test_store import db  # noqa: F401


def test_upgrade_repeat_and_original_schema(db, monkeypatch):  # noqa: F811
    with db.cursor() as cur:
        cur.execute(
            "SELECT version, artifacts ? 'schema.sql' FROM evidence_pipeline.installation WHERE singleton"
        )
        previous, already_installed = cur.fetchone()
        assert already_installed, (
            "The consolidated baseline artifact must be registered"
        )
        before = {}
        for view in ("current_missing_patches", "current_update_status"):
            cur.execute("SELECT to_regclass(%s)", ("evidence_pipeline." + view,))
            before[view] = []
            if cur.fetchone()[0] is not None:
                cur.execute(f"SELECT * FROM evidence_pipeline.{view} ORDER BY 1")
                before[view] = cur.fetchall()
        database_schema.verify(cur)
        if already_installed:
            cur.execute(
                "SELECT version FROM evidence_pipeline.installation WHERE singleton"
            )
            assert cur.fetchone() == (previous,)
        database_schema.verify(cur)
        verify_schema(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for view in ("current_missing_patches", "current_update_status"):
            cur.execute(f"SELECT * FROM evidence_pipeline.{view} ORDER BY 1")
            assert cur.fetchall() == before[view]


def test_new_source_authority_drift_is_detected(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("DROP POLICY update_insert ON evidence.device_missing_patches")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_writer_can_read_version_but_not_authority_metadata(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        expected = cur.fetchone()
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        cur.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        assert cur.fetchone() == expected
        import psycopg2

        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("SELECT signature FROM evidence_pipeline.installation")


def test_version_column_grant_drift_is_detected(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "REVOKE SELECT(version) ON evidence_pipeline.installation FROM tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
