"""Antivirus upgrade checks roll back in the existing synthetic/lab database."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema


import psycopg2
import pytest


from .test_store import db  # noqa: F401


def test_upgrade_preserves_rows_and_earlier_verification(db, monkeypatch):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT id::text,mode,signature_current FROM evidence.antivirus_observations ORDER BY id"
        )
        original = cur.fetchall()
        cur.execute(
            "SELECT artifacts ? 'schema.sql' FROM evidence_pipeline.installation WHERE singleton"
        )
        already_installed = cur.fetchone()[0]
        assert already_installed, (
            "The consolidated baseline artifact must be registered"
        )
        previous_view = []
        if already_installed:
            cur.execute("SELECT * FROM evidence_pipeline.current_antivirus ORDER BY id")
            previous_view = cur.fetchall()
        database_schema.verify(cur)
        cur.execute(
            "SELECT id::text,mode,signature_current FROM evidence.antivirus_observations ORDER BY id"
        )
        assert cur.fetchall() == original
        verify_schema(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute("SELECT * FROM evidence_pipeline.current_antivirus ORDER BY id")
        assert cur.fetchall() == previous_view
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM evidence.antivirus_observations")


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY antivirus_insert ON evidence.antivirus_observations",
        "GRANT UPDATE ON evidence.antivirus_observations TO tm_pipeline_writer",
        "ALTER TABLE evidence.antivirus_observations DISABLE TRIGGER exposure_provenance",
    ],
)
def test_antivirus_authority_drift_is_detected(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_upgrade_does_not_bless_disabled_earlier_trigger(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "ALTER TABLE evidence.vulnerability_findings DISABLE TRIGGER exposure_provenance"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
