"""CVE migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_cve_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence.observation_receipts DISABLE TRIGGER cve_receipt_complete",
        "DROP POLICY cve_insert ON evidence.cve_contributions",
        "ALTER FUNCTION evidence_pipeline.cve_projection_matches(uuid,text,text,jsonb) SECURITY DEFINER",
        "ALTER TABLE evidence.cve_contributions DROP CONSTRAINT cve_contribution_receipt_position_key",
        "CREATE OR REPLACE VIEW evidence_pipeline.current_cve_records AS SELECT * FROM evidence_pipeline.current_cve_records WHERE false",
    ],
)
def test_cve_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
