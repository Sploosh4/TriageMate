"""OSV migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_osv_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence.observation_receipts DISABLE TRIGGER osv_receipt_complete",
        "DROP POLICY osv_insert ON evidence.osv_aliases",
        "ALTER FUNCTION evidence_pipeline.osv_projection_matches(uuid,text,text,jsonb) SECURITY DEFINER",
        "ALTER TABLE evidence.osv_aliases DROP CONSTRAINT osv_alias_receipt_position_key",
        "CREATE OR REPLACE VIEW evidence_pipeline.current_osv_advisories AS SELECT * FROM evidence_pipeline.current_osv_advisories WHERE false",
    ],
)
def test_osv_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
