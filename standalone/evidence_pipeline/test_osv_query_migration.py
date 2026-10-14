"""OSV query migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_osv_query_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence_pipeline.osv_query_pages DISABLE ROW LEVEL SECURITY",
        "DROP POLICY query_page_insert ON evidence_pipeline.osv_query_pages",
        "ALTER TABLE evidence_pipeline.osv_query_advisory_links DROP CONSTRAINT osv_query_advisory_links_pkey",
        "GRANT UPDATE ON evidence_pipeline.osv_query_pages TO tm_pipeline_writer",
        "CREATE OR REPLACE VIEW evidence_pipeline.osv_query_history AS SELECT * FROM evidence_pipeline.osv_query_history WHERE false",
        "CREATE OR REPLACE FUNCTION evidence_pipeline.osv_query_record_hashes(wire bytea) RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS 'SELECT ARRAY[]::text[]'",
        "ALTER TABLE evidence.collection_attempts DISABLE TRIGGER osv_query_attempt_complete",
    ],
)
def test_osv_query_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
