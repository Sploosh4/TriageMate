"""Enrichment migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_enrichment_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence_pipeline.enrichment_requests DISABLE ROW LEVEL SECURITY",
        "DROP POLICY enrichment_insert ON evidence_pipeline.enrichment_requests",
        "ALTER TABLE evidence_pipeline.enrichment_requests DROP CONSTRAINT enrichment_identity",
        "GRANT UPDATE ON evidence_pipeline.enrichment_runs TO tm_pipeline_writer",
        "CREATE OR REPLACE VIEW evidence_pipeline.enrichment_request_status AS SELECT * FROM evidence_pipeline.enrichment_request_status WHERE false",
    ],
)
def test_enrichment_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
