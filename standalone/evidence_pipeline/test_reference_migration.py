"""Public reference migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_reference_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY reference_claim_insert ON evidence_pipeline.public_claims",
        "CREATE OR REPLACE VIEW evidence_pipeline.current_public_references AS SELECT * FROM evidence_pipeline.current_public_references WHERE false",
        "CREATE OR REPLACE FUNCTION evidence_pipeline.osv_receipt_claim(target uuid) RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS 'SELECT NULL::jsonb'",
        "ALTER TABLE evidence.observation_receipts DISABLE TRIGGER reference_receipt_complete",
    ],
)
def test_reference_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


@pytest.mark.full_baseline
def test_reference_upgrade_with_all_sources_passes_retained_attribution(db):  # noqa: F811
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from .test_reference_store import snapshot
    from .test_attribution import verify

    with db.cursor() as cur:
        database_schema.verify(cur)
    for kind in ("exploit", "ctid", "attack"):
        value = snapshot(kind)
        with db.cursor() as cur:
            authorize_connection(cur, value)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        persist_public(db, value)
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
    with db.cursor() as cur:
        verify(cur)
