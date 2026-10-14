"""Ubuntu migration replay and authority drift use real rolled-back PostgreSQL."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_ubuntu_migration_replay(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY ubuntu_advisory_claim_insert ON evidence_pipeline.public_claims",
        "CREATE OR REPLACE VIEW evidence_pipeline.current_osv_advisories AS SELECT * FROM evidence_pipeline.current_osv_advisories WHERE false",
        "CREATE OR REPLACE FUNCTION evidence_pipeline.osv_receipt_claim(target uuid) RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS 'SELECT NULL::jsonb'",
        "ALTER TABLE evidence.observation_receipts DISABLE TRIGGER osv_receipt_complete",
    ],
)
def test_ubuntu_migration_rejects_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


@pytest.mark.full_baseline
def test_ubuntu_preserves_full_retained_attribution(db, tmp_path, monkeypatch):  # noqa: F811
    from .test_ubuntu_store import collected, setup
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from .test_attribution import verify

    value = collected(tmp_path, monkeypatch)
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)
