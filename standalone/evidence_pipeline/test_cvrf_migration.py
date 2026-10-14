"""Explicit CVRF migration refuses altered authority and verifies prior entry points."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

import pytest


from .test_store import db  # noqa: F401


def test_cvrf_migration_replay_and_original_schema_projection(db, monkeypatch):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence.observation_receipts DISABLE TRIGGER cvrf_receipt_complete",
        "DROP POLICY cvrf_insert ON evidence.patch_applicability",
        "ALTER FUNCTION evidence_pipeline.check_cvrf_projection() SECURITY DEFINER",
        "CREATE OR REPLACE VIEW evidence_pipeline.current_msrc_patch_fixes AS SELECT * FROM evidence_pipeline.current_msrc_patch_fixes WHERE false",
    ],
)
def test_cvrf_enforcement_drift_cannot_be_resealed(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
