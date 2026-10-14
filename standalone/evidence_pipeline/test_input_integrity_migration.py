"""New enforcement is additive and cannot be silently removed or resealed."""

from backend.database import schema as database_schema

import pytest


from .test_store import db  # noqa: F401


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence.recommendations DISABLE TRIGGER defender_recommendation_projection_complete",
        "DROP TRIGGER assessment_projection_integrity ON evidence_pipeline.assessment_observations",
        "ALTER FUNCTION evidence_pipeline.check_assessment_projection() SECURITY DEFINER",
    ],
)
def test_integrity_migration_rejects_enforcement_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
