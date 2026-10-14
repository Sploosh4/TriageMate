"""Cisco persistence authority and predecessor compatibility in rolled-back state."""

from backend.database import schema as database_schema

import pytest


from .test_store import db  # noqa: F401


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY vendor_advisory_synthetic_only ON evidence_pipeline.public_claims",
        "GRANT UPDATE ON evidence.public_reference_observations TO tm_pipeline_writer",
    ],
)
def test_cisco_upgrade_does_not_accept_authority_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
