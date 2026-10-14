"""Additive vendor acceptance upgrade checks predecessor entry points and provenance."""

from backend.database import schema as database_schema

import pytest


from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_advisory_store import prepare, SOURCES
from .test_store import db  # noqa: F401


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY vendor_advisory_synthetic_only ON evidence_pipeline.public_claims",
        "GRANT UPDATE ON evidence.public_reference_observations TO tm_pipeline_writer",
    ],
)
def test_upgrade_rejects_authority_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


@pytest.mark.full_baseline
def test_all_vendor_formats_pass_full_attribution(db):  # noqa: F811
    for source in SOURCES:
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
        value = prepare(db, source)
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        from .test_attribution import verify

        verify(cur)
