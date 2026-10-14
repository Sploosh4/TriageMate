"""Reference validator migration preserves exact equality and installed authority."""

from backend.database import schema as database_schema

from uuid import uuid4

import pytest


from .test_store import db as database_fixture
from .test_reference_store import snapshot, setup
from standalone.evidence_pipeline.persistence.public_store import persist_public

db = database_fixture


def test_explicit_reference_upgrade_is_idempotent_and_verified(db):
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        previous = cursor.fetchone()[0]
        database_schema.verify(cursor)
        cursor.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        assert cursor.fetchone() == (previous,)

        database_schema.verify(cursor)
        cursor.execute(
            "SELECT proconfig,prosecdef FROM pg_proc WHERE oid='evidence_pipeline.reference_projection_matches(uuid,text,text,text[],jsonb)'::regprocedure"
        )
        assert cursor.fetchone() == (["search_path=pg_catalog"], False)


@pytest.mark.parametrize(
    "field",
    [None, "native_id", "reference_kind", "cve_ids", "source_fields", "receipt_id"],
)
def test_upgraded_reference_validator_accepts_only_exact_projection(db, field):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    value = snapshot("ctid")
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT o.receipt_id,o.native_id,o.reference_kind,o.cve_ids,o.source_fields::text FROM evidence.public_reference_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s",
            (value.scope.connection_id,),
        )
        row = list(cursor.fetchone())
        changes = {
            "receipt_id": (0, str(uuid4())),
            "native_id": (1, "wrong"),
            "reference_kind": (2, "wrong"),
            "cve_ids": (3, []),
            "source_fields": (4, "{}"),
        }
        if field:
            index, value = changes[field]
            row[index] = value
        cursor.execute(
            "SELECT evidence_pipeline.reference_projection_matches(%s,%s,%s,%s,%s::jsonb)",
            row,
        )
        assert cursor.fetchone() == (field is None,)
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_reference_function_drift_is_rejected(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "ALTER FUNCTION evidence_pipeline.reference_projection_matches(uuid,text,text,text[],jsonb) SECURITY DEFINER"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)
