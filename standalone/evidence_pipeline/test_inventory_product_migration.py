"""Inventory query upgrade is atomic, repeatable, and checks schema authority."""

from backend.database import schema as database_schema

import pytest


from .test_store import db as db


def test_upgrade_is_idempotent_and_prior_writers_verify(db):

    with db.cursor() as cursor:
        cursor.execute(
            "SELECT version, artifacts ? 'schema.sql' FROM evidence_pipeline.installation WHERE singleton"
        )
        previous, installed = cursor.fetchone()
        assert installed, "The consolidated baseline artifact must be registered"
        database_schema.verify(cursor)
        if installed:
            cursor.execute(
                "SELECT version FROM evidence_pipeline.installation WHERE singleton"
            )
            assert cursor.fetchone() == (previous,)
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")
        cursor.execute(
            "SELECT * FROM evidence_pipeline.current_inventory_product_evaluations LIMIT 0"
        )


def test_upgrade_rejects_changed_authority(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT SELECT ON evidence_pipeline.current_inventory_product_evaluations TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)
