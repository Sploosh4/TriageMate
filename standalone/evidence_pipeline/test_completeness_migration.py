"""Completeness upgrade replay and authority drift; all changes roll back."""

from backend.database import schema as database_schema

import pytest


from .test_store import db as database_fixture

db = database_fixture


@pytest.mark.parametrize("damage", ["view", "reader", "function", "metadata"])
def test_changed_completeness_authority_or_definition_is_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if damage == "view":
            cur.execute("DROP VIEW evidence_pipeline.current_completeness")
        elif damage == "reader":
            cur.execute(
                "REVOKE SELECT ON evidence_pipeline.current_completeness FROM tm_mock_reader"
            )
        elif damage == "function":
            cur.execute(
                "REVOKE EXECUTE ON FUNCTION pg_catalog.lower(text) FROM tm_mock_reader"
            )
        else:
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'schema.sql'"
            )
        with pytest.raises(ValueError, match="schema/authority differs|metadata"):
            database_schema.verify(cur)
