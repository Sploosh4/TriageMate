"""Integrated coverage upgrade preserves evidence and rejects authority drift."""

from backend.database import schema as database_schema

import pytest


from .test_store import db as database_fixture

db = database_fixture


@pytest.mark.parametrize("damage", ["function", "grant", "metadata", "view"])
def test_modified_coverage_authority_is_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if damage == "function":
            cur.execute(
                "CREATE OR REPLACE FUNCTION evidence_pipeline.product_database_bytes() "
                "RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint'"
            )
        elif damage == "grant":
            cur.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.product_database_bytes() TO PUBLIC"
            )
        elif damage == "metadata":
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'schema.sql'"
            )
        else:
            cur.execute(
                "REVOKE SELECT ON evidence_pipeline.current_vulnerability_completeness FROM tm_mock_reader"
            )
        with pytest.raises(ValueError, match="schema/authority differs|metadata"):
            database_schema.verify(cur)
