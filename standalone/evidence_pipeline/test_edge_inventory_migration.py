"""Additive Edge migration preserves earlier writers and reader authority."""

from backend.database import schema as database_schema

import pytest
from .test_store import db as db


def test_upgrade_is_idempotent_and_prior_entrypoints_verify(db):

    with db.cursor() as q:
        database_schema.verify(q)
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT * FROM evidence_pipeline.current_inventory_product_evaluations LIMIT 0"
        )


@pytest.mark.parametrize("object_name", ["view", "function", "scoped-cells", "summary"])
def test_changed_authority_is_rejected(db, object_name):
    with db.cursor() as q:
        database_schema.verify(q)
        if object_name == "view":
            q.execute(
                "GRANT SELECT ON evidence_pipeline.current_inventory_product_evaluations TO PUBLIC"
            )
        elif object_name == "function":
            q.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.edge_inventory_status(jsonb,text,jsonb) TO PUBLIC"
            )
        elif object_name == "scoped-cells":
            q.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.selected_product_completeness_cells(uuid[]) TO PUBLIC"
            )
        else:
            q.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.completeness_summary(uuid[]) TO PUBLIC"
            )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(q)
