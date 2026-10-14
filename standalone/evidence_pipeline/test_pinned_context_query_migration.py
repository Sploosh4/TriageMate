"""Product query optimisation preserves authority, evidence and prior entrypoints."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema


import pytest
from psycopg2 import sql


from .test_store import db as db


def test_explicit_upgrade_preserves_evidence_and_reader_contract(db, monkeypatch):
    tables = (
        "collection_attempts",
        "observation_receipts",
        "source_revisions",
        "vulnerability_findings",
        "patches",
        "patch_applicability",
    )
    with db.cursor() as cur:

        def counts():
            values = []
            for table in tables:
                cur.execute(
                    sql.SQL("SELECT count(*) FROM evidence.{}").format(
                        sql.Identifier(table)
                    )
                )
                values.append(cur.fetchone()[0])
            return values

        before = counts()
        database_schema.verify(cur)
        verify_schema(cur)
        assert counts() == before
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT finding_receipt_id,device_receipt_id,advisory_receipt_id,independent_applicability FROM evidence_pipeline.current_device_product_candidates LIMIT 1"
        )
        cur.fetchall()
        cur.execute("RESET ROLE")
        database_schema.verify(cur)


@pytest.mark.parametrize("damage", ["query", "public_grant"])
def test_changed_query_or_public_grant_is_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT pg_get_viewdef('evidence_pipeline.current_device_product_candidates'::regclass,true)"
        )
        definition = cur.fetchone()[0]
        assert "finding_context AS MATERIALIZED" in definition
        if damage == "query":
            cur.execute(
                "CREATE OR REPLACE VIEW evidence_pipeline.current_device_product_candidates AS "
                + definition.replace("AS MATERIALIZED", "AS NOT MATERIALIZED", 1)
            )
        else:
            cur.execute(
                "GRANT SELECT ON evidence_pipeline.current_device_product_candidates TO PUBLIC"
            )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
