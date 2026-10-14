"""Catalog metadata through the authorised writer and actual query reader."""

from backend.database import schema as database_schema

from uuid import uuid4

from .test_store import db as database_fixture
from .test_advisory_feeds import fixture
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.authority import authorize_connection

from .test_update_catalog import ID, NEXT

db = database_fixture


def test_catalog_metadata_relationships_and_completeness(db, tmp_path):
    scope, raw = fixture("Microsoft Update Catalog")
    value = prepare(scope, str(uuid4()), tmp_path / "catalog", synthetic_payload=raw)
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT update_id,origin,metadata->>'architecture' FROM evidence_pipeline.current_catalog_updates WHERE connection_id=%s",
            (scope.connection_id,),
        )
        assert cur.fetchone() == (ID, "synthetic", "n/a")
        cur.execute(
            "SELECT direction,target_update_id,identity_basis FROM evidence_pipeline.current_catalog_replacement_claims WHERE connection_id=%s ORDER BY direction",
            (scope.connection_id,),
        )
        assert cur.fetchall() == [
            ("replaced_by", NEXT, "explicit_source_catalog_identity"),
            ("replaces", None, "source_title_only_identity_unresolved"),
        ]
        cur.execute(
            "SELECT domain,populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain<>'whole-product'",
            ([scope.connection_id],),
        )
        assert cur.fetchall() == [("catalog-update", 7, 8)]
        cur.execute(
            "SELECT completeness_domain FROM evidence_pipeline.product_collection_coverage WHERE connection_id=%s",
            (scope.connection_id,),
        )
        assert cur.fetchone() == ("catalog-update",)
