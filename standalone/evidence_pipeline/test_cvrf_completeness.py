"""CVRF patch cells use the existing definition and exact selected source scope."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from .test_store import db as db
from .test_cvrf_store import snapshot
from .test_cvrf_updates import document
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public


def test_cvrf_cells_and_empty_latest_snapshot_under_reader(db):
    first = snapshot()
    second = replace(
        first,
        scope=replace(first.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    with db.cursor() as q:
        database_schema.verify(q)
        for item in (first, second):
            authorize_connection(q, item)
    for item in (first, second):
        with db.cursor() as q:
            q.execute("SET LOCAL ROLE tm_pipeline_writer")
        persist_public(db, item)
        with db.cursor() as q:
            q.execute("RESET ROLE")
    with db.cursor() as q:
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT connection_id,count(*),count(*) FILTER(WHERE populated),count(*) FILTER(WHERE applicability='unknown') FROM evidence_pipeline.current_public_completeness_cells WHERE connection_id=ANY(%s::uuid[]) GROUP BY connection_id",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        rows = q.fetchall()
        assert len(rows) == 2 and all(row[1:] == (10, 6, 0) for row in rows)
        q.execute(
            "SELECT count(*) FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND domain='public-patch'",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        assert q.fetchone() == (20,)
        q.execute("RESET ROLE")
    failure = replace(
        first,
        execution_id=str(uuid4()),
        finished_at=first.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        payload=b"invalid",
        error_code="invalid_public_payload",
    )
    with db.cursor() as q:
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, failure)
    with db.cursor() as q:
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT eligible_cells,collection_state,selected_attempt_id::text FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
            (first.scope.connection_id,),
        )
        # Whole-product coverage also includes the five native CVRF claim fields.
        assert q.fetchone() == (15, "last_success_retained", first.execution_id)
        q.execute(
            "SELECT domain,count(*) FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && ARRAY[%s::uuid] GROUP BY domain ORDER BY domain",
            (first.scope.connection_id,),
        )
        assert q.fetchall() == [("msrc-update", 5), ("public-patch", 10)]
        q.execute("RESET ROLE")
    raw = document()
    raw["Vulnerability"] = []
    empty = replace(
        first,
        execution_id=str(uuid4()),
        finished_at=first.finished_at + timedelta(seconds=2),
        payload=json.dumps(raw).encode(),
    )
    with db.cursor() as q:
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, empty)
    with db.cursor() as q:
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_completeness_cells WHERE connection_id=%s",
            (first.scope.connection_id,),
        )
        assert q.fetchone() == (0,)
        q.execute(
            "SELECT eligible_cells,unknown_applicability,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
            (first.scope.connection_id,),
        )
        assert q.fetchone() == (0, 0, "Not assessable: no eligible evidence cells")
        q.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_completeness_cells WHERE connection_id=%s",
            (second.scope.connection_id,),
        )
        assert q.fetchone() == (10,)


def test_patch_cell_values_equal_original_row_projection(db):
    item = snapshot()
    with db.cursor() as q:
        database_schema.verify(q)
        authorize_connection(q, item)
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, item)
    with db.cursor() as q:
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT p.id::text,d.field_name,to_jsonb(p)->d.field_name "
            "FROM evidence_pipeline.current_public_patches p "
            "JOIN evidence_pipeline.product_completeness_definition d ON d.domain='public-patch' "
            "WHERE p.connection_id=%s ORDER BY 1,2",
            (item.scope.connection_id,),
        )
        expected = q.fetchall()
        q.execute(
            "SELECT entity_key,field_name,value FROM evidence_pipeline.current_public_completeness_cells "
            "WHERE connection_id=%s AND domain='public-patch' ORDER BY 1,2",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == expected and len(expected) == 10


@pytest.mark.parametrize(
    "native_id,bad_adapter",
    [
        ("CVE-2026-12345", "msrc-cvrf-advisory-v1"),
        ("ADV160001", "msrc-cvrf-updates-v1"),
    ],
)
def test_adapter_tampering_cannot_enter_identity_filtered_view(
    db, monkeypatch, native_id, bad_adapter
):
    import psycopg2
    from standalone.evidence_pipeline.persistence import public_store
    from .text_bytes import utf8_sha256

    item = snapshot()
    raw = json.loads(item.payload)
    raw["Vulnerability"][0]["CVE"] = native_id
    item = replace(item, payload=json.dumps(raw).encode())
    with db.cursor() as q:
        database_schema.verify(q)
        authorize_connection(q, item)
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    original = public_store.normalize_public

    def changed(feed):
        for record in original(feed):
            claim = json.loads(record.claim)
            claim["adapter"] = bad_adapter
            encoded = json.dumps(claim, sort_keys=True, separators=(",", ":"))
            yield replace(record, claim=encoded, content_hash=utf8_sha256(encoded))

    monkeypatch.setattr(public_store, "normalize_public", changed)
    with pytest.raises(psycopg2.Error, match="Invalid CVRF source claim"):
        persist_public(db, item)
    with db.cursor() as q:
        q.execute("SET CONSTRAINTS ALL IMMEDIATE")
        q.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (item.execution_id,),
        )
        assert q.fetchone() == (0,)
        q.execute(
            "SELECT count(*) FROM evidence_pipeline.current_msrc_update_claims WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchone() == (0,)


def test_native_advisory_and_cve_remain_separate_after_optimisation(db):
    from copy import deepcopy

    item = snapshot()
    raw = json.loads(item.payload)
    advisory = deepcopy(raw["Vulnerability"][0])
    advisory["CVE"] = "ADV160001"
    raw["Vulnerability"].append(advisory)
    item = replace(item, payload=json.dumps(raw).encode())
    with db.cursor() as q:
        database_schema.verify(q)
        authorize_connection(q, item)
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, item)
    with db.cursor() as q:
        q.execute("SET CONSTRAINTS ALL IMMEDIATE")
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT cve_id FROM evidence_pipeline.current_msrc_update_claims WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == [(raw["Vulnerability"][0]["CVE"],)]
        q.execute(
            "SELECT native_id FROM evidence_pipeline.current_msrc_advisory_claims WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == [("ADV160001",)]


def test_scoped_cell_function_preserves_values_and_duplicate_scope_semantics(db):
    items = [snapshot(), snapshot()]
    with db.cursor() as q:
        database_schema.verify(q)
        for item in items:
            authorize_connection(q, item)
    for item in items:
        with db.cursor() as q:
            q.execute("SET LOCAL ROLE tm_pipeline_writer")
        persist_public(db, item)
        with db.cursor() as q:
            q.execute("RESET ROLE")
    with db.cursor() as q:
        q.execute("SET LOCAL ROLE tm_mock_reader")
        for ids in (
            [],
            [items[0].scope.connection_id],
            [x.scope.connection_id for x in items],
            [items[0].scope.connection_id] * 2,
        ):
            q.execute(
                "SELECT to_jsonb(c) FROM evidence_pipeline.current_product_completeness_cells c "
                "WHERE scope_connections && %s::uuid[] ORDER BY domain,entity_key,field_name",
                (ids,),
            )
            expected = q.fetchall()
            q.execute(
                "SELECT to_jsonb(c) FROM evidence_pipeline.selected_product_completeness_cells(%s::uuid[]) c "
                "ORDER BY domain,entity_key,field_name",
                (ids,),
            )
            assert q.fetchall() == expected
            q.execute(
                "SELECT applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
                (ids,),
            )
            assert q.fetchone() == (len(expected),)


def test_epss_scope_filter_preserves_public_values_and_zero_cells(db):
    from .test_public_snapshot import attempt
    from .test_public_inputs import epss

    item = attempt(epss("CVE-2099-12345,0,0\n"))
    with db.cursor() as q:
        authorize_connection(q, item)
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, item)
    with db.cursor() as q:
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT to_jsonb(p) FROM evidence_pipeline.current_public_epss_observations p WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        previous = q.fetchall()
        assert len(previous) == 1
        q.execute("RESET ROLE")
        database_schema.verify(q)
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT to_jsonb(p) FROM evidence_pipeline.current_public_epss_observations p WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == previous
        q.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='public-epss'",
            ([item.scope.connection_id],),
        )
        assert q.fetchone() == (5, 5)
        q.execute(
            "SELECT field_name,populated FROM evidence_pipeline.selected_product_completeness_cells(%s::uuid[]) WHERE field_name IN ('probability','percentile') ORDER BY field_name",
            ([item.scope.connection_id],),
        )
        assert q.fetchall() == [("percentile", True), ("probability", True)]
