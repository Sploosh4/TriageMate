"""Draft query storage tested with rollback and synthetic source pages only."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4

import psycopg2
import pytest
from standalone.evidence_pipeline.source_json import encode_source_records
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .contracts import Snapshot
from standalone.evidence_pipeline.parsing.osv_query import URL, query_bytes
from .test_retained_public_fixture import query_fixture as prepare
from standalone.evidence_pipeline.persistence.osv_query_snapshot import from_collection
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import atomic, stage_attempt
from .test_osv import scope, document
from .test_store import db  # noqa: F401


def collection(tmp_path, chosen=None, pages=None, name="synthetic-package"):
    chosen = chosen or replace(scope(), scope_reference=URL)
    execution = str(uuid4())
    if pages is None:
        pages = [encode_source_records({"vulns": [document()]})]
    return from_collection(
        prepare(
            chosen,
            execution,
            tmp_path / execution,
            name=name,
            ecosystem="PyPI",
            synthetic_pages=pages,
        )
    )


def setup(connection, value):
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")

        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute(
            "INSERT INTO evidence_pipeline.osv_query_bindings VALUES(%s,%s)",
            (
                value.scope.connection_id,
                query_bytes(Snapshot.records(value)[0]["query"]).decode(),
            ),
        )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


def flush(connection):
    from standalone.evidence_pipeline.persistence.osv_query_attribution import (
        verify_osv_queries,
    )

    with connection.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        cur.execute("RESET SESSION AUTHORIZATION")
        verify_osv_queries(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


def test_query_receipts_pages_replay_and_actual_reader(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    assert not persist_public(db, value)["replayed"]
    flush(db)
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT query,page_count,outcome,origin FROM evidence_pipeline.osv_query_history WHERE collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchall() == [
            (
                {"package": {"name": "synthetic-package", "ecosystem": "PyPI"}},
                1,
                "success",
                "synthetic",
            )
        ]
        cur.execute(
            "SELECT l.page_index,l.record_index,o.advisory_id FROM evidence_pipeline.osv_query_advisory_links l JOIN evidence.osv_advisory_observations o ON o.receipt_id=l.receipt_id WHERE l.attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchall() == [(0, 0, "x_synthetic-advisory")]


def test_repeated_advisory_retains_positions_without_duplicate_observations(
    db,  # noqa: F811
    tmp_path,
):
    raw = document()
    value = collection(
        tmp_path,
        pages=[
            encode_source_records({"vulns": [raw], "next_page_token": "next"}),
            encode_source_records({"vulns": [raw]}),
        ],
    )
    setup(db, value)
    persist_public(db, value)
    flush(db)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*),count(DISTINCT receipt_id) FROM evidence_pipeline.osv_query_advisory_links WHERE attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (2, 1)


def test_failure_keeps_previous_current_and_empty_success_replaces_it(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    persist_public(db, value)
    failed = collection(tmp_path, value.scope, [b"synthetic invalid response"])
    persist_public(db, failed)
    flush(db)
    with db.cursor() as cur:
        cur.execute(
            "SELECT collection_attempt_id::text FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [(value.execution_id,)]
    empty = collection(tmp_path, value.scope, [b"{}"])
    persist_public(db, empty)
    flush(db)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT wire FROM evidence_pipeline.osv_query_pages WHERE attempt_id=%s",
            (failed.execution_id,),
        )
        assert bytes(cur.fetchone()[0]) == b"synthetic invalid response"


def test_connection_cannot_be_reused_for_changed_query(db, tmp_path):  # noqa: F811
    first = collection(tmp_path)
    setup(db, first)
    other = collection(tmp_path, first.scope, name="different-synthetic-package")
    with db.cursor() as cur, atomic(cur):
        with pytest.raises(psycopg2.Error):
            persist_public(db, other)


def test_query_attempt_cannot_omit_manifest(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    with db.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="manifest"):
            with atomic(cur):
                stage_attempt(cur, value)
                cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize("table", ["osv_query_pages", "osv_query_advisory_links"])
def test_missing_page_or_link_rolls_back_whole_import(db, tmp_path, monkeypatch, table):  # noqa: F811
    from standalone.evidence_pipeline.persistence import osv_query_store

    value = collection(tmp_path)
    setup(db, value)
    if table.endswith("links"):
        monkeypatch.setattr(osv_query_store, "link_advisories", lambda *args: None)
    else:

        def omit_pages(cur, snapshot):
            cur.execute(
                "INSERT INTO evidence_pipeline.osv_query_batches VALUES(%s,%s)",
                (snapshot.execution_id, snapshot.payload.decode()),
            )

        monkeypatch.setattr(osv_query_store, "stage_context", omit_pages)
        monkeypatch.setattr(osv_query_store, "link_advisories", lambda *args: None)
    with db.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="incomplete"):
            with atomic(cur):
                persist_public(db, value)
                cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_changed_wire_is_rejected_before_database_mutation(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    with pytest.raises(ValueError, match="manifest"):
        replace(
            value, responses=(replace(value.responses[0], wire=b"{}", payload=b"{}"),)
        )


def test_conflicting_revisions_within_query_do_not_choose_a_winner(tmp_path):
    original = document()
    changed = dict(original, summary="different synthetic revision")
    with pytest.raises(ValueError, match="conflicting revisions"):
        collection(
            tmp_path, pages=[encode_source_records({"vulns": [original, changed]})]
        )


def test_swapped_valid_advisory_receipts_are_rejected_at_transaction_end(
    db,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    from standalone.evidence_pipeline.persistence import osv_query_store

    first = document()
    second = dict(first, id="x_synthetic-second")
    value = collection(
        tmp_path, pages=[encode_source_records({"vulns": [first, second]})]
    )
    setup(db, value)

    def swapped(cursor, snapshot):
        cursor.execute(
            "SELECT o.receipt_id::text FROM evidence.osv_advisory_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s ORDER BY o.advisory_id DESC",
            (snapshot.execution_id,),
        )
        receipts = [row[0] for row in cursor.fetchall()]
        assert len(receipts) == 2
        for index, receipt in enumerate(receipts):
            cursor.execute(
                "INSERT INTO evidence_pipeline.osv_query_advisory_links VALUES(%s,0,%s,%s)",
                (snapshot.execution_id, index, receipt),
            )

    monkeypatch.setattr(osv_query_store, "link_advisories", swapped)
    with pytest.raises(psycopg2.Error, match="row-level security"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_bom_and_exact_decimal_source_page_match(db, tmp_path):  # noqa: F811
    from decimal import Decimal

    raw = document()
    raw["database_specific"] = {"synthetic_value": Decimal("0.123456789123456789")}
    value = collection(
        tmp_path, pages=[b"\xef\xbb\xbf" + encode_source_records({"vulns": [raw]})]
    )
    setup(db, value)
    persist_public(db, value)
    flush(db)
    with db.cursor() as cur:
        cur.execute(
            "SELECT source_fields->'database_specific'->>'synthetic_value' FROM evidence.osv_advisory_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == ("0.123456789123456789",)


@pytest.mark.parametrize("mutation", ["page", "link", "binding", "update", "delete"])
def test_writer_cannot_change_query_evidence_or_add_unmatched_rows(
    db,  # noqa: F811
    tmp_path,
    mutation,
):
    value = collection(tmp_path)
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        with pytest.raises(psycopg2.Error):
            with atomic(cur):
                if mutation == "page":
                    cur.execute(
                        "INSERT INTO evidence_pipeline.osv_query_pages VALUES(%s,1,%s)",
                        (value.execution_id, b"{}"),
                    )
                elif mutation == "link":
                    cur.execute(
                        "INSERT INTO evidence_pipeline.osv_query_advisory_links SELECT attempt_id,page_index,99,receipt_id FROM evidence_pipeline.osv_query_advisory_links WHERE attempt_id=%s",
                        (value.execution_id,),
                    )
                elif mutation == "binding":
                    cur.execute(
                        "UPDATE evidence_pipeline.osv_query_bindings SET query_document='{}' WHERE connection_id=%s",
                        (value.scope.connection_id,),
                    )
                elif mutation == "update":
                    cur.execute(
                        "UPDATE evidence_pipeline.osv_query_pages SET wire=%s WHERE attempt_id=%s",
                        (b"{}", value.execution_id),
                    )
                else:
                    cur.execute(
                        "DELETE FROM evidence_pipeline.osv_query_batches WHERE attempt_id=%s",
                        (value.execution_id,),
                    )


def test_reader_cannot_insert_query_evidence(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        with pytest.raises(psycopg2.Error):
            with atomic(cur):
                cur.execute(
                    "INSERT INTO evidence_pipeline.osv_query_batches VALUES(%s,%s)",
                    (value.execution_id, value.payload.decode()),
                )


def test_writer_cannot_supply_forged_record_hashes(db, tmp_path):  # noqa: F811
    value = collection(tmp_path)
    setup(db, value)
    with db.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="row-level security"):
            with atomic(cur):
                stage_attempt(cur, value)
                cur.execute(
                    "INSERT INTO evidence_pipeline.osv_query_batches VALUES(%s,%s)",
                    (value.execution_id, value.payload.decode()),
                )
                cur.execute(
                    "INSERT INTO evidence_pipeline.osv_query_pages VALUES(%s,0,%s,ARRAY['forged'])",
                    (value.execution_id, value.responses[0].wire),
                )


@pytest.mark.full_baseline
def test_query_evidence_passes_full_retained_attribution(db, tmp_path):  # noqa: F811
    from .test_attribution import verify

    value = collection(tmp_path)
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)


@pytest.mark.parametrize(
    "mutation", ["wire", "binding", "position", "manifest", "hashes"]
)
def test_readonly_audit_detects_changed_query_evidence(db, tmp_path, mutation):  # noqa: F811
    from standalone.evidence_pipeline.persistence.osv_query_attribution import (
        verify_osv_queries,
    )

    value = collection(tmp_path)
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify_osv_queries(cur)
        if mutation == "wire":
            cur.execute(
                "UPDATE evidence_pipeline.osv_query_pages SET wire=%s WHERE attempt_id=%s",
                (b"{}", value.execution_id),
            )
        elif mutation == "binding":
            cur.execute(
                "UPDATE evidence_pipeline.osv_query_bindings SET query_document=%s WHERE connection_id=%s",
                (
                    '{"package":{"name":"other-synthetic-package","ecosystem":"PyPI"}}',
                    value.scope.connection_id,
                ),
            )
        elif mutation == "position":
            cur.execute(
                "UPDATE evidence_pipeline.osv_query_advisory_links SET record_index=99 WHERE attempt_id=%s",
                (value.execution_id,),
            )
        elif mutation == "hashes":
            cur.execute(
                "UPDATE evidence_pipeline.osv_query_pages SET record_hashes=ARRAY['invalid'] WHERE attempt_id=%s",
                (value.execution_id,),
            )
        else:
            cur.execute(
                "UPDATE evidence_pipeline.osv_query_batches SET manifest='[{}]' WHERE attempt_id=%s",
                (value.execution_id,),
            )
        with pytest.raises((AssertionError, ValueError, KeyError)):
            verify_osv_queries(cur)
