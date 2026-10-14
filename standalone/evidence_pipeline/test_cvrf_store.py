"""CVRF authority is exercised in a rolled-back synthetic transaction."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4
import json

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_updates import document, source
from .test_store import db as db


def snapshot():
    now = datetime.now(timezone.utc)
    return PublicSnapshot(
        source(),
        str(uuid4()),
        now,
        now,
        "success",
        True,
        json.dumps(document()).encode(),
    )


def prepare(connection):
    value = snapshot()
    with connection.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return value


@pytest.mark.parametrize("streamed", [False, True])
def test_restricted_update_relationship_roundtrip(db, tmp_path, streamed):
    value = prepare(db)
    if streamed:
        from .test_cvrf_stream import saved

        value = replace(value, payload=saved(tmp_path, value.payload))
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            """SELECT p.source_patch_id,old.source_patch_id,a.software_product
            FROM evidence.patch_replacements r
            JOIN evidence.patches p ON p.id=r.patch_id
            JOIN evidence.patches old ON old.id=r.superseded_patch_id
            JOIN evidence.patch_applicability a ON a.patch_id=p.id
            JOIN evidence.observation_receipts receipt ON receipt.id=r.receipt_id
            WHERE receipt.collection_attempt_id=%s""",
            (value.execution_id,),
        )
        assert cur.fetchall() == [
            ("KB9999991", "KB9999990", "Synthetic product release A")
        ]
    failure = replace(
        value,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        payload=b"invalid",
        error_code="invalid_public_payload",
    )
    assert persist_public(db, failure)["outcome"] == "failure"
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_msrc_patch_fixes WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (1,)
    from datetime import timedelta

    raw = document()
    raw["Vulnerability"] = []
    empty = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        payload=json.dumps(raw).encode(),
    )
    persist_public(db, empty)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        for view in (
            "current_msrc_patch_fixes",
            "current_msrc_patch_replacements",
            "current_msrc_update_claims",
        ):
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline."
                + view
                + " WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.patch_replacements WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (value.execution_id,),
        )
        assert cur.fetchone() == (1,)


@pytest.mark.parametrize("mutation", ["field", "omit", "cross_product"])
@pytest.mark.parametrize("streamed", [False, True])
def test_projection_tampering_rolls_back_entire_attempt(
    db,
    monkeypatch,
    mutation,
    tmp_path,
    streamed,
):
    from standalone.evidence_pipeline.parsing.cvrf_records import UpdateRecord

    original = UpdateRecord.evidence_rows
    value = prepare(db)
    if streamed:
        from .test_cvrf_stream import saved

        value = replace(value, payload=saved(tmp_path, value.payload))

    def changed(self, receipt):
        for table, row in original(self, receipt):
            if table == "patch_applicability":
                if mutation == "omit":
                    continue
                if mutation == "field":
                    row["version_expression"] = "invented range"
            if table == "patches" and mutation == "cross_product":
                row["product_names"] = ["Synthetic unrelated product"]
            yield table, row

    monkeypatch.setattr(UpdateRecord, "evidence_rows", changed)
    with pytest.raises(Exception, match="CVRF"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_no_fix_claim_and_empty_success_are_preserved(db):
    value = prepare(db)
    raw = document()
    raw["Vulnerability"][0]["Remediations"] = []
    value = replace(value, payload=json.dumps(raw).encode())
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            """SELECT claim::jsonb->'record'->'updates' FROM evidence_pipeline.public_claims c
            JOIN evidence.observation_receipts r ON r.source_revision_id=c.source_revision_id
            WHERE r.collection_attempt_id=%s""",
            (value.execution_id,),
        )
        assert cur.fetchone() == ([],)
    raw["Vulnerability"] = []
    empty = replace(value, execution_id=str(uuid4()), payload=json.dumps(raw).encode())
    assert persist_public(db, empty)["outcome"] == "success"


def test_one_kb_for_many_products_preserves_each_explicit_identity(db):
    value = prepare(db)
    raw = document()
    targets = [f"p{i}" for i in range(50)]
    raw["ProductTree"]["FullProductName"] = [
        {"ProductID": product, "Value": "Synthetic shared product label"}
        for product in targets
    ]
    item = raw["Vulnerability"][0]
    item["ProductStatuses"][0]["ProductID"] = targets
    item["Remediations"] = [{**item["Remediations"][0], "ProductID": targets}]
    with db.cursor() as cur:
        cur.execute("SET LOCAL statement_timeout=20000")
    persist_public(db, replace(value, payload=json.dumps(raw).encode()))
    with db.cursor() as cur:
        cur.execute(
            """SELECT source_product_id,source_patch_id FROM evidence_pipeline.current_msrc_patch_fixes
            WHERE connection_id=%s ORDER BY source_product_id""",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [(product, "KB9999991") for product in sorted(targets)]
        cur.execute(
            """SELECT count(*) FROM evidence_pipeline.current_msrc_patch_replacements
            WHERE connection_id=%s""",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (50,)


def test_extra_rows_and_writer_mutation_are_rejected(db):
    from .test_authority import reject
    from standalone.evidence_pipeline.persistence.store import atomic
    import psycopg2

    value = prepare(db)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (value.execution_id,),
        )
        (receipt,) = cur.fetchone()
        with pytest.raises(psycopg2.Error, match="row-level security"):
            with atomic(cur):
                cur.execute(
                    """INSERT INTO evidence.patches(id,source_patch_id,receipt_id,title)
                    VALUES(%s,'KB9999999',%s,'Synthetic invented patch')""",
                    (str(uuid4()), receipt),
                )
    for table in (
        "evidence_pipeline.cvrf_projection",
        "evidence_pipeline.cvrf_batches",
        "evidence.patch_applicability",
        "evidence.patch_replacements",
    ):
        reject(db, "DELETE FROM " + table)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            """SELECT count(*) FROM evidence.patch_replacements p
            JOIN evidence.observation_receipts r ON r.id=p.receipt_id
            WHERE r.collection_attempt_id=%s""",
            (value.execution_id,),
        )
        assert cur.fetchone() == (1,)
    reject(db, "INSERT INTO evidence.patch_replacements DEFAULT VALUES")


def test_product_scope_cannot_relax_legacy_patch_uniqueness(db):
    from .test_csaf_store import snapshot as advisory_snapshot
    from standalone.evidence_pipeline.persistence.store import atomic
    import psycopg2

    prepare(db)
    value = advisory_snapshot()
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT p.source_patch_id,p.receipt_id FROM evidence.patches p JOIN evidence.observation_receipts r ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        patch, receipt = cur.fetchone()
        with pytest.raises(psycopg2.Error, match="CVRF source"):
            with atomic(cur):
                cur.execute(
                    "INSERT INTO evidence.patches(id,source_patch_id,receipt_id,title,source_product_id) VALUES(%s,%s,%s,'Synthetic duplicate','p2')",
                    (str(uuid4()), patch, receipt),
                )
    with (
        db.cursor() as cur,
        pytest.raises(psycopg2.errors.UniqueViolation),
        atomic(cur),
    ):
        cur.execute(
            "INSERT INTO evidence.patches(id,source_patch_id,receipt_id,title) VALUES(%s,%s,%s,'Synthetic duplicate')",
            (str(uuid4()), patch, receipt),
        )


@pytest.mark.parametrize("interruption", [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("streamed", [False, True])
def test_later_batch_failure_rolls_back_already_validated_receipts(
    db,
    monkeypatch,
    tmp_path,
    interruption,
    streamed,
):
    from standalone.evidence_pipeline.persistence import public_store

    value = prepare(db)
    raw = json.loads(value.payload)
    raw["Vulnerability"].append({**raw["Vulnerability"][0], "CVE": "CVE-2026-99998"})
    value = replace(value, payload=json.dumps(raw).encode())
    if streamed:
        from .test_cvrf_stream import saved

        value = replace(value, payload=saved(tmp_path, value.payload))
    import sqlite3
    from contextlib import contextmanager
    from standalone.evidence_pipeline.parsing import cvrf_stream
    from standalone.evidence_pipeline import json_stream
    from .temporary_index import temporary_index

    connections = []

    @contextmanager
    def temporary():
        with temporary_index() as connection:
            connections.append(connection)
            yield connection

    monkeypatch.setattr(cvrf_stream, "temporary_index", temporary)
    monkeypatch.setattr(json_stream, "temporary_index", temporary)
    monkeypatch.setattr(
        public_store, "_batches", lambda records: ([record] for record in records)
    )
    original = public_store._insert_many
    batches = 0

    def fail_second(cursor, schema, table, values, conflict=False):
        nonlocal batches
        if table == "cvrf_batches":
            batches += 1
            if batches == 2:
                raise interruption("synthetic interrupted second batch")
        return original(cursor, schema, table, values, conflict)

    monkeypatch.setattr(public_store, "_insert_many", fail_second)
    with pytest.raises(interruption, match="second batch") as interrupted:
        persist_public(db, value)
    assert interrupted.value is not None  # Keep traceback alive while checking cleanup.
    if streamed:
        assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
    assert batches == 2
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
    monkeypatch.setattr(public_store, "_insert_many", original)
    assert not persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_untargeted_status_persists_raw_without_patch_rows(db):
    value = prepare(db)
    raw = document()
    raw["Vulnerability"][0]["ProductStatuses"] = [{"Type": 3}]
    raw["Vulnerability"][0]["Remediations"] = []
    value = replace(value, payload=json.dumps(raw).encode())
    assert persist_public(db, value)["outcome"] == "success"
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT c.claim::jsonb->'source_vulnerability'->'ProductStatuses' "
            "FROM evidence_pipeline.public_claims c JOIN evidence.observation_receipts r "
            "ON r.source_revision_id=c.source_revision_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchall() == [([{"Type": 3}],)]
        cur.execute(
            "SELECT count(*) FROM evidence.patches p JOIN evidence.observation_receipts r "
            "ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


@pytest.mark.parametrize("streamed", [False, True])
def test_absent_vulnerability_publication_persists_zero_receipts(
    db, tmp_path, streamed
):
    from .test_cvrf_stream import empty_publication, saved

    value = snapshot()
    value = replace(
        value,
        scope=replace(
            value.scope,
            scope_reference="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2017-May-B",
        ),
        payload=json.dumps(empty_publication()).encode(),
    )
    if streamed:
        value = replace(value, payload=saved(tmp_path, value.payload))
    with db.cursor() as cur:
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT outcome,complete,input_fingerprint FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == ("success", True, value.input_fingerprint)
        cur.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_msrc_update_claims WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
