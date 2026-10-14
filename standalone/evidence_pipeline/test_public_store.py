"""Synthetic public DDL/data checks, rolled back in the existing database."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_authority import reject
from .test_public_inputs import kev, nvd, scope, wire
from .test_public_snapshot import attempt
from .test_store import db  # noqa: F401


@pytest.fixture
def public_db(db):  # noqa: F811
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    return db


def test_single_large_projection_preserves_text_and_constraints(db):  # noqa: F811
    import psycopg2

    from standalone.evidence_pipeline.persistence.public_store import _insert_many

    text = "Synthetic 'quoted' \\ text; DROP TABLE ignored; 🐍\n" * 50_000
    with db.cursor() as cursor:
        cursor.execute(
            'CREATE TEMP TABLE "large projection" '
            '(id int PRIMARY KEY CHECK(id>0), "source text" text NOT NULL)'
        )
        value = {"id": 1, "source text": text}
        _insert_many(cursor, "pg_temp", "large projection", [value])
        _insert_many(cursor, "pg_temp", "large projection", [value], conflict=True)
        cursor.execute('SELECT id,"source text" FROM "large projection"')
        assert cursor.fetchall() == [(1, text)]
        cursor.execute("SAVEPOINT invalid_projection")
        with pytest.raises(psycopg2.errors.CheckViolation):
            _insert_many(
                cursor,
                "pg_temp",
                "large projection",
                [{"id": -1, "source text": text}],
            )
        cursor.execute("ROLLBACK TO SAVEPOINT invalid_projection")
        cursor.execute('SELECT count(*) FROM "large projection"')
        assert cursor.fetchone() == (1,)


@pytest.mark.parametrize(
    "source,streamed",
    [("FIRST", False), ("FIRST", True), ("CISA", False), ("NVD", False)],
)
def test_restricted_public_roundtrip_and_replay(public_db, source, streamed, tmp_path):
    value = attempt()
    if source != "FIRST":
        value = PublicSnapshot(
            scope(source),
            value.execution_id,
            value.started_at,
            value.finished_at,
            "success",
            True,
            wire(kev() if source == "CISA" else nvd()),
        )
    if streamed:
        from .test_epss_stream import saved

        value = replace(value, payload=saved(tmp_path, value.payload))
    with public_db.cursor() as cursor:
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert not persist_public(public_db, value)["replayed"]
    assert persist_public(public_db, value)["replayed"]
    again = replace(value, execution_id=str(uuid4()))
    assert not persist_public(public_db, again)["replayed"]
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence_pipeline.public_claims p JOIN evidence.source_revisions r ON r.id=p.source_revision_id WHERE r.connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (1,)
        cursor.execute(
            "SELECT count(*) FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (2,)
    reject(public_db, "DELETE FROM evidence_pipeline.public_claims")
    reject(public_db, "UPDATE evidence.epss_observations SET probability=0")


def test_cannot_relabel_kev_receipt_as_epss_or_another_cve(public_db):
    value = attempt()
    value = PublicSnapshot(
        scope("CISA"),
        value.execution_id,
        value.started_at,
        value.finished_at,
        "success",
        True,
        wire(kev()),
    )
    with public_db.cursor() as cursor:
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(public_db, value)
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s",
            (value.scope.connection_id,),
        )
        receipt = cursor.fetchone()[0]
    reject(
        public_db,
        "INSERT INTO evidence.epss_observations(id,cve_id,receipt_id,probability) VALUES(%s,%s,%s,0.5)",
        (str(uuid4()), "CVE-2026-9999999", receipt),
    )
    reject(
        public_db,
        "INSERT INTO evidence.kev_observations(id,cve_id,receipt_id,membership) VALUES(%s,%s,%s,true)",
        (str(uuid4()), "CVE-2026-9999998", receipt),
    )


@pytest.mark.parametrize(
    "code",
    [
        "invalid_public_input",
        "public_not_found",
        "public_gone",
        "public_access_denied",
        "public_rate_limited",
        "public_unavailable",
        "public_http_failed",
    ],
)
def test_failed_public_attempt_has_no_claims(public_db, code):
    value = replace(attempt(b"invalid public payload", complete=False), error_code=code)
    with public_db.cursor() as cursor:
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert persist_public(public_db, value)["outcome"] == "failure"
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence_pipeline.public_claims p JOIN evidence.source_revisions r ON r.id=p.source_revision_id WHERE r.connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cursor.execute(
            "SELECT outcome,complete,error_code FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cursor.fetchone() == ("failure", False, code)


def test_reader_has_no_public_write_privileges(public_db):
    with public_db.cursor() as cursor:
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cursor.execute("SELECT claim FROM evidence_pipeline.public_claims WHERE false")
        assert cursor.fetchall() == []
    reject(
        public_db,
        "INSERT INTO evidence_pipeline.public_claims VALUES(%s,%s)",
        (str(uuid4()), "{}"),
    )
    reject(
        public_db,
        "INSERT INTO evidence.kev_observations(id,cve_id,receipt_id,membership) VALUES(%s,%s,%s,true)",
        (str(uuid4()), "CVE-2026-9999999", str(uuid4())),
    )


def test_current_public_preserves_failure_but_empty_success_clears(public_db):
    base = attempt()
    value = PublicSnapshot(
        scope("CISA"),
        base.execution_id,
        base.started_at,
        base.finished_at,
        "success",
        True,
        wire(kev()),
    )
    with public_db.cursor() as cursor:
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(public_db, value)
    failure = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        payload=b"transport failed",
        error_code="transport_failed",
    )
    persist_public(public_db, failure)
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT membership,latest_outcome FROM evidence_pipeline.current_public_kev_observations WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchall() == [(True, "failure")]
    empty = kev()
    empty.update(count=0, vulnerabilities=[])
    cleared = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=2),
        payload=wire(empty),
    )
    persist_public(public_db, cleared)
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_kev_observations WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT count(*) FROM evidence.kev_observations e JOIN evidence.observation_receipts r ON r.id=e.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cursor.fetchone() == (1,)


def test_later_batch_failure_rolls_back_earlier_batches(public_db, monkeypatch):
    from standalone.evidence_pipeline.persistence import public_store
    from .test_public_inputs import epss
    import psycopg2

    value = attempt(
        epss("".join(f"CVE-2099-{9100000 + i},0.1,0.2\n" for i in range(251)))
    )
    value = replace(value, scope=replace(value.scope, connection_id=str(uuid4())))
    original = public_store.normalize_public

    def corrupted_tail(feed):
        for index, record in enumerate(original(feed)):
            if index == 250:
                table, fields = record.rows[0]
                fields = tuple(
                    (key, 2 if key == "probability" else val) for key, val in fields
                )
                record = replace(record, rows=((table, fields),))
            yield record

    monkeypatch.setattr(public_store, "normalize_public", corrupted_tail)
    with public_db.cursor() as cursor:
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    with pytest.raises(psycopg2.errors.CheckViolation):
        persist_public(public_db, value)
    with public_db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (0,)
    monkeypatch.setattr(public_store, "normalize_public", original)
    assert not persist_public(public_db, value)["replayed"]


@pytest.mark.parametrize("exception", [ValueError, KeyboardInterrupt])
def test_streamed_epss_later_batch_failure_rolls_back_checked_batches(
    public_db, tmp_path, monkeypatch, exception
):
    from standalone.evidence_pipeline.persistence import public_store
    from .test_epss_stream import saved

    value = attempt()
    raw = (
        b"#model_version:synthetic,score_date:2026-09-16\ncve,epss,percentile\n"
        + b"".join(f"CVE-2099-{10000 + i},0.1,0.5\n".encode() for i in range(600))
    )
    value = replace(value, payload=saved(tmp_path, raw))
    with public_db.cursor() as cur:
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    original = public_store._insert_many
    calls = 0

    def interrupted(cur, schema, table, rows, **kwargs):
        nonlocal calls
        result = original(cur, schema, table, rows, **kwargs)
        if table == "epss_observations":
            calls += 1
            if calls == 2:
                raise exception("Synthetic later-batch failure")
        return result

    monkeypatch.setattr(public_store, "_insert_many", interrupted)
    with pytest.raises(exception):
        persist_public(public_db, value)
    with public_db.cursor() as cur:
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
    assert not persist_public(public_db, value)["replayed"]
    with public_db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (600,)
