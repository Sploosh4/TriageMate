"""Synthetic advisory persistence exercises real restricted writers and SQL readers."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence import public_store


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from .test_advisory_feeds import fixture
from .test_store import db  # noqa: F401

SOURCES = ["Debian", "Apache HTTP Server", "Apache Tomcat", "Samba", "Cisco"]


def prepare(conn, source):
    scope, payload = fixture(source)
    now = datetime.now(timezone.utc)
    value = PublicSnapshot(scope, str(uuid4()), now, now, "success", True, payload)
    with conn.cursor() as cur:
        if source == "Cisco":
            database_schema.verify(cur)
        else:
            database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return value


@pytest.mark.parametrize("source", SOURCES)
def test_projection_replay_failed_refresh_and_reader(db, source):  # noqa: F811
    # Force deferred constraints inside the rollback-isolated acceptance transaction.
    value = prepare(db, source)
    assert not public_store.persist_public(db, value)["replayed"]
    assert public_store.persist_public(db, value)["replayed"]
    public_store.persist_public(
        db,
        replace(
            value,
            execution_id=str(uuid4()),
            finished_at=value.finished_at + timedelta(seconds=1),
            complete=False,
            outcome="failure",
            payload=b"",
            error_code="synthetic_unavailable",
        ),
    )
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET SESSION AUTHORIZATION")
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            """SELECT collection_attempt_id::text,native_id,cve_ids,source_fields,origin
          FROM evidence_pipeline.current_public_references WHERE connection_id=%s ORDER BY native_id""",
            (value.scope.connection_id,),
        )
        rows = cur.fetchall()
        assert len(rows) == (2 if source == "Debian" else 1)
        assert all(
            row[0] == value.execution_id and row[4] == "synthetic" for row in rows
        )
        if source == "Cisco":
            assert rows[0][1] == "cisco-sa-synthetic-AbC"
            assert (
                rows[0][3]["document"]["document"]["notes"][0]["text"]
                == "Synthetic prose only"
            )
        elif source == "Debian":
            assert rows[0][1:3] == ("empty-package", [])
            assert (
                rows[1][3]["document"]["synthetic-package"]["CVE-2099-1234"][
                    "releases"
                ]["synthetic-future"]["next_point_update"]
                is False
            )
        elif source == "Apache Tomcat":
            assert rows[0][3]["notices"][2]["fixed_release"] is None
        elif source == "Samba":
            assert "only with option X enabled" in rows[0][3]["notice"]["versions_text"]
        else:
            assert (
                rows[0][3]["document"]["timeline"][0]["value"]
                == "Synthetic release candidate only"
            )


@pytest.mark.parametrize("source", SOURCES)
def test_projection_tampering_rejected(db, source, monkeypatch):  # noqa: F811
    value = prepare(db, source)
    original = public_store._insert_many

    def damaged(cursor, schema, table, rows, **kwargs):
        if table == "public_reference_observations":
            rows = [dict(row, source_fields="{}") for row in rows]
        return original(cursor, schema, table, rows, **kwargs)

    monkeypatch.setattr(public_store, "_insert_many", damaged)
    with pytest.raises(psycopg2.Error):
        public_store.persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


@pytest.mark.parametrize("source", SOURCES)
def test_public_origin_follows_enabled_source_policy(db, source):  # noqa: F811
    # Other vendor routes were explicitly enabled by public_vendor_schema.sql.
    # Cisco remains inactive and must not be enabled by writer-side SQL.

    with db.cursor() as cur:
        database_schema.verify(cur)
    value = prepare(db, source)
    public_store.persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            """SELECT p.source_revision_id,p.claim FROM evidence_pipeline.public_claims p
          JOIN evidence.source_revisions r ON r.id=p.source_revision_id WHERE r.connection_id=%s""",
            (value.scope.connection_id,),
        )
        revision, claim = cur.fetchone()
        # Simulate an owner-authorized public connection inside this rolled-back
        # synthetic test. The writer must obey the enabled-source policy.
        cur.execute(
            "UPDATE evidence_pipeline.authorized_connections SET origin='public' WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        cur.execute(
            "UPDATE evidence.source_revisions SET origin='public' WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id=%s",
            (revision,),
        )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        cur.execute("SAVEPOINT public_boundary")
        if source == "Cisco":
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(
                    "INSERT INTO evidence_pipeline.public_claims(source_revision_id,claim) VALUES (%s,%s)",
                    (revision, claim),
                )
        else:
            cur.execute(
                "INSERT INTO evidence_pipeline.public_claims(source_revision_id,claim) VALUES (%s,%s)",
                (revision, claim),
            )
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("ROLLBACK TO SAVEPOINT public_boundary")


def test_complete_empty_tracker_clears_current_but_keeps_history(db):  # noqa: F811
    value = prepare(db, "Debian")
    public_store.persist_public(db, value)
    empty = replace(
        value,
        execution_id=str(uuid4()),
        payload=b"{}",
        finished_at=value.finished_at + timedelta(seconds=1),
    )
    public_store.persist_public(db, empty)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            """SELECT count(*) FROM evidence.public_reference_observations o
          JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s""",
            (value.execution_id,),
        )
        assert cur.fetchone() == (2,)
