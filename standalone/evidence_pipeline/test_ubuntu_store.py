"""Rolled-back Ubuntu publisher authority and distinct OSV relationship views."""

from backend.database import schema as database_schema

from dataclasses import replace
import json
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .test_retained_public_fixture import prepare
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_store import db  # noqa: F401
from .test_osv import document
from .test_ubuntu_advisories import scope
from standalone.evidence_pipeline.parsing.ubuntu_advisories import parse_ubuntu


def setup(conn, value):
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")

        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


def collected(tmp_path, monkeypatch):
    assert PARSERS["Ubuntu", "advisories"] is parse_ubuntu
    raw = dict(
        document(),
        id="USN-9999-1",
        aliases=[],
        upstream=["UBUNTU-CVE-2099-1234"],
        related=["USN-9998-1"],
    )
    return prepare(
        scope("USN-9999-1"),
        str(uuid4()),
        tmp_path / "bundle",
        advisory_id=raw["id"],
        synthetic_payload=json.dumps(raw).encode(),
    )


def test_ubuntu_collection_reader_and_failed_refresh(db, tmp_path, monkeypatch):  # noqa: F811
    value = collected(tmp_path, monkeypatch)
    setup(db, value)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    persist_public(
        db,
        replace(
            value,
            execution_id=str(uuid4()),
            complete=False,
            outcome="failure",
            payload=b"",
            error_code="public_unavailable",
        ),
    )
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        from standalone.evidence_pipeline.persistence.osv_attribution import (
            verify_osv_receipt,
        )

        cur.execute(
            "SELECT to_jsonb(t) FROM evidence.source_connections t WHERE id=%s",
            (value.scope.connection_id,),
        )
        source = cur.fetchone()[0]
        cur.execute(
            "SELECT to_jsonb(t) FROM evidence.source_revisions t WHERE connection_id=%s",
            (source["id"],),
        )
        revision = cur.fetchone()[0]
        cur.execute(
            "SELECT to_jsonb(t) FROM evidence.observation_receipts t WHERE source_revision_id=%s",
            (revision["id"],),
        )
        receipt = cur.fetchone()[0]
        cur.execute(
            "SELECT claim FROM evidence_pipeline.public_claims WHERE source_revision_id=%s",
            (revision["id"],),
        )
        verified, cves = verify_osv_receipt(
            cur, source, revision, receipt, cur.fetchone()[0]
        )
        assert verified["osv_advisory_observations"] and not cves
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT relationship_kind,target_id,source_name FROM evidence_pipeline.current_osv_relationships WHERE connection_id=%s ORDER BY relationship_kind",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [
            ("related", "USN-9998-1", "Ubuntu"),
            ("upstream", "UBUNTU-CVE-2099-1234", "Ubuntu"),
        ]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_osv_aliases WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)


@pytest.mark.parametrize("damage", ["omit", "alter"])
def test_ubuntu_projection_failure_is_atomic(db, tmp_path, monkeypatch, damage):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store

    value = collected(tmp_path, monkeypatch)
    setup(db, value)
    original = public_store._insert_many

    def changed(cur, schema, table, rows, **kwargs):
        if table == "osv_advisory_observations":
            if damage == "omit":
                return
            rows = [dict(row, source_fields="{}") for row in rows]
        return original(cur, schema, table, rows, **kwargs)

    monkeypatch.setattr(public_store, "_insert_many", changed)
    with pytest.raises(psycopg2.Error):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)
