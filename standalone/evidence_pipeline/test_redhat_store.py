"""Native Red Hat notices retain source trees, including notices without CVEs."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import (
    PublicSnapshot,
    PARSERS,
)
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.parsing.redhat_advisories import parse_redhat
from .test_redhat_advisories import scope, document
from .test_store import db  # noqa: F401


def value(monkeypatch, empty=False):
    assert PARSERS["Red Hat", "advisories"] is parse_redhat
    raw = document()
    if empty:
        raw["vulnerabilities"] = []
    now = datetime.now(timezone.utc)
    return PublicSnapshot(
        scope(), str(uuid4()), now, now, "success", True, json.dumps(raw).encode()
    )


def setup(conn, snapshot):
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")

        database_schema.verify(cur)
        authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


@pytest.mark.parametrize("empty", [False, True])
def test_native_notice_replay_and_reader_preserve_tree(db, monkeypatch, empty):  # noqa: F811
    snapshot = value(monkeypatch, empty)
    setup(db, snapshot)
    assert not persist_public(db, snapshot)["replayed"]
    assert persist_public(db, snapshot)["replayed"]
    persist_public(
        db,
        replace(
            snapshot,
            execution_id=str(uuid4()),
            outcome="failure",
            complete=False,
            payload=b"",
            error_code="public_unavailable",
        ),
    )
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT native_id,cve_ids,source_fields->'document' FROM evidence_pipeline.current_vendor_advisories WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        identity, cves, raw = cur.fetchone()
        assert identity == "RHSA-2099:1234"
        assert cves == ([] if empty else ["CVE-2099-9999999"])
        assert raw == json.loads(snapshot.payload)
        cur.execute(
            "SELECT product_id,identification FROM evidence_pipeline.current_vendor_products WHERE connection_id=%s ORDER BY product_id",
            (snapshot.scope.connection_id,),
        )
        rows = cur.fetchall()
        assert len(rows) == 2 and rows[1][1]["purl"].startswith("pkg:rpm/redhat/")
        cur.execute(
            "SELECT relationship_category,combined_product_id FROM evidence_pipeline.current_vendor_relationships WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == ("default_component_of", "combined")


@pytest.mark.parametrize("damage", ["omit", "tree"])
def test_redhat_missing_or_altered_projection_rolls_back(db, monkeypatch, damage):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store

    snapshot = value(monkeypatch)
    setup(db, snapshot)
    original = public_store._insert_many

    def changed(cur, schema, table, rows, **kwargs):
        if table == "public_reference_observations":
            if damage == "omit":
                return
            rows = [dict(row, source_fields="{}") for row in rows]
        return original(cur, schema, table, rows, **kwargs)

    monkeypatch.setattr(public_store, "_insert_many", changed)
    with pytest.raises(psycopg2.Error):
        persist_public(db, snapshot)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (snapshot.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_interruption_after_cve_insert_leaves_no_orphan(db, monkeypatch):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store

    snapshot = value(monkeypatch)
    owned_cve = "CVE-2099-" + str(uuid4().int)[:18]
    snapshot = replace(
        snapshot,
        payload=snapshot.payload.replace(b"CVE-2099-9999999", owned_cve.encode()),
    )
    setup(db, snapshot)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id=%s",
            (owned_cve,),
        )
        assert cur.fetchone() == (0,)
    original = public_store._insert_many
    interrupted = []

    def interrupt_after_insert(cur, schema, table, rows, **kwargs):
        original(cur, schema, table, rows, **kwargs)
        if table == "vulnerabilities":
            interrupted.append(True)
            raise KeyboardInterrupt("synthetic cancellation after CVE insertion")

    monkeypatch.setattr(public_store, "_insert_many", interrupt_after_insert)
    with pytest.raises(KeyboardInterrupt):
        persist_public(db, snapshot)
    assert interrupted == [True]
    # Catching cancellation must leave this same transaction usable and clean.
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id=%s",
            (owned_cve,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (snapshot.execution_id,),
        )
        assert cur.fetchone() == (0,)
