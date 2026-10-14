"""Restricted OSV storage in rolled-back synthetic PostgreSQL transactions."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
import psycopg2

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.osv import parse_osv
from standalone.evidence_pipeline.parsing.osv_records import OsvPublicRecord
from standalone.evidence_pipeline.parsing.public_snapshot import (
    PARSERS,
    PublicSnapshot,
)
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import atomic
from .test_osv import document, scope
from .test_store import db  # noqa: F401


def prepare(connection, monkeypatch, aliases=True):
    monkeypatch.setitem(PARSERS, ("OSV", "advisories"), parse_osv)
    raw = document()
    if not aliases:
        raw["aliases"] = []
    now = datetime.now(timezone.utc)
    value = PublicSnapshot(
        scope(), str(uuid4()), now, now, "success", True, json.dumps(raw).encode()
    )
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return value


@pytest.mark.parametrize("aliases", [False, True])
def test_native_identity_replay_failure_and_withdrawal(db, monkeypatch, aliases):  # noqa: F811
    value = prepare(db, monkeypatch, aliases)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT advisory_id,withdrawn_text FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("x_synthetic-advisory", None)]
        cur.execute(
            "SELECT alias_id FROM evidence_pipeline.current_osv_aliases WHERE connection_id=%s ORDER BY alias_index",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == (
            [("CVE-2099-1234",), ("CVE-2099-5678",)] if aliases else []
        )
        cur.execute(
            "SELECT package_name,ecosystem FROM evidence_pipeline.current_osv_affected_packages WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("synthetic-package", "PyPI")]
    failed = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="public_transport_failed",
    )
    assert persist_public(db, failed)["outcome"] == "failure"
    raw = json.loads(value.payload)
    raw["withdrawn"] = "2026-09-14T02:00:00Z"
    withdrawn = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=2),
        payload=json.dumps(raw).encode(),
    )
    persist_public(db, withdrawn)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT advisory_id,withdrawn_text FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("x_synthetic-advisory", raw["withdrawn"])]
        cur.execute(
            "SELECT count(*) FROM evidence.osv_advisory_observations WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (value.execution_id,),
        )
        assert cur.fetchone() == (1,)


@pytest.mark.parametrize(
    "damage", ["omit", "alias", "package", "identity", "duplicate"]
)
def test_damaged_projection_rolls_back_attempt(db, monkeypatch, damage):  # noqa: F811
    value = prepare(db, monkeypatch)
    original = OsvPublicRecord.evidence_rows

    def changed(self, receipt):
        for table, row in original(self, receipt):
            if table == "osv_aliases":
                if damage == "omit":
                    continue
                if damage == "alias":
                    row["alias_id"] = "CVE-2099-9999"
                if damage == "identity":
                    row["advisory_id"] = "x_unrelated"
                if damage == "duplicate":
                    yield table, {**row, "id": str(uuid4())}
            if table == "osv_affected_packages" and damage == "package":
                row["ecosystem"] = "npm"
            yield table, row

    monkeypatch.setattr(OsvPublicRecord, "evidence_rows", changed)
    with pytest.raises(psycopg2.Error, match="OSV|row-level security|duplicate key"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_completed_advisory_rejects_extra_alias_and_mutation(db, monkeypatch):  # noqa: F811
    from .test_authority import reject

    value = prepare(db, monkeypatch)
    persist_public(db, value)
    with (
        db.cursor() as cur,
        pytest.raises(
            psycopg2.errors.InsufficientPrivilege, match="row-level security"
        ),
        atomic(cur),
    ):
        cur.execute(
            "INSERT INTO evidence.osv_aliases SELECT %s,receipt_id,advisory_id,99,'CVE-2099-9999' FROM evidence.osv_aliases LIMIT 1",
            (str(uuid4()),),
        )
    for table in ("osv_advisory_observations", "osv_aliases", "osv_affected_packages"):
        reject(db, "DELETE FROM evidence." + table)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
    reject(db, "INSERT INTO evidence.osv_aliases DEFAULT VALUES")


def test_attribution_checks_native_identity_and_package_fields(db, monkeypatch):  # noqa: F811
    from standalone.evidence_pipeline.persistence.osv_attribution import (
        verify_osv_receipt,
        verify_osv_inventory,
    )

    value = prepare(db, monkeypatch)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT to_jsonb(c),to_jsonb(rev),to_jsonb(r),p.claim FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id JOIN evidence.source_connections c ON c.id=rev.connection_id JOIN evidence_pipeline.public_claims p ON p.source_revision_id=rev.id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        source, revision, receipt, claim = cur.fetchone()
        verified, cves = verify_osv_receipt(cur, source, revision, receipt, claim)
        assert cves == {"CVE-2099-1234", "CVE-2099-5678"}
        assert revision["source_record_id"] == "x_synthetic-advisory"
        cur.execute("RESET SESSION AUTHORIZATION")
        verify_osv_inventory(cur, verified)
        cur.execute(
            "UPDATE evidence.osv_affected_packages SET ecosystem='npm' WHERE receipt_id=%s",
            (receipt["id"],),
        )
        with pytest.raises(AssertionError, match="OSV projection changed"):
            verify_osv_receipt(cur, source, revision, receipt, claim)


def test_unknown_claimed_projection_is_not_silently_ignored(db, monkeypatch):  # noqa: F811
    import hashlib
    from standalone.evidence_pipeline.persistence import public_store

    value = prepare(db, monkeypatch)
    original = public_store.normalize_public

    def changed(feed):
        for record in original(feed):
            claim = json.loads(record.claim)
            claim["projection"].append(["unrecognized_table", {}])
            text = json.dumps(claim)
            yield replace(
                record,
                claim=text,
                content_hash=hashlib.sha256(text.encode()).hexdigest(),
            )

    monkeypatch.setattr(public_store, "normalize_public", changed)
    with pytest.raises(psycopg2.Error, match="Unexpected OSV projection"):
        persist_public(db, value)


@pytest.mark.parametrize("aliases", [False, True])
def test_full_attribution_accepts_native_advisories(db, monkeypatch, aliases):  # noqa: F811
    from .test_attribution import verify

    value = prepare(db, monkeypatch, aliases)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)
