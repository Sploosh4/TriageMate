"""Rolled-back reference authority with constrained writer and application reader."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_store import db  # noqa: F401
from .test_attack_definitions import (
    definition,
    payload as attack_payload,
    scope as attack_scope,
)
from .test_ctid_mappings import payload as ctid_payload, scope as ctid_scope
from .test_exploit_db import payload as exploit_payload, scope as exploit_scope


def snapshot(kind):
    chosen, raw = {
        "exploit": (exploit_scope(), exploit_payload([dict(codes="", verified="0")])),
        "ctid": (ctid_scope(), ctid_payload()),
        "attack": (attack_scope(), attack_payload([definition(revoked=True)])),
    }[kind]
    now = datetime.now(timezone.utc)
    return PublicSnapshot(chosen, str(uuid4()), now, now, "success", True, raw)


def setup(conn, value):
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")

        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


@pytest.mark.parametrize("kind", ["exploit", "ctid", "attack"])
def test_reference_receipts_and_reader_survive_failed_refresh(db, kind):  # noqa: F811
    value = snapshot(kind)
    setup(db, value)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    failed = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        complete=False,
        outcome="failure",
        payload=b"",
        error_code="public_unavailable",
    )
    persist_public(db, failed)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT source_name,collection_attempt_id::text,cve_ids FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        rows = cur.fetchall()
        assert len(rows) == 1 and rows[0][:2] == (
            value.scope.source,
            value.execution_id,
        )
        assert rows[0][2] == (["CVE-2099-1234"] if kind == "ctid" else [])
        if kind == "ctid":
            cur.execute(
                "SELECT mapping_category,technique_id FROM evidence_pipeline.current_ctid_mappings WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert len(cur.fetchall()) == 3
        elif kind == "exploit":
            cur.execute(
                "SELECT publisher_verified FROM evidence_pipeline.current_exploit_metadata WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == (False,)
        else:
            cur.execute(
                "SELECT revoked FROM evidence_pipeline.current_attack_definitions WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == (True,)


@pytest.mark.parametrize("damage", ["omit", "cve", "kind", "native", "fields"])
def test_reference_projection_cannot_be_omitted_or_changed(db, monkeypatch, damage):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store

    value = snapshot("ctid")
    setup(db, value)
    original = public_store._insert_many

    def changed(cur, schema, table, rows, **kwargs):
        if table == "public_reference_observations":
            if damage == "omit":
                return
            changes = {
                "cve": dict(cve_ids=["CVE-2099-9999"]),
                "kind": dict(reference_kind="exploit_metadata"),
                "native": dict(native_id="CVE-2099-9999"),
                "fields": dict(source_fields="{}"),
            }[damage]
            rows = [dict(row, **changes) for row in rows]
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


@pytest.mark.parametrize("kind", ["exploit", "ctid", "attack"])
def test_reference_attribution_detects_projection_tampering(db, kind):  # noqa: F811
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        verify_reference_receipt,
        verify_reference_inventory,
    )

    # The shared synthetic/public database can already contain demonstrated
    # public imports. This test verifies its own receipt, preserving that inventory.
    with db.cursor() as cur:
        cur.execute("SELECT id::text FROM evidence.public_reference_observations")
        existing_inventory = {row[0] for row in cur.fetchall()}
    value = snapshot(kind)
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
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
        claim = cur.fetchone()[0]
        identities, cves = verify_reference_receipt(
            cur, source, revision, receipt, claim
        )
        assert cves == ({"CVE-2099-1234"} if kind == "ctid" else set())
        verify_reference_inventory(cur, existing_inventory | identities)
        with pytest.raises(AssertionError, match="Unexplained public reference"):
            verify_reference_inventory(
                cur, existing_inventory | identities | {str(uuid4())}
            )
        cur.execute(
            "UPDATE evidence.public_reference_observations SET source_fields='{}' WHERE receipt_id=%s",
            (receipt["id"],),
        )
        with pytest.raises(AssertionError, match="Reference projection changed"):
            verify_reference_receipt(cur, source, revision, receipt, claim)


@pytest.mark.parametrize("kind", ["exploit", "ctid", "attack"])
def test_reference_collection_bundle_to_database_replays_offline(
    db,  # noqa: F811
    tmp_path,
    monkeypatch,
    kind,
):
    from standalone.evidence_pipeline.collection import public_collection

    value = snapshot(kind)
    monkeypatch.setattr(
        public_collection, "download", lambda *a, **k: pytest.fail("Unexpected network")
    )
    bundle = tmp_path / "bundle"
    from .test_retained_public_fixture import prepare as fixture_snapshot

    collected = fixture_snapshot(
        value.scope, value.execution_id, bundle, synthetic_payload=value.payload
    )
    setup(db, collected)
    assert not persist_public(db, collected)["replayed"]
    replayed = fixture_snapshot(
        value.scope, value.execution_id, bundle, replay_only=True
    )
    assert replayed == collected
    assert persist_public(db, replayed)["replayed"]


@pytest.mark.parametrize("collision", [False, True])
def test_existing_claim_comparison_preserves_recollection_and_collision_rejection(
    db,  # noqa: F811
    monkeypatch,
    collision,
):
    from standalone.evidence_pipeline.persistence import public_store
    from standalone.evidence_pipeline.persistence.store import ReplayConflict

    value = snapshot("ctid")
    setup(db, value)
    persist_public(db, value)
    later = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
    )
    if collision:
        original = public_store.normalize_public

        def changed(feed):
            for record in original(feed):
                yield replace(record, claim=record.claim + " ")

        monkeypatch.setattr(public_store, "normalize_public", changed)
        with pytest.raises(ReplayConflict, match="claim revision collision"):
            persist_public(db, later)
    else:
        assert not persist_public(db, later)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (later.execution_id,),
        )
        assert cur.fetchone() == ((0,) if collision else (1,))
        cur.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (1,)


@pytest.mark.parametrize("damage", [None, "omit", "native", "kind", "cve", "receipt"])
def test_reused_reference_preserves_receipt_authority(db, monkeypatch, damage):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store
    from standalone.evidence_pipeline.persistence.store import ReplayConflict

    value = snapshot("ctid")
    setup(db, value)
    persist_public(db, value)
    later = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
    )
    original = public_store._reuse_reference
    calls = []

    def changed(cursor, row):
        calls.append(True)
        if damage == "omit":
            return
        updates = {
            "native": dict(native_id="CVE-2099-9999"),
            "kind": dict(reference_kind="exploit_metadata"),
            "cve": dict(cve_ids=["CVE-2099-9999"]),
            "receipt": dict(receipt_id=str(uuid4())),
        }.get(damage, {})
        return original(cursor, dict(row, **updates))

    monkeypatch.setattr(public_store, "_reuse_reference", changed)
    if damage:
        with pytest.raises((psycopg2.Error, ReplayConflict)):
            persist_public(db, later)
    else:
        persist_public(db, later)
    assert calls == [True]
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (later.execution_id,),
        )
        assert cur.fetchone() == (0 if damage else 1,)
        if damage is None:
            cur.execute(
                "SELECT count(DISTINCT o.source_fields),count(DISTINCT o.receipt_id) FROM evidence.public_reference_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == (1, 2)


def test_reused_reference_rejects_changed_prior_source_fields(db):  # noqa: F811
    value = snapshot("ctid")
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "UPDATE evidence.public_reference_observations o SET source_fields='{}' FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE o.receipt_id=r.id AND s.connection_id=%s",
            (value.scope.connection_id,),
        )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    later = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
    )
    with pytest.raises(psycopg2.Error):
        persist_public(db, later)
