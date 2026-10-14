"""Real PostgreSQL checks; generated records roll back in the existing database."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
)

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "pipeline_pg_manage", ROOT / "ui-engine/postgres/manage.py"
)
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


@pytest.fixture
def db():
    try:
        conn = manage.connect()
        # Multi-table attribution checks must see one committed snapshot while
        # authorised collectors continue writing. Own test writes stay visible.
        conn.set_session(isolation_level="REPEATABLE READ")
    except Exception:
        pytest.fail("Local PostgreSQL connection unavailable", pytrace=False)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def snapshot():
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    scope = SourceScope(
        str(uuid4()),
        "Entra",
        "devices",
        "synthetic-writer-test",
        "synthetic",
        "TriageMate generated synthetic fixture",
        str(uuid4()),
    )
    raw = [
        {
            "id": str(uuid4()),
            "deviceId": str(uuid4()),
            "displayName": "Synthetic workstation",
            "isManaged": False,
        }
    ]
    return Snapshot(
        scope,
        str(uuid4()),
        now,
        now + timedelta(seconds=1),
        "success",
        True,
        json.dumps(raw).encode(),
    )


def rows(db, statement, params=()):
    with db.cursor() as cursor:
        cursor.execute(statement, params)
        return cursor.fetchall()


def count(db, table):
    from psycopg2 import sql

    with db.cursor() as cur:
        cur.execute(
            sql.SQL("SELECT count(*) FROM evidence.{}").format(sql.Identifier(table))
        )
        return cur.fetchone()[0]


def test_persist_replay_and_changed_evidence(db, snapshot):
    initial = {
        table: count(db, table)
        for table in (
            "provider_devices",
            "source_revisions",
            "observation_receipts",
            "device_observations",
        )
    }
    assert persist_devices(db, snapshot)["devices"] == 1
    assert persist_devices(db, snapshot)["replayed"]
    assert count(db, "provider_devices") == initial["provider_devices"] + 1
    assert count(db, "device_observations") == initial["device_observations"] + 1
    repeated = replace(
        snapshot,
        execution_id=str(uuid4()),
        finished_at=snapshot.finished_at + timedelta(seconds=1),
    )
    persist_devices(db, repeated)
    assert count(db, "source_revisions") == initial["source_revisions"] + 1
    assert count(db, "observation_receipts") == initial["observation_receipts"] + 2
    changed = replace(
        repeated,
        execution_id=str(uuid4()),
        payload=snapshot.payload.replace(b"false", b"true"),
    )
    persist_devices(db, changed)
    assert count(db, "source_revisions") == initial["source_revisions"] + 2
    values = rows(
        db,
        "SELECT o.managed_flag,o.observed_at FROM evidence.device_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
        (snapshot.execution_id,),
    )
    assert values == [(False, None)]


def test_conflicting_execution_rolls_back_and_leaves_connection_usable(db, snapshot):
    persist_devices(db, snapshot)
    before = count(db, "device_observations")
    with pytest.raises(ReplayConflict):
        persist_devices(db, replace(snapshot, payload=snapshot.payload + b" "))
    assert count(db, "device_observations") == before
    assert rows(db, "SELECT 1") == [(1,)]


def test_scope_reuse_rejected(db, snapshot):
    persist_devices(db, snapshot)
    for field, value in [
        ("tenant_id", str(uuid4())),
        ("scope_reference", "different"),
        ("provenance", "different"),
    ]:
        with pytest.raises(ReplayConflict):
            persist_devices(
                db,
                replace(
                    snapshot,
                    scope=replace(snapshot.scope, **{field: value}),
                    execution_id=str(uuid4()),
                ),
            )


def test_changed_registration_rolls_back_new_attempt_and_receipts(db, snapshot):
    persist_devices(db, snapshot)
    data = json.loads(snapshot.payload)
    data[0]["deviceId"] = str(uuid4())
    before = {
        t: count(db, t)
        for t in ("collection_attempts", "source_revisions", "observation_receipts")
    }
    with pytest.raises(ReplayConflict):
        persist_devices(
            db,
            replace(
                snapshot, execution_id=str(uuid4()), payload=json.dumps(data).encode()
            ),
        )
    assert {t: count(db, t) for t in before} == before


def test_failure_partial_and_empty_have_distinct_receipts(db, snapshot):
    persist_devices(db, snapshot)
    before = count(db, "device_observations")
    for outcome in ("failure", "partial"):
        attempt = replace(
            snapshot,
            execution_id=str(uuid4()),
            outcome=outcome,
            complete=False,
            payload=b"[]",
            error_code="source_unavailable",
        )
        assert persist_devices(db, attempt)["outcome"] == "failure"
        assert rows(
            db,
            "SELECT complete FROM evidence.collection_attempts WHERE id=%s",
            (attempt.execution_id,),
        ) == [(False,)]
    empty = replace(snapshot, execution_id=str(uuid4()), payload=b"[]")
    assert persist_devices(db, empty)["outcome"] == "success"
    assert rows(
        db,
        "SELECT complete FROM evidence.collection_attempts WHERE id=%s",
        (empty.execution_id,),
    ) == [(True,)]
    assert count(db, "device_observations") == before


def test_invalid_tail_cannot_leave_earlier_rows(db, snapshot):
    raw = json.loads(snapshot.payload) + [{"id": str(uuid4()), "isManaged": "wrong"}]
    before = count(db, "collection_attempts")
    with pytest.raises(ValueError):
        persist_devices(db, replace(snapshot, payload=json.dumps(raw).encode()))
    assert count(db, "collection_attempts") == before


def test_no_lab_relabeling_before_provenance_migration(snapshot):
    from standalone.evidence_pipeline.persistence.store import require_lab_schema

    class PriorSchema:
        def execute(self, statement):
            assert "evidence_origin" in statement

        def fetchone(self):
            return None

    with pytest.raises(ValueError, match="provenance-schema"):
        require_lab_schema(PriorSchema(), replace(snapshot.scope, origin="lab"))


def current(db, connection_id):
    from psycopg2.extras import RealDictCursor

    with db.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute(
            "SELECT * FROM evidence_pipeline.current_device_status WHERE connection_id=%s",
            (connection_id,),
        )
        return cursor.fetchall()


def test_current_retains_last_good_after_failure_and_late_arrival(db, snapshot):
    persist_devices(db, snapshot)
    failed = replace(
        snapshot,
        execution_id=str(uuid4()),
        finished_at=snapshot.finished_at + timedelta(hours=1),
        outcome="failure",
        complete=False,
        payload=b"[]",
        error_code="unavailable",
    )
    persist_devices(db, failed)
    (row,) = current(db, snapshot.scope.connection_id)
    assert str(row["selected_attempt_id"]) == snapshot.execution_id
    assert str(row["latest_attempt_id"]) == failed.execution_id
    assert row["source_present"] and row["latest_outcome"] == "failure"
    assert row["reporting_at"] is None  # never substitute collection time
    old = replace(
        snapshot,
        execution_id=str(uuid4()),
        started_at=snapshot.started_at - timedelta(days=1),
        finished_at=snapshot.finished_at - timedelta(days=1),
    )
    persist_devices(db, old)
    (row,) = current(db, snapshot.scope.connection_id)
    assert str(row["selected_attempt_id"]) == snapshot.execution_id


def test_current_empty_preserves_identity_but_does_not_claim_source_presence(
    db, snapshot
):
    persist_devices(db, snapshot)
    empty = replace(
        snapshot,
        execution_id=str(uuid4()),
        payload=b"[]",
        finished_at=snapshot.finished_at + timedelta(hours=1),
    )
    persist_devices(db, empty)
    (row,) = current(db, snapshot.scope.connection_id)
    assert str(row["selected_attempt_id"]) == empty.execution_id
    assert row["source_present"] is False
    assert row["observation_id"] is None and row["display_name"] is None
    assert row["native_device_id"]


def test_ui_reader_cannot_write_device_evidence():
    import psycopg2

    try:
        connection = manage.connect(reader=True)
    except Exception:
        pytest.fail("Local PostgreSQL reader unavailable", pytrace=False)
    try:
        connection.set_session(readonly=False)
        with connection.cursor() as cursor:
            for table in (
                "provider_devices",
                "device_observations",
                "source_connections",
                "collection_attempts",
                "source_revisions",
                "observation_receipts",
            ):
                cursor.execute(
                    "SELECT has_table_privilege(current_user,%s,%s)",
                    ("evidence." + table, "INSERT,UPDATE,DELETE,TRUNCATE"),
                )
                assert cursor.fetchone() == (False,)
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cursor.execute(
                    "INSERT INTO evidence.provider_devices(id,connection_id,native_device_id) VALUES (%s,%s,'forbidden')",
                    (str(uuid4()), str(uuid4())),
                )
    finally:
        connection.rollback()
        connection.close()
