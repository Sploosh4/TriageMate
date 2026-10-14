from backend.database import schema as database_schema
from backend.database.schema import verify_supported as verify_schema
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection


from standalone.evidence_pipeline.notifications import (
    CollectionAttempt,
    collection_notifications,
)
from standalone.evidence_pipeline.persistence.store import persist_devices
from standalone.evidence_pipeline.test_store import (
    db as database_fixture,
    snapshot as snapshot_fixture,
)

db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def ready(db, snapshot):
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, snapshot)
    return db


def failed(snapshot, hour):
    return replace(
        snapshot,
        execution_id=str(uuid4()),
        complete=False,
        outcome="failure",
        payload=b"[]",
        error_code="unavailable",
        finished_at=snapshot.finished_at + timedelta(hours=hour),
    )


def test_persisted_episode_matches_pure_logic_and_keeps_failed_attempts(
    ready, snapshot
):
    first, second = failed(snapshot, 1), failed(snapshot, 2)
    recovery = replace(snapshot, finished_at=snapshot.finished_at + timedelta(hours=3))
    for item in (first, second, recovery):
        persist_devices(ready, item)
    (expected,) = collection_notifications(
        [
            CollectionAttempt(
                x.execution_id,
                x.scope.connection_id,
                x.started_at,
                x.finished_at,
                x.complete,
                x.outcome,
            )
            for x in (first, second, recovery)
        ]
    )
    with ready.cursor() as cur:
        cur.execute(
            "SELECT id::text,status,failure_count,recovery_attempt_id::text,revision FROM evidence.notifications WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        row = cur.fetchone()
        assert row[:4] == (expected.id, "resolved", 2, recovery.execution_id)
        revision = row[4]
        cur.execute(
            "SELECT evidence_pipeline.refresh_notifications(%s)",
            (snapshot.scope.connection_id,),
        )
        cur.execute(
            "SELECT revision FROM evidence.notifications WHERE id=%s", (expected.id,)
        )
        assert cur.fetchone() == (revision,)
        cur.execute(
            "SELECT outcome FROM evidence.collection_attempts WHERE id=ANY(%s::uuid[]) ORDER BY id",
            ([first.execution_id, second.execution_id],),
        )
        assert cur.fetchall() == [("failure",), ("failure",)]


def test_runtime_writer_cannot_modify_notification_state_directly(ready, snapshot):
    from standalone.evidence_pipeline.test_authority import reject

    with ready.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_devices(ready, failed(snapshot, 1))
    reject(ready, "UPDATE evidence.notifications SET status='resolved'")
    reject(ready, "DELETE FROM evidence.notification_attempts")


def test_new_failure_after_recovery_and_late_history(ready, snapshot):
    first = failed(snapshot, 1)
    recovery = replace(snapshot, finished_at=snapshot.finished_at + timedelta(hours=3))
    newer = failed(snapshot, 4)
    earlier = failed(snapshot, 0)
    for item in (first, recovery, newer, earlier):
        persist_devices(ready, item)
    with ready.cursor() as cur:
        cur.execute(
            "SELECT status,failure_count FROM evidence.notifications WHERE connection_id=%s ORDER BY episode_started_at",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchall() == [("resolved", 2), ("unresolved", 1)]
        cur.execute(
            "SELECT count(*) FROM evidence.notification_attempts a JOIN evidence.notifications n ON n.id=a.notification_id WHERE n.connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (3,)


def test_upgrade_repeats_and_original_verifiers_accept_only_derived_rows(
    ready, snapshot
):
    from standalone.evidence_pipeline.test_attribution import verify as verify_data

    with ready.cursor() as cur:
        before = verify_data(cur)
    persist_devices(ready, failed(snapshot, 1))
    with ready.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)
        assert verify_data(cur)["notifications"] == before.get("notifications", 0) + 1
        cur.execute(
            "UPDATE evidence.notifications SET failure_count=99 WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        with pytest.raises(AssertionError, match="Notification state"):
            verify_data(cur)
