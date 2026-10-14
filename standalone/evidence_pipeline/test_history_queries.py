"""Retirement audit: source-time snapshots/diffs, not ingestion-time history."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_store import db as database_fixture, snapshot as snapshot_fixture

db = database_fixture
snapshot = snapshot_fixture

# Only complete successful snapshots participate, including authoritative empty ones.
AS_OF = """
WITH selected AS (
 SELECT id FROM evidence.collection_attempts
 WHERE connection_id=%s AND complete AND outcome='success' AND finished_at <= %s
 ORDER BY finished_at DESC,started_at DESC,id DESC LIMIT 1
)
SELECT o.provider_device_id,o.managed_flag
FROM evidence.device_observations o
JOIN evidence.observation_receipts r ON r.id=o.receipt_id
JOIN selected s ON s.id=r.collection_attempt_id
"""


def _read(db, snapshot, cutoff):
    with db.cursor() as cur:
        cur.execute(AS_OF, (snapshot.scope.connection_id, cutoff))
        return cur.fetchall()


def test_source_time_snapshot_diff_failure_and_empty(db, snapshot):
    first = persist_devices(db, snapshot)
    assert not first["replayed"]
    second = replace(
        snapshot,
        execution_id=str(uuid4()),
        started_at=snapshot.started_at + timedelta(hours=1),
        finished_at=snapshot.finished_at + timedelta(hours=1),
        payload=snapshot.payload.replace(b"false", b"true"),
    )
    persist_devices(db, second)
    before = _read(db, snapshot, snapshot.finished_at)
    after = _read(db, snapshot, second.finished_at)
    assert len(before) == len(after) == 1
    assert before[0][0] == after[0][0]
    assert before[0][1] is False and after[0][1] is True
    with db.cursor() as cur:
        cur.execute(
            "WITH old_snapshot AS ("
            + AS_OF
            + "), new_snapshot AS ("
            + AS_OF
            + ") SELECT o.managed_flag,n.managed_flag FROM old_snapshot o FULL JOIN new_snapshot n USING (provider_device_id) WHERE o.managed_flag IS DISTINCT FROM n.managed_flag",
            (
                snapshot.scope.connection_id,
                snapshot.finished_at,
                snapshot.scope.connection_id,
                second.finished_at,
            ),
        )
        assert cur.fetchall() == [(False, True)]
    failure = replace(
        second,
        execution_id=str(uuid4()),
        finished_at=second.finished_at + timedelta(hours=1),
        outcome="failure",
        complete=False,
        payload=b"timeout",
        error_code="TIMEOUT",
    )
    persist_devices(db, failure)
    assert _read(db, snapshot, failure.finished_at) == after
    empty = replace(
        second,
        execution_id=str(uuid4()),
        finished_at=failure.finished_at + timedelta(hours=1),
        payload=b"[]",
    )
    persist_devices(db, empty)
    assert _read(db, snapshot, empty.finished_at) == []
    assert _read(db, snapshot, snapshot.finished_at) == before


def test_late_import_does_not_establish_what_was_known_then(db, snapshot):
    cutoff = snapshot.finished_at
    assert _read(db, snapshot, cutoff) == []
    # Imported now, but carries an earlier source/collection timestamp.
    persist_devices(db, snapshot)
    assert len(_read(db, snapshot, cutoff)) == 1
    # The same cutoff changes after a late import: this is intentionally NOT an
    # immutable knowledge-time/as-known-at query. Retirement must preserve this gap.
