"""Revision checks and notice journaling use the actual restricted database role."""

from uuid import uuid4

import psycopg2
import pytest

from backend.database import schema as database_schema
from standalone.evidence_pipeline.test_store import db  # noqa: F401

from . import store
from .checkpoint import encode
from .test_checkpoint import running_state
from .test_dispatch import at

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def prepare(connection):
    with connection.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


def test_checkpoint_roundtrip_and_competing_writer_conflict(db):  # noqa: F811
    prepare(db)
    key, original = str(uuid4()), running_state()
    with db.cursor() as cur:
        assert store.load(cur, key) is None
        assert store.save(cur, key, 0, original) == 1
        revision, restored = store.load(cur, key)
        assert revision == 1 and encode(restored) == encode(original)
        with pytest.raises(store.CheckpointConflict):
            store.save(cur, key, 0, original)
        actions = restored.tick(at(1801))
        assert store.save(cur, key, 1, restored, notices=actions.notices) == 2
        with pytest.raises(store.CheckpointConflict):
            store.save(cur, key, 1, original, notices=actions.notices)
        cur.execute(
            "SELECT checkpoint_revision,event FROM evidence_pipeline.operation_events WHERE service_key=%s",
            (key,),
        )
        events = cur.fetchall()
        assert len(events) == 1 and events[0][0] == 2
        assert events[0][1]["kind"] == "overlap_opened"
        assert events[0][1]["skipped_count"] == 2
        assert store.load(cur, key)[0] == 2


@pytest.mark.parametrize("kind", ["repository", "enrichment"])
def test_repository_notice_source_is_committed_with_event(db, kind):  # noqa: F811
    prepare(db)
    key, state = str(uuid4()), running_state()
    actions = state.tick(at(1801))
    source = {
        "source": "Ubuntu" if kind == "repository" else "NVD",
        "origin": "synthetic",
    }
    with db.cursor() as cur:
        store.save(
            cur,
            key,
            0,
            state,
            notices=actions.notices,
            **{kind + "_sources": {actions.notices[0].input_id: source}},
        )
        cur.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s",
            (key,),
        )
        assert cur.fetchone()[0][kind + "_scope"] == source
        assert store.load(cur, key)[0] == 1


def test_rolled_back_checkpoint_does_not_consume_revision_or_notice(db):  # noqa: F811
    prepare(db)
    key, original = str(uuid4()), running_state()
    with db.cursor() as cur:
        store.save(cur, key, 0, original)
        cur.execute("SAVEPOINT before_decision")
        actions = original.tick(at(1801))
        store.save(cur, key, 1, original, notices=actions.notices)
        cur.execute("ROLLBACK TO SAVEPOINT before_decision")
        revision, restored = store.load(cur, key)
        assert revision == 1
        assert restored.tick(at(1801)).notices == actions.notices
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
            (key,),
        )
        assert cur.fetchone() == (0,)


def test_query_reader_sees_status_without_raw_checkpoint_or_write_authority(db):  # noqa: F811
    prepare(db)
    key, value = str(uuid4()), running_state()
    with db.cursor() as cur:
        store.save(cur, key, 0, value)
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT requested_mode,state,active_runs FROM evidence_pipeline.operation_status WHERE service_key=%s",
            (key,),
        )
        assert cur.fetchone() == ("running", "running", 0)
        for statement in [
            "SELECT document FROM evidence_pipeline.operation_checkpoints",
            "UPDATE evidence_pipeline.operation_checkpoints SET document='{}'::jsonb",
            "DELETE FROM evidence_pipeline.operation_events",
        ]:
            cur.execute("SAVEPOINT reader_boundary")
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(statement)
            cur.execute("ROLLBACK TO SAVEPOINT reader_boundary")


def test_corrupt_checkpoint_is_reported_and_retained(db):  # noqa: F811
    prepare(db)
    key = str(uuid4())
    with db.cursor() as cur:
        store.save(cur, key, 0, running_state())
        cur.execute(
            "UPDATE evidence_pipeline.operation_checkpoints SET document='{}'::jsonb WHERE service_key=%s",
            (key,),
        )
        with pytest.raises(ValueError, match="checkpoint fields"):
            store.load(cur, key)
        cur.execute(
            "SELECT document FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
            (key,),
        )
        assert cur.fetchone() == ({},)


def test_committed_checkpoint_recovers_in_a_fresh_connection():
    from contextlib import closing
    from standalone.evidence_pipeline.runtime import connect, local_database

    key = "synthetic-operations-" + str(uuid4())
    value = running_state()
    try:
        with closing(connect()) as conn, conn, conn.cursor() as cur:
            assert store.save(cur, key, 0, value) == 1
        with closing(connect()) as conn, conn, conn.cursor() as cur:
            revision, restored = store.load(cur, key)
            assert revision == 1 and encode(restored) == encode(value)
            actions = restored.tick(at(1801))
            assert (
                store.save(cur, key, revision, restored, notices=actions.notices) == 2
            )
        with closing(connect()) as conn, conn, conn.cursor() as cur:
            revision, restored = store.load(cur, key)
            assert revision == 2
            assert restored.tick(at(1801)).notices == ()
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            assert cur.fetchone() == (1,)
    finally:
        # Only this test's explicitly synthetic operational rows are removed.
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )


def test_completion_probe_waits_for_an_inflight_writer_transaction():
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import closing
    from datetime import datetime, timezone
    import time
    from standalone.evidence_pipeline.runtime import connect, local_database
    from .dispatch import Job
    from .supervisor import PostgresRepository

    name = "synthetic_probe_" + uuid4().hex

    def reader():
        conn = connect()
        with conn.cursor() as cur:
            cur.execute("SET application_name=%s", (name,))
        return conn

    now = datetime.now(timezone.utc)
    job = Job(str(uuid4()), str(uuid4()), now, now, ())
    with closing(connect()) as writer, ThreadPoolExecutor(max_workers=1) as pool:
        with writer.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        pending = pool.submit(
            PostgresRepository(connector=reader).committed_snapshot, job
        )
        try:
            deadline = time.monotonic() + 3
            waiting = False
            with (
                closing(local_database().connect()) as observer,
                observer.cursor() as cur,
            ):
                while time.monotonic() < deadline:
                    cur.execute(
                        "SELECT wait_event FROM pg_stat_activity WHERE application_name=%s",
                        (name,),
                    )
                    row = cur.fetchone()
                    if row == ("advisory",):
                        waiting = True
                        break
                    observer.rollback()
                    time.sleep(0.01)
            assert waiting and not pending.done()
        finally:
            writer.rollback()
        assert pending.result(timeout=5) is None
