"""High source-absence episodes preserve exact failures, recovery and authority."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_public_snapshot import attempt
from .test_store import db as db


def test_upgrade_backfills_absence_then_preserves_mixed_failure_and_recovery(
    db, monkeypatch
):
    good = attempt()
    absent = replace(
        good,
        execution_id=str(uuid4()),
        complete=False,
        outcome="failure",
        payload=b"",
        error_code="public_not_found",
    )
    with db.cursor() as cur:
        authorize_connection(cur, absent)
    persist_public(db, absent)
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT id::text,urgency,status,failure_count FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        before = cur.fetchone()
        assert before[1:] == ("high", "unresolved", 1)
        verify_schema(cur)
    broken = replace(
        absent,
        execution_id=str(uuid4()),
        finished_at=good.finished_at + timedelta(hours=1),
        error_code="public_connection_failed",
    )
    persist_public(db, broken)
    again = replace(
        absent,
        execution_id=str(uuid4()),
        finished_at=good.finished_at + timedelta(hours=2),
    )
    persist_public(db, again)
    with db.cursor() as cur:
        cur.execute(
            "SELECT id::text,urgency,status,failure_count FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        assert cur.fetchone() == (before[0], "critical", "unresolved", 3)
    recovered = replace(good, finished_at=good.finished_at + timedelta(hours=3))
    persist_public(db, recovered)
    with db.cursor() as cur:
        cur.execute(
            "SELECT id::text,urgency,status,failure_count,recovery_attempt_id::text FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        assert cur.fetchone() == (
            before[0],
            "critical",
            "resolved",
            3,
            recovered.execution_id,
        )
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=%s AND outcome='failure'",
            (good.scope.connection_id,),
        )
        assert cur.fetchone() == (3,)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT urgency FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        assert cur.fetchone() == ("critical",)
        cur.execute("RESET ROLE")
        database_schema.verify(cur)


@pytest.mark.parametrize("damage", ["constraint", "view", "grant"])
def test_absence_migration_refuses_drift(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if damage == "constraint":
            cur.execute(
                "ALTER TABLE evidence.notifications DROP CONSTRAINT notifications_urgency_check"
            )
        elif damage == "view":
            cur.execute(
                "SELECT pg_get_viewdef('evidence_pipeline.notification_episodes'::regclass,true)"
            )
            definition = cur.fetchone()[0]
            assert "'high'::text" in definition
            cur.execute(
                "CREATE OR REPLACE VIEW evidence_pipeline.notification_episodes AS "
                + definition.replace("'high'::text", "'moderate'::text")
            )
        else:
            cur.execute("GRANT UPDATE ON evidence.notifications TO tm_mock_reader")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_high_absence_replay_and_complete_recovery_keep_one_episode(db):
    good = attempt()
    absent = replace(
        good,
        execution_id=str(uuid4()),
        complete=False,
        outcome="failure",
        payload=b"",
        error_code="public_not_found",
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, absent)
    assert not persist_public(db, absent)["replayed"]
    assert persist_public(db, absent)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT id::text,urgency,status,failure_count FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        before = cur.fetchone()
        assert before[1:] == ("high", "unresolved", 1)
    persist_public(db, replace(good, finished_at=good.finished_at + timedelta(hours=1)))
    with db.cursor() as cur:
        cur.execute(
            "SELECT id::text,urgency,status,failure_count FROM evidence.notifications WHERE connection_id=%s",
            (good.scope.connection_id,),
        )
        assert cur.fetchone() == (before[0], "high", "resolved", 1)
