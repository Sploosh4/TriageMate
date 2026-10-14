"""Synthetic classification operations; DDL and records are rolled back."""

from backend.database import schema as database_schema

from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_authority import reject
from .test_store import db as db_fixture, snapshot as snapshot_fixture

db = db_fixture
snapshot = snapshot_fixture


@pytest.fixture
def classified(db, snapshot):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, snapshot)
    persist_devices(db, snapshot)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT id FROM evidence.provider_devices WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        device = cursor.fetchone()[0]
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return db, device


def call(
    db,
    decision,
    device,
    chosen="Workstation",
    reason="Synthetic operator test",
    previous=None,
):
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT evidence_pipeline.record_classification(%s,%s,%s,%s,%s)",
            (decision, device, chosen, reason, previous),
        )
        return cursor.fetchone()[0]


def test_history_replay_and_source_preservation(classified):
    db, device = classified
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM evidence.device_observations WHERE provider_device_id=%s",
            (device,),
        )
        original = cursor.fetchall()
    first = str(uuid4())
    second = str(uuid4())
    assert str(call(db, first, device)) == first
    assert str(call(db, first, device)) == first
    call(db, second, device, chosen="Server", previous=first)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT selected_type,actor_kind,actor_reference,revision,supersedes_decision_id::text,decided_at IS NOT NULL FROM evidence.classification_decisions WHERE provider_device_id=%s ORDER BY revision",
            (device,),
        )
        assert cursor.fetchall() == [
            ("Workstation", "analyst", "local operator", 1, None, True),
            ("Server", "analyst", "local operator", 2, first, True),
        ]
        cursor.execute(
            "SELECT count(*) FROM evidence.device_observations WHERE provider_device_id=%s",
            (device,),
        )
        assert cursor.fetchone() == (1,)
        cursor.execute(
            "SELECT * FROM evidence.device_observations WHERE provider_device_id=%s",
            (device,),
        )
        assert cursor.fetchall() == original
        cursor.execute(
            "SELECT source_device_type,selected_type,decision_revision FROM evidence_pipeline.current_classifications WHERE provider_device_id=%s",
            (device,),
        )
        assert cursor.fetchall() == [(None, "Server", 2)]
    reject(db, "UPDATE evidence.classification_decisions SET selected_type='changed'")
    reject(db, "DELETE FROM evidence.classification_decisions")


@pytest.mark.parametrize("case", ["stale", "reused", "blank", "unregistered"])
def test_invalid_decisions_do_not_append(classified, case):
    db, device = classified
    first = str(uuid4())
    call(db, first, device)
    with db.cursor() as cursor:
        cursor.execute("SAVEPOINT invalid_decision")
        with pytest.raises(psycopg2.Error):
            call(
                db,
                first if case == "reused" else str(uuid4()),
                str(uuid4()) if case == "unregistered" else device,
                chosen="" if case == "blank" else "Server",
            )
        cursor.execute("ROLLBACK TO SAVEPOINT invalid_decision")
        cursor.execute(
            "SELECT count(*) FROM evidence.classification_decisions WHERE provider_device_id=%s",
            (device,),
        )
        assert cursor.fetchone() == (1,)


def test_reader_cannot_call_classification(classified):
    db, device = classified
    with db.cursor() as cursor:
        cursor.execute("RESET SESSION AUTHORIZATION")
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
    reject(
        db,
        "SELECT evidence_pipeline.record_classification(%s,%s,%s,%s,NULL)",
        (str(uuid4()), device, "Server", "Synthetic"),
    )


def test_writer_cannot_forge_classification_actor(classified):
    db, device = classified
    reject(
        db,
        "INSERT INTO evidence.classification_decisions(id,provider_device_id,selected_type,actor_kind,actor_reference,reason,decided_at,revision) VALUES(%s,%s,'Server','analyst','someone else','Synthetic',now(),1)",
        (str(uuid4()), device),
    )
