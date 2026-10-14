"""Authority DDL and data are rolled back after each synthetic test."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.store import persist_devices
from standalone.evidence_pipeline.test_store import (
    db as database_fixture,
    snapshot as snapshot_fixture,
    rows,
)

db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def restricted(db, snapshot):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, snapshot)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    yield db


def test_restricted_writer_persists_only_registered_source(restricted, snapshot):
    assert persist_devices(restricted, snapshot)["devices"] == 1
    assert persist_devices(restricted, snapshot)["replayed"]
    other = replace(
        snapshot,
        scope=replace(snapshot.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        persist_devices(restricted, other)
    assert rows(restricted, "SELECT 1") == [(1,)]


def reject(db, statement, params=()):
    with db.cursor() as cursor:
        cursor.execute("SAVEPOINT forbidden")
        try:
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cursor.execute(statement, params)
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        finally:
            cursor.execute("ROLLBACK TO SAVEPOINT forbidden")
            cursor.execute("RELEASE SAVEPOINT forbidden")


def test_writer_cannot_update_delete_or_claim_new_authority(restricted, snapshot):
    persist_devices(restricted, snapshot)
    reject(restricted, "UPDATE evidence.device_observations SET display_name='changed'")
    reject(restricted, "DELETE FROM evidence.provider_devices")
    reject(restricted, "TRUNCATE evidence.device_observations")
    reject(
        restricted,
        "INSERT INTO evidence_pipeline.authorized_connections VALUES(%s,'synthetic')",
        (str(uuid4()),),
    )
    reject(restricted, "CREATE ROLE unauthorized_pipeline_role")
    reject(restricted, "SET ROLE tm_mock_owner")


def test_writer_cannot_insert_attempt_on_fixture_connection(restricted, snapshot):
    foreign = rows(
        restricted,
        "SELECT id FROM evidence.source_connections WHERE id<>%s LIMIT 1",
        (snapshot.scope.connection_id,),
    )[0][0]
    reject(
        restricted,
        "INSERT INTO evidence.collection_attempts(id,connection_id,started_at,finished_at,outcome,complete,revision) VALUES(%s,%s,now(),now(),'success',true,1)",
        (str(uuid4()), foreign),
    )


def test_writer_cannot_forge_public_provenance(restricted, snapshot):
    reject(
        restricted,
        "INSERT INTO evidence.source_revisions(id,connection_id,source_record_id,collected_at,content_hash,origin,licence_or_provenance) VALUES(%s,%s,'forged',%s,%s,'public','forged')",
        (str(uuid4()), snapshot.scope.connection_id, snapshot.finished_at, "a" * 64),
    )


def test_existing_reader_keeps_select_but_gains_no_write(db, snapshot):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, snapshot)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cursor.execute("SELECT count(*) FROM evidence.device_observations")
        assert cursor.fetchone()[0] > 0
    reject(
        db,
        "INSERT INTO evidence.device_observations(id,provider_device_id,receipt_id) VALUES(%s,%s,%s)",
        (str(uuid4()), str(uuid4()), str(uuid4())),
    )


def test_existing_epss_function_still_works_under_new_row_policies(db):
    from pathlib import Path

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_epss_importer")
        raw = (
            Path(__file__).resolve().parents[2]
            / "standalone/fixtures/synthetic_epss_v1.json"
        ).read_bytes()
        cursor.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)", (str(uuid4()), raw)
        )
        assert cursor.fetchone()[0]["outcome"] == "success"


def test_writer_cannot_attach_observation_to_foreign_receipt(restricted, snapshot):
    persist_devices(restricted, snapshot)
    provider = rows(
        restricted,
        "SELECT id FROM evidence.provider_devices WHERE connection_id=%s",
        (snapshot.scope.connection_id,),
    )[0][0]
    receipt = rows(
        restricted,
        "SELECT r.id FROM evidence.observation_receipts r JOIN evidence.collection_attempts a ON a.id=r.collection_attempt_id WHERE a.connection_id<>%s LIMIT 1",
        (snapshot.scope.connection_id,),
    )[0][0]
    reject(
        restricted,
        "INSERT INTO evidence.device_observations(id,provider_device_id,receipt_id) VALUES(%s,%s,%s)",
        (str(uuid4()), provider, receipt),
    )
