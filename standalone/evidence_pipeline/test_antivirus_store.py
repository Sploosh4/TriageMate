"""Actual PostgreSQL antivirus writes, isolation and replay; all tests roll back."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import psycopg2
import pytest


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure

from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
)
from .test_store import db, snapshot  # noqa: F401
from .test_update_schema import update_bound  # noqa: F401


@pytest.fixture
def antivirus_bound(db, snapshot):  # noqa: F811
    device = replace(snapshot, scope=replace(snapshot.scope, source="Defender"))
    raw = {
        "id": "synthetic-health",
        "machineId": device.records()[0]["id"],
        "avMode": "0",
        "avIsSignatureUpToDate": "Unknown",
        "avIsEngineUpToDate": "False",
        "avIsPlatformUpToDate": "True",
        "rbacGroupId": 42,
        "lastSeenTime": "2026-09-12T00:00:00.100Z",
    }
    child = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="antivirus"),
        payload=json.dumps([raw]).encode(),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, device)
        persist_devices(db, device)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        database_schema.verify(cur)
        authorize_connection(cur, child)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (child.scope.connection_id, device.scope.connection_id),
        )
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    return device, child


def current(cur, child):
    cur.execute(
        "SELECT source_record_id,signature_status,signature_current,engine_current,platform_current,source_rbac_group_id "
        "FROM evidence_pipeline.current_antivirus WHERE connection_id=%s ORDER BY source_record_id",
        (child.scope.connection_id,),
    )
    return cur.fetchall()


def test_antivirus_persistence_replay_failure_empty_and_history(db, antivirus_bound):  # noqa: F811
    device, child = antivirus_bound
    first = persist_exposure(db, child, device.execution_id)
    assert first["records"] == 1 and not first["replayed"]
    assert persist_exposure(db, child, device.execution_id)["replayed"]
    with db.cursor() as cur:
        assert current(cur, child) == [
            ("synthetic-health", "Unknown", None, False, True, "42")
        ]
    failed = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="synthetic_failure",
    )
    persist_exposure(db, failed)
    with db.cursor() as cur:
        assert len(current(cur, child)) == 1
    empty = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(seconds=2),
        payload=b"[]",
    )
    persist_exposure(db, empty, device.execution_id)
    with db.cursor() as cur:
        assert current(cur, child) == []
        cur.execute(
            "SELECT count(*) FROM evidence.antivirus_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
            (child.execution_id,),
        )
        assert cur.fetchone() == (1,)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_changed_replay_and_unknown_device_leave_no_partial_rows(db, antivirus_bound):  # noqa: F811
    device, child = antivirus_bound
    persist_exposure(db, child, device.execution_id)
    with pytest.raises(ReplayConflict):
        persist_exposure(db, replace(child, payload=b"[]"), device.execution_id)
    other = replace(child, execution_id=str(uuid4()))
    with pytest.raises(ValueError, match="complete snapshot"):
        persist_exposure(db, other, str(uuid4()))
    with db.cursor() as cur:
        assert len(current(cur, child)) == 1
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (other.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_multiple_source_records_for_one_device_are_preserved(db, antivirus_bound):  # noqa: F811
    device, child = antivirus_bound
    raw = child.records()[0]
    child = replace(
        child, payload=json.dumps([raw, {**raw, "id": "synthetic-health-2"}]).encode()
    )
    assert persist_exposure(db, child, device.execution_id)["records"] == 2
    with db.cursor() as cur:
        assert len(current(cur, child)) == 2
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize(
    "mutation",
    [
        "signature_current=true",
        "provider_device_id=(SELECT id FROM evidence.provider_devices WHERE native_device_id<>%s LIMIT 1)",
    ],
)
def test_source_status_and_device_binding_enforced_by_database(
    db,  # noqa: F811
    antivirus_bound,
    mutation,
):
    device, child = antivirus_bound
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        params = (
            (device.records()[0]["id"], child.execution_id)
            if "%s" in mutation
            else (child.execution_id,)
        )
        cur.execute(
            "UPDATE evidence.antivirus_observations SET "
            + mutation
            + " WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            params,
        )
        with pytest.raises(psycopg2.Error):
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_antivirus_import_preserves_original_fixture_verification(
    db,  # noqa: F811
    antivirus_bound,
    monkeypatch,
):
    import importlib.util
    from pathlib import Path

    device, child = antivirus_bound
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.antivirus_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id JOIN evidence.source_revisions v ON v.id=r.source_revision_id JOIN evidence_pipeline.authorized_connections a ON a.connection_id=v.connection_id"
        )
        previous = cur.fetchone()[0]
    persist_exposure(db, child, device.execution_id)
    path = Path(__file__).resolve().parents[2] / "ui-engine/postgres/epss/baseline.py"
    monkeypatch.syspath_prepend(str(path.parent.parent))
    spec = importlib.util.spec_from_file_location("antivirus_baseline", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        result = module.verify(cur)
        assert result["antivirus_observations"] == previous + 1


def test_existing_update_writers_work_after_antivirus_upgrade(db, update_bound):  # noqa: F811
    device, child, _, _ = update_bound
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    assert persist_exposure(db, child, device.execution_id)["records"] == 1
    assert persist_exposure(db, child, device.execution_id)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_mid_import_failure_rolls_back_receipts_and_attempt(
    db,  # noqa: F811
    antivirus_bound,
    monkeypatch,
):
    from standalone.evidence_pipeline.persistence import exposure_store

    device, child = antivirus_bound
    original_insert = exposure_store.insert

    def fail_observation(cur, table, values):
        if table == "antivirus_observations":
            raise RuntimeError("synthetic storage failure")
        return original_insert(cur, table, values)

    monkeypatch.setattr(exposure_store, "insert", fail_observation)
    with pytest.raises(RuntimeError, match="synthetic storage failure"):
        persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        for table, column in (
            ("collection_attempts", "id"),
            ("observation_receipts", "collection_attempt_id"),
        ):
            cur.execute(
                f"SELECT count(*) FROM evidence.{table} WHERE {column}=%s",
                (child.execution_id,),
            )
            assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
    monkeypatch.setattr(exposure_store, "insert", original_insert)
    assert persist_exposure(db, child, device.execution_id)["records"] == 1
