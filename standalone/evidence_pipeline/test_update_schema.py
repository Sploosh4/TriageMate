"""Pending update schema: actual restricted inserts, rolled back after each test."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4
import json

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection


from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    stage_attempt,
    insert,
)
from standalone.evidence_pipeline.persistence.exposure_store import receipt
from standalone.evidence_pipeline.parsing.update_records import (
    rows,
    content,
    source_record_id,
)
from standalone.evidence_pipeline.parsing.update_status import (
    normalize_missing_patches,
    normalize_update_status,
)
from .test_store import db, snapshot  # noqa: F401


@pytest.fixture(params=["Defender", "Intune"])
def update_bound(db, snapshot, request):  # noqa: F811
    source = request.param
    device = replace(snapshot, scope=replace(snapshot.scope, source=source))
    native = device.records()[0]["id"]
    raw = (
        {"machineId": native, "id": "KB-synthetic", "cveAddressed": 2}
        if source == "Defender"
        else {
            "DeviceId": native,
            "PolicyId": str(uuid4()),
            "CurrentDeviceUpdateStatus": "installed",
            "EventDateTimeUTC": "2026-09-12T10:00:00.100Z",
            "LastWUScanTimeUTC": "2026-09-12T09:00:00.123400Z",
        }
    )
    child = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="missing_patches" if source == "Defender" else "update_status",
        ),
        payload=json.dumps([raw]).encode(),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, device)
        persist_devices(db, device)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        database_schema.verify(cur)
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        authorize_connection(cur, child)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (child.scope.connection_id, device.scope.connection_id),
        )
        cur.execute(
            "SELECT id::text FROM evidence.provider_devices WHERE connection_id=%s",
            (device.scope.connection_id,),
        )
        provider = cur.fetchone()[0]
    adapter = (
        normalize_missing_patches if source == "Defender" else normalize_update_status
    )
    return device, child, provider, adapter(child, {native})[0]


def project(connection, bound):
    device, child, provider, item = bound
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        stage_attempt(cur, child)
        cur.execute(
            "INSERT INTO evidence_pipeline.exposure_snapshots VALUES(%s,%s,%s,NULL)",
            (child.execution_id, child.scope.connection_id, device.execution_id),
        )
        received = receipt(cur, child, source_record_id(item), content(item))
        projected = rows(item, received, provider, child.finished_at)
        for table, row in projected:
            insert(cur, table, row)
    return projected


def test_restricted_writer_accepts_bound_source_status(db, update_bound):  # noqa: F811
    projected = project(db, update_bound)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        table, row = projected[-1]
        cur.execute(
            f"SELECT provider_device_id::text FROM evidence.{table} WHERE id=%s",
            (row["id"],),
        )
        assert cur.fetchone() == (update_bound[2],)
        with pytest.raises(psycopg2.Error):
            cur.execute(f"DELETE FROM evidence.{table} WHERE id=%s", (row["id"],))


def test_parent_scope_change_is_rejected(db, update_bound):  # noqa: F811
    project(db, update_bound)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        cur.execute(
            "UPDATE evidence.source_connections SET source_name='Entra' WHERE id=%s",
            (update_bound[1].scope.connection_id,),
        )
        with pytest.raises(psycopg2.Error):
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize("update_bound", ["Defender"], indirect=True)
def test_patch_parent_receipt_change_is_rejected(db, update_bound):  # noqa: F811
    projected = project(db, update_bound)
    patch = dict(projected)["patches"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        cur.execute(
            "SELECT id FROM evidence.observation_receipts WHERE id<>%s LIMIT 1",
            (patch["receipt_id"],),
        )
        other = cur.fetchone()[0]
        cur.execute(
            "UPDATE evidence.patches SET receipt_id=%s WHERE id=%s",
            (other, patch["id"]),
        )
        with pytest.raises(psycopg2.Error, match="Missing patch must retain"):
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
