from backend.database import schema as database_schema
from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure

from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
)
from standalone.evidence_pipeline.test_store import (
    db as database_fixture,
    snapshot as snapshot_fixture,
)

db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def bound(db, snapshot, request):
    source = getattr(request, "param", "Intune")
    device = replace(snapshot, scope=replace(snapshot.scope, source=source))
    child = replace(
        snapshot,
        execution_id=str(uuid4()),
        payload=b"[]",
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="software" if source == "Intune" else "findings",
        ),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, device)
        persist_devices(db, device)
        authorize_connection(cur, child)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (child.scope.connection_id, device.scope.connection_id),
        )
    return device, child


def inventory(bound):
    device, child = bound
    apps = [
        {
            "id": "app",
            "displayName": "Synthetic software",
            "version": "1",
            "deviceCount": 1,
        },
        {
            "id": "empty",
            "displayName": "Synthetic app without devices",
            "deviceCount": 0,
        },
    ]
    native = device.records()[0]["id"]
    return replace(child, payload=json.dumps(apps).encode()), json.dumps(
        {"app": [native], "empty": []}
    ).encode()


def counts(cur, execution):
    cur.execute(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (execution,),
    )
    return cur.fetchone()[0]


def test_inventory_persists_zero_cve_software_and_zero_link_apps(db, bound):
    snapshot, raw = inventory(bound)
    first = persist_exposure(db, snapshot, bound[0].execution_id, raw)
    assert first["records"] == 2 and not first["replayed"]
    assert persist_exposure(db, snapshot, bound[0].execution_id, raw)["replayed"]
    with db.cursor() as cur:
        assert counts(cur, snapshot.execution_id) == 2
        cur.execute(
            "SELECT i.source_application_id,count(o.id) FROM evidence_pipeline.software_inventory i "
            "LEFT JOIN evidence.software_observations o ON o.inventory_id=i.id "
            "WHERE i.collection_attempt_id=%s GROUP BY i.source_application_id ORDER BY 1",
            (snapshot.execution_id,),
        )
        assert cur.fetchall() == [("app", 1), ("empty", 0)]
    with pytest.raises(ReplayConflict):
        persist_exposure(db, snapshot, bound[0].execution_id, raw + b" ")


def test_same_content_new_receipts_and_failed_or_empty_snapshots(db, bound):
    snapshot, raw = inventory(bound)
    persist_exposure(db, snapshot, bound[0].execution_id, raw)
    newer = replace(
        snapshot,
        execution_id=str(uuid4()),
        finished_at=snapshot.finished_at + timedelta(hours=1),
    )
    persist_exposure(db, newer, bound[0].execution_id, raw)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (2,)
        assert counts(cur, newer.execution_id) == 2
    failed = replace(
        newer,
        execution_id=str(uuid4()),
        outcome="partial",
        complete=False,
        payload=b"bad response",
    )
    assert persist_exposure(db, failed)["outcome"] == "failure"
    assert persist_exposure(db, failed)["replayed"]
    empty = replace(
        newer,
        execution_id=str(uuid4()),
        payload=b"[]",
        finished_at=newer.finished_at + timedelta(hours=1),
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_software_inventory WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (2,)
    assert persist_exposure(db, empty, bound[0].execution_id, b"{}")["records"] == 0
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_software_inventory WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT selected_attempt_id::text FROM evidence_pipeline.collection_status WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (empty.execution_id,)


def test_invalid_associations_roll_back_attempt_and_preserve_existing(db, bound):
    snapshot, raw = inventory(bound)
    with pytest.raises(ValueError):
        persist_exposure(db, snapshot, bound[0].execution_id, b'{"app":[],"empty":[]}')
    with db.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM evidence.collection_attempts WHERE id=%s",
            (snapshot.execution_id,),
        )
        assert cur.fetchone() is None
    assert persist_exposure(db, snapshot, bound[0].execution_id, raw)["records"] == 2


def test_unrelated_or_failed_device_attempt_rejected(db, bound):
    snapshot, raw = inventory(bound)
    with pytest.raises(ValueError, match="bound device source"):
        persist_exposure(db, snapshot, str(uuid4()), raw)


def test_restricted_runtime_can_ingest_but_cannot_change_binding(db, bound):
    from standalone.evidence_pipeline.test_authority import reject

    snapshot, raw = inventory(bound)
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert persist_exposure(db, snapshot, bound[0].execution_id, raw)["records"] == 2
    reject(
        db,
        "UPDATE evidence_pipeline.input_device_scopes SET device_connection_id=input_connection_id",
    )
    reject(db, "DELETE FROM evidence.software")
    reject(db, "TRUNCATE evidence.vulnerability_findings")


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_findings_preserve_source_fix_reference_without_fabricating_patch(db, bound):
    device, child = bound
    record = {
        "id": "finding",
        "machineId": device.records()[0]["id"],
        "cveId": "CVE-2026-999999",
        "productName": "Synthetic product",
        "productVersion": "1",
        "severity": "High",
        "fixingKbId": "KB-SYNTHETIC",
    }
    child = replace(child, payload=json.dumps([record]).encode())
    assert persist_exposure(db, child, device.execution_id)["records"] == 1
    assert persist_exposure(db, child, device.execution_id)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT f.cve_id,f.fixing_patch_id,f.fixing_patch_reference,f.source_severity_label "
            "FROM evidence.vulnerability_findings f JOIN evidence.observation_receipts r ON r.id=f.receipt_id "
            "WHERE r.collection_attempt_id=%s",
            (child.execution_id,),
        )
        assert cur.fetchone() == (record["cveId"], None, "KB-SYNTHETIC", "High")


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_finding_validation_batches_remain_atomic_and_replayable(
    db, bound, monkeypatch
):
    import psycopg2
    from standalone.evidence_pipeline.persistence import exposure_store

    device, child = bound
    records = [
        {
            "id": f"synthetic-batched-{number}",
            "machineId": device.records()[0]["id"],
            "cveId": "CVE-2026-999999",
            "productName": "Synthetic batched findings",
            "productVersion": str(number),
        }
        for number in range(105)
    ]
    child = replace(child, payload=json.dumps(records).encode())
    original = exposure_store.insert
    count = 0

    def fail_last(cursor, table, values):
        nonlocal count
        if table == "vulnerability_findings":
            count += 1
            if count == 105:
                values = {**values, "fixing_patch_id": str(uuid4())}
        return original(cursor, table, values)

    monkeypatch.setattr(exposure_store, "insert", fail_last)
    with pytest.raises(psycopg2.IntegrityError):
        persist_exposure(db, child, device.execution_id)
    assert count == 105
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (child.execution_id,),
        )
        assert cursor.fetchone() == (0,)
        assert counts(cursor, child.execution_id) == 0
        cursor.execute(
            "SELECT count(*) FROM evidence.vulnerability_findings "
            "WHERE source_finding_id LIKE 'synthetic-batched-%'"
        )
        assert cursor.fetchone() == (0,)

    monkeypatch.setattr(exposure_store, "insert", original)
    assert persist_exposure(db, child, device.execution_id)["records"] == 105
    assert persist_exposure(db, child, device.execution_id)["replayed"]
    with db.cursor() as cursor:
        assert counts(cursor, child.execution_id) == 105
