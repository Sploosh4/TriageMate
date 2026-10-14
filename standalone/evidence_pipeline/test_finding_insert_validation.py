"""Finding insert checks retain pinned evidence and parent-edit invariants."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import psycopg2
import pytest


from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.store import persist_devices, atomic
from .test_exposure_store import bound, db, snapshot  # noqa: F401


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "damage",
    [
        "duplicate",
        "unpinned_device",
        "wrong_receipt",
        "parent_binding",
        "parent_delete",
    ],
)
def test_insert_and_parent_mutations_cannot_bypass_pinned_evidence(db, bound, damage):  # noqa: F811
    device, child = bound
    with db.cursor() as cur:
        database_schema.verify(cur)
    child = replace(
        child,
        payload=json.dumps(
            [
                {
                    "id": f"synthetic-finding-{i}",
                    "machineId": device.records()[0]["id"],
                    "cveId": "CVE-2099-99999",
                    "productName": "Synthetic product",
                    "productVersion": str(i),
                }
                for i in range(2)
            ]
        ).encode(),
    )
    assert persist_exposure(db, child, device.execution_id)["records"] == 2
    later = replace(
        device,
        execution_id=str(uuid4()),
        finished_at=device.finished_at + timedelta(seconds=1),
        payload=json.dumps(
            [{"id": "synthetic-later-device", "osPlatform": "Windows11"}]
        ).encode(),
    )
    persist_devices(db, later)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT id FROM evidence.provider_devices WHERE connection_id=%s AND native_device_id=%s",
            (device.scope.connection_id, "synthetic-later-device"),
        )
        unpinned = cur.fetchone()[0]
        cur.execute(
            "SELECT f.id,f.receipt_id FROM evidence.vulnerability_findings f JOIN evidence.observation_receipts r ON r.id=f.receipt_id WHERE r.collection_attempt_id=%s LIMIT 1",
            (child.execution_id,),
        )
        finding, receipt = cur.fetchone()
        with pytest.raises(psycopg2.Error), atomic(cur):
            if damage in ("duplicate", "unpinned_device", "wrong_receipt"):
                changes = {"id": str(uuid4())}
                if damage == "unpinned_device":
                    changes.update(
                        provider_device_id=unpinned,
                        source_finding_id="synthetic-new-identity",
                    )
                if damage == "wrong_receipt":
                    cur.execute(
                        "SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s LIMIT 1",
                        (device.execution_id,),
                    )
                    changes.update(
                        receipt_id=cur.fetchone()[0],
                        source_finding_id="synthetic-wrong-receipt",
                    )
                cur.execute(
                    "INSERT INTO evidence.vulnerability_findings SELECT (jsonb_populate_record(NULL::evidence.vulnerability_findings,to_jsonb(f)||%s::jsonb)).* FROM evidence.vulnerability_findings f WHERE id=%s",
                    (json.dumps(changes), finding),
                )
            elif damage == "parent_binding":
                cur.execute(
                    "UPDATE evidence_pipeline.exposure_snapshots SET device_attempt_id=%s WHERE collection_attempt_id=%s",
                    (later.execution_id, child.execution_id),
                )
            else:
                cur.execute(
                    "DELETE FROM evidence.device_observations WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
                    (device.execution_id,),
                )
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerability_findings WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (child.execution_id,),
        )
        assert cur.fetchone() == (2,)
        assert persist_exposure(db, child, device.execution_id)["replayed"]


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_restricted_writer_and_function_drift(db, bound):  # noqa: F811
    device, child = bound
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    child = replace(
        child,
        payload=json.dumps(
            [
                {
                    "id": "synthetic-restricted-finding",
                    "productName": "Synthetic product",
                    "machineId": device.records()[0]["id"],
                    "cveId": "CVE-2099-99999",
                }
            ]
        ).encode(),
    )
    assert persist_exposure(db, child, device.execution_id)["records"] == 1
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("ALTER FUNCTION evidence.check_device_receipts() SECURITY DEFINER")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
