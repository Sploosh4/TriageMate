"""Scoped app relationships retain source counts without claiming full inventory."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4
import json
import pytest
import psycopg2
from .test_store import db as db_fixture, snapshot as snapshot_fixture
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import persist_devices
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure


db = db_fixture
snapshot = snapshot_fixture


@pytest.mark.parametrize("reported", [0, 1, 7, None])
def test_source_count_and_explicit_scoped_link_are_separate(db, snapshot, reported):
    device = replace(snapshot, scope=replace(snapshot.scope, source="Intune"))
    native = device.records()[0]["id"]
    child = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="software",
            scope_reference="managed-device-apps:" + native,
        ),
        execution_id=str(uuid4()),
        payload=json.dumps(
            [
                {
                    "id": "synthetic-app",
                    "displayName": "Synthetic app",
                    "deviceCount": reported,
                }
            ]
        ).encode(),
    )
    with db.cursor() as c:
        database_schema.verify(c)
        authorize_connection(c, device)
        persist_devices(db, device)
        authorize_connection(c, child)
        c.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (child.scope.connection_id, device.scope.connection_id),
        )
        c.execute("SET LOCAL ROLE tm_pipeline_writer")
    links = json.dumps({"synthetic-app": [native]}).encode()
    assert not persist_exposure(db, child, device.execution_id, links)["replayed"]
    assert persist_exposure(db, child, device.execution_id, links)["replayed"]
    with db.cursor() as c:
        c.execute("SET CONSTRAINTS ALL IMMEDIATE")
        c.execute("RESET ROLE")
        c.execute("SET LOCAL ROLE tm_mock_reader")
        c.execute(
            "SELECT reported_device_count,observed_device_count FROM evidence_pipeline.current_software_inventory WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert c.fetchall() == [(reported, 1)]
        c.execute("RESET ROLE")
        c.execute("SAVEPOINT bad_link")
        with pytest.raises(psycopg2.Error):
            c.execute(
                "DELETE FROM evidence.software_observations WHERE inventory_id IN (SELECT inventory_id FROM evidence_pipeline.current_software_inventory WHERE connection_id=%s)",
                (child.scope.connection_id,),
            )
            c.execute("SELECT evidence_pipeline.validate_exposure()")
        c.execute("ROLLBACK TO SAVEPOINT bad_link")
        database_schema.verify(c)
