"""Actual restricted login, committed imports, UI reader and scoped cleanup."""

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.commands import register, ingest, ingest_exposure
from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.evidence_pipeline.test_store import snapshot as snapshot_fixture

snapshot = snapshot_fixture


def remove_exposure(scope):
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        cur.execute(
            "SELECT DISTINCT i.software_id FROM evidence_pipeline.software_inventory i "
            "JOIN evidence.collection_attempts a ON a.id=i.collection_attempt_id WHERE a.connection_id=%s",
            (scope.connection_id,),
        )
        software = [row[0] for row in cur.fetchall()]
        cur.execute(
            "DELETE FROM evidence.device_missing_patches WHERE receipt_id IN "
            "(SELECT r.id FROM evidence.observation_receipts r JOIN evidence.collection_attempts a "
            "ON a.id=r.collection_attempt_id WHERE a.connection_id=%s)",
            (scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence.patches WHERE receipt_id IN "
            "(SELECT r.id FROM evidence.observation_receipts r JOIN evidence.collection_attempts a "
            "ON a.id=r.collection_attempt_id WHERE a.connection_id=%s)",
            (scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence.software_observations o USING evidence.observation_receipts r,evidence.collection_attempts a "
            "WHERE o.receipt_id=r.id AND r.collection_attempt_id=a.id AND a.connection_id=%s",
            (scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence_pipeline.software_inventory i USING evidence.collection_attempts a "
            "WHERE i.collection_attempt_id=a.id AND a.connection_id=%s",
            (scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence_pipeline.exposure_snapshots WHERE input_connection_id=%s",
            (scope.connection_id,),
        )
        cur.execute(
            "DELETE FROM evidence_pipeline.input_device_scopes WHERE input_connection_id=%s",
            (scope.connection_id,),
        )
        for key in software:
            cur.execute(
                "DELETE FROM evidence.software WHERE id=%s AND NOT EXISTS(SELECT 1 FROM evidence.software_observations WHERE software_id=%s) AND NOT EXISTS(SELECT 1 FROM evidence.vulnerability_findings WHERE software_id=%s) AND NOT EXISTS(SELECT 1 FROM evidence_pipeline.software_inventory WHERE software_id=%s)",
                (key, key, key, key),
            )
    cleanup(scope)


def test_software_command_commit_and_reader_query(snapshot):
    device = replace(snapshot, scope=replace(snapshot.scope, source="Intune"))
    child = replace(
        snapshot,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="software"),
        payload=json.dumps(
            [
                {
                    "id": "app",
                    "displayName": "Synthetic command test " + str(uuid4()),
                    "deviceCount": 1,
                }
            ]
        ).encode(),
    )
    raw = json.dumps({"app": [device.records()[0]["id"]]}).encode()
    from app.services.postgres_query import PostgreSQLQueries

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ui-engine/postgres"))
    from epss.baseline import verify

    with local_database().connect() as conn, conn.cursor() as cur:
        original_observations = verify(cur).get("software_observations", 0)
    try:
        assert register(device.scope)
        ingest(device)
        assert register(child.scope, device.scope.connection_id)
        assert not register(child.scope, device.scope.connection_id)
        assert ingest_exposure(child, device.execution_id, raw)["records"] == 1
        assert ingest_exposure(child, device.execution_id, raw)["replayed"]
        query = PostgreSQLQueries()
        result = json.loads(
            query.execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT source_application_id,reported_device_count,observed_device_count "
                    "FROM evidence_pipeline.current_software_inventory WHERE connection_id='"
                    + child.scope.connection_id
                    + "'::uuid",
                }
            )
        )
        assert result["rows"] == [["app", 1, 1]]
        with local_database().connect() as conn, conn.cursor() as cur:
            assert verify(cur)["software_observations"] == original_observations + 1
        failed = replace(
            child,
            execution_id=str(uuid4()),
            payload=b'[{"id":"invalid-app"}]',
            finished_at=child.finished_at + timedelta(hours=1),
        )
        assert ingest_exposure(failed, device.execution_id, raw)["outcome"] == "failure"
        from fastapi.testclient import TestClient
        from app.api import create_app
        from unittest.mock import patch
        import os
        from standalone.evidence_pipeline.notifications import notification_id

        class Operations:
            def __init__(self, *_args):
                pass

            def close(self):
                return True

            def notifications(self):
                return []

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGEMATE_STATE_DIR": temporary}),
        ):
            key = notification_id(child.scope.connection_id, failed.execution_id)
            with TestClient(create_app(lambda: query, Operations)) as client:
                notices = {
                    n["id"]: n
                    for n in client.get("/api/notifications").json()["notifications"]
                }
                assert notices[key]["status"] == "unresolved"
                assert "markdown" not in notices[key]
                recovered = replace(
                    child,
                    execution_id=str(uuid4()),
                    finished_at=child.finished_at + timedelta(hours=2),
                )
                assert (
                    ingest_exposure(recovered, device.execution_id, raw)["outcome"]
                    == "success"
                )
                notices = {
                    n["id"]: n
                    for n in client.get("/api/notifications").json()["notifications"]
                }
                assert notices[key]["status"] == "resolved"
    finally:
        remove_exposure(child.scope)
        cleanup(device.scope)


@pytest.mark.parametrize(
    "source,input_kind",
    [
        ("Defender", "missing_patches"),
        ("Defender", "antivirus"),
        ("Intune", "update_status"),
    ],
)
def test_current_upgrade_accepts_dependent_registration(snapshot, source, input_kind):
    """Every dependent registration gate must recognize the installed upgrade."""
    device = replace(snapshot.scope, source=source)
    child = replace(device, connection_id=str(uuid4()), input_kind=input_kind)
    try:
        assert register(device)
        assert register(child, device.connection_id)
        assert not register(child, device.connection_id)
    finally:
        remove_exposure(child)
        cleanup(device)
