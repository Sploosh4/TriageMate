"""Transactional synthetic event history and checkpoint regression tests."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest


from standalone.evidence_pipeline.persistence.assessment_store import (
    persist_assessments,
    checkpoint,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
)
from .test_store import db, snapshot  # noqa: F401


def test_baseline_delta_replay_and_failed_import_do_not_lose_checkpoint(db, snapshot):  # noqa: F811
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-device"}]',
    )
    row = {
        "id": "synthetic-instance",
        "deviceId": "synthetic-device",
        "softwareVendor": "Synthetic vendor",
        "softwareName": "Synthetic app",
        "softwareVersion": "1",
        "cveId": "CVE-2026-10001",
    }
    baseline = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_baseline",
        ),
        execution_id=str(uuid4()),
        payload=json.dumps(
            [
                row,
                {
                    **row,
                    "id": "synthetic-retired-instance",
                    "deviceId": "synthetic-retired",
                },
            ]
        ).encode(),
    )
    delta = replace(
        baseline,
        scope=replace(
            baseline.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_events",
        ),
        execution_id=str(uuid4()),
        started_at=baseline.started_at + timedelta(hours=6),
        finished_at=baseline.finished_at + timedelta(hours=6),
        payload=json.dumps(
            [{**row, "status": "Fixed", "eventTimestamp": "2026-09-12 01:00:00"}]
        ).encode(),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        for source in (device, baseline, delta):
            authorize_connection(cur, source)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL),(%s,%s,%s)",
            (
                baseline.scope.connection_id,
                device.scope.connection_id,
                delta.scope.connection_id,
                device.scope.connection_id,
                baseline.scope.connection_id,
            ),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, device)
    persist_assessments(db, baseline, device.execution_id)
    with db.cursor() as cur:
        cur.execute(
            "SELECT source_native_device_id,link_state,provider_device_id IS NULL FROM evidence_pipeline.assessment_device_references WHERE collection_attempt_id=%s ORDER BY source_native_device_id",
            (baseline.execution_id,),
        )
        assert cur.fetchall() == [
            ("synthetic-device", "bound", False),
            ("synthetic-retired", "unbound", True),
        ]
    from psycopg2.extensions import cursor as PgCursor
    from psycopg2.errors import RaiseException

    for fault in ("invented_event", "cve", "instance", "fingerprint", "absolute_time"):

        class ChangedProjectionCursor(PgCursor):
            def execute(self, query, parameters=None):
                if isinstance(query, str) and query.startswith(
                    "INSERT INTO evidence_pipeline.assessment_observations"
                ):
                    values = list(parameters)
                    if fault == "invented_event":
                        values[5:7] = ["Fixed", "2026-09-12T00:00:00Z"]
                    elif fault == "cve":
                        values[2] = None
                    elif fault == "instance":
                        values[3] = '["wrong-device","wrong-product",null]'
                    elif fault == "fingerprint":
                        values[4] = "0" * 64
                    else:
                        values[7] = "2026-09-12T00:00:00Z"
                    parameters = tuple(values)
                return super().execute(query, parameters)

        class ChangedProjectionConnection:
            autocommit = False

            def cursor(self):
                return db.cursor(cursor_factory=ChangedProjectionCursor)

        with pytest.raises(RaiseException, match="Assessment projection"):
            persist_assessments(
                ChangedProjectionConnection(),
                replace(baseline, execution_id=str(uuid4())),
                device.execution_id,
            )
    since = baseline.started_at - timedelta(hours=6)
    result = persist_assessments(
        db, delta, device.execution_id, baseline.execution_id, since
    )
    assert result["records"] == 1
    assert persist_assessments(
        db, delta, device.execution_id, baseline.execution_id, since
    )["replayed"]
    with db.cursor() as cur:
        before = checkpoint(cur, delta.scope.connection_id)
        cur.execute("RESET ROLE")
        import importlib.util
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2] / "ui-engine/postgres/epss/baseline.py"
        )
        spec = importlib.util.spec_from_file_location(
            "assessment_baseline_verify", path
        )
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        verifier.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    failed = replace(
        delta,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        error_code="synthetic_failure",
        payload=b"",
        finished_at=delta.finished_at + timedelta(hours=1),
    )
    persist_assessments(db, failed, device.execution_id)
    with db.cursor() as cur:
        assert checkpoint(cur, delta.scope.connection_id) == before
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT event_kind,event_time_text,event_time_utc FROM evidence_pipeline.vulnerability_event_history WHERE connection_id=%s",
            (delta.scope.connection_id,),
        )
        assert cur.fetchall() == [("Fixed", "2026-09-12 01:00:00", None)]
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    with pytest.raises(ReplayConflict, match="checkpoint"):
        persist_assessments(
            db,
            replace(delta, execution_id=str(uuid4())),
            device.execution_id,
            baseline.execution_id,
            since,
        )
    with db.cursor() as cur:
        assert checkpoint(cur, delta.scope.connection_id) == before
