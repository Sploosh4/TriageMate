"""Committed synthetic baseline/delta commands and actual SQL reader."""

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

from .commands import register, ingest
from .assessment_commands import ingest as ingest_assessment
from .runtime import local_database
from .test_commands import cleanup
from .test_store import snapshot  # noqa: F401


def test_committed_baseline_and_delta_are_queryable(snapshot):  # noqa: F811
    cve = "CVE-2099-" + str(uuid4().int)[:18]
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-event-device"}]',
    )
    raw = {
        "id": "synthetic-instance",
        "deviceId": "synthetic-event-device",
        "softwareVendor": "Synthetic vendor",
        "softwareName": "Synthetic app",
        "softwareVersion": "1",
        "cveId": cve,
    }
    baseline = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_baseline",
        ),
        execution_id=str(uuid4()),
        payload=json.dumps([raw]).encode(),
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
            [{**raw, "status": "New", "eventTimestamp": "2026-09-12 01:00:00"}]
        ).encode(),
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        register(device.scope)
        ingest(device)
        register(baseline.scope, device.scope.connection_id)
        assert not register(baseline.scope, device.scope.connection_id)
        register(delta.scope, device.scope.connection_id, baseline.scope.connection_id)
        collected = ingest_assessment(baseline, device.execution_id)
        assert collected["records"] == 1
        assert collected["enrichment"] == {
            "state": "checked",
            "queued": 4,
            "batch_limit": 100,
        }
        since = baseline.started_at - timedelta(hours=6)
        changed = ingest_assessment(
            delta, device.execution_id, baseline.execution_id, since
        )
        assert changed["records"] == 1
        assert changed["enrichment"]["queued"] == 0
        assert ingest_assessment(
            delta, device.execution_id, baseline.execution_id, since
        )["replayed"]
        data = json.loads(
            PostgreSQLQueries().execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT cve_id,event_kind,event_time_text,event_time_utc,origin FROM evidence_pipeline.vulnerability_event_history WHERE connection_id='"
                    + delta.scope.connection_id
                    + "'::uuid",
                }
            )
        )
        assert data["rows"] == [[cve, "New", "2026-09-12 01:00:00", None, "synthetic"]]
    finally:
        for source in (delta, baseline):
            with local_database().connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM evidence_pipeline.assessment_observations o USING evidence.observation_receipts r,evidence.collection_attempts a WHERE o.receipt_id=r.id AND r.collection_attempt_id=a.id AND a.connection_id=%s",
                    (source.scope.connection_id,),
                )
                cur.execute(
                    "DELETE FROM evidence_pipeline.assessment_runs r USING evidence.collection_attempts a WHERE a.id=r.attempt_id AND a.connection_id=%s",
                    (source.scope.connection_id,),
                )
                cur.execute(
                    "DELETE FROM evidence_pipeline.assessment_bindings WHERE connection_id=%s",
                    (source.scope.connection_id,),
                )
            cleanup(source.scope)
        cleanup(device.scope)
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
