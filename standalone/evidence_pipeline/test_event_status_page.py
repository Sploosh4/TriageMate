"""The event page follows successful checkpoints, including empty collections."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
from uuid import uuid4


from standalone.evidence_pipeline.persistence.assessment_store import (
    checkpoint,
    persist_assessments,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_store import db, snapshot  # noqa: F401

PAGE = (
    Path(__file__).resolve().parents[2]
    / "standalone/evidence_pipeline/fixtures/analysis_queries/vulnerability_events.json"
)


def read_page(connection, scope):
    queries = json.loads(PAGE.read_text())
    assert len(queries) == 3
    result = []
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for statement in queries:
            cur.execute(statement)
            columns = [column.name for column in cur.description]
            result.append(
                [
                    row
                    for values in cur.fetchall()
                    if (row := dict(zip(columns, values)))["connection_id"] == scope
                ]
            )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    return result


def test_latest_empty_success_failure_recovery_and_history_are_distinct(db, snapshot):  # noqa: F811
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-device"}]',
    )
    record = dict(
        id="synthetic-instance",
        deviceId="synthetic-device",
        softwareVendor="Synthetic vendor",
        softwareName="Synthetic app",
        softwareVersion="1",
        cveId="CVE-2026-10001",
    )
    baseline = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_baseline",
        ),
        execution_id=str(uuid4()),
        payload=json.dumps([record]).encode(),
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
            [record | dict(status="Fixed", eventTimestamp="2026-09-12 01:00:00")]
        ).encode(),
    )
    never_collected = replace(
        delta,
        scope=replace(
            delta.scope,
            connection_id=str(uuid4()),
            scope_reference="synthetic-uncollected-page-scope",
        ),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        for source in (device, baseline, delta, never_collected):
            authorize_connection(cur, source)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL),(%s,%s,%s),(%s,%s,%s)",
            (
                baseline.scope.connection_id,
                device.scope.connection_id,
                delta.scope.connection_id,
                device.scope.connection_id,
                baseline.scope.connection_id,
                never_collected.scope.connection_id,
                device.scope.connection_id,
                baseline.scope.connection_id,
            ),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, device)
    persist_assessments(db, baseline, device.execution_id)
    unknown, details, history = read_page(db, never_collected.scope.connection_id)
    assert len(unknown) == 1 and unknown[0]["selected_batch_events"] is None
    assert unknown[0]["selected_event_attempt_id"] is None
    assert details == history == []
    since = baseline.started_at - timedelta(hours=6)
    persist_assessments(db, delta, device.execution_id, baseline.execution_id, since)
    summary, details, history = read_page(db, delta.scope.connection_id)
    assert summary[0]["selected_batch_events"] == 1
    assert str(summary[0]["selected_event_attempt_id"]) == delta.execution_id
    assert len(details) == 1 and details[0]["event_kind"] == "Fixed"
    assert history[0]["distinct_source_events"] == 1
    empty = replace(
        delta,
        execution_id=str(uuid4()),
        started_at=delta.started_at + timedelta(hours=6),
        finished_at=delta.finished_at + timedelta(hours=6),
        payload=b"[]",
    )
    with db.cursor() as cur:
        previous, since, _ = checkpoint(cur, delta.scope.connection_id)
    persist_assessments(db, empty, device.execution_id, previous, since)
    summary, details, history = read_page(db, delta.scope.connection_id)
    assert summary[0]["selected_batch_events"] == 0
    assert str(summary[0]["selected_event_attempt_id"]) == empty.execution_id
    assert details == [] and history[0]["distinct_source_events"] == 1
    failed = replace(
        empty,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        error_code="synthetic_failure",
        payload=b"",
        finished_at=empty.finished_at + timedelta(hours=1),
    )
    persist_assessments(db, failed, device.execution_id)
    summary, details, history = read_page(db, delta.scope.connection_id)
    assert summary[0]["latest_outcome"] == "failure"
    assert str(summary[0]["latest_attempt_id"]) == failed.execution_id
    assert str(summary[0]["selected_event_attempt_id"]) == empty.execution_id
    assert summary[0]["selected_batch_events"] == 0
    assert details == [] and history[0]["distinct_source_events"] == 1
    recovery = replace(
        delta,
        execution_id=str(uuid4()),
        started_at=failed.finished_at + timedelta(hours=1),
        finished_at=failed.finished_at + timedelta(hours=1, seconds=1),
    )
    with db.cursor() as cur:
        previous, since, _ = checkpoint(cur, delta.scope.connection_id)
    persist_assessments(db, recovery, device.execution_id, previous, since)
    summary, details, history = read_page(db, delta.scope.connection_id)
    assert summary[0]["latest_outcome"] == "success"
    assert str(summary[0]["selected_event_attempt_id"]) == recovery.execution_id
    assert summary[0]["selected_batch_events"] == 1
    assert len(details) == 1 and details[0]["event_kind"] == "Fixed"
    assert history[0]["distinct_source_events"] == 1
    assert all(
        row["origin"] == "synthetic"
        for group in (summary, details, history)
        for row in group
    )
    untouched, details, history = read_page(db, never_collected.scope.connection_id)
    assert untouched[0]["selected_batch_events"] is None and details == history == []
