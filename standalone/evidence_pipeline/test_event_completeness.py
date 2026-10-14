"""Separate historical completeness using generated, transactional source events."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest


from standalone.evidence_pipeline.persistence.assessment_store import (
    persist_assessments,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_store import db as db, snapshot as snapshot


def prepare(db, snapshot):
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-device"}]',
    )
    row = dict(
        id="synthetic-instance",
        deviceId="synthetic-device",
        softwareVendor="Synthetic vendor",
        softwareName="Synthetic app",
        softwareVersion="1",
        cveId="CVE-2026-10001",
        rbacGroupId=0,
        cvssScore=0,
        securityUpdateAvailable=False,
        diskPaths=[],
    )
    baseline = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_baseline",
        ),
        execution_id=str(uuid4()),
        payload=json.dumps([row]).encode(),
    )
    event = replace(
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
            [{**row, "status": "New", "eventTimestamp": "2026-09-12T01:00:00Z"}]
        ).encode(),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        for item in (device, baseline, event):
            authorize_connection(cur, item)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL),(%s,%s,%s)",
            (
                baseline.scope.connection_id,
                device.scope.connection_id,
                event.scope.connection_id,
                device.scope.connection_id,
                baseline.scope.connection_id,
            ),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, device)
    persist_assessments(db, baseline, device.execution_id)
    persist_assessments(
        db,
        event,
        device.execution_id,
        baseline.execution_id,
        baseline.started_at - timedelta(hours=6),
    )
    return device, baseline, event


def test_history_cells_replay_zero_false_and_current_exclusion(db, snapshot):
    device, baseline, event = prepare(db, snapshot)
    repeat = replace(
        event,
        execution_id=str(uuid4()),
        started_at=event.started_at + timedelta(hours=1),
        finished_at=event.finished_at + timedelta(hours=1),
    )
    persist_assessments(
        db,
        repeat,
        device.execution_id,
        event.execution_id,
        event.started_at - timedelta(hours=6),
    )
    assert persist_assessments(
        db,
        repeat,
        device.execution_id,
        event.execution_id,
        event.started_at - timedelta(hours=6),
    )["replayed"]
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT field_name,value,populated FROM evidence_pipeline.historical_event_completeness_cells WHERE connection_id=%s",
            (event.scope.connection_id,),
        )
        cells = {
            field: (value, populated) for field, value, populated in cur.fetchall()
        }
        assert len(cells) == 27
        assert cells["cvssScore"] == ("0", True)
        assert cells["rbac_group_id"] == (0, True)
        assert cells["securityUpdateAvailable"] == (False, True)
        assert cells["diskPaths"] == ([], True)
        assert cells["recommendedSecurityUpdateId"] == (None, False)
        cur.execute(
            "SELECT * FROM evidence_pipeline.historical_event_completeness_summary(ARRAY[%s,%s]::uuid[])",
            (event.scope.connection_id, event.scope.connection_id),
        )
        result = cur.fetchone()
        assert result[:4] == (sum(value[1] for value in cells.values()), 27, 0, 1)
        cur.execute(
            "SELECT applicable,percentage,assessment FROM evidence_pipeline.completeness_summary(ARRAY[%s]::uuid[]) WHERE domain='whole-product'",
            (event.scope.connection_id,),
        )
        assert cur.fetchone() == (0, None, "Not assessable")
        cur.execute(
            "SELECT completeness_domain,eligible_cells,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
            (event.scope.connection_id,),
        )
        assert cur.fetchone() == (
            "historical-event",
            27,
            "Separate historical definition; excluded from current whole-product",
        )


def test_empty_and_null_selection_is_not_assessable(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for selection in ("ARRAY[]::uuid[]", "NULL::uuid[]"):
            cur.execute(
                "SELECT * FROM evidence_pipeline.historical_event_completeness_summary("
                + selection
                + ")"
            )
            assert cur.fetchone() == (0, 0, 0, 0, None, "Not assessable")


def test_event_completeness_authority_drift_is_rejected(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.historical_event_completeness_summary(uuid[]) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_identical_claims_keep_scope_and_tenant_boundaries(db, snapshot):
    _, _, first = prepare(db, snapshot)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
    other = replace(
        snapshot,
        execution_id=str(uuid4()),
        scope=replace(
            snapshot.scope, connection_id=str(uuid4()), tenant_id=str(uuid4())
        ),
    )
    _, _, second = prepare(db, other)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT applicable,distinct_events FROM evidence_pipeline.historical_event_completeness_summary(ARRAY[%s,%s,%s]::uuid[])",
            (
                first.scope.connection_id,
                second.scope.connection_id,
                first.scope.connection_id,
            ),
        )
        assert cur.fetchone() == (54, 2)
        cur.execute(
            "SELECT count(DISTINCT provider_device_id) FROM evidence_pipeline.historical_event_completeness_cells WHERE connection_id=ANY(%s::uuid[])",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        assert cur.fetchone() == (2,)
