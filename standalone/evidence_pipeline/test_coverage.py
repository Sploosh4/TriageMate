"""New coverage projections tested transactionally before integrated migration."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.assessment_store import (
    persist_assessments,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_exposure_store import bound as bound_fixture, inventory
from .test_store import db as database_fixture, snapshot as snapshot_fixture

db = database_fixture
snapshot = snapshot_fixture
bound = bound_fixture


@pytest.fixture
def coverage(db, bound):
    with db.cursor() as cur:
        database_schema.verify(cur)
    return bound


def read(db, connection):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT collection_state,inventory_count,device_dependency_state "
            "FROM evidence_pipeline.software_collection_coverage WHERE connection_id=%s",
            (connection,),
        )
        result = cur.fetchone()
        cur.execute("RESET ROLE")
        return result


def test_uncollected_and_successful_empty_are_distinct(db, coverage):
    device, child = coverage
    assert read(db, child.scope.connection_id) == ("not_collected", None, "unknown")
    persist_exposure(db, child, device.execution_id, b"{}")
    assert read(db, child.scope.connection_id) == ("complete_empty", 0, "current")


def test_missing_fields_and_zero_count_are_distinct(db, coverage):
    child, associations = inventory(coverage)
    persist_exposure(db, child, coverage[0].execution_id, associations)
    assert read(db, child.scope.connection_id) == ("complete_nonempty", 2, "current")
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT i.source_application_id,c.completeness,c.completeness_total,c.origin "
            "FROM evidence_pipeline.current_software_completeness c "
            "JOIN evidence_pipeline.current_software_inventory i USING(inventory_id) "
            "WHERE c.connection_id=%s ORDER BY 1",
            (child.scope.connection_id,),
        )
        assert cur.fetchall() == [
            ("app", 4, 6, "synthetic"),
            ("empty", 3, 6, "synthetic"),
        ]


def test_new_device_snapshot_does_not_remap_software(db, coverage):
    device, child = coverage
    persist_exposure(db, child, device.execution_id, b"{}")
    newer = replace(
        device,
        execution_id=str(uuid4()),
        finished_at=device.finished_at + timedelta(hours=1),
    )
    persist_devices(db, newer)
    assert read(db, child.scope.connection_id) == (
        "complete_empty",
        0,
        "older_snapshot",
    )


def test_failed_refresh_retains_selected_inventory_and_reports_failure(db, coverage):
    child, associations = inventory(coverage)
    persist_exposure(db, child, coverage[0].execution_id, associations)
    failed = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(hours=1),
        outcome="failure",
        complete=False,
        payload=b"[]",
        error_code="synthetic_failure",
    )
    persist_exposure(db, failed, coverage[0].execution_id, b"{}")
    assert read(db, child.scope.connection_id) == ("complete_nonempty", 2, "current")
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT selected_attempt_id::text,latest_attempt_id::text,latest_outcome "
            "FROM evidence_pipeline.software_collection_coverage WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchone() == (child.execution_id, failed.execution_id, "failure")


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_findings_do_not_count_unverified_fix_references(db, coverage):
    device, child = coverage
    child = replace(
        child,
        payload=json.dumps(
            [
                {
                    "id": "synthetic-finding",
                    "machineId": device.records()[0]["id"],
                    "cveId": "CVE-2026-999999",
                    "productName": "Synthetic product",
                    "productVersion": "1",
                    "severity": "High",
                    "fixingKbId": "KB-SYNTHETIC",
                }
            ]
        ).encode(),
    )
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT completeness,completeness_total,applicability_unknown_total,origin "
            "FROM evidence_pipeline.current_vulnerability_completeness WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchone() == (6, 7, 0, "synthetic")
        cur.execute(
            "SELECT collection_state,record_count FROM evidence_pipeline.vulnerability_collection_coverage WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchone() == ("complete_nonempty", 1)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_baseline_unknown_cve_and_unbound_device_preserve_coverage(db, coverage):
    device, child = coverage
    baseline = replace(
        child,
        scope=replace(
            child.scope, connection_id=str(uuid4()), input_kind="vulnerability_baseline"
        ),
        payload=json.dumps(
            [
                {
                    "id": "synthetic-unbound",
                    "deviceId": "synthetic-absent-device",
                    "softwareVendor": "Synthetic vendor",
                    "softwareName": "Synthetic app",
                    "softwareVersion": "1",
                    "cveId": None,
                    "securityUpdateAvailable": False,
                },
                {
                    "id": "synthetic-bound",
                    "deviceId": device.records()[0]["id"],
                    "softwareVendor": "Synthetic vendor",
                    "softwareName": "Synthetic app",
                    "softwareVersion": "1",
                    "cveId": "CVE-2026-999999",
                    "cvssScore": 0,
                    "securityUpdateAvailable": False,
                },
            ]
        ).encode(),
    )
    with db.cursor() as cur:
        authorize_connection(cur, baseline)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL)",
            (baseline.scope.connection_id, device.scope.connection_id),
        )
    persist_assessments(db, baseline, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT provider_device_id IS NULL,completeness,completeness_total,applicability_unknown_total "
            "FROM evidence_pipeline.current_vulnerability_completeness WHERE connection_id=%s ORDER BY 1",
            (baseline.scope.connection_id,),
        )
        assert cur.fetchall() == [(False, 8, 9, 0), (True, 6, 6, 3)]


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_empty_baseline_and_delta_remain_separate_collection_scopes(db, coverage):
    device, child = coverage
    baseline = replace(
        child,
        scope=replace(
            child.scope, connection_id=str(uuid4()), input_kind="vulnerability_baseline"
        ),
    )
    delta = replace(
        baseline,
        scope=replace(
            baseline.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_events",
        ),
        execution_id=str(uuid4()),
        started_at=baseline.started_at + timedelta(hours=1),
        finished_at=baseline.finished_at + timedelta(hours=1),
    )
    with db.cursor() as cur:
        for item in (baseline, delta):
            authorize_connection(cur, item)
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
    persist_assessments(db, baseline, device.execution_id)
    persist_assessments(
        db,
        delta,
        device.execution_id,
        baseline.execution_id,
        baseline.started_at - timedelta(hours=6),
    )
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT input_kind,collection_state,record_count,device_dependency_state "
            "FROM evidence_pipeline.vulnerability_collection_coverage "
            "WHERE connection_id IN (%s,%s) ORDER BY input_kind",
            (baseline.scope.connection_id, delta.scope.connection_id),
        )
        assert cur.fetchall() == [
            ("vulnerability_baseline", "complete_empty", 0, "current"),
            ("vulnerability_events", "complete_empty", 0, "current"),
        ]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_vulnerability_completeness WHERE connection_id IN (%s,%s)",
            (baseline.scope.connection_id, delta.scope.connection_id),
        )
        assert cur.fetchone() == (0,)
