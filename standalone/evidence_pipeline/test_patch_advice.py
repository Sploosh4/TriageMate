"""Source-scoped advice remains separate across products and unsuccessful refreshes."""

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
from .test_store import db, snapshot  # noqa: F401
from .test_update_schema import update_bound  # noqa: F401


def test_source_advice_reader_and_empty_refresh(db, snapshot):  # noqa: F811
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-device"}]',
    )
    raw = dict(
        id="synthetic-one",
        deviceId="synthetic-device",
        softwareVendor="Synthetic vendor",
        softwareName="First product",
        softwareVersion="1.0",
        cveId="CVE-2099-9999999",
        recommendedSecurityUpdateId="GUIDANCE-1",
        recommendedSecurityUpdate="Synthetic guidance",
        securityUpdateAvailable=False,
    )
    other = dict(
        raw,
        id="synthetic-two",
        softwareName="Second product",
        softwareVersion="2.0",
        recommendedSecurityUpdateId="9999991",
        securityUpdateAvailable=True,
    )
    baseline = replace(
        device,
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_baseline",
        ),
        execution_id=str(uuid4()),
        payload=json.dumps([raw, other]).encode(),
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        for value in (device, baseline):
            authorize_connection(cur, value)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL)",
            (baseline.scope.connection_id, device.scope.connection_id),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, device)
    persist_assessments(db, baseline, device.execution_id)

    def read():
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT software_name,software_version,recommended_update_reference,security_update_available,origin FROM evidence_pipeline.current_defender_update_advice WHERE connection_id=%s ORDER BY software_name",
                (baseline.scope.connection_id,),
            )
            result = cur.fetchall()
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_pipeline_writer")
            return result

    expected = [
        ("First product", "1.0", "GUIDANCE-1", False, "synthetic"),
        ("Second product", "2.0", "9999991", True, "synthetic"),
    ]
    assert read() == expected
    failed = replace(
        baseline,
        execution_id=str(uuid4()),
        complete=False,
        outcome="failure",
        payload=b"",
        error_code="synthetic_failure",
        finished_at=baseline.finished_at + timedelta(seconds=1),
    )
    persist_assessments(db, failed, device.execution_id)
    assert read() == expected
    empty = replace(
        baseline,
        execution_id=str(uuid4()),
        payload=b"[]",
        finished_at=baseline.finished_at + timedelta(seconds=2),
    )
    persist_assessments(db, empty, device.execution_id)
    assert read() == []
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.defender_update_advice_history WHERE connection_id=%s",
            (baseline.scope.connection_id,),
        )
        assert cur.fetchone() == (2,)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_migration_replays_prior_entry_points(db):  # noqa: F811

    with db.cursor() as cur:
        database_schema.verify(cur)


def test_migration_rejects_reader_view_drift(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("DROP VIEW evidence_pipeline.current_defender_update_advice")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


@pytest.mark.parametrize("update_bound", ["Defender"], indirect=True)
def test_missing_kb_reader_is_device_scoped_and_read_only(db, update_bound):  # noqa: F811
    from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure

    device, child, provider, item = update_bound
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT provider_device_id::text,native_device_id,source_patch_id,reported_cve_count,origin FROM evidence_pipeline.current_defender_missing_updates WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchall() == [
            (provider, item.native_device_id, "KB-synthetic", 2, "synthetic")
        ]
        cur.execute("RESET ROLE")
        for view in (
            "current_defender_update_advice",
            "defender_update_advice_history",
            "current_defender_missing_updates",
        ):
            for role in ("tm_mock_reader", "tm_pipeline_writer"):
                cur.execute(
                    "SELECT has_table_privilege(%s,%s,'INSERT,UPDATE,DELETE')",
                    (role, "evidence_pipeline." + view),
                )
                assert cur.fetchone() == (False,)


def test_epss_reference_authority_is_bounded_and_reader_drift_rejected(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT has_function_privilege('tm_epss_function','evidence_pipeline.reference_source_allowed(text,text,text)','EXECUTE'),has_table_privilege('tm_epss_importer','evidence.public_reference_observations','INSERT')"
        )
        assert cur.fetchone() == (True, False)
        cur.execute("GRANT UPDATE ON evidence.device_observations TO tm_mock_reader")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
